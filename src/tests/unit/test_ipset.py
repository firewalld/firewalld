# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
import socket

import firewall.core.io.ipset
import firewall.core.ipset
import firewall.errors

from tests.unit import helpers

###############################################################################


def test_ipset_type_parse():
    with pytest.raises(firewall.errors.FirewallError):
        firewall.core.ipset.ipset_type_parse("foo:")
    with pytest.raises(firewall.errors.FirewallError):
        firewall.core.ipset.ipset_type_parse("hash:")
    assert firewall.core.ipset.ipset_type_parse("hash:net") == ["net"]
    assert firewall.core.ipset.ipset_type_parse("hash:ip,port") == [
        "ip",
        "port",
    ]

    assert firewall.core.ipset.ipset_entry_split_with_type(
        "1.2.3.4,80", "hash:ip,port"
    ) == (["1.2.3.4", "80"], ["ip", "port"])
    with pytest.raises(firewall.errors.FirewallError):
        firewall.core.ipset.ipset_entry_split_with_type("1.2.3.4", "hash:ip,port")


def test_ipset_entry_parse():
    def _parse(
        entry,
        ipset_type,
        family,
        skip_idx=None,
        expected_check=None,
        ipset_check_entry_is_wrong=False,
        ipset_check_entry_error=None,
    ):
        first_exception = None
        l = []
        lst_entry, lst_ipset_type = firewall.core.ipset.ipset_entry_split_with_type(
            entry, ipset_type
        )
        for idx in range(len(lst_entry)):
            if skip_idx and idx in skip_idx:
                l.append(None)
                continue
            try:
                r = firewall.core.ipset.ipset_entry_parse(
                    entry, ipset_type, lst_entry, lst_ipset_type, idx, family
                )
            except (ValueError, firewall.errors.FirewallError) as ex:
                if first_exception is None:
                    first_exception = ex
                l.append(ex)
                continue
            l.append(r)

        if expected_check is not None:
            assert expected_check == (first_exception is None)

        if not skip_idx:
            ipset_ex = None
            try:
                firewall.core.io.ipset.IPSet.check_entry(
                    entry,
                    {
                        "family": ("inet6" if family == "ipv6" else "inet"),
                    },
                    ipset_type,
                )
            except firewall.errors.FirewallError as ex:
                ipset_ex = ex

            if ipset_check_entry_error is not None:
                helpers.assert_firewall_error(ipset_ex, msg=ipset_check_entry_error)

            if not ipset_check_entry_is_wrong:
                assert (ipset_ex is None) == (first_exception is None)
                if first_exception and ipset_check_entry_error is None:
                    assert str(ipset_ex) == str(first_exception)
            else:
                # IPSet.check_entry() does the wrong thing. We check that
                # it disagreed.
                assert (ipset_ex is None) != (first_exception is None)

        return l

    with pytest.raises(
        firewall.errors.FirewallError,
        match="INVALID_IPSET: ipset type 'bogus' not usable",
    ):
        assert _parse("1.2.3.4", "bogus", "ipv4")

    assert _parse("1.2.3.4", "hash:ip", "ipv4") == [
        (
            firewall.functions.EntryTypeAddr,
            (helpers.ipaddr_to_bin("1.2.3.4"), socket.AF_INET),
        )
    ]

    assert _parse("1.2.3.4-1.2.3.5", "hash:ip", "ipv4") == [
        (
            firewall.functions.EntryTypeAddrRange,
            (
                helpers.ipaddr_to_bin("1.2.3.4"),
                helpers.ipaddr_to_bin("1.2.3.5"),
                -1,
                socket.AF_INET,
            ),
        )
    ]

    l = _parse("0.0.0.0", "hash:ip", "ipv4")
    assert len(l) == 1
    helpers.assert_firewall_error(
        l[0],
        firewall.errors.INVALID_ENTRY,
        "invalid address '0.0.0.0' in '0.0.0.0' for hash:ip (ipv4)",
    )

    l = _parse("1.2.3.4-1.2.3.5/8", "hash:ip", "ipv4")
    assert len(l) == 1
    helpers.assert_firewall_error(
        l[0],
        firewall.errors.INVALID_ENTRY,
        "invalid address '1.2.3.5/8' in '1.2.3.4-1.2.3.5/8' for hash:ip (ipv4)",
    )

    assert _parse("1.2.3.4-1.2.3.5/8", "hash:net", "ipv4") == [
        (
            firewall.functions.EntryTypeAddrRange,
            (
                helpers.ipaddr_to_bin("1.2.3.4"),
                helpers.ipaddr_to_bin("1.2.3.5"),
                8,
                socket.AF_INET,
            ),
        )
    ]

    assert _parse("1.2.3.4,8022,1.3.4.5", "hash:ip,port,ip", "ipv4") == [
        (
            firewall.functions.EntryTypeAddr,
            (helpers.ipaddr_to_bin("1.2.3.4"), socket.AF_INET),
        ),
        (
            firewall.functions.EntryTypePort,
            (None, 8022, None, None, None),
        ),
        (
            firewall.functions.EntryTypeAddr,
            (helpers.ipaddr_to_bin("1.3.4.5"), socket.AF_INET),
        ),
    ]

    assert _parse("1.2.3.4/24,8022,1.3.4.5", "hash:ip,port,ip", "ipv4") == [
        (
            firewall.functions.EntryTypeAddrMask,
            (helpers.ipaddr_to_bin("1.2.3.4"), 24, socket.AF_INET),
        ),
        (
            firewall.functions.EntryTypePort,
            (None, 8022, None, None, None),
        ),
        (
            firewall.functions.EntryTypeAddr,
            (helpers.ipaddr_to_bin("1.3.4.5"), socket.AF_INET),
        ),
    ]

    l = _parse("1.2.3.4,8022,1.3.4.5/24", "hash:ip,port,ip", "ipv4")
    assert len(l) == 3
    assert l[0] == (
        firewall.functions.EntryTypeAddr,
        (helpers.ipaddr_to_bin("1.2.3.4"), socket.AF_INET),
    )
    assert l[1] == (firewall.functions.EntryTypePort, (None, 8022, None, None, None))
    helpers.assert_firewall_error(
        l[2],
        firewall.errors.INVALID_ENTRY,
        "invalid address '1.3.4.5/24' in '1.2.3.4,8022,1.3.4.5/24' for hash:ip,port,ip (ipv4)",
    )

    l = _parse(
        "1.2.3.4,8022,1.3.4.5-1.3.4.10",
        "hash:ip,port,ip",
        "ipv4",
    )
    assert len(l) == 3
    assert l[0] == (
        firewall.functions.EntryTypeAddr,
        (helpers.ipaddr_to_bin("1.2.3.4"), socket.AF_INET),
    )
    assert l[1] == (firewall.functions.EntryTypePort, (None, 8022, None, None, None))
    helpers.assert_firewall_error(
        l[2],
        firewall.errors.INVALID_ENTRY,
        "invalid address '1.3.4.5-1.3.4.10' in '1.2.3.4,8022,1.3.4.5-1.3.4.10'[2]",
    )

    l = _parse("1-1-2", "hash:ip", "ipv4")
    assert len(l) == 1
    helpers.assert_firewall_error(
        l[0],
        firewall.errors.INVALID_ENTRY,
        "invalid address range '1-1-2' in '1-1-2' for hash:ip (ipv4)",
    )

    l = _parse("a::b1", "hash:ip", "ipv4")
    assert len(l) == 1
    helpers.assert_firewall_error(
        l[0],
        firewall.errors.INVALID_ENTRY,
        "invalid address 'a::b1' in 'a::b1' for hash:ip (ipv4)",
    )

    assert _parse("a::b1", "hash:ip", "ipv6") == [
        (
            firewall.functions.EntryTypeAddr,
            (helpers.ipaddr_to_bin("a::b1"), socket.AF_INET6),
        ),
    ]

    assert _parse("0a:00::b1", "hash:ip", "ipv6") == [
        (
            firewall.functions.EntryTypeAddr,
            (helpers.ipaddr_to_bin("a::b1"), socket.AF_INET6),
        ),
    ]

    l = _parse("0a:00::b1/182", "hash:ip", "ipv6")
    assert len(l) == 1
    helpers.assert_firewall_error(
        l[0],
        firewall.errors.INVALID_ENTRY,
        "invalid address '0a:00::b1/182' in '0a:00::b1/182' for hash:ip (ipv6)",
    )

    assert _parse("0a:00::b1/128", "hash:net", "ipv6") == [
        (
            firewall.functions.EntryTypeAddrMask,
            (helpers.ipaddr_to_bin("a::b1"), 128, socket.AF_INET6),
        ),
    ]

    assert _parse("a::b,tcp:8022-http,cc:0::00f", "hash:ip,port,ip", "ipv6") == [
        (
            firewall.functions.EntryTypeAddr,
            (helpers.ipaddr_to_bin("a::b"), socket.AF_INET6),
        ),
        (
            firewall.functions.EntryTypePort,
            ("tcp", helpers.getservbyname("http", 80), "http", 8022, None),
        ),
        (
            firewall.functions.EntryTypeAddr,
            (helpers.ipaddr_to_bin("cc::f"), socket.AF_INET6),
        ),
    ]

    l = _parse("a::b-a::f,tcp:8022-http,cc:0::00f/24", "hash:ip,port,ip", "ipv6")
    assert len(l) == 3
    helpers.assert_firewall_error(
        l[0],
        firewall.errors.INVALID_ENTRY,
        "invalid address 'a::b-a::f' in 'a::b-a::f,tcp:8022-http,cc:0::00f/24' for hash:ip,port,ip (ipv6)",
    )
    assert l[1] == (
        firewall.functions.EntryTypePort,
        ("tcp", helpers.getservbyname("http", 80), "http", 8022, None),
    )
    helpers.assert_firewall_error(
        l[2],
        firewall.errors.INVALID_ENTRY,
        "invalid address 'cc:0::00f/24' in 'a::b-a::f,tcp:8022-http,cc:0::00f/24' for hash:ip,port,ip (ipv6)",
    )

    l = _parse("a::00f,tcp:8022-http,cc:0::00f/24", "hash:ip,port,ip", "ipv6")
    assert len(l) == 3
    assert l[0] == (
        firewall.functions.EntryTypeAddr,
        (helpers.ipaddr_to_bin("a::f"), socket.AF_INET6),
    )
    assert l[1] == (
        firewall.functions.EntryTypePort,
        ("tcp", helpers.getservbyname("http", 80), "http", 8022, None),
    )
    helpers.assert_firewall_error(
        l[2],
        firewall.errors.INVALID_ENTRY,
        "invalid address 'cc:0::00f/24' in 'a::00f,tcp:8022-http,cc:0::00f/24' for hash:ip,port,ip (ipv6)",
    )

    l = _parse("a::b-a::f,tcp:8022-http,cc:0::00f/24", "hash:net,port,ip", "ipv6")
    assert len(l) == 3
    assert l[0] == (
        firewall.functions.EntryTypeAddrRange,
        (
            helpers.ipaddr_to_bin("a::b"),
            helpers.ipaddr_to_bin("a::f"),
            -1,
            socket.AF_INET6,
        ),
    )
    assert l[1] == (
        firewall.functions.EntryTypePort,
        ("tcp", helpers.getservbyname("http", 80), "http", 8022, None),
    )
    helpers.assert_firewall_error(
        l[2],
        firewall.errors.INVALID_ENTRY,
        "invalid address 'cc:0::00f/24' in 'a::b-a::f,tcp:8022-http,cc:0::00f/24' for hash:net,port,ip (ipv6)",
    )

    l = _parse("bogusport", "hash:port", "ipv6")
    assert len(l) == 1
    helpers.assert_firewall_error(
        l[0],
        firewall.errors.INVALID_ENTRY,
        "invalid port 'bogusport' in 'bogusport'",
    )

    assert _parse(
        "a::b/1,cc:0::00f,bb::11-bb::ff,bb::11-bb::1f/5,bb::11-bb::/5,bb::11-bb::",
        "hash:net,net,net,net,net,net",
        "ipv6",
    ) == [
        (
            firewall.functions.EntryTypeAddrMask,
            (helpers.ipaddr_to_bin("a::b"), 1, socket.AF_INET6),
        ),
        (
            firewall.functions.EntryTypeAddr,
            (helpers.ipaddr_to_bin("cc::f"), socket.AF_INET6),
        ),
        (
            firewall.functions.EntryTypeAddrRange,
            (
                helpers.ipaddr_to_bin("bb::11"),
                helpers.ipaddr_to_bin("bb::ff"),
                -1,
                socket.AF_INET6,
            ),
        ),
        (
            firewall.functions.EntryTypeAddrRange,
            (
                helpers.ipaddr_to_bin("bb::11"),
                helpers.ipaddr_to_bin("bb::1f"),
                5,
                socket.AF_INET6,
            ),
        ),
        (
            firewall.functions.EntryTypeAddrRange,
            (
                helpers.ipaddr_to_bin("bb::11"),
                helpers.ipaddr_to_bin("bb::"),
                5,
                socket.AF_INET6,
            ),
        ),
        (
            firewall.functions.EntryTypeAddrRange,
            (
                helpers.ipaddr_to_bin("bb::11"),
                helpers.ipaddr_to_bin("bb::"),
                -1,
                socket.AF_INET6,
            ),
        ),
    ]

    l = _parse("a::0b/0", "hash:net", "ipv6")
    assert len(l) == 1
    helpers.assert_firewall_error(
        l[0],
        firewall.errors.INVALID_ENTRY,
        "invalid address 'a::0b/0' in 'a::0b/0' for hash:net (ipv6)",
    )

    assert _parse("0A:00:00:00:00:bb", "hash:mac", "ipv6") == [
        (
            firewall.functions.EntryTypeMac,
            ("0a:00:00:00:00:bb",),
        ),
    ]
    assert _parse(
        "F3:14:3D:93:7E:8F,00:aa:bb:cc:dd:EE,0xfa1,1", "hash:mac,mac,mark,mark", "ipv4"
    ) == [
        (
            firewall.functions.EntryTypeMac,
            ("f3:14:3d:93:7e:8f",),
        ),
        (
            firewall.functions.EntryTypeMac,
            ("00:aa:bb:cc:dd:ee",),
        ),
        (
            firewall.functions.EntryTypeMark,
            (0xFA1, True),
        ),
        (
            firewall.functions.EntryTypeMark,
            (1, False),
        ),
    ]

    l = _parse("00:00:00:00:00:00", "hash:mac", "ipv4")
    assert len(l) == 1
    helpers.assert_firewall_error(
        l[0],
        firewall.errors.INVALID_ENTRY,
        "invalid mac address '00:00:00:00:00:00' in '00:00:00:00:00:00'",
    )

    l = _parse("1.2.3.4/0,eth0", "hash:net,iface", "ipv4")
    assert len(l) == 2
    helpers.assert_firewall_error(
        l[0],
        firewall.errors.INVALID_ENTRY,
        "invalid address '1.2.3.4/0' in '1.2.3.4/0,eth0' for hash:net,iface (ipv4)",
    )
    assert l[1] == (
        firewall.functions.EntryTypeIface,
        ("eth0",),
    )

    assert _parse("1::2/0,eth0", "hash:net,iface", "ipv6") == [
        (
            firewall.functions.EntryTypeAddrMask,
            (helpers.ipaddr_to_bin("1::2"), 0, socket.AF_INET6),
        ),
        (
            firewall.functions.EntryTypeIface,
            ("eth0",),
        ),
    ]

    assert _parse("1::2/1,eth0,http", "hash:net,iface,port", "ipv6") == [
        (
            firewall.functions.EntryTypeAddrMask,
            (helpers.ipaddr_to_bin("1::2"), 1, socket.AF_INET6),
        ),
        (
            firewall.functions.EntryTypeIface,
            ("eth0",),
        ),
        (
            firewall.functions.EntryTypePort,
            (None, 80, "http", None, None),
        ),
    ]

    l = _parse("1::2/0,eth0,http", "hash:net,iface,port", "ipv6")
    assert len(l) == 3
    helpers.assert_firewall_error(
        l[0],
        firewall.errors.INVALID_ENTRY,
        "invalid address '1::2/0' in '1::2/0,eth0,http' for hash:net,iface,port (ipv6)",
    )
    assert l[1] == (
        firewall.functions.EntryTypeIface,
        ("eth0",),
    )
    assert l[2] == (
        firewall.functions.EntryTypePort,
        (None, 80, "http", None, None),
    )

    l = _parse("1.2.3.4/0", "hash:net", "ipv4")
    assert len(l) == 1
    helpers.assert_firewall_error(
        l[0],
        firewall.errors.INVALID_ENTRY,
        "invalid address '1.2.3.4/0' in '1.2.3.4/0' for hash:net (ipv4)",
    )

    l = _parse(
        "1.2.3.4/0.0.0.0",
        "hash:net",
        "ipv4",
        ipset_check_entry_is_wrong=True,
    )
    assert len(l) == 1
    helpers.assert_firewall_error(
        l[0],
        firewall.errors.INVALID_ENTRY,
        "invalid address '1.2.3.4/0.0.0.0' in '1.2.3.4/0.0.0.0' for hash:net (ipv4)",
    )

    assert _parse("1.2.3.4/255.0.0.0", "hash:net", "ipv4") == [
        (
            firewall.functions.EntryTypeAddrMask,
            (helpers.ipaddr_to_bin("1.2.3.4"), 8, socket.AF_INET),
        )
    ]
