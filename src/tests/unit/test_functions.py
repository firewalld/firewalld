# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
import socket

import firewall.functions

from tests.unit import helpers

###############################################################################


def ipaddrmask_from_plen(plen, family):
    n = firewall.functions.addr_family_bitsize(family)
    if isinstance(plen, int) and (plen >= 0 and plen <= n):
        pass
    else:
        raise ValueError("Invalid prefix length")

    l = [0] * int(n / 8)
    i = 0
    while plen >= 8:
        plen -= 8
        l[i] = 255
        i += 1
    if plen > 0:
        l[i] = 255 & ~((1 << (8 - plen)) - 1)

    return bytes(l)


def ipaddrmask_make_subnet(addrbin, plen):
    family = None
    if isinstance(addrbin, bytes):
        if len(addrbin) == 4:
            family = socket.AF_INET
        elif len(addrbin) == 16:
            family = socket.AF_INET6
    if family is None:
        raise ValueError("Invalid address")

    maskbin = ipaddrmask_from_plen(plen, family)

    subnet = bytes(addrbin[i] & maskbin[i] for i in range(len(addrbin)))

    if subnet == addrbin:
        return addrbin
    return subnet


###############################################################################


def test_fcnport():
    http_port = helpers.getservbyname("http", 80)
    www_http_port = helpers.getservbyname("www-http", 80, maybe_missing=True)
    gopher_port = helpers.getservbyname("gopher", 70, maybe_missing=True)

    with pytest.raises(TypeError):
        assert firewall.functions.getPortID(None)
    assert firewall.functions.getPortID(1) == 1
    assert firewall.functions.getPortID(65535) == 65535
    assert firewall.functions.getPortID(0) == 0
    assert firewall.functions.getPortID(-1) == -1
    assert firewall.functions.getPortID(-3) == -3
    assert firewall.functions.getPortID(65536) == -2
    assert firewall.functions.getPortID("6") == 6
    assert firewall.functions.getPortID("  66 ") == 66
    assert firewall.functions.getPortID("  65535 ") == 65535
    assert firewall.functions.getPortID("  65536 ") == -2
    assert firewall.functions.getPortID("0") == 0
    assert firewall.functions.getPortID("-1") == -1
    assert firewall.functions.getPortID("-3") == -3
    assert firewall.functions.getPortID("foo") == -1
    assert firewall.functions.getPortID("") == -1
    assert firewall.functions.getPortID(" ") == -1
    assert firewall.functions.getPortID("http") == http_port
    assert firewall.functions.getPortID(" http") == http_port
    if www_http_port is not None:
        assert firewall.functions.getPortID(" www-http   ") == www_http_port

    with pytest.raises(AttributeError):
        assert firewall.functions.getPortRange(None)
    assert firewall.functions.getPortRange([]) == []
    assert firewall.functions.getPortRange(()) == ()
    assert firewall.functions.getPortRange((1,)) == (1,)
    assert firewall.functions.getPortRange([2342423432]) == [2342423432]
    assert firewall.functions.getPortRange((1, 4)) == (1, 4)
    assert firewall.functions.getPortRange([2342423432, 5]) == [2342423432, 5]
    assert firewall.functions.getPortRange((1, 6, 4)) == (1, 6, 4)

    assert firewall.functions.getPortRange(-5) == -5
    assert firewall.functions.getPortRange(-1) == -1
    assert firewall.functions.getPortRange(0) == (0,)
    assert firewall.functions.getPortRange(5) == (5,)
    assert firewall.functions.getPortRange(65535) == (65535,)
    assert firewall.functions.getPortRange(65536) == -2

    assert firewall.functions.getPortRange("-5") == -1
    assert firewall.functions.getPortRange("-1") == -1
    assert firewall.functions.getPortRange("0") == (0,)
    assert firewall.functions.getPortRange("0 ") == (0,)
    assert firewall.functions.getPortRange("1") == (1,)
    assert firewall.functions.getPortRange(" 1 ") == (1,)
    assert firewall.functions.getPortRange("65535") == (65535,)
    assert firewall.functions.getPortRange("65536") == -2
    assert firewall.functions.getPortRange(" 65536 ") == -1

    assert firewall.functions.getPortRange("-") == -1
    assert firewall.functions.getPortRange("1-1") == (1,)
    assert firewall.functions.getPortRange("1-2") == (1, 2)
    assert firewall.functions.getPortRange(" 1-2") == (1, 2)
    assert firewall.functions.getPortRange(" 2-1") == (1, 2)
    assert firewall.functions.getPortRange(" 0-1") == (0, 1)
    assert firewall.functions.getPortRange(" 0-65535") == (0, 65535)
    assert firewall.functions.getPortRange(" 65535 \n - 1  ") == (1, 65535)
    assert firewall.functions.getPortRange(" 65536-1") == -1

    assert firewall.functions.getPortRange(" http") == (http_port,)
    assert firewall.functions.getPortRange(" http-http") == (http_port,)
    if www_http_port is not None:
        assert firewall.functions.getPortRange(" http-www-http") == (http_port,)
    if www_http_port is not None and gopher_port is not None:
        assert firewall.functions.getPortRange(" gopher-www-http") == (
            gopher_port,
            http_port,
        )
        assert firewall.functions.getPortRange(" gopher -www-http") == (
            gopher_port,
            http_port,
        )
        assert firewall.functions.getPortRange(" gopher -76") == (gopher_port, 76)

    assert firewall.functions.getPortRange("foo") == -1
    assert firewall.functions.getPortRange(" xgopher -76") == -1

    assert firewall.functions.portStr("0") == "0"
    assert firewall.functions.portStr("x") is None
    assert firewall.functions.portStr(" http") == "80"
    assert firewall.functions.portStr(" 1 - 5") == "1:5"
    assert firewall.functions.portStr(" http - 5") == "5:80"


def test_checkIP():
    with pytest.raises(TypeError):
        assert not firewall.functions.checkIP(None)
    assert firewall.functions.checkIP("0.0.0.0")
    assert firewall.functions.checkIP("1.2.3.4")
    assert not firewall.functions.checkIP("::")
    assert not firewall.functions.checkIP("")

    with pytest.raises(TypeError):
        assert not firewall.functions.checkIP6(None)
    assert firewall.functions.checkIP6("[::]")
    assert firewall.functions.checkIP6("[1:00::a22]")
    assert not firewall.functions.checkIP6("[::")
    assert not firewall.functions.checkIP6("[[[[[::")
    assert not firewall.functions.checkIP6("[[[[[::[")
    assert not firewall.functions.checkIP6("[[[[[1::2[")
    assert not firewall.functions.checkIP6("[[[[[bogus[")

    with pytest.raises(TypeError):
        assert not firewall.functions.normalizeIP6(None)
    assert firewall.functions.normalizeIP6("[::]") == "::"
    assert firewall.functions.normalizeIP6("[1:00::a22]") == "1::a22"
    assert firewall.functions.normalizeIP6("1:00::a22") == "1::a22"
    with pytest.raises(ValueError):
        assert firewall.functions.normalizeIP6("[::")
    with pytest.raises(ValueError):
        assert firewall.functions.normalizeIP6("[[[[[::")
    with pytest.raises(ValueError):
        assert firewall.functions.normalizeIP6("[[[[[::[")
    with pytest.raises(ValueError):
        assert firewall.functions.normalizeIP6("[[[[[1::2[")
    with pytest.raises(ValueError):
        assert firewall.functions.normalizeIP6("[[[[[bogus[")


def test_checkInterface():
    assert not firewall.functions.checkInterface(None)
    assert not firewall.functions.checkInterface(0)
    with pytest.raises(TypeError):
        firewall.functions.checkInterface(b"eth0")

    assert not firewall.functions.checkInterface("")
    assert not firewall.functions.checkInterface("/")
    assert not firewall.functions.checkInterface("a/")
    assert firewall.functions.checkInterface("\240a")
    assert firewall.functions.checkInterface(".")
    assert firewall.functions.checkInterface("..")
    assert firewall.functions.checkInterface("...")
    assert firewall.functions.checkInterface("all")
    assert firewall.functions.checkInterface("bonding_masters")
    assert firewall.functions.checkInterface("default")
    assert firewall.functions.checkInterface("defaultx")
    assert firewall.functions.checkInterface("1234567890abcd")
    assert firewall.functions.checkInterface("1234567890abcde")
    assert firewall.functions.checkInterface("1234567890abcdef")
    assert not firewall.functions.checkInterface("1234567890abcdefg")
    assert not firewall.functions.checkInterface("eth!x")
    assert not firewall.functions.checkInterface("eth*x")

    smiley = b"\xF0\x9F\x98\x8A".decode("utf-8")
    iface = f"{smiley}{smiley}{smiley}"
    assert firewall.functions.checkInterface(f"123{iface}")
    assert firewall.functions.checkInterface(f"1234{iface}")
    assert firewall.functions.checkInterface(f"1234567890abc{iface}")
    assert not firewall.functions.checkInterface(f"1234567890abcd{iface}")


def test_addr_family():
    assert firewall.functions.addr_family("4") == socket.AF_INET
    assert firewall.functions.addr_family("IP6") == socket.AF_INET6
    assert firewall.functions.addr_family(None, allow_unspec=True) == socket.AF_UNSPEC
    assert firewall.functions.addr_family(socket.AF_INET) == socket.AF_INET
    assert firewall.functions.addr_family(socket.AF_INET6) == socket.AF_INET6
    assert (
        firewall.functions.addr_family(socket.AF_UNSPEC, allow_unspec=True)
        == socket.AF_UNSPEC
    )
    assert firewall.functions.addr_family("IP", allow_unspec=True) == socket.AF_UNSPEC

    with pytest.raises(firewall.errors.BugError):
        firewall.functions.addr_family("x")
    with pytest.raises(firewall.errors.BugError):
        firewall.functions.addr_family("")
    with pytest.raises(firewall.errors.BugError):
        firewall.functions.addr_family("", allow_unspec=True)
    with pytest.raises(firewall.errors.BugError):
        firewall.functions.addr_family("IP")

    for family_str in ("IPv4", "IPv6", "IP"):
        f2 = firewall.functions.addr_family(family_str, allow_unspec=True)
        assert family_str == firewall.functions.addr_family_str(f2)
        assert family_str == firewall.functions.addr_family_str(family_str)


def test_addr_parse():
    assert firewall.functions.IPAddrZero4 == helpers.ipaddr_to_bin("0.0.0.0")

    def _parse(*a, **kw):
        addrbin, family = firewall.functions.ipaddr_parse(*a, **kw)

        addr_norm = firewall.functions.ipaddr_norm(*a, **kw)
        assert firewall.functions.ipaddr_parse(addr_norm) == (addrbin, family)
        assert firewall.functions.ipaddr_parse(addr_norm, family=family) == (
            addrbin,
            family,
        )

        return addr_norm

    assert _parse("1.2.3.4") == "1.2.3.4"
    assert _parse("::0", family=socket.AF_INET6) == "::"

    with pytest.raises(ValueError):
        firewall.functions.ipaddr_parse(
            "[1::2]",
            family=socket.AF_INET6,
            flags=firewall.functions.EntryType.ParseFlags.NO_IP6_BRACKETS,
        )
    assert _parse("[1::2]", family=socket.AF_INET6) == "1::2"

    assert firewall.functions.ipaddr_parse("0.0.0.0") == (
        firewall.functions.IPAddrZero4,
        socket.AF_INET,
    )


def test_ipaddrmask_to_plen():
    def check(addr, expect_plen):
        addrbin, family = firewall.functions.ipaddr_parse(addr)
        assert firewall.functions.ipaddrmask_to_plen(addrbin) == expect_plen
        addrbin2 = ipaddrmask_from_plen(expect_plen, family)
        assert firewall.functions.ipaddrmask_to_plen(addrbin2) == expect_plen

    check("224.0.0.0", 3)
    check("127.0.0.0", 8)
    check("255.0.0.0", 8)
    check("255.255.0.0", 16)
    check("255.1.0.0", 16)
    check("255.1.0.1", 32)
    check("255.1.0.255", 32)
    check("255.255.255.255", 32)
    check("255.248.0.0", 13)
    check("113.1.26.220", 30)
    check("0.0.0.0", 0)
    check("::", 0)
    check("::1", 128)
    check("ffff::1", 128)
    check("ffff::", 16)
    check("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 128)
    check("ffff:ffff:ffff:fe00::", 55)
    check("ffff:ffff:ffff:ffff:ffff:ffff:fe00::", 103)
    check("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffc0", 122)
    check("54db:020a:cd5d:a2cd:3c96:8ed8:7ea1:8540", 122)
    check("54db:020a::a2cd:3c96:8ed8:7ea1:8540", 122)


def test_ipaddrmask_make_subnet():
    def s(addr, plen):
        addrbin = helpers.ipaddr_to_bin(addr)
        subnetbin = ipaddrmask_make_subnet(addrbin, plen)
        if addrbin == subnetbin:
            assert addrbin is subnetbin
        return helpers.ipaddr_from_bin(subnetbin)

    assert s("192.168.0.0", 24) == "192.168.0.0"
    assert s("192.168.0.1", 32) == "192.168.0.1"
    assert s("192.168.0.3", 24) == "192.168.0.0"
    assert s("192.168.0.3", 0) == "0.0.0.0"
    assert s("aa::4:1", 128) == "aa::4:1"
    assert s("aa::4:1", 127) == "aa::4:0"
    assert s("aa::4:1", 0) == "::"


def test_addrmask_parse():
    def _parse(*a, **kw):
        addrbin, plen, family = firewall.functions.ipaddrmask_parse(*a, **kw)

        addr_norm = firewall.functions.ipaddrmask_norm(*a, **kw)
        assert firewall.functions.ipaddrmask_parse(addr_norm, require_plen=False) == (
            addrbin,
            plen,
            family,
        )
        assert firewall.functions.ipaddrmask_parse(
            addr_norm, family=family, require_plen=False
        ) == (
            addrbin,
            plen,
            family,
        )

        kw2 = dict(kw)
        kw2["require_plen"] = True
        if plen == -1:
            with pytest.raises(ValueError):
                firewall.functions.ipaddrmask_parse(*a, **kw2)
        else:
            assert firewall.functions.ipaddrmask_parse(*a, **kw2) == (
                addrbin,
                plen,
                family,
            )

        return addr_norm

    assert _parse("1::0/5") == "1::/5"
    with pytest.raises(ValueError):
        assert _parse("1::0/255.0.0.0") == "1::/8"
    assert _parse("1.2.3.4/255.0.0.0") == "1.2.3.4/8"
    with pytest.raises(ValueError):
        _parse("::/::")
    with pytest.raises(ValueError):
        _parse("::") == "::"
    assert _parse("::", require_plen=False) == "::"
    with pytest.raises(ValueError):
        _parse("1.2.3.4")
    assert _parse("1.2.3.4", require_plen=False) == "1.2.3.4"
    with pytest.raises(ValueError):
        _parse("1.2.3.4/::")
    with pytest.raises(ValueError):
        _parse("::/1.2.3.4")

    assert _parse("::/5") == "::/5"
    assert _parse("a::01/0") == "a::1/0"


def test_ipaddrrange():
    assert firewall.functions.ipaddrrange_parse("192.168.0.3-192.168.0.10") == (
        helpers.ipaddr_to_bin("192.168.0.3"),
        helpers.ipaddr_to_bin("192.168.0.10"),
        -1,
        socket.AF_INET,
    )
    assert firewall.functions.ipaddrrange_parse("192.168.0.132-192.168.0.132") == (
        helpers.ipaddr_to_bin("192.168.0.132"),
        helpers.ipaddr_to_bin("192.168.0.132"),
        -1,
        socket.AF_INET,
    )

    assert firewall.functions.ipaddrrange_parse(
        "192.168.0.132-192.168.0.132", family="4"
    ) == (
        helpers.ipaddr_to_bin("192.168.0.132"),
        helpers.ipaddr_to_bin("192.168.0.132"),
        -1,
        socket.AF_INET,
    )
    with pytest.raises(ValueError, match="not a valid IPv6 address range"):
        firewall.functions.ipaddrrange_parse("192.168.0.132-192.168.0.132", family="6")

    with pytest.raises(ValueError, match="not a valid IPv4 address range"):
        firewall.functions.ipaddrrange_parse("192.168.0.132/4-192.168.0.132")
    assert firewall.functions.ipaddrrange_parse("192.168.0.132-192.168.0.132/4") == (
        helpers.ipaddr_to_bin("192.168.0.132"),
        helpers.ipaddr_to_bin("192.168.0.132"),
        4,
        socket.AF_INET,
    )

    firewall.functions.ipaddrrange_parse("::5-::10", family="6") == (
        helpers.ipaddr_to_bin("::5"),
        helpers.ipaddr_to_bin("::10"),
        -1,
        socket.AF_INET6,
    )

    firewall.functions.ipaddrrange_parse("::5-::10/128", family="6") == (
        helpers.ipaddr_to_bin("::5"),
        helpers.ipaddr_to_bin("::10"),
        128,
        socket.AF_INET6,
    )

    with pytest.raises(ValueError, match="not a valid IPv6 address range"):
        firewall.functions.ipaddrrange_parse("::5/128-::10", family="6")

    assert firewall.functions.ipaddrrange_parse("192.168.0.132-192.168.0.131") == (
        helpers.ipaddr_to_bin("192.168.0.132"),
        helpers.ipaddr_to_bin("192.168.0.131"),
        -1,
        socket.AF_INET,
    )

    assert firewall.functions.ipaddrrange_parse("192.168.0.132-192.168.0.131/4") == (
        helpers.ipaddr_to_bin("192.168.0.132"),
        helpers.ipaddr_to_bin("192.168.0.131"),
        4,
        socket.AF_INET,
    )

    assert firewall.functions.ipaddrrange_parse(
        "192.168.0.132-192.168.0.132/5", family="4"
    ) == (
        helpers.ipaddr_to_bin("192.168.0.132"),
        helpers.ipaddr_to_bin("192.168.0.132"),
        5,
        socket.AF_INET,
    )

    assert firewall.functions.ipaddrrange_parse("192.168.0.132-192.168.0.132/5") == (
        helpers.ipaddr_to_bin("192.168.0.132"),
        helpers.ipaddr_to_bin("192.168.0.132"),
        5,
        socket.AF_INET,
    )

    assert firewall.functions.ipaddrrange_parse("1.2.3.4-1.2.3.5/8") == (
        helpers.ipaddr_to_bin("1.2.3.4"),
        helpers.ipaddr_to_bin("1.2.3.5"),
        8,
        socket.AF_INET,
    )

    assert firewall.functions.ipaddrrange_parse("1.2.3.4-1.2.3.1") == (
        helpers.ipaddr_to_bin("1.2.3.4"),
        helpers.ipaddr_to_bin("1.2.3.1"),
        -1,
        socket.AF_INET,
    )

    assert firewall.functions.ipaddrrange_parse("1.2.3.4-1.2.3.1/8") == (
        helpers.ipaddr_to_bin("1.2.3.4"),
        helpers.ipaddr_to_bin("1.2.3.1"),
        8,
        socket.AF_INET,
    )


def test_mac():
    assert firewall.functions.mac_check("00:11:33:44:55:66")
    assert firewall.functions.mac_parse("00:aA:33:44:55:66") == ("00:aa:33:44:55:66",)
    assert firewall.functions.mac_norm("00:aA:33:44:55:66") == "00:aa:33:44:55:66"

    assert not firewall.functions.mac_check("00:11:33:44:5566")
    with pytest.raises(ValueError):
        firewall.functions.mac_parse("00:11:33:4x:55:66")

    assert (
        firewall.functions.EntryTypeMac.norm("aa:BB:cc:dd:ee:00") == "aa:bb:cc:dd:ee:00"
    )


def test_entrytype():
    with pytest.raises(TypeError):
        assert firewall.functions.EntryType.check("fooo", types=None)

    with pytest.raises(ValueError):
        firewall.functions.EntryType.parse("fooo", types=())
    assert not firewall.functions.EntryType.check("fooo", types=())

    assert firewall.functions.EntryTypeAddr.parse("1::55:00") == (
        helpers.ipaddr_to_bin("1::55:0"),
        socket.AF_INET6,
    )

    assert firewall.functions.EntryType.parse(
        "1.2.3.4", types=(firewall.functions.EntryTypeAddr,)
    ) == (
        firewall.functions.EntryTypeAddr,
        (
            helpers.ipaddr_to_bin("1.2.3.4"),
            socket.AF_INET,
        ),
    )
    assert firewall.functions.EntryType.check(
        "1.2.3.4-1.3.4.5",
        types=(
            firewall.functions.EntryTypeAddrMask,
            firewall.functions.EntryTypeAddrRange,
        ),
    )

    assert firewall.functions.EntryType.parse(
        "1:2::aa:ff", types=(firewall.functions.EntryTypeAddr,)
    ) == (
        firewall.functions.EntryTypeAddr,
        (
            helpers.ipaddr_to_bin("1:2::aa:ff"),
            socket.AF_INET6,
        ),
    )

    assert firewall.functions.EntryType.parse(
        "1:2::aa:ff/64", types=(firewall.functions.EntryTypeAddrMask,)
    ) == (
        firewall.functions.EntryTypeAddrMask,
        (
            helpers.ipaddr_to_bin("1:2::aa:ff"),
            64,
            socket.AF_INET6,
        ),
    )
    assert (
        firewall.functions.EntryTypeAddrMask.norm("1:2:00::aa:ff/64") == "1:2::aa:ff/64"
    )
    assert firewall.functions.EntryTypeAddrMask.check("1:2:00::aa:ff/64")
    assert not firewall.functions.EntryTypeAddrMask.check("1:2:00::aa:ff/129")

    assert firewall.functions.EntryTypeAddrMask.check(
        "1:2:00::aa:ff", require_plen=False
    )
    assert not firewall.functions.EntryTypeAddrMask.check(
        "1:2:00::aa:ff", require_plen=True
    )

    assert firewall.functions.EntryType.parse(
        "1.2.3.4-1.3.4.5",
        types=(
            firewall.functions.EntryTypeAddrMask,
            firewall.functions.EntryTypeAddrRange,
        ),
    ) == (
        firewall.functions.EntryTypeAddrRange,
        (
            helpers.ipaddr_to_bin("1.2.3.4"),
            helpers.ipaddr_to_bin("1.3.4.5"),
            -1,
            socket.AF_INET,
        ),
    )

    assert firewall.functions.EntryType.parse(
        "::1-::4", types=(firewall.functions.EntryTypeAddrRange,)
    ) == (
        firewall.functions.EntryTypeAddrRange,
        (
            helpers.ipaddr_to_bin("::1"),
            helpers.ipaddr_to_bin("::4"),
            -1,
            socket.AF_INET6,
        ),
    )

    assert firewall.functions.EntryType.check(
        "1.2.3.4", types=(firewall.functions.EntryTypeAddr,)
    )
    assert not firewall.functions.EntryType.check(
        "1.2.3.", types=(firewall.functions.EntryTypeAddr,)
    )
    assert not firewall.functions.EntryType.check(
        "1.2.3.", types=(firewall.functions.EntryTypeAddrRange,)
    )
    assert firewall.functions.EntryType.check(
        "::1-::4", types=(firewall.functions.EntryTypeAddrRange,)
    )

    entrytype, detail = firewall.functions.EntryType.parse(
        "[1:2::aa:ff]", types=(firewall.functions.EntryTypeAddr,)
    )
    assert (entrytype, detail) == (
        firewall.functions.EntryTypeAddr,
        (helpers.ipaddr_to_bin("1:2::aa:ff"), socket.AF_INET6),
    )
    assert entrytype.unparse(*detail) == "1:2::aa:ff"

    assert firewall.functions.EntryTypeAddr.check("1.2.3.4")
    assert not firewall.functions.EntryTypeAddr.check("1.2.")
    assert firewall.functions.EntryTypeAddr.norm("1.2.3.4") == "1.2.3.4"
    assert firewall.functions.EntryTypeAddr.norm("1:02::aa:ff") == "1:2::aa:ff"
    assert firewall.functions.EntryTypeAddr.norm("[1:2::aa:ff]") == "1:2::aa:ff"

    assert firewall.functions.EntryTypeMac.check("aa:dd:11:22:33:44")
    assert not firewall.functions.EntryTypeMac.check("asdf")
    assert (
        firewall.functions.EntryTypeMac.norm("aa:dD:11:22:33:44") == "aa:dd:11:22:33:44"
    )
