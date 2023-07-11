# SPDX-License-Identifier: GPL-2.0-or-later

import pytest

import firewall.functions

from tests.unit import helpers

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

    with pytest.raises(AttributeError):
        assert not firewall.functions.checkIP6(None)
    assert firewall.functions.checkIP6("[::]")
    assert firewall.functions.checkIP6("[1:00::a22]")
    assert firewall.functions.checkIP6("[::")
    assert firewall.functions.checkIP6("[[[[[::")
    assert firewall.functions.checkIP6("[[[[[::[")
    assert firewall.functions.checkIP6("[[[[[1::2[")
    assert not firewall.functions.checkIP6("[[[[[bogus[")

    with pytest.raises(AttributeError):
        assert not firewall.functions.normalizeIP6(None)
    assert firewall.functions.normalizeIP6("[::]") == "::"
    assert firewall.functions.normalizeIP6("[1:00::a22]") == "1:00::a22"
    assert firewall.functions.normalizeIP6("1:00::a22") == "1:00::a22"
    assert firewall.functions.normalizeIP6("[::") == "::"
    assert firewall.functions.normalizeIP6("[[[[[::") == "::"
    assert firewall.functions.normalizeIP6("[[[[[::[") == "::"
    assert firewall.functions.normalizeIP6("[[[[[1::2[") == "1::2"
    assert firewall.functions.normalizeIP6("[[[[[bogus[") == "bogus"
