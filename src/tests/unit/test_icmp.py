# SPDX-License-Identifier: GPL-2.0-or-later

import os

import firewall.core.icmp
import firewall.core.io.icmptype
import firewall.core.ipXtables
import firewall.core.nftables

from tests.unit import helpers


def test_icmp():
    assert not firewall.core.icmp.check_icmpv6_name("foo")
    assert firewall.core.icmp.check_icmpv6_name("neigbour-solicitation")


def _get_destination(xmlobj):
    d = xmlobj.destination
    if d == []:
        d = ["ipv4", "ipv6"]

    assert d in (
        ["ipv4"],
        ["ipv6"],
        ["ipv4", "ipv6"],
    )

    return d


def _icmptypes_load_file(dirname, file):
    assert dirname
    assert file
    assert file.endswith(".xml")
    assert "/" not in file

    full_name = os.path.join(dirname, file)

    assert os.path.exists(dirname)
    assert os.path.exists(full_name)

    xmlobj = firewall.core.io.icmptype.icmptype_reader(file, dirname)
    assert xmlobj

    assert xmlobj.name == file[: -len(".xml")]
    assert xmlobj.path == dirname
    _get_destination(xmlobj)
    return xmlobj


def _test_icmptypes_defined_type_and_code(xmlobjs):
    """Verify that every icmptype has a type/code defined in ICMP_TYPES and/or
    ICMPV6_TYPES."""
    types4 = firewall.core.icmp.ICMP_TYPES
    types6 = firewall.core.icmp.ICMPV6_TYPES
    for xmlobj in xmlobjs:
        should_have4 = "ipv4" in _get_destination(xmlobj)
        should_have6 = "ipv6" in _get_destination(xmlobj)
        assert should_have4 or should_have6
        has4 = xmlobj.name in types4
        has6 = xmlobj.name in types6
        assert has4 == should_have4
        assert has6 == should_have6


def test_icmptypes():
    dirname = helpers.srcdir("config/icmptypes")
    files = [f for f in os.listdir(dirname) if f.endswith(".xml")]
    assert files
    xmlobjs = []
    for file in files:
        xmlobjs.append(_icmptypes_load_file(dirname, file))

    _test_icmptypes_defined_type_and_code(xmlobjs)
