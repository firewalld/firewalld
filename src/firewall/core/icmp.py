# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2017 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>

ICMP_TYPES = {
    # "type": (type, code, backend omit code)
    "echo-reply": (0, 0, True),
    "pong": (0, 0, True),
    "destination-unreachable": (3, 0, True),
    "network-unreachable": (3, 0, False),
    "tos-network-unreachable": (3, 0, False),
    "host-unreachable": (3, 1, False),
    "tos-host-unreachable": (3, 1, False),
    "protocol-unreachable": (3, 2, False),
    "port-unreachable": (3, 3, False),
    "fragmentation-needed": (3, 4, False),
    "source-route-failed": (3, 5, False),
    # RFC-1112 Section 3.2.2.1 defines type 3, code 6-12
    "network-unknown": (3, 6, False),
    "host-unknown": (3, 7, False),
    "network-prohibited": (3, 9, False),
    "host-prohibited": (3, 10, False),
    "TOS-network-unreachable": (3, 11, False),
    "TOS-host-unreachable": (3, 12, False),
    # RFC-1812 Section 5.2.7.1 defines type 3, code 13-15
    "communication-prohibited": (3, 13, False),
    "host-precedence-violation": (3, 14, False),
    "precedence-cutoff": (3, 15, False),
    "source-quench": (4, 0, True),
    "network-redirect": (5, 0, False),
    "redirect": (5, 0, True),
    "host-redirect": (5, 1, False),
    "tos-host-redirect": (5, 1, False),
    "TOS-network-redirect": (5, 2, False),
    "tos-network-redirect": (5, 2, False),
    "TOS-host-redirect": (5, 3, False),
    "echo-request": (8, 0, True),
    "ping": (8, 0, True),
    "router-advertisement": (9, 0, True),
    "router-solicitation": (10, 0, True),
    "time-exceeded": (11, 0, True),
    "ttl-zero-during-transit": (11, 0, False),
    "ttl-zero-during-reassembly": (11, 1, False),
    "parameter-problem": (12, 0, True),
    "ip-header-bad": (12, 0, False),
    "required-option-missing": (12, 1, False),
    "timestamp-request": (13, 0, True),
    "timestamp-reply": (14, 0, True),
    "address-mask-request": (17, 0, False),
    "address-mask-reply": (18, 0, False),
}

ICMPV6_TYPES = {
    # "type": (type, code, backend omit code)
    "destination-unreachable": (1, 0, True),
    "no-route": (1, 0, False),
    "communication-prohibited": (1, 1, False),
    "beyond-scope": (1, 2, False),
    "address-unreachable": (1, 3, False),
    "port-unreachable": (1, 4, False),
    "failed-policy": (1, 5, False),
    "reject-route": (1, 6, False),
    "packet-too-big": (2, 0, True),
    "time-exceeded": (3, 0, True),
    "ttl-zero-during-transit": (3, 0, False),
    "ttl-zero-during-reassembly": (3, 1, False),
    "parameter-problem": (4, 0, True),
    "bad-header": (4, 0, False),
    "unknown-header-type": (4, 1, False),
    "unknown-option": (4, 2, False),
    "echo-request": (128, 0, True),
    "ping": (128, 0, True),
    "echo-reply": (129, 0, True),
    "pong": (129, 0, True),
    "router-solicitation": (133, 0, False),
    "router-advertisement": (134, 0, False),
    "neighbour-solicitation": (135, 0, False),
    "neigbour-solicitation": (135, 0, False),
    "neighbour-advertisement": (136, 0, False),
    "neigbour-advertisement": (136, 0, False),
    "redirect": (137, 0, False),
    # MLD is RFC-2710
    "mld-listener-query": (130, 0, True),
    "mld-listener-report": (131, 0, True),
    "mld-listener-done": (132, 0, True),
    # MLDv2 is RFC-9777
    "mld2-listener-report": (143, 0, True),
}


def check_icmp_name(_name):
    if _name in ICMP_TYPES:
        return True
    return False


def check_icmp_type_code(_type, _code):
    if (_type, _code) in ICMP_TYPES.values():
        return True
    return False


def check_icmpv6_name(_name):
    if _name in ICMPV6_TYPES:
        return True
    return False


def check_icmpv6_type_code(_type, _code):
    if (_type, _code) in ICMPV6_TYPES.values():
        return True
    return False
