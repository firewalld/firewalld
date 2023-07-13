# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2017 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>

ICMP_TYPES = {
    "echo-reply": "0/0",
    "pong": "0/0",
    "network-unreachable": "3/0",
    "host-unreachable": "3/1",
    "protocol-unreachable": "3/2",
    "port-unreachable": "3/3",
    "fragmentation-needed": "3/4",
    "source-route-failed": "3/5",
    "network-unknown": "3/6",
    "host-unknown": "3/7",
    "network-prohibited": "3/9",
    "host-prohibited": "3/10",
    "TOS-network-unreachable": "3/11",
    "TOS-host-unreachable": "3/12",
    "communication-prohibited": "3/13",
    "host-precedence-violation": "3/14",
    "precedence-cutoff": "3/15",
    "source-quench": "4/0",
    "network-redirect": "5/0",
    "host-redirect": "5/1",
    "TOS-network-redirect": "5/2",
    "TOS-host-redirect": "5/3",
    "echo-request": "8/0",
    "ping": "8/0",
    "router-advertisement": "9/0",
    "router-solicitation": "10/0",
    "ttl-zero-during-transit": "11/0",
    "ttl-zero-during-reassembly": "11/1",
    "ip-header-bad": "12/0",
    "required-option-missing": "12/1",
    "timestamp-request": "13/0",
    "timestamp-reply": "14/0",
    "address-mask-request": "17/0",
    "address-mask-reply": "18/0",
}

ICMPV6_TYPES = {
    "no-route": "1/0",
    "communication-prohibited": "1/1",
    "address-unreachable": "1/3",
    "port-unreachable": "1/4",
    "packet-too-big": "2/0",
    "ttl-zero-during-transit": "3/0",
    "ttl-zero-during-reassembly": "3/1",
    "bad-header": "4/0",
    "unknown-header-type": "4/1",
    "unknown-option": "4/2",
    "echo-request": "128/0",
    "ping": "128/0",
    "echo-reply": "129/0",
    "pong": "129/0",
    "router-solicitation": "133/0",
    "router-advertisement": "134/0",
    "neighbour-solicitation": "135/0",
    "neigbour-solicitation": "135/0",
    "neighbour-advertisement": "136/0",
    "neigbour-advertisement": "136/0",
    "redirect": "137/0",
}


def check_icmp_name(_name):
    if _name in ICMP_TYPES:
        return True
    return False


def check_icmp_type(_type):
    if _type in ICMP_TYPES.values():
        return True
    return False


def check_icmpv6_name(_name):
    if _name in ICMPV6_TYPES:
        return True
    return False


def check_icmpv6_type(_type):
    if _type in ICMPV6_TYPES.values():
        return True
    return False
