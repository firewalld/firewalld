# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2011-2016 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>

"""Base firewall settings"""

DEFAULT_ZONE_TARGET = "{chain}_{zone}"
DEFAULT_POLICY_TARGET = "CONTINUE"
DEFAULT_POLICY_PRIORITY = -1
DEFAULT_ZONE_PRIORITY = 0

ZONE_TARGETS = ["ACCEPT", "%%REJECT%%", "DROP", DEFAULT_ZONE_TARGET, "default"]

POLICY_TARGETS = ["ACCEPT", "REJECT", "DROP", "CONTINUE"]

SHORTCUTS = {
    "PREROUTING": "PRE",
    "POSTROUTING": "POST",
    "INPUT": "IN",
    "FORWARD": "FWD",
    "OUTPUT": "OUT",
}

REJECT_TYPES = {
    "ipv4": [
        "icmp-host-prohibited",
        "host-prohib",
        "icmp-net-unreachable",
        "net-unreach",
        "icmp-host-unreachable",
        "host-unreach",
        "icmp-port-unreachable",
        "port-unreach",
        "icmp-proto-unreachable",
        "proto-unreach",
        "icmp-net-prohibited",
        "net-prohib",
        "tcp-reset",
        "tcp-rst",
        "icmp-admin-prohibited",
        "admin-prohib",
    ],
    "ipv6": [
        "icmp6-adm-prohibited",
        "adm-prohibited",
        "icmp6-no-route",
        "no-route",
        "icmp6-addr-unreachable",
        "addr-unreach",
        "icmp6-port-unreachable",
        "port-unreach",
        "tcp-reset",
    ],
}

# ipset types that can be used as a source in zones
# The match-set option will be src or src,src according to the
# dimension of the ipset.
SOURCE_IPSET_TYPES = [
    "hash:ip",
    "hash:ip,port",
    "hash:ip,mark",
    "hash:net",
    "hash:net,port",
    "hash:net,iface",
    "hash:mac",
]
