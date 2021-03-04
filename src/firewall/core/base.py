# -*- coding: utf-8 -*-
#
# Copyright (C) 2011-2016 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

"""Base firewall settings"""

DEFAULT_ZONE_TARGET = "{chain}_{zone}"
DEFAULT_POLICY_TARGET = "CONTINUE"
DEFAULT_POLICY_PRIORITY = -1

ZONE_TARGETS = [ "ACCEPT", "%%REJECT%%", "DROP", DEFAULT_ZONE_TARGET,
                 "default" ]

POLICY_TARGETS = [ "ACCEPT", "REJECT", "DROP", "CONTINUE" ]

SHORTCUTS = {
    "PREROUTING": "PRE",
    "POSTROUTING": "POST",
    "INPUT": "IN",
    "FORWARD": "FWD",
    "OUTPUT": "OUT",
}

REJECT_TYPES = {
    "ipv4": [ "icmp-host-prohibited", "host-prohib", "icmp-net-unreachable",
              "net-unreach", "icmp-host-unreachable", "host-unreach",
              "icmp-port-unreachable", "port-unreach", "icmp-proto-unreachable",
              "proto-unreach", "icmp-net-prohibited", "net-prohib", "tcp-reset",
              "tcp-rst", "icmp-admin-prohibited", "admin-prohib" ],
    "ipv6": [ "icmp6-adm-prohibited", "adm-prohibited", "icmp6-no-route",
              "no-route", "icmp6-addr-unreachable", "addr-unreach",
              "icmp6-port-unreachable", "port-unreach", "tcp-reset" ]
}

# ipset types that can be used as a source in zones
# The match-set option will be src or src,src according to the
# dimension of the ipset.
SOURCE_IPSET_TYPES = [
    "hash:ip", "hash:ip,port", "hash:ip,mark",
    "hash:net", "hash:net,port", "hash:net,iface",
    "hash:mac"
]
