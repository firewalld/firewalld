# -*- coding: utf-8 -*-
#
# Copyright (C) 2011,2012 Red Hat, Inc.
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

from ipXtables import ip4tables_available_tables, ip6tables_available_tables

DEFAULT_ZONE_TARGET = "{chain}_{zone}"
ZONE_TARGETS = [ "ACCEPT", "%%REJECT%%", "DROP", DEFAULT_ZONE_TARGET ]

SHORTCUTS = {
    "PREROUTING": "PRE",
    "POSTROUTING": "POST",
    "INPUT": "IN",
    "FORWARD_IN": "FWDI",
    "FORWARD_OUT": "FWDO",
    "OUTPUT": "OUT",
}

INTERFACE_ZONE_OPTS = {
    "PREROUTING": "-i",
    "POSTROUTING": "-o",
    "INPUT": "-i",
    "FORWARD_IN": "-i",
    "FORWARD_OUT": "-o",
    "OUTPUT": "-o",
}

mangle = []
if "mangle" in ip4tables_available_tables:
    mangle.append("ipv4")
if "mangle" in ip6tables_available_tables:
    mangle.append("ipv6")

nat = []
if "nat" in ip4tables_available_tables:
    nat.append("ipv4")
else:
    if "ipv4" in mangle:
        mangle.remove("ipv4")
if "nat" in ip6tables_available_tables:
    nat.append("ipv6")
else:
    if "ipv6" in mangle:
        mangle.remove("ipv6")

ZONE_CHAINS = {
    "filter": {
        "INPUT": [ "ipv4", "ipv6" ],
        "FORWARD_IN": [ "ipv4", "ipv6" ],
        "FORWARD_OUT": [ "ipv4", "ipv6" ],
        },
    "nat": {
        "PREROUTING": nat,
        "POSTROUTING": nat,
        },
    "mangle": {
        "PREROUTING": mangle,
        },
}
