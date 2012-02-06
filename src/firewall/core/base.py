#
# Copyright (C) 2011 Red Hat, Inc.
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

DEFAULT_ZONE_TARGET = "{chain}_ZONE_{zone}"

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

INTERFACE_ZONE_SRC = {
    "PREROUTING": "PREROUTING",
    "POSTROUTING": "POSTROUTING",
    "INPUT": "INPUT",
    "FORWARD_IN": "FORWARD",
    "FORWARD_OUT": "FORWARD",
    "OUTPUT": "OUTPUT",
}

CHAINS = {
    "raw": [ "PREROUTING", "OUTPUT" ],
    "mangle": [ "PREROUTING", "POSTROUTING", "INPUT", "OUTPUT", "FORWARD" ],
    "nat": [ "PREROUTING", "POSTROUTING", "OUTPUT" ],
    "filter": [ "INPUT", "OUTPUT", "FORWARD" ],
}

REJECT_TYPE = {
    "ipv4": "icmp-host-prohibited",
    "ipv6": "icmp6-adm-prohibited",
    "eb": None,
}

MANGLE_RULES = [ ]
for chain in CHAINS["mangle"]:
    MANGLE_RULES.append("-N %s_direct" % chain)
    MANGLE_RULES.append("-I %s 1 -j %s_direct" % (chain, chain))

    if chain == "PREROUTING":
        MANGLE_RULES.append("-N %s_ZONES" % chain)
        MANGLE_RULES.append("-I %s 2 -j %s_ZONES" % (chain, chain))

NAT_RULES = [ ]
for chain in CHAINS["nat"]:
    NAT_RULES.append("-N %s_direct" % chain)
    NAT_RULES.append("-I %s 1 -j %s_direct" % (chain, chain))

    if chain in [ "PREROUTING", "POSTROUTING" ]:
        NAT_RULES.append("-N %s_ZONES" % chain)
        NAT_RULES.append("-I %s 2 -j %s_ZONES" % (chain, chain))

FILTER_RULES = [
    "-N INPUT_direct",
    "-N INPUT_ZONES",

    "-I INPUT 1 -m conntrack --ctstate INVALID -j %%REJECT%%",
    "-I INPUT 2 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
    "-I INPUT 3 -i lo -j ACCEPT",
    "-I INPUT 4 -j INPUT_direct",
    "-I INPUT 5 -j INPUT_ZONES",
    "-I INPUT 6 -p icmp -j ACCEPT",
    "-I INPUT 7 -j %%REJECT%%",

    "-N FORWARD_direct",
    "-N FORWARD_ZONES",

    "-I FORWARD 1 -m conntrack --ctstate INVALID -j %%REJECT%%",
    "-I FORWARD 2 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
    "-I FORWARD 3 -i lo -j ACCEPT",
    "-I FORWARD 4 -j FORWARD_direct",
    "-I FORWARD 5 -j FORWARD_ZONES",
    "-I FORWARD 6 -p icmp -j ACCEPT",
    "-I FORWARD 7 -j %%REJECT%%",

    "-N OUTPUT_direct",

    "-I OUTPUT 1 -j OUTPUT_direct",
]
