# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2011-2016 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>

from firewall.core.logger import log
from firewall import errors
from firewall.errors import FirewallError


class FirewallIcmpType:
    def __init__(self, fw):
        self._fw = fw
        self._icmptypes = {}

    def __repr__(self):
        return "%s(%r)" % (self.__class__, self._icmptypes)

    def cleanup(self):
        self._icmptypes.clear()

    # zones

    def get_icmptypes(self):
        return sorted(self._icmptypes.keys())

    def check_icmptype(self, icmptype):
        if icmptype not in self._icmptypes:
            raise FirewallError(errors.INVALID_ICMPTYPE, icmptype)

    def get_icmptype(self, icmptype):
        self.check_icmptype(icmptype)
        return self._icmptypes[icmptype]

    def add_icmptype(self, obj):
        orig_ipvs = obj.destination
        if len(orig_ipvs) == 0:
            orig_ipvs = ["ipv4", "ipv6"]
        for ipv in orig_ipvs:
            if ipv == "ipv4":
                if not self._fw.ip4tables_enabled and not self._fw.nftables_enabled:
                    continue
                supported_icmps = self._fw.ipv4_supported_icmp_types
            elif ipv == "ipv6":
                if not self._fw.ip6tables_enabled and not self._fw.nftables_enabled:
                    continue
                supported_icmps = self._fw.ipv6_supported_icmp_types
            else:
                supported_icmps = []
            if obj.name.lower() not in supported_icmps:
                log.info1(
                    "ICMP type '%s' is not supported by the kernel for %s."
                    % (obj.name, ipv)
                )
        self._icmptypes[obj.name] = obj

    def remove_icmptype(self, icmptype):
        self.check_icmptype(icmptype)
        del self._icmptypes[icmptype]
