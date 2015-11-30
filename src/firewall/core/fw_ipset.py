# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Red Hat, Inc.
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


from firewall.core.base import *
from firewall.core.logger import log
from firewall.functions import portStr, checkIPnMask, checkIP6nMask, \
    checkProtocol, enable_ip_forwarding, check_single_address
from firewall.errors import *
from firewall.core import ipset
from firewall.core.io.ipset import IPSet

class FirewallIPSet(object):
    def __init__(self, fw):
        self._fw = fw
        self._ipsets = { }

    def __repr__(self):
        return '%s(%r)' % (self.__class__, self._ipsets)

    def cleanup(self):
        for ipset in self.get_ipsets():
            obj = self._ipsets[ipset]
            if obj.applied:
                try:
                    self._fw._ipset.destroy(obj.name)
                except Exception as msg:
                    log.error("Failed to destroy ipset '%s'" % obj.name)
                    log.error(msg)

        self._ipsets.clear()

    # ipsets

    def check_ipset(self, ipset):
        if ipset not in self.get_ipsets():
            raise FirewallError(INVALID_IPSET, ipset)

    def get_ipsets(self):
        return sorted(self._ipsets.keys())

    def get_ipset(self, name):
        self.check_ipset(name)
        return self._ipsets[name]

    def _error2warning(self, f, name, *args):
        # transform errors into warnings
        try:
            f(name, *args)
        except FirewallError as error:
            msg = str(error)
            log.warning("%s: %s" % (name, msg))

    def add_ipset(self, obj):
        self._ipsets[obj.name] = obj

    def remove_ipset(self, name):
        obj = self._ipsets[name]
        if obj.applied:
            self._fw._ipset.destroy(name)
        del self._ipsets[name]

    def apply_ipsets(self):
        for ipset in self.get_ipsets():
            obj = self._ipsets[ipset]
            applied = False

            try:
                self._fw._ipset.create(obj.name, obj.type, obj.options)
            except Exception as msg:
                log.error("Failed to create ipset '%s'" % obj.name)
                log.error(msg)
            else:
                applied = True
                if "timeout" not in obj.options:
                    # no entries visible for ipsets with timeout
                    obj.applied = applied
                    continue

                for entry in obj.entries:
                    try:
                        self._fw._ipset.add(obj.name, entry)
                    except Exception as msg:
                        log.error("Failed to add entry '%s' to ipset '%s'" % \
                                  (entry, obj.name))
                        log.error(msg)

            obj.applied = applied

    # TYPE

    def get_type(self, ipset):
        return self.get_ipset(ipset).type

    # OPTIONS

    def get_family(self, ipset):
        obj = self.get_ipset(ipset)
        if "family" in obj.options:
            if obj.options["family"] == "inet6":
                return "ipv6"
        return "ipv4"

    # ENTRIES

    def __entry_id(self, entry):
        return entry

    def __entry(self, enable, ipset, entry):
        pass

    def add_entry(self, ipset, entry, sender=None):
        obj = self.get_ipset(ipset)
        if "timeout" in obj.options:
            # no entries visible for ipsets with timeout
            raise FirewallError(IPSET_WITH_TIMEOUT, ipset)

        IPSet.check_entry(entry, obj.options, obj.type)
        if entry in obj.entries:
            raise FirewallError(ALREADY_ENABLED,
                                "'%s' already is in '%s'" % (entry, ipset))

        try:
            self._fw._ipset.add(obj.name, entry)
        except Exception as msg:
            log.error("Failed to add entry '%s' to ipset '%s'" % \
                      (entry, obj.name))
            log.error(msg)
        else:
            if "timeout" not in obj.options:
                # no entries visible for ipsets with timeout
                obj.entries.append(entry)

    def remove_entry(self, ipset, entry, sender=None):
        obj = self.get_ipset(ipset)
        if "timeout" in obj.options:
            # no entries visible for ipsets with timeout
            raise FirewallError(IPSET_WITH_TIMEOUT, ipset)

        # no entry check for removal
        if entry not in obj.entries:
            raise FirewallError(NOT_ENABLED,
                                "'%s' not in '%s'" % (entry, ipset))
        try:
            self._fw._ipset.delete(obj.name, entry)
        except Exception as msg:
            log.error("Failed to remove entry '%s' from ipset '%s'" % \
                      (entry, obj.name))
            log.error(msg)
        else:
            if "timeout" not in obj.options:
                # no entries visible for ipsets with timeout
                obj.entries.remove(entry)

    def query_entry(self, ipset, entry, sender=None):
        obj = self.get_ipset(ipset)
        if "timeout" in obj.options:
            # no entries visible for ipsets with timeout
            raise FirewallError(IPSET_WITH_TIMEOUT, ipset)

        return (entry in obj.entries)

    def get_entries(self, ipset, sender=None):
        obj = self.get_ipset(ipset)
        if "timeout" in obj.options:
            # no entries visible for ipsets with timeout
            raise FirewallError(IPSET_WITH_TIMEOUT, ipset)

        return obj.entries

    def set_entries(self, ipset, entries, sender=None):
        obj = self.get_ipset(ipset)
        if "timeout" in obj.options:
            # no entries visible for ipsets with timeout
            raise FirewallError(IPSET_WITH_TIMEOUT, ipset)

        for entry in entries:
            IPSet.check_entry(entry, obj.options, obj.type)

        for entry in obj.entries:
            try:
                self._fw._ipset.remove(obj.name, entry)
            except Exception as msg:
                log.error("Failed to remove entry '%s' from ipset '%s'" % \
                          (entry, obj.name))
                log.error(msg)
        obj.entries.clear()

        for entry in entries:
            try:
                self._fw._ipset.add(obj.name, entry)
            except Exception as msg:
                log.error("Failed to remove entry '%s' from ipset '%s'" % \
                          (entry, obj.name))
                log.error(msg)
            else:
                obj.entries.append(entry)
