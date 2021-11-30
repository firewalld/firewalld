# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2016 Red Hat, Inc.
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

"""ipset backend"""

__all__ = [ "FirewallIPSet" ]

from firewall.core.logger import log
from firewall.core.ipset import remove_default_create_options as rm_def_cr_opts, \
                                normalize_ipset_entry, check_entry_overlaps_existing, \
                                check_for_overlapping_entries
from firewall.core.io.ipset import IPSet
from firewall import errors
from firewall.errors import FirewallError

class FirewallIPSet(object):
    def __init__(self, fw):
        self._fw = fw
        self._ipsets = { }

    def __repr__(self):
        return '%s(%r)' % (self.__class__, self._ipsets)

    # ipsets

    def cleanup(self):
        self._ipsets.clear()

    def check_ipset(self, name):
        if name not in self.get_ipsets():
            raise FirewallError(errors.INVALID_IPSET, name)

    def query_ipset(self, name):
        return name in self.get_ipsets()

    def get_ipsets(self):
        return sorted(self._ipsets.keys())

    def has_ipsets(self):
        return len(self._ipsets) > 0

    def get_ipset(self, name, applied=False):
        self.check_ipset(name)
        obj = self._ipsets[name]
        if applied:
            self.check_applied_obj(obj)
        return obj

    def backends(self):
        backends = []
        if self._fw.nftables_enabled:
            backends.append(self._fw.nftables_backend)
        if self._fw.ipset_enabled:
            backends.append(self._fw.ipset_backend)
        return backends

    def add_ipset(self, obj):
        if obj.type not in self._fw.ipset_supported_types:
            raise FirewallError(errors.INVALID_TYPE,
                                "'%s' is not supported by ipset." % obj.type)
        self._ipsets[obj.name] = obj

    def remove_ipset(self, name, keep=False):
        obj = self._ipsets[name]
        if obj.applied and not keep:
            try:
                for backend in self.backends():
                    backend.set_destroy(name)
            except Exception as msg:
                raise FirewallError(errors.COMMAND_FAILED, msg)
        else:
            log.debug1("Keeping ipset '%s' because of timeout option", name)
        del self._ipsets[name]

    def apply_ipset(self, name):
        obj = self._ipsets[name]

        for backend in self.backends():
            if backend.name == "ipset":
                active = backend.set_get_active_terse()

                if name in active and ("timeout" not in obj.options or \
                                       obj.options["timeout"] == "0" or \
                                       obj.type != active[name][0] or \
                                       rm_def_cr_opts(obj.options) != \
                                       active[name][1]):
                    try:
                        backend.set_destroy(name)
                    except Exception as msg:
                        raise FirewallError(errors.COMMAND_FAILED, msg)

            if self._fw._individual_calls:
                try:
                    backend.set_create(obj.name, obj.type, obj.options)
                except Exception as msg:
                    raise FirewallError(errors.COMMAND_FAILED, msg)
                else:
                    obj.applied = True
                    if "timeout" in obj.options and \
                       obj.options["timeout"] != "0":
                        # no entries visible for ipsets with timeout
                        continue

                try:
                    backend.set_flush(obj.name)
                except Exception as msg:
                    raise FirewallError(errors.COMMAND_FAILED, msg)

                for entry in obj.entries:
                    try:
                        backend.set_add(obj.name, entry)
                    except Exception as msg:
                        raise FirewallError(errors.COMMAND_FAILED, msg)
            else:
                try:
                    backend.set_restore(obj.name, obj.type,
                                                   obj.entries, obj.options,
                                                   None)
                except Exception as msg:
                    raise FirewallError(errors.COMMAND_FAILED, msg)
                else:
                    obj.applied = True

    def apply_ipsets(self):
        for name in self.get_ipsets():
            obj = self._ipsets[name]
            obj.applied = False

            log.debug1("Applying ipset '%s'" % name)
            self.apply_ipset(name)

    def flush(self):
        for backend in self.backends():
            # nftables sets are part of the normal firewall ruleset.
            if backend.name == "nftables":
                continue
            for ipset in self.get_ipsets():
                try:
                    self.check_applied(ipset)
                    backend.set_destroy(ipset)
                except FirewallError as msg:
                    if msg.code != errors.NOT_APPLIED:
                        raise msg

    # TYPE

    def get_type(self, name, applied=True):
        return self.get_ipset(name, applied=applied).type

    # DIMENSION
    def get_dimension(self, name):
        return len(self.get_ipset(name, applied=True).type.split(","))

    def check_applied(self, name):
        obj = self.get_ipset(name)
        self.check_applied_obj(obj)

    def check_applied_obj(self, obj):
        if not obj.applied:
            raise FirewallError(
                errors.NOT_APPLIED, obj.name)

    # OPTIONS

    def get_family(self, name, applied=True):
        obj = self.get_ipset(name, applied=applied)
        if "family" in obj.options:
            if obj.options["family"] == "inet6":
                return "ipv6"
        return "ipv4"

    # ENTRIES

    def add_entry(self, name, entry):
        obj = self.get_ipset(name, applied=True)
        entry = normalize_ipset_entry(entry)

        IPSet.check_entry(entry, obj.options, obj.type)
        if entry in obj.entries:
            raise FirewallError(errors.ALREADY_ENABLED,
                                "'%s' already is in '%s'" % (entry, name))
        check_entry_overlaps_existing(entry, obj.entries)

        try:
            for backend in self.backends():
                backend.set_add(obj.name, entry)
        except Exception as msg:
            raise FirewallError(errors.COMMAND_FAILED, msg)
        else:
            if "timeout" not in obj.options or obj.options["timeout"] == "0":
                # no entries visible for ipsets with timeout
                obj.entries.append(entry)

    def remove_entry(self, name, entry):
        obj = self.get_ipset(name, applied=True)
        entry = normalize_ipset_entry(entry)

        # no entry check for removal
        if entry not in obj.entries:
            raise FirewallError(errors.NOT_ENABLED,
                                "'%s' not in '%s'" % (entry, name))
        try:
            for backend in self.backends():
                backend.set_delete(obj.name, entry)
        except Exception as msg:
            raise FirewallError(errors.COMMAND_FAILED, msg)
        else:
            if "timeout" not in obj.options or obj.options["timeout"] == "0":
                # no entries visible for ipsets with timeout
                obj.entries.remove(entry)

    def query_entry(self, name, entry):
        obj = self.get_ipset(name, applied=True)
        entry = normalize_ipset_entry(entry)
        if "timeout" in obj.options and obj.options["timeout"] != "0":
            # no entries visible for ipsets with timeout
            raise FirewallError(errors.IPSET_WITH_TIMEOUT, name)

        return entry in obj.entries

    def get_entries(self, name):
        obj = self.get_ipset(name, applied=True)
        return obj.entries

    def set_entries(self, name, entries):
        obj = self.get_ipset(name, applied=True)

        check_for_overlapping_entries(entries)

        for entry in entries:
            IPSet.check_entry(entry, obj.options, obj.type)
        if "timeout" not in obj.options or obj.options["timeout"] == "0":
            # no entries visible for ipsets with timeout
            obj.entries = entries

        try:
            for backend in self.backends():
                backend.set_flush(obj.name)
        except Exception as msg:
            raise FirewallError(errors.COMMAND_FAILED, msg)
        else:
            obj.applied = True

        try:
            for backend in self.backends():
                if self._fw._individual_calls:
                    for entry in obj.entries:
                        backend.set_add(obj.name, entry)
                else:
                    backend.set_restore(obj.name, obj.type, obj.entries,
                                                   obj.options, None)
        except Exception as msg:
            raise FirewallError(errors.COMMAND_FAILED, msg)
        else:
            obj.applied = True

        return
