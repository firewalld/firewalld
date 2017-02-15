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
from firewall.core.ipset import remove_default_create_options as rm_def_cr_opts
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

    def _error2warning(self, f, name, *args):
        # transform errors into warnings
        try:
            f(name, *args)
        except FirewallError as error:
            msg = str(error)
            log.warning("%s: %s" % (name, msg))

    def add_ipset(self, obj):
        if obj.type not in self._fw.ipset_supported_types:
            raise FirewallError(errors.INVALID_TYPE,
                                "'%s' is not supported by ipset." % obj.type)
        self._ipsets[obj.name] = obj

    def remove_ipset(self, name, keep=False):
        obj = self._ipsets[name]
        if obj.applied and not keep:
            try:
                self._fw.ipset_backend.destroy(name)
            except Exception as msg:
                log.error("Failed to destroy ipset '%s'" % name)
                log.error(msg)
        else:
            log.debug1("Keeping ipset '%s' because of timeout option", name)
        del self._ipsets[name]

    def apply_ipsets(self):
        active = self._fw.ipset_backend.get_active_terse()

        for name in self.get_ipsets():
            obj = self._ipsets[name]
            obj.applied = False

            log.debug1("Applying ipset '%s'" % name)

            if name in active and ("timeout" not in obj.options or \
                                   obj.options["timeout"] == "0" or \
                                   obj.type != active[name][0] or \
                                   rm_def_cr_opts(obj.options) != \
                                   active[name][1]):
                try:
                    self._fw.ipset_backend.destroy(name)
                except Exception as msg:
                    log.error("Failed to destroy ipset '%s'" % name)
                    log.error(msg)

            if self._fw.individual_calls():
                try:
                    self._fw.ipset_backend.create(obj.name, obj.type, obj.options)
                except Exception as msg:
                    log.error("Failed to create ipset '%s'" % obj.name)
                    log.error(msg)
                else:
                    obj.applied = True
                    if "timeout" not in obj.options or \
                       obj.options["timeout"] != "0":
                        # no entries visible for ipsets with timeout
                        continue

                for entry in obj.entries:
                    try:
                        self._fw.ipset_backend.add(obj.name, entry)
                    except Exception as msg:
                        log.error("Failed to add entry '%s' to ipset '%s'" % \
                                  (entry, obj.name))
                        log.error(msg)
            else:
                try:
                    self._fw.ipset_backend.restore(obj.name, obj.type,
                                                   obj.entries, obj.options,
                                                   None)
                except Exception as msg:
                    log.error("Failed to create ipset '%s'" % obj.name)
                    log.error(msg)
                else:
                    obj.applied = True

    # TYPE

    def get_type(self, name):
        return self.get_ipset(name, applied=True).type

    # DIMENSION
    def get_dimension(self, name):
        return len(self.get_ipset(name, applied=True).type.split(","))

    # APPLIED

    def is_applied(self, name):
        return self.get_ipset(name).applied == True

    def check_applied(self, name):
        obj = self.get_ipset(name)
        self.check_applied_obj(obj)

    def check_applied_obj(self, obj):
        if not obj.applied:
            raise FirewallError(
                errors.NOT_APPLIED, obj.name)

    # OPTIONS

    def get_family(self, name):
        obj = self.get_ipset(name, applied=True)
        if "family" in obj.options:
            if obj.options["family"] == "inet6":
                return "ipv6"
        return "ipv4"

    # ENTRIES

    def __entry_id(self, entry):
        return entry

    def __entry(self, enable, name, entry):
        pass

    def add_entry(self, name, entry):
        obj = self.get_ipset(name, applied=True)
        if "timeout" in obj.options and obj.options["timeout"] != "0":
            # no entries visible for ipsets with timeout
            raise FirewallError(errors.IPSET_WITH_TIMEOUT, name)

        IPSet.check_entry(entry, obj.options, obj.type)
        if entry in obj.entries:
            raise FirewallError(errors.ALREADY_ENABLED,
                                "'%s' already is in '%s'" % (entry, name))

        try:
            self._fw.ipset_backend.add(obj.name, entry)
        except Exception as msg:
            log.error("Failed to add entry '%s' to ipset '%s'" % \
                      (entry, obj.name))
            log.error(msg)
        else:
            if "timeout" not in obj.options or obj.options["timeout"] == "0":
                # no entries visible for ipsets with timeout
                obj.entries.append(entry)

    def remove_entry(self, name, entry):
        obj = self.get_ipset(name, applied=True)
        if "timeout" in obj.options and obj.options["timeout"] != "0":
            # no entries visible for ipsets with timeout
            raise FirewallError(errors.IPSET_WITH_TIMEOUT, name)

        # no entry check for removal
        if entry not in obj.entries:
            raise FirewallError(errors.NOT_ENABLED,
                                "'%s' not in '%s'" % (entry, name))
        try:
            self._fw.ipset_backend.delete(obj.name, entry)
        except Exception as msg:
            log.error("Failed to remove entry '%s' from ipset '%s'" % \
                      (entry, obj.name))
            log.error(msg)
        else:
            if "timeout" not in obj.options or obj.options["timeout"] == "0":
                # no entries visible for ipsets with timeout
                obj.entries.remove(entry)

    def query_entry(self, name, entry):
        obj = self.get_ipset(name, applied=True)
        if "timeout" in obj.options and obj.options["timeout"] != "0":
            # no entries visible for ipsets with timeout
            raise FirewallError(errors.IPSET_WITH_TIMEOUT, name)

        return entry in obj.entries

    def get_entries(self, name):
        obj = self.get_ipset(name, applied=True)
        return obj.entries

    def set_entries(self, name, entries):
        obj = self.get_ipset(name, applied=True)
        if "timeout" in obj.options and obj.options["timeout"] != "0":
            # no entries visible for ipsets with timeout
            raise FirewallError(errors.IPSET_WITH_TIMEOUT, name)

        for entry in entries:
            IPSet.check_entry(entry, obj.options, obj.type)
        obj.entries = entries

        if self._fw.individual_calls():
            try:
                self._fw.ipset_backend.flush(obj.name)
            except Exception as msg:
                log.error("Failed to flush ipset '%s'" % obj.name)
                log.error(msg)
            else:
                obj.applied = True

            for entry in obj.entries:
                try:
                    self._fw.ipset_backend.add(obj.name, entry)
                except Exception as msg:
                    log.error("Failed to add entry '%s' to ipset '%s'" % \
                              (entry, obj.name))
                    log.error(msg)
        else:
            try:
                self._fw.ipset_backend.flush(obj.name)
            except Exception as msg:
                log.error("Failed to flush ipset '%s'" % obj.name)
                log.error(msg)
            else:
                obj.applied = True

            try:
                self._fw.ipset_backend.restore(obj.name, obj.type, obj.entries,
                                               obj.options, None)
            except Exception as msg:
                log.error("Failed to create ipset '%s'" % obj.name)
                log.error(msg)
            else:
                obj.applied = True

        return
