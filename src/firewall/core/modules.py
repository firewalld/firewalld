# -*- coding: utf-8 -*-
#
# Copyright (C) 2010-2016 Red Hat, Inc.
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

"""modules backend"""

__all__ = [ "modules" ]

from firewall.core.prog import runProg
from firewall.core.logger import log
from firewall.config import COMMANDS

class modules(object):
    def __init__(self):
        self._load_command = COMMANDS["modprobe"]
        # Use rmmod instead of modprobe -r (RHBZ#1031102)
        self._unload_command = COMMANDS["rmmod"]

    def __repr__(self):
        return '%s' % (self.__class__)

    def loaded_modules(self):
        """ get all loaded kernel modules and their dependencies """
        mods = [ ]
        deps = { }
        with open("/proc/modules", "r") as f:
            for line in f:
                if not line:
                    break
                line = line.strip()
                splits = line.split()
                mods.append(splits[0])
                if splits[3] != "-":
                    deps[splits[0]] = splits[3].split(",")[:-1]
                else:
                    deps[splits[0]] = [ ]

        return mods, deps # [loaded modules], {module:[dependants]}

    def load_module(self, module):
        log.debug2("%s: %s %s", self.__class__, self._load_command, module)
        return runProg(self._load_command, [ module ])

    def unload_module(self, module):
        log.debug2("%s: %s %s", self.__class__, self._unload_command, module)
        return runProg(self._unload_command, [ module ])

    def get_deps(self, module, deps, ret):
        """ get all dependants of a module """
        if module not in deps:
            return
        for mod in deps[module]:
            self.get_deps(mod, deps, ret)
            if mod not in ret:
                ret.append(mod)
        if module not in ret:
            ret.append(module)

    def get_firewall_modules(self):
        """ get all loaded firewall-related modules """
        mods = [ ]
        (mods2, deps) = self.loaded_modules()

        self.get_deps("nf_conntrack", deps, mods)
        # these modules don't have dependants listed in /proc/modules
        for bad_bad_module in ["nf_conntrack_ipv4", "nf_conntrack_ipv6"]:
            if bad_bad_module in mods:
                # move them to end of list, so we'll remove them later
                mods.remove(bad_bad_module)
                mods.insert(-1, bad_bad_module)

        for mod in mods2:
            if mod in [ "ip_tables", "ip6_tables", "ebtables" ] or \
               mod.startswith("iptable_") or mod.startswith("ip6table_") or \
               mod.startswith("nf_") or mod.startswith("xt_") or \
               mod.startswith("ipt_") or mod.startswith("ip6t_") :
                self.get_deps(mod, deps, mods)
        return mods

    def unload_firewall_modules(self):
        """ unload all firewall-related modules """
        for module in self.get_firewall_modules():
            (status, ret) = self.unload_module(module)
            if status != 0:
                log.debug1("Failed to unload module '%s': %s" %(module, ret))
