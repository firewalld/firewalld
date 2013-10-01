# -*- coding: utf-8 -*-
#
# Copyright (C) 2010-2012 Red Hat, Inc.
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

from firewall.core.prog import runProg
from firewall.core.logger import log

class modules:
    def __init__(self):
        self._command = "/sbin/modprobe"

    def loaded_modules(self):
        modules = [ ]
        deps = { }
        with open("/proc/modules", "r") as f:
            for line in f.xreadlines():
                if not line:
                    break
                line = line.strip()
                splits = line.split()
                modules.append(splits[0])
                if splits[3] != "-":
                    deps[splits[0]] = splits[3].split(",")[:-1]
                else:
                    deps[splits[0]] = [ ]

        return modules, deps

    def load_module(self, module):
        log.debug2("%s: %s %s", self.__class__, self._command, module)
        return runProg(self._command, [ module ])

    def unload_module(self, module):
        log.debug2("%s: %s -r %s", self.__class__, self._command, module)
        return runProg(self._command, [ "-r", module ])

    def get_deps(self, module, deps, ret):
        if module not in deps:
            return
        for mod in deps[module]:
            self.get_deps(mod, deps, ret)
            if mod not in ret:
                ret.append(mod)
        if module not in ret:
            ret.append(module)

    def get_firewall_modules(self):
        modules = [ ]
        (mods, deps) = self.loaded_modules()

        for mod in [ "ip_tables", "ip6_tables", "nf_conntrack", "ebtables" ]:
            self.get_deps(mod, deps, modules)

        for mod in mods:
            if mod.startswith("iptable_") or mod.startswith("ip6table_") or \
                    mod.startswith("nf_") or mod.startswith("xt_") or \
                    mod.startswith("ipt_") or mod.startswith("ip6t_") :
                self.get_deps(mod, deps, modules)
        return modules

    def unload_modules(self, modules):
        (mods, deps) = self.loaded_modules()

        to_unload = [ ]
        for module in modules:
            self.get_deps(module, deps, to_unload)

        for module in to_unload:
            (status, ret) = self.unload_module(module)
            if status != 0:
                raise ValueError("Unable to unload module %s: %s" % (module,
                                                                     ret))

    def unload_firewall_modules(self):
        for module in self.get_firewall_modules():
            (status, ret) = self.unload_module(module)
            if status != 0:
                log.debug1("Failed to unload module '%s': %s" %(module, ret))

    def get_dep_modules(self, module):
        (mods, deps) = self.loaded_modules()

        dependant = [ ]
        self.get_deps(module, deps, dependant)

        return dependant
