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

from firewall.config import *
from firewall.core import ipXtables
from firewall.core import ebtables
from firewall.core import modules
from firewall.core.fw_zone import FirewallZone
from firewall.core.fw_direct import FirewallDirect
from firewall.core.logger import log
from firewall.core.io.firewalld_conf import firewalld_conf
from firewall.core.io.zone import zone_reader
from firewall.errors import *

############################################################################
#
# class Firewall
#
############################################################################

class Firewall:
    def __init__(self):
        self._firewalld_conf = firewalld_conf(FIREWALLD_CONF)

        # TODO: check if ipv4 is enabled:
        self._ip4tables = ipXtables.ip4tables()
        # TODO: check if ipv6 is enabled:
        self._ip6tables = ipXtables.ip6tables()

        self._ebtables = ebtables.ebtables()

        self._modules = modules.modules()

        self.zone = FirewallZone(self)
        self.direct = FirewallDirect(self)

        self.__init_vars()

    def __init_vars(self):
        self._initialized = False
        self._panic = False
        self._default_zone = "public" # initial default, will be overloaded by firewalld.conf
        self._module_refcount = { }
        self._marks = [ ]
        self._min_mark = 100 # initial default, will be overloaded by firewalld.conf

    def start(self):
        # initialize firewall
        self._flush()
        self._set_policy("ACCEPT")

        # load firewalld config
        log.debug1("Loading firewalld config file '%s'", FIREWALLD_CONF)
        try:
            self._firewalld_conf.read()
        except Exception, msg:
            log.error("Failed to open firewalld config file '%s': %s",
                      FIREWALLD_CONF, msg)
        else:
            if self._firewalld_conf.get("DefaultZone"):
                self._default_zone = self._firewalld_conf.get("DefaultZone")
            if self._firewalld_conf.get("MinimalMark"):
                mark = self._firewalld_conf.get("MinimalMark")
                try:
                    self._min_mark = int(mark)
                except Exception, msg:
                    log.error("MinimalMark %s is not valid, using default "
                              "value %d", mark, self._min_mark)

        # apply default rules
        self._apply_default_rules()

        # load zone files
        path = FIREWALLD_ZONES
        if os.path.isdir(path):
            for filename in os.listdir(path):
                if filename.endswith(".xml"):
                    log.debug1("Loading zone file '%s/%s'", path, filename)
                    try:
                        obj = zone_reader(filename, path)
                        self.zone.add_zone(obj)
                    except FirewallError, msg:
                        log.error("Failed to load zone file '%s/%s': %s", path,
                                  filename, msg)
                    except Exception, msg:
                        log.error("Failed to load zone file '%s/%s':", path,
                                  filename)
                        log.exception()

        if len(self.zone.get_zones()) == 0:
            log.fatal("No zones found.")

        # check if default_zone is a valid zone
        if self._default_zone not in self.zone.get_zones():
            if "public" in self.zone.get_zones():
                zone = "public"
            elif "external" in self.zone.get_zones():
                zone = "external"
            else:
                zone = "block" # block is a base zone, therefore it has to exist
                
            log.error("Default zone '%s' is not valid. Using '%s'.",
                      self._default_zone, zone)
            self._default_zone = zone
        else:
            log.debug1("Using default zone '%s'", self._default_zone)

        self._initialized = True

    def stop(self):
        self.__init_vars()
        self.zone.cleanup()

        # if cleanup on exit
        self._flush()
        self._set_policy("ACCEPT")
        self._modules.unload_firewall_modules()

    # marks

    def new_mark(self):
        # return first unused mark
        i = self._min_mark
        while i in self._marks:
            i += 1
        self._marks.append(i)
        return i

    def del_mark(self, mark):
        self._marks.remove(mark)

    # handle rules, chains and modules

    def handle_rules(self, rules, enable, insert=False):
        if insert:
            append_delete = { True: "-I", False: "-D", }
        else:
            append_delete = { True: "-A", False: "-D", }

        # appends rules
        # returns None if all worked, else (cleanup rules, error message)
        i = 0
        for i in xrange(len(rules)):
            if len(rules[i]) == 3:
                (ipv, rule, insert) = rules[i]
            else:
                (ipv, rule) = rules[i]

            # drop insert rule number if it exists
            if insert and not enable and isinstance(rule[1], IntType):
                rule.pop(1)

            # run
            try:
                self.__rule(ipv, [ append_delete[enable], ] + rule)
            except Exception, msg:
                log.error(msg)
                return (rules[:i], msg) # cleanup rules and error message
        return None

    def handle_chains(self, rules, enable):
        new_delete = { True: "-N", False: "-X" }

        # appends chains
        # returns None if all worked, else (cleanup chains, error message)
        i = 0
        for i in xrange(len(rules)):
            (ipv, rule) = rules[i]
            try:
                self.__rule(ipv, [ new_delete[enable], ] + rule)
            except Exception, msg:
                log.error(msg)
                return (rules[:i], msg) # cleanup chains and error message
        return None

    def handle_modules(self, modules, enable):
        for i in xrange(len(modules)):
            module = modules[i]
            if enable:
                (status, msg) = self._modules.load_module(module)
            else:
                if self._module_refcount[module] > 1:
                    status = 0 # module referenced more then one, do not unload
                else:
                    (status, msg) = self._modules.unload_module(module)
            if status != 0:
                if enable:
                    return (modules[:i], msg) # cleanup modules and error msg
                # else: ignore cleanup

            if enable:
                self._module_refcount.setdefault(module, 0)
                self._module_refcount[module] += 1
            else:
                if module in self._module_refcount:
                     self._module_refcount[module] -= 1
                     if self._module_refcount[module] == 0:
                         del self._module_refcount[module]
        return None

    # apply default rules

    def __apply_default_rules(self, ipv):
        if ipv in [ "ipv4", "ipv6" ]:
            default_rules = ipXtables.DEFAULT_RULES
        else:
            default_rules = ebtables.DEFAULT_RULES

        for table in default_rules:
            if ipv == "ipv6" and table == "nat":
                # no nat for IPv6 for now
                continue

            prefix = [ "-t", table ]
            for rule in default_rules[table]:
                _rule = prefix + rule.split()
                self.__rule(ipv, _rule)

#                try:
#                except Exception, msg:
# TODO: better handling of init error
#                    if "Chain already exists." in msg:
#                        continue
#                    # TODO: log msg
#                    raise FirewallError, <code>

    def _apply_default_rules(self):
        for ipv in [ "ipv4", "ipv6", "eb" ]:
            self.__apply_default_rules(ipv)

    # flush and policy

    def _flush(self):
        self._ip4tables.flush()
        self._ip6tables.flush()

    def _set_policy(self, policy, which="used"):
        self._ip4tables.set_policy(policy, which)
        self._ip6tables.set_policy(policy, which)

    # internal __rule function use in handle_ functions

    def __rule(self, ipv, rule):
        # replace %%REJECT%%
        try:
            i = rule.index("%%REJECT%%")
        except:
            pass
        else:
            if ipv in [ "ipv4", "ipv6" ]:
                rule[i:i+1] = [ "REJECT", "--reject-with",
                                ipXtables.DEFAULT_REJECT_TYPE[ipv] ]
            else:
                FirewallError(EBTABLES_NO_REJECT)

        if ipv == "ipv4":
            self._ip4tables.set_rule(rule)
        elif ipv == "ipv6":
            self._ip6tables.set_rule(rule)
        elif ipv == "eb":
            self._ebtables.set_rule(rule)
        else:
            raise FirewallError(INVALID_IPV)

    # RESTART

    def reload(self):
        _panic = self._panic

        self.__init_vars()
        self.start()

        # start
        if _panic:
            self.enable_panic_mode()

    def restart(self):
        self._modules.unload_firewall_modules()
        self.reload()

    # STATUS

    def status(self):
        return (self._initialized == True)

    # PANIC MODE

    def enable_panic_mode(self):
        if self._panic:
            raise FirewallError(ALREADY_ENABLED)
        try:
            self._set_policy("DROP", "all")
        except Exception, msg:
            # TODO: log msg
            raise FirewallError(ENABLE_FAILED)
        self._panic = True

    def disable_panic_mode(self):
        if not self._panic:
            raise FirewallError(NOT_ENABLED)
        try:
            self._set_policy("ACCEPT", "all")
        except Exception, msg:
            # TODO: log msg
            raise FirewallError(DISABLE_FAILED)
        self._panic = False

    def query_panic_mode(self):
        return (self._panic == True)

    # DEFAULT ZONE

    def get_default_zone(self):
        return self._default_zone

    def set_default_zone(self, zone):
        if zone in self.zone.get_zones():
            self._default_zone = zone
            self._firewalld_conf.set("DefaultZone", zone)
            self._firewalld_conf.write()
        else:
            raise FirewallError(INVALID_ZONE)
