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

import os.path
import copy
from firewall.config import *
from firewall import functions
from firewall.core import ipXtables
from firewall.core import ebtables
from firewall.core import modules
from firewall.core.fw_icmptype import FirewallIcmpType
from firewall.core.fw_service import FirewallService
from firewall.core.fw_zone import FirewallZone
from firewall.core.fw_direct import FirewallDirect
from firewall.core.fw_config import FirewallConfig
from firewall.core.logger import log
from firewall.core.io.firewalld_conf import firewalld_conf
from firewall.core.io.service import service_reader
from firewall.core.io.icmptype import icmptype_reader
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

        self.icmptype = FirewallIcmpType(self)
        self.service = FirewallService(self)
        self.zone = FirewallZone(self)
        self.direct = FirewallDirect(self)
        self.config = FirewallConfig(self)

        self.__init_vars()

    def __init_vars(self):
        self._state = "INIT"
        self._panic = False
        self._default_zone = "public" # initial default, will be overloaded by firewalld.conf
        self._module_refcount = { }
        self._marks = [ ]
        self._min_mark = 100 # initial default, will be overloaded by firewalld.conf
        self.cleanup_on_exit = True

    def start(self):
        # initialize firewall
        self._flush()
        self._set_policy("ACCEPT")

        # load firewalld config
        log.debug1("Loading firewalld config file '%s'", FIREWALLD_CONF)
        try:
            self._firewalld_conf.read()
        except Exception as msg:
            log.error("Failed to open firewalld config file '%s': %s",
                      FIREWALLD_CONF, msg)
        else:
            if self._firewalld_conf.get("DefaultZone"):
                self._default_zone = self._firewalld_conf.get("DefaultZone")
            if self._firewalld_conf.get("MinimalMark"):
                mark = self._firewalld_conf.get("MinimalMark")
                try:
                    self._min_mark = int(mark)
                except Exception as msg:
                    log.error("MinimalMark %s is not valid, using default "
                              "value %d", mark, self._min_mark)
            if self._firewalld_conf.get("CleanupOnExit"):
                value = self._firewalld_conf.get("CleanupOnExit")
                if value.lower() in [ "no", "false" ]:
                    self.cleanup_on_exit = False

        # apply default rules
        self._apply_default_rules()

        # load icmptype files
        self._loader(FIREWALLD_ICMPTYPES, "icmptype", True)
        self._loader(ETC_FIREWALLD_ICMPTYPES, "icmptype")

        if len(self.icmptype.get_icmptypes()) == 0:
            log.error("No icmptypes found.")

        # load service files
        self._loader(FIREWALLD_SERVICES, "service", True)
        self._loader(ETC_FIREWALLD_SERVICES, "service")

        if len(self.service.get_services()) == 0:
            log.error("No services found.")

        # load zone files
        self._loader(FIREWALLD_ZONES, "zone", True)
        self._loader(ETC_FIREWALLD_ZONES, "zone")

        if len(self.zone.get_zones()) == 0:
            log.fatal("No zones found.")
            sys.exit(1)

        # check minimum required zones
        error = False
        for z in [ "block", "drop", "trusted" ]:
            if not z in self.zone.get_zones():
                log.fatal("Zone '%s' is not available.", z)
                error = True
        if error:
            sys.exit(1)

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

        self._state = "RUNNING"

    def _loader(self, path, reader_type, default=False):
        if not os.path.isdir(path):
            return

        for filename in os.listdir(path):
            if not filename.endswith(".xml"):
                continue

            name = "%s/%s" % (path, filename)
            log.debug1("Loading %s file '%s'", reader_type, name)
            try:
                if reader_type == "icmptype":
                    obj = icmptype_reader(filename, path)
                    if obj.name in self.icmptype.get_icmptypes():
                        orig_obj = self.icmptype.get_icmptype(obj.name)
                        log.debug1("  Overloads %s '%s' ('%s/%s')", reader_type,
                                   orig_obj.name, orig_obj.path,
                                   orig_obj.filename)

                    self.icmptype.add_icmptype(obj)
                    # add a deep copy to the configuration interface
                    self.config.add_icmptype(copy.deepcopy(obj), default)
                elif reader_type == "service":
                    obj = service_reader(filename, path)
                    if obj.name in self.service.get_services():
                        orig_obj = self.service.get_service(obj.name)
                        log.debug1("  Overloads %s '%s' ('%s/%s')", reader_type,
                                   orig_obj.name, orig_obj.path,
                                   orig_obj.filename)
                    self.service.add_service(obj)
                    # add a deep copy to the configuration interface
                    self.config.add_service(copy.deepcopy(obj), default)
                elif reader_type == "zone":
                    obj = zone_reader(filename, path)
                    if obj.name in self.zone.get_zones():
                        orig_obj = self.zone.get_zone(obj.name)
                        if orig_obj.immutable:
                            raise FirewallError(NOT_OVERLOADABLE, obj.name)
                        log.debug1("  Overloads %s '%s' ('%s/%s')", reader_type,
                                   orig_obj.name, orig_obj.path,
                                   orig_obj.filename)
                    self.zone.add_zone(obj)
                    # add a deep copy to the configuration interface
                    self.config.add_zone(copy.deepcopy(obj), default)
                else:
                    log.fatal("Unknown reader type %s", reader_type)
            except FirewallError as msg:
                log.error("Failed to load %s file '%s': %s", reader_type,
                          name, msg)
            except Exception as msg:
                log.error("Failed to load %s file '%s':", reader_type, name)
                log.exception()

    def cleanup(self):
        self.__init_vars()
        self.icmptype.cleanup()
        self.service.cleanup()
        self.zone.cleanup()
        self.config.cleanup()
        self.direct.cleanup()

    def stop(self):
        if self.cleanup_on_exit:
            self._flush()
            self._set_policy("ACCEPT")
            self._modules.unload_firewall_modules()

        self.cleanup()

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
            if insert and not enable and isinstance(rule[1], int):
                rule.pop(1)

            # run
            try:
                self.rule(ipv, [ append_delete[enable], ] + rule)
            except Exception as msg:
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
                self.rule(ipv, [ new_delete[enable], ] + rule)
            except Exception as msg:
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
                self.rule(ipv, _rule)

#                try:
#                except Exception as msg:
# TODO: better handling of init error
#                    if "Chain already exists." in msg:
#                        continue
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

    # rule function used in handle_ functions

    def rule(self, ipv, rule):
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
                raise FirewallError(EBTABLES_NO_REJECT)

        # replace %%ICMP%%
        try:
            i = rule.index("%%ICMP%%")
        except:
            pass
        else:
            if ipv in [ "ipv4", "ipv6" ]:
                rule[i] = ipXtables.ICMP[ipv]
            else:
                raise FirewallError(INVALID_IPV, ipv)

        if ipv == "ipv4":
            return self._ip4tables.set_rule(rule)
        elif ipv == "ipv6":
            return self._ip6tables.set_rule(rule)
        elif ipv == "eb":
            return self._ebtables.set_rule(rule)
        else:
            raise FirewallError(INVALID_IPV, ipv)

    # check functions

    def check_panic(self):
        if self._panic:
            raise FirewallError(PANIC_MODE)

    def check_zone(self, zone):
        _zone = zone
        if not _zone or _zone == "":
            _zone = self.get_default_zone()
        if _zone not in self.zone.get_zones():
            raise FirewallError(INVALID_ZONE, _zone)
        return _zone

    def check_interface(self, interface):
        if not functions.checkInterface(interface):
            raise FirewallError(INVALID_INTERFACE, interface)

    def check_service(self, service):
        self.service.check_service(service)

    def check_port(self, port):
        range = functions.getPortRange(port)

        if range == -2 or range == -1 or range == None or \
                (len(range) == 2 and range[0] >= range[1]):
            if range == -2:
                log.debug2("'%s': port > 65535" % port)
            elif range == -1:
                log.debug2("'%s': port is invalid" % port)
            elif range == None:
                log.debug2("'%s': port is ambiguous" % port)
            elif len(range) == 2 and range[0] >= range[1]:
                log.debug2("'%s': range start >= end" % port)
            raise FirewallError(INVALID_PORT, port)

    def check_protocol(self, protocol):
        if not protocol:
            raise FirewallError(MISSING_PROTOCOL)
        if not protocol in [ "tcp", "udp" ]:
            raise FirewallError(INVALID_PROTOCOL, protocol)

    def check_ip(self, ip):
        if not functions.checkIP(ip):
            raise FirewallError(INVALID_ADDR, ip)

    def check_icmptype(self, icmp):
        self.icmptype.check_icmptype(icmp)

    # RELOAD

    def reload(self, stop=False):
        _panic = self._panic

        # save zone settings
        _zone_settings = { }
        for zone in self.zone.get_zones():
            _zone_settings[zone] = self.zone.get_settings(zone)
        # save direct config
        _direct_config = self.direct.get_config()
        _old_dz = self.get_default_zone()

        if stop:
            self.stop()
        else:
            self.cleanup()
            self._flush()
            self._set_policy("ACCEPT")
        self.start()

        # start
        if _panic:
            self.enable_panic_mode()

        _new_dz = self.get_default_zone()
        if _new_dz != _old_dz:
            # default zone changed. Move interfaces from old default zone to the new one.
            for iface, settings in _zone_settings[_old_dz]["interfaces"].items():
                if settings["__default__"]:
                    # move only those that were added to default zone
                    # (not those that were added to specific zone same as default)
                    _zone_settings[_new_dz]["interfaces"][iface] = \
                    _zone_settings[_old_dz]["interfaces"][iface]
                    del _zone_settings[_old_dz]["interfaces"][iface]

# do not apply the old settings
#        # restore zone settings
#        for zone in self.zone.get_zones():
#            if zone in _zone_settings:
#                self.zone.set_settings(zone, _zone_settings[zone])
#                del _zone_settings[zone]
#            else:
#                log.info1("New zone '%s'.", zone)
#        if len(_zone_settings) > 0:
#            for zone in _zone_settings:
#                log.info1("Lost zone '%s', settings dropped.", zone)
#        del _zone_settings

        # restore direct config
        self.direct.set_config(_direct_config)

    # STATE

    def get_state(self):
        return self._state

    # PANIC MODE

    def enable_panic_mode(self):
        if self._panic:
            raise FirewallError(ALREADY_ENABLED)

        # TODO: use rule in raw table not default chain policy
        try:
            self._set_policy("DROP", "all")
        except Exception as msg:
            raise FirewallError(COMMAND_FAILED, msg)
        self._panic = True

    def disable_panic_mode(self):
        if not self._panic:
            raise FirewallError(NOT_ENABLED)

        # TODO: use rule in raw table not default chain policy
        try:
            self._set_policy("ACCEPT", "all")
        except Exception as msg:
            raise FirewallError(COMMAND_FAILED, msg)
        self._panic = False

    def query_panic_mode(self):
        return (self._panic == True)

    # DEFAULT ZONE

    def get_default_zone(self):
        return self._default_zone

    def set_default_zone(self, zone):
        _zone = self.check_zone(zone)
        if _zone != self._default_zone:
            _old_dz = self._default_zone
            self._default_zone = _zone
            self._firewalld_conf.set("DefaultZone", _zone)
            self._firewalld_conf.write()

            # Move interfaces from old default zone to the new one.
            _old_dz_settings = self.zone.get_settings(_old_dz)
            for iface, settings in _old_dz_settings["interfaces"].items():
                if settings["__default__"]:
                    # move only those that were added to default zone
                    # (not those that were added to specific zone same as default)
                    self.zone.change_zone("", iface)
        else:
            raise FirewallError(ZONE_ALREADY_SET, _zone)
