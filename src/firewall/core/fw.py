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
from firewall.core.fw_policies import FirewallPolicies
from firewall.core.logger import log
from firewall.core.io.firewalld_conf import firewalld_conf
from firewall.core.io.direct import Direct
from firewall.core.io.service import service_reader
from firewall.core.io.icmptype import icmptype_reader
from firewall.core.io.zone import zone_reader, Zone
from firewall.errors import *

############################################################################
#
# class Firewall
#
############################################################################

class Firewall:
    def __init__(self):
        self._firewalld_conf = firewalld_conf(FIREWALLD_CONF)

        self._ip4tables = ipXtables.ip4tables()
        self.ip4tables_enabled = True
        self._ip6tables = ipXtables.ip6tables()
        self.ip6tables_enabled = True
        self._ebtables = ebtables.ebtables()
        self.ebtables_enabled = True

        self._modules = modules.modules()

        self.icmptype = FirewallIcmpType(self)
        self.service = FirewallService(self)
        self.zone = FirewallZone(self)
        self.direct = FirewallDirect(self)
        self.config = FirewallConfig(self)
        self.policies = FirewallPolicies(self)

        self.__init_vars()

    def __init_vars(self):
        self._state = "INIT"
        self._panic = False
        self._default_zone = ""
        self._module_refcount = { }
        self._marks = [ ]
        self._min_mark = FALLBACK_MINIMAL_MARK # will be overloaded by firewalld.conf
        self.cleanup_on_exit = True

    def _check_tables(self):
        # check if iptables, ip6tables and ebtables are usable, else disable
        if not "filter" in ipXtables.ip4tables_available_tables:
            log.warning("iptables not usable, disabling IPv4 firewall.")
            self.ip4tables_enabled = False

        if not "filter" in ipXtables.ip6tables_available_tables:
            log.warning("ip6tables not usable, disabling IPv6 firewall.")
            self.ip6tables_enabled = False

        if not "filter" in ebtables.ebtables_available_tables:
            log.error("ebtables not usable, disabling ethernet bridge firewall.")
            self.ebtables_enabled = False

        if not self.ip4tables_enabled and not self.ip6tables_enabled:
            log.fatal("No IPv4 and IPv6 firewall.")
            sys.exit(1)

    def _start(self):
        # initialize firewall
        default_zone = FALLBACK_ZONE

        # load firewalld config
        log.debug1("Loading firewalld config file '%s'", FIREWALLD_CONF)
        try:
            self._firewalld_conf.read()
        except Exception as msg:
            log.error("Failed to open firewalld config file '%s': %s",
                      FIREWALLD_CONF, msg)
        else:
            if self._firewalld_conf.get("DefaultZone"):
                default_zone = self._firewalld_conf.get("DefaultZone")
            if self._firewalld_conf.get("MinimalMark"):
                mark = self._firewalld_conf.get("MinimalMark")
                if mark != None:
                    try:
                        self._min_mark = int(mark)
                    except Exception as msg:
                        log.error("MinimalMark %s is not valid, using default "
                                  "value %d", mark, self._min_mark)
            if self._firewalld_conf.get("CleanupOnExit"):
                value = self._firewalld_conf.get("CleanupOnExit")
                if value != None and value.lower() in [ "no", "false" ]:
                    self.cleanup_on_exit = False

            if self._firewalld_conf.get("Lockdown"):
                value = self._firewalld_conf.get("Lockdown")
                if value != None and value.lower() in [ "yes", "true" ]:
                    log.debug1("Lockdown is enabled")
                    try:
                        self.policies.enable_lockdown()
                    except FirewallError:
                        # already enabled, this is probably reload
                        pass

        self.config.set_firewalld_conf(copy.deepcopy(self._firewalld_conf))

        # apply default rules
        self._apply_default_rules()

        # load lockdown whitelist
        log.debug1("Loading lockdown whitelist")
        try:
            self.policies.lockdown_whitelist.read()
        except Exception as msg:
            log.error("Failed to load lockdown whitelist '%s': %s",
                      self.policies.lockdown_whitelist.filename, msg)

        # copy policies to config interface
        self.config.set_policies(copy.deepcopy(self.policies))

        # load icmptype files
        self._loader(FIREWALLD_ICMPTYPES, "icmptype")
        self._loader(ETC_FIREWALLD_ICMPTYPES, "icmptype")

        if len(self.icmptype.get_icmptypes()) == 0:
            log.error("No icmptypes found.")

        # load service files
        self._loader(FIREWALLD_SERVICES, "service")
        self._loader(ETC_FIREWALLD_SERVICES, "service")

        if len(self.service.get_services()) == 0:
            log.error("No services found.")

        # load zone files
        self._loader(FIREWALLD_ZONES, "zone")
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

        # load direct rules
        log.debug1("Loading direct rules file '%s'" % FIREWALLD_DIRECT)
        obj = Direct(FIREWALLD_DIRECT)
        try:
            obj.read()
        except Exception as msg:
            log.debug1("Failed to load direct rules file '%s': %s",
                      FIREWALLD_DIRECT, msg)
        else:
            self.direct.set_config((obj.get_all_chains(), obj.get_all_rules()))
            for ipv, args in obj.get_all_passthroughs().items():
                for arg in args:
                    try:
                        self.direct.passthrough(ipv, arg)
                    except FirewallError as error:
                        log.warning(str(error))
            # TODO: copy obj into config interface
        self.config.set_direct(copy.deepcopy(obj))

        # check if default_zone is a valid zone
        if default_zone not in self.zone.get_zones():
            if "public" in self.zone.get_zones():
                zone = "public"
            elif "external" in self.zone.get_zones():
                zone = "external"
            else:
                zone = "block" # block is a base zone, therefore it has to exist

            log.error("Default zone '%s' is not valid. Using '%s'.",
                      default_zone, zone)
            default_zone = zone
        else:
            log.debug1("Using default zone '%s'", default_zone)

        self._default_zone = self.check_zone(default_zone)
        self.zone.change_default_zone(None, self._default_zone)

        self._state = "RUNNING"

    def start(self):
        self._check_tables()
        self._flush()
        self._set_policy("ACCEPT")
        self._start()

    def _loader(self, path, reader_type, combine=False):
        # combine: several zone files are getting combined into one obj
        if not os.path.isdir(path):
            return

        if combine == True:
            if path.startswith(ETC_FIREWALLD) and reader_type == "zone":
                combined_zone = Zone()
                combined_zone.name = os.path.basename(path)
                combined_zone.check_name(combined_zone.name)
                combined_zone.path = path
                combined_zone.default = False
            else:
                combine = False

        for filename in sorted(os.listdir(path)):
            if not filename.endswith(".xml"):
                if path.startswith(ETC_FIREWALLD) and \
                        reader_type == "zone" and \
                        os.path.isdir("%s/%s" % (path, filename)):
                    self._loader("%s/%s" % (path, filename), reader_type,
                                 combine=True)
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
                        self.icmptype.remove_icmptype(orig_obj.name)
                    self.icmptype.add_icmptype(obj)
                    # add a deep copy to the configuration interface
                    self.config.add_icmptype(copy.deepcopy(obj))
                elif reader_type == "service":
                    obj = service_reader(filename, path)
                    if obj.name in self.service.get_services():
                        orig_obj = self.service.get_service(obj.name)
                        log.debug1("  Overloads %s '%s' ('%s/%s')", reader_type,
                                   orig_obj.name, orig_obj.path,
                                   orig_obj.filename)
                        self.service.remove_service(orig_obj.name)
                    self.service.add_service(obj)
                    # add a deep copy to the configuration interface
                    self.config.add_service(copy.deepcopy(obj))
                elif reader_type == "zone":
                    obj = zone_reader(filename, path)
                    if not combine:
                        if obj.name in self.zone.get_zones():
                            orig_obj = self.zone.get_zone(obj.name)
                            if orig_obj.combined:
                                raise FirewallError(NOT_OVERLOADABLE,
                                                    "%s is a combined zone" % \
                                                        obj.name)
                            log.debug1("  Overloads %s '%s' ('%s/%s')",
                                       reader_type,
                                       orig_obj.name, orig_obj.path,
                                       orig_obj.filename)
                            self.zone.remove_zone(orig_obj.name)
                        self.zone.add_zone(obj)
                        # add a deep copy to the configuration interface
                        self.config.add_zone(copy.deepcopy(obj))
                    else:
                        combined_zone.combine(obj)
                else:
                    log.fatal("Unknown reader type %s", reader_type)
            except FirewallError as msg:
                log.error("Failed to load %s file '%s': %s", reader_type,
                          name, msg)
            except Exception as msg:
                log.error("Failed to load %s file '%s':", reader_type, name)
                log.exception()

        if combine == True and combined_zone.combined == True:
            if combined_zone.name in self.zone.get_zones():
                orig_obj = self.zone.get_zone(combined_zone.name)
                log.debug1("  Overloading and deactivating %s '%s' ('%s/%s')",
                           reader_type, orig_obj.name, orig_obj.path,
                           orig_obj.filename)
                try:
                    self.zone.remove_zone(combined_zone.name)
                except:
                    pass
                self.config.forget_zone(combined_zone.name)
            self.zone.add_zone(combined_zone)

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
        for i,value in enumerate(rules):
            if len(value) == 3:
                (ipv, rule, insert) = value
            else:
                (ipv, rule) = value

            # drop insert rule number if it exists
            if insert and not enable and isinstance(rule[1], int):
                rule.pop(1)

            table = None
            for t in ipXtables.CHAINS.keys():
                if t in rule:
                    table = t
            if table and not self.is_table_available(ipv, table):
                if ((ipv == "ipv4" and self.ip4tables_enabled) or
                    (ipv == "ipv6" and self.ip6tables_enabled)):
                    log.error("Unable to add %s into %s %s" % (rule, ipv, table))
                continue

            # run
            try:
                self.rule(ipv, [ append_delete[enable], ] + rule)
            except Exception as msg:
                log.error(msg)
                return (rules[:i], msg) # cleanup rules and error message
        return None

    def handle_rules2(self, rules, enable, insert=False):
        if insert:
            append_delete = { True: "-I", False: "-D", }
        else:
            append_delete = { True: "-A", False: "-D", }

        # appends rules
        # returns None if all worked, else (cleanup rules, error message)
        for i,value in enumerate(rules):
            if len(value) == 5:
                (ipv, table, chain, rule, insert) = value
            else:
                (ipv, table, chain, rule) = value

            # drop insert rule number if it exists
            if insert and not enable and isinstance(rule[1], int):
                rule.pop(1)

            if not self.is_table_available(ipv, table):
                if ((ipv == "ipv4" and self.ip4tables_enabled) or
                    (ipv == "ipv6" and self.ip6tables_enabled)):
                    log.error("Unable to add %s into %s %s" % (rule, ipv, table))
                continue

            # run
            try:
                self.rule(ipv, [ "-t", table,
                                 append_delete[enable], chain, ] + rule)
            except Exception as msg:
                log.error(msg)
                return (rules[:i], msg) # cleanup rules and error message
        return None

    def handle_chains(self, rules, enable):
        new_delete = { True: "-N", False: "-X" }

        # appends chains
        # returns None if all worked, else (cleanup chains, error message)
        for i,(ipv, rule) in enumerate(rules):
            try:
                self.rule(ipv, [ new_delete[enable], ] + rule)
            except Exception as msg:
                log.error(msg)
                return (rules[:i], msg) # cleanup chains and error message
        return None

    def handle_modules(self, modules, enable):
        for i,module in enumerate(modules):
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

    def is_table_available(self, ipv, table):
        return ((ipv == "ipv4" and table in ipXtables.ip4tables_available_tables) or
                (ipv == "ipv6" and table in ipXtables.ip6tables_available_tables) or
                (ipv == "eb" and table in ebtables.ebtables_available_tables))

    # apply default rules
    def __apply_default_rules(self, ipv):
        if ipv in [ "ipv4", "ipv6" ]:
            default_rules = ipXtables.DEFAULT_RULES
        else:
            default_rules = ebtables.DEFAULT_RULES

        for table in default_rules:
            if not self.is_table_available(ipv, table):
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
        if self.ip4tables_enabled:
            self._ip4tables.flush()
        if self.ip6tables_enabled:
            self._ip6tables.flush()

    def _set_policy(self, policy, which="used"):
        if self.ip4tables_enabled:
            self._ip4tables.set_policy(policy, which)
        if self.ip6tables_enabled:
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
            # do not call if disabled
            if self.ip4tables_enabled:
                return self._ip4tables.set_rule(rule)
        elif ipv == "ipv6":
            # do not call if disabled
            if self.ip6tables_enabled:
                return self._ip6tables.set_rule(rule)
        elif ipv == "eb":
            # do not call if disabled
            if self.ebtables_enabled:
                return self._ebtables.set_rule(rule)
        else:
            raise FirewallError(INVALID_IPV, ipv)

        return ""

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

    def check_address(self, ipv, source):
        if ipv == "ipv4":
            if not functions.checkIPnMask(source):
                raise FirewallError(INVALID_ADDR, source)
        elif ipv == "ipv6":
            if not functions.checkIP6nMask(source):
                raise FirewallError(INVALID_ADDR, source)
        else:
            raise FirewallError(INVALID_IPV)

    def check_icmptype(self, icmp):
        self.icmptype.check_icmptype(icmp)

    # RELOAD

    def reload(self, stop=False):
        _panic = self._panic

        # save zone interfaces
        _zone_interfaces = { }
        for zone in self.zone.get_zones():
            _zone_interfaces[zone] = self.zone.get_settings(zone)["interfaces"]
        # save direct config
        _direct_config = self.direct.get_config()
        _old_dz = self.get_default_zone()

        # stop
        self._set_policy("DROP")
        self._flush()
        if stop:
            self._modules.unload_firewall_modules()
        self.cleanup()

        # start
        self._start()

        # handle interfaces in the default zone and move them to the new 
        # default zone if it changed
        _new_dz = self.get_default_zone()
        if _new_dz != _old_dz:
            # default zone changed. Move interfaces from old default zone to 
            # the new one.
            for iface, settings in _zone_interfaces[_old_dz].items():
                if settings["__default__"]:
                    # move only those that were added to default zone
                    # (not those that were added to specific zone same as 
                    # default)
                    _zone_interfaces[_new_dz][iface] = \
                        _zone_interfaces[_old_dz][iface]
                    del _zone_interfaces[_old_dz][iface]

        # add interfaces to zones again
        for zone in self.zone.get_zones():
            if zone in _zone_interfaces:
                self.zone.set_settings(zone, { "interfaces":
                                                   _zone_interfaces[zone] })
                del _zone_interfaces[zone]
            else:
                log.info1("New zone '%s'.", zone)
        if len(_zone_interfaces) > 0:
            for zone in _zone_interfaces.keys():
                log.info1("Lost zone '%s', zone interfaces dropped.", zone)
                del _zone_interfaces[zone]
        del _zone_interfaces

        # restore direct config
        self.direct.set_config(_direct_config)

        # enable panic mode again if it has been enabled before or set policy 
        # to ACCEPT
        if _panic:
            self.enable_panic_mode()
        else:
            self._set_policy("ACCEPT")

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

            # remove old default zone from ZONES and add new default zone
            self.zone.change_default_zone(_old_dz, _zone)

            # Move interfaces from old default zone to the new one.
            _old_dz_settings = self.zone.get_settings(_old_dz)
            for iface, settings in _old_dz_settings["interfaces"].items():
                if settings["__default__"]:
                    # move only those that were added to default zone
                    # (not those that were added to specific zone same as default)
                    self.zone.change_zone_of_interface("", iface)
        else:
            raise FirewallError(ZONE_ALREADY_SET, _zone)
