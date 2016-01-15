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
from firewall.core import ipset
from firewall.core import modules
from firewall.core.fw_icmptype import FirewallIcmpType
from firewall.core.fw_service import FirewallService
from firewall.core.fw_zone import FirewallZone
from firewall.core.fw_direct import FirewallDirect
from firewall.core.fw_config import FirewallConfig
from firewall.core.fw_policies import FirewallPolicies
from firewall.core.fw_ipset import FirewallIPSet
from firewall.core.logger import log
from firewall.core.io.firewalld_conf import firewalld_conf
from firewall.core.io.direct import Direct
from firewall.core.io.service import service_reader
from firewall.core.io.icmptype import icmptype_reader
from firewall.core.io.zone import zone_reader, Zone
from firewall.core.io.ipset import ipset_reader
from firewall.errors import *

############################################################################
#
# class Firewall
#
############################################################################

class Firewall(object):
    def __init__(self):
        self._firewalld_conf = firewalld_conf(FIREWALLD_CONF)

        self._ip4tables = ipXtables.ip4tables()
        self.ip4tables_enabled = True
        self._ip6tables = ipXtables.ip6tables()
        self.ip6tables_enabled = True
        self._ebtables = ebtables.ebtables()
        self.ebtables_enabled = True
        self._ipset = ipset.ipset()
        self.ipset_enabled = True

        self._modules = modules.modules()

        self.icmptype = FirewallIcmpType(self)
        self.service = FirewallService(self)
        self.zone = FirewallZone(self)
        self.direct = FirewallDirect(self)
        self.config = FirewallConfig(self)
        self.policies = FirewallPolicies()
        self.ipset = FirewallIPSet(self)

        self.__init_vars()

    def __repr__(self):
        return '%s(%r, %r, %r, %r, %r, %r, %r, %r, %r, %r, %r, %r, %r)' % \
            (self.__class__, self.ip4tables_enabled, self.ip6tables_enabled,
             self.ebtables_enabled, self._state, self._panic,
             self._default_zone, self._module_refcount, self._marks,
             self._min_mark, self.cleanup_on_exit, self.ipv6_rpfilter_enabled,
             self.ipset_enabled, self._individual_calls)

    def __init_vars(self):
        self._state = "INIT"
        self._panic = False
        self._default_zone = ""
        self._module_refcount = { }
        self._marks = [ ]
        # fallback settings will be overloaded by firewalld.conf
        self._min_mark = FALLBACK_MINIMAL_MARK
        self.cleanup_on_exit = FALLBACK_CLEANUP_ON_EXIT
        self.ipv6_rpfilter_enabled = FALLBACK_IPV6_RPFILTER
        self._individual_calls = FALLBACK_INDIVIDUAL_CALLS

    def _check_tables(self):
        # check if iptables, ip6tables and ebtables are usable, else disable
        if self.ip4tables_enabled and \
           "filter" not in ipXtables.ip4tables_available_tables:
            log.warning("iptables not usable, disabling IPv4 firewall.")
            self.ip4tables_enabled = False

        if self.ip6tables_enabled and \
           "filter" not in ipXtables.ip6tables_available_tables:
            log.warning("ip6tables not usable, disabling IPv6 firewall.")
            self.ip6tables_enabled = False

        if self.ebtables_enabled and \
           "filter" not in ebtables.ebtables_available_tables:
            log.error("ebtables not usable, disabling ethernet bridge firewall.")
            self.ebtables_enabled = False

        if not self.ip4tables_enabled and not self.ip6tables_enabled:
            log.fatal("No IPv4 and IPv6 firewall.")
            sys.exit(1)

    def _start_check(self):
        try:
            x = self._ipset.list()
        except:
            log.error("ipset not usable, disabling ipset usage in firewall.")
            self.ipset_enabled = False

    def _start(self):
        # initialize firewall
        default_zone = FALLBACK_ZONE

        # load firewalld config
        log.debug1("Loading firewalld config file '%s'", FIREWALLD_CONF)
        try:
            self._firewalld_conf.read()
        except Exception as msg:
            log.warning("Using fallback firewalld configuration settings.")
        else:
            if self._firewalld_conf.get("DefaultZone"):
                default_zone = self._firewalld_conf.get("DefaultZone")

            if self._firewalld_conf.get("MinimalMark"):
                self._min_mark = int(self._firewalld_conf.get("MinimalMark"))

            if self._firewalld_conf.get("CleanupOnExit"):
                value = self._firewalld_conf.get("CleanupOnExit")
                if value is not None and value.lower() in [ "no", "false" ]:
                    self.cleanup_on_exit = False

            if self._firewalld_conf.get("Lockdown"):
                value = self._firewalld_conf.get("Lockdown")
                if value is not None and value.lower() in [ "yes", "true" ]:
                    log.debug1("Lockdown is enabled")
                    try:
                        self.policies.enable_lockdown()
                    except FirewallError:
                        # already enabled, this is probably reload
                        pass

            if self._firewalld_conf.get("IPv6_rpfilter"):
                value = self._firewalld_conf.get("IPv6_rpfilter")
                if value is not None:
                    if value.lower() in [ "no", "false" ]:
                        self.ipv6_rpfilter_enabled = False
                    if value.lower() in [ "yes", "true" ]:
                        self.ipv6_rpfilter_enabled = True
            if self.ipv6_rpfilter_enabled:
                log.debug1("IPv6 rpfilter is enabled")
            else:
                log.debug1("IPV6 rpfilter is disabled")

            if self._firewalld_conf.get("IndividualCalls"):
                value = self._firewalld_conf.get("IndividualCalls")
                if value is not None and value.lower() in [ "yes", "true" ]:
                    log.debug1("IndividualCalls is enabled")
                    self._individual_calls = True

            if not self._individual_calls and \
               not self._ebtables.restore_noflush_option:
                log.debug1("ebtables-restore is not supporting the --noflush option, will therefore not be used")

        self.config.set_firewalld_conf(copy.deepcopy(self._firewalld_conf))

        # apply default rules
        self._apply_default_rules()

        # load lockdown whitelist
        log.debug1("Loading lockdown whitelist")
        try:
            self.policies.lockdown_whitelist.read()
        except Exception as msg:
            if self.policies.query_lockdown():
                log.error("Failed to load lockdown whitelist '%s': %s",
                      self.policies.lockdown_whitelist.filename, msg)
            else:
                log.debug1("Failed to load lockdown whitelist '%s': %s",
                      self.policies.lockdown_whitelist.filename, msg)

        # copy policies to config interface
        self.config.set_policies(copy.deepcopy(self.policies))

        # load ipset files
        self._loader(FIREWALLD_IPSETS, "ipset")
        self._loader(ETC_FIREWALLD_IPSETS, "ipset")

        self.ipset.apply_ipsets()

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
            if z not in self.zone.get_zones():
                log.fatal("Zone '%s' is not available.", z)
                error = True
        if error:
            sys.exit(1)

        # apply settings for loaded zones
        self.zone.apply_zones()

        # load direct rules
        obj = Direct(FIREWALLD_DIRECT)
        if os.path.exists(FIREWALLD_DIRECT):
            log.debug1("Loading direct rules file '%s'" % FIREWALLD_DIRECT)
            try:
                obj.read()
            except Exception as msg:
                log.debug1("Failed to load direct rules file '%s': %s",
                           FIREWALLD_DIRECT, msg)
        self.direct.set_permanent_config(obj)
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
        self._start_check()
        self._check_tables()
        self._flush()
        self._set_policy("ACCEPT")
        self._start()

    def _loader(self, path, reader_type, combine=False):
        # combine: several zone files are getting combined into one obj
        if not os.path.isdir(path):
            return

        if combine:
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
                    elif obj.path.startswith(ETC_FIREWALLD):
                        obj.default = True
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
                    elif obj.path.startswith(ETC_FIREWALLD):
                        obj.default = True
                    self.service.add_service(obj)
                    # add a deep copy to the configuration interface
                    self.config.add_service(copy.deepcopy(obj))
                elif reader_type == "zone":
                    obj = zone_reader(filename, path)
                    if combine:
                        # Change name for permanent configuration
                        obj.name = "%s/%s" % (
                            os.path.basename(path),
                            os.path.basename(filename)[0:-4])
                        obj.check_name(obj.name)
                    # Copy object before combine
                    config_obj = copy.deepcopy(obj)
                    if obj.name in self.zone.get_zones():
                        orig_obj = self.zone.get_zone(obj.name)
                        self.zone.remove_zone(orig_obj.name)
                        if orig_obj.combined:
                            log.debug1("  Combining %s '%s' ('%s/%s')",
                                        reader_type, obj.name,
                                        path, filename)
                            obj.combine(orig_obj)
                        else:
                            log.debug1("  Overloads %s '%s' ('%s/%s')",
                                       reader_type,
                                       orig_obj.name, orig_obj.path,
                                       orig_obj.filename)
                    elif obj.path.startswith(ETC_FIREWALLD):
                        obj.default = True
                        config_obj.default = True
                    self.config.add_zone(config_obj)
                    if combine:
                        log.debug1("  Combining %s '%s' ('%s/%s')",
                                   reader_type, combined_zone.name,
                                   path, filename)
                        combined_zone.combine(obj)
                    else:
                        self.zone.add_zone(obj)
                elif reader_type == "ipset":
                    obj = ipset_reader(filename, path)
                    if obj.name in self.ipset.get_ipsets():
                        orig_obj = self.ipset.get_ipset(obj.name)
                        log.debug1("  Overloads %s '%s' ('%s/%s')", reader_type,
                                   orig_obj.name, orig_obj.path,
                                   orig_obj.filename)
                        self.ipset.remove_ipset(orig_obj.name)
                    elif obj.path.startswith(ETC_FIREWALLD):
                        obj.default = True
                    self.ipset.add_ipset(obj)
                    # add a deep copy to the configuration interface
                    self.config.add_ipset(copy.deepcopy(obj))
                else:
                    log.fatal("Unknown reader type %s", reader_type)
            except FirewallError as msg:
                log.error("Failed to load %s file '%s': %s", reader_type,
                          name, msg)
            except Exception as msg:
                log.error("Failed to load %s file '%s':", reader_type, name)
                log.exception()

        if combine and combined_zone.combined:
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
        self.icmptype.cleanup()
        self.service.cleanup()
        self.zone.cleanup()
        self.ipset.cleanup()
        self.config.cleanup()
        self.direct.cleanup()
        self.policies.cleanup()
        self._firewalld_conf.cleanup()
        self.__init_vars()

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

        _rules = { }
        # appends rules
        # returns None if all worked, else (cleanup rules, error message)
        for i,value in enumerate(rules):
            table = chain = None
            if len(value) == 5:
                (ipv, table, chain, rule, insert) = value
                # drop insert rule number if it exists
                if insert and not enable and isinstance(rule[1], int):
                    rule.pop(1)
            elif len(value) == 4:
                (ipv, table, chain, rule) = value
                # drop insert rule number if it exists
                if insert and not enable and isinstance(rule[1], int):
                    rule.pop(1)
            elif len(value) == 3:
                (ipv, rule, insert) = value
            else:
                (ipv, rule) = value

            # drop insert rule number if it exists
            if insert and not enable and isinstance(rule[1], int):
                rule.pop(1)

            if table and not self.is_table_available(ipv, table):
                if ((ipv == "ipv4" and self.ip4tables_enabled) or
                    (ipv == "ipv6" and self.ip6tables_enabled)):
                    log.error("Unable to add %s into %s %s" % (rule, ipv, table))
                continue

            if table != None:
                _rule = [ "-t", table, append_delete[enable], ]
            else:
                _rule = [ append_delete[enable], ]
            if chain != None:
                _rule.append(chain)
            _rule += [ "%s" % item for item in rule ]

            if self._individual_calls or \
               (ipv == "eb" and not self._ebtables.restore_noflush_option):
                ## run
                try:
                    self.rule(ipv, _rule)
                except Exception as msg:
                    log.error("Failed to apply rules. A firewall reload might solve the issue if the firewall has been modified using ip*tables or ebtables.")
                    log.error(msg)
                    return (rules[:i], msg) # cleanup rules and error message
            else:
                _rules.setdefault(ipv, []).append(_rule)

        try:
            for ipv in _rules:
                self.rules(ipv, _rules[ipv])
        except Exception as msg:
            log.error("Failed to apply rules. A firewall reload might solve the issue if the firewall has been modified using ip*tables or ebtables.")
            log.error(msg)
            return ([ ], msg) # no cleanup rules and error message

        return None

    def handle_chains(self, rules, enable):
        new_delete = { True: "-N", False: "-X" }

        _rules = { }
        # appends chains
        # returns None if all worked, else (cleanup chains, error message)
        for i,(ipv, rule) in enumerate(rules):
            _rule = [ new_delete[enable], ] + rule
            if self._individual_calls or \
               (ipv == "eb" and not self._ebtables.restore_noflush_option):
                try:
                    self.rule(ipv, _rule)
                except Exception as msg:
                    log.error(msg)
                    return (rules[:i], msg) # cleanup chains and error message
            else:
                _rules.setdefault(ipv, []).append(_rule)
        try:
            for ipv in _rules:
                self.rules(ipv, _rules[ipv])
        except Exception as msg:
            log.error("Failed to apply rules. A firewall reload might solve the issue if the firewall has been modified using ip*tables or ebtables.")
            log.error(msg)
            return ([ ], msg) # no cleanup rules and error message
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

        rules = { }
        for table in default_rules:
            if not self.is_table_available(ipv, table):
                continue
            prefix = [ "-t", table ]
            for rule in default_rules[table]:
                _rule = prefix + rule.split()
                if self._individual_calls or \
                   (ipv == "eb" and not self._ebtables.restore_noflush_option):
                    self.rule(ipv, _rule)
                else:
                    rules.setdefault(ipv, []).append(_rule)

        for ipv in rules:
            self.rules(ipv, rules[ipv])

    def _apply_default_rules(self):
        for ipv in [ "ipv4", "ipv6", "eb" ]:
            self.__apply_default_rules(ipv)

        if self.ipv6_rpfilter_enabled and \
           self.is_table_available("ipv6", "raw"):
            if self._individual_calls:
                # here is no check for ebtables.restore_noflush_option needed
                # as ebtables is not used in here
                rule = [ "-t", "raw", "-I", "PREROUTING", "1",
                         "-p", "icmpv6", "--icmpv6-type=router-advertisement",
                         "-j", "ACCEPT" ]       # RHBZ#1058505
                self.rule("ipv6", rule)
                rule = [ "-t", "raw", "-I", "PREROUTING", "2",
                         "-m", "rpfilter", "--invert", "-j", "DROP" ]
                try:
                    self.rule("ipv6", rule)
                except ValueError:    # some problem with ip6t_rpfilter module ?
                    rule = [ "-t", "raw", "-D", "PREROUTING", "1"]
                    self.rule("ipv6", rule)
            else:
                rules = [
                    [ "-t", "raw", "-I", "PREROUTING", "1",
                      "-p", "icmpv6", "--icmpv6-type=router-advertisement",
                      "-j", "ACCEPT" ],       # RHBZ#1058505
                    [ "-t", "raw", "-I", "PREROUTING", "2",
                      "-m", "rpfilter", "--invert", "-j", "DROP" ]
                ]
                return self._ip6tables.set_rules(rules)

    # flush and policy

    def _flush(self):
        if self.ip4tables_enabled:
            self._ip4tables.flush(individual=self._individual_calls)
        if self.ip6tables_enabled:
            self._ip6tables.flush(individual=self._individual_calls)
        if self.ebtables_enabled:
            self._ebtables.flush(individual=(self._individual_calls or \
                                             not self._ebtables.restore_noflush_option))

    def _set_policy(self, policy, which="used"):
        if self.ip4tables_enabled:
            self._ip4tables.set_policy(policy, which,
                                       individual=self._individual_calls)
        if self.ip6tables_enabled:
            self._ip6tables.set_policy(policy, which,
                                       individual=self._individual_calls)
        if self.ebtables_enabled:
            self._ebtables.set_policy(policy, which,
                                      individual=(self._individual_calls or \
                                                  not self._ebtables.restore_noflush_option))

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
                raise FirewallError(EBTABLES_NO_REJECT,
                                    "'%s' not in {'ipv4'|'ipv6'}" % ipv)

        # replace %%ICMP%%
        try:
            i = rule.index("%%ICMP%%")
        except:
            pass
        else:
            if ipv in [ "ipv4", "ipv6" ]:
                rule[i] = ipXtables.ICMP[ipv]
            else:
                raise FirewallError(INVALID_IPV,
                                    "'%s' not in {'ipv4'|'ipv6'}" % ipv)

        # remove leading and trailing '"' for use with execve
        i = 0
        while i < len(rule):
            x = rule[i]
            if len(x) > 2 and x[0] == '"' and x[-1] == '"':
                rule[i] = x[1:-1]
            i += 1

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
            raise FirewallError(INVALID_IPV,
                                "'%s' not in {'ipv4'|'ipv6'|'eb'}" % ipv)

        return ""

    def rules(self, ipv, rules):
        _rules = [ ]

        for rule in rules:
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
                    raise FirewallError(EBTABLES_NO_REJECT,
                                        "'%s' not in {'ipv4'|'ipv6'}" % ipv)

            # replace %%ICMP%%
            try:
                i = rule.index("%%ICMP%%")
            except:
                pass
            else:
                if ipv in [ "ipv4", "ipv6" ]:
                    rule[i] = ipXtables.ICMP[ipv]
                else:
                    raise FirewallError(INVALID_IPV,
                                        "'%s' not in {'ipv4'|'ipv6'}" % ipv)

            _rules.append(rule)

        if ipv == "ipv4":
            # do not call if disabled
            if self.ip4tables_enabled:
                return self._ip4tables.set_rules(_rules)
        elif ipv == "ipv6":
            # do not call if disabled
            if self.ip6tables_enabled:
                return self._ip6tables.set_rules(_rules)
        elif ipv == "eb":
            # do not call if disabled
            if self.ebtables_enabled:
                return self._ebtables.set_rules(_rules)
        else:
            raise FirewallError(INVALID_IPV,
                                "'%s' not in {'ipv4'|'ipv6'|'eb'}" % ipv)

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

        if range == -2 or range == -1 or range is None or \
                (len(range) == 2 and range[0] >= range[1]):
            if range == -2:
                log.debug1("'%s': port > 65535" % port)
            elif range == -1:
                log.debug1("'%s': port is invalid" % port)
            elif range is None:
                log.debug1("'%s': port is ambiguous" % port)
            elif len(range) == 2 and range[0] >= range[1]:
                log.debug1("'%s': range start >= end" % port)
            raise FirewallError(INVALID_PORT, port)

    def check_tcpudp(self, protocol):
        if not protocol:
            raise FirewallError(MISSING_PROTOCOL)
        if not protocol in [ "tcp", "udp" ]:
            raise FirewallError(INVALID_PROTOCOL,
                                "'%s' not in {'tcp'|'udp'}" % protocol)

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
            raise FirewallError(INVALID_IPV,
                                "'%s' not in {'ipv4'|'ipv6'}")

    def check_icmptype(self, icmp):
        self.icmptype.check_icmptype(icmp)

    def check_timeout(self, timeout):
        if not isinstance(timeout, int):
            raise TypeError("%s is %s, expected int" % (timeout, type(timeout)))
        if int(timeout) < 0:
            raise FirewallError(INVALID_VALUE,
                                "timeout '%d' is not positive number" % timeout)

    # RELOAD

    def reload(self, stop=False):
        _panic = self._panic

        # save zone interfaces
        _zone_interfaces = { }
        for zone in self.zone.get_zones():
            _zone_interfaces[zone] = self.zone.get_settings(zone)["interfaces"]
        # save direct config
        _direct_config = self.direct.get_runtime_config()
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
            # if_new_dz has been introduced with the reload, we need to add it
            # https://github.com/t-woerner/firewalld/issues/53
            if _new_dz not in _zone_interfaces:
                _zone_interfaces[_new_dz] = { }
            # default zone changed. Move interfaces from old default zone to 
            # the new one.
            for iface, settings in list(_zone_interfaces[_old_dz].items()):
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
            raise FirewallError(ALREADY_ENABLED,
                                "panic mode already enabled")

        # TODO: use rule in raw table not default chain policy
        try:
            self._set_policy("DROP", "all")
        except Exception as msg:
            raise FirewallError(COMMAND_FAILED, msg)
        self._panic = True

    def disable_panic_mode(self):
        if not self._panic:
            raise FirewallError(NOT_ENABLED,
                                "panic mode is not enabled")

        # TODO: use rule in raw table not default chain policy
        try:
            self._set_policy("ACCEPT", "all")
        except Exception as msg:
            raise FirewallError(COMMAND_FAILED, msg)
        self._panic = False

    def query_panic_mode(self):
        return self._panic

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
            for iface, settings in list(_old_dz_settings["interfaces"].items()):
                if settings["__default__"]:
                    # move only those that were added to default zone
                    # (not those that were added to specific zone same as default)
                    self.zone.change_zone_of_interface("", iface)
        else:
            raise FirewallError(ZONE_ALREADY_SET, _zone)
