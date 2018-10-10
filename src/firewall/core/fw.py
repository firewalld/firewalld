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

__all__ = [ "Firewall" ]

import os.path
import sys
import copy
import time
import traceback
from firewall import config
from firewall import functions
from firewall.core import ipXtables
from firewall.core import ebtables
from firewall.core import nftables
from firewall.core import ipset
from firewall.core import modules
from firewall.core.fw_icmptype import FirewallIcmpType
from firewall.core.fw_service import FirewallService
from firewall.core.fw_zone import FirewallZone
from firewall.core.fw_direct import FirewallDirect
from firewall.core.fw_config import FirewallConfig
from firewall.core.fw_policies import FirewallPolicies
from firewall.core.fw_ipset import FirewallIPSet
from firewall.core.fw_transaction import FirewallTransaction
from firewall.core.fw_helper import FirewallHelper
from firewall.core.logger import log
from firewall.core.io.firewalld_conf import firewalld_conf
from firewall.core.io.direct import Direct
from firewall.core.io.service import service_reader
from firewall.core.io.icmptype import icmptype_reader
from firewall.core.io.zone import zone_reader, Zone
from firewall.core.io.ipset import ipset_reader
from firewall.core.io.helper import helper_reader
from firewall import errors
from firewall.errors import FirewallError

############################################################################
#
# class Firewall
#
############################################################################

class Firewall(object):
    def __init__(self):
        self._firewalld_conf = firewalld_conf(config.FIREWALLD_CONF)

        self.ip4tables_backend = ipXtables.ip4tables(self)
        self.ip4tables_enabled = True
        self.ip4tables_supported_icmp_types = [ ]
        self.ip6tables_backend = ipXtables.ip6tables(self)
        self.ip6tables_enabled = True
        self.ip6tables_supported_icmp_types = [ ]
        self.ebtables_backend = ebtables.ebtables()
        self.ebtables_enabled = True
        self.ipset_backend = ipset.ipset()
        self.ipset_enabled = True
        self.ipset_supported_types = [ ]
        self.nftables_backend = nftables.nftables(self)
        self.nftables_enabled = True

        self.modules_backend = modules.modules()

        self.icmptype = FirewallIcmpType(self)
        self.service = FirewallService(self)
        self.zone = FirewallZone(self)
        self.direct = FirewallDirect(self)
        self.config = FirewallConfig(self)
        self.policies = FirewallPolicies()
        self.ipset = FirewallIPSet(self)
        self.helper = FirewallHelper(self)

        self.__init_vars()

    def __repr__(self):
        return '%s(%r, %r, %r, %r, %r, %r, %r, %r, %r, %r, %r, %r, %r, %r, %r)' % \
            (self.__class__, self.ip4tables_enabled, self.ip6tables_enabled,
             self.ebtables_enabled, self._state, self._panic,
             self._default_zone, self._module_refcount, self._marks,
             self._min_mark, self.cleanup_on_exit, self.ipv6_rpfilter_enabled,
             self.ipset_enabled, self._individual_calls, self._log_denied,
             self._automatic_helpers)

    def __init_vars(self):
        self._state = "INIT"
        self._panic = False
        self._default_zone = ""
        self._module_refcount = { }
        self._marks = [ ]
        # fallback settings will be overloaded by firewalld.conf
        self._min_mark = config.FALLBACK_MINIMAL_MARK
        self.cleanup_on_exit = config.FALLBACK_CLEANUP_ON_EXIT
        self.ipv6_rpfilter_enabled = config.FALLBACK_IPV6_RPFILTER
        self._individual_calls = config.FALLBACK_INDIVIDUAL_CALLS
        self._log_denied = config.FALLBACK_LOG_DENIED
        self._automatic_helpers = config.FALLBACK_AUTOMATIC_HELPERS
        self._firewall_backend = config.FALLBACK_FIREWALL_BACKEND
        self.nf_conntrack_helper_setting = 0
        self.nf_conntrack_helpers = { }
        self.nf_nat_helpers = { }

    def individual_calls(self):
        return self._individual_calls

    def _check_tables(self):
        # check if iptables, ip6tables and ebtables are usable, else disable
        if self.ip4tables_enabled and \
           "filter" not in self.get_backend_by_ipv("ipv4").get_available_tables():
            log.warning("iptables not usable, disabling IPv4 firewall.")
            self.ip4tables_enabled = False

        if self.ip6tables_enabled and \
           "filter" not in self.get_backend_by_ipv("ipv6").get_available_tables():
            log.warning("ip6tables not usable, disabling IPv6 firewall.")
            self.ip6tables_enabled = False

        if self.ebtables_enabled and \
           "filter" not in self.get_backend_by_ipv("eb").get_available_tables():
            log.warning("ebtables not usable, disabling ethernet bridge firewall.")
            self.ebtables_enabled = False

        # is there at least support for ipv4 or ipv6
        if not self.ip4tables_enabled and not self.ip6tables_enabled \
           and not self.nftables_enabled:
            log.fatal("No IPv4 and IPv6 firewall.")
            sys.exit(1)

    def _start_check(self):
        try:
            self.ipset_backend.set_list()
        except ValueError:
            log.warning("ipset not usable, disabling ipset usage in firewall.")
            # ipset is not usable, no supported types
            self.ipset_enabled = False
            self.ipset_supported_types = [ ]
        else:
            # ipset is usable, get all supported types
            self.ipset_supported_types = self.ipset_backend.set_supported_types()

        self.ip4tables_backend.fill_exists()
        if not self.ip4tables_backend.restore_command_exists:
            if self.ip4tables_backend.command_exists:
                log.warning("iptables-restore is missing, using "
                            "individual calls for IPv4 firewall.")
            else:
                log.warning("iptables-restore and iptables are missing, "
                            "disabling IPv4 firewall.")
                self.ip4tables_enabled = False
        if self.ip4tables_enabled:
            self.ip4tables_supported_icmp_types = \
                self.ip4tables_backend.supported_icmp_types()
        else:
            self.ip4tables_supported_icmp_types = [ ]
        self.ip6tables_backend.fill_exists()
        if not self.ip6tables_backend.restore_command_exists:
            if self.ip6tables_backend.command_exists:
                log.warning("ip6tables-restore is missing, using "
                            "individual calls for IPv6 firewall.")
            else:
                log.warning("ip6tables-restore and ip6tables are missing, "
                            "disabling IPv6 firewall.")
                self.ip6tables_enabled = False
        if self.ip6tables_enabled:
            self.ip6tables_supported_icmp_types = \
                self.ip6tables_backend.supported_icmp_types()
        else:
            self.ip6tables_supported_icmp_types = [ ]
        self.ebtables_backend.fill_exists()
        if not self.ebtables_backend.restore_command_exists:
            if self.ebtables_backend.command_exists:
                log.warning("ebtables-restore is missing, using "
                            "individual calls for bridge firewall.")
            else:
                log.warning("ebtables-restore and ebtables are missing, "
                            "disabling bridge firewall.")
                self.ebtables_enabled = False

        if self.ebtables_enabled and not self._individual_calls and \
           not self.ebtables_backend.restore_noflush_option:
            log.debug1("ebtables-restore is not supporting the --noflush "
                       "option, will therefore not be used")

        if os.path.exists(config.COMMANDS["modinfo"]):
            self.nf_conntrack_helpers = functions.get_nf_conntrack_helpers()
            if len(self.nf_conntrack_helpers) > 0:
                log.debug1("Conntrack helpers supported by the kernel:")
                for key,values in self.nf_conntrack_helpers.items():
                    log.debug1("  %s: %s", key, ", ".join(values))
            else:
                log.debug1("No conntrack helpers supported by the kernel.")

            self.nf_nat_helpers = functions.get_nf_nat_helpers()
            if len(self.nf_nat_helpers) > 0:
                log.debug1("NAT helpers supported by the kernel:")
                for key,values in self.nf_nat_helpers.items():
                    log.debug1("  %s: %s", key, ", ".join(values))
            else:
                log.debug1("No NAT helpers supported by the kernel.")

        else:
            self.nf_conntrack_helpers = { }
            self.nf_nat_helpers = { }
            log.warning("modinfo command is missing, not able to detect conntrack helpers.")

    def _start(self, reload=False, complete_reload=False):
        # initialize firewall
        default_zone = config.FALLBACK_ZONE

        # load firewalld config
        log.debug1("Loading firewalld config file '%s'", config.FIREWALLD_CONF)
        try:
            self._firewalld_conf.read()
        except Exception as msg:
            log.warning(msg)
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
                log.debug1("CleanupOnExit is set to '%s'",
                           self.cleanup_on_exit)

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

            if self._firewalld_conf.get("LogDenied"):
                value = self._firewalld_conf.get("LogDenied")
                if value is None or value.lower() == "no":
                    self._log_denied = "off"
                else:
                    self._log_denied = value.lower()
                    log.debug1("LogDenied is set to '%s'", self._log_denied)

            if self._firewalld_conf.get("AutomaticHelpers"):
                value = self._firewalld_conf.get("AutomaticHelpers")
                if value is not None:
                    if value.lower() in [ "no", "false" ]:
                        self._automatic_helpers = "no"
                    elif value.lower() in [ "yes", "true" ]:
                        self._automatic_helpers = "yes"
                    else:
                        self._automatic_helpers = value.lower()
                    log.debug1("AutomaticHelpers is set to '%s'",
                               self._automatic_helpers)

            if self._firewalld_conf.get("FirewallBackend"):
                self._firewall_backend = self._firewalld_conf.get("FirewallBackend")
                log.debug1("FirewallBackend is set to '%s'",
                           self._firewall_backend)

        self.config.set_firewalld_conf(copy.deepcopy(self._firewalld_conf))

        self._select_firewall_backend(self._firewall_backend)

        self._start_check()

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
        self._loader(config.FIREWALLD_IPSETS, "ipset")
        self._loader(config.ETC_FIREWALLD_IPSETS, "ipset")

        # load icmptype files
        self._loader(config.FIREWALLD_ICMPTYPES, "icmptype")
        self._loader(config.ETC_FIREWALLD_ICMPTYPES, "icmptype")

        if len(self.icmptype.get_icmptypes()) == 0:
            log.error("No icmptypes found.")

        # load helper files
        self._loader(config.FIREWALLD_HELPERS, "helper")
        self._loader(config.ETC_FIREWALLD_HELPERS, "helper")

        # load service files
        self._loader(config.FIREWALLD_SERVICES, "service")
        self._loader(config.ETC_FIREWALLD_SERVICES, "service")

        if len(self.service.get_services()) == 0:
            log.error("No services found.")

        # load zone files
        self._loader(config.FIREWALLD_ZONES, "zone")
        self._loader(config.ETC_FIREWALLD_ZONES, "zone")

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

        # load direct rules
        obj = Direct(config.FIREWALLD_DIRECT)
        if os.path.exists(config.FIREWALLD_DIRECT):
            log.debug1("Loading direct rules file '%s'" % \
                       config.FIREWALLD_DIRECT)
            try:
                obj.read()
            except Exception as msg:
                log.error("Failed to load direct rules file '%s': %s",
                          config.FIREWALLD_DIRECT, msg)
        self.direct.set_permanent_config(obj)
        self.config.set_direct(copy.deepcopy(obj))

        # automatic helpers
        #
        # NOTE: must force loading of nf_conntrack to make sure the values are
        # available in /proc
        module_return = self.handle_modules(["nf_conntrack"], True)
        if module_return:
            log.error("Failed to load nf_conntrack module: %s" % module_return[1])
            sys.exit(1)
        if self._automatic_helpers != "system":
            functions.set_nf_conntrack_helper_setting(self._automatic_helpers == "yes")
        self.nf_conntrack_helper_setting = \
            functions.get_nf_conntrack_helper_setting()

        # check if needed tables are there
        self._check_tables()

        if log.getDebugLogLevel() > 0:
            # get time before flushing and applying
            tm1 = time.time()

        # Start transaction
        transaction = FirewallTransaction(self)

        # flush rules
        self.flush(use_transaction=transaction)

        # If modules need to be unloaded in complete reload or if there are
        # ipsets to get applied, limit the transaction to flush.
        #
        # Future optimization for the ipset case in reload: The transaction
        # only needs to be split here if there are conflicting ipset types in
        # exsting ipsets and the configuration in firewalld.
        if (reload and complete_reload) or \
           (self.ipset_enabled and self.ipset.has_ipsets()):
            transaction.execute(True)
            transaction.clear()

        # complete reload: unload modules also
        if reload and complete_reload:
            log.debug1("Unloading firewall modules")
            self.modules_backend.unload_firewall_modules()

        self.apply_default_tables(use_transaction=transaction)
        transaction.execute(True)
        transaction.clear()

        # apply settings for loaded ipsets while reloading here
        if self.ipset_enabled and self.ipset.has_ipsets():
            log.debug1("Applying ipsets")
            self.ipset.apply_ipsets()

        # Start or continue with transaction

        # apply default rules
        log.debug1("Applying default rule set")
        self.apply_default_rules(use_transaction=transaction)

        # apply settings for loaded zones
        log.debug1("Applying used zones")
        self.zone.apply_zones(use_transaction=transaction)

        self._default_zone = self.check_zone(default_zone)
        self.zone.change_default_zone(None, self._default_zone,
                                      use_transaction=transaction)

        # Execute transaction
        transaction.execute(True)

        # Start new transaction for direct rules
        transaction.clear()

        # apply direct chains, rules and passthrough rules
        if self.direct.has_configuration():
            log.debug1("Applying direct chains rules and passthrough rules")
            self.direct.apply_direct(transaction)

            # since direct rules are easy to make syntax errors lets highlight
            # the cause if the transaction fails.
            try:
                transaction.execute(True)
                transaction.clear()
            except FirewallError as e:
                raise FirewallError(e.code, "Direct: %s" % (e.msg if e.msg else ""))
            except Exception:
                raise

        del transaction

        if log.getDebugLogLevel() > 1:
            # get time after flushing and applying
            tm2 = time.time()
            log.debug2("Flushing and applying took %f seconds" % (tm2 - tm1))

    def start(self):
        try:
            self._start()
        except Exception:
            self._state = "FAILED"
            self.set_policy("ACCEPT")
            raise
        else:
            self._state = "RUNNING"
            self.set_policy("ACCEPT")

    def _loader(self, path, reader_type, combine=False):
        # combine: several zone files are getting combined into one obj
        if not os.path.isdir(path):
            return

        if combine:
            if path.startswith(config.ETC_FIREWALLD) and reader_type == "zone":
                combined_zone = Zone()
                combined_zone.name = os.path.basename(path)
                combined_zone.check_name(combined_zone.name)
                combined_zone.path = path
                combined_zone.default = False
            else:
                combine = False

        for filename in sorted(os.listdir(path)):
            if not filename.endswith(".xml"):
                if path.startswith(config.ETC_FIREWALLD) and \
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
                    elif obj.path.startswith(config.ETC_FIREWALLD):
                        obj.default = True
                    try:
                        self.icmptype.add_icmptype(obj)
                    except FirewallError as error:
                        log.info1("%s: %s, ignoring for run-time." % \
                                    (obj.name, str(error)))
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
                    elif obj.path.startswith(config.ETC_FIREWALLD):
                        obj.default = True
                    self.service.add_service(obj)
                    # add a deep copy to the configuration interface
                    self.config.add_service(copy.deepcopy(obj))
                elif reader_type == "zone":
                    obj = zone_reader(filename, path, no_check_name=combine)
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
                    elif obj.path.startswith(config.ETC_FIREWALLD):
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
                    elif obj.path.startswith(config.ETC_FIREWALLD):
                        obj.default = True
                    try:
                        self.ipset.add_ipset(obj)
                    except FirewallError as error:
                        log.warning("%s: %s, ignoring for run-time." % \
                                    (obj.name, str(error)))
                    # add a deep copy to the configuration interface
                    self.config.add_ipset(copy.deepcopy(obj))
                elif reader_type == "helper":
                    obj = helper_reader(filename, path)
                    if obj.name in self.helper.get_helpers():
                        orig_obj = self.helper.get_helper(obj.name)
                        log.debug1("  Overloads %s '%s' ('%s/%s')", reader_type,
                                   orig_obj.name, orig_obj.path,
                                   orig_obj.filename)
                        self.helper.remove_helper(orig_obj.name)
                    elif obj.path.startswith(config.ETC_FIREWALLD):
                        obj.default = True
                    self.helper.add_helper(obj)
                    # add a deep copy to the configuration interface
                    self.config.add_helper(copy.deepcopy(obj))
                else:
                    log.fatal("Unknown reader type %s", reader_type)
            except FirewallError as msg:
                log.error("Failed to load %s file '%s': %s", reader_type,
                          name, msg)
            except Exception:
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
                except Exception:
                    pass
                self.config.forget_zone(combined_zone.name)
            self.zone.add_zone(combined_zone)

    def cleanup(self):
        self.icmptype.cleanup()
        self.service.cleanup()
        self.zone.cleanup()
        self.ipset.cleanup()
        self.helper.cleanup()
        self.config.cleanup()
        self.direct.cleanup()
        self.policies.cleanup()
        self._firewalld_conf.cleanup()
        self.__init_vars()

    def stop(self):
        if self.cleanup_on_exit:
            self.flush()
            self.set_policy("ACCEPT")
            self.modules_backend.unload_firewall_modules()

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

    # handle modules

    def handle_modules(self, _modules, enable):
        for i,module in enumerate(_modules):
            if enable:
                (status, msg) = self.modules_backend.load_module(module)
            else:
                if self._module_refcount[module] > 1:
                    status = 0 # module referenced more then one, do not unload
                else:
                    (status, msg) = self.modules_backend.unload_module(module)
            if status != 0:
                if enable:
                    return (_modules[:i], msg) # cleanup modules and error msg
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

    def _select_firewall_backend(self, backend):
        if backend != "nftables":
            self.nftables_enabled = False
        # even if using nftables, the other backends are enabled for use with
        # the direct interface. nftables is used for the firewalld primitives.

    def get_backend_by_name(self, name):
        for backend in self.all_backends():
            if backend.name == name:
                return backend
        raise FirewallError(errors.UNKNOWN_ERROR,
                            "'%s' backend does not exist" % name)

    def get_backend_by_ipv(self, ipv):
        if self.nftables_enabled:
            return self.nftables_backend
        if ipv == "ipv4":
            return self.ip4tables_backend
        elif ipv == "ipv6":
            return self.ip6tables_backend
        elif ipv == "eb":
            return self.ebtables_backend
        raise FirewallError(errors.INVALID_IPV,
                            "'%s' is not a valid backend" % ipv)

    def get_direct_backend_by_ipv(self, ipv):
        if ipv == "ipv4":
            return self.ip4tables_backend
        elif ipv == "ipv6":
            return self.ip6tables_backend
        elif ipv == "eb":
            return self.ebtables_backend
        raise FirewallError(errors.INVALID_IPV,
                            "'%s' is not a valid backend" % ipv)

    def is_backend_enabled(self, name):
        if name == "ip4tables":
            return self.ip4tables_enabled
        elif name == "ip6tables":
            return self.ip6tables_enabled
        elif name == "ebtables":
            return self.ebtables_enabled
        elif name == "nftables":
            return self.nftables_enabled
        return False

    def is_ipv_enabled(self, ipv):
        if self.nftables_enabled:
            return True
        if ipv == "ipv4":
            return self.ip4tables_enabled
        elif ipv == "ipv6":
            return self.ip6tables_enabled
        elif ipv == "eb":
            return self.ebtables_enabled
        return False

    def enabled_backends(self):
        backends = []
        if self.nftables_enabled:
            backends.append(self.nftables_backend)
        else:
            if self.ip4tables_enabled:
                backends.append(self.ip4tables_backend)
            if self.ip6tables_enabled:
                backends.append(self.ip6tables_backend)
            if self.ebtables_enabled:
                backends.append(self.ebtables_backend)
        return backends

    def all_backends(self):
        backends = []
        if self.ip4tables_enabled:
            backends.append(self.ip4tables_backend)
        if self.ip6tables_enabled:
            backends.append(self.ip6tables_backend)
        if self.ebtables_enabled:
            backends.append(self.ebtables_backend)
        if self.nftables_enabled:
            backends.append(self.nftables_backend)
        return backends

    def apply_default_tables(self, use_transaction=None):
        if use_transaction is None:
            transaction = FirewallTransaction(self)
        else:
            transaction = use_transaction

        for backend in self.enabled_backends():
            transaction.add_rules(backend, backend.build_default_tables())

        if use_transaction is None:
            transaction.execute(True)

    def apply_default_rules(self, use_transaction=None):
        if use_transaction is None:
            transaction = FirewallTransaction(self)
        else:
            transaction = use_transaction

        for backend in self.enabled_backends():
            rules = backend.build_default_rules(self._log_denied)
            transaction.add_rules(backend, rules)

        ipv6_backend = self.get_backend_by_ipv("ipv6")
        if self.ipv6_rpfilter_enabled and \
           "raw" in ipv6_backend.get_available_tables():

            # Execute existing transaction
            transaction.execute(True)
            # Start new transaction
            transaction.clear()

            rules = ipv6_backend.build_rpfilter_rules(self._log_denied)
            transaction.add_rules(ipv6_backend, rules)

            # Execute ipv6_rpfilter transaction, it might fail
            try:
                transaction.execute(True)
            except FirewallError as msg:
                log.warning("Applying rules for ipv6_rpfilter failed: %s", msg)
            # Start new transaction
            transaction.clear()

        else:
            if use_transaction is None:
                transaction.execute(True)

    # flush and policy

    def flush(self, use_transaction=None):
        if use_transaction is None:
            transaction = FirewallTransaction(self)
        else:
            transaction = use_transaction

        log.debug1("Flushing rule set")

        for backend in self.all_backends():
            rules = backend.build_flush_rules()
            transaction.add_rules(backend, rules)

        if use_transaction is None:
            transaction.execute(True)

    def set_policy(self, policy, use_transaction=None):
        if use_transaction is None:
            transaction = FirewallTransaction(self)
        else:
            transaction = use_transaction

        log.debug1("Setting policy to '%s'", policy)

        for backend in self.enabled_backends():
            rules = backend.build_set_policy_rules(policy)
            transaction.add_rules(backend, rules)

        if use_transaction is None:
            transaction.execute(True)

    # rule function used in handle_ functions

    def rule(self, backend_name, rule):
        if not rule:
            return ""

        backend = self.get_backend_by_name(backend_name)
        if not backend:
            raise FirewallError(errors.INVALID_IPV,
                                "'%s' is not a valid backend" % backend_name)

        if not self.is_backend_enabled(backend_name):
            return ""

        return backend.set_rule(rule, self._log_denied)

    def rules(self, backend_name, rules):
        _rules = list(filter(None, rules))

        backend = self.get_backend_by_name(backend_name)
        if not backend:
            raise FirewallError(errors.INVALID_IPV,
                                "'%s' is not a valid backend" % backend_name)

        if not self.is_backend_enabled(backend_name):
            return ""

        if self._individual_calls or \
           not backend.restore_command_exists or \
           (backend_name == "ebtables" and not self.ebtables_backend.restore_noflush_option):
            for i,rule in enumerate(_rules):
                try:
                    backend.set_rule(rule, self._log_denied)
                except Exception as msg:
                    log.debug1(traceback.format_exc())
                    log.error("Failed to apply rules. A firewall reload might solve the issue if the firewall has been modified using ip*tables or ebtables.")
                    log.error(msg)
                    for rule in reversed(_rules[:i]):
                        try:
                            backend.set_rule(backend.reverse_rule(rule), self._log_denied)
                        except Exception:
                            # ignore errors here
                            pass
                    return False
            return True
        else:
            return backend.set_rules(_rules, self._log_denied)

    # check functions

    def check_panic(self):
        if self._panic:
            raise FirewallError(errors.PANIC_MODE)

    def check_zone(self, zone):
        _zone = zone
        if not _zone or _zone == "":
            _zone = self.get_default_zone()
        if _zone not in self.zone.get_zones():
            raise FirewallError(errors.INVALID_ZONE, _zone)
        return _zone

    def check_interface(self, interface):
        if not functions.checkInterface(interface):
            raise FirewallError(errors.INVALID_INTERFACE, interface)

    def check_service(self, service):
        self.service.check_service(service)

    def check_port(self, port):
        if not functions.check_port(port):
            raise FirewallError(errors.INVALID_PORT, port)

    def check_tcpudp(self, protocol):
        if not protocol:
            raise FirewallError(errors.MISSING_PROTOCOL)
        if protocol not in [ "tcp", "udp", "sctp", "dccp" ]:
            raise FirewallError(errors.INVALID_PROTOCOL,
                                "'%s' not in {'tcp'|'udp'|'sctp'|'dccp'}" % \
                                protocol)

    def check_ip(self, ip):
        if not functions.checkIP(ip):
            raise FirewallError(errors.INVALID_ADDR, ip)

    def check_address(self, ipv, source):
        if ipv == "ipv4":
            if not functions.checkIPnMask(source):
                raise FirewallError(errors.INVALID_ADDR, source)
        elif ipv == "ipv6":
            if not functions.checkIP6nMask(source):
                raise FirewallError(errors.INVALID_ADDR, source)
        else:
            raise FirewallError(errors.INVALID_IPV,
                                "'%s' not in {'ipv4'|'ipv6'}")

    def check_icmptype(self, icmp):
        self.icmptype.check_icmptype(icmp)

    def check_timeout(self, timeout):
        if not isinstance(timeout, int):
            raise TypeError("%s is %s, expected int" % (timeout, type(timeout)))
        if int(timeout) < 0:
            raise FirewallError(errors.INVALID_VALUE,
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
        self.cleanup()

        self.set_policy("DROP")

        start_exception = None
        try:
            self._start(reload=True, complete_reload=stop)
        except Exception as e:
            # save the exception for later, but continue restoring interfaces,
            # etc. We'll re-raise it at the end.
            start_exception = e

        # handle interfaces in the default zone and move them to the new
        # default zone if it changed
        _new_dz = self.get_default_zone()
        if _new_dz != _old_dz:
            # if_new_dz has been introduced with the reload, we need to add it
            # https://github.com/firewalld/firewalld/issues/53
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
            for zone in list(_zone_interfaces.keys()):
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
            self.set_policy("ACCEPT")

        if start_exception:
            self._state = "FAILED"
            raise start_exception
        else:
            self._state = "RUNNING"

    # STATE

    def get_state(self):
        return self._state

    # PANIC MODE

    def enable_panic_mode(self):
        if self._panic:
            raise FirewallError(errors.ALREADY_ENABLED,
                                "panic mode already enabled")

        # TODO: use rule in raw table not default chain policy
        try:
            self.set_policy("DROP")
        except Exception as msg:
            raise FirewallError(errors.COMMAND_FAILED, msg)
        self._panic = True

    def disable_panic_mode(self):
        if not self._panic:
            raise FirewallError(errors.NOT_ENABLED,
                                "panic mode is not enabled")

        # TODO: use rule in raw table not default chain policy
        try:
            self.set_policy("ACCEPT")
        except Exception as msg:
            raise FirewallError(errors.COMMAND_FAILED, msg)
        self._panic = False

    def query_panic_mode(self):
        return self._panic

    # LOG DENIED

    def get_log_denied(self):
        return self._log_denied

    def set_log_denied(self, value):
        if value not in config.LOG_DENIED_VALUES:
            raise FirewallError(errors.INVALID_VALUE,
                                "'%s', choose from '%s'" % \
                                (value, "','".join(config.LOG_DENIED_VALUES)))

        if value != self.get_log_denied():
            self._log_denied = value
            self._firewalld_conf.set("LogDenied", value)
            self._firewalld_conf.write()
        else:
            raise FirewallError(errors.ALREADY_SET, value)

    # AUTOMATIC HELPERS

    def get_automatic_helpers(self):
        return self._automatic_helpers

    def set_automatic_helpers(self, value):
        if value not in config.AUTOMATIC_HELPERS_VALUES:
            raise FirewallError(errors.INVALID_VALUE,
                                "'%s', choose from '%s'" % \
                                (value, "','".join(config.AUTOMATIC_HELPERS_VALUES)))

        if value != self.get_automatic_helpers():
            self._automatic_helpers = value
            self._firewalld_conf.set("AutomaticHelpers", value)
            self._firewalld_conf.write()
        else:
            raise FirewallError(errors.ALREADY_SET, value)

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
            raise FirewallError(errors.ZONE_ALREADY_SET, _zone)
