# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2010-2016 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>

import os
import sys
import copy
import time
import traceback
from typing import Dict, List
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
from firewall.core.fw_policy import FirewallPolicy
from firewall.core.fw_nm import nm_get_bus_name, nm_get_interfaces_in_zone
from firewall.core.logger import log
from firewall.core.io.io_object import IO_Object
from firewall.core.io.firewalld_conf import firewalld_conf
from firewall.core.io.direct import Direct
from firewall.core.io.service import service_reader
from firewall.core.io.icmptype import icmptype_reader
from firewall.core.io.zone import zone_reader, Zone
from firewall.core.io.ipset import ipset_reader
from firewall.core.ipset import IPSET_TYPES
from firewall.core.io.helper import helper_reader
from firewall.core.io.policy import policy_reader
from firewall.core.io.functions import check_on_disk_config
from firewall.core.rich import Rich_Rule
from firewall import errors
from firewall.errors import FirewallError

############################################################################
#
# class Firewall
#
############################################################################


class Firewall:
    def __init__(self, offline=False):
        self._firewalld_conf = firewalld_conf(config.FIREWALLD_CONF)
        self._offline = offline

        if not offline:
            self.ip4tables_backend = ipXtables.ip4tables(self)
            self.ip6tables_backend = ipXtables.ip6tables(self)
            self.ebtables_backend = ebtables.ebtables()
            self.ipset_backend = ipset.ipset()
            self.nftables_backend = nftables.nftables(self)
            self.modules_backend = modules.modules()

        self.icmptype = FirewallIcmpType(self)
        self.service = FirewallService(self)
        self.zone = FirewallZone(self)
        self.direct = FirewallDirect(self)
        self.config = FirewallConfig(self)
        self.policies = FirewallPolicies()
        self.ipset = FirewallIPSet(self)
        self.helper = FirewallHelper(self)
        self.policy = FirewallPolicy(self)

        self.__init_vars()

    def __repr__(self):
        return "%s(%r, %r, %r, %r, %r, %r, %r, %r, %r, %r, %r, %r, %r, %r)" % (
            self.__class__,
            self.ip4tables_enabled,
            self.ip6tables_enabled,
            self.ebtables_enabled,
            self._state,
            self._panic,
            self._default_zone,
            self._module_refcount,
            self._marks,
            self.cleanup_on_exit,
            self.cleanup_modules_on_exit,
            self.ipv6_rpfilter_enabled,
            self.ipset_enabled,
            self._individual_calls,
            self._log_denied,
        )

    def __init_vars(self):
        self._state = "INIT"
        self._panic = False
        self._default_zone = config.FALLBACK_ZONE
        self._default_zone_interfaces = []
        self._nm_assigned_interfaces = []
        self._module_refcount = {}
        self._marks = []
        # fallback settings will be overloaded by firewalld.conf
        self.cleanup_on_exit = config.FALLBACK_CLEANUP_ON_EXIT
        self.cleanup_modules_on_exit = config.FALLBACK_CLEANUP_MODULES_ON_EXIT
        self.ipv6_rpfilter_enabled = config.FALLBACK_IPV6_RPFILTER
        self._individual_calls = config.FALLBACK_INDIVIDUAL_CALLS
        self._log_denied = config.FALLBACK_LOG_DENIED
        self._firewall_backend = config.FALLBACK_FIREWALL_BACKEND
        self._flush_all_on_reload = config.FALLBACK_FLUSH_ALL_ON_RELOAD
        self._rfc3964_ipv4 = config.FALLBACK_RFC3964_IPV4
        self._allow_zone_drifting = config.FALLBACK_ALLOW_ZONE_DRIFTING
        self._nftables_flowtable = config.FALLBACK_NFTABLES_FLOWTABLE
        self._nftables_counters = config.FALLBACK_NFTABLES_COUNTERS

        if self._offline:
            self.ip4tables_enabled = False
            self.ip6tables_enabled = False
            self.ebtables_enabled = False
            self.ipset_enabled = False
            self.ipset_supported_types = IPSET_TYPES
            self.nftables_enabled = False
        else:
            self.ip4tables_enabled = True
            self.ipv4_supported_icmp_types = []
            self.ip6tables_enabled = True
            self.ipv6_supported_icmp_types = []
            self.ebtables_enabled = True
            self.ipset_enabled = True
            self.ipset_supported_types = IPSET_TYPES
            self.nftables_enabled = True

    def get_all_io_objects_dict(self):
        """
        Returns a dict of dicts of all runtime config objects.
        """
        conf_dict = {}
        conf_dict["ipsets"] = {
            _ipset: self.ipset.get_ipset(_ipset) for _ipset in self.ipset.get_ipsets()
        }
        conf_dict["helpers"] = {
            helper: self.helper.get_helper(helper)
            for helper in self.helper.get_helpers()
        }
        conf_dict["icmptypes"] = {
            icmptype: self.icmptype.get_icmptype(icmptype)
            for icmptype in self.icmptype.get_icmptypes()
        }
        conf_dict["services"] = {
            service: self.service.get_service(service)
            for service in self.service.get_services()
        }
        conf_dict["zones"] = {
            zone: self.zone.get_zone(zone) for zone in self.zone.get_zones()
        }
        conf_dict["policies"] = {
            policy: self.policy.get_policy(policy)
            for policy in self.policy.get_policies_not_derived_from_zone()
        }

        conf_dict["conf"] = {}
        conf_dict["conf"]["FirewallBackend"] = self._firewalld_conf.get(
            "FirewallBackend"
        )

        # The runtime might not actually support all the defined icmptypes.
        # This is the case if ipv6 (ip6tables) is disabled. Unfortunately users
        # disable IPv6 and also expect the IPv6 stuff to be silently ignored.
        # This is problematic for defaults that include IPv6 stuff, e.g. policy
        # 'allow-host-ipv6'. Use this to make a better decision about errors vs
        # warnings.
        #
        conf_dict["runtime"] = {}
        conf_dict["runtime"]["icmptypes_unsupported"] = {}
        for icmptype in set(self.config.get_icmptypes()).difference(
            set(self.icmptype.get_icmptypes())
        ):
            conf_dict["runtime"]["icmptypes_unsupported"][
                icmptype
            ] = self.config.get_icmptype(icmptype)
        # Some icmptypes support multiple families. Add those that are missing
        # support for a subset of families.
        for icmptype in set(self.config.get_icmptypes()).intersection(
            set(self.icmptype.get_icmptypes())
        ):
            if (
                icmptype not in self.ipv4_supported_icmp_types
                or icmptype not in self.ipv6_supported_icmp_types
            ):
                conf_dict["runtime"]["icmptypes_unsupported"][icmptype] = copy.copy(
                    self.config.get_icmptype(icmptype)
                )
                conf_dict["runtime"]["icmptypes_unsupported"][icmptype].destination = []
                if icmptype not in self.ipv4_supported_icmp_types:
                    conf_dict["runtime"]["icmptypes_unsupported"][
                        icmptype
                    ].destination.append("ipv4")
                if icmptype not in self.ipv6_supported_icmp_types:
                    conf_dict["runtime"]["icmptypes_unsupported"][
                        icmptype
                    ].destination.append("ipv6")

        return conf_dict

    def full_check_config(self, extra_io_objects: Dict[str, List[IO_Object]] = {}):
        all_io_objects = self.get_all_io_objects_dict()
        # mix in the extra objects
        for type_key in extra_io_objects:
            for obj in extra_io_objects[type_key]:
                all_io_objects[type_key][obj.name] = obj

        # we need to check in a well defined order because some io_objects will
        # cross-check others
        order = ["ipsets", "helpers", "icmptypes", "services", "zones", "policies"]
        for io_obj_type in order:
            io_objs = all_io_objects[io_obj_type]
            for name, io_obj in io_objs.items():
                io_obj.check_config_dict(io_obj.export_config_dict(), all_io_objects)

    def _start_check_tables(self):
        # check if iptables, ip6tables and ebtables are usable, else disable
        if (
            self.ip4tables_enabled
            and "filter" not in self.ip4tables_backend.get_available_tables()
        ):
            log.info1("iptables is not usable.")
            self.ip4tables_enabled = False

        if (
            self.ip6tables_enabled
            and "filter" not in self.ip6tables_backend.get_available_tables()
        ):
            log.info1("ip6tables is not usable.")
            self.ip6tables_enabled = False

        if (
            self.ebtables_enabled
            and "filter" not in self.ebtables_backend.get_available_tables()
        ):
            log.info1("ebtables is not usable.")
            self.ebtables_enabled = False

        # is there at least support for ipv4 or ipv6
        if (
            not self.ip4tables_enabled
            and not self.ip6tables_enabled
            and not self.nftables_enabled
        ):
            raise FirewallError(errors.UNKNOWN_ERROR, "No IPv4 and IPv6 firewall.")

    def _start_probe_backends(self):
        try:
            self.ipset_backend.set_list()
        except ValueError:
            if self.nftables_enabled:
                log.info1(
                    "ipset not usable, disabling ipset usage in firewall. Other set backends (nftables) remain usable."
                )
            else:
                log.warning("ipset not usable, disabling ipset usage in firewall.")
                self.ipset_supported_types = []
            # ipset is not usable
            self.ipset_enabled = False
        else:
            # ipset is usable, get all supported types
            self.ipset_supported_types = self.ipset_backend.set_supported_types()

        self.ip4tables_backend.fill_exists()
        if not self.ip4tables_backend.restore_command_exists:
            if self.ip4tables_backend.command_exists:
                log.warning(
                    "iptables-restore is missing, using "
                    "individual calls for IPv4 firewall."
                )
            else:
                if self.nftables_enabled:
                    log.info1(
                        "iptables-restore and iptables are missing, "
                        "IPv4 direct rules won't be usable."
                    )
                else:
                    log.warning(
                        "iptables-restore and iptables are missing, "
                        "disabling IPv4 firewall."
                    )
                self.ip4tables_enabled = False
        if self.nftables_enabled:
            self.ipv4_supported_icmp_types = self.nftables_backend.supported_icmp_types(
                "ipv4"
            )
        else:
            if self.ip4tables_enabled:
                self.ipv4_supported_icmp_types = (
                    self.ip4tables_backend.supported_icmp_types()
                )
            else:
                self.ipv4_supported_icmp_types = []
        self.ip6tables_backend.fill_exists()
        if not self.ip6tables_backend.restore_command_exists:
            if self.ip6tables_backend.command_exists:
                log.warning(
                    "ip6tables-restore is missing, using "
                    "individual calls for IPv6 firewall."
                )
            else:
                if self.nftables_enabled:
                    log.info1(
                        "ip6tables-restore and ip6tables are missing, "
                        "IPv6 direct rules won't be usable."
                    )
                else:
                    log.warning(
                        "ip6tables-restore and ip6tables are missing, "
                        "disabling IPv6 firewall."
                    )
                self.ip6tables_enabled = False
        if self.nftables_enabled:
            self.ipv6_supported_icmp_types = self.nftables_backend.supported_icmp_types(
                "ipv6"
            )
        else:
            if self.ip6tables_enabled:
                self.ipv6_supported_icmp_types = (
                    self.ip6tables_backend.supported_icmp_types()
                )
            else:
                self.ipv6_supported_icmp_types = []
        self.ebtables_backend.fill_exists()
        if not self.ebtables_backend.restore_command_exists:
            if self.ebtables_backend.command_exists:
                log.warning(
                    "ebtables-restore is missing, using "
                    "individual calls for bridge firewall."
                )
            else:
                if self.nftables_enabled:
                    log.info1(
                        "ebtables-restore and ebtables are missing, "
                        "eb direct rules won't be usable."
                    )
                else:
                    log.warning(
                        "ebtables-restore and ebtables are missing, "
                        "disabling bridge firewall."
                    )
                self.ebtables_enabled = False

        if (
            self.ebtables_enabled
            and not self._individual_calls
            and not self.ebtables_backend.restore_noflush_option
        ):
            log.debug1(
                "ebtables-restore is not supporting the --noflush "
                "option, will therefore not be used"
            )

    def _start_load_firewalld_conf(self):
        # load firewalld config
        log.debug1("Loading firewalld config file '%s'", config.FIREWALLD_CONF)
        try:
            self._firewalld_conf.read()
        except Exception as msg:
            log.warning(msg)
            log.warning("Using fallback firewalld configuration settings.")
        else:
            if self._firewalld_conf.get("DefaultZone"):
                self._default_zone = self._firewalld_conf.get("DefaultZone")

            if self._firewalld_conf.get("CleanupOnExit"):
                value = self._firewalld_conf.get("CleanupOnExit")
                if value is not None and value.lower() in ["no", "false"]:
                    self.cleanup_on_exit = False
                log.debug1("CleanupOnExit is set to '%s'", self.cleanup_on_exit)

            if self._firewalld_conf.get("CleanupModulesOnExit"):
                value = self._firewalld_conf.get("CleanupModulesOnExit")
                if value is not None and value.lower() in ["yes", "true"]:
                    self.cleanup_modules_on_exit = True
                log.debug1(
                    "CleanupModulesOnExit is set to '%s'", self.cleanup_modules_on_exit
                )

            if self._firewalld_conf.get("Lockdown"):
                value = self._firewalld_conf.get("Lockdown")
                if value is not None and value.lower() in ["yes", "true"]:
                    log.debug1("Lockdown is enabled")
                    try:
                        self.policies.enable_lockdown()
                    except FirewallError:
                        # already enabled, this is probably reload
                        pass

            if self._firewalld_conf.get("IPv6_rpfilter"):
                value = self._firewalld_conf.get("IPv6_rpfilter")
                if value is not None:
                    if value.lower() in ["no", "false"]:
                        self.ipv6_rpfilter_enabled = False
                    if value.lower() in ["yes", "true"]:
                        self.ipv6_rpfilter_enabled = True
            if self.ipv6_rpfilter_enabled:
                log.debug1("IPv6 rpfilter is enabled")
            else:
                log.debug1("IPV6 rpfilter is disabled")

            if self._firewalld_conf.get("IndividualCalls"):
                value = self._firewalld_conf.get("IndividualCalls")
                if value is not None and value.lower() in ["yes", "true"]:
                    log.debug1("IndividualCalls is enabled")
                    self._individual_calls = True

            if self._firewalld_conf.get("LogDenied"):
                value = self._firewalld_conf.get("LogDenied")
                if value is None or value.lower() == "no":
                    self._log_denied = "off"
                else:
                    self._log_denied = value.lower()
                    log.debug1("LogDenied is set to '%s'", self._log_denied)

            if self._firewalld_conf.get("FirewallBackend"):
                self._firewall_backend = self._firewalld_conf.get("FirewallBackend")
                log.debug1("FirewallBackend is set to '%s'", self._firewall_backend)

            if self._firewalld_conf.get("FlushAllOnReload"):
                value = self._firewalld_conf.get("FlushAllOnReload")
                if value.lower() in ["no", "false"]:
                    self._flush_all_on_reload = False
                else:
                    self._flush_all_on_reload = True
                log.debug1("FlushAllOnReload is set to '%s'", self._flush_all_on_reload)

            if self._firewalld_conf.get("RFC3964_IPv4"):
                value = self._firewalld_conf.get("RFC3964_IPv4")
                if value.lower() in ["no", "false"]:
                    self._rfc3964_ipv4 = False
                else:
                    self._rfc3964_ipv4 = True
                log.debug1("RFC3964_IPv4 is set to '%s'", self._rfc3964_ipv4)

            if self._firewalld_conf.get("NftablesFlowtable"):
                self._nftables_flowtable = self._firewalld_conf.get("NftablesFlowtable")
                log.debug1("NftablesFlowtable is set to '%s'", self._nftables_flowtable)

            if self._firewalld_conf.get("NftablesCounters"):
                value = self._firewalld_conf.get("NftablesCounters")
                if value.lower() in ["no", "false"]:
                    self._nftables_counters = False
                else:
                    self._nftables_counters = True
                log.debug1("NftablesCounters is set to '%s'", self._nftables_counters)

        self.config.set_firewalld_conf(copy.deepcopy(self._firewalld_conf))

    def _start_load_lockdown_whitelist(self):
        # load lockdown whitelist
        log.debug1("Loading lockdown whitelist")
        try:
            self.policies.lockdown_whitelist.read()
        except Exception as msg:
            if self.policies.query_lockdown():
                log.error(
                    "Failed to load lockdown whitelist '%s': %s",
                    self.policies.lockdown_whitelist.filename,
                    msg,
                )
            else:
                log.debug1(
                    "Failed to load lockdown whitelist '%s': %s",
                    self.policies.lockdown_whitelist.filename,
                    msg,
                )

        # copy policies to config interface
        self.config.set_policies(copy.deepcopy(self.policies))

    def _start_load_stock_config(self):
        self._loader_ipsets(config.FIREWALLD_IPSETS)
        self._loader_icmptypes(config.FIREWALLD_ICMPTYPES)
        self._loader_helpers(config.FIREWALLD_HELPERS)
        self._loader_services(config.FIREWALLD_SERVICES)
        self._loader_zones(config.FIREWALLD_ZONES)
        self._loader_policies(config.FIREWALLD_POLICIES)

    def _start_load_user_config(self):
        self._loader_ipsets(config.ETC_FIREWALLD_IPSETS)
        self._loader_icmptypes(config.ETC_FIREWALLD_ICMPTYPES)
        self._loader_helpers(config.ETC_FIREWALLD_HELPERS)
        self._loader_services(config.ETC_FIREWALLD_SERVICES)
        self._loader_zones(config.ETC_FIREWALLD_ZONES)
        self._loader_policies(config.ETC_FIREWALLD_POLICIES)

    def _start_copy_config_to_runtime(self):
        for _ipset in self.config.get_ipsets():
            self.ipset.add_ipset(copy.deepcopy(self.config.get_ipset(_ipset)))
        for icmptype in self.config.get_icmptypes():
            self.icmptype.add_icmptype(
                copy.deepcopy(self.config.get_icmptype(icmptype))
            )
        for helper in self.config.get_helpers():
            self.helper.add_helper(copy.deepcopy(self.config.get_helper(helper)))
        for service in self.config.get_services():
            self.service.add_service(copy.deepcopy(self.config.get_service(service)))
        for policy in self.config.get_policy_objects():
            self.policy.add_policy(copy.deepcopy(self.config.get_policy_object(policy)))

        self.direct.set_permanent_config(copy.deepcopy(self.config.get_direct()))

        # copy combined permanent zones to runtime
        # zones with a '/' in the name will be combined into one runtime zone
        combined_zones = {}
        for zone in self.config.get_zones():
            z_obj = self.config.get_zone(zone)
            if "/" not in z_obj.name:
                self.zone.add_zone(copy.deepcopy(self.config.get_zone(zone)))
                continue

            combined_name = os.path.basename(z_obj.path)
            if combined_name not in combined_zones:
                combined_zone = Zone()
                combined_zone.name = combined_name
                combined_zone.check_name(combined_zone.name)
                combined_zone.path = z_obj.path
                combined_zone.default = False
                combined_zone.forward = False  # see note in zone_reader()

                combined_zones[combined_name] = combined_zone

            log.debug1(
                "Combining zone '%s' using '%s%s%s'",
                combined_name,
                z_obj.path,
                os.sep,
                z_obj.filename,
            )
            combined_zones[combined_name].combine(z_obj)

        for zone in combined_zones:
            self.zone.add_zone(combined_zones[zone])

    def _start_load_direct_rules(self):
        # load direct rules
        obj = Direct(config.FIREWALLD_DIRECT)
        if os.path.exists(config.FIREWALLD_DIRECT):
            log.debug1("Loading direct rules file '%s'" % config.FIREWALLD_DIRECT)
            try:
                obj.read()
            except Exception as msg:
                log.error(
                    "Failed to load direct rules file '%s': %s",
                    config.FIREWALLD_DIRECT,
                    msg,
                )
        self.config.set_direct(obj)

    def _start_apply_objects(self, reload=False, complete_reload=False):
        transaction = FirewallTransaction(self)

        if not reload:
            self.flush(use_transaction=transaction)

        # If modules need to be unloaded in complete reload or if there are
        # ipsets to get applied, limit the transaction to flush.
        #
        # Future optimization for the ipset case in reload: The transaction
        # only needs to be split here if there are conflicting ipset types in
        # exsting ipsets and the configuration in firewalld.
        if (reload and complete_reload) or (
            self.ipset.backends() and self.ipset.has_ipsets()
        ):
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
        if (self.ipset.backends()) and self.ipset.has_ipsets():
            log.debug1("Applying ipsets")
            self.ipset.apply_ipsets()

        log.debug1("Applying default rule set")
        self.apply_default_rules(use_transaction=transaction)

        log.debug1("Applying default zone")
        self.zone.apply_zone_settings(self._default_zone, transaction)
        self.zone._interface(True, self._default_zone, "+", transaction)

        log.debug1("Applying used zones")
        self.zone.apply_zones(use_transaction=transaction)

        log.debug1("Applying used policies")
        self.policy.apply_policies(use_transaction=transaction)

        transaction.execute(True)
        transaction.clear()

    def _start_apply_direct_rules(self):
        transaction = FirewallTransaction(self)

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

        transaction.execute(True)
        transaction.clear()

    def _start_check(self):
        # check minimum required zones
        for z in ["block", "drop", "trusted"]:
            if z not in self.zone.get_zones():
                raise FirewallError(
                    errors.INVALID_ZONE, "Zone '{}' is not available.".format(z)
                )

        # check if default_zone is a valid zone
        if self._default_zone not in self.zone.get_zones():
            if "public" in self.zone.get_zones():
                zone = "public"
            elif "external" in self.zone.get_zones():
                zone = "external"
            else:
                zone = "block"  # block is a base zone, therefore it has to exist

            log.error(
                "Default zone '%s' is not valid. Using '%s'.", self._default_zone, zone
            )
            self._default_zone = zone
        else:
            log.debug1("Using default zone '%s'", self._default_zone)

        if not self._offline:
            self.full_check_config()
            self._start_check_tables()

            # check our desired backend is actually available
            if self._firewall_backend == "iptables":
                backend_to_check = "ip4tables"  # ip6tables is always optional
            else:
                backend_to_check = self._firewall_backend
            if not self.is_backend_enabled(backend_to_check):
                raise FirewallError(
                    errors.UNKNOWN_ERROR,
                    "Firewall backend '{}' is not available.".format(
                        self._firewall_backend
                    ),
                )

    def _start(self, reload=False, complete_reload=False):
        self._start_load_firewalld_conf()
        self._start_load_lockdown_whitelist()

        self._select_firewall_backend(self._firewall_backend)

        if not self._offline:
            self._start_probe_backends()

        self._start_load_stock_config()
        self._start_load_user_config()
        self._start_load_direct_rules()
        self._start_copy_config_to_runtime()

        self._start_check()

        if self._offline:
            return

        if log.getDebugLogLevel() > 0:
            # get time before flushing and applying
            tm1 = time.time()

        self._start_apply_objects(reload=reload, complete_reload=complete_reload)
        self._start_apply_direct_rules()

        if log.getDebugLogLevel() > 1:
            # get time after flushing and applying
            tm2 = time.time()
            log.debug2("Flushing and applying took %f seconds" % (tm2 - tm1))

    def _start_failsafe(self, reload=False, complete_reload=False):
        """
        This is basically _start() with at least the following differences:
            - built-in defaults for firewalld.conf
            - no lockdown list
            - no user config (/etc/firewalld)
            - no direct rules
        """
        self.cleanup()
        self._firewalld_conf.set_defaults()
        self.config.set_firewalld_conf(copy.deepcopy(self._firewalld_conf))

        self._select_firewall_backend(self._firewall_backend)

        if not self._offline:
            self._start_probe_backends()

        self._start_load_stock_config()
        self._start_copy_config_to_runtime()
        self._start_check()

        if self._offline:
            return

        self._start_apply_objects(reload=reload, complete_reload=complete_reload)

    def start(self):
        try:
            self._start()
        except Exception as original_ex:
            log.error(
                "Failed to load user configuration. Falling back to "
                "full stock configuration."
            )
            try:
                self._start_failsafe()
                self._state = "FAILED"
                self.set_policy("ACCEPT")
            except Exception as new_ex:
                log.error(original_ex)
                log.exception()
                log.error(new_ex)
                log.error(
                    "Failed to load full stock configuration. This likely "
                    "indicates a system level issue, e.g. the firewall "
                    "backend (nftables, iptables) is broken. "
                    "All hope is lost. Exiting."
                )
                try:
                    self.flush()
                except Exception:
                    pass
                sys.exit(errors.UNKNOWN_ERROR)
            # propagate the original exception that caused us to enter failed
            # state.
            raise original_ex
        else:
            self._state = "RUNNING"
            self.set_policy("ACCEPT")

    def _loader_config_file_generator(self, path):
        if not os.path.isdir(path):
            return

        for filename in sorted(os.listdir(path)):
            if not filename.endswith(".xml"):
                continue
            yield filename

    def _loader_services(self, path):
        for filename in self._loader_config_file_generator(path):
            log.debug1("Loading service file '%s%s%s'", path, os.sep, filename)

            obj = service_reader(filename, path)
            if obj.name in self.config.get_services():
                orig_obj = self.config.get_service(obj.name)
                log.debug1(
                    "Overrides '%s%s%s'", orig_obj.path, os.sep, orig_obj.filename
                )
            elif obj.path.startswith(config.ETC_FIREWALLD):
                obj.default = True

            self.config.add_service(obj)

    def _loader_ipsets(self, path):
        for filename in self._loader_config_file_generator(path):
            log.debug1("Loading ipset file '%s%s%s'", path, os.sep, filename)

            obj = ipset_reader(filename, path)
            if obj.name in self.config.get_ipsets():
                orig_obj = self.config.get_ipset(obj.name)
                log.debug1(
                    "Overrides '%s%s%s'", orig_obj.path, os.sep, orig_obj.filename
                )
            elif obj.path.startswith(config.ETC_FIREWALLD):
                obj.default = True

            self.config.add_ipset(obj)

    def _loader_helpers(self, path):
        for filename in self._loader_config_file_generator(path):
            log.debug1("Loading helper file '%s%s%s'", path, os.sep, filename)

            obj = helper_reader(filename, path)
            if obj.name in self.config.get_helpers():
                orig_obj = self.config.get_helper(obj.name)
                log.debug1(
                    "Overrides '%s%s%s'", orig_obj.path, os.sep, orig_obj.filename
                )
            elif obj.path.startswith(config.ETC_FIREWALLD):
                obj.default = True

            self.config.add_helper(obj)

    def _loader_policies(self, path):
        for filename in self._loader_config_file_generator(path):
            log.debug1("Loading policy file '%s%s%s'", path, os.sep, filename)

            obj = policy_reader(filename, path)
            if obj.name in self.config.get_policy_objects():
                orig_obj = self.config.get_policy_object(obj.name)
                log.debug1(
                    "Overrides '%s%s%s'", orig_obj.path, os.sep, orig_obj.filename
                )
            elif obj.path.startswith(config.ETC_FIREWALLD):
                obj.default = True

            self.config.add_policy_object(obj)

    def _loader_icmptypes(self, path):
        for filename in self._loader_config_file_generator(path):
            log.debug1("Loading icmptype file '%s%s%s'", path, os.sep, filename)

            obj = icmptype_reader(filename, path)
            if obj.name in self.config.get_icmptypes():
                orig_obj = self.config.get_icmptype(obj.name)
                log.debug1(
                    "Overrides '%s%s%s'", orig_obj.path, os.sep, orig_obj.filename
                )
            elif obj.path.startswith(config.ETC_FIREWALLD):
                obj.default = True

            self.config.add_icmptype(obj)

    def _loader_zones(self, path, combine=False):
        if not os.path.isdir(path):
            return

        for filename in sorted(os.listdir(path)):
            if not filename.endswith(".xml"):
                if path.startswith(config.ETC_FIREWALLD) and os.path.isdir(
                    "%s/%s" % (path, filename)
                ):
                    # Combined zones are added to permanent config
                    # individually. They're coalesced into one object when
                    # added to the runtime
                    self._loader_zones("%s/%s" % (path, filename), combine=True)
                continue

            name = "%s/%s" % (path, filename)
            log.debug1("Loading zone file '%s'", name)

            obj = zone_reader(filename, path, no_check_name=combine)
            if combine:
                # Change name for permanent configuration
                obj.name = "%s/%s" % (
                    os.path.basename(path),
                    os.path.basename(filename)[0:-4],
                )
                obj.check_name(obj.name)

            if obj.name in self.config.get_zones():
                orig_obj = self.config.get_zone(obj.name)
                log.debug1(
                    "Overrides '%s%s%s'", orig_obj.path, os.sep, orig_obj.filename
                )
            elif obj.path.startswith(config.ETC_FIREWALLD):
                obj.default = True

            self.config.add_zone(obj)

    def cleanup(self):
        self.icmptype.cleanup()
        self.service.cleanup()
        self.zone.cleanup()
        self.ipset.cleanup()
        self.helper.cleanup()
        self.config.cleanup()
        self.direct.cleanup()
        self.policies.cleanup()
        self.policy.cleanup()
        self._firewalld_conf.cleanup()
        self.__init_vars()

    def stop(self):
        if not self._offline:
            if self.cleanup_on_exit:
                self.flush()
                self.ipset.flush()
                self.set_policy("ACCEPT")

            if self.cleanup_modules_on_exit:
                log.debug1("Unloading firewall kernel modules")
                self.modules_backend.unload_firewall_modules()

        self.cleanup()

    # handle modules

    def handle_modules(self, _modules, enable):
        num_failed = 0
        error_msgs = ""
        for i, module in enumerate(_modules):
            if enable:
                (status, msg) = self.modules_backend.load_module(module)
            else:
                if self._module_refcount[module] > 1:
                    status = 0  # module referenced more then one, do not unload
                else:
                    (status, msg) = self.modules_backend.unload_module(module)
            if status != 0:
                num_failed += 1
                error_msgs += msg
                continue

            if enable:
                self._module_refcount.setdefault(module, 0)
                self._module_refcount[module] += 1
            else:
                if module in self._module_refcount:
                    self._module_refcount[module] -= 1
                    if self._module_refcount[module] == 0:
                        del self._module_refcount[module]
        return (num_failed, error_msgs)

    def _select_firewall_backend(self, backend):
        if backend != "nftables":
            self.nftables_enabled = False
        # even if using nftables, the other backends are enabled for use with
        # the direct interface. nftables is used for the firewalld primitives.

    def get_backend_by_name(self, name):
        for backend in self.all_backends():
            if backend.name == name:
                return backend
        raise FirewallError(errors.UNKNOWN_ERROR, "'%s' backend does not exist" % name)

    def get_backend_by_ipv(self, ipv):
        if self.nftables_enabled:
            return self.nftables_backend
        if ipv == "ipv4" and self.ip4tables_enabled:
            return self.ip4tables_backend
        elif ipv == "ipv6" and self.ip6tables_enabled:
            return self.ip6tables_backend
        elif ipv == "eb" and self.ebtables_enabled:
            return self.ebtables_backend
        raise FirewallError(
            errors.INVALID_IPV, "'%s' is not a valid backend or is unavailable" % ipv
        )

    def get_direct_backend_by_ipv(self, ipv):
        if ipv == "ipv4" and self.ip4tables_enabled:
            return self.ip4tables_backend
        elif ipv == "ipv6" and self.ip6tables_enabled:
            return self.ip6tables_backend
        elif ipv == "eb" and self.ebtables_enabled:
            return self.ebtables_backend
        raise FirewallError(
            errors.INVALID_IPV, "'%s' is not a valid backend or is unavailable" % ipv
        )

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

        if self.is_ipv_enabled("ipv6"):
            ipv6_backend = self.get_backend_by_ipv("ipv6")
            if "raw" in ipv6_backend.get_available_tables():
                if self.ipv6_rpfilter_enabled:
                    rules = ipv6_backend.build_rpfilter_rules(self._log_denied)
                    transaction.add_rules(ipv6_backend, rules)

        if self.is_ipv_enabled("ipv6") and self._rfc3964_ipv4:
            rules = ipv6_backend.build_rfc3964_ipv4_rules()
            transaction.add_rules(ipv6_backend, rules)

        if use_transaction is None:
            transaction.execute(True)

    def may_skip_flush_direct_backends(self):
        if self.nftables_enabled and not self.direct.has_runtime_configuration():
            return True

        return False

    def flush_direct_backends(self, use_transaction=None):
        if use_transaction is None:
            transaction = FirewallTransaction(self)
        else:
            transaction = use_transaction

        for backend in self.all_backends():
            if backend in self.enabled_backends():
                continue
            rules = backend.build_flush_rules()
            transaction.add_rules(backend, rules)

        if use_transaction is None:
            transaction.execute(True)

    def flush(self, use_transaction=None):
        if use_transaction is None:
            transaction = FirewallTransaction(self)
        else:
            transaction = use_transaction

        log.debug1("Flushing rule set")

        if not self.may_skip_flush_direct_backends():
            self.flush_direct_backends(use_transaction=transaction)

        for backend in self.enabled_backends():
            rules = backend.build_flush_rules()
            transaction.add_rules(backend, rules)

        if use_transaction is None:
            transaction.execute(True)

    def _set_policy_build_rules(self, backend, policy, policy_details=None):
        assert policy in ("ACCEPT", "DROP", "PANIC")
        if policy_details is None:
            dp = "ACCEPT" if policy == "ACCEPT" else "DROP"
            policy_details = {
                "INPUT": dp,
                "OUTPUT": dp,
                "FORWARD": dp,
            }
        return backend.build_set_policy_rules(policy, policy_details)

    def set_policy(self, policy, policy_details=None, use_transaction=None):
        if use_transaction is None:
            transaction = FirewallTransaction(self)
        else:
            transaction = use_transaction

        log.debug1(
            "Setting policy to '%s'%s",
            policy,
            f" (ReloadPolicy={firewalld_conf._unparse_reload_policy(policy_details)})"
            if policy == "DROP"
            else "",
        )

        for backend in self.enabled_backends():
            rules = self._set_policy_build_rules(backend, policy, policy_details)
            transaction.add_rules(backend, rules)

        if use_transaction is None:
            transaction.execute(True)

    # rule function used in handle_ functions

    def rule(self, backend_name, rule):
        if not rule:
            return ""

        backend = self.get_backend_by_name(backend_name)
        if not backend:
            raise FirewallError(
                errors.INVALID_IPV, "'%s' is not a valid backend" % backend_name
            )

        if not self.is_backend_enabled(backend_name):
            return ""

        return backend.set_rule(rule, self._log_denied)

    def rules(self, backend_name, rules):
        _rules = list(filter(None, rules))

        backend = self.get_backend_by_name(backend_name)
        if not backend:
            raise FirewallError(
                errors.INVALID_IPV, "'%s' is not a valid backend" % backend_name
            )

        if not self.is_backend_enabled(backend_name):
            return

        if (
            self._individual_calls
            or not backend.restore_command_exists
            or (
                backend_name == "ebtables"
                and not self.ebtables_backend.restore_noflush_option
            )
        ):
            for i, rule in enumerate(_rules):
                try:
                    backend.set_rule(rule, self._log_denied)
                except Exception as msg:
                    log.debug1(traceback.format_exc())
                    log.error(msg)
                    for rrule in reversed(_rules[:i]):
                        try:
                            backend.set_rule(
                                backend.reverse_rule(rrule), self._log_denied
                            )
                        except Exception:
                            # ignore errors here
                            pass
                    raise msg
        else:
            backend.set_rules(_rules, self._log_denied)

    # check functions

    def check_panic(self):
        if self._panic:
            raise FirewallError(errors.PANIC_MODE)

    def check_policy(self, policy):
        _policy = policy
        if _policy not in self.policy.get_policies():
            raise FirewallError(errors.INVALID_POLICY, _policy)
        return _policy

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
        if protocol not in ["tcp", "udp", "sctp", "dccp"]:
            raise FirewallError(
                errors.INVALID_PROTOCOL,
                "'%s' not in {'tcp'|'udp'|'sctp'|'dccp'}" % protocol,
            )

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
            raise FirewallError(errors.INVALID_IPV, "'%s' not in {'ipv4'|'ipv6'}")

    def check_icmptype(self, icmp):
        self.icmptype.check_icmptype(icmp)

    def check_timeout(self, timeout):
        if not isinstance(timeout, int):
            raise TypeError("%s is %s, expected int" % (timeout, type(timeout)))
        if int(timeout) < 0:
            raise FirewallError(
                errors.INVALID_VALUE, "timeout '%d' is not positive number" % timeout
            )

    # RELOAD

    def reload(self, stop=False):
        # we're about to load the on-disk config, so verify it's sane.
        check_on_disk_config(self)

        _panic = self._panic
        _omit_native_ipset = self.ipset.omit_native_ipset()

        # must stash this. The value may change after _start()
        old_firewall_backend = self._firewall_backend
        flush_all = self._flush_all_on_reload

        if not flush_all:
            # save zone interfaces
            _zone_interfaces = {}
            for zone in self.zone.get_zones():
                _zone_interfaces[zone] = self.zone.get_zone(zone).interfaces
            # save direct config
            _direct_config = self.direct.get_runtime_config()
            _old_dz = self.get_default_zone()

        _ipset_objs = []
        for _name in self.ipset.get_ipsets():
            _ipset_objs.append(self.ipset.get_ipset(_name))

        if not _panic:
            reload_policy = firewalld_conf._parse_reload_policy(
                self._firewalld_conf.get("ReloadPolicy")
            )
            self.set_policy("DROP", policy_details=reload_policy)

        self.flush()
        self.cleanup()

        start_exception = None
        try:
            self._start(reload=True, complete_reload=stop)
        except Exception as e:
            # save the exception for later, but continue restoring interfaces,
            # etc. We'll re-raise it at the end.
            start_exception = e

        # destroy ipsets no longer in the permanent configuration
        if flush_all:
            for obj in _ipset_objs:
                if not self.ipset.query_ipset(obj.name):
                    # nftables sets are part of the normal firewall ruleset and
                    # thus do not need flushed here.
                    if self.ipset_enabled and not _omit_native_ipset:
                        self.ipset_backend.set_destroy(obj.name)

        if not flush_all:
            # handle interfaces in the default zone and move them to the new
            # default zone if it changed
            _new_dz = self.get_default_zone()
            if _new_dz != _old_dz:
                # if_new_dz has been introduced with the reload, we need to add it
                # https://github.com/firewalld/firewalld/issues/53
                if _new_dz not in _zone_interfaces:
                    _zone_interfaces[_new_dz] = {}
                # default zone changed. Move interfaces from old default zone to
                # the new one.
                for iface in _zone_interfaces[_old_dz]:
                    if iface in self._default_zone_interfaces:
                        # move only those that were added to default zone
                        # (not those that were added to specific zone same as
                        # default)
                        _zone_interfaces[_new_dz][iface] = _zone_interfaces[_old_dz][
                            iface
                        ]
                        del _zone_interfaces[_old_dz][iface]

            # add interfaces to zones again
            for zone in self.zone.get_zones():
                if zone in _zone_interfaces:
                    for interface_id in _zone_interfaces[zone]:
                        self.zone.change_zone_of_interface(zone, interface_id)

                    del _zone_interfaces[zone]
                else:
                    log.info1("New zone '%s'.", zone)
            if len(_zone_interfaces) > 0:
                for zone in list(_zone_interfaces.keys()):
                    log.info1("Lost zone '%s', zone interfaces dropped.", zone)
                    del _zone_interfaces[zone]
            del _zone_interfaces

            # restore runtime-only ipsets
            for obj in _ipset_objs:
                if self.ipset.query_ipset(obj.name):
                    for entry in obj.entries:
                        try:
                            self.ipset.add_entry(obj.name, entry)
                        except FirewallError as msg:
                            if msg.code != errors.ALREADY_ENABLED:
                                raise msg
                else:
                    self.ipset.add_ipset(obj)
                    self.ipset.apply_ipset(obj.name)

            # restore direct config
            self.direct.set_config(_direct_config)

        # Restore permanent interfaces from NetworkManager
        nm_bus_name = nm_get_bus_name()
        if nm_bus_name:
            for zone in self.zone.get_zones() + [""]:
                for interface in nm_get_interfaces_in_zone(zone):
                    self.zone.change_zone_of_interface(
                        zone, interface, sender=nm_bus_name
                    )

        self._panic = _panic
        if not self._panic:
            self.set_policy("ACCEPT")

        # If the FirewallBackend changed, then we must also cleanup the policy
        # for the old backend that was set to DROP above.
        if not self._panic and old_firewall_backend != self._firewall_backend:
            if old_firewall_backend == "nftables":
                for rule in self._set_policy_build_rules(
                    self.nftables_backend, "ACCEPT"
                ):
                    self.nftables_backend.set_rule(rule, self._log_denied)
            else:
                for rule in self._set_policy_build_rules(
                    self.ip4tables_backend, "ACCEPT"
                ):
                    self.ip4tables_backend.set_rule(rule, self._log_denied)
                if self.ip6tables_enabled:
                    for rule in self._set_policy_build_rules(
                        self.ip6tables_backend, "ACCEPT"
                    ):
                        self.ip6tables_backend.set_rule(rule, self._log_denied)

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
            raise FirewallError(errors.ALREADY_ENABLED, "panic mode already enabled")

        try:
            self.set_policy("PANIC")
        except Exception as msg:
            raise FirewallError(errors.COMMAND_FAILED, msg)
        self._panic = True

    def disable_panic_mode(self):
        if not self._panic:
            raise FirewallError(errors.NOT_ENABLED, "panic mode is not enabled")

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
            raise FirewallError(
                errors.INVALID_VALUE,
                "'%s', choose from '%s'"
                % (value, "','".join(config.LOG_DENIED_VALUES)),
            )

        if value != self.get_log_denied():
            self._log_denied = value
            self._firewalld_conf.set("LogDenied", value)
            self._firewalld_conf.write()
        else:
            raise FirewallError(errors.ALREADY_SET, value)

    # DEFAULT ZONE

    def get_default_zone(self):
        return self._default_zone

    def set_default_zone(self, zone):
        _zone = self.check_zone(zone)
        if _zone == self._default_zone:
            raise FirewallError(errors.ZONE_ALREADY_SET, _zone)

        self._firewalld_conf.set("DefaultZone", _zone)
        self._firewalld_conf.write()

    def combine_runtime_with_permanent_settings(self, permanent, runtime):
        combined = permanent.copy()

        for key, value in runtime.items():
            # omit empty entries
            if value or isinstance(value, bool) or isinstance(value, int):
                combined[key] = value
            # make sure to remove values that were in permanent, but no
            # longer in runtime.
            elif key in combined:
                del combined[key]

        return combined

    def get_added_and_removed_settings(self, old_settings, new_settings):
        # normalize rich rules, zones and policies use a different key
        for rich_key in ["rich_rules", "rules_str"]:
            if rich_key in new_settings:
                new_settings[rich_key] = [
                    str(Rich_Rule(rule_str=rule_str))
                    for rule_str in new_settings[rich_key]
                ]

        add_settings = {}
        remove_settings = {}
        for key in set(old_settings.keys()) | set(new_settings.keys()):
            if key in new_settings:
                if isinstance(new_settings[key], list):
                    old = set(old_settings[key] if key in old_settings else [])
                    add_settings[key] = list(set(new_settings[key]) - old)
                    remove_settings[key] = list((old ^ set(new_settings[key])) & old)
                # check for bool or int because dbus.Boolean is a subclass of
                # int (because bool can't be subclassed).
                elif isinstance(new_settings[key], bool) or isinstance(
                    new_settings[key], int
                ):
                    if not old_settings[key] and new_settings[key]:
                        add_settings[key] = True
                    elif old_settings[key] and not new_settings[key]:
                        remove_settings[key] = False
                else:
                    raise FirewallError(
                        errors.INVALID_SETTING,
                        "Unhandled setting type {} key {}".format(
                            type(new_settings[key]), key
                        ),
                    )

        return (add_settings, remove_settings)
