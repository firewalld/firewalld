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

__all__ = [ "Firewall_test" ]

import os.path, sys
import copy
from firewall import config
from firewall import functions
from firewall.core.fw_icmptype import FirewallIcmpType
from firewall.core.fw_service import FirewallService
from firewall.core.fw_zone import FirewallZoneIPTables
from firewall.core.fw_direct import FirewallDirectIPTables
from firewall.core.fw_config import FirewallConfig
from firewall.core.fw_policies import FirewallPolicies
from firewall.core.fw_ipset import FirewallIPSet
from firewall.core.fw_helper import FirewallHelper
from firewall.core.logger import log
from firewall.core.io.firewalld_conf import firewalld_conf
from firewall.core.io.direct import Direct
from firewall.core.io.service import service_reader
from firewall.core.io.icmptype import icmptype_reader
from firewall.core.io.zone import zone_reader, Zone
from firewall.core.io.ipset import ipset_reader
from firewall.core.ipset import IPSET_TYPES
from firewall.core.io.helper import helper_reader
from firewall import errors
from firewall.errors import FirewallError

############################################################################
#
# class Firewall
#
############################################################################

class Firewall_test(object):
    def __init__(self):
        self._firewalld_conf = firewalld_conf(config.FIREWALLD_CONF)

        self.ip4tables_enabled = False
        self.ip6tables_enabled = False
        self.ebtables_enabled = False
        self.ipset_enabled = False
        self.ipset_supported_types = IPSET_TYPES

        self.available_tables = { }
        self.available_tables["ipv4"] = [ ]
        self.available_tables["ipv6"] = [ ]
        self.available_tables["eb"] = [ ]

        self.icmptype = FirewallIcmpType(self)
        self.service = FirewallService(self)
        self.zone = FirewallZoneIPTables(self)
        self.direct = FirewallDirectIPTables(self)
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

    def individual_calls(self):
        return self._individual_calls

    def _start(self, reload=False, complete_reload=False):
        # initialize firewall
        default_zone = config.FALLBACK_ZONE

        # load firewalld config
        log.debug1("Loading firewalld config file '%s'", config.FIREWALLD_CONF)
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

        self.config.set_firewalld_conf(copy.deepcopy(self._firewalld_conf))

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
        self.config.set_direct(copy.deepcopy(obj))

        self._default_zone = self.check_zone(default_zone)

        self._state = "RUNNING"

    def start(self):
        self._start()

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
                    self.ipset.add_ipset(obj)
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

    def get_available_tables(self, ipv):
        if ipv in [ "ipv4", "ipv6", "eb" ]:
            return self.available_tables[ipv]
        return [ ]

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
        self.cleanup()

    # check functions

    def check_panic(self):
        return

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
            raise FirewallError(errors.INVALID_PORT, port)

    def check_tcpudp(self, protocol):
        if not protocol:
            raise FirewallError(errors.MISSING_PROTOCOL)
        if not protocol in [ "tcp", "udp", "sctp", "dccp" ]:
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

    # RELOAD

    def reload(self, stop=False):
        return

    # STATE

    def get_state(self):
        return self._state

    # PANIC MODE

    def enable_panic_mode(self):
        return

    def disable_panic_mode(self):
        return

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

            # now reload the firewall
            self.reload()
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

            # now reload the firewall
            self.reload()
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
        else:
            raise FirewallError(errors.ZONE_ALREADY_SET, _zone)

    # lockdown

    def enable_lockdown(self):
        self._firewalld_conf.set("Lockdown", "yes")
        self._firewalld_conf.write()
        
    def disable_lockdown(self):
        self._firewalld_conf.set("Lockdown", "no")
        self._firewalld_conf.write()
