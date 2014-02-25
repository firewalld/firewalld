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

class Firewall_test:
    def __init__(self):
        self._firewalld_conf = firewalld_conf(FIREWALLD_CONF)

        self.ip4tables_enabled = False
        self.ip6tables_enabled = False
        self.ebtables_enabled = False

        self.icmptype = FirewallIcmpType(self)
        self.service = FirewallService(self)
        self.zone = FirewallZone(self)
        self.direct = FirewallDirect(self)
        self.config = FirewallConfig(self)
        self.policies = FirewallPolicies()

        self.__init_vars()

    def __repr__(self):
        return '%s(%r, %r, %r, %r, %r, %r, %r, %r, %r, %r, %r)' % \
            (self.__class__, self.ip4tables_enabled, self.ip6tables_enabled,
             self.ebtables_enabled, self._state, self._panic,
             self._default_zone, self._module_refcount, self._marks,
             self._min_mark, self.cleanup_on_exit, self.ipv6_rpfilter_enabled)

    def __init_vars(self):
        self._state = "INIT"
        self._panic = False
        self._default_zone = ""
        self._module_refcount = { }
        self._marks = [ ]
        self._min_mark = FALLBACK_MINIMAL_MARK # will be overloaded by firewalld.conf
        self.cleanup_on_exit = True
        self.ipv6_rpfilter_enabled = True

    def start(self):
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

            if self._firewalld_conf.get("IPv6_rpfilter"):
                value = self._firewalld_conf.get("IPv6_rpfilter")
                if value != None:
                    if value.lower() in [ "no", "false" ]:
                        self.ipv6_rpfilter_enabled = False
                    if value.lower() in [ "yes", "true" ]:
                        self.ipv6_rpfilter_enabled = True
            if self.ipv6_rpfilter_enabled:
                log.debug1("IPv6 rpfilter is enabled")
            else:
                log.debug1("IPV6 rpfilter is disabled")

        self.config.set_firewalld_conf(copy.deepcopy(self._firewalld_conf))

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
        obj = Direct(FIREWALLD_DIRECT)
        if os.path.exists(FIREWALLD_DIRECT):
            log.debug1("Loading direct rules file '%s'" % FIREWALLD_DIRECT)
            try:
                obj.read()
            except Exception as msg:
                log.debug1("Failed to load direct rules file '%s': %s",
                           FIREWALLD_DIRECT, msg)
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

        self._state = "RUNNING"

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
                    self.config.add_zone(config_obj)
                    if combine:
                        log.debug1("  Combining %s '%s' ('%s/%s')",
                                   reader_type, combined_zone.name,
                                   path, filename)
                        combined_zone.combine(obj)
                    else:
                        self.zone.add_zone(obj)
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
        self.icmptype.cleanup()
        self.service.cleanup()
        self.zone.cleanup()
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
        else:
            raise FirewallError(ZONE_ALREADY_SET, _zone)

    # lockdown

    def enable_lockdown(self):
        self._firewalld_conf.set("Lockdown", "yes")
        self._firewalld_conf.write()
        
    def disable_lockdown(self):
        self._firewalld_conf.set("Lockdown", "no")
        self._firewalld_conf.write()
