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

# force use of pygobject3 in python-slip
from gi.repository import GObject
import sys
sys.modules['gobject'] = GObject

import dbus
import dbus.service
import slip.dbus
import slip.dbus.service

from firewall.config import *
from firewall.config.dbus import *
from firewall.core.watcher import Watcher
from firewall.core.logger import log
from firewall.server.decorators import *
from firewall.server.config_icmptype import FirewallDConfigIcmpType
from firewall.server.config_service import FirewallDConfigService
from firewall.server.config_zone import FirewallDConfigZone
from firewall.core.io.zone import Zone
from firewall.core.io.service import Service
from firewall.core.io.icmptype import IcmpType
from firewall.core.io.lockdown_whitelist import LockdownWhitelist
from firewall.core.io.direct import Direct
from firewall.dbus_utils import dbus_to_python, \
    command_of_sender, context_of_sender, uid_of_sender, user_of_uid
from firewall.errors import *

############################################################################
#
# class FirewallDConfig
#
############################################################################

class FirewallDConfig(slip.dbus.service.Object):
    """FirewallD main class"""

    persistent = True
    """ Make FirewallD persistent. """
    default_polkit_auth_required = PK_ACTION_CONFIG
    """ Use PK_ACTION_INFO as a default """

    @handle_exceptions
    def __init__(self, config, *args, **kwargs):
        super(FirewallDConfig, self).__init__(*args, **kwargs)
        self.config = config
        self.path = args[0]
        self._init_vars()
        self.watcher = Watcher(self.watch_updater, 5)
        self.watcher.add_watch_dir(FIREWALLD_ICMPTYPES)
        self.watcher.add_watch_dir(ETC_FIREWALLD_ICMPTYPES)
        self.watcher.add_watch_dir(FIREWALLD_SERVICES)
        self.watcher.add_watch_dir(ETC_FIREWALLD_SERVICES)
        self.watcher.add_watch_dir(FIREWALLD_ZONES)
        self.watcher.add_watch_dir(ETC_FIREWALLD_ZONES)
        self.watcher.add_watch_file(LOCKDOWN_WHITELIST)
        self.watcher.add_watch_file(FIREWALLD_DIRECT)

    @handle_exceptions
    def _init_vars(self):
        self.icmptypes = [ ]
        self.icmptype_idx = 0
        self.services = [ ]
        self.service_idx = 0
        self.zones = [ ]
        self.zone_idx = 0

        for icmptype in self.config.get_icmptypes():
            self._addIcmpType(self.config.get_icmptype(icmptype))
        for service in self.config.get_services():
            self._addService(self.config.get_service(service))
        for zone in self.config.get_zones():
            self._addZone(self.config.get_zone(zone))

    @handle_exceptions
    def __del__(self):
        pass

    @handle_exceptions
    def reload(self):
        while len(self.icmptypes) > 0:
            x = self.icmptypes.pop()
            x.unregister()
            del x
        while len(self.services) > 0:
            x = self.services.pop()
            x.unregister()
            del x
        while len(self.zones) > 0:
            x = self.zones.pop()
            x.unregister()
            del x
        self._init_vars()

    @handle_exceptions
    def watch_updater(self, name):
        if not name.endswith(".xml"):
            raise FirewallError(INVALID_FILENAME, name)

        if name.startswith(FIREWALLD_ICMPTYPES) or \
                name.startswith(ETC_FIREWALLD_ICMPTYPES):
            (what, obj) = self.config.update_icmptype_from_path(name)
            if what == "new":
                self._addIcmpType(obj)
            elif what == "remove":
                self.removeIcmpType(obj)
            elif what == "update":
                self._updateIcmpType(obj)

        elif name.startswith(FIREWALLD_SERVICES) or \
                name.startswith(ETC_FIREWALLD_SERVICES):
            (what, obj) = self.config.update_service_from_path(name)
            if what == "new":
                self._addService(obj)
            elif what == "remove":
                self.removeService(obj)
            elif what == "update":
                self._updateService(obj)

        elif name.startswith(FIREWALLD_ZONES) or \
                name.startswith(ETC_FIREWALLD_ZONES):
            (what, obj) = self.config.update_zone_from_path(name)
            if what == "new":
                self._addZone(obj)
            elif what == "remove":
                self.removeZone(obj)
            elif what == "update":
                self._updateZone(obj)

        elif name == LOCKDOWN_WHITELIST:
            self.config.update_lockdown_whitelist()
            self.LockdownWhitelistUpdated()

        elif name == FIREWALLD_DIRECT:
            self.config.update_direct()
            self.Updated()


    @handle_exceptions
    def _addIcmpType(self, obj):
        # TODO: check for idx overflow
        config_icmptype = FirewallDConfigIcmpType(self, \
            self.config, obj, self.icmptype_idx, self.path,
            "%s/%d" % (DBUS_PATH_CONFIG_ICMPTYPE, self.icmptype_idx))
        self.icmptypes.append(config_icmptype)
        self.icmptype_idx += 1
        self.IcmpTypeAdded(obj.name)
        return config_icmptype

    @handle_exceptions
    def _updateIcmpType(self, obj):
        for icmptype in self.icmptypes:
            if icmptype.obj.name == obj.name and \
                    icmptype.obj.path == obj.path and \
                    icmptype.obj.filename == obj.filename:
                icmptype.obj = obj
                icmptype.Updated(obj.name)

    @handle_exceptions
    def removeIcmpType(self, obj):
        index = 7 # see IMPORT_EXPORT_STRUCTURE in class Zone(IO_Object)
        for zone in self.zones:
            settings = zone.getSettings()
            # if this IcmpType is used in a zone remove it from that zone first
            if obj.name in settings[index]:
                settings[index].remove(obj.name)
                zone.obj = self.config.set_zone_config(zone.obj, settings)
                zone.Updated(zone.obj.name)

        for icmptype in self.icmptypes:
            if icmptype.obj == obj:
                icmptype.Removed(obj.name)
                icmptype.unregister()
                self.icmptypes.remove(icmptype)
                del icmptype

    @handle_exceptions
    def _addService(self, obj):
        # TODO: check for idx overflow
        config_service = FirewallDConfigService(self, \
            self.config, obj, self.service_idx, self.path,
            "%s/%d" % (DBUS_PATH_CONFIG_SERVICE, self.service_idx))
        self.services.append(config_service)
        self.service_idx += 1
        self.ServiceAdded(obj.name)
        return config_service

    @handle_exceptions
    def _updateService(self, obj):
        for service in self.services:
            if service.obj.name == obj.name and \
                    service.obj.path == obj.path and \
                    service.obj.filename == obj.filename:
                service.obj = obj
                service.Updated(obj.name)

    @handle_exceptions
    def removeService(self, obj):
        index = 5 # see IMPORT_EXPORT_STRUCTURE in class Zone(IO_Object)
        for zone in self.zones:
            settings = zone.getSettings()
            # if this Service is used in a zone remove it from that zone first
            if obj.name in settings[index]:
                settings[index].remove(obj.name)
                zone.obj = self.config.set_zone_config(zone.obj, settings)
                zone.Updated(zone.obj.name)

        for service in self.services:
            if service.obj == obj:
                service.Removed(obj.name)
                service.unregister()
                self.services.remove(service)
                del service

    @handle_exceptions
    def _addZone(self, obj):
        # TODO: check for idx overflow
        config_zone = FirewallDConfigZone(self, \
            self.config, obj, self.zone_idx, self.path,
            "%s/%d" % (DBUS_PATH_CONFIG_ZONE, self.zone_idx))
        self.zones.append(config_zone)
        self.zone_idx += 1
        self.ZoneAdded(obj.name)
        return config_zone

    @handle_exceptions
    def _updateZone(self, obj):
        for zone in self.zones:
            if zone.obj.name == obj.name and zone.obj.path == obj.path and \
                    zone.obj.filename == obj.filename:
                zone.obj = obj
                zone.Updated(obj.name)

    @handle_exceptions
    def removeZone(self, obj):
        for zone in self.zones:
            if zone.obj == obj:
                zone.Removed(obj.name)
                zone.unregister()
                self.zones.remove(zone)
                del zone

    # access check

    @dbus_handle_exceptions
    def accessCheck(self, sender):
        if self.config.lockdown_enabled():
            if sender == None:
                log.error("Lockdown not possible, sender not set.")
                return
            bus = dbus.SystemBus()
            context = context_of_sender(bus, sender)
            if self.config.access_check("context", context):
                return
            uid = uid_of_sender(bus, sender)
            if self.config.access_check("uid", uid):
                return
            user = user_of_uid(uid)
            if self.config.access_check("user", user):
                return
            command = command_of_sender(bus, sender)
            if self.config.access_check("command", command):
                return
            raise FirewallError(ACCESS_DENIED, "lockdown is enabled")

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # P R O P E R T I E S

    @dbus_handle_exceptions
    def _get_property(self, prop):
        if prop in [ "DefaultZone", "MinimalMark", "CleanupOnExit",
                     "Lockdown" ]:
            value = self.config.get_firewalld_conf().get(prop)
            if prop == "MinimalMark":
                value = int(value)
            if value != None:
                return value
            if prop == "DefaultZone":
                return FALLBACK_ZONE
            elif prop == "MinimalMark":
                return FALLBACK_MINIMAL_MARK
            elif prop == "CleanupOnExit":
                return "yes"
            elif prop == "Lockdown":
                return "no"
        else:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.AccessDenied: "
                "Property '%s' isn't exported (or may not exist)" % prop)

    @dbus_service_method(dbus.PROPERTIES_IFACE, in_signature='ss',
                         out_signature='v')
    @dbus_handle_exceptions
    def Get(self, interface_name, property_name, sender=None):
        # get a property
        interface_name = dbus_to_python(interface_name)
        property_name = dbus_to_python(property_name)
        log.debug1("config.Get('%s', '%s')", interface_name, property_name)

        if interface_name != DBUS_INTERFACE_CONFIG:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.UnknownInterface: "
                "FirewallD does not implement %s" % interface_name)

        return self._get_property(property_name)

    @dbus_service_method(dbus.PROPERTIES_IFACE, in_signature='s',
                         out_signature='a{sv}')
    @dbus_handle_exceptions
    def GetAll(self, interface_name, sender=None):
        interface_name = dbus_to_python(interface_name)
        log.debug1("config.GetAll('%s')", interface_name)

        if interface_name != DBUS_INTERFACE_CONFIG:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.UnknownInterface: "
                "FirewallD does not implement %s" % interface_name)

        return {
            'DefaultZone': self._get_property("DefaultZone"),
            'MinimalMark': self._get_property("MinimalMark"),
            'CleanupOnExit': self._get_property("CleanupOnExit"),
            'Lockdown': self._get_property("Lockdown"),
        }

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(dbus.PROPERTIES_IFACE, in_signature='ssv')
    @dbus_handle_exceptions
    def Set(self, interface_name, property_name, new_value, sender=None):
        interface_name = dbus_to_python(interface_name)
        property_name = dbus_to_python(property_name)
        new_value = dbus_to_python(new_value)
        log.debug1("config.Set('%s', '%s', '%s')", interface_name,
                   property_name, new_value)
        self.accessCheck(sender)

        if interface_name != DBUS_INTERFACE_CONFIG:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.UnknownInterface: "
                "FirewallD does not implement %s" % interface_name)

        if property_name in [ "DefaultZone", "MinimalMark", "CleanupOnExit",
                              "Lockdown" ]:
            if property_name == "MinimalMark":
                try:
                    foo = int(new_value)
                except:
                    raise FirewallError(INVALID_MARK, new_value)
            try:
                new_value = str(new_value)
            except:
                raise FirewallError(INVALID_VALUE, "'%s' for %s" % \
                                            (new_value, property_name))
            if property_name in [ "CleanupOnExit", "Lockdown" ]:
                if new_value.lower() not in [ "yes", "no", "true", "false" ]:
                    raise FirewallError(INVALID_VALUE, "'%s' for %s" % \
                                            (new_value, property_name))
            self.config.get_firewalld_conf().set(property_name, new_value)
            self.config.get_firewalld_conf().write()
            self.PropertiesChanged(interface_name,
                                   { property_name: new_value }, [ ])
        else:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.AccessDenied: "
                "Property '%s' does not exist" % prop)

    @dbus.service.signal(dbus.PROPERTIES_IFACE, signature='sa{sv}as')
    def PropertiesChanged(self, interface_name, changed_properties,
                          invalidated_properties):
        pass

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # policies

    @dbus_service_method(DBUS_INTERFACE_CONFIG_POLICIES,
                         out_signature=LockdownWhitelist.DBUS_SIGNATURE)
    @dbus_handle_exceptions
    def getLockdownWhitelist(self, sender=None):
        log.debug1("config.policies.getLockdownWhitelist()")
        return self.config.get_policies().lockdown_whitelist.export_config()

    @dbus_service_method(DBUS_INTERFACE_CONFIG_POLICIES, 
                         in_signature=LockdownWhitelist.DBUS_SIGNATURE)
    @dbus_handle_exceptions
    def setLockdownWhitelist(self, settings, sender=None):
        log.debug1("config.policies.setLockdownWhitelistSettings(...)")
        settings = dbus_to_python(settings)
        self.config.get_policies().lockdown_whitelist.import_config(settings)
        self.config.get_policies().lockdown_whitelist.write()
        self.LockdownWhitelistUpdated()

    @dbus.service.signal(DBUS_INTERFACE_CONFIG_POLICIES)
    @dbus_handle_exceptions
    def LockdownWhitelistUpdated(self):
        log.debug1("config.policies.LockdownWhitelistUpdated()")

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # I C M P T Y P E S

    @dbus_service_method(DBUS_INTERFACE_CONFIG, out_signature='ao')
    @dbus_handle_exceptions
    def listIcmpTypes(self, sender=None):
        """list icmptypes objects paths
        """
        log.debug1("config.listIcmpTypes()")
        return self.icmptypes

    @dbus_service_method(DBUS_INTERFACE_CONFIG, in_signature='s',
                         out_signature='o')
    @dbus_handle_exceptions
    def getIcmpTypeByName(self, icmptype, sender=None):
        """object path of icmptype with given name
        """
        icmptype = dbus_to_python(icmptype)
        log.debug1("config.getIcmpTypeByName('%s')", icmptype)
        for obj in self.icmptypes:
            if obj.obj.name == icmptype:
                return obj
        raise FirewallError(INVALID_ICMPTYPE, icmptype)

    @dbus_service_method(DBUS_INTERFACE_CONFIG,
                         in_signature='s'+IcmpType.DBUS_SIGNATURE,
                         out_signature='o')
    @dbus_handle_exceptions
    def addIcmpType(self, icmptype, settings, sender=None):
        """add icmptype with given name and settings
        """
        icmptype = dbus_to_python(icmptype)
        settings = dbus_to_python(settings)
        log.debug1("config.addIcmpType('%s')", icmptype)
        self.accessCheck(sender)
        obj = self.config.new_icmptype(icmptype, settings)
        config_icmptype = self._addIcmpType(obj)
        return config_icmptype

    @dbus.service.signal(DBUS_INTERFACE_CONFIG, signature='s')
    @dbus_handle_exceptions
    def IcmpTypeAdded(self, icmptype):
        log.debug1("config.IcmpTypeAdded('%s')" % (icmptype))

    # S E R V I C E S

    @dbus_service_method(DBUS_INTERFACE_CONFIG, out_signature='ao')
    @dbus_handle_exceptions
    def listServices(self, sender=None):
        """list services objects paths
        """
        log.debug1("config.listServices()")
        return self.services

    @dbus_service_method(DBUS_INTERFACE_CONFIG, in_signature='s',
                         out_signature='o')
    @dbus_handle_exceptions
    def getServiceByName(self, service, sender=None):
        """object path of service with given name
        """
        service = dbus_to_python(service)
        log.debug1("config.getServiceByName('%s')", service)
        for obj in self.services:
            if obj.obj.name == service:
                return obj
        raise FirewallError(INVALID_SERVICE, service)

    @dbus_service_method(DBUS_INTERFACE_CONFIG,
                         in_signature='s'+Service.DBUS_SIGNATURE,
                         out_signature='o')
    @dbus_handle_exceptions
    def addService(self, service, settings, sender=None):
        """add service with given name and settings
        """
        service = dbus_to_python(service)
        settings = dbus_to_python(settings)
        log.debug1("config.addService('%s')", service)
        self.accessCheck(sender)
        obj = self.config.new_service(service, settings)
        config_service = self._addService(obj)
        return config_service

    @dbus.service.signal(DBUS_INTERFACE_CONFIG, signature='s')
    @dbus_handle_exceptions
    def ServiceAdded(self, service):
        log.debug1("config.ServiceAdded('%s')" % (service))

    # Z O N E S

    @dbus_service_method(DBUS_INTERFACE_CONFIG, out_signature='ao')
    @dbus_handle_exceptions
    def listZones(self, sender=None):
        """list zones objects paths
        """
        log.debug1("config.listZones()")
        return self.zones

    @dbus_service_method(DBUS_INTERFACE_CONFIG, in_signature='s',
                         out_signature='o')
    @dbus_handle_exceptions
    def getZoneByName(self, zone, sender=None):
        """object path of zone with given name
        """
        zone = dbus_to_python(zone)
        log.debug1("config.getZoneByName('%s')", zone)
        for obj in self.zones:
            if obj.obj.name == zone:
                return obj
        raise FirewallError(INVALID_ZONE, zone)

    @dbus_service_method(DBUS_INTERFACE_CONFIG, in_signature='s',
                         out_signature='s')
    @dbus_handle_exceptions
    def getZoneOfInterface(self, iface, sender=None):
        """name of zone the given interface belongs to
        """
        iface = dbus_to_python(iface)
        log.debug1("config.getZoneOfInterface('%s')", iface)
        ret = []
        for obj in self.zones:
            if iface in obj.obj.interfaces:
                ret.append(obj.obj.name)
        if len(ret) > 1:
            # Even it shouldn't happen, it's actually possible that
            # the same interface is in several zone XML files
            return " ".join(ret) + "  (ERROR: interface '%s' is in %s zone XML files, can be only in one)" % (iface, len(ret))
        return ret[0] if ret else ""

    @dbus_service_method(DBUS_INTERFACE_CONFIG, in_signature='s',
                         out_signature='s')
    @dbus_handle_exceptions
    def getZoneOfSource(self, source, sender=None):
        """name of zone the given source belongs to
        """
        source = dbus_to_python(source)
        log.debug1("config.getZoneOfSource('%s')", source)
        ret = []
        for obj in self.zones:
            if source in obj.obj.sources:
                ret.append(obj.obj.name)
        if len(ret) > 1:
            # Even it shouldn't happen, it's actually possible that
            # the same source is in several zone XML files
            return " ".join(ret) + "  (ERROR: source '%s' is in %s zone XML files, can be only in one)" % (iface, len(ret))
        return ret[0] if ret else ""

    @dbus_service_method(DBUS_INTERFACE_CONFIG,
                         in_signature='s'+Zone.DBUS_SIGNATURE,
                         out_signature='o')
    @dbus_handle_exceptions
    def addZone(self, zone, settings, sender=None):
        """add zone with given name and settings
        """
        zone = dbus_to_python(zone)
        settings = dbus_to_python(settings)
        log.debug1("config.addZone('%s')", zone)
        self.accessCheck(sender)
        obj = self.config.new_zone(zone, settings)
        config_zone = self._addZone(obj)
        return config_zone

    @dbus.service.signal(DBUS_INTERFACE_CONFIG, signature='s')
    @dbus_handle_exceptions
    def ZoneAdded(self, zone):
        log.debug1("config.ZoneAdded('%s')" % (zone))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # DIRECT

    @dbus_service_method(DBUS_INTERFACE_CONFIG_DIRECT,
                         out_signature=Direct.DBUS_SIGNATURE)
    @dbus_handle_exceptions
    def getSettings(self, sender=None):
        # returns list ipv, table, list of chains
        log.debug1("config.direct.getSettings()")
        return self.config.get_direct().export_config()

    @dbus_service_method(DBUS_INTERFACE_CONFIG_DIRECT,
                         in_signature=Direct.DBUS_SIGNATURE)
    @dbus_handle_exceptions
    def update(self, settings, sender=None):
        # returns list ipv, table, list of chains
        log.debug1("config.direct.update()")
        settings = dbus_to_python(settings)
        self.config.get_direct().import_config(settings)
        self.config.get_direct().write()
        self.Updated()

    @dbus.service.signal(DBUS_INTERFACE_CONFIG_DIRECT)
    @dbus_handle_exceptions
    def Updated(self):
        log.debug1("config.direct.Updated()")
