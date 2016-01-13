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
from firewall.dbus_utils import dbus_to_python
from firewall.config.dbus import *
from firewall.core.fw import Firewall
from firewall.core.io.zone import Zone
from firewall.core.logger import log
from firewall.server.decorators import *
from firewall.errors import *
from firewall.core.base import DEFAULT_ZONE_TARGET
from firewall.core.rich import Rich_Rule
from firewall.functions import portStr

############################################################################
#
# class FirewallDConfig
#
############################################################################

class FirewallDConfigZone(slip.dbus.service.Object):
    """FirewallD main class"""

    persistent = True
    """ Make FirewallD persistent. """
    default_polkit_auth_required = PK_ACTION_CONFIG
    """ Use PK_ACTION_INFO as a default """

    @handle_exceptions
    def __init__(self, parent, config, zone, id, *args, **kwargs):
        super(FirewallDConfigZone, self).__init__(*args, **kwargs)
        self.parent = parent
        self.config = config
        self.obj = zone
        self.id = id
        self.path = args[0]

    @dbus_handle_exceptions
    def __del__(self):
        pass

    @dbus_handle_exceptions
    def unregister(self):
        self.remove_from_connection()

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # P R O P E R T I E S

    @dbus_service_method(dbus.PROPERTIES_IFACE, in_signature='ss',
                         out_signature='v')
    @dbus_handle_exceptions
    def Get(self, interface_name, property_name, sender=None):
        # get a property
        interface_name = dbus_to_python(interface_name, str)
        property_name = dbus_to_python(property_name, str)
        log.debug1("config.zone.%d.Get('%s', '%s')", self.id,
                   interface_name, property_name)

        if interface_name != DBUS_INTERFACE_CONFIG_ZONE:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.UnknownInterface: "
                "FirewallD does not implement %s" % interface_name)

        if property_name == "name":
            return self.obj.name
        elif property_name == "filename":
            return self.obj.filename
        elif property_name == "path":
            return self.obj.path
        elif property_name == "default":
            return self.obj.default
        elif property_name == "builtin":
            return self.obj.builtin
        else:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.AccessDenied: "
                "Property '%s' isn't exported (or may not exist)" % \
                    property_name)

    @dbus_service_method(dbus.PROPERTIES_IFACE, in_signature='s',
                         out_signature='a{sv}')
    @dbus_handle_exceptions
    def GetAll(self, interface_name, sender=None):
        interface_name = dbus_to_python(interface_name, str)
        log.debug1("config.zone.%d.GetAll('%s')", self.id, interface_name)

        if interface_name != DBUS_INTERFACE_CONFIG_ZONE:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.UnknownInterface: "
                "FirewallD does not implement %s" % interface_name)

        return {
            'name': self.obj.name,
            'filename': self.obj.filename,
            'path': self.obj.path,
            'default': self.obj.default,
        }

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(dbus.PROPERTIES_IFACE, in_signature='ssv')
    @dbus_handle_exceptions
    def Set(self, interface_name, property_name, new_value, sender=None):
        interface_name = dbus_to_python(interface_name, str)
        property_name = dbus_to_python(property_name, str)
        new_value = dbus_to_python(new_value)
        log.debug1("config.zone.%d.Set('%s', '%s', '%s')", self.id,
                   interface_name, property_name, new_value)
        self.parent.accessCheck(sender)

        if interface_name != DBUS_INTERFACE_CONFIG_ZONE:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.UnknownInterface: "
                "FirewallD does not implement %s" % interface_name)

        raise dbus.exceptions.DBusException(
            "org.freedesktop.DBus.Error.AccessDenied: "
            "Property '%s' is not settable" % property_name)

    @dbus.service.signal(dbus.PROPERTIES_IFACE, signature='sa{sv}as')
    def PropertiesChanged(self, interface_name, changed_properties,
                          invalidated_properties):
        pass

    # S E T T I N G S

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, out_signature=Zone.DBUS_SIGNATURE)
    @dbus_handle_exceptions
    def getSettings(self, sender=None):
        """get settings for zone
        """
        log.debug1("config.zone.%d.getSettings()", self.id)
        settings = self.config.get_zone_config(self.obj)
        if settings[4] == DEFAULT_ZONE_TARGET:
            # convert to list, fix target, convert back to tuple
            _settings = list(settings)
            _settings[4] = "default"
            settings = tuple(_settings)
        return settings

    def _checkDuplicateInterfacesSources(self, settings):
        """Assignment of interfaces/sources to zones is different from other
           zone settings in the sense that particular interface/zone can be
           part of only one zone. So make sure added interfaces/sources have
           not already been bound to another zone."""
        old_settings = self.config.get_zone_config(self.obj)
        idx_i = Zone.index_of("interfaces")
        idx_s = Zone.index_of("sources")
        added_ifaces = set(settings[idx_i]) - set(old_settings[idx_i])
        added_sources = set(settings[idx_s]) - set(old_settings[idx_s])

        for iface in added_ifaces:
            if self.parent.getZoneOfInterface(iface):
                raise FirewallError(ZONE_CONFLICT, iface)  # or move to new zone ?
        for source in added_sources:
            if self.parent.getZoneOfSource(source):
                raise FirewallError(ZONE_CONFLICT, source) # or move to new zone ?

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature=Zone.DBUS_SIGNATURE)
    @dbus_handle_exceptions
    def update(self, settings, sender=None):
        """update settings for zone
        """
        settings = dbus_to_python(settings)
        log.debug1("config.zone.%d.update('...')", self.id)
        self.parent.accessCheck(sender)
        if settings[4] == "default":
            # convert to list, fix target, convert back to tuple
            _settings = list(settings)
            _settings[4] = DEFAULT_ZONE_TARGET
            settings = tuple(_settings)
        self._checkDuplicateInterfacesSources(settings)
        self.obj = self.config.set_zone_config(self.obj, settings)
        self.Updated(self.obj.name)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE)
    @dbus_handle_exceptions
    def loadDefaults(self, sender=None):
        """load default settings for builtin zone
        """
        log.debug1("config.zone.%d.loadDefaults()", self.id)
        self.parent.accessCheck(sender)
        self.obj = self.config.load_zone_defaults(self.obj)
        self.Updated(self.obj.name)

    @dbus.service.signal(DBUS_INTERFACE_CONFIG_ZONE, signature='s')
    @dbus_handle_exceptions
    def Updated(self, name):
        log.debug1("config.zone.%d.Updated('%s')" % (self.id, name))

    # R E M O V E

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE)
    @dbus_handle_exceptions
    def remove(self, sender=None):
        """remove zone
        """
        log.debug1("config.zone.%d.removeZone()", self.id)
        self.parent.accessCheck(sender)
        self.config.remove_zone(self.obj)
        self.parent.removeZone(self.obj)

    @dbus.service.signal(DBUS_INTERFACE_CONFIG_ZONE, signature='s')
    @dbus_handle_exceptions
    def Removed(self, name):
        log.debug1("config.zone.%d.Removed('%s')" % (self.id, name))

    # R E N A M E

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='s')
    @dbus_handle_exceptions
    def rename(self, name, sender=None):
        """rename zone
        """
        name = dbus_to_python(name, str)
        log.debug1("config.zone.%d.rename('%s')", self.id, name)
        self.parent.accessCheck(sender)
        self.obj = self.config.rename_zone(self.obj, name)
        self.Renamed(name)

    @dbus.service.signal(DBUS_INTERFACE_CONFIG_ZONE, signature='s')
    @dbus_handle_exceptions
    def Renamed(self, name):
        log.debug1("config.zone.%d.Renamed('%s')" % (self.id, name))

    # version

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, out_signature='s')
    @dbus_handle_exceptions
    def getVersion(self, sender=None):
        log.debug1("config.zone.%d.getVersion()", self.id)
        return self.getSettings()[0]

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='s')
    @dbus_handle_exceptions
    def setVersion(self, version, sender=None):
        version = dbus_to_python(version, str)
        log.debug1("config.zone.%d.setVersion('%s')", self.id, version)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[0] = version
        self.update(settings)

    # short

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, out_signature='s')
    @dbus_handle_exceptions
    def getShort(self, sender=None):
        log.debug1("config.zone.%d.getShort()", self.id)
        return self.getSettings()[1]

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='s')
    @dbus_handle_exceptions
    def setShort(self, short, sender=None):
        short = dbus_to_python(short, str)
        log.debug1("config.zone.%d.setShort('%s')", self.id, short)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[1] = short
        self.update(settings)

    # description

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, out_signature='s')
    @dbus_handle_exceptions
    def getDescription(self, sender=None):
        log.debug1("config.zone.%d.getDescription()", self.id)
        return self.getSettings()[2]

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='s')
    @dbus_handle_exceptions
    def setDescription(self, description, sender=None):
        description = dbus_to_python(description, str)
        log.debug1("config.zone.%d.setDescription('%s')", self.id, description)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[2] = description
        self.update(settings)

    # immutable (deprecated)
    # settings[3] was used for 'immutable'

    # target

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, out_signature='s')
    @dbus_handle_exceptions
    def getTarget(self, sender=None):
        log.debug1("config.zone.%d.getTarget()", self.id)
        settings = self.getSettings()
        return settings[4] if settings[4] != DEFAULT_ZONE_TARGET else "default"

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='s')
    @dbus_handle_exceptions
    def setTarget(self, target, sender=None):
        target = dbus_to_python(target, str)
        log.debug1("config.zone.%d.setTarget('%s')", self.id, target)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[4] = target if target != "default" else DEFAULT_ZONE_TARGET
        self.update(settings)

    # service

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, out_signature='as')
    @dbus_handle_exceptions
    def getServices(self, sender=None):
        log.debug1("config.zone.%d.getServices()", self.id)
        return sorted(self.getSettings()[5])

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='as')
    @dbus_handle_exceptions
    def setServices(self, services, sender=None):
        services = dbus_to_python(services, list)
        log.debug1("config.zone.%d.setServices('[%s]')", self.id,
                   ",".join(services))
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[5] = services
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='s')
    @dbus_handle_exceptions
    def addService(self, service, sender=None):
        service = dbus_to_python(service, str)
        log.debug1("config.zone.%d.addService('%s')", self.id, service)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if service in settings[5]:
            raise FirewallError(ALREADY_ENABLED, service)
        settings[5].append(service)
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='s')
    @dbus_handle_exceptions
    def removeService(self, service, sender=None):
        service = dbus_to_python(service, str)
        log.debug1("config.zone.%d.removeService('%s')", self.id, service)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if service not in settings[5]:
            raise FirewallError(NOT_ENABLED, service)
        settings[5].remove(service)
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='s',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryService(self, service, sender=None):
        service = dbus_to_python(service, str)
        log.debug1("config.zone.%d.queryService('%s')", self.id, service)
        return service in self.getSettings()[5]

    # port

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, out_signature='a(ss)')
    @dbus_handle_exceptions
    def getPorts(self, sender=None):
        log.debug1("config.zone.%d.getPorts()", self.id)
        return self.getSettings()[6]

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='a(ss)')
    @dbus_handle_exceptions
    def setPorts(self, ports, sender=None):
        _ports = [ ]
        # convert embedded lists to tuples
        for port in dbus_to_python(ports, list):
            if type(port) == list:
                _ports.append(tuple(port))
            else:
                _ports.append(port)
        ports = _ports
        log.debug1("config.zone.%d.setPorts('[%s]')", self.id,
                   ",".join("('%s, '%s')" % (port[0], port[1]) for port in ports))
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[6] = ports
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='ss')
    @dbus_handle_exceptions
    def addPort(self, port, protocol, sender=None):
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        log.debug1("config.zone.%d.addPort('%s', '%s')", self.id, port,
                   protocol)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if (port,protocol) in settings[6]:
            raise FirewallError(ALREADY_ENABLED, "%s:%s" % (port, protocol))
        settings[6].append((port,protocol))
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='ss')
    @dbus_handle_exceptions
    def removePort(self, port, protocol, sender=None):
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        log.debug1("config.zone.%d.removePort('%s', '%s')", self.id, port,
                   protocol)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if (port,protocol) not in settings[6]:
            raise FirewallError(NOT_ENABLED, "%s:%s" % (port, protocol))
        settings[6].remove((port,protocol))
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='ss',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryPort(self, port, protocol, sender=None):
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        log.debug1("config.zone.%d.queryPort('%s', '%s')", self.id, port,
                   protocol)
        return (port,protocol) in self.getSettings()[6]

    # protocol

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, out_signature='as')
    @dbus_handle_exceptions
    def getProtocols(self, sender=None):
        log.debug1("config.zone.%d.getProtocols()", self.id)
        return self.getSettings()[13]

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='as')
    @dbus_handle_exceptions
    def setProtocols(self, protocols, sender=None):
        protocols = dbus_to_python(protocols, list)
        log.debug1("config.zone.%d.setProtocols('[%s]')", self.id,
                   ",".join(protocols))
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[13] = protocols
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='s')
    @dbus_handle_exceptions
    def addProtocol(self, protocol, sender=None):
        protocol = dbus_to_python(protocol, str)
        log.debug1("config.zone.%d.addProtocol('%s')", self.id, protocol)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if protocol in settings[13]:
            raise FirewallError(ALREADY_ENABLED, protocol)
        settings[13].append(protocol)
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='s')
    @dbus_handle_exceptions
    def removeProtocol(self, protocol, sender=None):
        protocol = dbus_to_python(protocol, str)
        log.debug1("config.zone.%d.removeProtocol('%s')", self.id, protocol)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if protocol not in settings[13]:
            raise FirewallError(NOT_ENABLED, protocol)
        settings[13].remove(protocol)
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='s',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryProtocol(self, protocol, sender=None):
        protocol = dbus_to_python(protocol, str)
        log.debug1("config.zone.%d.queryProtocol('%s')", self.id, protocol)
        return protocol in self.getSettings()[13]

    # icmp block

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, out_signature='as')
    @dbus_handle_exceptions
    def getIcmpBlocks(self, sender=None):
        log.debug1("config.zone.%d.getIcmpBlocks()", self.id)
        return sorted(self.getSettings()[7])

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='as')
    @dbus_handle_exceptions
    def setIcmpBlocks(self, icmptypes, sender=None):
        icmptypes = dbus_to_python(icmptypes, list)
        log.debug1("config.zone.%d.setIcmpBlocks('[%s]')", self.id,
                   ",".join(icmptypes))
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[7] = icmptypes
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='s')
    @dbus_handle_exceptions
    def addIcmpBlock(self, icmptype, sender=None):
        icmptype = dbus_to_python(icmptype, str)
        log.debug1("config.zone.%d.addIcmpBlock('%s')", self.id, icmptype)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if icmptype in settings[7]:
            raise FirewallError(ALREADY_ENABLED, icmptype)
        settings[7].append(icmptype)
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='s')
    @dbus_handle_exceptions
    def removeIcmpBlock(self, icmptype, sender=None):
        icmptype = dbus_to_python(icmptype, str)
        log.debug1("config.zone.%d.removeIcmpBlock('%s')", self.id, icmptype)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if icmptype not in settings[7]:
            raise FirewallError(NOT_ENABLED, icmptype)
        settings[7].remove(icmptype)
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='s',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryIcmpBlock(self, icmptype, sender=None):
        icmptype = dbus_to_python(icmptype, str)
        log.debug1("config.zone.%d.removeIcmpBlock('%s')", self.id, icmptype)
        return icmptype in self.getSettings()[7]

    # masquerade

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, out_signature='b')
    @dbus_handle_exceptions
    def getMasquerade(self, sender=None):
        log.debug1("config.zone.%d.getMasquerade()", self.id)
        return self.getSettings()[8]

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='b')
    @dbus_handle_exceptions
    def setMasquerade(self, masquerade, sender=None):
        masquerade = dbus_to_python(masquerade, bool)
        log.debug1("config.zone.%d.setMasquerade('%s')", self.id, masquerade)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[8] = masquerade
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE)
    @dbus_handle_exceptions
    def addMasquerade(self, sender=None):
        log.debug1("config.zone.%d.addMasquerade()", self.id)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if settings[8]:
            raise FirewallError(ALREADY_ENABLED, "masquerade")
        settings[8] = True
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE)
    @dbus_handle_exceptions
    def removeMasquerade(self, sender=None):
        log.debug1("config.zone.%d.removeMasquerade()", self.id)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if not settings[8]:
            raise FirewallError(NOT_ENABLED, "masquerade")
        settings[8] = False
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, out_signature='b')
    @dbus_handle_exceptions
    def queryMasquerade(self, sender=None):
        log.debug1("config.zone.%d.queryMasquerade()", self.id)
        return self.getSettings()[8]

    # forward port

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, out_signature='a(ssss)')
    @dbus_handle_exceptions
    def getForwardPorts(self, sender=None):
        log.debug1("config.zone.%d.getForwardPorts()", self.id)
        return self.getSettings()[9]

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='a(ssss)')
    @dbus_handle_exceptions
    def setForwardPorts(self, ports, sender=None):
        _ports = [ ]
        # convert embedded lists to tuples
        for port in dbus_to_python(ports, list):
            if type(port) == list:
                _ports.append(tuple(port))
            else:
                _ports.append(port)
        ports = _ports
        log.debug1("config.zone.%d.setForwardPorts('[%s]')", self.id,
                   ",".join("('%s, '%s', '%s', '%s')" % (port[0], port[1], \
                                                         port[2], port[3]) for port in ports))
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[9] = ports
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='ssss')
    @dbus_handle_exceptions
    def addForwardPort(self, port, protocol, toport, toaddr, sender=None):
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        toport = dbus_to_python(toport, str)
        toaddr = dbus_to_python(toaddr, str)
        log.debug1("config.zone.%d.addForwardPort('%s', '%s', '%s', '%s')",
                   self.id, port, protocol, toport, toaddr)
        self.parent.accessCheck(sender)
        fwp_id = (portStr(port, "-"), protocol, portStr(toport, "-"),
                  str(toaddr))
        settings = list(self.getSettings())
        if fwp_id in settings[9]:
            raise FirewallError(ALREADY_ENABLED,
                                "%s:%s:%s:%s" % (port, protocol, toport, toaddr))
        settings[9].append(fwp_id)
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='ssss')
    @dbus_handle_exceptions
    def removeForwardPort(self, port, protocol, toport, toaddr, sender=None):
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        toport = dbus_to_python(toport, str)
        toaddr = dbus_to_python(toaddr, str)
        log.debug1("config.zone.%d.removeForwardPort('%s', '%s', '%s', '%s')",
                   self.id, port, protocol, toport, toaddr)
        self.parent.accessCheck(sender)
        fwp_id = (portStr(port, "-"), protocol, portStr(toport, "-"),
                  str(toaddr))
        settings = list(self.getSettings())
        if fwp_id not in settings[9]:
            raise FirewallError(NOT_ENABLED,
                                "%s:%s:%s:%s" % (port, protocol, toport, toaddr))
        settings[9].remove(fwp_id)
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='ssss',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryForwardPort(self, port, protocol, toport, toaddr, sender=None):
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        toport = dbus_to_python(toport, str)
        toaddr = dbus_to_python(toaddr, str)
        log.debug1("config.zone.%d.queryForwardPort('%s', '%s', '%s', '%s')",
                   self.id, port, protocol, toport, toaddr)
        fwp_id = (portStr(port, "-"), protocol, portStr(toport, "-"),
                  str(toaddr))
        return fwp_id in self.getSettings()[9]

    # interface

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, out_signature='as')
    @dbus_handle_exceptions
    def getInterfaces(self, sender=None):
        log.debug1("config.zone.%d.getInterfaces()", self.id)
        return sorted(self.getSettings()[10])

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='as')
    @dbus_handle_exceptions
    def setInterfaces(self, interfaces, sender=None):
        interfaces = dbus_to_python(interfaces, list)
        log.debug1("config.zone.%d.setInterfaces('[%s]')", self.id,
                   ",".join(interfaces))
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[10] = interfaces
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='s')
    @dbus_handle_exceptions
    def addInterface(self, interface, sender=None):
        interface = dbus_to_python(interface, str)
        log.debug1("config.zone.%d.addInterface('%s')", self.id, interface)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if interface in settings[10]:
            raise FirewallError(ALREADY_ENABLED, interface)
        settings[10].append(interface)
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='s')
    @dbus_handle_exceptions
    def removeInterface(self, interface, sender=None):
        interface = dbus_to_python(interface, str)
        log.debug1("config.zone.%d.removeInterface('%s')", self.id, interface)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if interface not in settings[10]:
            raise FirewallError(NOT_ENABLED, interface)
        settings[10].remove(interface)
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='s',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryInterface(self, interface, sender=None):
        interface = dbus_to_python(interface, str)
        log.debug1("config.zone.%d.queryInterface('%s')", self.id, interface)
        return interface in self.getSettings()[10]

    # source

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, out_signature='as')
    @dbus_handle_exceptions
    def getSources(self, sender=None):
        log.debug1("config.zone.%d.getSources()", self.id)
        return sorted(self.getSettings()[11])

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='as')
    @dbus_handle_exceptions
    def setSources(self, sources, sender=None):
        sources = dbus_to_python(sources, list)
        log.debug1("config.zone.%d.setSources('[%s]')", self.id,
                   ",".join(sources))
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[11] = sources
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='s')
    @dbus_handle_exceptions
    def addSource(self, source, sender=None):
        source = dbus_to_python(source, str)
        log.debug1("config.zone.%d.addSource('%s')", self.id, source)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if source in settings[11]:
            raise FirewallError(ALREADY_ENABLED, source)
        settings[11].append(source)
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='s')
    @dbus_handle_exceptions
    def removeSource(self, source, sender=None):
        source = dbus_to_python(source, str)
        log.debug1("config.zone.%d.removeSource('%s')", self.id, source)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if source not in settings[11]:
            raise FirewallError(NOT_ENABLED, source)
        settings[11].remove(source)
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='s',
                         out_signature='b')
    @dbus_handle_exceptions
    def querySource(self, source, sender=None):
        source = dbus_to_python(source, str)
        log.debug1("config.zone.%d.querySource('%s')", self.id, source)
        return source in self.getSettings()[11]

    # rich rule

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, out_signature='as')
    @dbus_handle_exceptions
    def getRichRules(self, sender=None):
        log.debug1("config.zone.%d.getRichRules()", self.id)
        return self.getSettings()[12]

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='as')
    @dbus_handle_exceptions
    def setRichRules(self, rules, sender=None):
        rules = dbus_to_python(rules, list)
        log.debug1("config.zone.%d.setRichRules('[%s]')", self.id,
                   ",".join(rules))
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        rules = [ str(Rich_Rule(rule_str=r)) for r in rules ]
        settings[12] = rules
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='s')
    @dbus_handle_exceptions
    def addRichRule(self, rule, sender=None):
        rule = dbus_to_python(rule, str)
        log.debug1("config.zone.%d.addRichRule('%s')", self.id, rule)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        rule_str = str(Rich_Rule(rule_str=rule))
        if rule_str in settings[12]:
            raise FirewallError(ALREADY_ENABLED, rule)
        settings[12].append(rule_str)
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='s')
    @dbus_handle_exceptions
    def removeRichRule(self, rule, sender=None):
        rule = dbus_to_python(rule, str)
        log.debug1("config.zone.%d.removeRichRule('%s')", self.id, rule)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        rule_str = str(Rich_Rule(rule_str=rule))
        if rule_str not in settings[12]:
            raise FirewallError(NOT_ENABLED, rule)
        settings[12].remove(rule_str)
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature='s',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryRichRule(self, rule, sender=None):
        rule = dbus_to_python(rule, str)
        log.debug1("config.zone.%d.queryRichRule('%s')", self.id, rule)
        rule_str = str(Rich_Rule(rule_str=rule))
        return rule_str in self.getSettings()[12]
