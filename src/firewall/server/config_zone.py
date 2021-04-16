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

import dbus
import dbus.service

from firewall import config
from firewall.dbus_utils import dbus_to_python, \
    dbus_introspection_prepare_properties, \
    dbus_introspection_add_properties
from firewall.core.io.zone import Zone
from firewall.core.fw_ifcfg import ifcfg_set_zone_of_interface
from firewall.core.base import DEFAULT_ZONE_TARGET
from firewall.core.rich import Rich_Rule
from firewall.core.logger import log
from firewall.server.dbus import DbusServiceObject
from firewall.server.decorators import handle_exceptions, \
    dbus_handle_exceptions, dbus_service_method, \
    dbus_polkit_require_auth
from firewall import errors
from firewall.errors import FirewallError
from firewall.functions import portStr, portInPortRange, coalescePortRange, \
                               breakPortRange

############################################################################
#
# class FirewallDConfig
#
############################################################################

class FirewallDConfigZone(DbusServiceObject):
    """FirewallD main class"""

    persistent = True
    """ Make FirewallD persistent. """
    default_polkit_auth_required = config.dbus.PK_ACTION_CONFIG
    """ Use PK_ACTION_INFO as a default """

    @handle_exceptions
    def __init__(self, parent, conf, zone, item_id, *args, **kwargs):
        super(FirewallDConfigZone, self).__init__(*args, **kwargs)
        self.parent = parent
        self.config = conf
        self.obj = zone
        self.item_id = item_id
        self.busname = args[0]
        self.path = args[1]
        self._log_prefix = "config.zone.%d" % self.item_id
        dbus_introspection_prepare_properties(
            self, config.dbus.DBUS_INTERFACE_CONFIG_ZONE)

    @dbus_handle_exceptions
    def __del__(self):
        pass

    @dbus_handle_exceptions
    def unregister(self):
        self.remove_from_connection()

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # P R O P E R T I E S

    @dbus_handle_exceptions
    def _get_property(self, property_name):
        if property_name == "name":
            return dbus.String(self.obj.name)
        elif property_name == "filename":
            return dbus.String(self.obj.filename)
        elif property_name == "path":
            return dbus.String(self.obj.path)
        elif property_name == "default":
            return dbus.Boolean(self.obj.default)
        elif property_name == "builtin":
            return dbus.Boolean(self.obj.builtin)
        else:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.InvalidArgs: "
                "Property '%s' does not exist" % property_name)

    @dbus_service_method(dbus.PROPERTIES_IFACE, in_signature='ss',
                         out_signature='v')
    @dbus_handle_exceptions
    def Get(self, interface_name, property_name, sender=None): # pylint: disable=W0613
        # get a property
        interface_name = dbus_to_python(interface_name, str)
        property_name = dbus_to_python(property_name, str)
        log.debug1("%s.Get('%s', '%s')", self._log_prefix,
                   interface_name, property_name)

        if interface_name != config.dbus.DBUS_INTERFACE_CONFIG_ZONE:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.UnknownInterface: "
                "Interface '%s' does not exist" % interface_name)

        return self._get_property(property_name)

    @dbus_service_method(dbus.PROPERTIES_IFACE, in_signature='s',
                         out_signature='a{sv}')
    @dbus_handle_exceptions
    def GetAll(self, interface_name, sender=None): # pylint: disable=W0613
        interface_name = dbus_to_python(interface_name, str)
        log.debug1("%s.GetAll('%s')", self._log_prefix, interface_name)

        if interface_name != config.dbus.DBUS_INTERFACE_CONFIG_ZONE:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.UnknownInterface: "
                "Interface '%s' does not exist" % interface_name)

        ret = { }
        for x in [ "name", "filename", "path", "default", "builtin" ]:
            ret[x] = self._get_property(x)
        return dbus.Dictionary(ret, signature="sv")

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(dbus.PROPERTIES_IFACE, in_signature='ssv')
    @dbus_handle_exceptions
    def Set(self, interface_name, property_name, new_value, sender=None):
        interface_name = dbus_to_python(interface_name, str)
        property_name = dbus_to_python(property_name, str)
        new_value = dbus_to_python(new_value)
        log.debug1("%s.Set('%s', '%s', '%s')", self._log_prefix,
                   interface_name, property_name, new_value)
        self.parent.accessCheck(sender)

        if interface_name != config.dbus.DBUS_INTERFACE_CONFIG_ZONE:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.UnknownInterface: "
                "Interface '%s' does not exist" % interface_name)

        raise dbus.exceptions.DBusException(
            "org.freedesktop.DBus.Error.PropertyReadOnly: "
            "Property '%s' is read-only" % property_name)

    @dbus.service.signal(dbus.PROPERTIES_IFACE, signature='sa{sv}as')
    def PropertiesChanged(self, interface_name, changed_properties,
                          invalidated_properties):
        interface_name = dbus_to_python(interface_name, str)
        changed_properties = dbus_to_python(changed_properties)
        invalidated_properties = dbus_to_python(invalidated_properties)
        log.debug1("%s.PropertiesChanged('%s', '%s', '%s')", self._log_prefix,
                   interface_name, changed_properties, invalidated_properties)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_INFO)
    @dbus_service_method(dbus.INTROSPECTABLE_IFACE, out_signature='s')
    @dbus_handle_exceptions
    def Introspect(self, sender=None): # pylint: disable=W0613
        log.debug2("%s.Introspect()", self._log_prefix)

        data = super(FirewallDConfigZone, self).Introspect(
            self.path, self.busname.get_bus())

        return dbus_introspection_add_properties(
            self, data, config.dbus.DBUS_INTERFACE_CONFIG_ZONE)

    # S E T T I N G S

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         out_signature="(sssbsasa(ss)asba(ssss)asasasasa(ss)b)")
    @dbus_handle_exceptions
    def getSettings(self, sender=None): # pylint: disable=W0613
        """get settings for zone
        """
        log.debug1("%s.getSettings()", self._log_prefix)
        settings = self.config.get_zone_config(self.obj)
        if settings[4] == DEFAULT_ZONE_TARGET:
            # convert to list, fix target, convert back to tuple
            _settings = list(settings)
            _settings[4] = "default"
            settings = tuple(_settings)
        return settings

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         out_signature="a{sv}")
    @dbus_handle_exceptions
    def getSettings2(self, sender=None):
        """get settings for zone
        """
        log.debug1("%s.getSettings2()", self._log_prefix)
        settings = self.config.get_zone_config_dict(self.obj)
        if settings["target"] == DEFAULT_ZONE_TARGET:
            settings["target"] = "default"
        return settings

    def _checkDuplicateInterfacesSources(self, settings):
        """Assignment of interfaces/sources to zones is different from other
           zone settings in the sense that particular interface/zone can be
           part of only one zone. So make sure added interfaces/sources have
           not already been bound to another zone."""
        old_settings = self.config.get_zone_config_dict(self.obj)
        old_ifaces = set(old_settings["interfaces"]) if "interfaces" in old_settings else set()
        old_sources = set(old_settings["sources"]) if "sources" in old_settings else set()
        if isinstance(settings, tuple):
            added_ifaces = set(settings[Zone.index_of("interfaces")]) - old_ifaces
            added_sources = set(settings[Zone.index_of("sources")]) - old_sources
        else: # dict
            new_ifaces = set(settings["interfaces"]) if "interfaces" in settings else set()
            new_sources = set(settings["sources"]) if "sources" in settings else set()
            added_ifaces = new_ifaces - old_ifaces
            added_sources = new_sources - old_sources

        for iface in added_ifaces:
            if self.parent.getZoneOfInterface(iface):
                raise FirewallError(errors.ZONE_CONFLICT, iface)  # or move to new zone ?
        for source in added_sources:
            if self.parent.getZoneOfSource(source):
                raise FirewallError(errors.ZONE_CONFLICT, source) # or move to new zone ?

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature="(sssbsasa(ss)asba(ssss)asasasasa(ss)b)")
    @dbus_handle_exceptions
    def update(self, settings, sender=None):
        """update settings for zone
        """
        settings = dbus_to_python(settings)
        log.debug1("%s.update('...')", self._log_prefix)
        self.parent.accessCheck(sender)
        if settings[4] == "default":
            # convert to list, fix target, convert back to tuple
            _settings = list(settings)
            _settings[4] = DEFAULT_ZONE_TARGET
            settings = tuple(_settings)
        self._checkDuplicateInterfacesSources(settings)
        self.obj = self.config.set_zone_config(self.obj, settings)
        self.Updated(self.obj.name)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature="a{sv}")
    @dbus_handle_exceptions
    def update2(self, settings, sender=None):
        """update settings for zone
        """
        settings = dbus_to_python(settings)
        log.debug1("%s.update2('...')", self._log_prefix)
        self.parent.accessCheck(sender)
        if "target" in settings and settings["target"] == "default":
            settings["target"] = DEFAULT_ZONE_TARGET
        self._checkDuplicateInterfacesSources(settings)
        self.obj = self.config.set_zone_config_dict(self.obj, settings)
        self.Updated(self.obj.name)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE)
    @dbus_handle_exceptions
    def loadDefaults(self, sender=None):
        """load default settings for builtin zone
        """
        log.debug1("%s.loadDefaults()", self._log_prefix)
        self.parent.accessCheck(sender)
        self.obj = self.config.load_zone_defaults(self.obj)
        self.Updated(self.obj.name)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_CONFIG_ZONE, signature='s')
    @dbus_handle_exceptions
    def Updated(self, name):
        log.debug1("%s.Updated('%s')" % (self._log_prefix, name))

    # R E M O V E

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE)
    @dbus_handle_exceptions
    def remove(self, sender=None):
        """remove zone
        """
        log.debug1("%s.removeZone()", self._log_prefix)
        self.parent.accessCheck(sender)
        self.config.remove_zone(self.obj)
        self.parent.removeZone(self.obj)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_CONFIG_ZONE, signature='s')
    @dbus_handle_exceptions
    def Removed(self, name):
        log.debug1("%s.Removed('%s')" % (self._log_prefix, name))

    # R E N A M E

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='s')
    @dbus_handle_exceptions
    def rename(self, name, sender=None):
        """rename zone
        """
        name = dbus_to_python(name, str)
        log.debug1("%s.rename('%s')", self._log_prefix, name)
        self.parent.accessCheck(sender)
        self.obj = self.config.rename_zone(self.obj, name)
        self.Renamed(name)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_CONFIG_ZONE, signature='s')
    @dbus_handle_exceptions
    def Renamed(self, name):
        log.debug1("%s.Renamed('%s')" % (self._log_prefix, name))

    # version

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         out_signature='s')
    @dbus_handle_exceptions
    def getVersion(self, sender=None): # pylint: disable=W0613
        log.debug1("%s.getVersion()", self._log_prefix)
        return self.getSettings()[0]

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='s')
    @dbus_handle_exceptions
    def setVersion(self, version, sender=None):
        version = dbus_to_python(version, str)
        log.debug1("%s.setVersion('%s')", self._log_prefix, version)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[0] = version
        self.update(settings)

    # short

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         out_signature='s')
    @dbus_handle_exceptions
    def getShort(self, sender=None): # pylint: disable=W0613
        log.debug1("%s.getShort()", self._log_prefix)
        return self.getSettings()[1]

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='s')
    @dbus_handle_exceptions
    def setShort(self, short, sender=None):
        short = dbus_to_python(short, str)
        log.debug1("%s.setShort('%s')", self._log_prefix, short)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[1] = short
        self.update(settings)

    # description

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         out_signature='s')
    @dbus_handle_exceptions
    def getDescription(self, sender=None): # pylint: disable=W0613
        log.debug1("%s.getDescription()", self._log_prefix)
        return self.getSettings()[2]

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='s')
    @dbus_handle_exceptions
    def setDescription(self, description, sender=None):
        description = dbus_to_python(description, str)
        log.debug1("%s.setDescription('%s')", self._log_prefix, description)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[2] = description
        self.update(settings)

    # immutable (deprecated)
    # settings[3] was used for 'immutable'

    # target

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         out_signature='s')
    @dbus_handle_exceptions
    def getTarget(self, sender=None): # pylint: disable=W0613
        log.debug1("%s.getTarget()", self._log_prefix)
        settings = self.getSettings()
        return settings[4] if settings[4] != DEFAULT_ZONE_TARGET else "default"

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='s')
    @dbus_handle_exceptions
    def setTarget(self, target, sender=None):
        target = dbus_to_python(target, str)
        log.debug1("%s.setTarget('%s')", self._log_prefix, target)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[4] = target if target != "default" else DEFAULT_ZONE_TARGET
        self.update(settings)

    # service

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         out_signature='as')
    @dbus_handle_exceptions
    def getServices(self, sender=None): # pylint: disable=W0613
        log.debug1("%s.getServices()", self._log_prefix)
        return self.getSettings()[5]

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='as')
    @dbus_handle_exceptions
    def setServices(self, services, sender=None):
        services = dbus_to_python(services, list)
        log.debug1("%s.setServices('[%s]')", self._log_prefix,
                   ",".join(services))
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[5] = services
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='s')
    @dbus_handle_exceptions
    def addService(self, service, sender=None):
        service = dbus_to_python(service, str)
        log.debug1("%s.addService('%s')", self._log_prefix, service)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if service in settings[5]:
            raise FirewallError(errors.ALREADY_ENABLED, service)
        settings[5].append(service)
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='s')
    @dbus_handle_exceptions
    def removeService(self, service, sender=None):
        service = dbus_to_python(service, str)
        log.debug1("%s.removeService('%s')", self._log_prefix, service)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if service not in settings[5]:
            raise FirewallError(errors.NOT_ENABLED, service)
        settings[5].remove(service)
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='s', out_signature='b')
    @dbus_handle_exceptions
    def queryService(self, service, sender=None): # pylint: disable=W0613
        service = dbus_to_python(service, str)
        log.debug1("%s.queryService('%s')", self._log_prefix, service)
        return service in self.getSettings()[5]

    # port

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         out_signature='a(ss)')
    @dbus_handle_exceptions
    def getPorts(self, sender=None): # pylint: disable=W0613
        log.debug1("%s.getPorts()", self._log_prefix)
        return self.getSettings()[6]

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='a(ss)')
    @dbus_handle_exceptions
    def setPorts(self, ports, sender=None):
        _ports = [ ]
        # convert embedded lists to tuples
        for port in dbus_to_python(ports, list):
            if isinstance(port, list):
                _ports.append(tuple(port))
            else:
                _ports.append(port)
        ports = _ports
        log.debug1("%s.setPorts('[%s]')", self._log_prefix,
                   ",".join("('%s, '%s')" % (port[0], port[1]) for port in ports))
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[6] = ports
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='ss')
    @dbus_handle_exceptions
    def addPort(self, port, protocol, sender=None):
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        log.debug1("%s.addPort('%s', '%s')", self._log_prefix, port,
                   protocol)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        existing_port_ids = list(filter(lambda x: x[1] == protocol, settings[6]))
        for port_id in existing_port_ids:
            if portInPortRange(port, port_id[0]):
                raise FirewallError(errors.ALREADY_ENABLED,
                                    "%s:%s" % (port, protocol))
        added_ranges, removed_ranges = coalescePortRange(port, [_port for (_port, _protocol) in existing_port_ids])
        for range in removed_ranges:
            settings[6].remove((portStr(range, "-"), protocol))
        for range in added_ranges:
            settings[6].append((portStr(range, "-"), protocol))
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='ss')
    @dbus_handle_exceptions
    def removePort(self, port, protocol, sender=None):
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        log.debug1("%s.removePort('%s', '%s')", self._log_prefix, port,
                   protocol)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        existing_port_ids = list(filter(lambda x: x[1] == protocol, settings[6]))
        for port_id in existing_port_ids:
            if portInPortRange(port, port_id[0]):
                break
        else:
            raise FirewallError(errors.NOT_ENABLED, "%s:%s" % (port, protocol))
        added_ranges, removed_ranges = breakPortRange(port, [_port for (_port, _protocol) in existing_port_ids])
        for range in removed_ranges:
            settings[6].remove((portStr(range, "-"), protocol))
        for range in added_ranges:
            settings[6].append((portStr(range, "-"), protocol))
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='ss', out_signature='b')
    @dbus_handle_exceptions
    def queryPort(self, port, protocol, sender=None): # pylint: disable=W0613
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        log.debug1("%s.queryPort('%s', '%s')", self._log_prefix, port,
                   protocol)
        for (_port, _protocol) in self.getSettings()[6]:
            if portInPortRange(port, _port) and protocol == _protocol:
                return True

        return False

    # protocol

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         out_signature='as')
    @dbus_handle_exceptions
    def getProtocols(self, sender=None): # pylint: disable=W0613
        log.debug1("%s.getProtocols()", self._log_prefix)
        return self.getSettings()[13]

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='as')
    @dbus_handle_exceptions
    def setProtocols(self, protocols, sender=None):
        protocols = dbus_to_python(protocols, list)
        log.debug1("%s.setProtocols('[%s]')", self._log_prefix,
                   ",".join(protocols))
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[13] = protocols
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='s')
    @dbus_handle_exceptions
    def addProtocol(self, protocol, sender=None):
        protocol = dbus_to_python(protocol, str)
        log.debug1("%s.addProtocol('%s')", self._log_prefix, protocol)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if protocol in settings[13]:
            raise FirewallError(errors.ALREADY_ENABLED, protocol)
        settings[13].append(protocol)
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='s')
    @dbus_handle_exceptions
    def removeProtocol(self, protocol, sender=None):
        protocol = dbus_to_python(protocol, str)
        log.debug1("%s.removeProtocol('%s')", self._log_prefix, protocol)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if protocol not in settings[13]:
            raise FirewallError(errors.NOT_ENABLED, protocol)
        settings[13].remove(protocol)
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='s', out_signature='b')
    @dbus_handle_exceptions
    def queryProtocol(self, protocol, sender=None): # pylint: disable=W0613
        protocol = dbus_to_python(protocol, str)
        log.debug1("%s.queryProtocol('%s')", self._log_prefix, protocol)
        return protocol in self.getSettings()[13]

    # source port

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         out_signature='a(ss)')
    @dbus_handle_exceptions
    def getSourcePorts(self, sender=None): # pylint: disable=W0613
        log.debug1("%s.getSourcePorts()", self._log_prefix)
        return self.getSettings()[14]

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='a(ss)')
    @dbus_handle_exceptions
    def setSourcePorts(self, ports, sender=None):
        _ports = [ ]
        # convert embedded lists to tuples
        for port in dbus_to_python(ports, list):
            if isinstance(port, list):
                _ports.append(tuple(port))
            else:
                _ports.append(port)
        ports = _ports
        log.debug1("%s.setSourcePorts('[%s]')", self._log_prefix,
                   ",".join("('%s, '%s')" % (port[0], port[1]) for port in ports))
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[14] = ports
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='ss')
    @dbus_handle_exceptions
    def addSourcePort(self, port, protocol, sender=None):
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        log.debug1("%s.addSourcePort('%s', '%s')", self._log_prefix, port,
                   protocol)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        existing_port_ids = list(filter(lambda x: x[1] == protocol, settings[14]))
        for port_id in existing_port_ids:
            if portInPortRange(port, port_id[0]):
                raise FirewallError(errors.ALREADY_ENABLED,
                                    "%s:%s" % (port, protocol))
        added_ranges, removed_ranges = coalescePortRange(port, [_port for (_port, _protocol) in existing_port_ids])
        for range in removed_ranges:
            settings[14].remove((portStr(range, "-"), protocol))
        for range in added_ranges:
            settings[14].append((portStr(range, "-"), protocol))
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='ss')
    @dbus_handle_exceptions
    def removeSourcePort(self, port, protocol, sender=None):
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        log.debug1("%s.removeSourcePort('%s', '%s')", self._log_prefix, port,
                   protocol)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        existing_port_ids = list(filter(lambda x: x[1] == protocol, settings[14]))
        for port_id in existing_port_ids:
            if portInPortRange(port, port_id[0]):
                break
        else:
            raise FirewallError(errors.NOT_ENABLED, "%s:%s" % (port, protocol))
        added_ranges, removed_ranges = breakPortRange(port, [_port for (_port, _protocol) in existing_port_ids])
        for range in removed_ranges:
            settings[14].remove((portStr(range, "-"), protocol))
        for range in added_ranges:
            settings[14].append((portStr(range, "-"), protocol))
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='ss', out_signature='b')
    @dbus_handle_exceptions
    def querySourcePort(self, port, protocol, sender=None): # pylint: disable=W0613
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        log.debug1("%s.querySourcePort('%s', '%s')", self._log_prefix, port,
                   protocol)
        for (_port, _protocol) in self.getSettings()[14]:
            if portInPortRange(port, _port) and protocol == _protocol:
                return True

        return False

    # icmp block

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         out_signature='as')
    @dbus_handle_exceptions
    def getIcmpBlocks(self, sender=None): # pylint: disable=W0613
        log.debug1("%s.getIcmpBlocks()", self._log_prefix)
        return self.getSettings()[7]

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='as')
    @dbus_handle_exceptions
    def setIcmpBlocks(self, icmptypes, sender=None):
        icmptypes = dbus_to_python(icmptypes, list)
        log.debug1("%s.setIcmpBlocks('[%s]')", self._log_prefix,
                   ",".join(icmptypes))
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[7] = icmptypes
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='s')
    @dbus_handle_exceptions
    def addIcmpBlock(self, icmptype, sender=None):
        icmptype = dbus_to_python(icmptype, str)
        log.debug1("%s.addIcmpBlock('%s')", self._log_prefix, icmptype)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if icmptype in settings[7]:
            raise FirewallError(errors.ALREADY_ENABLED, icmptype)
        settings[7].append(icmptype)
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='s')
    @dbus_handle_exceptions
    def removeIcmpBlock(self, icmptype, sender=None):
        icmptype = dbus_to_python(icmptype, str)
        log.debug1("%s.removeIcmpBlock('%s')", self._log_prefix, icmptype)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if icmptype not in settings[7]:
            raise FirewallError(errors.NOT_ENABLED, icmptype)
        settings[7].remove(icmptype)
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='s', out_signature='b')
    @dbus_handle_exceptions
    def queryIcmpBlock(self, icmptype, sender=None): # pylint: disable=W0613
        icmptype = dbus_to_python(icmptype, str)
        log.debug1("%s.queryIcmpBlock('%s')", self._log_prefix, icmptype)
        return icmptype in self.getSettings()[7]

    # icmp block inversion

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         out_signature='b')
    @dbus_handle_exceptions
    def getIcmpBlockInversion(self, sender=None): # pylint: disable=W0613
        log.debug1("%s.getIcmpBlockInversion()", self._log_prefix)
        return self.getSettings()[15]

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='b')
    @dbus_handle_exceptions
    def setIcmpBlockInversion(self, flag, sender=None):
        flag = dbus_to_python(flag, bool)
        log.debug1("%s.setIcmpBlockInversion('%s')", self._log_prefix, flag)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[15] = flag
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE)
    @dbus_handle_exceptions
    def addIcmpBlockInversion(self, sender=None):
        log.debug1("%s.addIcmpBlockInversion()", self._log_prefix)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if settings[15]:
            raise FirewallError(errors.ALREADY_ENABLED, "icmp-block-inversion")
        settings[15] = True
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE)
    @dbus_handle_exceptions
    def removeIcmpBlockInversion(self, sender=None):
        log.debug1("%s.removeIcmpBlockInversion()", self._log_prefix)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if not settings[15]:
            raise FirewallError(errors.NOT_ENABLED, "icmp-block-inversion")
        settings[15] = False
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         out_signature='b')
    @dbus_handle_exceptions
    def queryIcmpBlockInversion(self, sender=None): # pylint: disable=W0613
        log.debug1("%s.queryIcmpBlockInversion()", self._log_prefix)
        return self.getSettings()[15]

    # masquerade

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         out_signature='b')
    @dbus_handle_exceptions
    def getMasquerade(self, sender=None): # pylint: disable=W0613
        log.debug1("%s.getMasquerade()", self._log_prefix)
        return self.getSettings()[8]

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='b')
    @dbus_handle_exceptions
    def setMasquerade(self, masquerade, sender=None):
        masquerade = dbus_to_python(masquerade, bool)
        log.debug1("%s.setMasquerade('%s')", self._log_prefix, masquerade)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[8] = masquerade
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE)
    @dbus_handle_exceptions
    def addMasquerade(self, sender=None):
        log.debug1("%s.addMasquerade()", self._log_prefix)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if settings[8]:
            raise FirewallError(errors.ALREADY_ENABLED, "masquerade")
        settings[8] = True
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE)
    @dbus_handle_exceptions
    def removeMasquerade(self, sender=None):
        log.debug1("%s.removeMasquerade()", self._log_prefix)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if not settings[8]:
            raise FirewallError(errors.NOT_ENABLED, "masquerade")
        settings[8] = False
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         out_signature='b')
    @dbus_handle_exceptions
    def queryMasquerade(self, sender=None): # pylint: disable=W0613
        log.debug1("%s.queryMasquerade()", self._log_prefix)
        return self.getSettings()[8]

    # forward port

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         out_signature='a(ssss)')
    @dbus_handle_exceptions
    def getForwardPorts(self, sender=None): # pylint: disable=W0613
        log.debug1("%s.getForwardPorts()", self._log_prefix)
        return self.getSettings()[9]

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='a(ssss)')
    @dbus_handle_exceptions
    def setForwardPorts(self, ports, sender=None):
        _ports = [ ]
        # convert embedded lists to tuples
        for port in dbus_to_python(ports, list):
            if isinstance(port, list):
                _ports.append(tuple(port))
            else:
                _ports.append(port)
        ports = _ports
        log.debug1("%s.setForwardPorts('[%s]')", self._log_prefix,
                   ",".join("('%s, '%s', '%s', '%s')" % (port[0], port[1], \
                                                         port[2], port[3]) for port in ports))
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[9] = ports
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='ssss')
    @dbus_handle_exceptions
    def addForwardPort(self, port, protocol, toport, toaddr, sender=None): # pylint: disable=R0913
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        toport = dbus_to_python(toport, str)
        toaddr = dbus_to_python(toaddr, str)
        log.debug1("%s.addForwardPort('%s', '%s', '%s', '%s')",
                   self._log_prefix, port, protocol, toport, toaddr)
        self.parent.accessCheck(sender)
        fwp_id = (port, protocol, str(toport), str(toaddr))
        settings = list(self.getSettings())
        if fwp_id in settings[9]:
            raise FirewallError(errors.ALREADY_ENABLED,
                                "%s:%s:%s:%s" % (port, protocol, toport,
                                                 toaddr))
        settings[9].append(fwp_id)
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='ssss')
    @dbus_handle_exceptions
    def removeForwardPort(self, port, protocol, toport, toaddr, sender=None): # pylint: disable=R0913
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        toport = dbus_to_python(toport, str)
        toaddr = dbus_to_python(toaddr, str)
        log.debug1("%s.removeForwardPort('%s', '%s', '%s', '%s')",
                   self._log_prefix, port, protocol, toport, toaddr)
        self.parent.accessCheck(sender)
        fwp_id = (port, protocol, str(toport), str(toaddr))
        settings = list(self.getSettings())
        if fwp_id not in settings[9]:
            raise FirewallError(errors.NOT_ENABLED,
                                "%s:%s:%s:%s" % (port, protocol, toport,
                                                 toaddr))
        settings[9].remove(fwp_id)
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='ssss',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryForwardPort(self, port, protocol, toport, toaddr, sender=None): # pylint: disable=W0613, R0913
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        toport = dbus_to_python(toport, str)
        toaddr = dbus_to_python(toaddr, str)
        log.debug1("%s.queryForwardPort('%s', '%s', '%s', '%s')",
                   self._log_prefix, port, protocol, toport, toaddr)
        fwp_id = (port, protocol, str(toport), str(toaddr))
        return fwp_id in self.getSettings()[9]

    # interface

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         out_signature='as')
    @dbus_handle_exceptions
    def getInterfaces(self, sender=None): # pylint: disable=W0613
        log.debug1("%s.getInterfaces()", self._log_prefix)
        return self.getSettings()[10]

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='as')
    @dbus_handle_exceptions
    def setInterfaces(self, interfaces, sender=None):
        interfaces = dbus_to_python(interfaces, list)
        log.debug1("%s.setInterfaces('[%s]')", self._log_prefix,
                   ",".join(interfaces))
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[10] = interfaces
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='s')
    @dbus_handle_exceptions
    def addInterface(self, interface, sender=None):
        interface = dbus_to_python(interface, str)
        log.debug1("%s.addInterface('%s')", self._log_prefix, interface)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if interface in settings[10]:
            raise FirewallError(errors.ALREADY_ENABLED, interface)
        settings[10].append(interface)
        self.update(settings)

        ifcfg_set_zone_of_interface(self.obj.name, interface)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='s')
    @dbus_handle_exceptions
    def removeInterface(self, interface, sender=None):
        interface = dbus_to_python(interface, str)
        log.debug1("%s.removeInterface('%s')", self._log_prefix, interface)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if interface not in settings[10]:
            raise FirewallError(errors.NOT_ENABLED, interface)
        settings[10].remove(interface)
        self.update(settings)

        ifcfg_set_zone_of_interface("", interface)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='s',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryInterface(self, interface, sender=None): # pylint: disable=W0613
        interface = dbus_to_python(interface, str)
        log.debug1("%s.queryInterface('%s')", self._log_prefix, interface)
        return interface in self.getSettings()[10]

    # source

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         out_signature='as')
    @dbus_handle_exceptions
    def getSources(self, sender=None): # pylint: disable=W0613
        log.debug1("%s.getSources()", self._log_prefix)
        return self.getSettings()[11]

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='as')
    @dbus_handle_exceptions
    def setSources(self, sources, sender=None):
        sources = dbus_to_python(sources, list)
        log.debug1("%s.setSources('[%s]')", self._log_prefix,
                   ",".join(sources))
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[11] = sources
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='s')
    @dbus_handle_exceptions
    def addSource(self, source, sender=None):
        source = dbus_to_python(source, str)
        log.debug1("%s.addSource('%s')", self._log_prefix, source)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if source in settings[11]:
            raise FirewallError(errors.ALREADY_ENABLED, source)
        settings[11].append(source)
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='s')
    @dbus_handle_exceptions
    def removeSource(self, source, sender=None):
        source = dbus_to_python(source, str)
        log.debug1("%s.removeSource('%s')", self._log_prefix, source)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if source not in settings[11]:
            raise FirewallError(errors.NOT_ENABLED, source)
        settings[11].remove(source)
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='s', out_signature='b')
    @dbus_handle_exceptions
    def querySource(self, source, sender=None): # pylint: disable=W0613
        source = dbus_to_python(source, str)
        log.debug1("%s.querySource('%s')", self._log_prefix, source)
        return source in self.getSettings()[11]

    # rich rule

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         out_signature='as')
    @dbus_handle_exceptions
    def getRichRules(self, sender=None): # pylint: disable=W0613
        log.debug1("%s.getRichRules()", self._log_prefix)
        return self.getSettings()[12]

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='as')
    @dbus_handle_exceptions
    def setRichRules(self, rules, sender=None):
        rules = dbus_to_python(rules, list)
        log.debug1("%s.setRichRules('[%s]')", self._log_prefix,
                   ",".join(rules))
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        rules = [ str(Rich_Rule(rule_str=r)) for r in rules ]
        settings[12] = rules
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='s')
    @dbus_handle_exceptions
    def addRichRule(self, rule, sender=None):
        rule = dbus_to_python(rule, str)
        log.debug1("%s.addRichRule('%s')", self._log_prefix, rule)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        rule_str = str(Rich_Rule(rule_str=rule))
        if rule_str in settings[12]:
            raise FirewallError(errors.ALREADY_ENABLED, rule)
        settings[12].append(rule_str)
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='s')
    @dbus_handle_exceptions
    def removeRichRule(self, rule, sender=None):
        rule = dbus_to_python(rule, str)
        log.debug1("%s.removeRichRule('%s')", self._log_prefix, rule)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        rule_str = str(Rich_Rule(rule_str=rule))
        if rule_str not in settings[12]:
            raise FirewallError(errors.NOT_ENABLED, rule)
        settings[12].remove(rule_str)
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                         in_signature='s', out_signature='b')
    @dbus_handle_exceptions
    def queryRichRule(self, rule, sender=None): # pylint: disable=W0613
        rule = dbus_to_python(rule, str)
        log.debug1("%s.queryRichRule('%s')", self._log_prefix, rule)
        rule_str = str(Rich_Rule(rule_str=rule))
        return rule_str in self.getSettings()[12]
