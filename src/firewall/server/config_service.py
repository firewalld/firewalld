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
from firewall.core.io.service import Service
from firewall.core.logger import log
from firewall.server.decorators import *
from firewall.errors import *

############################################################################
#
# class FirewallDConfig
#
############################################################################

class FirewallDConfigService(slip.dbus.service.Object):
    """FirewallD main class"""

    persistent = True
    """ Make FirewallD persistent. """
    default_polkit_auth_required = PK_ACTION_CONFIG
    """ Use PK_ACTION_INFO as a default """

    @handle_exceptions
    def __init__(self, parent, config, service, id, *args, **kwargs):
        super(FirewallDConfigService, self).__init__(*args, **kwargs)
        self.parent = parent
        self.config = config
        self.obj = service
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
        log.debug1("config.service.%d.Get('%s', '%s')", self.id,
                   interface_name, property_name)

        if interface_name != DBUS_INTERFACE_CONFIG_SERVICE:
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
            return self.config.is_builtin_service(self.obj)
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
        log.debug1("config.service.%d.GetAll('%s')", self.id, interface_name)

        if interface_name != DBUS_INTERFACE_CONFIG_SERVICE:
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
        log.debug1("config.service.%d.Set('%s', '%s', '%s')", self.id,
                   interface_name, property_name, new_value)
        self.parent.accessCheck(sender)

        if interface_name != DBUS_INTERFACE_CONFIG_SERVICE:
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

    @dbus_service_method(DBUS_INTERFACE_CONFIG_SERVICE, out_signature=Service.DBUS_SIGNATURE)
    @dbus_handle_exceptions
    def getSettings(self, sender=None):
        """get settings for service
        """
        log.debug1("config.service.%d.getSettings()", self.id)
        return self.config.get_service_config(self.obj)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_SERVICE, in_signature=Service.DBUS_SIGNATURE)
    @dbus_handle_exceptions
    def update(self, settings, sender=None):
        """update settings for service
        """
        settings = dbus_to_python(settings)
        log.debug1("config.service.%d.update('...')", self.id)
        self.parent.accessCheck(sender)
        self.obj = self.config.set_service_config(self.obj, settings)
        self.Updated(self.obj.name)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_SERVICE)
    @dbus_handle_exceptions
    def loadDefaults(self, sender=None):
        """load default settings for builtin service
        """
        log.debug1("config.service.%d.loadDefaults()", self.id)
        self.parent.accessCheck(sender)
        self.obj = self.config.load_service_defaults(self.obj)
        self.Updated(self.obj.name)

    @dbus.service.signal(DBUS_INTERFACE_CONFIG_SERVICE, signature='s')
    @dbus_handle_exceptions
    def Updated(self, name):
        log.debug1("config.service.%d.Updated('%s')" % (self.id, name))

    # R E M O V E

    @dbus_service_method(DBUS_INTERFACE_CONFIG_SERVICE)
    @dbus_handle_exceptions
    def remove(self, sender=None):
        """remove service
        """
        log.debug1("config.service.%d.removeService()", self.id)
        self.parent.accessCheck(sender)
        self.config.remove_service(self.obj)
        self.parent.removeService(self.obj)

    @dbus.service.signal(DBUS_INTERFACE_CONFIG_SERVICE, signature='s')
    @dbus_handle_exceptions
    def Removed(self, name):
        log.debug1("config.service.%d.Removed('%s')" % (self.id, name))

    # R E N A M E

    @dbus_service_method(DBUS_INTERFACE_CONFIG_SERVICE, in_signature='s')
    @dbus_handle_exceptions
    def rename(self, name, sender=None):
        """rename service
        """
        name = dbus_to_python(name, str)
        log.debug1("config.service.%d.rename('%s')", self.id, name)
        self.parent.accessCheck(sender)
        self.obj = self.config.rename_service(self.obj, name)
        self.Renamed(name)

    @dbus.service.signal(DBUS_INTERFACE_CONFIG_SERVICE, signature='s')
    @dbus_handle_exceptions
    def Renamed(self, name):
        log.debug1("config.service.%d.Renamed('%s')" % (self.id, name))

    # version

    @dbus_service_method(DBUS_INTERFACE_CONFIG_SERVICE, out_signature='s')
    @dbus_handle_exceptions
    def getVersion(self, sender=None):
        log.debug1("config.service.%d.getVersion()", self.id)
        return self.getSettings()[0]

    @dbus_service_method(DBUS_INTERFACE_CONFIG_SERVICE, in_signature='s')
    @dbus_handle_exceptions
    def setVersion(self, version, sender=None):
        version = dbus_to_python(version, str)
        log.debug1("config.service.%d.setVersion('%s')", self.id, version)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[0] = version
        self.update(settings)

    # short

    @dbus_service_method(DBUS_INTERFACE_CONFIG_SERVICE, out_signature='s')
    @dbus_handle_exceptions
    def getShort(self, sender=None):
        log.debug1("config.service.%d.getShort()", self.id)
        return self.getSettings()[1]

    @dbus_service_method(DBUS_INTERFACE_CONFIG_SERVICE, in_signature='s')
    @dbus_handle_exceptions
    def setShort(self, short, sender=None):
        short = dbus_to_python(short, str)
        log.debug1("config.service.%d.setShort('%s')", self.id, short)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[1] = short
        self.update(settings)

    # description

    @dbus_service_method(DBUS_INTERFACE_CONFIG_SERVICE, out_signature='s')
    @dbus_handle_exceptions
    def getDescription(self, sender=None):
        log.debug1("config.service.%d.getDescription()", self.id)
        return self.getSettings()[2]

    @dbus_service_method(DBUS_INTERFACE_CONFIG_SERVICE, in_signature='s')
    @dbus_handle_exceptions
    def setDescription(self, description, sender=None):
        description = dbus_to_python(description, str)
        log.debug1("config.service.%d.setDescription('%s')", self.id,
                   description)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[2] = description
        self.update(settings)

    # port

    @dbus_service_method(DBUS_INTERFACE_CONFIG_SERVICE, out_signature='a(ss)')
    @dbus_handle_exceptions
    def getPorts(self, sender=None):
        log.debug1("config.service.%d.getPorts()", self.id)
        return self.getSettings()[3]

    @dbus_service_method(DBUS_INTERFACE_CONFIG_SERVICE, in_signature='a(ss)')
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
        log.debug1("config.service.%d.setPorts('[%s]')", self.id,
                   ",".join("('%s, '%s')" % (port[0], port[1]) for port in ports))
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[3] = ports
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_SERVICE, in_signature='ss')
    @dbus_handle_exceptions
    def addPort(self, port, protocol, sender=None):
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        log.debug1("config.service.%d.addPort('%s', '%s')", self.id, port,
                   protocol)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if (port,protocol) in settings[3]:
            raise FirewallError(ALREADY_ENABLED, "%s:%s" % (port, protocol))
        settings[3].append((port,protocol))
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_SERVICE, in_signature='ss')
    @dbus_handle_exceptions
    def removePort(self, port, protocol, sender=None):
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        log.debug1("config.service.%d.removePort('%s', '%s')", self.id, port,
                   protocol)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if (port,protocol) not in settings[3]:
            raise FirewallError(NOT_ENABLED, "%s:%s" % (port, protocol))
        settings[3].remove((port,protocol))
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_SERVICE, in_signature='ss',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryPort(self, port, protocol, sender=None):
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        log.debug1("config.service.%d.queryPort('%s', '%s')", self.id, port,
                   protocol)
        return (port,protocol) in self.getSettings()[3]

    # module

    @dbus_service_method(DBUS_INTERFACE_CONFIG_SERVICE, out_signature='as')
    @dbus_handle_exceptions
    def getModules(self, sender=None):
        log.debug1("config.service.%d.getModules()", self.id)
        return sorted(self.getSettings()[4])

    @dbus_service_method(DBUS_INTERFACE_CONFIG_SERVICE, in_signature='as')
    @dbus_handle_exceptions
    def setModules(self, modules, sender=None):
        modules = dbus_to_python(modules, list)
        log.debug1("config.service.%d.setModules('[%s]')", self.id,
                   ",".join(modules))
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[4] = modules
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_SERVICE, in_signature='s')
    @dbus_handle_exceptions
    def addModule(self, module, sender=None):
        module = dbus_to_python(module, str)
        log.debug1("config.service.%d.addModule('%s')", self.id, module)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if module in settings[4]:
            raise FirewallError(ALREADY_ENABLED, module)
        settings[4].append(module)
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_SERVICE, in_signature='s')
    @dbus_handle_exceptions
    def removeModule(self, module, sender=None):
        module = dbus_to_python(module, str)
        log.debug1("config.service.%d.removeModule('%s')", self.id, module)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if module not in settings[4]:
            raise FirewallError(NOT_ENABLED, module)
        settings[4].remove(module)
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_SERVICE, in_signature='s',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryModule(self, module, sender=None):
        module = dbus_to_python(module, str)
        log.debug1("config.service.%d.queryModule('%s')", self.id, module)
        return module in self.getSettings()[4]

    # destination

    @dbus_service_method(DBUS_INTERFACE_CONFIG_SERVICE, out_signature='a{ss}')
    @dbus_handle_exceptions
    def getDestinations(self, sender=None):
        log.debug1("config.service.%d.getDestinations()", self.id)
        return self.getSettings()[5]

    @dbus_service_method(DBUS_INTERFACE_CONFIG_SERVICE, in_signature='a{ss}')
    @dbus_handle_exceptions
    def setDestinations(self, destinations, sender=None):
        destinations = dbus_to_python(destinations, dict)
        log.debug1("config.service.%d.setDestinations({ipv4:'%s', ipv6:'%s'})",
                   self.id, destinations.get('ipv4'), destinations.get('ipv6'))
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[5] = destinations
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_SERVICE, in_signature='s',
                         out_signature='s')
    @dbus_handle_exceptions
    def getDestination(self, family, sender=None):
        family = dbus_to_python(family, str)
        log.debug1("config.service.%d.getDestination('%s')", self.id,
                   family)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if family not in settings[5]:
            raise FirewallError(NOT_ENABLED, family)
        return settings[5][family]

    @dbus_service_method(DBUS_INTERFACE_CONFIG_SERVICE, in_signature='ss')
    @dbus_handle_exceptions
    def setDestination(self, family, address, sender=None):
        family = dbus_to_python(family, str)
        address = dbus_to_python(address, str)
        log.debug1("config.service.%d.setDestination('%s', '%s')", self.id,
                   family, address)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if family in settings[5]:
            raise FirewallError(ALREADY_ENABLED, family)
        settings[5][family] = address
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_SERVICE, in_signature='s')
    @dbus_handle_exceptions
    def removeDestination(self, family, sender=None):
        family = dbus_to_python(family, str)
        log.debug1("config.service.%d.removeDestination('%s')", self.id,
                   family)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if family not in settings[5]:
            raise FirewallError(NOT_ENABLED, family)
        settings[5].remove(family)
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_SERVICE, in_signature='ss',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryDestination(self, family, address, sender=None):
        family = dbus_to_python(family, str)
        address = dbus_to_python(address, str)
        log.debug1("config.service.%d.queryDestination('%s', '%s')", self.id,
                   family, address)
        settings = self.getSettings()
        return (family in settings[5] and
                address == settings[5][family])
