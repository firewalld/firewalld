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
from firewall.core.io.helper import Helper
from firewall.core.logger import log
from firewall.server.dbus import DbusServiceObject
from firewall.server.decorators import handle_exceptions, \
    dbus_handle_exceptions, dbus_service_method, \
    dbus_polkit_require_auth
from firewall import errors
from firewall.errors import FirewallError

############################################################################
#
# class FirewallDConfig
#
############################################################################

class FirewallDConfigHelper(DbusServiceObject):
    """FirewallD main class"""

    persistent = True
    """ Make FirewallD persistent. """
    default_polkit_auth_required = config.dbus.PK_ACTION_CONFIG
    """ Use PK_ACTION_INFO as a default """

    @handle_exceptions
    def __init__(self, parent, conf, helper, item_id, *args, **kwargs):
        super(FirewallDConfigHelper, self).__init__(*args, **kwargs)
        self.parent = parent
        self.config = conf
        self.obj = helper
        self.item_id = item_id
        self.busname = args[0]
        self.path = args[1]
        self._log_prefix = "config.helper.%d" % self.item_id
        dbus_introspection_prepare_properties(
            self, config.dbus.DBUS_INTERFACE_CONFIG_HELPER)

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

        if interface_name != config.dbus.DBUS_INTERFACE_CONFIG_HELPER:
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

        if interface_name != config.dbus.DBUS_INTERFACE_CONFIG_HELPER:
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

        if interface_name != config.dbus.DBUS_INTERFACE_CONFIG_HELPER:
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

        data = super(FirewallDConfigHelper, self).Introspect(
            self.path, self.busname.get_bus())

        return dbus_introspection_add_properties(
            self, data, config.dbus.DBUS_INTERFACE_CONFIG_HELPER)

    # S E T T I N G S

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_HELPER,
                         out_signature=Helper.DBUS_SIGNATURE)
    @dbus_handle_exceptions
    def getSettings(self, sender=None): # pylint: disable=W0613
        """get settings for helper
        """
        log.debug1("%s.getSettings()", self._log_prefix)
        return self.config.get_helper_config(self.obj)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_HELPER,
                         in_signature=Helper.DBUS_SIGNATURE)
    @dbus_handle_exceptions
    def update(self, settings, sender=None):
        """update settings for helper
        """
        settings = dbus_to_python(settings)
        log.debug1("%s.update('...')", self._log_prefix)
        self.parent.accessCheck(sender)
        self.obj = self.config.set_helper_config(self.obj, settings)
        self.Updated(self.obj.name)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_HELPER)
    @dbus_handle_exceptions
    def loadDefaults(self, sender=None):
        """load default settings for builtin helper
        """
        log.debug1("%s.loadDefaults()", self._log_prefix)
        self.parent.accessCheck(sender)
        self.obj = self.config.load_helper_defaults(self.obj)
        self.Updated(self.obj.name)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_CONFIG_HELPER,
                         signature='s')
    @dbus_handle_exceptions
    def Updated(self, name):
        log.debug1("%s.Updated('%s')" % (self._log_prefix, name))

    # R E M O V E

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_HELPER)
    @dbus_handle_exceptions
    def remove(self, sender=None):
        """remove helper
        """
        log.debug1("%s.removeHelper()", self._log_prefix)
        self.parent.accessCheck(sender)
        self.config.remove_helper(self.obj)
        self.parent.removeHelper(self.obj)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_CONFIG_HELPER,
                         signature='s')
    @dbus_handle_exceptions
    def Removed(self, name):
        log.debug1("%s.Removed('%s')" % (self._log_prefix, name))

    # R E N A M E

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_HELPER,
                         in_signature='s')
    @dbus_handle_exceptions
    def rename(self, name, sender=None):
        """rename helper
        """
        name = dbus_to_python(name, str)
        log.debug1("%s.rename('%s')", self._log_prefix, name)
        self.parent.accessCheck(sender)
        self.obj = self.config.rename_helper(self.obj, name)
        self.Renamed(name)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_CONFIG_HELPER,
                         signature='s')
    @dbus_handle_exceptions
    def Renamed(self, name):
        log.debug1("%s.Renamed('%s')" % (self._log_prefix, name))

    # version

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_HELPER,
                         out_signature='s')
    @dbus_handle_exceptions
    def getVersion(self, sender=None): # pylint: disable=W0613
        log.debug1("%s.getVersion()", self._log_prefix)
        return self.getSettings()[0]

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_HELPER,
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

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_HELPER,
                         out_signature='s')
    @dbus_handle_exceptions
    def getShort(self, sender=None): # pylint: disable=W0613
        log.debug1("%s.getShort()", self._log_prefix)
        return self.getSettings()[1]

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_HELPER,
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

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_HELPER,
                         out_signature='s')
    @dbus_handle_exceptions
    def getDescription(self, sender=None): # pylint: disable=W0613
        log.debug1("%s.getDescription()", self._log_prefix)
        return self.getSettings()[2]

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_HELPER,
                         in_signature='s')
    @dbus_handle_exceptions
    def setDescription(self, description, sender=None):
        description = dbus_to_python(description, str)
        log.debug1("%s.setDescription('%s')", self._log_prefix,
                   description)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[2] = description
        self.update(settings)

    # family

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_HELPER,
                         out_signature='s')
    @dbus_handle_exceptions
    def getFamily(self, sender=None):
        log.debug1("%s.getFamily()", self._log_prefix)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        return settings[3]

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_HELPER,
                         in_signature='s')
    @dbus_handle_exceptions
    def setFamily(self, ipv, sender=None):
        ipv = dbus_to_python(ipv, str)
        log.debug1("%s.setFamily('%s')", self._log_prefix, ipv)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if settings[3] == ipv:
            raise FirewallError(errors.ALREADY_ENABLED, "'%s'" % ipv)
        settings[3] = ipv
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_HELPER,
                         in_signature='s', out_signature='b')
    @dbus_handle_exceptions
    def queryFamily(self, ipv, sender=None): # pylint: disable=W0613
        ipv = dbus_to_python(ipv, str)
        log.debug1("%s.queryFamily('%s')", self._log_prefix, ipv)
        settings = self.getSettings()
        return (settings[3] == ipv)

    # module

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_HELPER,
                         out_signature='s')
    @dbus_handle_exceptions
    def getModule(self, sender=None):
        log.debug1("%s.getModule()", self._log_prefix)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        return settings[4]

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_HELPER,
                         in_signature='s')
    @dbus_handle_exceptions
    def setModule(self, module, sender=None):
        module = dbus_to_python(module, str)
        log.debug1("%s.setModule('%s')", self._log_prefix, module)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if settings[4] == module:
            raise FirewallError(errors.ALREADY_ENABLED, "'%s'" % module)
        settings[4] = module
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_HELPER,
                         in_signature='s', out_signature='b')
    @dbus_handle_exceptions
    def queryModule(self, module, sender=None): # pylint: disable=W0613
        module = dbus_to_python(module, str)
        log.debug1("%s.queryModule('%s')", self._log_prefix, module)
        settings = self.getSettings()
        return (settings[4] == module)

    # port

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_HELPER,
                         out_signature='a(ss)')
    @dbus_handle_exceptions
    def getPorts(self, sender=None): # pylint: disable=W0613
        log.debug1("%s.getPorts()", self._log_prefix)
        return self.getSettings()[5]

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_HELPER,
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
        settings[5] = ports
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_HELPER,
                         in_signature='ss')
    @dbus_handle_exceptions
    def addPort(self, port, protocol, sender=None):
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        log.debug1("%s.addPort('%s', '%s')", self._log_prefix, port,
                   protocol)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if (port,protocol) in settings[5]:
            raise FirewallError(errors.ALREADY_ENABLED,
                                "%s:%s" % (port, protocol))
        settings[5].append((port,protocol))
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_HELPER,
                         in_signature='ss')
    @dbus_handle_exceptions
    def removePort(self, port, protocol, sender=None):
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        log.debug1("%s.removePort('%s', '%s')", self._log_prefix, port,
                   protocol)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if (port,protocol) not in settings[5]:
            raise FirewallError(errors.NOT_ENABLED, "%s:%s" % (port, protocol))
        settings[5].remove((port,protocol))
        self.update(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_HELPER,
                         in_signature='ss', out_signature='b')
    @dbus_handle_exceptions
    def queryPort(self, port, protocol, sender=None): # pylint: disable=W0613
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        log.debug1("%s.queryPort('%s', '%s')", self._log_prefix, port,
                   protocol)
        return (port,protocol) in self.getSettings()[5]
