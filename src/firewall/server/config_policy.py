# -*- coding: utf-8 -*-
#
# SPDX-License-Identifier: GPL-2.0-or-later

import dbus
import dbus.service

from firewall import config
from firewall.dbus_utils import dbus_to_python, \
    dbus_introspection_prepare_properties, \
    dbus_introspection_add_properties
from firewall.core.logger import log
from firewall.server.dbus import DbusServiceObject
from firewall.server.decorators import handle_exceptions, \
    dbus_handle_exceptions, dbus_service_method, \
    dbus_polkit_require_auth

class FirewallDConfigPolicy(DbusServiceObject):
    persistent = True
    default_polkit_auth_required = config.dbus.PK_ACTION_CONFIG

    @handle_exceptions
    def __init__(self, parent, conf, policy, item_id, *args, **kwargs):
        super(FirewallDConfigPolicy, self).__init__(*args, **kwargs)
        self.parent = parent
        self.config = conf
        self.obj = policy
        self.item_id = item_id
        self.busname = args[0]
        self.path = args[1]
        self._log_prefix = "config.policy.%d" % self.item_id
        dbus_introspection_prepare_properties(
            self, config.dbus.DBUS_INTERFACE_CONFIG_POLICY)

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
    def Get(self, interface_name, property_name, sender=None):
        # get a property
        interface_name = dbus_to_python(interface_name, str)
        property_name = dbus_to_python(property_name, str)
        log.debug1("%s.Get('%s', '%s')", self._log_prefix,
                   interface_name, property_name)

        if interface_name != config.dbus.DBUS_INTERFACE_CONFIG_POLICY:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.UnknownInterface: "
                "Interface '%s' does not exist" % interface_name)

        return self._get_property(property_name)

    @dbus_service_method(dbus.PROPERTIES_IFACE, in_signature='s',
                         out_signature='a{sv}')
    @dbus_handle_exceptions
    def GetAll(self, interface_name, sender=None):
        interface_name = dbus_to_python(interface_name, str)
        log.debug1("%s.GetAll('%s')", self._log_prefix, interface_name)

        if interface_name != config.dbus.DBUS_INTERFACE_CONFIG_POLICY:
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

        if interface_name != config.dbus.DBUS_INTERFACE_CONFIG_POLICY:
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
    def Introspect(self, sender=None):
        log.debug2("%s.Introspect()", self._log_prefix)

        data = super(FirewallDConfigPolicy, self).Introspect(
            self.path, self.busname.get_bus())

        return dbus_introspection_add_properties(
            self, data, config.dbus.DBUS_INTERFACE_CONFIG_POLICY)

    # S E T T I N G S

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_POLICY,
                         out_signature="a{sv}")
    @dbus_handle_exceptions
    def getSettings(self, sender=None):
        """get settings for policy
        """
        log.debug1("%s.getSettings()", self._log_prefix)
        settings = self.config.get_policy_object_config_dict(self.obj)
        return settings

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_POLICY,
                         in_signature="a{sv}")
    @dbus_handle_exceptions
    def update(self, settings, sender=None):
        """update settings for policy
        """
        settings = dbus_to_python(settings)
        log.debug1("%s.update('...')", self._log_prefix)
        self.parent.accessCheck(sender)
        self.obj = self.config.set_policy_object_config_dict(self.obj, settings)
        self.Updated(self.obj.name)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_POLICY)
    @dbus_handle_exceptions
    def loadDefaults(self, sender=None):
        """load default settings for builtin policy
        """
        log.debug1("%s.loadDefaults()", self._log_prefix)
        self.parent.accessCheck(sender)
        self.obj = self.config.load_policy_object_defaults(self.obj)
        self.Updated(self.obj.name)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_CONFIG_POLICY, signature='s')
    @dbus_handle_exceptions
    def Updated(self, name):
        log.debug1("%s.Updated('%s')" % (self._log_prefix, name))

    # R E M O V E

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_POLICY)
    @dbus_handle_exceptions
    def remove(self, sender=None):
        """remove policy
        """
        log.debug1("%s.removePolicy()", self._log_prefix)
        self.parent.accessCheck(sender)
        self.config.remove_policy_object(self.obj)
        self.parent.removePolicy(self.obj)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_CONFIG_POLICY, signature='s')
    @dbus_handle_exceptions
    def Removed(self, name):
        log.debug1("%s.Removed('%s')" % (self._log_prefix, name))

    # R E N A M E

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_POLICY,
                         in_signature='s')
    @dbus_handle_exceptions
    def rename(self, name, sender=None):
        """rename policy
        """
        name = dbus_to_python(name, str)
        log.debug1("%s.rename('%s')", self._log_prefix, name)
        self.parent.accessCheck(sender)
        self.obj = self.config.rename_policy_object(self.obj, name)
        self.Renamed(name)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_CONFIG_POLICY, signature='s')
    @dbus_handle_exceptions
    def Renamed(self, name):
        log.debug1("%s.Renamed('%s')" % (self._log_prefix, name))
