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
        interface_name = dbus_to_python(interface_name)
        property_name = dbus_to_python(property_name)
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
            return self.config.is_builtin_zone(self.obj)
        else:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.AccessDenied: "
                "Property '%s' isn't exported (or may not exist)" % \
                    property_name)

    @dbus_service_method(dbus.PROPERTIES_IFACE, in_signature='s',
                         out_signature='a{sv}')
    @dbus_handle_exceptions
    def GetAll(self, interface_name, sender=None):
        interface_name = dbus_to_python(interface_name)
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
        interface_name = dbus_to_python(interface_name)
        property_name = dbus_to_python(property_name)
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
        return self.config.get_zone_config(self.obj)

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
                raise FirewallError(ZONE_CONFLICT)    # or move to new zone ?
        for source in added_sources:
            if self.parent.getZoneOfSource(source):
                raise FirewallError(ZONE_CONFLICT)    # or move to new zone ?

    @dbus_service_method(DBUS_INTERFACE_CONFIG_ZONE, in_signature=Zone.DBUS_SIGNATURE)
    @dbus_handle_exceptions
    def update(self, settings, sender=None):
        """update settings for zone
        """
        settings = dbus_to_python(settings)
        log.debug1("config.zone.%d.update('...')", self.id)
        self.parent.accessCheck(sender)
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
        name = dbus_to_python(name)
        log.debug1("config.zone.%d.rename('%s')", self.id, name)
        self.parent.accessCheck(sender)
        new_zone = self.config.rename_zone(self.obj, name)
        self.parent._addZone(new_zone)
        self.parent.removeZone(self.obj)
        self.Renamed(name)

    @dbus.service.signal(DBUS_INTERFACE_CONFIG_ZONE, signature='s')
    @dbus_handle_exceptions
    def Renamed(self, name):
        log.debug1("config.zone.%d.Renamed('%s')" % (self.id, name))
