# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Red Hat, Inc.
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
from firewall.core.io.ipset import IPSet
from firewall.core.ipset import IPSET_TYPES
from firewall.core.logger import log
from firewall.server.decorators import *
from firewall.errors import *

############################################################################
#
# class FirewallDConfigIPSet
#
############################################################################

class FirewallDConfigIPSet(slip.dbus.service.Object):
    """FirewallD main class"""

    persistent = True
    """ Make FirewallD persistent. """
    default_polkit_auth_required = PK_ACTION_CONFIG
    """ Use PK_ACTION_INFO as a default """

    @handle_exceptions
    def __init__(self, parent, config, ipset, id, *args, **kwargs):
        super(FirewallDConfigIPSet, self).__init__(*args, **kwargs)
        self.parent = parent
        self.config = config
        self.obj = ipset
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
        log.debug1("config.ipset.%d.Get('%s', '%s')", self.id,
                   interface_name, property_name)

        if interface_name != DBUS_INTERFACE_CONFIG_IPSET:
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
            return self.config.is_builtin_ipset(self.obj)
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
        log.debug1("config.ipset.%d.GetAll('%s')", self.id, interface_name)

        if interface_name != DBUS_INTERFACE_CONFIG_IPSET:
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
        log.debug1("config.ipset.%d.Set('%s', '%s', '%s')", self.id,
                   interface_name, property_name, new_value)
        self.parent.accessCheck(sender)

        if interface_name != DBUS_INTERFACE_CONFIG_IPSET:
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

    @dbus_service_method(DBUS_INTERFACE_CONFIG_IPSET, out_signature=IPSet.DBUS_SIGNATURE)
    @dbus_handle_exceptions
    def getSettings(self, sender=None):
        """get settings for ipset
        """
        log.debug1("config.ipset.%d.getSettings()", self.id)
        return self.config.get_ipset_config(self.obj)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_IPSET, in_signature=IPSet.DBUS_SIGNATURE)
    @dbus_handle_exceptions
    def update(self, settings, sender=None):
        """update settings for ipset
        """
        settings = dbus_to_python(settings)
        log.debug1("config.ipset.%d.update('...')", self.id)
        self.parent.accessCheck(sender)
        self.obj = self.config.set_ipset_config(self.obj, settings)
        self.Updated(self.obj.name)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_IPSET)
    @dbus_handle_exceptions
    def loadDefaults(self, sender=None):
        """load default settings for builtin ipset
        """
        log.debug1("config.ipset.%d.loadDefaults()", self.id)
        self.parent.accessCheck(sender)
        self.obj = self.config.load_ipset_defaults(self.obj)
        self.Updated(self.obj.name)

    @dbus.service.signal(DBUS_INTERFACE_CONFIG_IPSET, signature='s')
    @dbus_handle_exceptions
    def Updated(self, name):
        log.debug1("config.ipset.%d.Updated('%s')" % (self.id, name))

    # R E M O V E

    @dbus_service_method(DBUS_INTERFACE_CONFIG_IPSET)
    @dbus_handle_exceptions
    def remove(self, sender=None):
        """remove ipset
        """
        log.debug1("config.ipset.%d.remove()", self.id)
        self.parent.accessCheck(sender)
        self.config.remove_ipset(self.obj)
        self.parent.removeIPSet(self.obj)

    @dbus.service.signal(DBUS_INTERFACE_CONFIG_IPSET, signature='s')
    @dbus_handle_exceptions
    def Removed(self, name):
        log.debug1("config.ipset.%d.Removed('%s')" % (self.id, name))

    # R E N A M E

    @dbus_service_method(DBUS_INTERFACE_CONFIG_IPSET, in_signature='s')
    @dbus_handle_exceptions
    def rename(self, name, sender=None):
        """rename ipset
        """
        name = dbus_to_python(name, str)
        log.debug1("config.ipset.%d.rename('%s')", self.id, name)
        self.parent.accessCheck(sender)
        self.obj = self.config.rename_ipset(self.obj, name)
        self.Renamed(name)

    @dbus.service.signal(DBUS_INTERFACE_CONFIG_IPSET, signature='s')
    @dbus_handle_exceptions
    def Renamed(self, name):
        log.debug1("config.ipset.%d.Renamed('%s')" % (self.id, name))

    # version

    @dbus_service_method(DBUS_INTERFACE_CONFIG_IPSET, out_signature='s')
    @dbus_handle_exceptions
    def getVersion(self, sender=None):
        log.debug1("config.ipset.%d.getVersion()", self.id)
        return self.getSettings()[0]

    @dbus_service_method(DBUS_INTERFACE_CONFIG_IPSET, in_signature='s')
    @dbus_handle_exceptions
    def setVersion(self, version, sender=None):
        version = dbus_to_python(version, str)
        log.debug1("config.ipset.%d.setVersion('%s')", self.id, version)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[0] = version
        self.update(settings)

    # short

    @dbus_service_method(DBUS_INTERFACE_CONFIG_IPSET, out_signature='s')
    @dbus_handle_exceptions
    def getShort(self, sender=None):
        log.debug1("config.ipset.%d.getShort()", self.id)
        return self.getSettings()[1]

    @dbus_service_method(DBUS_INTERFACE_CONFIG_IPSET, in_signature='s')
    @dbus_handle_exceptions
    def setShort(self, short, sender=None):
        short = dbus_to_python(short, str)
        log.debug1("config.ipset.%d.setShort('%s')", self.id, short)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[1] = short
        self.update(settings)

    # description

    @dbus_service_method(DBUS_INTERFACE_CONFIG_IPSET, out_signature='s')
    @dbus_handle_exceptions
    def getDescription(self, sender=None):
        log.debug1("config.ipset.%d.getDescription()", self.id)
        return self.getSettings()[2]

    @dbus_service_method(DBUS_INTERFACE_CONFIG_IPSET, in_signature='s')
    @dbus_handle_exceptions
    def setDescription(self, description, sender=None):
        description = dbus_to_python(description, str)
        log.debug1("config.ipset.%d.setDescription('%s')", self.id,
                   description)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[2] = description
        self.update(settings)

    # type

    @dbus_service_method(DBUS_INTERFACE_CONFIG_IPSET, out_signature='s')
    @dbus_handle_exceptions
    def getType(self, sender=None):
        log.debug1("config.ipset.%d.getType()", self.id)
        return self.getSettings()[3]

    @dbus_service_method(DBUS_INTERFACE_CONFIG_IPSET, in_signature='s')
    @dbus_handle_exceptions
    def setType(self, ipset_type, sender=None):
        ipset_type = dbus_to_python(ipset_type, str)
        log.debug1("config.ipset.%d.setType('%s')", self.id, ipset_type)
        self.parent.accessCheck(sender)
        if ipset_type not in IPSET_TYPES:
            raise FirewallError(INVALID_TYPE, ipset_type)
        settings = list(self.getSettings())
        settings[3] = ipset_type
        self.update(settings)

    # options

    @dbus_service_method(DBUS_INTERFACE_CONFIG_IPSET, out_signature='a{ss}')
    @dbus_handle_exceptions
    def getOptions(self, sender=None):
        log.debug1("config.ipset.%d.getOptions()", self.id)
        return self.getSettings()[4]

    @dbus_service_method(DBUS_INTERFACE_CONFIG_IPSET, in_signature='a{ss}')
    @dbus_handle_exceptions
    def setOptions(self, options, sender=None):
        options = dbus_to_python(options, dict)
        log.debug1("config.ipset.%d.setOptions('[%s]')", self.id,
                   repr(options))
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[4] = options
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_IPSET, in_signature='ss')
    @dbus_handle_exceptions
    def addOption(self, key, value, sender=None):
        key = dbus_to_python(key, str)
        value = dbus_to_python(value, str)
        log.debug1("config.ipset.%d.addOption('%s', '%s')", self.id, key, value)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if key in settings[4] and settings[4][key] == value:
            raise FirewallError(ALREADY_ENABLED, "'%s': '%s'" % (key, value))
        settings[4][key] = value
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_IPSET, in_signature='s')
    @dbus_handle_exceptions
    def removeOption(self, key, sender=None):
        key = dbus_to_python(key, str)
        log.debug1("config.ipset.%d.removeOption('%s')", self.id, key)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if key not in settings[4]:
            raise FirewallError(NOT_ENABLED, key)
        del settings[4][key]
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_IPSET, in_signature='ss',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryOption(self, key, value, sender=None):
        key = dbus_to_python(key, str)
        value = dbus_to_python(value, str)
        log.debug1("config.ipset.%d.queryOption('%s', '%s')", self.id, key,
                   value)
        settings = list(self.getSettings())
        return (key in settings[4] and settings[4][key] == value)

    # entries

    @dbus_service_method(DBUS_INTERFACE_CONFIG_IPSET, out_signature='as')
    @dbus_handle_exceptions
    def getEntries(self, sender=None):
        log.debug1("config.ipset.%d.getEntries()", self.id)
        return self.getSettings()[5]

    @dbus_service_method(DBUS_INTERFACE_CONFIG_IPSET, in_signature='as')
    @dbus_handle_exceptions
    def setEntries(self, entries, sender=None):
        entries = dbus_to_python(entries, list)
        log.debug1("config.ipset.%d.setEntries('[%s]')", self.id,
                   ",".join(entries))
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        settings[5] = entries
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_IPSET, in_signature='s')
    @dbus_handle_exceptions
    def addEntry(self, entry, sender=None):
        entry = dbus_to_python(entry, str)
        log.debug1("config.ipset.%d.addEntry('%s')", self.id, entry)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if entry in settings[5]:
            raise FirewallError(ALREADY_ENABLED, entry)
        settings[5].append(entry)
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_IPSET, in_signature='s')
    @dbus_handle_exceptions
    def removeEntry(self, entry, sender=None):
        entry = dbus_to_python(entry, str)
        log.debug1("config.ipset.%d.removeEntry('%s')", self.id, entry)
        self.parent.accessCheck(sender)
        settings = list(self.getSettings())
        if entry not in settings[5]:
            raise FirewallError(NOT_ENABLED, entry)
        settings[5].remove(entry)
        self.update(settings)

    @dbus_service_method(DBUS_INTERFACE_CONFIG_IPSET, in_signature='s',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryEntry(self, entry, sender=None):
        entry = dbus_to_python(entry, str)
        log.debug1("config.ipset.%d.queryEntry('%s')", self.id, entry)
        return entry in self.getSettings()[5]
