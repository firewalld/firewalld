#!/usr/bin/python
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

__all__ = [ "NetworkManager", "check_nm_imported", "nm_is_imported",
            "nm_get_zone_of_connection", "nm_set_zone_for_connection",
            "nm_get_connections" ]

import dbus

import gi
try:
    gi.require_version('NetworkManager', '1.0')
except ValueError:
    _nm_imported = False
else:
    try:
        from gi.repository import NetworkManager
        _nm_imported = True
    except ImportError, ValueError:
        NetworkManager = None
        _nm_imported = False

from firewall.core.logger import log
from firewall.dbus_utils import dbus_to_python
from firewall import errors
from firewall.errors import FirewallError

def check_nm_imported():
    """Check function to raise a MISSING_IMPORT error if the import of NetworkManager failed
    """
    if not _nm_imported:
        raise FirewallError(errors.MISSING_IMPORT,
                            "gi.repository.NetworkManager = 1.0")

def nm_is_imported():
    """Returns true if NetworkManager has been properly imported
    @return True if import was successful, False otherwirse
    """
    return _nm_imported

def nm_get_zone_of_connection(connection):
    """Get zone of connection from NetworkManager
    @param connection name
    @return zone string setting of connection, empty string if not set, None if connection is unknown
    """
    check_nm_imported()

    bus = dbus.SystemBus()

    nm_obj = bus.get_object(NetworkManager.DBUS_INTERFACE,
                            NetworkManager.DBUS_PATH)
    nm_props = dbus.Interface(nm_obj, dbus_interface=dbus.PROPERTIES_IFACE)
    active_connections = nm_props.Get(NetworkManager.DBUS_INTERFACE,
                                      "ActiveConnections")

    for active in active_connections:
        active_obj = bus.get_object(NetworkManager.DBUS_INTERFACE, active)
        active_props = dbus.Interface(active_obj,
                                      dbus_interface=dbus.PROPERTIES_IFACE)
        nm_connection = active_props.Get(
            NetworkManager.DBUS_INTERFACE+".Connection.Active",
            "Connection")

        # get settings for connection
        nm_connection_obj = bus.get_object(NetworkManager.DBUS_INTERFACE,
                                           nm_connection)
        nm_connection_iface = dbus.Interface(
            nm_connection_obj,
            dbus_interface=NetworkManager.DBUS_INTERFACE+\
            ".Settings.Connection")
        settings = nm_connection_iface.GetSettings()

        if settings["connection"]["id"] == connection:
            zone = settings["connection"]["zone"]
            if zone is None:
                zone = ""
            return zone

    return None

def nm_set_zone_for_connection(zone, connection):
    """Set the zone for a connection
    @param zone name
    @param connection name
    @return True if zone was set, else False
    """
    check_nm_imported()

    bus = dbus.SystemBus()

    nm_obj = bus.get_object(NetworkManager.DBUS_INTERFACE,
                            NetworkManager.DBUS_PATH)
    nm_props = dbus.Interface(nm_obj, dbus_interface=dbus.PROPERTIES_IFACE)
    active_connections = nm_props.Get(NetworkManager.DBUS_INTERFACE,
                                      "ActiveConnections")

    for active in active_connections:
        active_obj = bus.get_object(NetworkManager.DBUS_INTERFACE, active)
        active_props = dbus.Interface(active_obj,
                                      dbus_interface=dbus.PROPERTIES_IFACE)
        nm_connection = active_props.Get(
            NetworkManager.DBUS_INTERFACE+".Connection.Active",
            "Connection")

        # get settings for connection
        nm_connection_obj = bus.get_object(NetworkManager.DBUS_INTERFACE,
                                           nm_connection)
        nm_connection_iface = dbus.Interface(
            nm_connection_obj,
            dbus_interface=NetworkManager.DBUS_INTERFACE+\
            ".Settings.Connection")
        settings = nm_connection_iface.GetSettings()

        if settings["connection"]["id"] == connection:
            settings["connection"]["zone"] = zone
            nm_connection_iface.Update(settings)
            return True

    return False

def nm_get_connections(connections, connections_uuid):
    """Get active connections from NetworkManager
    @param connections return dict
    @param connections_uuid return dict
    """

    connections.clear()
    connections_uuid.clear()

    check_nm_imported()

    bus = dbus.SystemBus()

    # get active connections
    nm_obj = bus.get_object(NetworkManager.DBUS_INTERFACE,
                            NetworkManager.DBUS_PATH)
    nm_props = dbus.Interface(nm_obj, dbus_interface=dbus.PROPERTIES_IFACE)
    nm_active_connections = dbus_to_python(nm_props.Get(
        NetworkManager.DBUS_INTERFACE, "ActiveConnections"))

    # for all active connections:
    for active in nm_active_connections:
        # get connection and devices from active connection
        active_obj = bus.get_object(NetworkManager.DBUS_INTERFACE, active)
        active_props = dbus.Interface(active_obj,
                                      dbus_interface=dbus.PROPERTIES_IFACE)
        active_connection = dbus_to_python(active_props.Get(
            NetworkManager.DBUS_INTERFACE+".Connection.Active",
            "Connection"))
        active_devices = dbus_to_python(active_props.Get(
            NetworkManager.DBUS_INTERFACE+".Connection.Active",
            "Devices"))

        # get name (id) from connection
        settings_obj = bus.get_object(NetworkManager.DBUS_INTERFACE,
                                      active_connection)
        settings_iface = dbus.Interface(
            settings_obj,
            dbus_interface=NetworkManager.DBUS_INTERFACE+\
            ".Settings.Connection")
        settings = dbus_to_python(settings_iface.GetSettings())
        name = settings["connection"]["id"]
        connections_uuid[name] = settings["connection"]["uuid"]

        # for all devices:
        for device in active_devices:
            device_obj = bus.get_object(NetworkManager.DBUS_INTERFACE,
                                        device)
            device_props = dbus.Interface(
                device_obj, dbus_interface=dbus.PROPERTIES_IFACE)
            # get interface from device (first try: IpInterface)
            device_iface = dbus_to_python(device_props.Get(
                NetworkManager.DBUS_INTERFACE+".Device", "IpInterface"))
            if device_iface == "":
                device_iface = dbus_to_python(device_props.Get(
                    NetworkManager.DBUS_INTERFACE+".Device",
                    "Interface"))
            connections[device_iface] = name
