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

"""Functions for NetworkManager interaction"""

__all__ = [ "check_nm_imported", "nm_is_imported",
            "nm_get_zone_of_connection", "nm_set_zone_of_connection",
            "nm_get_connections", "nm_get_connection_of_interface",
            "nm_get_bus_name", "nm_get_dbus_interface" ]

import gi
from gi.repository import GLib
try:
    gi.require_version('NM', '1.0')
except ValueError:
    _nm_imported = False
else:
    try:
        from gi.repository import NM
        _nm_imported = True
    except (ImportError, ValueError, GLib.Error):
        _nm_imported = False
_nm_client = None

from firewall import errors
from firewall.errors import FirewallError
from firewall.core.logger import log
import dbus

def check_nm_imported():
    """Check function to raise a MISSING_IMPORT error if the import of NM failed
    """
    if not _nm_imported:
        raise FirewallError(errors.MISSING_IMPORT, "gi.repository.NM = 1.0")

def nm_is_imported():
    """Returns true if NM has been properly imported
    @return True if import was successful, False otherwirse
    """
    return _nm_imported

def nm_get_client():
    """Returns the NM client object or None if the import of NM failed
    @return NM.Client instance if import was successful, None otherwise
    """
    global _nm_client
    if not _nm_client:
        _nm_client = NM.Client.new(None)
    return _nm_client

def nm_get_zone_of_connection(connection):
    """Get zone of connection from NM
    @param connection name
    @return zone string setting of connection, empty string if not set, None if connection is unknown
    """
    check_nm_imported()

    con = nm_get_client().get_connection_by_uuid(connection)
    if con is None:
        return None

    setting_con = con.get_setting_connection()
    if setting_con is None:
        return None

    try:
        if con.get_flags() & (NM.SettingsConnectionFlags.NM_GENERATED
                              | NM.SettingsConnectionFlags.NM_VOLATILE):
            return ""
    except AttributeError:
        # Prior to NetworkManager 1.12, we can only guess
        # that a connection was generated/volatile.
        if con.get_unsaved():
            return ""

    zone = setting_con.get_zone()
    if zone is None:
        zone = ""
    return zone

def nm_set_zone_of_connection(zone, connection):
    """Set the zone for a connection
    @param zone name
    @param connection name
    @return True if zone was set, else False
    """
    check_nm_imported()

    con = nm_get_client().get_connection_by_uuid(connection)
    if con is None:
        return False

    setting_con = con.get_setting_connection()
    if setting_con is None:
        return False

    if zone == "":
        zone = None
    setting_con.set_property("zone", zone)
    return con.commit_changes(True, None)

def nm_get_connections(connections, connections_name):
    """Get active connections from NM
    @param connections return dict
    @param connections_name return dict
    """

    connections.clear()
    connections_name.clear()

    check_nm_imported()

    active_connections = nm_get_client().get_active_connections()

    for active_con in active_connections:
        # ignore vpn devices for now
        if active_con.get_vpn():
            continue

        name = active_con.get_id()
        uuid = active_con.get_uuid()
        devices = active_con.get_devices()

        connections_name[uuid] = name
        for dev in devices:
            ip_iface = dev.get_ip_iface()
            if ip_iface:
                connections[ip_iface] = uuid

def nm_get_interfaces():
    """Get active interfaces from NM
    @returns list of interface names
    """

    check_nm_imported()

    active_interfaces = []

    for active_con in nm_get_client().get_active_connections():
        # ignore vpn devices for now
        if active_con.get_vpn():
            continue

        try:
            con = active_con.get_connection()
            if con.get_flags() & (NM.SettingsConnectionFlags.NM_GENERATED
                                  | NM.SettingsConnectionFlags.NM_VOLATILE):
                continue
        except AttributeError:
            # Prior to NetworkManager 1.12, we can only guess
            # that a connection was generated/volatile.
            if con.get_unsaved():
                continue

        for dev in active_con.get_devices():
            ip_iface = dev.get_ip_iface()
            if ip_iface:
                active_interfaces.append(ip_iface)

    return active_interfaces

def nm_get_interfaces_in_zone(zone):
    interfaces = []
    for interface in nm_get_interfaces():
        conn = nm_get_connection_of_interface(interface)
        if zone == nm_get_zone_of_connection(conn):
            interfaces.append(interface)

    return interfaces

def nm_get_connection_of_interface(interface):
    """Get connection from NM that is using the interface
    @param interface name
    @returns connection that is using interface or None
    """
    check_nm_imported()

    device = nm_get_client().get_device_by_iface(interface)
    if device is None:
        return None

    active_con = device.get_active_connection()
    if active_con is None:
        return None

    try:
        con = active_con.get_connection()
        if con.get_flags() & NM.SettingsConnectionFlags.NM_GENERATED:
            return None
    except AttributeError:
        # Prior to NetworkManager 1.12, we can only guess
        # that a connection was generated.
        if con.get_unsaved():
            return None

    return active_con.get_uuid()

def nm_get_bus_name():
    if not _nm_imported:
        return None
    try:
        bus = dbus.SystemBus()
        obj = bus.get_object(NM.DBUS_INTERFACE, NM.DBUS_PATH)
        name = obj.bus_name
        del obj, bus
        return name
    except Exception:
        log.debug2("Failed to get bus name of NetworkManager")
    return None

def nm_get_dbus_interface():
    if not _nm_imported:
        return ""
    return NM.DBUS_INTERFACE
