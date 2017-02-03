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

    active_connections = nm_get_client().get_active_connections()

    for active_con in active_connections:
        if active_con.get_id() == connection:
            con = active_con.get_connection()
            if con is None:
                continue
            setting_con = con.get_setting_connection()
            if setting_con is None:
                continue
            zone = setting_con.get_zone()
            if zone is None:
                zone = ""
            return zone

    return None

def nm_set_zone_of_connection(zone, connection):
    """Set the zone for a connection
    @param zone name
    @param connection name
    @return True if zone was set, else False
    """
    check_nm_imported()

    active_connections = nm_get_client().get_active_connections()

    for active_con in active_connections:
        con = active_con.get_connection()
        if con is None:
            continue

        if active_con.get_id() == connection:
            setting_con = con.get_setting_connection()
            if setting_con is None:
                continue
            if zone == "":
                zone = None
            setting_con.set_property("zone", zone)
            con.commit_changes(True, None)
            return True

    return False

def nm_get_connections(connections, connections_uuid):
    """Get active connections from NM
    @param connections return dict
    @param connections_uuid return dict
    """

    connections.clear()
    connections_uuid.clear()

    check_nm_imported()

    active_connections = nm_get_client().get_active_connections()

    for active_con in active_connections:
        # ignore vpn devices for now
        if active_con.get_vpn():
            continue

        name = active_con.get_id()
        uuid = active_con.get_uuid()
        devices = active_con.get_devices()

        connections_uuid[name] = uuid
        for dev in devices:
            connections[dev.get_iface()] = name

def nm_get_connection_of_interface(interface):
    """Get connection from NM that is using the interface
    @param interface name
    @returns connection that is using interface or None
    """
    check_nm_imported()

    active_connections = nm_get_client().get_active_connections()

    for active_con in active_connections:
        # ignore vpn devices for now
        if active_con.get_vpn():
            continue

        devices = active_con.get_devices()

        for dev in devices:
            if dev.get_iface() == interface:
                return active_con.get_id()


    return None

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
