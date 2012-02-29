#
# Copyright (C) 2009 ,2010 Red Hat, Inc.
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

import dbus.mainloop.glib
import slip.dbus
from dbus.exceptions import DBusException
from firewall.config import *
from firewall.config.dbus import *
from firewall.dbus_utils import dbus_to_python
import dbus

#

class FirewallClient(object):
    def __init__(self, bus=None):
        if not bus:
            try:
                self.bus = slip.dbus.SystemBus()
                self.bus.default_timeout = None
            except:
                print("Not using slip")
                self.bus = dbus.SystemBus()
        else:
            self.bus = bus
        self.dbus_obj = self.bus.get_object(DBUS_INTERFACE, DBUS_PATH)
        self.fw = dbus.Interface(self.dbus_obj, dbus_interface=DBUS_INTERFACE)
        self.fw_zone = dbus.Interface(self.dbus_obj,
                                      dbus_interface=DBUS_INTERFACE_ZONE)
        self.fw_direct = dbus.Interface(self.dbus_obj,
                                        dbus_interface=DBUS_INTERFACE_DIRECT)
        self.fw_properties = dbus.Interface(
            self.dbus_obj, dbus_interface='org.freedesktop.DBus.Properties')

    @slip.dbus.polkit.enable_proxy
    def reload(self):
        self.fw.reload()

    @slip.dbus.polkit.enable_proxy
    def complete_reload(self):
        self.fw.completeReload()

    @slip.dbus.polkit.enable_proxy
    def get_property(self, prop):
        return self.fw_properties.Get(DBUS_INTERFACE, prop)

    @slip.dbus.polkit.enable_proxy
    def get_properties(self, prop):
        return self.fw_properties.GetAll(DBUS_INTERFACE)

    @slip.dbus.polkit.enable_proxy
    def set_property(self, prop, value):
        return self.fw_properties.Set(DBUS_INTERFACE, prop, value)

    # panic mode

    @slip.dbus.polkit.enable_proxy
    def enablePanicMode(self):
        self.fw.enablePanicMode()
    
    @slip.dbus.polkit.enable_proxy
    def disablePanicMode(self):
        self.fw.disablePanicMode()

    @slip.dbus.polkit.enable_proxy
    def queryPanicMode(self):
        return self.fw.queryPanicMode()

    # default zone

    @slip.dbus.polkit.enable_proxy
    def getDefaultZone(self):
        return dbus_to_python(self.fw.getDefaultZone())

    @slip.dbus.polkit.enable_proxy
    def setDefaultZone(self, zone):
        return dbus_to_python(self.fw.setDefaultZone(zone))

    # zone

    @slip.dbus.polkit.enable_proxy
    def getZones(self):
        return dbus_to_python(self.fw_zone.getZones())

    @slip.dbus.polkit.enable_proxy
    def getActiveZones(self):
        return dbus_to_python(self.fw_zone.getActiveZones())

    @slip.dbus.polkit.enable_proxy
    def getZoneOfInterface(self, interface):
        return dbus_to_python(self.fw_zone.getZoneOfInterface(interface))

    # interfaces

    @slip.dbus.polkit.enable_proxy
    def addInterface(self, zone, interface):
        return dbus_to_python(self.fw_zone.addInterface(zone, interface))

    @slip.dbus.polkit.enable_proxy
    def changeZone(self, zone, interface):
        return dbus_to_python(self.fw_zone.changeZone(zone, interface))

    @slip.dbus.polkit.enable_proxy
    def getInterfaces(self, zone):
        return dbus_to_python(self.fw_zone.getInterfaces(zone))

    @slip.dbus.polkit.enable_proxy
    def queryInterface(self, zone, interface):
        return dbus_to_python(self.fw_zone.queryInterface(zone, interface))

    @slip.dbus.polkit.enable_proxy
    def removeInterface(self, zone, interface):
        return dbus_to_python(self.fw_zone.removeInterface(zone, interface))

    # services

    @slip.dbus.polkit.enable_proxy
    def addService(self, zone, service, timeout=0):
        return dbus_to_python(self.fw_zone.addService(zone, service, timeout))

    @slip.dbus.polkit.enable_proxy
    def getServices(self, zone):
        return dbus_to_python(self.fw_zone.getServices(zone))

    @slip.dbus.polkit.enable_proxy
    def queryService(self, zone, service):
        return dbus_to_python(self.fw_zone.queryService(zone, service))

    @slip.dbus.polkit.enable_proxy
    def removeService(self, zone, service):
        return dbus_to_python(self.fw_zone.removeService(zone, service))

    # ports

    @slip.dbus.polkit.enable_proxy
    def addPort(self, zone, port, protocol, timeout=0):
        return dbus_to_python(self.fw_zone.addPort(zone, port, protocol, timeout))

    @slip.dbus.polkit.enable_proxy
    def getPorts(self, zone):
        return dbus_to_python(self.fw_zone.getPorts(zone))

    @slip.dbus.polkit.enable_proxy
    def queryPort(self, zone, port, protocol):
        return dbus_to_python(self.fw_zone.queryPort(zone, port, protocol))

    @slip.dbus.polkit.enable_proxy
    def removePort(self, zone, port, protocol):
        return dbus_to_python(self.fw_zone.removePort(zone, port, protocol))

    # masquerade

    @slip.dbus.polkit.enable_proxy
    def enableMasquerade(self, zone, timeout=0):
        return dbus_to_python(self.fw_zone.enableMasquerade(zone, timeout))

    @slip.dbus.polkit.enable_proxy
    def queryMasquerade(self, zone):
        return dbus_to_python(self.fw_zone.queryMasquerade(zone))

    @slip.dbus.polkit.enable_proxy
    def disableMasquerade(self, zone):
        return dbus_to_python(self.fw_zone.disableMasquerade(zone))

    # forward ports

    @slip.dbus.polkit.enable_proxy
    def addForwardPort(self, zone, port, protocol, toport, toaddr,
                       timeout=0):
        if not toport:
            toport = ""
        if not toaddr:
            toaddr = ""
        return dbus_to_python(self.fw_zone.addForwardPort(zone, port, protocol,
                                                          toport, toaddr,
                                                          timeout))

    @slip.dbus.polkit.enable_proxy
    def getForwardPorts(self, zone):
        return dbus_to_python(self.fw_zone.getForwardPorts(zone))

    @slip.dbus.polkit.enable_proxy
    def queryForwardPort(self, zone, port, protocol, toport, toaddr):
        if not toport:
            toport = ""
        if not toaddr:
            toaddr = ""
        return dbus_to_python(self.fw_zone.queryForwardPort(zone,
                                                            port, protocol,
                                                            toport, toaddr))

    @slip.dbus.polkit.enable_proxy
    def removeForwardPort(self, zone, port, protocol, toport, toaddr):
        if not toport:
            toport = ""
        if not toaddr:
            toaddr = ""
        return dbus_to_python(self.fw_zone.removeForwardPort(zone,
                                                             port, protocol,
                                                             toport, toaddr))

    # icmpblock

    @slip.dbus.polkit.enable_proxy
    def addIcmpBlock(self, zone, icmp, timeout=0):
        return dbus_to_python(self.fw_zone.addIcmpBlock(zone, icmp, timeout))

    @slip.dbus.polkit.enable_proxy
    def getIcmpBlocks(self, zone):
        return dbus_to_python(self.fw_zone.getIcmpBlocks(zone))

    @slip.dbus.polkit.enable_proxy
    def queryIcmpBlock(self, zone, icmp):
        return dbus_to_python(self.fw_zone.queryIcmpBlock(zone, icmp))

    @slip.dbus.polkit.enable_proxy
    def removeIcmpBlock(self, zone, icmp):
        return dbus_to_python(self.fw_zone.removeIcmpBlock(zone, icmp))
