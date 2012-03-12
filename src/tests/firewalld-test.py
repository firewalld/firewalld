#!/usr/bin/python
#
# Copyright (C) 2010-2012 Red Hat, Inc.
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

# To use in git tree: PYTHONPATH=.. python firewalld-test.py

import dbus
import sys
import time

from firewall.config import *
from firewall.config.dbus import *
from firewall.dbus_utils import dbus_to_python

bus = dbus.SystemBus()
dbus_obj = bus.get_object(DBUS_INTERFACE, DBUS_PATH)
fw = dbus.Interface(dbus_obj, dbus_interface=DBUS_INTERFACE)
fw_zone = dbus.Interface(dbus_obj, dbus_interface=DBUS_INTERFACE_ZONE)
fw_direct = dbus.Interface(dbus_obj, dbus_interface=DBUS_INTERFACE_DIRECT)

properties = dbus.Interface(dbus_obj,
                            dbus_interface='org.freedesktop.DBus.Properties')

print("FirewallD Info")

print properties.Get(DBUS_INTERFACE, "version")
print properties.Get(DBUS_INTERFACE, "interface_version")
print properties.Get(DBUS_INTERFACE, "state")

print("\nActive Zones")

try:
    active_zones = fw_zone.getActiveZones()
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    for zone in active_zones:
        print("Zone '%s' active for interface '%s'" % \
                  (zone, "','".join(active_zones[zone])))

print("\nDefault Zones")

zone = fw.getDefaultZone()
print("Current zone: '%s'" % zone)
sys.stdout.write("Setting to 'external': ")
try:
    fw.setDefaultZone("external")
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")

sys.stdout.write("Resetting default zone back to '%s': " % zone)
try:
    fw.setDefaultZone(zone)
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")


print("\nHandling Zones")
sys.stdout.write("Get zones: ")
try:
    z = fw_zone.getZones()
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("'%s'" % ','.join(z))

interface = "foo"
zone = "public"
sys.stdout.write("Adding interface '%s' to '%s' zone: " % (interface, zone))
try:
    fw_zone.addInterface(zone, interface)
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")

sys.stdout.write("Checking if interface '%s' has been added to '%s' zone: " % (interface, zone))
if fw_zone.queryInterface(zone, interface):
    print("YES")
else:
    print("NO")

sys.stdout.write("Get zone of interface '%s': " % (interface))
try:
    z = fw_zone.getZoneOfInterface(interface)
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("'%s'" % z)

sys.stdout.write("Get active zones: ")
try:
    z = fw_zone.getActiveZones()
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("'%s'" % ','.join(z))

sys.stdout.write("Removing interface '%s' from '%s' zone: " % (interface, zone))
try:
    fw_zone.removeInterface(zone, interface)
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")

sys.stdout.write("Get active zones: ")
try:
    z = fw_zone.getActiveZones()
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("'%s'" % ','.join(z))


print("\nHandling Services")
service = "samba"
zone = "external"
sys.stdout.write("Adding service '%s' to '%s' zone: " % (service, zone))
try:
    fw_zone.addService(zone, service, 0)
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")

sys.stdout.write("Get services of zone '%s': " % (zone))
try:
    z = fw_zone.getServices(zone)
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("'%s'" % ','.join(z))

sys.stdout.write("Removing service '%s' from '%s' zone: " % (service, zone))
try:
    fw_zone.removeService(zone, service)
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")

print("")

service = "samba"
zone = "dmz"
timeout = 5
sys.stdout.write("Adding timed service '%s' to '%s' zone, active for %d seconds: " % (service, zone, timeout))
try:
    fw_zone.addService(zone, service, timeout)
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")

time.sleep(timeout+1)
sys.stdout.write("Checking if timeout has been working: ")
if fw_zone.queryService(zone, service):
    print("NO")
else:
    print("YES")


print("\nHandling Ports")
port = "443"
protocol="tcp"
zone = "public"
sys.stdout.write("Adding port '%s/%s' to '%s' zone: " % (port, protocol, zone))
try:
    fw_zone.addPort(zone, port, protocol, 0)
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")

sys.stdout.write("Get ports of zone '%s': " % (zone))
try:
    z = fw_zone.getPorts(zone)
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("'%s'" % dbus_to_python(z))

sys.stdout.write("Removing port '%s/%s' from '%s' zone: " % (port, protocol, zone))
try:
    fw_zone.removePort(zone, port, protocol)
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")

print("")

port = "443-445"
protocol="udp"
zone = "dmz"
timeout = 5
sys.stdout.write("Adding timed port '%s/%s' to '%s' zone, active for %d seconds: " % (port, protocol, zone, timeout))
try:
    fw_zone.addPort(zone, port, protocol, timeout)
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")

time.sleep(timeout+1)
sys.stdout.write("Checking if timeout has been working: ")
if fw_zone.queryPort(zone, port, protocol):
    print("NO")
else:
    print("YES")


print("\nHandling Masquerade")
zone = "public"
sys.stdout.write("Enabling masquerade for '%s' zone: " % (zone))
try:
    fw_zone.enableMasquerade(zone, 0)
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")

sys.stdout.write("Checking if masquerade is enabled for zone '%s': " % (zone))
if fw_zone.queryMasquerade(zone):
    print("YES")
else:
    print("NO")
    
sys.stdout.write("Disabling masquerade for '%s' zone: " % (zone))
try:
    fw_zone.disableMasquerade(zone)
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")

print("")

zone = "dmz"
timeout = 5
sys.stdout.write("Enabling timed masquerade for '%s' zone, active for %d seconds: " % (zone, timeout))
try:
    fw_zone.enableMasquerade(zone, timeout)
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")

time.sleep(timeout+1)
sys.stdout.write("Checking if timeout has been working: ")
if fw_zone.queryMasquerade(zone):
    print("NO")
else:
    print("YES")


print("\nHandling Forward Ports")
port = "443"
protocol="tcp"
toport = "441"
toaddr = "192.168.0.2"
zone = "public"
sys.stdout.write("Adding forward port '%s/%s' to '%s:%s' to '%s' zone: " % (port, protocol, toaddr, toport, zone))
try:
    fw_zone.addForwardPort(zone, port, protocol, toport, toaddr, 0)
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")

sys.stdout.write("Get forward ports of zone '%s': " % (zone))
try:
    z = fw_zone.getForwardPorts(zone)
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("'%s'" % dbus_to_python(z))

sys.stdout.write("Removing forward port '%s/%s' to '%s:%s' from '%s' zone: " % (port, protocol, toaddr, toport, zone))
try:
    fw_zone.removeForwardPort(zone, port, protocol, toport, toaddr)
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")

print("")

port = "443-445"
protocol="udp"
toport = ""
toaddr = "192.168.0.3"
zone = "dmz"
timeout = 5
sys.stdout.write("Adding timed forward port '%s/%s' to '%s:%s' to '%s' zone, active for %d seconds: " % (port, protocol, toaddr, toport, zone, timeout))
try:
    fw_zone.addForwardPort(zone, port, protocol, toport, toaddr, timeout)
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")

time.sleep(timeout+1)
sys.stdout.write("Checking if timeout has been working: ")
if fw_zone.queryForwardPort(zone, port, protocol, toport, toaddr):
    print("NO")
else:
    print("YES")


print("\nHandling IcmpType")
icmp = "parameter-problem"
zone = "external"
sys.stdout.write("Adding icmp block '%s' to '%s' zone: " % (icmp, zone))
try:
    fw_zone.addIcmpBlock(zone, icmp, 0)
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")

sys.stdout.write("Get icmp blocks of zone '%s': " % (zone))
try:
    z = fw_zone.getIcmpBlocks(zone)
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("'%s'" % ','.join(z))

sys.stdout.write("Removing icmp block '%s' from '%s' zone: " % (icmp, zone))
try:
    fw_zone.removeIcmpBlock(zone, icmp)
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")

print("")

icmp = "redirect"
zone = "dmz"
timeout = 5
sys.stdout.write("Adding timed icmp block '%s' to '%s' zone, active for %d seconds: " % (icmp, zone, timeout))
try:
    fw_zone.addIcmpBlock(zone, icmp, timeout)
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")

time.sleep(timeout+1)
sys.stdout.write("Checking if timeout has been working: ")
if fw_zone.queryIcmpBlock(zone, icmp):
    print("NO")
else:
    print("YES")


print("Reloading Firewall")
fw.reload()

#print("Restarting Firewall")
#fw.restart()
