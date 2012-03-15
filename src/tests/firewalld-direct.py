#!/usr/bin/python
#
# Copyright (C) 2012 Red Hat, Inc.
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

#print("FirewallD Info")
#print properties.Get(DBUS_INTERFACE, "version")
#print properties.Get(DBUS_INTERFACE, "interface_version")
#print properties.Get(DBUS_INTERFACE, "state")

print "chains:", dbus_to_python(fw_direct.getChains("ipv4", "filter"))

try:
    fw_direct.addChain("ipv4", "filter", "direct_foo1")
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")

try:
    fw_direct.addChain("ipv4", "filter", "direct_foo2")
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")

try:
    fw_direct.removeChain("ipv4", "filter", "direct_foo1")
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")


#fw_direct.addChain("ipv4", "filter", "direct_foo2")
#fw_direct.getChains("ipv4", "filter")


try:
    fw_direct.addRule("ipv4", "filter", "direct_foo2", 0, [ "-m", "tcp", "-p", "tcp", "--dport", "332", "-j", "ACCEPT" ])
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")

try:
    fw_direct.addRule("ipv4", "filter", "direct_foo2", 0, [ "-m", "tcp", "-p", "tcp", "--dport", "333", "-j", "ACCEPT" ])
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")

try:
    fw_direct.addRule("ipv4", "filter", "direct_foo2", 1, [ "-m", "tcp", "-p", "tcp", "--dport", "334", "-j", "ACCEPT" ])
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")

try:
    fw_direct.addRule("ipv4", "filter", "direct_foo2", -5, [ "-m", "tcp", "-p", "tcp", "--dport", "331", "-j", "ACCEPT" ])
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")

try:
    fw_direct.addRule("ipv4", "filter", "direct_foo2", -10, [ "-m", "tcp", "-p", "tcp", "--dport", "330", "-j", "ACCEPT" ])
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")

try:
    fw_direct.addRule("ipv4", "filter", "direct_foo2", -5, [ "-m", "udp", "-p", "udp", "--dport", "331", "-j", "ACCEPT" ])
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")

try:
    fw_direct.removeRule("ipv4", "filter", "direct_foo2", [ "-m", "udp", "-p", "udp", "--dport", "331", "-j", "ACCEPT" ])
except Exception, msg:
    print("FAILED: %s" % msg)
else:
    print("OK")


fw_direct.passthrough("ipv4", [ "-t", "filter", "-N", "foobar" ])
#fw_direct.passthrough("ipv4", [ "-t", "filter", "-L" ])

fw.reload()
