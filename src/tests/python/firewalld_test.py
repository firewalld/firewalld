#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2010-2012 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>
# Jiri Popelka <jpopelka@redhat.com>
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
import unittest

from firewall.config.dbus import DBUS_PATH, DBUS_INTERFACE, \
                                 DBUS_INTERFACE_ZONE
from firewall.dbus_utils import dbus_to_python
from pprint import pprint

class TestFirewallD(unittest.TestCase):
    """
    For testing of temporary changes, ie. those that disappear with restart:
    adding/removing interfaces to zones, setting/changing of default zone
    adding/removing of services, ports, forward ports, icmp blocks
    """
    def setUp(self):
        unittest.TestCase.setUp(self)
        bus = dbus.SystemBus()
        dbus_obj = bus.get_object(DBUS_INTERFACE, DBUS_PATH)
        self.fw = dbus.Interface(dbus_obj, dbus_interface=DBUS_INTERFACE)
        self.fw_zone = dbus.Interface(dbus_obj,
                                     dbus_interface=DBUS_INTERFACE_ZONE)

    def test_get_setDefaultZone(self):
        old_zone = dbus_to_python(self.fw.getDefaultZone())
        print ("\nCurrent default zone is '%s'" % old_zone)

        self.fw_zone.addInterface("", "foo")
        self.fw_zone.addInterface(old_zone, "bar")

        print ("Setting default zone to 'external'")
        self.fw.setDefaultZone("external")

        # make sure the default zone was properly set
        self.assertEqual(self.fw.getDefaultZone(), "external")
        # check that *only* foo interface was moved to new default zone
        self.assertTrue(self.fw_zone.queryInterface("external", "foo"))
        self.assertTrue(self.fw_zone.queryInterface(old_zone, "bar"))

        print ("Re-setting default zone back to '%s'" % old_zone)
        self.fw.setDefaultZone(old_zone)
        self.fw_zone.removeInterface("", "foo")
        self.fw_zone.removeInterface("", "bar")

    def test_zone_getActiveZones(self):
        interface = "baz"
        zone = "home"

        print ("\nAdding interface '%s' to '%s' zone" % (interface, zone))
        self.fw_zone.addInterface(zone, interface)

        print ("Getting active zones: ")
        ret = self.fw_zone.getActiveZones()
        self.assertTrue(len(ret)>0)
        pprint (dbus_to_python(ret))

        self.fw_zone.removeInterface(zone, interface) #cleanup

    def test_zone_getZones(self):
        z = self.fw_zone.getZones()
        print ("\nZones:")
        pprint(dbus_to_python(z))

    def test_zone_add_remove_queryInterface(self):
        interface = "foo"
        zone = "trusted"

        print ("\nAdding interface '%s' to '%s' zone" % (interface, zone))
        ret = self.fw_zone.addInterface(zone, interface)
        self.assertEqual(ret, zone)
        self.assertTrue(self.fw_zone.queryInterface(zone, interface))

        print ("Re-adding")
        self.assertRaisesRegexp(Exception, 'ZONE_ALREADY_SET', self.fw_zone.addInterface, zone, interface)

        zone = "block"
        print ("Re-adding interface '%s' to '%s' zone" % (interface, zone))
        self.assertRaisesRegexp(Exception, 'ZONE_CONFLICT', self.fw_zone.addInterface, zone, interface)

        print ("Removing interface '%s' from '%s' zone" % (interface, zone))
        self.assertRaisesRegexp(Exception, 'ZONE_CONFLICT', self.fw_zone.removeInterface, zone, interface)

        zone = "trusted"
        print ("Removing interface '%s' from '%s' zone" % (interface, zone))
        ret = self.fw_zone.removeInterface(zone, interface)
        self.assertEqual(ret, zone)
        self.assertFalse(self.fw_zone.queryInterface(zone, interface))
        print ("Re-removing")
        self.assertRaises(Exception, self.fw_zone.removeInterface, zone, interface)

        print ("Add again and remove interface '%s' from zone it belongs to" % interface)
        self.fw_zone.addInterface(zone, interface)
        self.assertTrue(self.fw_zone.queryInterface(zone, interface))
        ret = self.fw_zone.removeInterface("", interface)
        self.assertEqual(ret, zone)
        self.assertFalse(self.fw_zone.queryInterface(zone, interface))
        print ("Re-removing")
        self.assertRaises(Exception, self.fw_zone.removeInterface, "", interface)

    def test_zone_change_queryZone(self):
        interface = "foo"
        zone = "internal"

        print ("\nChanging zone of interface '%s' to '%s'" % (interface, zone))
        ret = self.fw_zone.changeZone(zone, interface)
        self.assertEqual(ret, zone)
        self.assertTrue(self.fw_zone.queryInterface(zone, interface))

        print ("Get zone of interface '%s': " % (interface))
        ret = self.fw_zone.getZoneOfInterface(interface)
        self.assertEqual(ret, zone)
        print (dbus_to_python(ret))

        self.fw_zone.removeInterface(zone, interface) #cleanup

    def test_zone_add_get_query_removeService(self):
        service = "samba"
        zone = "external"
        print ("\nAdding service '%s' to '%s' zone" % (service, zone))
        ret = self.fw_zone.addService(zone, service, 0)
        self.assertEqual(ret, zone)
        print ("Re-adding")
        self.assertRaisesRegexp(Exception, 'ALREADY_ENABLED', self.fw_zone.addService, zone, service, 0)

        print ("Get services of zone '%s'" % (zone))
        ret = self.fw_zone.getServices(zone)
        self.assertTrue(len(ret)>0)
        pprint (dbus_to_python(ret))

        print ("Removing service '%s' from '%s' zone" % (service, zone))
        ret = self.fw_zone.removeService(zone, service)
        self.assertEqual(ret, zone)
        print ("Re-removing")
        self.assertRaisesRegexp(Exception, 'NOT_ENABLED', self.fw_zone.removeService, zone, service)

        zone = "dmz"
        timeout = 2
        print ("Adding timed service '%s' to '%s' zone, active for %d seconds" % (service, zone, timeout))
        ret = self.fw_zone.addService(zone, service, timeout)
        self.assertEqual(ret, zone)
        self.assertTrue(self.fw_zone.queryService(zone, service))
        time.sleep(timeout+1)
        print ("Checking if timeout has been working")
        self.assertFalse(self.fw_zone.queryService(zone, service))

    def test_zone_add_get_query_removePort(self):
        port = "443"
        protocol="tcp"
        zone = "public"
        print ("\nAdding port '%s/%s' to '%s' zone" % (port, protocol, zone))
        ret = self.fw_zone.addPort(zone, port, protocol, 0)
        self.assertEqual(ret, zone)
        print ("Re-adding port")
        self.assertRaisesRegexp(Exception, 'ALREADY_ENABLED', self.fw_zone.addPort, zone, port, protocol, 0)

        print ("Get ports of zone '%s': " % (zone))
        ret = self.fw_zone.getPorts(zone)
        self.assertTrue(len(ret)>0)
        pprint (dbus_to_python(ret))

        print ("Removing port '%s/%s' from '%s' zone" % (port, protocol, zone))
        ret = self.fw_zone.removePort(zone, port, protocol)
        self.assertEqual(ret, zone)
        print ("Re-removing")
        self.assertRaisesRegexp(Exception, 'NOT_ENABLED', self.fw_zone.removePort, zone, port, protocol)

        port = "443-445"
        protocol="udp"
        zone = "dmz"
        timeout = 2
        print ("Adding timed port '%s/%s' to '%s' zone, active for %d seconds" % (port, protocol, zone, timeout))
        ret = self.fw_zone.addPort(zone, port, protocol, timeout)
        self.assertEqual(ret, zone)
        self.assertTrue(self.fw_zone.queryPort(zone, port, protocol))
        time.sleep(timeout+1)
        print ("Checking if timeout has been working")
        self.assertFalse(self.fw_zone.queryPort(zone, port, protocol))

    def test_zone_add_query_removeMasquerade(self):
        zone = "public"
        print ("\nAdd masquerade to '%s' zone" % (zone))
        ret = self.fw_zone.addMasquerade(zone, 0)
        self.assertEqual(ret, zone)
        print ("Re-adding")
        self.assertRaisesRegexp(Exception, 'ALREADY_ENABLED', self.fw_zone.addMasquerade, zone, 0)

        print ("Checking if masquerade is added to zone '%s'" % (zone))
        self.assertTrue(self.fw_zone.queryMasquerade(zone))

        print ("Remove masquerade from '%s' zone" % (zone))
        ret = self.fw_zone.removeMasquerade(zone)
        self.assertEqual(ret, zone)
        print ("Re-adding")
        self.assertRaisesRegexp(Exception, 'NOT_ENABLED', self.fw_zone.removeMasquerade, zone)

        zone = "dmz"
        timeout = 2
        print ("Add timed masquerade to '%s' zone, active for %d seconds" % (zone, timeout))
        ret = self.fw_zone.addMasquerade(zone, timeout)
        self.assertEqual(ret, zone)
        self.assertTrue(self.fw_zone.queryMasquerade(zone))
        time.sleep(timeout+1)
        print ("Checking if timeout has been working")
        self.assertFalse(self.fw_zone.queryMasquerade(zone))

    def test_zone_add_get_query_removeForwardPort(self):
        port = "443"
        protocol="tcp"
        toport = "441"
        toaddr = "192.168.0.2"
        zone = "public"
        print ("\nAdding forward port '%s/%s' to '%s:%s' to '%s' zone" % (port, protocol, toaddr, toport, zone))
        ret = self.fw_zone.addForwardPort(zone, port, protocol, toport, toaddr, 0)
        self.assertEqual(ret, zone)
        print ("Re-adding")
        self.assertRaisesRegexp(Exception, 'ALREADY_ENABLED', self.fw_zone.addForwardPort, zone, port, protocol, toport, toaddr, 0)

        print ("Get forward ports of zone '%s': " % (zone))
        ret = self.fw_zone.getForwardPorts(zone)
        self.assertTrue(len(ret)>0)
        pprint (dbus_to_python(ret))

        print ("Removing forward port '%s/%s' to '%s:%s' from '%s' zone" % (port, protocol, toaddr, toport, zone))
        ret = self.fw_zone.removeForwardPort(zone, port, protocol, toport, toaddr)
        self.assertEqual(ret, zone)
        print ("Re-removing")
        self.assertRaisesRegexp(Exception, 'NOT_ENABLED', self.fw_zone.removeForwardPort, zone, port, protocol, toport, toaddr)

        port = "443-445"
        protocol="udp"
        toport = ""
        toaddr = "192.168.0.3"
        zone = "dmz"
        timeout = 2
        print ("Adding timed forward port '%s/%s' to '%s:%s' to '%s' zone, active for %d seconds" % (port, protocol, toaddr, toport, zone, timeout))
        ret = self.fw_zone.addForwardPort(zone, port, protocol, toport, toaddr, timeout)
        self.assertEqual(ret, zone)
        self.assertTrue(self.fw_zone.queryForwardPort(zone, port, protocol, toport, toaddr))
        time.sleep(timeout+1)
        print ("Checking if timeout has been working")
        self.assertFalse(self.fw_zone.queryForwardPort(zone, port, protocol, toport, toaddr))

    def test_zone_add_get_query_removeIcmpBlock(self):
        icmp = "parameter-problem"
        zone = "external"
        print ("\nAdding icmp block '%s' to '%s' zone" % (icmp, zone))
        ret = self.fw_zone.addIcmpBlock(zone, icmp, 0)
        self.assertEqual(ret, zone)
        print ("Re-adding")
        self.assertRaisesRegexp(Exception, 'ALREADY_ENABLED', self.fw_zone.addIcmpBlock, zone, icmp, 0)

        print ("Get icmp blocks of zone '%s': " % (zone))
        ret = self.fw_zone.getIcmpBlocks(zone)
        self.assertTrue(len(ret)>0)
        pprint (dbus_to_python(ret))

        print ("Removing icmp block '%s' from '%s' zone" % (icmp, zone))
        ret = self.fw_zone.removeIcmpBlock(zone, icmp)
        self.assertEqual(ret, zone)
        print ("Re-removing")
        self.assertRaisesRegexp(Exception, 'NOT_ENABLED', self.fw_zone.removeIcmpBlock, zone, icmp)

        icmp = "redirect"
        zone = "dmz"
        timeout = 2
        print ("Adding timed icmp block '%s' to '%s' zone, active for %d seconds: " % (icmp, zone, timeout))
        ret = self.fw_zone.addIcmpBlock(zone, icmp, timeout)
        self.assertEqual(ret, zone)
        self.assertTrue(self.fw_zone.queryIcmpBlock(zone, icmp))
        time.sleep(timeout+1)
        print ("Checking if timeout has been working: ")
        self.assertFalse(self.fw_zone.queryIcmpBlock(zone, icmp))

    def test_reload(self):
        interface = "foo"
        zone = "work"

        self.fw_zone.addInterface(zone, interface)
        self.fw.reload()
        print ("\nChecking if interface remains in zone after service reload: ")
        self.assertTrue(self.fw_zone.queryInterface(zone, interface))

        self.fw_zone.removeInterface(zone, interface) #cleanup

if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(TestFirewallD)
    results = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if results.wasSuccessful() else 1)
