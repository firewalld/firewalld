#!/usr/bin/python
#
# Copyright (C) 2010-2012 Red Hat, Inc.
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

import unittest
import time
import firewall
from firewall.client import FirewallClient, FirewallClientConfigZoneSettings
from firewall.core.base import DEFAULT_ZONE_TARGET

class TestFirewallDInterfaceConfig(unittest.TestCase):
    """
    For testing of persistent changes, ie. those that survive restart:
    """
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.fw = FirewallClient()

    def tearDown(self):
        unittest.TestCase.tearDown(self)

    def test_zones(self):
        """
        /org/fedoraproject/FirewallD1/config
            listZones()
            getZoneByName(String name)
            addZone(String name, Dict of {String, Variant} zone_settings)
        /org/fedoraproject/FirewallD1/config/zone/<id>
           getSettings()
           loadDefaults()
           update()
           rename()
           remove()
        """

        print ("\nChecking what zones we have")
        self.assertRaisesRegexp(Exception, 'INVALID_ZONE', self.fw.config().getZoneByName, "dummyname")

        zone_version = "1.0"
        zone_short = "Testing"
        zone_description = "this is just a testing zone"
        zone_immutable = False
        zone_target = DEFAULT_ZONE_TARGET
        zone_services = ["dhcpv6-client", "ssh"]
        zone_ports = [("123", "tcp"), ("666-667", "udp")]
        zone_icmpblocks = ["redirect", "echo-reply"]
        zone_masquerade = False
        zone_forward_ports = [("443", "tcp", "441", "192.168.0.2"), ("123", "udp", "321", "192.168.1.1")]
        settings = FirewallClientConfigZoneSettings()
        settings.setVersion(zone_version)
        settings.setShort(zone_short)
        settings.setDescription(zone_description)
        settings.setImmutable(zone_immutable)
        settings.setTarget(zone_target)
        settings.setServices(zone_services)
        settings.setPorts(zone_ports)
        settings.setIcmpBlocks(zone_icmpblocks)
        settings.setMasquerade(zone_masquerade)
        settings.setForwardPorts(zone_forward_ports)

        print ("Adding some malformed zones")
        print ("Adding zone with name that already exists")
        self.assertRaisesRegexp(Exception, 'NAME_CONFLICT', self.fw.config().addZone, "home", settings)
        print ("Adding zone with empty name")
        self.assertRaisesRegexp(Exception, 'INVALID_NAME', self.fw.config().addZone, "", settings)
        zone_name = "test"
        print ("Adding proper zone")
        self.fw.config().addZone (zone_name, settings)

        print ("Checking the saved (persistent) settings")
        config_zone = self.fw.config().getZoneByName(zone_name)
        self.assertIsInstance(config_zone, firewall.client.FirewallClientConfigZone)
        zone_settings = config_zone.getSettings()
        self.assertIsInstance(zone_settings, firewall.client.FirewallClientConfigZoneSettings)
        self.assertEquals(zone_settings.getVersion(), zone_version)
        self.assertEquals(zone_settings.getShort(), zone_short)
        self.assertEquals(zone_settings.getDescription(), zone_description)
        self.assertEquals(zone_settings.getImmutable(), zone_immutable)
        self.assertEquals(zone_settings.getTarget(), zone_target)
        self.assertEquals(zone_settings.getServices().sort(), zone_services.sort())
        self.assertEquals(zone_settings.getPorts().sort(), zone_ports.sort())
        self.assertEquals(zone_settings.getIcmpBlocks().sort(), zone_icmpblocks.sort())
        self.assertEquals(zone_settings.getMasquerade(), zone_masquerade)
        self.assertEquals(zone_settings.getForwardPorts().sort(), zone_forward_ports.sort())

        print ("Updating settings")
        zone_services.append("mdns")
        zone_settings.setServices(zone_services)
        config_zone.update(zone_settings)

        print ("Reloading firewalld")
        self.fw.reload()

        print ("Checking of runtime settings")
        self.assertTrue(zone_name in self.fw.getZones())
        self.assertEquals(self.fw.getServices(zone_name).sort(), zone_services.sort())
        self.assertEquals(self.fw.getPorts(zone_name).sort(), zone_ports.sort())
        self.assertEquals(self.fw.getIcmpBlocks(zone_name).sort(), zone_icmpblocks.sort())
        self.assertEquals(self.fw.queryMasquerade(zone_name), zone_masquerade)
        self.assertEquals(self.fw.getForwardPorts(zone_name).sort(), zone_forward_ports.sort())

        print ("Renaming zone to name that already exists")
        config_zone = self.fw.config().getZoneByName(zone_name)
        self.assertRaisesRegexp(Exception, 'NAME_CONFLICT', config_zone.rename, "home")
        new_zone_name = "renamed"
        print ("Renaming zone '%s' to '%s'" % (zone_name, new_zone_name))
        config_zone.rename(new_zone_name)
        #self.fw.reload() # to new_zone_name become accessible and zone_name stop being accessible
        print ("Checking whether the zone '%s' is accessible (it shouldn't be)" % zone_name)
        self.assertRaisesRegexp(Exception, 'INVALID_ZONE', self.fw.config().getZoneByName, zone_name)
        print ("Checking whether the zone '%s' is accessible" % new_zone_name)
        config_zone = self.fw.config().getZoneByName(new_zone_name)
        zone_settings = config_zone.getSettings()
        self.assertEquals(zone_settings.getVersion(), zone_version)
        self.assertEquals(zone_settings.getShort(), zone_short)
        self.assertEquals(zone_settings.getDescription(), zone_description)
        self.assertEquals(zone_settings.getImmutable(), zone_immutable)
        self.assertEquals(zone_settings.getTarget(), zone_target)
        self.assertEquals(zone_settings.getServices().sort(), zone_services.sort())
        self.assertEquals(zone_settings.getPorts().sort(), zone_ports.sort())
        self.assertEquals(zone_settings.getIcmpBlocks().sort(), zone_icmpblocks.sort())
        self.assertEquals(zone_settings.getMasquerade(), zone_masquerade)
        self.assertEquals(zone_settings.getForwardPorts().sort(), zone_forward_ports.sort())

        print ("Removing the zone '%s'" % new_zone_name)
        config_zone.remove()
        print ("Checking whether the removed zone is accessible (it shouldn't be)")
        self.assertRaisesRegexp(Exception, 'INVALID_ZONE', self.fw.config().getZoneByName, new_zone_name)

        # TODO test loadDefaults() ?

    def test_services(self):
        """
        /org/fedoraproject/FirewallD1/config
            listServices()
            getServiceByName(String name)
            addService(String name, Dict of {String, Variant} settings)
            
        /org/fedoraproject/FirewallD1/config/service/<id>
           getSettings()
           loadDefaults()
           update()
           rename()
           remove()
        """
        pass

    def test_icmptypes(self):
        """
        /org/fedoraproject/FirewallD1/config
            listIcmpTypes()
            getIcmpTypeByName(String name)
            addIcmpType(String name, Dict of {String, Variant} settings)
            
        /org/fedoraproject/FirewallD1/config/icmptype/<id>
           getSettings()
           loadDefaults()
           update()
           rename()
           remove()
        """
        pass

if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(TestFirewallDInterfaceConfig)
    unittest.TextTestRunner(verbosity=2).run(suite)
