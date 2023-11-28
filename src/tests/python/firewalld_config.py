#!/usr/bin/python
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2010-2012 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>
# Jiri Popelka <jpopelka@redhat.com>

# To use in git tree: PYTHONPATH=.. python firewalld-test.py

import sys
import unittest
import firewall
from firewall.client import (
    FirewallClient,
    FirewallClientZoneSettings,
    FirewallClientServiceSettings,
    FirewallClientIcmpTypeSettings,
)
from firewall.core.base import DEFAULT_ZONE_TARGET


class TestFirewallDInterfaceConfig(unittest.TestCase):
    """
    For testing of permanent changes, ie. those that survive restart:
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

        print("\nGetting invalid zone")
        self.assertRaisesRegex(
            Exception, "INVALID_ZONE", self.fw.config().getZoneByName, "dummyname"
        )

        zone_version = "1.0"
        zone_short = "Testing"
        zone_description = "this is just a testing zone"
        zone_target = DEFAULT_ZONE_TARGET
        zone_services = ["dhcpv6-client", "ssh"]
        zone_ports = [("123", "tcp"), ("666-667", "udp")]
        zone_icmpblocks = ["redirect", "echo-reply"]
        zone_masquerade = False
        zone_forward_ports = [
            ("443", "tcp", "441", "192.168.0.2"),
            ("123", "udp", "321", "192.168.1.1"),
        ]
        settings = FirewallClientZoneSettings()
        settings.setVersion(zone_version)
        settings.setShort(zone_short)
        settings.setDescription(zone_description)
        settings.setTarget(zone_target)
        settings.setServices(zone_services)
        settings.setPorts(zone_ports)
        settings.setIcmpBlocks(zone_icmpblocks)
        settings.setMasquerade(zone_masquerade)
        settings.setForwardPorts(zone_forward_ports)

        print("Adding zone with name that already exists")
        self.assertRaisesRegex(
            Exception, "NAME_CONFLICT", self.fw.config().addZone, "home", settings
        )
        print("Adding zone with empty name")
        self.assertRaisesRegex(
            Exception, "INVALID_NAME", self.fw.config().addZone, "", settings
        )
        zone_name = "test"
        print("Adding proper zone")
        self.fw.config().addZone(zone_name, settings)

        print("Checking the saved (permanent) settings")
        config_zone = self.fw.config().getZoneByName(zone_name)
        self.assertIsInstance(config_zone, firewall.client.FirewallClientConfigZone)
        zone_settings = config_zone.getSettings()
        self.assertIsInstance(zone_settings, firewall.client.FirewallClientZoneSettings)
        self.assertEqual(zone_settings.getVersion(), zone_version)
        self.assertEqual(zone_settings.getShort(), zone_short)
        self.assertEqual(zone_settings.getDescription(), zone_description)
        self.assertEqual(zone_settings.getTarget(), "default")
        self.assertEqual(zone_settings.getServices().sort(), zone_services.sort())
        self.assertEqual(zone_settings.getPorts().sort(), zone_ports.sort())
        self.assertEqual(zone_settings.getIcmpBlocks().sort(), zone_icmpblocks.sort())
        self.assertEqual(zone_settings.getMasquerade(), zone_masquerade)
        self.assertEqual(
            zone_settings.getForwardPorts().sort(), zone_forward_ports.sort()
        )

        print("Updating settings")
        zone_services.append("mdns")
        zone_settings.setServices(zone_services)
        config_zone.update(zone_settings)

        print("Reloading firewalld")
        self.fw.reload()

        print("Checking of runtime settings")
        self.assertTrue(zone_name in self.fw.getZones())
        self.assertEqual(self.fw.getServices(zone_name).sort(), zone_services.sort())
        self.assertEqual(self.fw.getPorts(zone_name).sort(), zone_ports.sort())
        self.assertEqual(
            self.fw.getIcmpBlocks(zone_name).sort(), zone_icmpblocks.sort()
        )
        self.assertEqual(self.fw.queryMasquerade(zone_name), zone_masquerade)
        self.assertEqual(
            self.fw.getForwardPorts(zone_name).sort(), zone_forward_ports.sort()
        )

        print("Checking that settings can be roundtripped through setZoneSettings")
        self.fw.setZoneSettings(zone_name, zone_settings)

        print("Renaming zone to name that already exists")
        config_zone = self.fw.config().getZoneByName(zone_name)
        self.assertRaisesRegex(Exception, "NAME_CONFLICT", config_zone.rename, "home")
        new_zone_name = "renamed"
        print("Renaming zone '%s' to '%s'" % (zone_name, new_zone_name))
        config_zone.rename(new_zone_name)

        print(
            "Checking whether the zone '%s' is accessible (it shouldn't be)" % zone_name
        )
        self.assertRaisesRegex(
            Exception, "INVALID_ZONE", self.fw.config().getZoneByName, zone_name
        )
        print("Checking whether the zone '%s' is accessible" % new_zone_name)
        config_zone = self.fw.config().getZoneByName(new_zone_name)
        zone_settings = config_zone.getSettings()
        self.assertEqual(zone_settings.getVersion(), zone_version)
        self.assertEqual(zone_settings.getShort(), zone_short)
        self.assertEqual(zone_settings.getDescription(), zone_description)
        self.assertEqual(zone_settings.getTarget(), "default")
        self.assertEqual(zone_settings.getServices().sort(), zone_services.sort())
        self.assertEqual(zone_settings.getPorts().sort(), zone_ports.sort())
        self.assertEqual(zone_settings.getIcmpBlocks().sort(), zone_icmpblocks.sort())
        self.assertEqual(zone_settings.getMasquerade(), zone_masquerade)
        self.assertEqual(
            zone_settings.getForwardPorts().sort(), zone_forward_ports.sort()
        )

        print("Removing the zone '%s'" % new_zone_name)
        config_zone.remove()
        print("Checking whether the removed zone is accessible (it shouldn't be)")
        self.assertRaisesRegex(
            Exception, "INVALID_ZONE", self.fw.config().getZoneByName, new_zone_name
        )

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

        print("\nGetting invalid service")
        self.assertRaisesRegex(
            Exception, "INVALID_SERVICE", self.fw.config().getServiceByName, "dummyname"
        )

        service_version = "1.0"
        service_short = "Testing"
        service_description = "this is just a testing service"
        service_ports = [("123", "tcp"), ("666-667", "udp")]
        service_modules = ["nf_conntrack_tftp"]
        service_destinations = {"ipv4": "1.2.3.4", "ipv6": "dead::beef"}
        settings = FirewallClientServiceSettings()  # ["", "", "", [], [], {}]
        settings.setVersion(service_version)
        settings.setShort(service_short)
        settings.setDescription(service_description)
        settings.setPorts(service_ports)
        settings.setModules(service_modules)
        settings.setDestinations(service_destinations)

        print("Adding service with name that already exists")
        self.assertRaisesRegex(
            Exception, "NAME_CONFLICT", self.fw.config().addService, "mdns", settings
        )
        print("Adding service with empty name")
        self.assertRaisesRegex(
            Exception, "INVALID_NAME", self.fw.config().addService, "", settings
        )
        service_name = "test"
        print("Adding proper service")
        self.fw.config().addService(service_name, settings)

        print("Checking the saved (permanent) settings")
        config_service = self.fw.config().getServiceByName(service_name)
        self.assertIsInstance(
            config_service, firewall.client.FirewallClientConfigService
        )
        service_settings = config_service.getSettings()
        self.assertIsInstance(
            service_settings, firewall.client.FirewallClientServiceSettings
        )

        print("Updating settings")
        service_modules.append("nf_conntrack_sip")
        service_destinations["ipv6"] = "3ffe:501:ffff::"
        service_settings.setModules(service_modules)
        service_settings.setDestinations(service_destinations)
        config_service.update(service_settings)
        self.assertEqual(service_settings.getVersion(), service_version)
        self.assertEqual(service_settings.getShort(), service_short)
        self.assertEqual(service_settings.getDescription(), service_description)
        self.assertEqual(service_settings.getPorts().sort(), service_ports.sort())
        self.assertEqual(service_settings.getModules().sort(), service_modules.sort())
        self.assertDictEqual(service_settings.getDestinations(), service_destinations)

        print("Renaming service to name that already exists")
        config_service = self.fw.config().getServiceByName(service_name)
        self.assertRaisesRegex(
            Exception, "NAME_CONFLICT", config_service.rename, "mdns"
        )
        new_service_name = "renamed"
        print("Renaming service '%s' to '%s'" % (service_name, new_service_name))
        config_service.rename(new_service_name)

        print(
            "Checking whether the service '%s' is accessible (it shouldn't be)"
            % service_name
        )
        self.assertRaisesRegex(
            Exception,
            "INVALID_SERVICE",
            self.fw.config().getServiceByName,
            service_name,
        )
        print("Checking whether the service '%s' is accessible" % new_service_name)
        config_service = self.fw.config().getServiceByName(new_service_name)
        service_settings = config_service.getSettings()
        self.assertEqual(service_settings.getVersion(), service_version)
        self.assertEqual(service_settings.getShort(), service_short)
        self.assertEqual(service_settings.getDescription(), service_description)
        self.assertEqual(service_settings.getPorts().sort(), service_ports.sort())
        self.assertEqual(service_settings.getModules().sort(), service_modules.sort())
        self.assertDictEqual(service_settings.getDestinations(), service_destinations)

        print("Removing the service '%s'" % new_service_name)
        config_service.remove()
        print("Checking whether the removed service is accessible (it shouldn't be)")
        self.assertRaisesRegex(
            Exception,
            "INVALID_SERVICE",
            self.fw.config().getServiceByName,
            new_service_name,
        )

        # TODO test loadDefaults() ?

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
        print("\nGetting invalid icmp-type")
        self.assertRaisesRegex(
            Exception,
            "INVALID_ICMPTYPE",
            self.fw.config().getIcmpTypeByName,
            "dummyname",
        )

        icmptype_version = "1.0"
        icmptype_short = "Testing"
        icmptype_description = "this is just a testing icmp type"
        icmptype_destinations = ["ipv4"]
        settings = FirewallClientIcmpTypeSettings()  # ["", "", "", []]
        settings.setVersion(icmptype_version)
        settings.setShort(icmptype_short)
        settings.setDescription(icmptype_description)
        settings.setDestinations(icmptype_destinations)

        print("Adding icmp type with name that already exists")
        self.assertRaisesRegex(
            Exception,
            "NAME_CONFLICT",
            self.fw.config().addIcmpType,
            "echo-reply",
            settings,
        )
        print("Adding icmp type with empty name")
        self.assertRaisesRegex(
            Exception, "INVALID_NAME", self.fw.config().addIcmpType, "", settings
        )
        icmptype_name = "test"
        print("Adding proper icmp type")
        self.fw.config().addIcmpType(icmptype_name, settings)

        print("Checking the saved (permanent) settings")
        config_icmptype = self.fw.config().getIcmpTypeByName(icmptype_name)
        self.assertIsInstance(
            config_icmptype, firewall.client.FirewallClientConfigIcmpType
        )
        icmptype_settings = config_icmptype.getSettings()
        self.assertIsInstance(
            icmptype_settings, firewall.client.FirewallClientIcmpTypeSettings
        )

        print("Updating settings")
        icmptype_destinations.append("ipv6")
        icmptype_settings.setDestinations(icmptype_destinations)
        config_icmptype.update(icmptype_settings)
        self.assertEqual(icmptype_settings.getVersion(), icmptype_version)
        self.assertEqual(icmptype_settings.getShort(), icmptype_short)
        self.assertEqual(icmptype_settings.getDescription(), icmptype_description)
        self.assertEqual(
            icmptype_settings.getDestinations().sort(), icmptype_destinations.sort()
        )

        print("Renaming icmp type to name that already exists")
        config_icmptype = self.fw.config().getIcmpTypeByName(icmptype_name)
        self.assertRaisesRegex(
            Exception, "NAME_CONFLICT", config_icmptype.rename, "echo-reply"
        )
        new_icmptype_name = "renamed"
        print("Renaming icmp type '%s' to '%s'" % (icmptype_name, new_icmptype_name))
        config_icmptype.rename(new_icmptype_name)

        print(
            "Checking whether the icmp type '%s' is accessible (it shouldn't be)"
            % icmptype_name
        )
        self.assertRaisesRegex(
            Exception,
            "INVALID_ICMPTYPE",
            self.fw.config().getIcmpTypeByName,
            icmptype_name,
        )
        print("Checking whether the icmp type '%s' is accessible" % new_icmptype_name)
        config_icmptype = self.fw.config().getIcmpTypeByName(new_icmptype_name)
        icmptype_settings = config_icmptype.getSettings()
        self.assertEqual(icmptype_settings.getVersion(), icmptype_version)
        self.assertEqual(icmptype_settings.getShort(), icmptype_short)
        self.assertEqual(icmptype_settings.getDescription(), icmptype_description)
        self.assertEqual(
            icmptype_settings.getDestinations().sort(), icmptype_destinations.sort()
        )

        print("Removing the icmp type '%s'" % new_icmptype_name)
        config_icmptype.remove()
        print("Checking whether the removed icmp type is accessible (it shouldn't be)")
        self.assertRaisesRegex(
            Exception,
            "INVALID_ICMPTYPE",
            self.fw.config().getIcmpTypeByName,
            new_icmptype_name,
        )

        # TODO test loadDefaults() ?


if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(TestFirewallDInterfaceConfig)
    results = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if results.wasSuccessful() else 1)
