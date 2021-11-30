# -*- coding: utf-8 -*-
#
# Copyright (C) 2009-2016 Red Hat, Inc.
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

from gi.repository import GLib

import dbus.mainloop.glib
import functools

from firewall import config
from firewall.core.base import DEFAULT_ZONE_TARGET, DEFAULT_POLICY_TARGET, DEFAULT_POLICY_PRIORITY
from firewall.dbus_utils import dbus_to_python
from firewall.core.rich import Rich_Rule
from firewall.core.ipset import normalize_ipset_entry, check_entry_overlaps_existing, \
                                check_for_overlapping_entries
from firewall import errors
from firewall.errors import FirewallError

import dbus
import traceback

exception_handler = None
not_authorized_loop = False

def handle_exceptions(func):
    """Decorator to handle exceptions
    """
    @functools.wraps(func)
    def _impl(*args, **kwargs):
        authorized = False
        while not authorized:
            try:
                return func(*args, **kwargs)
            except dbus.exceptions.DBusException as e:
                dbus_message = e.get_dbus_message() # returns unicode
                dbus_name = e.get_dbus_name()
                if not exception_handler:
                    raise
                if "NotAuthorizedException" in dbus_name:
                    exception_handler("NotAuthorizedException")
                elif "org.freedesktop.DBus.Error" in dbus_name:
                    # dbus error, try again
                    exception_handler(dbus_message)
                else:
                    authorized = True
                    if dbus_message:
                        exception_handler(dbus_message)
                    else:
                        exception_handler(str(e))
            except FirewallError as e:
                if not exception_handler:
                    raise
                else:
                    exception_handler(str(e))
            except Exception:
                if not exception_handler:
                    raise
                else:
                    exception_handler(traceback.format_exc())
            if not not_authorized_loop:
                break
    return _impl

# zone config setings

class FirewallClientZoneSettings(object):
    @handle_exceptions
    def __init__(self, settings = None):
        self.settings = ["", "", "", False, DEFAULT_ZONE_TARGET, [], [],
                         [], False, [], [], [], [], [], [], False, False]
        self.settings_name = ["version", "short", "description", "UNUSED",
                              "target", "services", "ports",
                              "icmp_blocks", "masquerade", "forward_ports",
                              "interfaces", "sources", "rules_str",
                              "protocols", "source_ports", "icmp_block_inversion",
                              "forward"]
        self.settings_dbus_type = ["s", "s", "s", "b",
                                   "s", "s", "(ss)",
                                   "s", "b", "(ssss)",
                                   "s", "s", "s",
                                   "s", "(ss)", "b",
                                   "b"]
        if settings:
            if isinstance(settings, list):
                for i,v in enumerate(settings):
                    self.settings[i] = settings[i]
            if isinstance(settings, dict):
                self.setSettingsDict(settings)

    @handle_exceptions
    def __repr__(self):
        return '%s(%r)' % (self.__class__, self.settings)

    @handle_exceptions
    def getSettingsDict(self):
        settings = {}
        for key,value in zip(self.settings_name, self.settings):
            if key == 'UNUSED':
                continue
            settings[key] = value
        return settings
    @handle_exceptions
    def setSettingsDict(self, settings):
        for key in settings:
            self.settings[self.settings_name.index(key)] = settings[key]
    @handle_exceptions
    def getSettingsDbusDict(self):
        settings = {}
        for key,value,sig in zip(self.settings_name, self.settings, self.settings_dbus_type):
            if key == 'UNUSED':
                continue
            if type(value) is list:
                settings[key] = dbus.Array(value, signature=sig)
            elif type(value) is dict:
                settings[key] = dbus.Dictionary(value, signature=sig)
            else:
                settings[key] = value
        return settings

    @handle_exceptions
    def getRuntimeSettingsDict(self):
        settings = self.getSettingsDict()
        # These are not configurable at runtime:
        del settings['version']
        del settings['short']
        del settings['description']
        del settings['target']
        return settings
    @handle_exceptions
    def getRuntimeSettingsDbusDict(self):
        settings = self.getSettingsDbusDict()
        # These are not configurable at runtime:
        del settings['version']
        del settings['short']
        del settings['description']
        del settings['target']
        return settings

    @handle_exceptions
    def getVersion(self):
        return self.settings[0]
    @handle_exceptions
    def setVersion(self, version):
        self.settings[0] = version

    @handle_exceptions
    def getShort(self):
        return self.settings[1]
    @handle_exceptions
    def setShort(self, short):
        self.settings[1] = short

    @handle_exceptions
    def getDescription(self):
        return self.settings[2]
    @handle_exceptions
    def setDescription(self, description):
        self.settings[2] = description

    # self.settings[3] was used for 'immutable'

    @handle_exceptions
    def getTarget(self):
        return self.settings[4] if self.settings[4] != DEFAULT_ZONE_TARGET else "default"
    @handle_exceptions
    def setTarget(self, target):
        self.settings[4] = target if target != "default" else DEFAULT_ZONE_TARGET

    @handle_exceptions
    def getServices(self):
        return self.settings[5]
    @handle_exceptions
    def setServices(self, services):
        self.settings[5] = services
    @handle_exceptions
    def addService(self, service):
        if service not in self.settings[5]:
            self.settings[5].append(service)
        else:
            raise FirewallError(errors.ALREADY_ENABLED, service)
    @handle_exceptions
    def removeService(self, service):
        if service in self.settings[5]:
            self.settings[5].remove(service)
        else:
            raise FirewallError(errors.NOT_ENABLED, service)
    @handle_exceptions
    def queryService(self, service):
        return service in self.settings[5]

    @handle_exceptions
    def getPorts(self):
        return self.settings[6]
    @handle_exceptions
    def setPorts(self, ports):
        self.settings[6] = ports
    @handle_exceptions
    def addPort(self, port, protocol):
        if (port,protocol) not in self.settings[6]:
            self.settings[6].append((port,protocol))
        else:
            raise FirewallError(errors.ALREADY_ENABLED,
                                "'%s:%s'" % (port, protocol))
    @handle_exceptions
    def removePort(self, port, protocol):
        if (port,protocol) in self.settings[6]:
            self.settings[6].remove((port,protocol))
        else:
            raise FirewallError(errors.NOT_ENABLED,
                                "'%s:%s'" % (port, protocol))
    @handle_exceptions
    def queryPort(self, port, protocol):
        return (port,protocol) in self.settings[6]

    @handle_exceptions
    def getProtocols(self):
        return self.settings[13]
    @handle_exceptions
    def setProtocols(self, protocols):
        self.settings[13] = protocols
    @handle_exceptions
    def addProtocol(self, protocol):
        if protocol not in self.settings[13]:
            self.settings[13].append(protocol)
        else:
            raise FirewallError(errors.ALREADY_ENABLED, protocol)
    @handle_exceptions
    def removeProtocol(self, protocol):
        if protocol in self.settings[13]:
            self.settings[13].remove(protocol)
        else:
            raise FirewallError(errors.NOT_ENABLED, protocol)
    @handle_exceptions
    def queryProtocol(self, protocol):
        return protocol in self.settings[13]

    @handle_exceptions
    def getSourcePorts(self):
        return self.settings[14]
    @handle_exceptions
    def setSourcePorts(self, ports):
        self.settings[14] = ports
    @handle_exceptions
    def addSourcePort(self, port, protocol):
        if (port,protocol) not in self.settings[14]:
            self.settings[14].append((port,protocol))
        else:
            raise FirewallError(errors.ALREADY_ENABLED,
                                "'%s:%s'" % (port, protocol))
    @handle_exceptions
    def removeSourcePort(self, port, protocol):
        if (port,protocol) in self.settings[14]:
            self.settings[14].remove((port,protocol))
        else:
            raise FirewallError(errors.NOT_ENABLED,
                                "'%s:%s'" % (port, protocol))
    @handle_exceptions
    def querySourcePort(self, port, protocol):
        return (port,protocol) in self.settings[14]

    @handle_exceptions
    def getIcmpBlocks(self):
        return self.settings[7]
    @handle_exceptions
    def setIcmpBlocks(self, icmpblocks):
        self.settings[7] = icmpblocks
    @handle_exceptions
    def addIcmpBlock(self, icmptype):
        if icmptype not in self.settings[7]:
            self.settings[7].append(icmptype)
        else:
            raise FirewallError(errors.ALREADY_ENABLED, icmptype)
    @handle_exceptions
    def removeIcmpBlock(self, icmptype):
        if icmptype in self.settings[7]:
            self.settings[7].remove(icmptype)
        else:
            raise FirewallError(errors.NOT_ENABLED, icmptype)
    @handle_exceptions
    def queryIcmpBlock(self, icmptype):
        return icmptype in self.settings[7]

    @handle_exceptions
    def getIcmpBlockInversion(self):
        return self.settings[15]
    @handle_exceptions
    def setIcmpBlockInversion(self, flag):
        self.settings[15] = flag
    @handle_exceptions
    def addIcmpBlockInversion(self):
        if not self.settings[15]:
            self.settings[15] = True
        else:
            FirewallError(errors.ALREADY_ENABLED, "icmp-block-inversion")
    @handle_exceptions
    def removeIcmpBlockInversion(self):
        if self.settings[15]:
            self.settings[15] = False
        else:
            FirewallError(errors.NOT_ENABLED, "icmp-block-inversion")
    @handle_exceptions
    def queryIcmpBlockInversion(self):
        return self.settings[15]

    @handle_exceptions
    def getForward(self):
        return self.settings[16]
    @handle_exceptions
    def setForward(self, forward):
        self.settings[16] = forward
    @handle_exceptions
    def addForward(self):
        if not self.settings[16]:
            self.settings[16] = True
        else:
            FirewallError(errors.ALREADY_ENABLED, "forward")
    @handle_exceptions
    def removeForward(self):
        if self.settings[16]:
            self.settings[16] = False
        else:
            FirewallError(errors.NOT_ENABLED, "forward")
    @handle_exceptions
    def queryForward(self):
        return self.settings[16]

    @handle_exceptions
    def getMasquerade(self):
        return self.settings[8]
    @handle_exceptions
    def setMasquerade(self, masquerade):
        self.settings[8] = masquerade
    @handle_exceptions
    def addMasquerade(self):
        if not self.settings[8]:
            self.settings[8] = True
        else:
            FirewallError(errors.ALREADY_ENABLED, "masquerade")
    @handle_exceptions
    def removeMasquerade(self):
        if self.settings[8]:
            self.settings[8] = False
        else:
            FirewallError(errors.NOT_ENABLED, "masquerade")
    @handle_exceptions
    def queryMasquerade(self):
        return self.settings[8]

    @handle_exceptions
    def getForwardPorts(self):
        return self.settings[9]
    @handle_exceptions
    def setForwardPorts(self, ports):
        self.settings[9] = ports
    @handle_exceptions
    def addForwardPort(self, port, protocol, to_port, to_addr):
        if to_port is None:
            to_port = ''
        if to_addr is None:
            to_addr = ''
        if (port,protocol,to_port,to_addr) not in self.settings[9]:
            self.settings[9].append((port,protocol,to_port,to_addr))
        else:
            raise FirewallError(errors.ALREADY_ENABLED, "'%s:%s:%s:%s'" % \
                                (port, protocol, to_port, to_addr))
    @handle_exceptions
    def removeForwardPort(self, port, protocol, to_port, to_addr):
        if to_port is None:
            to_port = ''
        if to_addr is None:
            to_addr = ''
        if (port,protocol,to_port,to_addr) in self.settings[9]:
            self.settings[9].remove((port,protocol,to_port,to_addr))
        else:
            raise FirewallError(errors.NOT_ENABLED, "'%s:%s:%s:%s'" % \
                                (port, protocol, to_port, to_addr))
    @handle_exceptions
    def queryForwardPort(self, port, protocol, to_port, to_addr):
        if to_port is None:
            to_port = ''
        if to_addr is None:
            to_addr = ''
        return (port,protocol,to_port,to_addr) in self.settings[9]

    @handle_exceptions
    def getInterfaces(self):
        return self.settings[10]
    @handle_exceptions
    def setInterfaces(self, interfaces):
        self.settings[10] = interfaces
    @handle_exceptions
    def addInterface(self, interface):
        if interface not in self.settings[10]:
            self.settings[10].append(interface)
        else:
            raise FirewallError(errors.ALREADY_ENABLED, interface)
    @handle_exceptions
    def removeInterface(self, interface):
        if interface in self.settings[10]:
            self.settings[10].remove(interface)
        else:
            raise FirewallError(errors.NOT_ENABLED, interface)
    @handle_exceptions
    def queryInterface(self, interface):
        return interface in self.settings[10]

    @handle_exceptions
    def getSources(self):
        return self.settings[11]
    @handle_exceptions
    def setSources(self, sources):
        self.settings[11] = sources
    @handle_exceptions
    def addSource(self, source):
        if source not in self.settings[11]:
            self.settings[11].append(source)
        else:
            raise FirewallError(errors.ALREADY_ENABLED, source)
    @handle_exceptions
    def removeSource(self, source):
        if source in self.settings[11]:
            self.settings[11].remove(source)
        else:
            raise FirewallError(errors.NOT_ENABLED, source)
    @handle_exceptions
    def querySource(self, source):
        return source in self.settings[11]

    @handle_exceptions
    def getRichRules(self):
        return self.settings[12]
    @handle_exceptions
    def setRichRules(self, rules):
        rules = [ str(Rich_Rule(rule_str=r)) for r in rules ]
        self.settings[12] = rules
    @handle_exceptions
    def addRichRule(self, rule):
        rule = str(Rich_Rule(rule_str=rule))
        if rule not in self.settings[12]:
            self.settings[12].append(rule)
        else:
            raise FirewallError(errors.ALREADY_ENABLED, rule)
    @handle_exceptions
    def removeRichRule(self, rule):
        rule = str(Rich_Rule(rule_str=rule))
        if rule in self.settings[12]:
            self.settings[12].remove(rule)
        else:
            raise FirewallError(errors.NOT_ENABLED, rule)
    @handle_exceptions
    def queryRichRule(self, rule):
        rule = str(Rich_Rule(rule_str=rule))
        return rule in self.settings[12]


# zone config

class FirewallClientConfigZone(object):
    def __init__(self, bus, path):
        self.bus = bus
        self.path = path
        self.dbus_obj = self.bus.get_object(config.dbus.DBUS_INTERFACE, path)
        self.fw_zone = dbus.Interface(
            self.dbus_obj,
            dbus_interface=config.dbus.DBUS_INTERFACE_CONFIG_ZONE)
        self.fw_properties = dbus.Interface(
            self.dbus_obj, dbus_interface='org.freedesktop.DBus.Properties')
        #TODO: check interface version and revision (need to match client 
        # version)

    @handle_exceptions
    def get_property(self, prop):
        return dbus_to_python(self.fw_properties.Get(
            config.dbus.DBUS_INTERFACE_CONFIG_ZONE, prop))

    @handle_exceptions
    def get_properties(self):
        return dbus_to_python(self.fw_properties.GetAll(
            config.dbus.DBUS_INTERFACE_CONFIG_ZONE))

    @handle_exceptions
    def set_property(self, prop, value):
        self.fw_properties.Set(config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                               prop, value)

    @handle_exceptions
    def getSettings(self):
        return FirewallClientZoneSettings(dbus_to_python(self.fw_zone.getSettings2()))

    @handle_exceptions
    def update(self, settings):
        self.fw_zone.update2(settings.getSettingsDbusDict())

    @handle_exceptions
    def loadDefaults(self):
        self.fw_zone.loadDefaults()

    @handle_exceptions
    def remove(self):
        self.fw_zone.remove()

    @handle_exceptions
    def rename(self, name):
        self.fw_zone.rename(name)

    # version

    @handle_exceptions
    def getVersion(self):
        return self.fw_zone.getVersion()

    @handle_exceptions
    def setVersion(self, version):
        self.fw_zone.setVersion(version)

    # short

    @handle_exceptions
    def getShort(self):
        return self.fw_zone.getShort()

    @handle_exceptions
    def setShort(self, short):
        self.fw_zone.setShort(short)

    # description

    @handle_exceptions
    def getDescription(self):
        return self.fw_zone.getDescription()

    @handle_exceptions
    def setDescription(self, description):
        self.fw_zone.setDescription(description)

    # target

    @handle_exceptions
    def getTarget(self):
        return self.fw_zone.getTarget()

    @handle_exceptions
    def setTarget(self, target):
        self.fw_zone.setTarget(target)

    # service

    @handle_exceptions
    def getServices(self):
        return self.fw_zone.getServices()

    @handle_exceptions
    def setServices(self, services):
        self.fw_zone.setServices(services)

    @handle_exceptions
    def addService(self, service):
        self.fw_zone.addService(service)

    @handle_exceptions
    def removeService(self, service):
        self.fw_zone.removeService(service)

    @handle_exceptions
    def queryService(self, service):
        return self.fw_zone.queryService(service)

    # port

    @handle_exceptions
    def getPorts(self):
        return self.fw_zone.getPorts()

    @handle_exceptions
    def setPorts(self, ports):
        self.fw_zone.setPorts(ports)

    @handle_exceptions
    def addPort(self, port, protocol):
        self.fw_zone.addPort(port, protocol)

    @handle_exceptions
    def removePort(self, port, protocol):
        self.fw_zone.removePort(port, protocol)

    @handle_exceptions
    def queryPort(self, port, protocol):
        return self.fw_zone.queryPort(port, protocol)

    # protocol

    @handle_exceptions
    def getProtocols(self):
        return self.fw_zone.getProtocols()

    @handle_exceptions
    def setProtocols(self, protocols):
        self.fw_zone.setProtocols(protocols)

    @handle_exceptions
    def addProtocol(self, protocol):
        self.fw_zone.addProtocol(protocol)

    @handle_exceptions
    def removeProtocol(self, protocol):
        self.fw_zone.removeProtocol(protocol)

    @handle_exceptions
    def queryProtocol(self, protocol):
        return self.fw_zone.queryProtocol(protocol)

    # source-port

    @handle_exceptions
    def getSourcePorts(self):
        return self.fw_zone.getSourcePorts()

    @handle_exceptions
    def setSourcePorts(self, ports):
        self.fw_zone.setSourcePorts(ports)

    @handle_exceptions
    def addSourcePort(self, port, protocol):
        self.fw_zone.addSourcePort(port, protocol)

    @handle_exceptions
    def removeSourcePort(self, port, protocol):
        self.fw_zone.removeSourcePort(port, protocol)

    @handle_exceptions
    def querySourcePort(self, port, protocol):
        return self.fw_zone.querySourcePort(port, protocol)

    # icmp block

    @handle_exceptions
    def getIcmpBlocks(self):
        return self.fw_zone.getIcmpBlocks()

    @handle_exceptions
    def setIcmpBlocks(self, icmptypes):
        self.fw_zone.setIcmpBlocks(icmptypes)

    @handle_exceptions
    def addIcmpBlock(self, icmptype):
        self.fw_zone.addIcmpBlock(icmptype)

    @handle_exceptions
    def removeIcmpBlock(self, icmptype):
        self.fw_zone.removeIcmpBlock(icmptype)

    @handle_exceptions
    def queryIcmpBlock(self, icmptype):
        return self.fw_zone.queryIcmpBlock(icmptype)

    # icmp-block-inversion

    @handle_exceptions
    def getIcmpBlockInversion(self):
        return self.fw_zone.getIcmpBlockInversion()

    @handle_exceptions
    def setIcmpBlockInversion(self, inversion):
        self.fw_zone.setIcmpBlockInversion(inversion)

    @handle_exceptions
    def addIcmpBlockInversion(self):
        self.fw_zone.addIcmpBlockInversion()

    @handle_exceptions
    def removeIcmpBlockInversion(self):
        self.fw_zone.removeIcmpBlockInversion()

    @handle_exceptions
    def queryIcmpBlockInversion(self):
        return self.fw_zone.queryIcmpBlockInversion()

    # forward

    @handle_exceptions
    def getForward(self):
        return self.fw_zone.getSettings2()["forward"]

    @handle_exceptions
    def setForward(self, forward):
        self.fw_zone.update2({"forward": forward})

    @handle_exceptions
    def addForward(self):
        self.fw_zone.update2({"forward": True})

    @handle_exceptions
    def removeForward(self):
        self.fw_zone.update2({"forward": False})

    @handle_exceptions
    def queryForward(self):
        return self.fw_zone.getSettings2()["forward"]

    # masquerade

    @handle_exceptions
    def getMasquerade(self):
        return self.fw_zone.getMasquerade()

    @handle_exceptions
    def setMasquerade(self, masquerade):
        self.fw_zone.setMasquerade(masquerade)

    @handle_exceptions
    def addMasquerade(self):
        self.fw_zone.addMasquerade()

    @handle_exceptions
    def removeMasquerade(self):
        self.fw_zone.removeMasquerade()

    @handle_exceptions
    def queryMasquerade(self):
        return self.fw_zone.queryMasquerade()

    # forward port

    @handle_exceptions
    def getForwardPorts(self):
        return self.fw_zone.getForwardPorts()

    @handle_exceptions
    def setForwardPorts(self, ports):
        self.fw_zone.setForwardPorts(ports)

    @handle_exceptions
    def addForwardPort(self, port, protocol, toport, toaddr):
        if toport is None:
            toport = ''
        if toaddr is None:
            toaddr = ''
        self.fw_zone.addForwardPort(port, protocol, toport, toaddr)

    @handle_exceptions
    def removeForwardPort(self, port, protocol, toport, toaddr):
        if toport is None:
            toport = ''
        if toaddr is None:
            toaddr = ''
        self.fw_zone.removeForwardPort(port, protocol, toport, toaddr)

    @handle_exceptions
    def queryForwardPort(self, port, protocol, toport, toaddr):
        if toport is None:
            toport = ''
        if toaddr is None:
            toaddr = ''
        return self.fw_zone.queryForwardPort(port, protocol, toport, toaddr)

    # interface

    @handle_exceptions
    def getInterfaces(self):
        return self.fw_zone.getInterfaces()

    @handle_exceptions
    def setInterfaces(self, interfaces):
        self.fw_zone.setInterfaces(interfaces)

    @handle_exceptions
    def addInterface(self, interface):
        self.fw_zone.addInterface(interface)

    @handle_exceptions
    def removeInterface(self, interface):
        self.fw_zone.removeInterface(interface)

    @handle_exceptions
    def queryInterface(self, interface):
        return self.fw_zone.queryInterface(interface)

    # source

    @handle_exceptions
    def getSources(self):
        return self.fw_zone.getSources()

    @handle_exceptions
    def setSources(self, sources):
        self.fw_zone.setSources(sources)

    @handle_exceptions
    def addSource(self, source):
        self.fw_zone.addSource(source)

    @handle_exceptions
    def removeSource(self, source):
        self.fw_zone.removeSource(source)

    @handle_exceptions
    def querySource(self, source):
        return self.fw_zone.querySource(source)

    # rich rule

    @handle_exceptions
    def getRichRules(self):
        return self.fw_zone.getRichRules()

    @handle_exceptions
    def setRichRules(self, rules):
        self.fw_zone.setRichRules(rules)

    @handle_exceptions
    def addRichRule(self, rule):
        self.fw_zone.addRichRule(rule)

    @handle_exceptions
    def removeRichRule(self, rule):
        self.fw_zone.removeRichRule(rule)

    @handle_exceptions
    def queryRichRule(self, rule):
        return self.fw_zone.queryRichRule(rule)

class FirewallClientPolicySettings(object):
    @handle_exceptions
    def __init__(self, settings=None):
        self.settings = {"description": "",
                         "egress_zones": [],
                         "forward_ports": [],
                         "icmp_blocks": [],
                         "ingress_zones": [],
                         "masquerade": False,
                         "ports": [],
                         "priority": DEFAULT_POLICY_PRIORITY,
                         "protocols": [],
                         "rich_rules": [],
                         "services": [],
                         "short": "",
                         "source_ports": [],
                         "target": DEFAULT_POLICY_TARGET,
                         "version": "",
                         }
        self.settings_dbus_type = ["s", "s", "(ssss)", "s",
                                   "s", "b", "(ss)",
                                   "i", "s", "s",
                                   "s", "s", "(ss)",
                                   "s", "s"]
        if settings:
            self.setSettingsDict(settings)

    @handle_exceptions
    def __repr__(self):
        return '%s(%r)' % (self.__class__, self.settings)

    @handle_exceptions
    def getSettingsDict(self):
        return self.settings
    @handle_exceptions
    def setSettingsDict(self, settings):
        for key in settings:
            self.settings[key] = settings[key]
    @handle_exceptions
    def getSettingsDbusDict(self):
        settings = {}
        for key,sig in zip(self.settings, self.settings_dbus_type):
            value = self.settings[key]
            if type(value) is list:
                settings[key] = dbus.Array(value, signature=sig)
            elif type(value) is dict:
                settings[key] = dbus.Dictionary(value, signature=sig)
            else:
                settings[key] = value
        return settings
    def getRuntimeSettingsDbusDict(self):
        settings = self.getSettingsDbusDict()
        for key in ["version", "short", "description", "target"]:
            del settings[key]
        return settings

    @handle_exceptions
    def getVersion(self):
        return self.settings["version"]
    @handle_exceptions
    def setVersion(self, version):
        self.settings["version"] = version

    @handle_exceptions
    def getShort(self):
        return self.settings["short"]
    @handle_exceptions
    def setShort(self, short):
        self.settings["short"] = short

    @handle_exceptions
    def getDescription(self):
        return self.settings["description"]
    @handle_exceptions
    def setDescription(self, description):
        self.settings["description"] = description

    @handle_exceptions
    def getTarget(self):
        return self.settings["target"]
    @handle_exceptions
    def setTarget(self, target):
        self.settings["target"] = target

    @handle_exceptions
    def getServices(self):
        return self.settings["services"]
    @handle_exceptions
    def setServices(self, services):
        self.settings["services"] = services
    @handle_exceptions
    def addService(self, service):
        if service not in self.settings["services"]:
            self.settings["services"].append(service)
        else:
            raise FirewallError(errors.ALREADY_ENABLED, service)
    @handle_exceptions
    def removeService(self, service):
        if service in self.settings["services"]:
            self.settings["services"].remove(service)
        else:
            raise FirewallError(errors.NOT_ENABLED, service)
    @handle_exceptions
    def queryService(self, service):
        return service in self.settings["services"]

    @handle_exceptions
    def getPorts(self):
        return self.settings["ports"]
    @handle_exceptions
    def setPorts(self, ports):
        self.settings["ports"] = ports
    @handle_exceptions
    def addPort(self, port, protocol):
        if (port,protocol) not in self.settings["ports"]:
            self.settings["ports"].append((port,protocol))
        else:
            raise FirewallError(errors.ALREADY_ENABLED,
                                "'%s:%s'" % (port, protocol))
    @handle_exceptions
    def removePort(self, port, protocol):
        if (port,protocol) in self.settings["ports"]:
            self.settings["ports"].remove((port,protocol))
        else:
            raise FirewallError(errors.NOT_ENABLED,
                                "'%s:%s'" % (port, protocol))
    @handle_exceptions
    def queryPort(self, port, protocol):
        return (port,protocol) in self.settings["ports"]

    @handle_exceptions
    def getProtocols(self):
        return self.settings["protocols"]
    @handle_exceptions
    def setProtocols(self, protocols):
        self.settings["protocols"] = protocols
    @handle_exceptions
    def addProtocol(self, protocol):
        if protocol not in self.settings["protocols"]:
            self.settings["protocols"].append(protocol)
        else:
            raise FirewallError(errors.ALREADY_ENABLED, protocol)
    @handle_exceptions
    def removeProtocol(self, protocol):
        if protocol in self.settings["protocols"]:
            self.settings["protocols"].remove(protocol)
        else:
            raise FirewallError(errors.NOT_ENABLED, protocol)
    @handle_exceptions
    def queryProtocol(self, protocol):
        return protocol in self.settings["protocols"]

    @handle_exceptions
    def getSourcePorts(self):
        return self.settings["source_ports"]
    @handle_exceptions
    def setSourcePorts(self, ports):
        self.settings["source_ports"] = ports
    @handle_exceptions
    def addSourcePort(self, port, protocol):
        if (port,protocol) not in self.settings["source_ports"]:
            self.settings["source_ports"].append((port,protocol))
        else:
            raise FirewallError(errors.ALREADY_ENABLED,
                                "'%s:%s'" % (port, protocol))
    @handle_exceptions
    def removeSourcePort(self, port, protocol):
        if (port,protocol) in self.settings["source_ports"]:
            self.settings["source_ports"].remove((port,protocol))
        else:
            raise FirewallError(errors.NOT_ENABLED,
                                "'%s:%s'" % (port, protocol))
    @handle_exceptions
    def querySourcePort(self, port, protocol):
        return (port,protocol) in self.settings["source_ports"]

    @handle_exceptions
    def getIcmpBlocks(self):
        return self.settings["icmp_blocks"]
    @handle_exceptions
    def setIcmpBlocks(self, icmpblocks):
        self.settings["icmp_blocks"] = icmpblocks
    @handle_exceptions
    def addIcmpBlock(self, icmptype):
        if icmptype not in self.settings["icmp_blocks"]:
            self.settings["icmp_blocks"].append(icmptype)
        else:
            raise FirewallError(errors.ALREADY_ENABLED, icmptype)
    @handle_exceptions
    def removeIcmpBlock(self, icmptype):
        if icmptype in self.settings["icmp_blocks"]:
            self.settings["icmp_blocks"].remove(icmptype)
        else:
            raise FirewallError(errors.NOT_ENABLED, icmptype)
    @handle_exceptions
    def queryIcmpBlock(self, icmptype):
        return icmptype in self.settings["icmp_blocks"]

    @handle_exceptions
    def getMasquerade(self):
        return self.settings["masquerade"]
    @handle_exceptions
    def setMasquerade(self, masquerade):
        self.settings["masquerade"] = masquerade
    @handle_exceptions
    def addMasquerade(self):
        if not self.settings["masquerade"]:
            self.settings["masquerade"] = True
        else:
            FirewallError(errors.ALREADY_ENABLED, "masquerade")
    @handle_exceptions
    def removeMasquerade(self):
        if self.settings["masquerade"]:
            self.settings["masquerade"] = False
        else:
            FirewallError(errors.NOT_ENABLED, "masquerade")
    @handle_exceptions
    def queryMasquerade(self):
        return self.settings["masquerade"]

    @handle_exceptions
    def getForwardPorts(self):
        return self.settings["forward_ports"]
    @handle_exceptions
    def setForwardPorts(self, ports):
        self.settings["forward_ports"] = ports
    @handle_exceptions
    def addForwardPort(self, port, protocol, to_port, to_addr):
        if to_port is None:
            to_port = ''
        if to_addr is None:
            to_addr = ''
        if (port,protocol,to_port,to_addr) not in self.settings["forward_ports"]:
            self.settings["forward_ports"].append((port,protocol,to_port,to_addr))
        else:
            raise FirewallError(errors.ALREADY_ENABLED, "'%s:%s:%s:%s'" % \
                                (port, protocol, to_port, to_addr))
    @handle_exceptions
    def removeForwardPort(self, port, protocol, to_port, to_addr):
        if to_port is None:
            to_port = ''
        if to_addr is None:
            to_addr = ''
        if (port,protocol,to_port,to_addr) in self.settings["forward_ports"]:
            self.settings["forward_ports"].remove((port,protocol,to_port,to_addr))
        else:
            raise FirewallError(errors.NOT_ENABLED, "'%s:%s:%s:%s'" % \
                                (port, protocol, to_port, to_addr))
    @handle_exceptions
    def queryForwardPort(self, port, protocol, to_port, to_addr):
        if to_port is None:
            to_port = ''
        if to_addr is None:
            to_addr = ''
        return (port,protocol,to_port,to_addr) in self.settings["forward_ports"]

    @handle_exceptions
    def getRichRules(self):
        return self.settings["rich_rules"]
    @handle_exceptions
    def setRichRules(self, rules):
        rules = [ str(Rich_Rule(rule_str=r)) for r in rules ]
        self.settings["rich_rules"] = rules
    @handle_exceptions
    def addRichRule(self, rule):
        rule = str(Rich_Rule(rule_str=rule))
        if rule not in self.settings["rich_rules"]:
            self.settings["rich_rules"].append(rule)
        else:
            raise FirewallError(errors.ALREADY_ENABLED, rule)
    @handle_exceptions
    def removeRichRule(self, rule):
        rule = str(Rich_Rule(rule_str=rule))
        if rule in self.settings["rich_rules"]:
            self.settings["rich_rules"].remove(rule)
        else:
            raise FirewallError(errors.NOT_ENABLED, rule)
    @handle_exceptions
    def queryRichRule(self, rule):
        rule = str(Rich_Rule(rule_str=rule))
        return rule in self.settings["rich_rules"]

    @handle_exceptions
    def getIngressZones(self):
        return self.settings["ingress_zones"]
    @handle_exceptions
    def setIngressZones(self, ingress_zones):
        self.settings["ingress_zones"] = ingress_zones
    @handle_exceptions
    def addIngressZone(self, ingress_zone):
        if ingress_zone not in self.settings["ingress_zones"]:
            self.settings["ingress_zones"].append(ingress_zone)
        else:
            raise FirewallError(errors.ALREADY_ENABLED, ingress_zone)
    @handle_exceptions
    def removeIngressZone(self, ingress_zone):
        if ingress_zone in self.settings["ingress_zones"]:
            self.settings["ingress_zones"].remove(ingress_zone)
        else:
            raise FirewallError(errors.NOT_ENABLED, ingress_zone)
    @handle_exceptions
    def queryIngressZone(self, ingress_zone):
        return ingress_zone in self.settings["ingress_zones"]

    @handle_exceptions
    def getEgressZones(self):
        return self.settings["egress_zones"]
    @handle_exceptions
    def setEgressZones(self, egress_zones):
        self.settings["egress_zones"] = egress_zones
    @handle_exceptions
    def addEgressZone(self, egress_zone):
        if egress_zone not in self.settings["egress_zones"]:
            self.settings["egress_zones"].append(egress_zone)
        else:
            raise FirewallError(errors.ALREADY_ENABLED, egress_zone)
    @handle_exceptions
    def removeEgressZone(self, egress_zone):
        if egress_zone in self.settings["egress_zones"]:
            self.settings["egress_zones"].remove(egress_zone)
        else:
            raise FirewallError(errors.NOT_ENABLED, egress_zone)
    @handle_exceptions
    def queryEgressZone(self, egress_zone):
        return egress_zone in self.settings["egress_zones"]

    @handle_exceptions
    def getPriority(self):
        return self.settings["priority"]
    @handle_exceptions
    def setPriority(self, priority):
        self.settings["priority"] = int(priority)

class FirewallClientConfigPolicy(object):
    def __init__(self, bus, path):
        self.bus = bus
        self.path = path
        self.dbus_obj = self.bus.get_object(config.dbus.DBUS_INTERFACE, path)
        self.fw_policy = dbus.Interface(
            self.dbus_obj,
            dbus_interface=config.dbus.DBUS_INTERFACE_CONFIG_POLICY)
        self.fw_properties = dbus.Interface(
            self.dbus_obj, dbus_interface='org.freedesktop.DBus.Properties')

    @handle_exceptions
    def get_property(self, prop):
        return dbus_to_python(self.fw_properties.Get(
            config.dbus.DBUS_INTERFACE_CONFIG_POLICY, prop))

    @handle_exceptions
    def get_properties(self):
        return dbus_to_python(self.fw_properties.GetAll(
            config.dbus.DBUS_INTERFACE_CONFIG_POLICY))

    @handle_exceptions
    def set_property(self, prop, value):
        self.fw_properties.Set(config.dbus.DBUS_INTERFACE_CONFIG_POLICY,
                               prop, value)

    @handle_exceptions
    def getSettings(self):
        return FirewallClientPolicySettings(dbus_to_python(self.fw_policy.getSettings()))

    @handle_exceptions
    def update(self, settings):
        self.fw_policy.update(settings.getSettingsDbusDict())

    @handle_exceptions
    def loadDefaults(self):
        self.fw_policy.loadDefaults()

    @handle_exceptions
    def remove(self):
        self.fw_policy.remove()

    @handle_exceptions
    def rename(self, name):
        self.fw_policy.rename(name)

# service config settings

class FirewallClientServiceSettings(object):
    @handle_exceptions
    def __init__(self, settings=None):
        self.settings = ["", "", "", [], [], {}, [], [], [], []]
        self.settings_name = ["version", "short", "description", "ports",
                              "modules", "destination", "protocols",
                              "source_ports", "includes", "helpers"]
        self.settings_dbus_type = ["s", "s", "s", "(ss)",
                                   "s", "ss", "s",
                                   "(ss)", "s", "s"]
        if settings:
            if type(settings) is list:
                for i,v in enumerate(settings):
                    self.settings[i] = settings[i]
            elif type(settings) is dict:
                self.setSettingsDict(settings)

    @handle_exceptions
    def __repr__(self):
        return '%s(%r)' % (self.__class__, self.settings)

    @handle_exceptions
    def getSettingsDict(self):
        settings = {}
        for key,value in zip(self.settings_name, self.settings):
            settings[key] = value
        return settings
    @handle_exceptions
    def setSettingsDict(self, settings):
        for key in settings:
            self.settings[self.settings_name.index(key)] = settings[key]
    @handle_exceptions
    def getSettingsDbusDict(self):
        settings = {}
        for key,value,sig in zip(self.settings_name, self.settings, self.settings_dbus_type):
            if type(value) is list:
                settings[key] = dbus.Array(value, signature=sig)
            elif type(value) is dict:
                settings[key] = dbus.Dictionary(value, signature=sig)
            else:
                settings[key] = value
        return settings

    @handle_exceptions
    def getVersion(self):
        return self.settings[0]
    @handle_exceptions
    def setVersion(self, version):
        self.settings[0] = version

    @handle_exceptions
    def getShort(self):
        return self.settings[1]
    @handle_exceptions
    def setShort(self, short):
        self.settings[1] = short

    @handle_exceptions
    def getDescription(self):
        return self.settings[2]
    @handle_exceptions
    def setDescription(self, description):
        self.settings[2] = description

    @handle_exceptions
    def getPorts(self):
        return self.settings[3]
    @handle_exceptions
    def setPorts(self, ports):
        self.settings[3] = ports
    @handle_exceptions
    def addPort(self, port, protocol):
        if (port,protocol) not in self.settings[3]:
            self.settings[3].append((port,protocol))
        else:
            raise FirewallError(errors.ALREADY_ENABLED,
                                "'%s:%s'" % (port, protocol))
    @handle_exceptions
    def removePort(self, port, protocol):
        if (port,protocol) in self.settings[3]:
            self.settings[3].remove((port,protocol))
        else:
            raise FirewallError(errors.NOT_ENABLED,
                                "'%s:%s'" % (port, protocol))
    @handle_exceptions
    def queryPort(self, port, protocol):
        return (port,protocol) in self.settings[3]

    @handle_exceptions
    def getProtocols(self):
        return self.settings[6]
    @handle_exceptions
    def setProtocols(self, protocols):
        self.settings[6] = protocols
    @handle_exceptions
    def addProtocol(self, protocol):
        if protocol not in self.settings[6]:
            self.settings[6].append(protocol)
        else:
            raise FirewallError(errors.ALREADY_ENABLED, protocol)
    @handle_exceptions
    def removeProtocol(self, protocol):
        if protocol in self.settings[6]:
            self.settings[6].remove(protocol)
        else:
            raise FirewallError(errors.NOT_ENABLED, protocol)
    @handle_exceptions
    def queryProtocol(self, protocol):
        return protocol in self.settings[6]

    @handle_exceptions
    def getSourcePorts(self):
        return self.settings[7]
    @handle_exceptions
    def setSourcePorts(self, ports):
        self.settings[7] = ports
    @handle_exceptions
    def addSourcePort(self, port, protocol):
        if (port,protocol) not in self.settings[7]:
            self.settings[7].append((port,protocol))
        else:
            raise FirewallError(errors.ALREADY_ENABLED,
                                "'%s:%s'" % (port, protocol))
    @handle_exceptions
    def removeSourcePort(self, port, protocol):
        if (port,protocol) in self.settings[7]:
            self.settings[7].remove((port,protocol))
        else:
            raise FirewallError(errors.NOT_ENABLED,
                                "'%s:%s'" % (port, protocol))
    @handle_exceptions
    def querySourcePort(self, port, protocol):
        return (port,protocol) in self.settings[7]

    @handle_exceptions
    def getModules(self):
        return self.settings[4]
    @handle_exceptions
    def setModules(self, modules):
        self.settings[4] = modules
    @handle_exceptions
    def addModule(self, module):
        if module not in self.settings[4]:
            self.settings[4].append(module)
        else:
            raise FirewallError(errors.ALREADY_ENABLED, module)
    @handle_exceptions
    def removeModule(self, module):
        if module in self.settings[4]:
            self.settings[4].remove(module)
        else:
            raise FirewallError(errors.NOT_ENABLED, module)
    @handle_exceptions
    def queryModule(self, module):
        return module in self.settings[4]

    @handle_exceptions
    def getDestinations(self):
        return self.settings[5]
    @handle_exceptions
    def setDestinations(self, destinations):
        self.settings[5] = destinations
    @handle_exceptions
    def setDestination(self, dest_type, address):
        if dest_type not in self.settings[5] or \
           self.settings[5][dest_type] != address:
            self.settings[5][dest_type] = address
        else:
            raise FirewallError(errors.ALREADY_ENABLED, "'%s:%s'" % \
                                (dest_type, address))
    @handle_exceptions
    def removeDestination(self, dest_type, address=None):
        if dest_type in self.settings[5]:
            if address is not None and self.settings[5][dest_type] != address:
                raise FirewallError(errors.NOT_ENABLED, "'%s:%s'" % \
                                    (dest_type, address))
            del self.settings[5][dest_type]
        else:
            raise FirewallError(errors.NOT_ENABLED, "'%s'" % dest_type)
    @handle_exceptions
    def queryDestination(self, dest_type, address):
        return (dest_type in self.settings[5] and \
                    address == self.settings[5][dest_type])

    @handle_exceptions
    def getIncludes(self):
        return self.settings[8]
    @handle_exceptions
    def setIncludes(self, includes):
        self.settings[8] = includes
    @handle_exceptions
    def addInclude(self, include):
        if include not in self.settings[8]:
            self.settings[8].append(include)
        else:
            raise FirewallError(errors.ALREADY_ENABLED, include)
    @handle_exceptions
    def removeInclude(self, include):
        if include in self.settings[8]:
            self.settings[8].remove(include)
        else:
            raise FirewallError(errors.NOT_ENABLED, include)
    @handle_exceptions
    def queryInclude(self, include):
        return include in self.settings[8]

    @handle_exceptions
    def getHelpers(self):
        return self.settings[9]
    @handle_exceptions
    def setHelpers(self, helpers):
        self.settings[9] = helpers
    @handle_exceptions
    def addHelper(self, helper):
        if helper not in self.settings[9]:
            self.settings[9].append(helper)
        else:
            raise FirewallError(errors.ALREADY_ENABLED, helper)
    @handle_exceptions
    def removeHelper(self, helper):
        if helper in self.settings[9]:
            self.settings[9].remove(helper)
        else:
            raise FirewallError(errors.NOT_ENABLED, helper)
    @handle_exceptions
    def queryHelper(self, helper):
        return helper in self.settings[9]

# ipset config settings

class FirewallClientIPSetSettings(object):
    @handle_exceptions
    def __init__(self, settings=None):
        if settings:
            self.settings = settings
        else:
            self.settings = ["", "", "", "", {}, []]

    @handle_exceptions
    def __repr__(self):
        return '%s(%r)' % (self.__class__, self.settings)

    @handle_exceptions
    def getVersion(self):
        return self.settings[0]
    @handle_exceptions
    def setVersion(self, version):
        self.settings[0] = version

    @handle_exceptions
    def getShort(self):
        return self.settings[1]
    @handle_exceptions
    def setShort(self, short):
        self.settings[1] = short

    @handle_exceptions
    def getDescription(self):
        return self.settings[2]
    @handle_exceptions
    def setDescription(self, description):
        self.settings[2] = description

    @handle_exceptions
    def getType(self):
        return self.settings[3]
    @handle_exceptions
    def setType(self, ipset_type):
        self.settings[3] = ipset_type

    @handle_exceptions
    def getOptions(self):
        return self.settings[4]
    @handle_exceptions
    def setOptions(self, options):
        self.settings[4] = options
    @handle_exceptions
    def addOption(self, key, value):
        if key not in self.settings[4] or self.settings[4][key] != value:
            self.settings[4][key] = value
        else:
            raise FirewallError(errors.ALREADY_ENABLED, "'%s=%s'" % (key,value)
                                if value else key)
    @handle_exceptions
    def removeOption(self, key):
        if key in self.settings[4]:
            del self.settings[4][key]
        else:
            raise FirewallError(errors.NOT_ENABLED, key)
    @handle_exceptions
    def queryOption(self, key, value):
        return key in self.settings[4] and self.settings[4][key] == value

    @handle_exceptions
    def getEntries(self):
        return self.settings[5]
    @handle_exceptions
    def setEntries(self, entries):
        if "timeout" in self.settings[4] and \
           self.settings[4]["timeout"] != "0":
            raise FirewallError(errors.IPSET_WITH_TIMEOUT)
        check_for_overlapping_entries(entries)
        self.settings[5] = entries
    @handle_exceptions
    def addEntry(self, entry):
        if "timeout" in self.settings[4] and \
           self.settings[4]["timeout"] != "0":
            raise FirewallError(errors.IPSET_WITH_TIMEOUT)
        entry = normalize_ipset_entry(entry)
        if entry not in self.settings[5]:
            check_entry_overlaps_existing(entry, self.settings[5])
            self.settings[5].append(entry)
        else:
            raise FirewallError(errors.ALREADY_ENABLED, entry)
    @handle_exceptions
    def removeEntry(self, entry):
        if "timeout" in self.settings[4] and \
           self.settings[4]["timeout"] != "0":
            raise FirewallError(errors.IPSET_WITH_TIMEOUT)
        entry = normalize_ipset_entry(entry)
        if entry in self.settings[5]:
            self.settings[5].remove(entry)
        else:
            raise FirewallError(errors.NOT_ENABLED, entry)
    @handle_exceptions
    def queryEntry(self, entry):
        if "timeout" in self.settings[4] and \
           self.settings[4]["timeout"] != "0":
            raise FirewallError(errors.IPSET_WITH_TIMEOUT)
        entry = normalize_ipset_entry(entry)
        return entry in self.settings[5]

# ipset config

class FirewallClientConfigIPSet(object):
    @handle_exceptions
    def __init__(self, bus, path):
        self.bus = bus
        self.path = path
        self.dbus_obj = self.bus.get_object(config.dbus.DBUS_INTERFACE, path)
        self.fw_ipset = dbus.Interface(
            self.dbus_obj,
            dbus_interface=config.dbus.DBUS_INTERFACE_CONFIG_IPSET)
        self.fw_properties = dbus.Interface(
            self.dbus_obj, dbus_interface='org.freedesktop.DBus.Properties')

    @handle_exceptions
    def get_property(self, prop):
        return dbus_to_python(self.fw_properties.Get(
            config.dbus.DBUS_INTERFACE_CONFIG_IPSET, prop))

    @handle_exceptions
    def get_properties(self):
        return dbus_to_python(self.fw_properties.GetAll(
            config.dbus.DBUS_INTERFACE_CONFIG_IPSET))

    @handle_exceptions
    def set_property(self, prop, value):
        self.fw_properties.Set(config.dbus.DBUS_INTERFACE_CONFIG_IPSET,
                               prop, value)

    @handle_exceptions
    def getSettings(self):
        return FirewallClientIPSetSettings(list(dbus_to_python(\
                    self.fw_ipset.getSettings())))

    @handle_exceptions
    def update(self, settings):
        self.fw_ipset.update(tuple(settings.settings))

    @handle_exceptions
    def loadDefaults(self):
        self.fw_ipset.loadDefaults()

    @handle_exceptions
    def remove(self):
        self.fw_ipset.remove()

    @handle_exceptions
    def rename(self, name):
        self.fw_ipset.rename(name)

    # version

    @handle_exceptions
    def getVersion(self):
        return self.fw_ipset.getVersion()

    @handle_exceptions
    def setVersion(self, version):
        self.fw_ipset.setVersion(version)

    # short

    @handle_exceptions
    def getShort(self):
        return self.fw_ipset.getShort()

    @handle_exceptions
    def setShort(self, short):
        self.fw_ipset.setShort(short)

    # description

    @handle_exceptions
    def getDescription(self):
        return self.fw_ipset.getDescription()

    @handle_exceptions
    def setDescription(self, description):
        self.fw_ipset.setDescription(description)

    # entry

    @handle_exceptions
    def getEntries(self):
        return self.fw_ipset.getEntries()

    @handle_exceptions
    def setEntries(self, entries):
        self.fw_ipset.setEntries(entries)

    @handle_exceptions
    def addEntry(self, entry):
        self.fw_ipset.addEntry(entry)

    @handle_exceptions
    def removeEntry(self, entry):
        self.fw_ipset.removeEntry(entry)

    @handle_exceptions
    def queryEntry(self, entry):
        return self.fw_ipset.queryEntry(entry)

# helper config settings

class FirewallClientHelperSettings(object):
    @handle_exceptions
    def __init__(self, settings=None):
        if settings:
            self.settings = settings
        else:
            self.settings = ["", "", "", "", "", [ ]]

    @handle_exceptions
    def __repr__(self):
        return '%s(%r)' % (self.__class__, self.settings)

    @handle_exceptions
    def getVersion(self):
        return self.settings[0]
    @handle_exceptions
    def setVersion(self, version):
        self.settings[0] = version

    @handle_exceptions
    def getShort(self):
        return self.settings[1]
    @handle_exceptions
    def setShort(self, short):
        self.settings[1] = short

    @handle_exceptions
    def getDescription(self):
        return self.settings[2]
    @handle_exceptions
    def setDescription(self, description):
        self.settings[2] = description

    @handle_exceptions
    def getFamily(self):
        return self.settings[3]
    @handle_exceptions
    def setFamily(self, ipv):
        if ipv is None:
            self.settings[3] = ""
        self.settings[3] = ipv

    @handle_exceptions
    def getModule(self):
        return self.settings[4]
    @handle_exceptions
    def setModule(self, module):
        self.settings[4] = module

    @handle_exceptions
    def getPorts(self):
        return self.settings[5]
    @handle_exceptions
    def setPorts(self, ports):
        self.settings[5] = ports
    @handle_exceptions
    def addPort(self, port, protocol):
        if (port,protocol) not in self.settings[5]:
            self.settings[5].append((port,protocol))
        else:
            raise FirewallError(errors.ALREADY_ENABLED,
                                "'%s:%s'" % (port, protocol))
    @handle_exceptions
    def removePort(self, port, protocol):
        if (port,protocol) in self.settings[5]:
            self.settings[5].remove((port,protocol))
        else:
            raise FirewallError(errors.NOT_ENABLED,
                                "'%s:%s'" % (port, protocol))
    @handle_exceptions
    def queryPort(self, port, protocol):
        return (port,protocol) in self.settings[5]

# helper config

class FirewallClientConfigHelper(object):
    @handle_exceptions
    def __init__(self, bus, path):
        self.bus = bus
        self.path = path
        self.dbus_obj = self.bus.get_object(config.dbus.DBUS_INTERFACE, path)
        self.fw_helper = dbus.Interface(
            self.dbus_obj,
            dbus_interface=config.dbus.DBUS_INTERFACE_CONFIG_HELPER)
        self.fw_properties = dbus.Interface(
            self.dbus_obj, dbus_interface='org.freedesktop.DBus.Properties')

    @handle_exceptions
    def get_property(self, prop):
        return dbus_to_python(self.fw_properties.Get(
            config.dbus.DBUS_INTERFACE_CONFIG_HELPER, prop))

    @handle_exceptions
    def get_properties(self):
        return dbus_to_python(self.fw_properties.GetAll(
            config.dbus.DBUS_INTERFACE_CONFIG_HELPER))

    @handle_exceptions
    def set_property(self, prop, value):
        self.fw_properties.Set(config.dbus.DBUS_INTERFACE_CONFIG_HELPER,
                               prop, value)

    @handle_exceptions
    def getSettings(self):
        return FirewallClientHelperSettings(list(dbus_to_python(\
                    self.fw_helper.getSettings())))

    @handle_exceptions
    def update(self, settings):
        self.fw_helper.update(tuple(settings.settings))

    @handle_exceptions
    def loadDefaults(self):
        self.fw_helper.loadDefaults()

    @handle_exceptions
    def remove(self):
        self.fw_helper.remove()

    @handle_exceptions
    def rename(self, name):
        self.fw_helper.rename(name)

    # version

    @handle_exceptions
    def getVersion(self):
        return self.fw_helper.getVersion()

    @handle_exceptions
    def setVersion(self, version):
        self.fw_helper.setVersion(version)

    # short

    @handle_exceptions
    def getShort(self):
        return self.fw_helper.getShort()

    @handle_exceptions
    def setShort(self, short):
        self.fw_helper.setShort(short)

    # description

    @handle_exceptions
    def getDescription(self):
        return self.fw_helper.getDescription()

    @handle_exceptions
    def setDescription(self, description):
        self.fw_helper.setDescription(description)

    # port

    @handle_exceptions
    def getPorts(self):
        return self.fw_helper.getPorts()

    @handle_exceptions
    def setPorts(self, ports):
        self.fw_helper.setPorts(ports)

    @handle_exceptions
    def addPort(self, port, protocol):
        self.fw_helper.addPort(port, protocol)

    @handle_exceptions
    def removePort(self, port, protocol):
        self.fw_helper.removePort(port, protocol)

    @handle_exceptions
    def queryPort(self, port, protocol):
        return self.fw_helper.queryPort(port, protocol)

    # family

    @handle_exceptions
    def getFamily(self):
        return self.fw_helper.getFamily()

    @handle_exceptions
    def setFamily(self, ipv):
        if ipv is None:
            self.fw_helper.setFamily("")
        self.fw_helper.setFamily(ipv)

    # module

    @handle_exceptions
    def getModule(self):
        return self.fw_helper.getModule()

    @handle_exceptions
    def setModule(self, module):
        self.fw_helper.setModule(module)

# service config

class FirewallClientConfigService(object):
    @handle_exceptions
    def __init__(self, bus, path):
        self.bus = bus
        self.path = path
        self.dbus_obj = self.bus.get_object(config.dbus.DBUS_INTERFACE, path)
        self.fw_service = dbus.Interface(
            self.dbus_obj,
            dbus_interface=config.dbus.DBUS_INTERFACE_CONFIG_SERVICE)
        self.fw_properties = dbus.Interface(
            self.dbus_obj, dbus_interface='org.freedesktop.DBus.Properties')

    @handle_exceptions
    def get_property(self, prop):
        return dbus_to_python(self.fw_properties.Get(
            config.dbus.DBUS_INTERFACE_CONFIG_SERVICE, prop))

    @handle_exceptions
    def get_properties(self):
        return dbus_to_python(self.fw_properties.GetAll(
            config.dbus.DBUS_INTERFACE_CONFIG_SERVICE))

    @handle_exceptions
    def set_property(self, prop, value):
        self.fw_properties.Set(config.dbus.DBUS_INTERFACE_CONFIG_SERVICE,
                               prop, value)

    @handle_exceptions
    def getSettings(self):
        return FirewallClientServiceSettings(dbus_to_python(
                    self.fw_service.getSettings2()))

    @handle_exceptions
    def update(self, settings):
        self.fw_service.update2(settings.getSettingsDbusDict())

    @handle_exceptions
    def loadDefaults(self):
        self.fw_service.loadDefaults()

    @handle_exceptions
    def remove(self):
        self.fw_service.remove()

    @handle_exceptions
    def rename(self, name):
        self.fw_service.rename(name)

    # version

    @handle_exceptions
    def getVersion(self):
        return self.fw_service.getVersion()

    @handle_exceptions
    def setVersion(self, version):
        self.fw_service.setVersion(version)

    # short

    @handle_exceptions
    def getShort(self):
        return self.fw_service.getShort()

    @handle_exceptions
    def setShort(self, short):
        self.fw_service.setShort(short)

    # description

    @handle_exceptions
    def getDescription(self):
        return self.fw_service.getDescription()

    @handle_exceptions
    def setDescription(self, description):
        self.fw_service.setDescription(description)

    # port

    @handle_exceptions
    def getPorts(self):
        return self.fw_service.getPorts()

    @handle_exceptions
    def setPorts(self, ports):
        self.fw_service.setPorts(ports)

    @handle_exceptions
    def addPort(self, port, protocol):
        self.fw_service.addPort(port, protocol)

    @handle_exceptions
    def removePort(self, port, protocol):
        self.fw_service.removePort(port, protocol)

    @handle_exceptions
    def queryPort(self, port, protocol):
        return self.fw_service.queryPort(port, protocol)

    # protocol

    @handle_exceptions
    def getProtocols(self):
        return self.fw_service.getProtocols()

    @handle_exceptions
    def setProtocols(self, protocols):
        self.fw_service.setProtocols(protocols)

    @handle_exceptions
    def addProtocol(self, protocol):
        self.fw_service.addProtocol(protocol)

    @handle_exceptions
    def removeProtocol(self, protocol):
        self.fw_service.removeProtocol(protocol)

    @handle_exceptions
    def queryProtocol(self, protocol):
        return self.fw_service.queryProtocol(protocol)

    # source-port

    @handle_exceptions
    def getSourcePorts(self):
        return self.fw_service.getSourcePorts()

    @handle_exceptions
    def setSourcePorts(self, ports):
        self.fw_service.setSourcePorts(ports)

    @handle_exceptions
    def addSourcePort(self, port, protocol):
        self.fw_service.addSourcePort(port, protocol)

    @handle_exceptions
    def removeSourcePort(self, port, protocol):
        self.fw_service.removeSourcePort(port, protocol)

    @handle_exceptions
    def querySourcePort(self, port, protocol):
        return self.fw_service.querySourcePort(port, protocol)

    # module

    @handle_exceptions
    def getModules(self):
        return self.fw_service.getModules()

    @handle_exceptions
    def setModules(self, modules):
        self.fw_service.setModules(modules)

    @handle_exceptions
    def addModule(self, module):
        self.fw_service.addModule(module)

    @handle_exceptions
    def removeModule(self, module):
        self.fw_service.removeModule(module)

    @handle_exceptions
    def queryModule(self, module):
        return self.fw_service.queryModule(module)

    # destination

    @handle_exceptions
    def getDestinations(self):
        return self.fw_service.getDestinations()

    @handle_exceptions
    def setDestinations(self, destinations):
        self.fw_service.setDestinations(destinations)

    @handle_exceptions
    def getDestination(self, destination):
        return self.fw_service.getDestination(destination)

    @handle_exceptions
    def setDestination(self, destination, address):
        self.fw_service.setDestination(destination, address)

    @handle_exceptions
    def removeDestination(self, destination, address=None):
        if address is not None and self.getDestination(destination) != address:
            raise FirewallError(errors.NOT_ENABLED, "'%s:%s'" % \
                                (destination, address))
        self.fw_service.removeDestination(destination)

    @handle_exceptions
    def queryDestination(self, destination, address):
        return self.fw_service.queryDestination(destination, address)

    # include

    @handle_exceptions
    def getIncludes(self):
        return self.fw_service.getIncludes()

    @handle_exceptions
    def setIncludes(self, includes):
        self.fw_service.setIncludes(includes)

    @handle_exceptions
    def addInclude(self, include):
        self.fw_service.addInclude(include)

    @handle_exceptions
    def removeInclude(self, include):
        self.fw_service.removeInclude(include)

    @handle_exceptions
    def queryInclude(self, include):
        return self.fw_service.queryInclude(include)


# icmptype config settings

class FirewallClientIcmpTypeSettings(object):
    @handle_exceptions
    def __init__(self, settings=None):
        if settings:
            self.settings = settings
        else:
            self.settings = ["", "", "", []]

    @handle_exceptions
    def __repr__(self):
        return '%s(%r)' % (self.__class__, self.settings)

    @handle_exceptions
    def getVersion(self):
        return self.settings[0]
    @handle_exceptions
    def setVersion(self, version):
        self.settings[0] = version

    @handle_exceptions
    def getShort(self):
        return self.settings[1]
    @handle_exceptions
    def setShort(self, short):
        self.settings[1] = short

    @handle_exceptions
    def getDescription(self):
        return self.settings[2]
    @handle_exceptions
    def setDescription(self, description):
        self.settings[2] = description

    @handle_exceptions
    def getDestinations(self):
        return self.settings[3]
    @handle_exceptions
    def setDestinations(self, destinations):
        self.settings[3] = destinations
    @handle_exceptions
    def addDestination(self, destination):
        # empty means all
        if not self.settings[3]:
            raise FirewallError(errors.ALREADY_ENABLED, destination)
        elif destination not in self.settings[3]:
            self.settings[3].append(destination)
        else:
            raise FirewallError(errors.ALREADY_ENABLED, destination)
    @handle_exceptions
    def removeDestination(self, destination):
        if destination in self.settings[3]:
            self.settings[3].remove(destination)
        # empty means all
        elif not self.settings[3]:
            self.setDestinations(list(set(['ipv4','ipv6']) - \
                                      set([destination])))
        else:
            raise FirewallError(errors.NOT_ENABLED, destination)

    @handle_exceptions
    def queryDestination(self, destination):
        # empty means all
        return not self.settings[3] or \
               destination in self.settings[3]

# icmptype config

class FirewallClientConfigIcmpType(object):
    @handle_exceptions
    def __init__(self, bus, path):
        self.bus = bus
        self.path = path
        self.dbus_obj = self.bus.get_object(config.dbus.DBUS_INTERFACE, path)
        self.fw_icmptype = dbus.Interface(
            self.dbus_obj,
            dbus_interface=config.dbus.DBUS_INTERFACE_CONFIG_ICMPTYPE)
        self.fw_properties = dbus.Interface(
            self.dbus_obj, dbus_interface='org.freedesktop.DBus.Properties')

    @handle_exceptions
    def get_property(self, prop):
        return dbus_to_python(self.fw_properties.Get(
            config.dbus.DBUS_INTERFACE_CONFIG_ICMPTYPE, prop))

    @handle_exceptions
    def get_properties(self):
        return dbus_to_python(self.fw_properties.GetAll(
            config.dbus.DBUS_INTERFACE_CONFIG_ICMPTYPE))

    @handle_exceptions
    def set_property(self, prop, value):
        self.fw_properties.Set(config.dbus.DBUS_INTERFACE_CONFIG_ICMPTYPE,
                               prop, value)

    @handle_exceptions
    def getSettings(self):
        return FirewallClientIcmpTypeSettings(list(dbus_to_python(\
                    self.fw_icmptype.getSettings())))

    @handle_exceptions
    def update(self, settings):
        self.fw_icmptype.update(tuple(settings.settings))

    @handle_exceptions
    def loadDefaults(self):
        self.fw_icmptype.loadDefaults()

    @handle_exceptions
    def remove(self):
        self.fw_icmptype.remove()

    @handle_exceptions
    def rename(self, name):
        self.fw_icmptype.rename(name)

    # version

    @handle_exceptions
    def getVersion(self):
        return self.fw_icmptype.getVersion()

    @handle_exceptions
    def setVersion(self, version):
        self.fw_icmptype.setVersion(version)

    # short

    @handle_exceptions
    def getShort(self):
        return self.fw_icmptype.getShort()

    @handle_exceptions
    def setShort(self, short):
        self.fw_icmptype.setShort(short)

    # description

    @handle_exceptions
    def getDescription(self):
        return self.fw_icmptype.getDescription()

    @handle_exceptions
    def setDescription(self, description):
        self.fw_icmptype.setDescription(description)

    # destination

    @handle_exceptions
    def getDestinations(self):
        return self.fw_icmptype.getDestinations()

    @handle_exceptions
    def setDestinations(self, destinations):
        self.fw_icmptype.setDestinations(destinations)

    @handle_exceptions
    def addDestination(self, destination):
        self.fw_icmptype.addDestination(destination)

    @handle_exceptions
    def removeDestination(self, destination):
        self.fw_icmptype.removeDestination(destination)

    @handle_exceptions
    def queryDestination(self, destination):
        return self.fw_icmptype.queryDestination(destination)


# config.policies lockdown whitelist

class FirewallClientPoliciesLockdownWhitelist(object):
    @handle_exceptions
    def __init__(self, settings=None):
        if settings:
            self.settings = settings
        else:
            self.settings = [ [], [], [], [] ]

    @handle_exceptions
    def __repr__(self):
        return '%s(%r)' % (self.__class__, self.settings)

    @handle_exceptions
    def getCommands(self):
        return self.settings[0]
    @handle_exceptions
    def setCommands(self, commands):
        self.settings[0] = commands
    @handle_exceptions
    def addCommand(self, command):
        if command not in self.settings[0]:
            self.settings[0].append(command)
    @handle_exceptions
    def removeCommand(self, command):
        if command in self.settings[0]:
            self.settings[0].remove(command)
    @handle_exceptions
    def queryCommand(self, command):
        return command in self.settings[0]

    @handle_exceptions
    def getContexts(self):
        return self.settings[1]
    @handle_exceptions
    def setContexts(self, contexts):
        self.settings[1] = contexts
    @handle_exceptions
    def addContext(self, context):
        if context not in self.settings[1]:
            self.settings[1].append(context)
    @handle_exceptions
    def removeContext(self, context):
        if context in self.settings[1]:
            self.settings[1].remove(context)
    @handle_exceptions
    def queryContext(self, context):
        return context in self.settings[1]

    @handle_exceptions
    def getUsers(self):
        return self.settings[2]
    @handle_exceptions
    def setUsers(self, users):
        self.settings[2] = users
    @handle_exceptions
    def addUser(self, user):
        if user not in self.settings[2]:
            self.settings[2].append(user)
    @handle_exceptions
    def removeUser(self, user):
        if user in self.settings[2]:
            self.settings[2].remove(user)
    @handle_exceptions
    def queryUser(self, user):
        return user in self.settings[2]

    @handle_exceptions
    def getUids(self):
        return self.settings[3]
    @handle_exceptions
    def setUids(self, uids):
        self.settings[3] = uids
    @handle_exceptions
    def addUid(self, uid):
        if uid not in self.settings[3]:
            self.settings[3].append(uid)
    @handle_exceptions
    def removeUid(self, uid):
        if uid in self.settings[3]:
            self.settings[3].remove(uid)
    @handle_exceptions
    def queryUid(self, uid):
        return uid in self.settings[3]

# config.policies

class FirewallClientConfigPolicies(object):
    @handle_exceptions
    def __init__(self, bus):
        self.bus = bus
        self.dbus_obj = self.bus.get_object(config.dbus.DBUS_INTERFACE,
                                            config.dbus.DBUS_PATH_CONFIG)
        self.fw_policies = dbus.Interface(
            self.dbus_obj,
            dbus_interface=config.dbus.DBUS_INTERFACE_CONFIG_POLICIES)

    @handle_exceptions
    def getLockdownWhitelist(self):
        return FirewallClientPoliciesLockdownWhitelist( \
            list(dbus_to_python(self.fw_policies.getLockdownWhitelist())))

    @handle_exceptions
    def setLockdownWhitelist(self, settings):
        self.fw_policies.setLockdownWhitelist(tuple(settings.settings))

    # command

    @handle_exceptions
    def addLockdownWhitelistCommand(self, command):
        self.fw_policies.addLockdownWhitelistCommand(command)

    @handle_exceptions
    def removeLockdownWhitelistCommand(self, command):
        self.fw_policies.removeLockdownWhitelistCommand(command)

    @handle_exceptions
    def queryLockdownWhitelistCommand(self, command):
        return dbus_to_python(self.fw_policies.queryLockdownWhitelistCommand(command))

    @handle_exceptions
    def getLockdownWhitelistCommands(self):
        return dbus_to_python(self.fw_policies.getLockdownWhitelistCommands())

    # context

    @handle_exceptions
    def addLockdownWhitelistContext(self, context):
        self.fw_policies.addLockdownWhitelistContext(context)

    @handle_exceptions
    def removeLockdownWhitelistContext(self, context):
        self.fw_policies.removeLockdownWhitelistContext(context)

    @handle_exceptions
    def queryLockdownWhitelistContext(self, context):
        return dbus_to_python(self.fw_policies.queryLockdownWhitelistContext(context))

    @handle_exceptions
    def getLockdownWhitelistContexts(self):
        return dbus_to_python(self.fw_policies.getLockdownWhitelistContexts())

    # user

    @handle_exceptions
    def addLockdownWhitelistUser(self, user):
        self.fw_policies.addLockdownWhitelistUser(user)

    @handle_exceptions
    def removeLockdownWhitelistUser(self, user):
        self.fw_policies.removeLockdownWhitelistUser(user)

    @handle_exceptions
    def queryLockdownWhitelistUser(self, user):
        return dbus_to_python(self.fw_policies.queryLockdownWhitelistUser(user))

    @handle_exceptions
    def getLockdownWhitelistUsers(self):
        return dbus_to_python(self.fw_policies.getLockdownWhitelistUsers())

    # uid

    @handle_exceptions
    def getLockdownWhitelistUids(self):
        return dbus_to_python(self.fw_policies.getLockdownWhitelistUids())

    @handle_exceptions
    def setLockdownWhitelistUids(self, uids):
        self.fw_policies.setLockdownWhitelistUids(uids)

    @handle_exceptions
    def addLockdownWhitelistUid(self, uid):
        self.fw_policies.addLockdownWhitelistUid(uid)

    @handle_exceptions
    def removeLockdownWhitelistUid(self, uid):
        self.fw_policies.removeLockdownWhitelistUid(uid)

    @handle_exceptions
    def queryLockdownWhitelistUid(self, uid):
        return dbus_to_python(self.fw_policies.queryLockdownWhitelistUid(uid))

# config.direct

class FirewallClientDirect(object):
    @handle_exceptions
    def __init__(self, settings=None):
        if settings:
            self.settings = settings
        else:
            self.settings = [ [], [], [], ]

    @handle_exceptions
    def __repr__(self):
        return '%s(%r)' % (self.__class__, self.settings)

    @handle_exceptions
    def getAllChains(self):
        return self.settings[0]
    @handle_exceptions
    def getChains(self, ipv, table):
        return [ entry[2] for entry in self.settings[0] \
                 if entry[0] == ipv and entry[1] == table ]
    @handle_exceptions
    def setAllChains(self, chains):
        self.settings[0] = chains
    @handle_exceptions
    def addChain(self, ipv, table, chain):
        idx = (ipv, table, chain)
        if idx not in self.settings[0]:
            self.settings[0].append(idx)
    @handle_exceptions
    def removeChain(self, ipv, table, chain):
        idx = (ipv, table, chain)
        if idx in self.settings[0]:
            self.settings[0].remove(idx)
    @handle_exceptions
    def queryChain(self, ipv, table, chain):
        idx = (ipv, table, chain)
        return idx in self.settings[0]

    @handle_exceptions
    def getAllRules(self):
        return self.settings[1]
    @handle_exceptions
    def getRules(self, ipv, table, chain):
        return [ entry[3:] for entry in self.settings[1] \
                 if entry[0] == ipv and entry[1] == table \
                 and entry[2] == chain ]
    @handle_exceptions
    def setAllRules(self, rules):
        self.settings[1] = rules
    @handle_exceptions
    def addRule(self, ipv, table, chain, priority, args):
        idx = (ipv, table, chain, priority, args)
        if idx not in self.settings[1]:
            self.settings[1].append(idx)
    @handle_exceptions
    def removeRule(self, ipv, table, chain, priority, args):
        idx = (ipv, table, chain, priority, args)
        if idx in self.settings[1]:
            self.settings[1].remove(idx)
    @handle_exceptions
    def removeRules(self, ipv, table, chain):
        for idx in list(self.settings[1]):
            if idx[0] == ipv and idx[1] == table and idx[2] == chain:
                self.settings[1].remove(idx)
    @handle_exceptions
    def queryRule(self, ipv, table, chain, priority, args):
        idx = (ipv, table, chain, priority, args)
        return idx in self.settings[1]

    @handle_exceptions
    def getAllPassthroughs(self):
        return self.settings[2]
    @handle_exceptions
    def setAllPassthroughs(self, passthroughs):
        self.settings[2] = passthroughs
    @handle_exceptions
    def removeAllPassthroughs(self):
        self.settings[2] = []
    @handle_exceptions
    def getPassthroughs(self, ipv):
        return [ entry[1] for entry in self.settings[2] \
                 if entry[0] == ipv ]
    @handle_exceptions
    def addPassthrough(self, ipv, args):
        idx = (ipv, args)
        if idx not in self.settings[2]:
            self.settings[2].append(idx)
    @handle_exceptions
    def removePassthrough(self, ipv, args):
        idx = (ipv, args)
        if idx in self.settings[2]:
            self.settings[2].remove(idx)
    @handle_exceptions
    def queryPassthrough(self, ipv, args):
        idx = (ipv, args)
        return idx in self.settings[2]

# config.direct

class FirewallClientConfigDirect(object):
    @handle_exceptions
    def __init__(self, bus):
        self.bus = bus
        self.dbus_obj = self.bus.get_object(config.dbus.DBUS_INTERFACE,
                                            config.dbus.DBUS_PATH_CONFIG)
        self.fw_direct = dbus.Interface(
            self.dbus_obj,
            dbus_interface=config.dbus.DBUS_INTERFACE_CONFIG_DIRECT)

    @handle_exceptions
    def getSettings(self):
        return FirewallClientDirect( \
            list(dbus_to_python(self.fw_direct.getSettings())))

    @handle_exceptions
    def update(self, settings):
        self.fw_direct.update(tuple(settings.settings))

    # direct chain

    @handle_exceptions
    def addChain(self, ipv, table, chain):
        self.fw_direct.addChain(ipv, table, chain)

    @handle_exceptions
    def removeChain(self, ipv, table, chain):
        self.fw_direct.removeChain(ipv, table, chain)

    @handle_exceptions
    def queryChain(self, ipv, table, chain):
        return dbus_to_python(self.fw_direct.queryChain(ipv, table, chain))

    @handle_exceptions
    def getChains(self, ipv, table):
        return dbus_to_python(self.fw_direct.getChains(ipv, table))

    @handle_exceptions
    def getAllChains(self):
        return dbus_to_python(self.fw_direct.getAllChains())

    # direct rule

    @handle_exceptions
    def addRule(self, ipv, table, chain, priority, args):
        self.fw_direct.addRule(ipv, table, chain, priority, args)

    @handle_exceptions
    def removeRule(self, ipv, table, chain, priority, args):
        self.fw_direct.removeRule(ipv, table, chain, priority, args)

    @handle_exceptions
    def removeRules(self, ipv, table, chain):
        self.fw_direct.removeRules(ipv, table, chain)

    @handle_exceptions
    def queryRule(self, ipv, table, chain, priority, args):
        return dbus_to_python(self.fw_direct.queryRule(ipv, table, chain, priority, args))

    @handle_exceptions
    def getRules(self, ipv, table, chain):
        return dbus_to_python(self.fw_direct.getRules(ipv, table, chain))

    @handle_exceptions
    def getAllRules(self):
        return dbus_to_python(self.fw_direct.getAllRules())

    # tracked passthrough

    @handle_exceptions
    def addPassthrough(self, ipv, args):
        self.fw_direct.addPassthrough(ipv, args)

    @handle_exceptions
    def removePassthrough(self, ipv, args):
        self.fw_direct.removePassthrough(ipv, args)

    @handle_exceptions
    def queryPassthrough(self, ipv, args):
        return dbus_to_python(self.fw_direct.queryPassthrough(ipv, args))

    @handle_exceptions
    def getPassthroughs(self, ipv):
        return dbus_to_python(self.fw_direct.getPassthroughs(ipv))

    @handle_exceptions
    def getAllPassthroughs(self):
        return dbus_to_python(self.fw_direct.getAllPassthroughs())

# config

class FirewallClientConfig(object):
    @handle_exceptions
    def __init__(self, bus):
        self.bus = bus
        self.dbus_obj = self.bus.get_object(config.dbus.DBUS_INTERFACE,
                                            config.dbus.DBUS_PATH_CONFIG)
        self.fw_config = dbus.Interface(
            self.dbus_obj,
            dbus_interface=config.dbus.DBUS_INTERFACE_CONFIG)
        self.fw_properties = dbus.Interface(
            self.dbus_obj, dbus_interface='org.freedesktop.DBus.Properties')
        self._policies = FirewallClientConfigPolicies(self.bus)
        self._direct = FirewallClientConfigDirect(self.bus)

    # properties

    @handle_exceptions
    def get_property(self, prop):
        return dbus_to_python(self.fw_properties.Get(
            config.dbus.DBUS_INTERFACE_CONFIG, prop))

    @handle_exceptions
    def get_properties(self):
        return dbus_to_python(self.fw_properties.GetAll(
            config.dbus.DBUS_INTERFACE_CONFIG))

    @handle_exceptions
    def set_property(self, prop, value):
        self.fw_properties.Set(config.dbus.DBUS_INTERFACE_CONFIG, prop, value)

    # ipset

    @handle_exceptions
    def getIPSetNames(self):
        return dbus_to_python(self.fw_config.getIPSetNames())

    @handle_exceptions
    def listIPSets(self):
        return dbus_to_python(self.fw_config.listIPSets())

    @handle_exceptions
    def getIPSet(self, path):
        return FirewallClientConfigIPSet(self.bus, path)

    @handle_exceptions
    def getIPSetByName(self, name):
        path = dbus_to_python(self.fw_config.getIPSetByName(name))
        return FirewallClientConfigIPSet(self.bus, path)

    @handle_exceptions
    def addIPSet(self, name, settings):
        if isinstance(settings, FirewallClientIPSetSettings):
            path = self.fw_config.addIPSet(name, tuple(settings.settings))
        else:
            path = self.fw_config.addIPSet(name, tuple(settings))
        return FirewallClientConfigIPSet(self.bus, path)

    # zone

    @handle_exceptions
    def getZoneNames(self):
        return dbus_to_python(self.fw_config.getZoneNames())

    @handle_exceptions
    def listZones(self):
        return dbus_to_python(self.fw_config.listZones())

    @handle_exceptions
    def getZone(self, path):
        return FirewallClientConfigZone(self.bus, path)

    @handle_exceptions
    def getZoneByName(self, name):
        path = dbus_to_python(self.fw_config.getZoneByName(name))
        return FirewallClientConfigZone(self.bus, path)

    @handle_exceptions
    def getZoneOfInterface(self, iface):
        return dbus_to_python(self.fw_config.getZoneOfInterface(iface))

    @handle_exceptions
    def getZoneOfSource(self, source):
        return dbus_to_python(self.fw_config.getZoneOfSource(source))

    @handle_exceptions
    def addZone(self, name, settings):
        if isinstance(settings, FirewallClientZoneSettings):
            path = self.fw_config.addZone2(name, settings.getSettingsDbusDict())
        elif isinstance(settings, dict):
            path = self.fw_config.addZone2(name, settings)
        else:
            # tuple based dbus API has 16 elements. Slice what we're given down
            # to the expected size.
            path = self.fw_config.addZone(name, tuple(settings[:16]))
        return FirewallClientConfigZone(self.bus, path)

    # policy

    @handle_exceptions
    def getPolicyNames(self):
        return dbus_to_python(self.fw_config.getPolicyNames())

    @handle_exceptions
    def listPolicies(self):
        return dbus_to_python(self.fw_config.listPolicies())

    @handle_exceptions
    def getPolicy(self, path):
        return FirewallClientConfigPolicy(self.bus, path)

    @handle_exceptions
    def getPolicyByName(self, name):
        path = dbus_to_python(self.fw_config.getPolicyByName(name))
        return FirewallClientConfigPolicy(self.bus, path)

    @handle_exceptions
    def addPolicy(self, name, settings):
        if isinstance(settings, FirewallClientPolicySettings):
            path = self.fw_config.addPolicy(name, settings.getSettingsDbusDict())
        else: # dict
            path = self.fw_config.addPolicy(name, settings)
        return FirewallClientConfigPolicy(self.bus, path)

    # service

    @handle_exceptions
    def getServiceNames(self):
        return dbus_to_python(self.fw_config.getServiceNames())

    @handle_exceptions
    def listServices(self):
        return dbus_to_python(self.fw_config.listServices())

    @handle_exceptions
    def getService(self, path):
        return FirewallClientConfigService(self.bus, path)

    @handle_exceptions
    def getServiceByName(self, name):
        path = dbus_to_python(self.fw_config.getServiceByName(name))
        return FirewallClientConfigService(self.bus, path)

    @handle_exceptions
    def addService(self, name, settings):
        if isinstance(settings, FirewallClientServiceSettings):
            path = self.fw_config.addService2(name, settings.getSettingsDbusDict())
        elif type(settings) is dict:
            path = self.fw_config.addService2(name, settings)
        else:
            # tuple based dbus API has 8 elements. Slice what we're given down
            # to the expected size.
            path = self.fw_config.addService(name, tuple(settings[:8]))
        return FirewallClientConfigService(self.bus, path)

    # icmptype

    @handle_exceptions
    def getIcmpTypeNames(self):
        return dbus_to_python(self.fw_config.getIcmpTypeNames())

    @handle_exceptions
    def listIcmpTypes(self):
        return dbus_to_python(self.fw_config.listIcmpTypes())

    @handle_exceptions
    def getIcmpType(self, path):
        return FirewallClientConfigIcmpType(self.bus, path)

    @handle_exceptions
    def getIcmpTypeByName(self, name):
        path = dbus_to_python(self.fw_config.getIcmpTypeByName(name))
        return FirewallClientConfigIcmpType(self.bus, path)

    @handle_exceptions
    def addIcmpType(self, name, settings):
        if isinstance(settings, FirewallClientIcmpTypeSettings):
            path = self.fw_config.addIcmpType(name, tuple(settings.settings))
        else:
            path = self.fw_config.addIcmpType(name, tuple(settings))
        return FirewallClientConfigIcmpType(self.bus, path)

    @handle_exceptions
    def policies(self):
        return self._policies

    @handle_exceptions
    def direct(self):
        return self._direct

    # helper

    @handle_exceptions
    def getHelperNames(self):
        return dbus_to_python(self.fw_config.getHelperNames())

    @handle_exceptions
    def listHelpers(self):
        return dbus_to_python(self.fw_config.listHelpers())

    @handle_exceptions
    def getHelper(self, path):
        return FirewallClientConfigHelper(self.bus, path)

    @handle_exceptions
    def getHelperByName(self, name):
        path = dbus_to_python(self.fw_config.getHelperByName(name))
        return FirewallClientConfigHelper(self.bus, path)

    @handle_exceptions
    def addHelper(self, name, settings):
        if isinstance(settings, FirewallClientHelperSettings):
            path = self.fw_config.addHelper(name, tuple(settings.settings))
        else:
            path = self.fw_config.addHelper(name, tuple(settings))
        return FirewallClientConfigHelper(self.bus, path)

#

class FirewallClient(object):
    @handle_exceptions
    def __init__(self, bus=None, wait=0, quiet=True):
        if not bus:
            dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
            try:
                self.bus = dbus.SystemBus()
            except dbus.exceptions.DBusException as e:
                raise FirewallError(errors.DBUS_ERROR,
                                    e.get_dbus_message())
        else:
            self.bus = bus

        self.bus.add_signal_receiver(
            handler_function=self._dbus_connection_changed,
            signal_name="NameOwnerChanged",
            dbus_interface="org.freedesktop.DBus",
            arg0=config.dbus.DBUS_INTERFACE)

        for interface in [ config.dbus.DBUS_INTERFACE,
                           config.dbus.DBUS_INTERFACE_IPSET,
                           config.dbus.DBUS_INTERFACE_ZONE,
                           config.dbus.DBUS_INTERFACE_POLICY,
                           config.dbus.DBUS_INTERFACE_DIRECT,
                           config.dbus.DBUS_INTERFACE_POLICIES,
                           config.dbus.DBUS_INTERFACE_CONFIG,
                           config.dbus.DBUS_INTERFACE_CONFIG_IPSET,
                           config.dbus.DBUS_INTERFACE_CONFIG_ZONE,
                           config.dbus.DBUS_INTERFACE_CONFIG_POLICY,
                           config.dbus.DBUS_INTERFACE_CONFIG_SERVICE,
                           config.dbus.DBUS_INTERFACE_CONFIG_HELPER,
                           config.dbus.DBUS_INTERFACE_CONFIG_DIRECT,
                           config.dbus.DBUS_INTERFACE_CONFIG_ICMPTYPE,
                           config.dbus.DBUS_INTERFACE_CONFIG_POLICIES ]:
            self.bus.add_signal_receiver(self._signal_receiver,
                                         dbus_interface=interface,
                                         interface_keyword='interface',
                                         member_keyword='member',
                                         path_keyword='path')

        # callbacks
        self._callback = { }
        self._callbacks = {
            # client callbacks
            "connection-changed": "connection-changed",
            "connection-established": "connection-established",
            "connection-lost": "connection-lost",
            # firewalld callbacks
            "log-denied-changed": "LogDeniedChanged",
            "default-zone-changed": "DefaultZoneChanged",
            "panic-mode-enabled": "PanicModeEnabled",
            "panic-mode-disabled": "PanicModeDisabled",
            "reloaded": "Reloaded",
            "service-added": "ServiceAdded",
            "service-removed": "ServiceRemoved",
            "port-added": "PortAdded",
            "port-removed": "PortRemoved",
            "source-port-added": "SourcePortAdded",
            "source-port-removed": "SourcePortRemoved",
            "protocol-added": "ProtocolAdded",
            "protocol-removed": "ProtocolRemoved",
            "masquerade-added": "MasqueradeAdded",
            "masquerade-removed": "MasqueradeRemoved",
            "forward-port-added": "ForwardPortAdded",
            "forward-port-removed": "ForwardPortRemoved",
            "icmp-block-added": "IcmpBlockAdded",
            "icmp-block-removed": "IcmpBlockRemoved",
            "icmp-block-inversion-added": "IcmpBlockInversionAdded",
            "icmp-block-inversion-removed": "IcmpBlockInversionRemoved",
            "richrule-added": "RichRuleAdded",
            "richrule-removed": "RichRuleRemoved",
            "interface-added": "InterfaceAdded",
            "interface-removed": "InterfaceRemoved",
            "zone-changed": "ZoneOfInterfaceChanged", # DEPRECATED, use zone-of-interface-changed instead
            "zone-of-interface-changed": "ZoneOfInterfaceChanged",
            "source-added": "SourceAdded",
            "source-removed": "SourceRemoved",
            "zone-of-source-changed": "ZoneOfSourceChanged",
            "zone-updated": "ZoneUpdated",
            "policy-updated": "PolicyUpdated",
            # ipset callbacks
            "ipset-entry-added": "EntryAdded",
            "ipset-entry-removed": "EntryRemoved",
            # direct callbacks
            "direct:chain-added": "ChainAdded",
            "direct:chain-removed": "ChainRemoved",
            "direct:rule-added": "RuleAdded",
            "direct:rule-removed": "RuleRemoved",
            "direct:passthrough-added": "PassthroughAdded",
            "direct:passthrough-removed": "PassthroughRemoved",
            "config:direct:updated": "config:direct:Updated",
            # policy callbacks
            "lockdown-enabled": "LockdownEnabled",
            "lockdown-disabled": "LockdownDisabled",
            "lockdown-whitelist-command-added": "LockdownWhitelistCommandAdded",
            "lockdown-whitelist-command-removed": "LockdownWhitelistCommandRemoved",
            "lockdown-whitelist-context-added": "LockdownWhitelistContextAdded",
            "lockdown-whitelist-context-removed": "LockdownWhitelistContextRemoved",
            "lockdown-whitelist-uid-added": "LockdownWhitelistUidAdded",
            "lockdown-whitelist-uid-removed": "LockdownWhitelistUidRemoved",
            "lockdown-whitelist-user-added": "LockdownWhitelistUserAdded",
            "lockdown-whitelist-user-removed": "LockdownWhitelistUserRemoved",
            # firewalld.config callbacks
            "config:policies:lockdown-whitelist-updated": "config:policies:LockdownWhitelistUpdated",
            "config:ipset-added": "config:IPSetAdded",
            "config:ipset-updated": "config:IPSetUpdated",
            "config:ipset-removed": "config:IPSetRemoved",
            "config:ipset-renamed": "config:IPSetRenamed",
            "config:zone-added": "config:ZoneAdded",
            "config:zone-updated": "config:ZoneUpdated",
            "config:zone-removed": "config:ZoneRemoved",
            "config:zone-renamed": "config:ZoneRenamed",
            "config:policy-added": "config:PolicyAdded",
            "config:policy-updated": "config:PolicyUpdated",
            "config:policy-removed": "config:PolicyRemoved",
            "config:policy-renamed": "config:PolicyRenamed",
            "config:service-added": "config:ServiceAdded",
            "config:service-updated": "config:ServiceUpdated",
            "config:service-removed": "config:ServiceRemoved",
            "config:service-renamed": "config:ServiceRenamed",
            "config:icmptype-added": "config:IcmpTypeAdded",
            "config:icmptype-updated": "config:IcmpTypeUpdated",
            "config:icmptype-removed": "config:IcmpTypeRemoved",
            "config:icmptype-renamed": "config:IcmpTypeRenamed",
            "config:helper-added": "config:HelperAdded",
            "config:helper-updated": "config:HelperUpdated",
            "config:helper-removed": "config:HelperRemoved",
            "config:helper-renamed": "config:HelperRenamed",
            }

        # initialize variables used for connection
        self._init_vars()

        self.quiet = quiet

        if wait > 0:
            # connect in one second
            GLib.timeout_add_seconds(wait, self._connection_established)
        else:
            self._connection_established()

    @handle_exceptions
    def _init_vars(self):
        self.fw = None
        self.fw_ipset = None
        self.fw_zone = None
        self.fw_policy = None
        self.fw_helper = None
        self.fw_direct = None
        self.fw_properties = None
        self._config = None
        self.connected = False

    @handle_exceptions
    def getExceptionHandler(self):
        return exception_handler

    @handle_exceptions
    def setExceptionHandler(self, handler):
        global exception_handler
        exception_handler = handler

    @handle_exceptions
    def getNotAuthorizedLoop(self):
        return not_authorized_loop

    @handle_exceptions
    def setNotAuthorizedLoop(self, enable):
        global not_authorized_loop
        not_authorized_loop = enable

    @handle_exceptions
    def connect(self, name, callback, *args):
        if name in self._callbacks:
            self._callback[self._callbacks[name]] = (callback, args)
        else:
            raise ValueError("Unknown callback name '%s'" % name)

    @handle_exceptions
    def _dbus_connection_changed(self, name, old_owner, new_owner):
        if name != config.dbus.DBUS_INTERFACE:
            return

        if new_owner:
            # connection established
            self._connection_established()
        else:
            # connection lost
            self._connection_lost()

    @handle_exceptions
    def _connection_established(self):
        try:
            self.dbus_obj = self.bus.get_object(config.dbus.DBUS_INTERFACE,
                                                config.dbus.DBUS_PATH)
            self.fw = dbus.Interface(self.dbus_obj,
                                     dbus_interface=config.dbus.DBUS_INTERFACE)
            self.fw_ipset = dbus.Interface(
                self.dbus_obj, dbus_interface=config.dbus.DBUS_INTERFACE_IPSET)
            self.fw_zone = dbus.Interface(
                self.dbus_obj,
                dbus_interface=config.dbus.DBUS_INTERFACE_ZONE)
            self.fw_policy = dbus.Interface(
                self.dbus_obj,
                dbus_interface=config.dbus.DBUS_INTERFACE_POLICY)
            self.fw_direct = dbus.Interface(
                self.dbus_obj, dbus_interface=config.dbus.DBUS_INTERFACE_DIRECT)
            self.fw_policies = dbus.Interface(
                self.dbus_obj,
                dbus_interface=config.dbus.DBUS_INTERFACE_POLICIES)
            self.fw_properties = dbus.Interface(
                self.dbus_obj, dbus_interface='org.freedesktop.DBus.Properties')
        except dbus.exceptions.DBusException as e:
            # ignore dbus errors
            if not self.quiet:
                print ("DBusException", e.get_dbus_message())
            return
        except Exception as e:
            if not self.quiet:
                print ("Exception", e)
            return
        self._config = FirewallClientConfig(self.bus)
        self.connected = True
        self._signal_receiver(member="connection-established",
                              interface=config.dbus.DBUS_INTERFACE)
        self._signal_receiver(member="connection-changed",
                              interface=config.dbus.DBUS_INTERFACE)

    @handle_exceptions
    def _connection_lost(self):
        self._init_vars()
        self._signal_receiver(member="connection-lost",
                              interface=config.dbus.DBUS_INTERFACE)
        self._signal_receiver(member="connection-changed",
                              interface=config.dbus.DBUS_INTERFACE)

    @handle_exceptions
    def _signal_receiver(self, *args, **kwargs):
        if "member" not in kwargs or "interface" not in kwargs:
            return

        signal = kwargs["member"]
        interface = kwargs["interface"]

        # config signals need special treatment
        # pimp signal name
        if interface.startswith(config.dbus.DBUS_INTERFACE_CONFIG_ZONE):
            signal = "config:Zone" + signal
        if interface.startswith(config.dbus.DBUS_INTERFACE_CONFIG_POLICY):
            signal = "config:Policy" + signal
        elif interface.startswith(config.dbus.DBUS_INTERFACE_CONFIG_IPSET):
            signal = "config:IPSet" + signal
        elif interface.startswith(config.dbus.DBUS_INTERFACE_CONFIG_SERVICE):
            signal = "config:Service" + signal
        elif interface.startswith(config.dbus.DBUS_INTERFACE_CONFIG_ICMPTYPE):
            signal = "config:IcmpType" + signal
        elif interface.startswith(config.dbus.DBUS_INTERFACE_CONFIG_HELPER):
            signal = "config:Helper" + signal
        elif interface == config.dbus.DBUS_INTERFACE_CONFIG:
            signal = "config:" + signal
        elif interface == config.dbus.DBUS_INTERFACE_CONFIG_POLICIES:
            signal = "config:policies:" + signal
        elif interface == config.dbus.DBUS_INTERFACE_CONFIG_DIRECT:
            signal = "config:direct:" + signal

        cb = None
        for callback in self._callbacks:
            if self._callbacks[callback] == signal and \
                    self._callbacks[callback] in self._callback:
                cb = self._callback[self._callbacks[callback]]
        if cb is None:
            return

        # call back with args converted to python types ...
        cb_args = [ dbus_to_python(arg) for arg in args ]
        try:
            if cb[1]:
                # add call data
                cb_args.extend(cb[1])
            # call back
            cb[0](*cb_args)
        except Exception as msg:
            print(msg)

    @handle_exceptions
    def config(self):
        return self._config

    @handle_exceptions
    def reload(self):
        self.fw.reload()

    @handle_exceptions
    def complete_reload(self):
        self.fw.completeReload()

    @handle_exceptions
    def runtimeToPermanent(self):
        self.fw.runtimeToPermanent()

    @handle_exceptions
    def checkPermanentConfig(self):
        self.fw.checkPermanentConfig()

    @handle_exceptions
    def get_property(self, prop):
        return dbus_to_python(self.fw_properties.Get(
            config.dbus.DBUS_INTERFACE, prop))

    @handle_exceptions
    def get_properties(self):
        return dbus_to_python(self.fw_properties.GetAll(
            config.dbus.DBUS_INTERFACE))

    @handle_exceptions
    def set_property(self, prop, value):
        self.fw_properties.Set(config.dbus.DBUS_INTERFACE, prop, value)

    # panic mode

    @handle_exceptions
    def enablePanicMode(self):
        self.fw.enablePanicMode()
    
    @handle_exceptions
    def disablePanicMode(self):
        self.fw.disablePanicMode()

    @handle_exceptions
    def queryPanicMode(self):
        return dbus_to_python(self.fw.queryPanicMode())

    # list functions

    @handle_exceptions
    def getZoneSettings(self, zone):
        return FirewallClientZoneSettings(dbus_to_python(self.fw_zone.getZoneSettings2(zone)))

    @handle_exceptions
    def getIPSets(self):
        return dbus_to_python(self.fw_ipset.getIPSets())

    @handle_exceptions
    def getIPSetSettings(self, ipset):
        return FirewallClientIPSetSettings(list(dbus_to_python(\
                    self.fw_ipset.getIPSetSettings(ipset))))

    @handle_exceptions
    def addEntry(self, ipset, entry):
        self.fw_ipset.addEntry(ipset, entry)

    @handle_exceptions
    def getEntries(self, ipset):
        return self.fw_ipset.getEntries(ipset)

    @handle_exceptions
    def setEntries(self, ipset, entries):
        return self.fw_ipset.setEntries(ipset, entries)

    @handle_exceptions
    def removeEntry(self, ipset, entry):
        self.fw_ipset.removeEntry(ipset, entry)

    @handle_exceptions
    def queryEntry(self, ipset, entry):
        return dbus_to_python(self.fw_ipset.queryEntry(ipset, entry))

    @handle_exceptions
    def listServices(self):
        return dbus_to_python(self.fw.listServices())

    @handle_exceptions
    def getServiceSettings(self, service):
        return FirewallClientServiceSettings(dbus_to_python(
                    self.fw.getServiceSettings2(service)))

    @handle_exceptions
    def listIcmpTypes(self):
        return dbus_to_python(self.fw.listIcmpTypes())

    @handle_exceptions
    def getIcmpTypeSettings(self, icmptype):
        return FirewallClientIcmpTypeSettings(list(dbus_to_python(\
                    self.fw.getIcmpTypeSettings(icmptype))))

    @handle_exceptions
    def getHelpers(self):
        return dbus_to_python(self.fw.getHelpers())

    @handle_exceptions
    def getHelperSettings(self, helper):
        return FirewallClientHelperSettings(list(dbus_to_python(\
                    self.fw.getHelperSettings(helper))))

    # automatic helper setting

    @handle_exceptions
    def getAutomaticHelpers(self):
        return dbus_to_python(self.fw.getAutomaticHelpers())

    @handle_exceptions
    def setAutomaticHelpers(self, value):
        self.fw.setAutomaticHelpers(value)

    # log denied

    @handle_exceptions
    def getLogDenied(self):
        return dbus_to_python(self.fw.getLogDenied())

    @handle_exceptions
    def setLogDenied(self, value):
        self.fw.setLogDenied(value)

    # default zone

    @handle_exceptions
    def getDefaultZone(self):
        return dbus_to_python(self.fw.getDefaultZone())

    @handle_exceptions
    def setDefaultZone(self, zone):
        self.fw.setDefaultZone(zone)

    # zone

    @handle_exceptions
    def setZoneSettings(self, zone, settings):
        self.fw_zone.setZoneSettings2(zone, settings.getRuntimeSettingsDbusDict())

    @handle_exceptions
    def getZones(self):
        return dbus_to_python(self.fw_zone.getZones())

    @handle_exceptions
    def getActiveZones(self):
        return dbus_to_python(self.fw_zone.getActiveZones())

    @handle_exceptions
    def getZoneOfInterface(self, interface):
        return dbus_to_python(self.fw_zone.getZoneOfInterface(interface))

    @handle_exceptions
    def getZoneOfSource(self, source):
        return dbus_to_python(self.fw_zone.getZoneOfSource(source))

    @handle_exceptions
    def isImmutable(self, zone):
        return dbus_to_python(self.fw_zone.isImmutable(zone))

    # policy

    @handle_exceptions
    def getPolicySettings(self, policy):
        return FirewallClientPolicySettings(dbus_to_python(self.fw_policy.getPolicySettings(policy)))

    @handle_exceptions
    def setPolicySettings(self, policy, settings):
        self.fw_policy.setPolicySettings(policy, settings.getRuntimeSettingsDbusDict())

    @handle_exceptions
    def getPolicies(self):
        return dbus_to_python(self.fw_policy.getPolicies())

    @handle_exceptions
    def getActivePolicies(self):
        return dbus_to_python(self.fw_policy.getActivePolicies())

    @handle_exceptions
    def isPolicyImmutable(self, policy):
        return dbus_to_python(self.fw_policy.isImmutable(policy))

    # interfaces

    @handle_exceptions
    def addInterface(self, zone, interface):
        return dbus_to_python(self.fw_zone.addInterface(zone, interface))

    @handle_exceptions
    def changeZone(self, zone, interface): # DEPRECATED
        return dbus_to_python(self.fw_zone.changeZone(zone, interface))

    @handle_exceptions
    def changeZoneOfInterface(self, zone, interface):
        return dbus_to_python(self.fw_zone.changeZoneOfInterface(zone,
                                                                 interface))

    @handle_exceptions
    def getInterfaces(self, zone):
        return dbus_to_python(self.fw_zone.getInterfaces(zone))

    @handle_exceptions
    def queryInterface(self, zone, interface):
        return dbus_to_python(self.fw_zone.queryInterface(zone, interface))

    @handle_exceptions
    def removeInterface(self, zone, interface):
        return dbus_to_python(self.fw_zone.removeInterface(zone, interface))

    # sources

    @handle_exceptions
    def addSource(self, zone, source):
        return dbus_to_python(self.fw_zone.addSource(zone, source))

    @handle_exceptions
    def changeZoneOfSource(self, zone, source):
        return dbus_to_python(self.fw_zone.changeZoneOfSource(zone, source))

    @handle_exceptions
    def getSources(self, zone):
        return dbus_to_python(self.fw_zone.getSources(zone))

    @handle_exceptions
    def querySource(self, zone, source):
        return dbus_to_python(self.fw_zone.querySource(zone, source))

    @handle_exceptions
    def removeSource(self, zone, source):
        return dbus_to_python(self.fw_zone.removeSource(zone, source))

    # rich rules

    @handle_exceptions
    def addRichRule(self, zone, rule, timeout=0):
        return dbus_to_python(self.fw_zone.addRichRule(zone, rule, timeout))

    @handle_exceptions
    def getRichRules(self, zone):
        return dbus_to_python(self.fw_zone.getRichRules(zone))

    @handle_exceptions
    def queryRichRule(self, zone, rule):
        return dbus_to_python(self.fw_zone.queryRichRule(zone, rule))

    @handle_exceptions
    def removeRichRule(self, zone, rule):
        return dbus_to_python(self.fw_zone.removeRichRule(zone, rule))

    # services

    @handle_exceptions
    def addService(self, zone, service, timeout=0):
        return dbus_to_python(self.fw_zone.addService(zone, service, timeout))

    @handle_exceptions
    def getServices(self, zone):
        return dbus_to_python(self.fw_zone.getServices(zone))

    @handle_exceptions
    def queryService(self, zone, service):
        return dbus_to_python(self.fw_zone.queryService(zone, service))

    @handle_exceptions
    def removeService(self, zone, service):
        return dbus_to_python(self.fw_zone.removeService(zone, service))

    # ports

    @handle_exceptions
    def addPort(self, zone, port, protocol, timeout=0):
        return dbus_to_python(self.fw_zone.addPort(zone, port, protocol, timeout))

    @handle_exceptions
    def getPorts(self, zone):
        return dbus_to_python(self.fw_zone.getPorts(zone))

    @handle_exceptions
    def queryPort(self, zone, port, protocol):
        return dbus_to_python(self.fw_zone.queryPort(zone, port, protocol))

    @handle_exceptions
    def removePort(self, zone, port, protocol):
        return dbus_to_python(self.fw_zone.removePort(zone, port, protocol))

    # protocols

    @handle_exceptions
    def addProtocol(self, zone, protocol, timeout=0):
        return dbus_to_python(self.fw_zone.addProtocol(zone, protocol, timeout))

    @handle_exceptions
    def getProtocols(self, zone):
        return dbus_to_python(self.fw_zone.getProtocols(zone))

    @handle_exceptions
    def queryProtocol(self, zone, protocol):
        return dbus_to_python(self.fw_zone.queryProtocol(zone, protocol))

    @handle_exceptions
    def removeProtocol(self, zone, protocol):
        return dbus_to_python(self.fw_zone.removeProtocol(zone, protocol))

    # forward

    @handle_exceptions
    def addForward(self, zone):
        self.fw_zone.setZoneSettings2(zone, {"forward": True})

    @handle_exceptions
    def queryForward(self, zone):
        return dbus_to_python(self.fw_zone.getZoneSettings2(zone))["forward"]

    @handle_exceptions
    def removeForward(self, zone):
        self.fw_zone.setZoneSettings2(zone, {"forward": False})

    # masquerade

    @handle_exceptions
    def addMasquerade(self, zone, timeout=0):
        return dbus_to_python(self.fw_zone.addMasquerade(zone, timeout))

    @handle_exceptions
    def queryMasquerade(self, zone):
        return dbus_to_python(self.fw_zone.queryMasquerade(zone))

    @handle_exceptions
    def removeMasquerade(self, zone):
        return dbus_to_python(self.fw_zone.removeMasquerade(zone))

    # forward ports

    @handle_exceptions
    def addForwardPort(self, zone, port, protocol, toport, toaddr,
                       timeout=0):
        if toport is None:
            toport = ""
        if toaddr is None:
            toaddr = ""
        return dbus_to_python(self.fw_zone.addForwardPort(zone, port, protocol,
                                                          toport, toaddr,
                                                          timeout))

    @handle_exceptions
    def getForwardPorts(self, zone):
        return dbus_to_python(self.fw_zone.getForwardPorts(zone))

    @handle_exceptions
    def queryForwardPort(self, zone, port, protocol, toport, toaddr):
        if toport is None:
            toport = ""
        if toaddr is None:
            toaddr = ""
        return dbus_to_python(self.fw_zone.queryForwardPort(zone,
                                                            port, protocol,
                                                            toport, toaddr))

    @handle_exceptions
    def removeForwardPort(self, zone, port, protocol, toport, toaddr):
        if toport is None:
            toport = ""
        if toaddr is None:
            toaddr = ""
        return dbus_to_python(self.fw_zone.removeForwardPort(zone,
                                                             port, protocol,
                                                             toport, toaddr))

    # source ports

    @handle_exceptions
    def addSourcePort(self, zone, port, protocol, timeout=0):
        return dbus_to_python(self.fw_zone.addSourcePort(zone, port, protocol,
                                                         timeout))

    @handle_exceptions
    def getSourcePorts(self, zone):
        return dbus_to_python(self.fw_zone.getSourcePorts(zone))

    @handle_exceptions
    def querySourcePort(self, zone, port, protocol):
        return dbus_to_python(self.fw_zone.querySourcePort(zone, port, protocol))

    @handle_exceptions
    def removeSourcePort(self, zone, port, protocol):
        return dbus_to_python(self.fw_zone.removeSourcePort(zone, port,
                                                            protocol))

    # icmpblock

    @handle_exceptions
    def addIcmpBlock(self, zone, icmp, timeout=0):
        return dbus_to_python(self.fw_zone.addIcmpBlock(zone, icmp, timeout))

    @handle_exceptions
    def getIcmpBlocks(self, zone):
        return dbus_to_python(self.fw_zone.getIcmpBlocks(zone))

    @handle_exceptions
    def queryIcmpBlock(self, zone, icmp):
        return dbus_to_python(self.fw_zone.queryIcmpBlock(zone, icmp))

    @handle_exceptions
    def removeIcmpBlock(self, zone, icmp):
        return dbus_to_python(self.fw_zone.removeIcmpBlock(zone, icmp))

    # icmp block inversion

    @handle_exceptions
    def addIcmpBlockInversion(self, zone):
        return dbus_to_python(self.fw_zone.addIcmpBlockInversion(zone))

    @handle_exceptions
    def queryIcmpBlockInversion(self, zone):
        return dbus_to_python(self.fw_zone.queryIcmpBlockInversion(zone))

    @handle_exceptions
    def removeIcmpBlockInversion(self, zone):
        return dbus_to_python(self.fw_zone.removeIcmpBlockInversion(zone))

    # direct chain

    @handle_exceptions
    def addChain(self, ipv, table, chain):
        self.fw_direct.addChain(ipv, table, chain)

    @handle_exceptions
    def removeChain(self, ipv, table, chain):
        self.fw_direct.removeChain(ipv, table, chain)

    @handle_exceptions
    def queryChain(self, ipv, table, chain):
        return dbus_to_python(self.fw_direct.queryChain(ipv, table, chain))

    @handle_exceptions
    def getChains(self, ipv, table):
        return dbus_to_python(self.fw_direct.getChains(ipv, table))

    @handle_exceptions
    def getAllChains(self):
        return dbus_to_python(self.fw_direct.getAllChains())

    # direct rule

    @handle_exceptions
    def addRule(self, ipv, table, chain, priority, args):
        self.fw_direct.addRule(ipv, table, chain, priority, args)

    @handle_exceptions
    def removeRule(self, ipv, table, chain, priority, args):
        self.fw_direct.removeRule(ipv, table, chain, priority, args)

    @handle_exceptions
    def removeRules(self, ipv, table, chain):
        self.fw_direct.removeRules(ipv, table, chain)

    @handle_exceptions
    def queryRule(self, ipv, table, chain, priority, args):
        return dbus_to_python(self.fw_direct.queryRule(ipv, table, chain, priority, args))

    @handle_exceptions
    def getRules(self, ipv, table, chain):
        return dbus_to_python(self.fw_direct.getRules(ipv, table, chain))

    @handle_exceptions
    def getAllRules(self):
        return dbus_to_python(self.fw_direct.getAllRules())

    # direct passthrough

    @handle_exceptions
    def passthrough(self, ipv, args):
        return dbus_to_python(self.fw_direct.passthrough(ipv, args))

    # tracked passthrough

    @handle_exceptions
    def getAllPassthroughs(self):
        return dbus_to_python(self.fw_direct.getAllPassthroughs())

    @handle_exceptions
    def removeAllPassthroughs(self):
        self.fw_direct.removeAllPassthroughs()

    @handle_exceptions
    def getPassthroughs(self, ipv):
        return dbus_to_python(self.fw_direct.getPassthroughs(ipv))

    @handle_exceptions
    def addPassthrough(self, ipv, args):
        self.fw_direct.addPassthrough(ipv, args)

    @handle_exceptions
    def removePassthrough(self, ipv, args):
        self.fw_direct.removePassthrough(ipv, args)

    @handle_exceptions
    def queryPassthrough(self, ipv, args):
        return dbus_to_python(self.fw_direct.queryPassthrough(ipv, args))

    # lockdown

    @handle_exceptions
    def enableLockdown(self):
        self.fw_policies.enableLockdown()

    @handle_exceptions
    def disableLockdown(self):
        self.fw_policies.disableLockdown()

    @handle_exceptions
    def queryLockdown(self):
        return dbus_to_python(self.fw_policies.queryLockdown())

    # policies

    # lockdown white list commands

    @handle_exceptions
    def addLockdownWhitelistCommand(self, command):
        self.fw_policies.addLockdownWhitelistCommand(command)

    @handle_exceptions
    def getLockdownWhitelistCommands(self):
        return dbus_to_python(self.fw_policies.getLockdownWhitelistCommands())

    @handle_exceptions
    def queryLockdownWhitelistCommand(self, command):
        return dbus_to_python(self.fw_policies.queryLockdownWhitelistCommand(command))

    @handle_exceptions
    def removeLockdownWhitelistCommand(self, command):
        self.fw_policies.removeLockdownWhitelistCommand(command)

    # lockdown white list contexts

    @handle_exceptions
    def addLockdownWhitelistContext(self, context):
        self.fw_policies.addLockdownWhitelistContext(context)

    @handle_exceptions
    def getLockdownWhitelistContexts(self):
        return dbus_to_python(self.fw_policies.getLockdownWhitelistContexts())

    @handle_exceptions
    def queryLockdownWhitelistContext(self, context):
        return dbus_to_python(self.fw_policies.queryLockdownWhitelistContext(context))

    @handle_exceptions
    def removeLockdownWhitelistContext(self, context):
        self.fw_policies.removeLockdownWhitelistContext(context)

    # lockdown white list uids

    @handle_exceptions
    def addLockdownWhitelistUid(self, uid):
        self.fw_policies.addLockdownWhitelistUid(uid)

    @handle_exceptions
    def getLockdownWhitelistUids(self):
        return dbus_to_python(self.fw_policies.getLockdownWhitelistUids())

    @handle_exceptions
    def queryLockdownWhitelistUid(self, uid):
        return dbus_to_python(self.fw_policies.queryLockdownWhitelistUid(uid))

    @handle_exceptions
    def removeLockdownWhitelistUid(self, uid):
        self.fw_policies.removeLockdownWhitelistUid(uid)

    # lockdown white list users

    @handle_exceptions
    def addLockdownWhitelistUser(self, user):
        self.fw_policies.addLockdownWhitelistUser(user)

    @handle_exceptions
    def getLockdownWhitelistUsers(self):
        return dbus_to_python(self.fw_policies.getLockdownWhitelistUsers())

    @handle_exceptions
    def queryLockdownWhitelistUser(self, user):
        return dbus_to_python(self.fw_policies.queryLockdownWhitelistUser(user))

    @handle_exceptions
    def removeLockdownWhitelistUser(self, user):
        self.fw_policies.removeLockdownWhitelistUser(user)

    @handle_exceptions
    def authorizeAll(self):
        """ Authorize once for all polkit actions. """
        self.fw.authorizeAll()
