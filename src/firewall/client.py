# -*- coding: utf-8 -*-
#
# Copyright (C) 2009,2010,2012 Red Hat, Inc.
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

from gi.repository import GLib, GObject

# force use of pygobject3 in python-slip
import sys
sys.modules['gobject'] = GObject

import dbus.mainloop.glib
import slip.dbus

from firewall.config import *
from firewall.config.dbus import *
from firewall.dbus_utils import dbus_to_python
import dbus
from decorator import decorator
from firewall.functions import b2u
from firewall.core.rich import Rich_Rule

exception_handler = None

@decorator
def handle_exceptions(func, *args, **kwargs):
    """Decorator to handle exceptions
    """
    global exception_handler
    #while 1:
    try:
        return func(*args, **kwargs)
    except dbus.exceptions.DBusException as e:
        dbus_message = e.get_dbus_message() # returns unicode
        dbus_name = e.get_dbus_name()
        if not exception_handler:
            raise
        if "NotAuthorizedException" in dbus_name:
            exception_handler("NotAuthorizedException")
        else:
            if dbus_message:
                exception_handler(dbus_message)
            else:
                exception_handler(b2u(str(e)))
    except Exception as e:
        if not exception_handler:
            raise
        else:
            exception_handler(b2u(str(e)))

# zone config setings

class FirewallClientZoneSettings(object):
    @handle_exceptions
    def __init__(self, settings = None):
        if settings:
            self.settings = settings
        else:
            self.settings = ["", "", "", False, "", [], [], [], False, [],
                             [], [], []]

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
        return self.settings[4]
    @handle_exceptions
    def setTarget(self, target):
        self.settings[4] = target

    @handle_exceptions
    def getServices(self):
        return sorted(self.settings[5])
    @handle_exceptions
    def setServices(self, services):
        self.settings[5] = services
    @handle_exceptions
    def addService(self, service):
        if service not in self.settings[5]:
            self.settings[5].append(service)
    @handle_exceptions
    def removeService(self, service):
        if service in self.settings[5]:
            self.settings[5].remove(service)
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
    @handle_exceptions
    def removePort(self, port, protocol):
        if (port,protocol) in self.settings[6]:
            self.settings[6].remove((port,protocol))
    @handle_exceptions
    def queryPort(self, port, protocol):
        return (port,protocol) in self.settings[6]

    @handle_exceptions
    def getIcmpBlocks(self):
        return sorted(self.settings[7])
    @handle_exceptions
    def setIcmpBlocks(self, icmpblocks):
        self.settings[7] = icmpblocks
    @handle_exceptions
    def addIcmpBlock(self, icmptype):
        if icmptype not in self.settings[7]:
            self.settings[7].append(icmptype)
    @handle_exceptions
    def removeIcmpBlock(self, icmptype):
        if icmptype in self.settings[7]:
            self.settings[7].remove(icmptype)
    @handle_exceptions
    def queryIcmpBlock(self, icmptype):
        return icmptype in self.settings[7]

    @handle_exceptions
    def getMasquerade(self):
        return self.settings[8]
    @handle_exceptions
    def setMasquerade(self, masquerade):
        self.settings[8] = masquerade

    @handle_exceptions
    def getForwardPorts(self):
        return self.settings[9]
    @handle_exceptions
    def setForwardPorts(self, ports):
        self.settings[9] = ports
    @handle_exceptions
    def addForwardPort(self, port, protocol, to_port, to_addr):
        if to_port == None:
            to_port = ''
        if to_addr == None:
            to_addr = ''
        if (port,protocol,to_port,to_addr) not in self.settings[9]:
            self.settings[9].append((port,protocol,to_port,to_addr))
    @handle_exceptions
    def removeForwardPort(self, port, protocol, to_port, to_addr):
        if to_port == None:
            to_port = ''
        if to_addr == None:
            to_addr = ''
        if (port,protocol,to_port,to_addr) in self.settings[9]:
            self.settings[9].remove((port,protocol,to_port,to_addr))
    @handle_exceptions
    def queryForwardPort(self, port, protocol, to_port, to_addr):
        if to_port == None:
            to_port = ''
        if to_addr == None:
            to_addr = ''
        return (port,protocol,to_port,to_addr) in self.settings[9]

    @handle_exceptions
    def getInterfaces(self):
        return sorted(self.settings[10])
    @handle_exceptions
    def setInterfaces(self, interfaces):
        self.settings[10] = interfaces
    @handle_exceptions
    def addInterface(self, interface):
        if interface not in self.settings[10]:
            self.settings[10].append(interface)
    @handle_exceptions
    def removeInterface(self, interface):
        if interface in self.settings[10]:
            self.settings[10].remove(interface)
    @handle_exceptions
    def queryInterface(self, interface):
        return interface in self.settings[10]

    @handle_exceptions
    def getSources(self):
        return sorted(self.settings[11])
    @handle_exceptions
    def setSources(self, sources):
        self.settings[11] = sources
    @handle_exceptions
    def addSource(self, source):
        if source not in self.settings[11]:
            self.settings[11].append(source)
    @handle_exceptions
    def removeSource(self, source):
        if source in self.settings[11]:
            self.settings[11].remove(source)
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
    @handle_exceptions
    def removeRichRule(self, rule):
        rule = str(Rich_Rule(rule_str=rule))
        if rule in self.settings[12]:
            self.settings[12].remove(rule)
    @handle_exceptions
    def queryRichRule(self, rule):
        rule = str(Rich_Rule(rule_str=rule))
        return rule in self.settings[12]


# zone config

class FirewallClientConfigZone(object):
    def __init__(self, bus, path):
        self.bus = bus
        self.path = path
        self.dbus_obj = self.bus.get_object(DBUS_INTERFACE, path)
        self.fw_zone = dbus.Interface(self.dbus_obj,
                                      dbus_interface=DBUS_INTERFACE_CONFIG_ZONE)
        self.fw_properties = dbus.Interface(
            self.dbus_obj, dbus_interface='org.freedesktop.DBus.Properties')
        #TODO: check interface version and revision (need to match client 
        # version)

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def get_property(self, prop):
        return dbus_to_python(self.fw_properties.Get(DBUS_INTERFACE_CONFIG_ZONE,
                                                     prop))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def get_properties(self):
        return dbus_to_python(self.fw_properties.GetAll(DBUS_INTERFACE_CONFIG_ZONE))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def set_property(self, prop, value):
        self.fw_properties.Set(DBUS_INTERFACE_CONFIG_ZONE, prop, value)

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getSettings(self):
        return FirewallClientZoneSettings(list(dbus_to_python(\
                    self.fw_zone.getSettings())))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def update(self, settings):
        self.fw_zone.update(tuple(settings.settings))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def loadDefaults(self):
        self.fw_zone.loadDefaults()

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def remove(self):
        self.fw_zone.remove()

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def rename(self, name):
        self.fw_zone.rename(name)

# service config settings

class FirewallClientServiceSettings(object):
    @handle_exceptions
    def __init__(self, settings=None):
        if settings:
            self.settings = settings
        else:
            self.settings = ["", "", "", [], [], {}]

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
    @handle_exceptions
    def removePort(self, port, protocol):
        if (port,protocol) in self.settings[3]:
            self.settings[3].remove((port,protocol))
    @handle_exceptions
    def queryPort(self, port, protocol):
        return (port,protocol) in self.settings[3]

    @handle_exceptions
    def getModules(self):
        return sorted(self.settings[4])
    @handle_exceptions
    def setModules(self, modules):
        self.settings[4] = modules
    @handle_exceptions
    def addModule(self, module):
        if module not in self.settings[4]:
            self.settings[4].append(module)
    @handle_exceptions
    def removeModule(self, module):
        if module in self.settings[4]:
            self.settings[4].remove(module)
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
        self.settings[5][dest_type] = address
    @handle_exceptions
    def removeDestination(self, dest_type):
        if dest_type in self.settings[5]:
            del self.settings[5][dest_type]
    @handle_exceptions
    def queryDestination(self, dest_type, address):
        return (dest_type in self.settings[5] and \
                    address == self.settings[5][dest_type])

# service config

class FirewallClientConfigService(object):
    @handle_exceptions
    def __init__(self, bus, path):
        self.bus = bus
        self.path = path
        self.dbus_obj = self.bus.get_object(DBUS_INTERFACE, path)
        self.fw_service = dbus.Interface(self.dbus_obj,
                                         dbus_interface=DBUS_INTERFACE_CONFIG_SERVICE)
        self.fw_properties = dbus.Interface(
            self.dbus_obj, dbus_interface='org.freedesktop.DBus.Properties')

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def get_property(self, prop):
        return dbus_to_python(self.fw_properties.Get(DBUS_INTERFACE_CONFIG_SERVICE,
                                                     prop))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def get_properties(self):
        return dbus_to_python(self.fw_properties.GetAll(DBUS_INTERFACE_CONFIG_SERVICE))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def set_property(self, prop, value):
        self.fw_properties.Set(DBUS_INTERFACE_CONFIG_SERVICE, prop, value)

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getSettings(self):
        return FirewallClientServiceSettings(list(dbus_to_python(\
                    self.fw_service.getSettings())))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def update(self, settings):
        self.fw_service.update(tuple(settings.settings))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def loadDefaults(self):
        self.fw_service.loadDefaults()

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def remove(self):
        self.fw_service.remove()

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def rename(self, name):
        self.fw_service.rename(name)

# icmptype config settings

class FirewallClientIcmpTypeSettings(object):
    @handle_exceptions
    def __init__(self, settings=None):
        if settings:
            self.settings = settings
        else:
            self.settings = ["", "", "", []]

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
        if destination not in self.settings[3]:
            self.settings[3].append(destination)
    @handle_exceptions
    def removeDestination(self, destination):
        if destination in self.settings[3]:
            self.settings[3].remove(destination)
        # empty means all
        elif not self.settings[3]:
            self.setDestinations(list(set(['ipv4','ipv6']) - \
                                      set([destination])))

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
        self.dbus_obj = self.bus.get_object(DBUS_INTERFACE, path)
        self.fw_icmptype = dbus.Interface(self.dbus_obj,
                                          dbus_interface=DBUS_INTERFACE_CONFIG_ICMPTYPE)
        self.fw_properties = dbus.Interface(
            self.dbus_obj, dbus_interface='org.freedesktop.DBus.Properties')

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def get_property(self, prop):
        return dbus_to_python(self.fw_properties.Get(DBUS_INTERFACE_CONFIG_ICMPTYPE,
                                                     prop))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def get_properties(self):
        return dbus_to_python(self.fw_properties.GetAll(DBUS_INTERFACE_CONFIG_ICMPTYPE))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def set_property(self, prop, value):
        self.fw_properties.Set(DBUS_INTERFACE_CONFIG_ICMPTYPE, prop, value)

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getSettings(self):
        return FirewallClientIcmpTypeSettings(list(dbus_to_python(\
                    self.fw_icmptype.getSettings())))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def update(self, settings):
        self.fw_icmptype.update(tuple(settings.settings))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def loadDefaults(self):
        self.fw_icmptype.loadDefaults()

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def remove(self):
        self.fw_icmptype.remove()

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def rename(self, name):
        self.fw_icmptype.rename(name)

# config.policies lockdown whitelist

class FirewallClientPoliciesLockdownWhitelist(object):
    @handle_exceptions
    def __init__(self, settings=None):
        if settings:
            self.settings = settings
        else:
            self.settings = [ [], [], [], [] ]

    @handle_exceptions
    def getCommands(self):
        return sorted(self.settings[0])
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
        return sorted(self.settings[1])
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
        return sorted(self.settings[2])
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
        return sorted(self.settings[3])
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
        self.dbus_obj = self.bus.get_object(DBUS_INTERFACE,
                                            DBUS_PATH_CONFIG)
        self.fw_policies = dbus.Interface( \
            self.dbus_obj, dbus_interface=DBUS_INTERFACE_CONFIG_POLICIES)

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getLockdownWhitelist(self):
        return FirewallClientPoliciesLockdownWhitelist( \
            list(dbus_to_python(self.fw_policies.getLockdownWhitelist())))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def setLockdownWhitelist(self, settings):
        self.fw_policies.setLockdownWhitelist(tuple(settings.settings))

# config.direct

class FirewallClientDirect(object):
    @handle_exceptions
    def __init__(self, settings=None):
        if settings:
            self.settings = settings
        else:
            self.settings = [ [], [], [], ]

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
    def queryRule(self, ipv, table, chain, priority, args):
        idx = (ipv, table, chain, priority, args)
        return idx in self.settings[1]

    @handle_exceptions
    def getAllPassthroughs(self):
        return self.settings[2]
    @handle_exceptions
    def getPassthroughs(self, ipv):
        return [ entry[1] for entry in self.settings[2] \
                 if entry[0] == ipv ]
    @handle_exceptions
    def setAllPassthroughs(self, passthroughs):
        self.settings[2] = passthroughs
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
        self.dbus_obj = self.bus.get_object(DBUS_INTERFACE,
                                            DBUS_PATH_CONFIG)
        self.fw_direct = dbus.Interface( \
            self.dbus_obj, dbus_interface=DBUS_INTERFACE_CONFIG_DIRECT)

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getSettings(self):
        return FirewallClientDirect( \
            list(dbus_to_python(self.fw_direct.getSettings())))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def update(self, settings):
        self.fw_direct.update(tuple(settings.settings))

# config

class FirewallClientConfig(object):
    @handle_exceptions
    def __init__(self, bus):
        self.bus = bus
        self.dbus_obj = self.bus.get_object(DBUS_INTERFACE,
                                            DBUS_PATH_CONFIG)
        self.fw_config = dbus.Interface(self.dbus_obj,
                                        dbus_interface=DBUS_INTERFACE_CONFIG)
        self.fw_properties = dbus.Interface(
            self.dbus_obj, dbus_interface='org.freedesktop.DBus.Properties')
        self._policies = FirewallClientConfigPolicies(self.bus)
        self._direct = FirewallClientConfigDirect(self.bus)

    # properties

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def get_property(self, prop):
        return dbus_to_python(self.fw_properties.Get(DBUS_INTERFACE_CONFIG,
                                                     prop))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def get_properties(self):
        return dbus_to_python(self.fw_properties.GetAll(DBUS_INTERFACE_CONFIG))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def set_property(self, prop, value):
        self.fw_properties.Set(DBUS_INTERFACE_CONFIG, prop, value)

    # zone

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def listZones(self):
        return dbus_to_python(self.fw_config.listZones())

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getZone(self, path):
        return FirewallClientConfigZone(self.bus, path)

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getZoneByName(self, name):
        path = dbus_to_python(self.fw_config.getZoneByName(name))
        return FirewallClientConfigZone(self.bus, path)

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getZoneOfInterface(self, iface):
        return dbus_to_python(self.fw_config.getZoneOfInterface(iface))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getZoneOfSource(self, source):
        return dbus_to_python(self.fw_config.getZoneOfSource(source))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def addZone(self, name, settings):
        path = self.fw_config.addZone(name, tuple(settings.settings))
        return FirewallClientConfigZone(self.bus, path)

    # service

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def listServices(self):
        return dbus_to_python(self.fw_config.listServices())

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getService(self, path):
        return FirewallClientConfigService(self.bus, path)

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getServiceByName(self, name):
        path = dbus_to_python(self.fw_config.getServiceByName(name))
        return FirewallClientConfigService(self.bus, path)

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def addService(self, name, settings):
        path = self.fw_config.addService(name, tuple(settings.settings))
        return FirewallClientConfigService(self.bus, path)

    # icmptype

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def listIcmpTypes(self):
        return dbus_to_python(self.fw_config.listIcmpTypes())

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getIcmpType(self, path):
        return FirewallClientConfigIcmpType(self.bus, path)

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getIcmpTypeByName(self, name):
        path = dbus_to_python(self.fw_config.getIcmpTypeByName(name))
        return FirewallClientConfigIcmpType(self.bus, path)

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def addIcmpType(self, name, settings):
        path = self.fw_config.addIcmpType(name, tuple(settings.settings))
        return FirewallClientConfigIcmpType(self.bus, path)

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def policies(self):
        return self._policies

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def direct(self):
        return self._direct

#

class FirewallClient(object):
    @handle_exceptions
    def __init__(self, bus=None, wait=0, quiet=True):
        if not bus:
            dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
            try:
                self.bus = slip.dbus.SystemBus()
                self.bus.default_timeout = None
            except:
                print("Not using slip")
                self.bus = dbus.SystemBus()
        else:
            self.bus = bus

        self.bus.add_signal_receiver(
            handler_function=self._dbus_connection_changed,
            signal_name="NameOwnerChanged",
            dbus_interface="org.freedesktop.DBus")

        for interface in [ DBUS_INTERFACE,
                           DBUS_INTERFACE_ZONE,
                           DBUS_INTERFACE_DIRECT,
                           DBUS_INTERFACE_POLICIES,
                           DBUS_INTERFACE_CONFIG,
                           DBUS_INTERFACE_CONFIG_ZONE,
                           DBUS_INTERFACE_CONFIG_SERVICE,
                           DBUS_INTERFACE_CONFIG_DIRECT,
                           DBUS_INTERFACE_CONFIG_ICMPTYPE,
                           DBUS_INTERFACE_CONFIG_POLICIES ]:
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
            "default-zone-changed": "DefaultZoneChanged",
            "panic-mode-enabled": "PanicModeEnabled",
            "panic-mode-disabled": "PanicModeDisabled",
            "reloaded": "Reloaded",
            "service-added": "ServiceAdded",
            "service-removed": "ServiceRemoved",
            "port-added": "PortAdded",
            "port-removed": "PortRemoved",
            "masquerade-added": "MasqueradeAdded",
            "masquerade-removed": "MasqueradeRemoved",
            "forward-port-added": "ForwardPortAdded",
            "forward-port-removed": "ForwardPortRemoved",
            "icmp-block-added": "IcmpBlockAdded",
            "icmp-block-removed": "IcmpBlockRemoved",
            "richrule-added": "RichRuleAdded",
            "richrule-removed": "RichRuleRemoved",
            "interface-added": "InterfaceAdded",
            "interface-removed": "InterfaceRemoved",
            "zone-changed": "ZoneOfInterfaceChanged", # DEPRECATED, use zone-of-interface-changed instead
            "zone-of-interface-changed": "ZoneOfInterfaceChanged",
            "source-added": "SourceAdded",
            "source-removed": "SourceRemoved",
            "zone-of-source-changed": "ZoneOfSourceChanged",
            # direct callbacks
            "direct:chain-added": "ChainAdded",
            "direct:chain-removed": "ChainRemoved",
            "direct:rule-added": "RuleAdded",
            "direct:rule-removed": "RuleRemoved",
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
            "config:zone-added": "config:ZoneAdded",
            "config:zone-updated": "config:ZoneUpdated",
            "config:zone-removed": "config:ZoneRemoved",
            "config:zone-renamed": "config:ZoneRenamed",
            "config:service-added": "config:ServiceAdded",
            "config:service-updated": "config:ServiceUpdated",
            "config:service-removed": "config:ServiceRemoved",
            "config:service-renamed": "config:ServiceRenamed",
            "config:icmptype-added": "config:IcmpTypeAdded",
            "config:icmptype-updated": "config:IcmpTypeUpdated",
            "config:icmptype-removed": "config:IcmpTypeRemoved",
            "config:icmptype-renamed": "config:IcmpTypeRenamed",
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
        self.fw_zone = None
        self.fw_direct = None
        self.fw_properties = None
        self._config = None
        self.connected = False

    @handle_exceptions
    def getExceptionHandler(self):
        global exception_handler
        return exception_handler

    @handle_exceptions
    def setExceptionHandler(self, handler):
        global exception_handler
        exception_handler = handler

    @handle_exceptions
    def connect(self, name, callback, *args):
        if name in self._callbacks:
            self._callback[self._callbacks[name]] = (callback, args)
        else:
            raise ValueError("Unknown callback name '%s'" % name)

    @handle_exceptions
    def _dbus_connection_changed(self, name, old_owner, new_owner):
        if name != DBUS_INTERFACE:
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
            self.dbus_obj = self.bus.get_object(DBUS_INTERFACE, DBUS_PATH)
            self.fw = dbus.Interface(self.dbus_obj,
                                     dbus_interface=DBUS_INTERFACE)
            self.fw_zone = dbus.Interface(self.dbus_obj,
                                          dbus_interface=DBUS_INTERFACE_ZONE)
            self.fw_direct = dbus.Interface(
                self.dbus_obj, dbus_interface=DBUS_INTERFACE_DIRECT)
            self.fw_policies = dbus.Interface(
                self.dbus_obj, dbus_interface=DBUS_INTERFACE_POLICIES)
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
                              interface=DBUS_INTERFACE)
        self._signal_receiver(member="connection-changed",
                              interface=DBUS_INTERFACE)

    @handle_exceptions
    def _connection_lost(self):
        self._init_vars()
        self._signal_receiver(member="connection-lost",
                              interface=DBUS_INTERFACE)
        self._signal_receiver(member="connection-changed",
                              interface=DBUS_INTERFACE)

    @handle_exceptions
    def _signal_receiver(self, *args, **kwargs):
        _args = [ ]
        for arg in args:
            _args.append(dbus_to_python(arg))
        args = _args
        if not "member" in kwargs:
            return
        signal = kwargs["member"]
        interface = kwargs["interface"]

        cb = None
        cb_args = [ ]

        # config signals need special treatment
        # pimp signal name
        if interface.startswith(DBUS_INTERFACE_CONFIG_ZONE):
            signal = "config:Zone" + signal
        elif interface.startswith(DBUS_INTERFACE_CONFIG_SERVICE):
            signal = "config:Service" + signal
        elif interface.startswith(DBUS_INTERFACE_CONFIG_ICMPTYPE):
            signal = "config:IcmpType" + signal
        elif interface == DBUS_INTERFACE_CONFIG:
            signal = "config:" + signal
        elif interface == DBUS_INTERFACE_CONFIG_POLICIES:
            signal = "config:policies:" + signal
        elif interface == DBUS_INTERFACE_CONFIG_DIRECT:
            signal = "config:direct:" + signal

        for callback in self._callbacks:
            if self._callbacks[callback] == signal and \
                    self._callbacks[callback] in self._callback:
                cb = self._callback[self._callbacks[callback]]
        if not cb:
            return

        cb_args.extend(args)

        # call back ...
        try:
            if cb[1]:
                # add call data
                cb_args.extend(cb[1])
            # call back
            cb[0](*cb_args)
        except Exception as msg:
            print(msg)

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def config(self):
        return self._config

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def reload(self):
        self.fw.reload()

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def complete_reload(self):
        self.fw.completeReload()

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def get_property(self, prop):
        return dbus_to_python(self.fw_properties.Get(DBUS_INTERFACE, prop))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def get_properties(self):
        return dbus_to_python(self.fw_properties.GetAll(DBUS_INTERFACE))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def set_property(self, prop, value):
        self.fw_properties.Set(DBUS_INTERFACE, prop, value)

    # panic mode

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def enablePanicMode(self):
        self.fw.enablePanicMode()
    
    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def disablePanicMode(self):
        self.fw.disablePanicMode()

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def queryPanicMode(self):
        return dbus_to_python(self.fw.queryPanicMode())

    # list functions

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def listServices(self):
        return dbus_to_python(self.fw.listServices())

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getServiceSettings(self, service):
        return FirewallClientServiceSettings(list(dbus_to_python(\
                    self.fw.getServiceSettings(service))))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def listIcmpTypes(self):
        return dbus_to_python(self.fw.listIcmpTypes())

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getIcmpTypeSettings(self, icmptype):
        return FirewallClientIcmpTypeSettings(list(dbus_to_python(\
                    self.fw.getIcmpTypeSettings(icmptype))))

    # default zone

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getDefaultZone(self):
        return dbus_to_python(self.fw.getDefaultZone())

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def setDefaultZone(self, zone):
        self.fw.setDefaultZone(zone)

    # zone

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getZones(self):
        return dbus_to_python(self.fw_zone.getZones())

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getActiveZones(self):
        return dbus_to_python(self.fw_zone.getActiveZones())

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getZoneOfInterface(self, interface):
        return dbus_to_python(self.fw_zone.getZoneOfInterface(interface))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getZoneOfSource(self, source):
        return dbus_to_python(self.fw_zone.getZoneOfSource(source))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def isImmutable(self, zone):
        return dbus_to_python(self.fw_zone.isImmutable(zone))

    # interfaces

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def addInterface(self, zone, interface):
        return dbus_to_python(self.fw_zone.addInterface(zone, interface))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def changeZone(self, zone, interface): # DEPRECATED
        return dbus_to_python(self.fw_zone.changeZone(zone, interface))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def changeZoneOfInterface(self, zone, interface):
        return dbus_to_python(self.fw_zone.changeZoneOfInterface(zone,
                                                                 interface))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getInterfaces(self, zone):
        return dbus_to_python(self.fw_zone.getInterfaces(zone))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def queryInterface(self, zone, interface):
        return dbus_to_python(self.fw_zone.queryInterface(zone, interface))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def removeInterface(self, zone, interface):
        return dbus_to_python(self.fw_zone.removeInterface(zone, interface))

    # sources

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def addSource(self, zone, source):
        return dbus_to_python(self.fw_zone.addSource(zone, source))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def changeZoneOfSource(self, zone, source):
        return dbus_to_python(self.fw_zone.changeZoneOfSource(zone, source))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getSources(self, zone):
        return dbus_to_python(self.fw_zone.getSources(zone))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def querySource(self, zone, source):
        return dbus_to_python(self.fw_zone.querySource(zone, source))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def removeSource(self, zone, source):
        return dbus_to_python(self.fw_zone.removeSource(zone, source))

    # rich rules

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def addRichRule(self, zone, rule, timeout=0):
        return dbus_to_python(self.fw_zone.addRichRule(zone, rule, timeout))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getRichRules(self, zone):
        return dbus_to_python(self.fw_zone.getRichRules(zone))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def queryRichRule(self, zone, rule):
        return dbus_to_python(self.fw_zone.queryRichRule(zone, rule))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def removeRichRule(self, zone, rule):
        return dbus_to_python(self.fw_zone.removeRichRule(zone, rule))

    # services

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def addService(self, zone, service, timeout=0):
        return dbus_to_python(self.fw_zone.addService(zone, service, timeout))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getServices(self, zone):
        return dbus_to_python(self.fw_zone.getServices(zone))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def queryService(self, zone, service):
        return dbus_to_python(self.fw_zone.queryService(zone, service))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def removeService(self, zone, service):
        return dbus_to_python(self.fw_zone.removeService(zone, service))

    # ports

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def addPort(self, zone, port, protocol, timeout=0):
        return dbus_to_python(self.fw_zone.addPort(zone, port, protocol, timeout))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getPorts(self, zone):
        return dbus_to_python(self.fw_zone.getPorts(zone))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def queryPort(self, zone, port, protocol):
        return dbus_to_python(self.fw_zone.queryPort(zone, port, protocol))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def removePort(self, zone, port, protocol):
        return dbus_to_python(self.fw_zone.removePort(zone, port, protocol))

    # masquerade

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def addMasquerade(self, zone, timeout=0):
        return dbus_to_python(self.fw_zone.addMasquerade(zone, timeout))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def queryMasquerade(self, zone):
        return dbus_to_python(self.fw_zone.queryMasquerade(zone))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def removeMasquerade(self, zone):
        return dbus_to_python(self.fw_zone.removeMasquerade(zone))

    # forward ports

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
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
    @handle_exceptions
    def getForwardPorts(self, zone):
        return dbus_to_python(self.fw_zone.getForwardPorts(zone))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def queryForwardPort(self, zone, port, protocol, toport, toaddr):
        if not toport:
            toport = ""
        if not toaddr:
            toaddr = ""
        return dbus_to_python(self.fw_zone.queryForwardPort(zone,
                                                            port, protocol,
                                                            toport, toaddr))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
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
    @handle_exceptions
    def addIcmpBlock(self, zone, icmp, timeout=0):
        return dbus_to_python(self.fw_zone.addIcmpBlock(zone, icmp, timeout))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getIcmpBlocks(self, zone):
        return dbus_to_python(self.fw_zone.getIcmpBlocks(zone))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def queryIcmpBlock(self, zone, icmp):
        return dbus_to_python(self.fw_zone.queryIcmpBlock(zone, icmp))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def removeIcmpBlock(self, zone, icmp):
        return dbus_to_python(self.fw_zone.removeIcmpBlock(zone, icmp))

    # direct chain

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def addChain(self, ipv, table, chain):
        self.fw_direct.addChain(ipv, table, chain)

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def removeChain(self, ipv, table, chain):
        self.fw_direct.removeChain(ipv, table, chain)

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def queryChain(self, ipv, table, chain):
        return dbus_to_python(self.fw_direct.queryChain(ipv, table, chain))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getChains(self, ipv, table):
        return dbus_to_python(self.fw_direct.getChains(ipv, table))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getAllChains(self):
        return dbus_to_python(self.fw_direct.getAllChains())

    # direct rule

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def addRule(self, ipv, table, chain, priority, args):
        self.fw_direct.addRule(ipv, table, chain, priority, args)

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def removeRule(self, ipv, table, chain, priority, args):
        self.fw_direct.removeRule(ipv, table, chain, priority, args)

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def queryRule(self, ipv, table, chain, priority, args):
        return dbus_to_python(self.fw_direct.queryRule(ipv, table, chain, priority, args))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getRules(self, ipv, table, chain):
        return dbus_to_python(self.fw_direct.getRules(ipv, table, chain))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getAllRules(self):
        return dbus_to_python(self.fw_direct.getAllRules())

    # direct passthrough

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def passthrough(self, ipv, args):
        return dbus_to_python(self.fw_direct.passthrough(ipv, args))

    # lockdown

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def enableLockdown(self):
        self.fw_policies.enableLockdown()

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def disableLockdown(self):
        self.fw_policies.disableLockdown()

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def queryLockdown(self):
        return dbus_to_python(self.fw_policies.queryLockdown())

    # policies

    # lockdown white list commands

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def addLockdownWhitelistCommand(self, command):
        self.fw_policies.addLockdownWhitelistCommand(command)

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getLockdownWhitelistCommands(self):
        return dbus_to_python(self.fw_policies.getLockdownWhitelistCommands())

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def queryLockdownWhitelistCommand(self, command):
        return dbus_to_python(self.fw_policies.queryLockdownWhitelistCommand(command))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def removeLockdownWhitelistCommand(self, command):
        self.fw_policies.removeLockdownWhitelistCommand(command)

    # lockdown white list contexts

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def addLockdownWhitelistContext(self, context):
        self.fw_policies.addLockdownWhitelistContext(context)

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getLockdownWhitelistContexts(self):
        return dbus_to_python(self.fw_policies.getLockdownWhitelistContexts())

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def queryLockdownWhitelistContext(self, context):
        return dbus_to_python(self.fw_policies.queryLockdownWhitelistContext(context))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def removeLockdownWhitelistContext(self, context):
        self.fw_policies.removeLockdownWhitelistContext(context)

    # lockdown white list uids

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def addLockdownWhitelistUid(self, uid):
        self.fw_policies.addLockdownWhitelistUid(uid)

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getLockdownWhitelistUids(self):
        return dbus_to_python(self.fw_policies.getLockdownWhitelistUids())

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def queryLockdownWhitelistUid(self, uid):
        return dbus_to_python(self.fw_policies.queryLockdownWhitelistUid(uid))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def removeLockdownWhitelistUid(self, uid):
        self.fw_policies.removeLockdownWhitelistUid(uid)

    # lockdown white list users

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def addLockdownWhitelistUser(self, user):
        self.fw_policies.addLockdownWhitelistUser(user)

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getLockdownWhitelistUsers(self):
        return dbus_to_python(self.fw_policies.getLockdownWhitelistUsers())

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def queryLockdownWhitelistUser(self, user):
        return dbus_to_python(self.fw_policies.queryLockdownWhitelistUser(user))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def removeLockdownWhitelistUser(self, user):
        self.fw_policies.removeLockdownWhitelistUser(user)

