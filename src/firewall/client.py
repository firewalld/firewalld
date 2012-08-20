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

# zone config setings

class FirewallClientConfigZoneSettings(object):
    def __init__(self, settings):
        self.settings = settings

    def getVersion(self):
        return self.settings[0]
    def setVersion(self, version):
        self.settings[0] = version

    def getShort(self):
        return self.settings[1]
    def setShort(self, short):
        self.settings[1] = short

    def getDescription(self):
        return self.settings[2]
    def setDescription(self, description):
        self.settings[2] = description

    def getImmutable(self):
        return self.settings[3]
    def setImmutable(self, immutable):
        self.settings[3] = immutable

    def getTarget(self):
        return self.settings[4]
    def setTarget(self, target):
        self.settings[4] = target

    def getServices(self):
        return self.settings[5]
    def setServices(self, services):
        self.settings[5] = services
    def addService(self, service):
        if service not in self.settings[5]:
            self.settings[5].append(service)
    def removeService(self, service):
        if service in self.settings[5]:
            self.settings[5].remove(service)

    def getPorts(self):
        return self.settings[6]
    def setPorts(self, ports):
        self.settings[6] = ports
    def addPort(self, port, protocol):
        if (port,protocol) not in self.settings[6]:
            self.settings[6].append((port,protocol))
    def removePort(self, port, protocol):
        if (port,protocol) in self.settings[6]:
            self.settings[6].remove((port,protocol))

    def getIcmpBlocks(self):
        return self.settings[7]
    def setIcmpBlocks(self, icmpblocks):
        self.settings[7] = icmpblocks
    def addIcmpBlock(self, icmptype):
        if icmptype not in self.settings[7]:
            self.settings[7].append(icmptype)
    def removeIcmpBlock(self, icmptype):
        if icmptype in self.settings[7]:
            self.settings[7].remove(icmptype)

    def getMasquerade(self):
        return self.settings[8]
    def setMasquerade(self, masquerade):
        self.settings[8] = masquerade

    def getForwardPorts(self):
        return self.settings[9]
    def setForwardPorts(self, ports):
        self.settings[9] = ports
    def addForwardPort(self, port, protocol, to_port, to_addr):
        if (port,protocol,to_port,to_addr) not in self.settings[9]:
            self.settings[9].append((port,protocol,to_port,to_addr))
    def removeForwardPort(self, port, protocol, to_port, to_addr):
        if (port,protocol,to_port,to_addr) in self.settings[9]:
            self.settings[9].remove((port,protocol,to_port,to_addr))

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
        self._updated_cb = None
        self._removed_cb = None
        self._renamed_cb = None

    @slip.dbus.polkit.enable_proxy
    def get_property(self, prop):
        return dbus_to_python(self.fw_properties.Get(DBUS_INTERFACE_CONFIG_ZONE,
                                                     prop))

    @slip.dbus.polkit.enable_proxy
    def get_properties(self):
        return dbus_to_python(self.fw_properties.GetAll(DBUS_INTERFACE_CONFIG_ZONE))

    @slip.dbus.polkit.enable_proxy
    def set_property(self, prop, value):
        self.fw_properties.Set(DBUS_INTERFACE_CONFIG_ZONE, prop, value)

    @slip.dbus.polkit.enable_proxy
    def getSettings(self):
        return FirewallClientConfigZoneSettings(list(dbus_to_python(\
                    self.fw_zone.getSettings())))

    @slip.dbus.polkit.enable_proxy
    def update(self, settings):
        self.fw_zone.update(tuple(settings.settings))

    @slip.dbus.polkit.enable_proxy
    def loadDefaults(self):
        self.fw_zone.loadDefaults()

    @slip.dbus.polkit.enable_proxy
    def remove(self):
        self.fw_zone.remove()

    @slip.dbus.polkit.enable_proxy
    def rename(self, name):
        self.fw_zone.rename(name)

    # callbacks

    def connect(self, name, callback, *args):
        if name == "updated":
            self._updated_cb = (callback, args)
        elif name == "removed":
            self._removed_cb = (callback, args)
        elif name == "renamed":
            self._renamed_cb = (callback, args)
        else:
            raise ValueError, "Unknown callback name '%s'" % name

# service config settings

class FirewallClientConfigServiceSettings(object):
    def __init__(self, settings):
        self.settings = settings

    def getVersion(self):
        return self.settings[0]
    def setVersion(self, version):
        self.settings[0] = version

    def getShort(self):
        return self.settings[1]
    def setShort(self, short):
        self.settings[1] = short

    def getDescription(self):
        return self.settings[2]
    def setDescription(self, description):
        self.settings[2] = description

    def getPorts(self):
        return self.settings[3]
    def setPorts(self, ports):
        self.settings[3] = ports
    def addPort(self, port, protocol):
        if (port,protocol) not in self.settings[3]:
            self.settings[3].append((port,protocol))
    def removePort(self, port, protocol):
        if (port,protocol) in self.settings[3]:
            self.settings[3].remove((port,protocol))

    def getModules(self):
        return self.settings[4]
    def setModules(self, modules):
        self.settings[4] = modules
    def addModule(self, module):
        if module not in self.settings[4]:
            self.settings[4].append(module)
    def removeModule(self, module):
        if module in self.settings[4]:
            self.settings[4].remove(module)

    def getDestinations(self):
        return self.settings[5]
    def setDestinations(self, destinations):
        self.settings[5] = destinations
    def setDestination(self, dest_type, address):
        self.settings[5][dest_type] = address
    def removeDestination(self, dest_type):
        if dest_type in self.settings[5]:
            del self.settings[5][dest_type]

# service config

class FirewallClientConfigService(object):
    def __init__(self, bus, path):
        self.bus = bus
        self.path = path
        self.dbus_obj = self.bus.get_object(DBUS_INTERFACE, path)
        self.fw_service = dbus.Interface(self.dbus_obj,
                                         dbus_interface=DBUS_INTERFACE_CONFIG_SERVICE)
        self.fw_properties = dbus.Interface(
            self.dbus_obj, dbus_interface='org.freedesktop.DBus.Properties')
        self._updated_cb = None
        self._removed_cb = None
        self._renamed_cb = None

    @slip.dbus.polkit.enable_proxy
    def get_property(self, prop):
        return dbus_to_python(self.fw_properties.Get(DBUS_INTERFACE_CONFIG_SERVICE,
                                                     prop))

    @slip.dbus.polkit.enable_proxy
    def get_properties(self):
        return dbus_to_python(self.fw_properties.GetAll(DBUS_INTERFACE_CONFIG_SERVICE))

    @slip.dbus.polkit.enable_proxy
    def set_property(self, prop, value):
        self.fw_properties.Set(DBUS_INTERFACE_CONFIG_SERVICE, prop, value)

    @slip.dbus.polkit.enable_proxy
    def getSettings(self):
        return FirewallClientConfigServiceSettings(list(dbus_to_python(\
                    self.fw_service.getSettings())))

    @slip.dbus.polkit.enable_proxy
    def update(self, settings):
        self.fw_service.update(tuple(settings.settings))

    @slip.dbus.polkit.enable_proxy
    def loadDefaults(self):
        self.fw_service.loadDefaults()

    @slip.dbus.polkit.enable_proxy
    def remove(self):
        self.fw_service.remove()

    @slip.dbus.polkit.enable_proxy
    def rename(self, name):
        self.fw_service.rename(name)

    # callbacks

    def connect(self, name, callback, *args):
        if name == "updated":
            self._updated_cb = (callback, args)
        elif name == "removed":
            self._removed_cb = (callback, args)
        elif name == "renamed":
            self._renamed_cb = (callback, args)
        else:
            raise ValueError, "Unknown callback name '%s'" % name

# icmptype config settings

class FirewallClientConfigIcmpTypeSettings(object):
    def __init__(self, settings):
        self.settings = settings

    def getVersion(self):
        return self.settings[0]
    def setVersion(self, version):
        self.settings[0] = version

    def getShort(self):
        return self.settings[1]
    def setShort(self, short):
        self.settings[1] = short

    def getDescription(self):
        return self.settings[2]
    def setDescription(self, description):
        self.settings[2] = description

    def getDestinations(self):
        return self.settings[3]
    def setDestinations(self, destinations):
        self.settings[3] = destinations
    def addDestination(self, destination):
        if destination not in self.settings[3]:
            self.settings[3].append(destination)
    def removeDestination(self, destination):
        if destination in self.settings[3]:
            self.settings[3].remove(destination)

# icmptype config

class FirewallClientConfigIcmpType(object):
    def __init__(self, bus, path):
        self.bus = bus
        self.path = path
        self.dbus_obj = self.bus.get_object(DBUS_INTERFACE, path)
        self.fw_icmptype = dbus.Interface(self.dbus_obj,
                                          dbus_interface=DBUS_INTERFACE_CONFIG_ICMPTYPE)
        self.fw_properties = dbus.Interface(
            self.dbus_obj, dbus_interface='org.freedesktop.DBus.Properties')
        self._updated_cb = None
        self._removed_cb = None
        self._renamed_cb = None

    @slip.dbus.polkit.enable_proxy
    def get_property(self, prop):
        return dbus_to_python(self.fw_properties.Get(DBUS_INTERFACE_CONFIG_ICMPTYPE,
                                                     prop))

    @slip.dbus.polkit.enable_proxy
    def get_properties(self):
        return dbus_to_python(self.fw_properties.GetAll(DBUS_INTERFACE_CONFIG_ICMPTYPE))

    @slip.dbus.polkit.enable_proxy
    def set_property(self, prop, value):
        self.fw_properties.Set(DBUS_INTERFACE_CONFIG_ICMPTYPE, prop, value)

    @slip.dbus.polkit.enable_proxy
    def getSettings(self):
        return FirewallClientConfigIcmpTypeSettings(list(dbus_to_python(\
                    self.fw_icmptype.getSettings())))

    @slip.dbus.polkit.enable_proxy
    def update(self, settings):
        self.fw_icmptype.update(tuple(settings.settings))

    @slip.dbus.polkit.enable_proxy
    def loadDefaults(self):
        self.fw_icmptype.loadDefaults()

    @slip.dbus.polkit.enable_proxy
    def remove(self):
        self.fw_icmptype.remove()

    @slip.dbus.polkit.enable_proxy
    def rename(self, name):
        self.fw_icmptype.rename(name)

    # callbacks

    def connect(self, name, callback, *args):
        if name == "updated":
            self._updated_cb = (callback, args)
        elif name == "removed":
            self._removed_cb = (callback, args)
        elif name == "renamed":
            self._renamed_cb = (callback, args)
        else:
            raise ValueError, "Unknown callback name '%s'" % name

# config

class FirewallClientConfig(object):
    def __init__(self, bus):
        self.bus = bus
        self.dbus_obj = self.bus.get_object(DBUS_INTERFACE,
                                            DBUS_PATH_CONFIG)
        self.fw_config = dbus.Interface(self.dbus_obj,
                                        dbus_interface=DBUS_INTERFACE_CONFIG)
        self._callback = { }
        self._callbacks = {
            "zone-added": "ZoneAdded",
            "zone-updated": "ZoneUpdated",
            "zone-removed": "ZoneRemoved",
            "zone-renamed": "ZoneRenamed",
            "service-added": "ServiceAdded",
            "service-updated": "ServiceUpdated",
            "service-removed": "ServiceRemoved",
            "service-renamed": "ServiceRenamed",
            "icmptype-added": "IcmpTypeAdded",
            "icmptype-updated": "IcmpTypeUpdated",
            "icmptype-removed": "IcmpTypeRemoved",
            "icmptype-renamed": "IcmpTypeRenamed",
            }

    def signal_receiver(self, *args, **kwargs):
        signal = kwargs["member"]
        path = kwargs["path"]
        interface = kwargs["interface"]

        dbus_obj = self.bus.get_object(DBUS_INTERFACE, path)
        properties = dbus.Interface(
            dbus_obj, dbus_interface='org.freedesktop.DBus.Properties')
        what = dbus_to_python(properties.Get(interface, "name"))

        if interface.startswith(DBUS_INTERFACE_CONFIG_ZONE):
            signal = "Zone" + signal
        elif interface.startswith(DBUS_INTERFACE_CONFIG_SERVICE):
            signal = "Service" + signal
        elif interface.startswith(DBUS_INTERFACE_CONFIG_ICMPTYPE):
            signal = "IcmpType" + signal

        cb = None
        cb_args = [ ]
        for callback in self._callbacks:
            if self._callbacks[callback] == signal and \
                    self._callbacks[callback] in self._callback:
                cb = self._callback[self._callbacks[callback]]
                cb_args.append(what)
                cb_args.extend(args)
                break

        return (cb, cb_args)

    # zone

    @slip.dbus.polkit.enable_proxy
    def listZones(self):
        return dbus_to_python(self.fw_config.listZones())

    @slip.dbus.polkit.enable_proxy
    def getZone(self, path):
        return FirewallClientConfigZone(self.bus, path)

    @slip.dbus.polkit.enable_proxy
    def getZoneByName(self, name):
        path = dbus_to_python(self.fw_config.getZoneByName(name))
        return FirewallClientConfigZone(self.bus, path)

    @slip.dbus.polkit.enable_proxy
    def addZone(self, name, settings):
        path = self.fw_config.addZone(name, settings)
        return FirewallClientConfigZone(self.bus, path)

    # service

    @slip.dbus.polkit.enable_proxy
    def listServices(self):
        return dbus_to_python(self.fw_config.listServices())

    @slip.dbus.polkit.enable_proxy
    def getService(self, path):
        return FirewallClientConfigService(self.bus, path)

    @slip.dbus.polkit.enable_proxy
    def getServiceByName(self, name):
        path = dbus_to_python(self.fw_config.getServiceByName(name))
        return FirewallClientConfigService(self.bus, path)

    @slip.dbus.polkit.enable_proxy
    def addService(self, name, settings):
        path = self.fw_config.addService(name, settings)
        return FirewallClientConfigService(self.bus, path)

    # icmptype

    @slip.dbus.polkit.enable_proxy
    def listIcmpTypes(self):
        return dbus_to_python(self.fw_config.listIcmpTypes())

    @slip.dbus.polkit.enable_proxy
    def getIcmpType(self, path):
        return FirewallClientConfigIcmpType(self.bus, path)

    @slip.dbus.polkit.enable_proxy
    def getIcmpTypeByName(self, name):
        path = dbus_to_python(self.fw_config.getIcmpTypeByName(name))
        return FirewallClientConfigIcmpType(self.bus, path)

    @slip.dbus.polkit.enable_proxy
    def addIcmpType(self, name, settings):
        path = self.fw_config.addIcmpType(name, settings)
        return FirewallClientConfigIcmpType(self.bus, path)

    # callbacks

    def connect(self, name, callback, *args):
        if name in self._callbacks:
            self._callback[self._callbacks[name]] = (callback, args)
        else:
            raise ValueError, "Unknown callback name '%s'" % name

#

class FirewallClient(object):
    def __init__(self, bus=None):
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
        self.dbus_obj = self.bus.get_object(DBUS_INTERFACE, DBUS_PATH)
        self.fw = dbus.Interface(self.dbus_obj, dbus_interface=DBUS_INTERFACE)
        self.fw_zone = dbus.Interface(self.dbus_obj,
                                      dbus_interface=DBUS_INTERFACE_ZONE)
        self.fw_direct = dbus.Interface(self.dbus_obj,
                                        dbus_interface=DBUS_INTERFACE_DIRECT)
        self.fw_properties = dbus.Interface(
            self.dbus_obj, dbus_interface='org.freedesktop.DBus.Properties')

        self._config = FirewallClientConfig(self.bus)

        self.bus.add_signal_receiver(
            handler_function=self.dbus_connection_changed,
            signal_name="NameOwnerChanged",
            dbus_interface="org.freedesktop.DBus")

        for interface in [ DBUS_INTERFACE,
                           DBUS_INTERFACE_ZONE,
                           DBUS_INTERFACE_DIRECT,
                           DBUS_INTERFACE_CONFIG,
                           DBUS_INTERFACE_CONFIG_ZONE,
                           DBUS_INTERFACE_CONFIG_SERVICE,
                           DBUS_INTERFACE_CONFIG_ICMPTYPE ]:
            self.bus.add_signal_receiver(self.signal_receiver,
                                         dbus_interface=interface,
                                         interface_keyword='interface',
                                         member_keyword='member',
                                         path_keyword='path')

        self._default_zone_changed_cb = None
        self._panic_mode_enabled_cb = None
        self._panic_mode_disabled_cb = None
        self._reloaded_cb = None
        self._callback = { }
        self._callbacks = {
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
            "interface-added": "InterfaceAdded",
            "interface-removed": "InterfaceRemoved",
            "zone-changed": "ZoneChanged",
            }

    def connect(self, name, callback, *args):
        if name in self._callbacks:
            self._callback[self._callbacks[name]] = (callback, args)
        else:
            raise ValueError, "Unknown callback name '%s'" % name

    def dbus_connection_changed(self, name, old_owner, new_owner):
        if name != DBUS_INTERFACE:
            return

        if new_owner:
            # new connection
            self.connect_to_firewalld()
        else:
            # lost connection
            self.connection_to_firewalld_lost()

    def connect_to_firewalld(self):
        pass

    def connection_to_firewalld_lost(self):
        pass

    def signal_receiver(self, *args, **kwargs):
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
        if interface.startswith(DBUS_INTERFACE_CONFIG):
            (cb,cb_args) = self._config.signal_receiver(*args, **kwargs)
        else:
            for callback in self._callbacks:
                if self._callbacks[callback] == signal and \
                        self._callbacks[callback] in self._callback:
                    cb = self._callback[self._callbacks[callback]]
                    cb_args = args
                    break
        if not cb:
            return

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
    def config(self):
        return self._config

    @slip.dbus.polkit.enable_proxy
    def reload(self):
        self.fw.reload()

    @slip.dbus.polkit.enable_proxy
    def complete_reload(self):
        self.fw.completeReload()

    @slip.dbus.polkit.enable_proxy
    def get_property(self, prop):
        return dbus_to_python(self.fw_properties.Get(DBUS_INTERFACE, prop))

    @slip.dbus.polkit.enable_proxy
    def get_properties(self):
        return dbus_to_python(self.fw_properties.GetAll(DBUS_INTERFACE))

    @slip.dbus.polkit.enable_proxy
    def set_property(self, prop, value):
        self.fw_properties.Set(DBUS_INTERFACE, prop, value)

    # panic mode

    @slip.dbus.polkit.enable_proxy
    def enablePanicMode(self):
        self.fw.enablePanicMode()
    
    @slip.dbus.polkit.enable_proxy
    def disablePanicMode(self):
        self.fw.disablePanicMode()

    @slip.dbus.polkit.enable_proxy
    def queryPanicMode(self):
        return dbus_to_python(self.fw.queryPanicMode())

    # list functions

    def listServices(self):
        return dbus_to_python(self.fw.listServices())

    def listIcmpTypes(self):
        return dbus_to_python(self.fw.listIcmpTypes())

    # default zone

    @slip.dbus.polkit.enable_proxy
    def getDefaultZone(self):
        return dbus_to_python(self.fw.getDefaultZone())

    @slip.dbus.polkit.enable_proxy
    def setDefaultZone(self, zone):
        self.fw.setDefaultZone(zone)

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

    @slip.dbus.polkit.enable_proxy
    def isImmutable(self, zone):
        return dbus_to_python(self.fw_zone.isImmutable(zone))

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
    def addMasquerade(self, zone, timeout=0):
        return dbus_to_python(self.fw_zone.addMasquerade(zone, timeout))

    @slip.dbus.polkit.enable_proxy
    def queryMasquerade(self, zone):
        return dbus_to_python(self.fw_zone.queryMasquerade(zone))

    @slip.dbus.polkit.enable_proxy
    def removeMasquerade(self, zone):
        return dbus_to_python(self.fw_zone.removeMasquerade(zone))

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

    # direct chain

    @slip.dbus.polkit.enable_proxy
    def addChain(self, ipv, table, chain):
        self.fw_direct.addChain(ipv, table, chain)

    @slip.dbus.polkit.enable_proxy
    def removeChain(self, ipv, table, chain):
        self.fw_direct.removeChain(ipv, table, chain)

    @slip.dbus.polkit.enable_proxy
    def queryChain(self, ipv, table, chain):
        return dbus_to_python(self.fw_direct.queryChain(ipv, table, chain))

    @slip.dbus.polkit.enable_proxy
    def getChains(self, ipv, table):
        return dbus_to_python(self.fw_direct.getChains(ipv, table))

    # direct rule

    @slip.dbus.polkit.enable_proxy
    def addRule(self, ipv, table, chain, priority, args):
        self.fw_direct.addRule(ipv, table, chain, priority, args)

    @slip.dbus.polkit.enable_proxy
    def removeRule(self, ipv, table, chain, args):
        self.fw_direct.removeRule(ipv, table, chain, args)

    @slip.dbus.polkit.enable_proxy
    def queryRule(self, ipv, table, chain, args):
        return dbus_to_python(self.fw_direct.queryRule(ipv, table, chain, args))

    @slip.dbus.polkit.enable_proxy
    def getRules(self, ipv, table, chain):
        return dbus_to_python(self.fw_direct.getRules(ipv, table, chain))

    # direct passthrough

    @slip.dbus.polkit.enable_proxy
    def passthrough(self, ipv, args):
        return self.fw_direct.passthrough(ipv, args)
