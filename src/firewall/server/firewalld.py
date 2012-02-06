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

import glib
import dbus
import dbus.service
import slip.dbus
import slip.dbus.service

from firewall.config import *
from firewall.config.dbus import *
from firewall.core.fw import Firewall
from firewall.core.logger import log
from firewall.server.decorators import *
from firewall.errors import *

############################################################################
#
# class FirewallD
#
############################################################################

class FirewallD(slip.dbus.service.Object):
    """FirewallD main class"""

    persistent = True
    """Make FirewallD persistent."""

    @handle_exceptions
    def __init__(self, *args, **kwargs):
        super(FirewallD, self).__init__(*args, **kwargs)
        self.fw = Firewall()
        self.path = args[0]
        self.start()

    def __del__(self):
        self.stop()

    @handle_exceptions
    def start(self):
        # tests if iptables and ip6tables are usable using test functions
        # loads default firewall rules for iptables and ip6tables
        log.debug1("start()")
        self._by_key = { }
        self._enabled_services = { }
        self._timeouts = { }
        
        return self.fw.start()

    @handle_exceptions
    def stop(self):
        # stops firewall: unloads firewall modules, flushes chains and tables,
        #   resets policies
        log.debug1("stop()")
        return self.fw.stop()

    # timeout functions

    @dbus_handle_exceptions
    def addTimeout(self, zone, x, tag):
        if zone not in self._timeouts:
            self._timeouts[zone] = { }
        self._timeouts[zone][x] = tag

    @dbus_handle_exceptions
    def removeTimeout(self, zone, x):
        if zone in self._timeouts and x in self._timeouts[zone]:
            glib.source_remove(self._timeouts[zone][x])
            del self._timeouts[zone][x]

    @dbus_handle_exceptions
    def cleanup_timeouts(self):
        # cleanup timeouts
        for zone in self._timeouts:
            for x in self._timeouts[zone]:
                glib.source_remove(self._timeouts[zone][x])
            self._timeouts[zone].clear()
        self._timeouts.clear()

    # property handling

    @dbus_handle_exceptions
    def _get_property(self, prop):
        if prop == "version":
            return VERSION
        elif prop == "interface_version":
            return "%d.%d" % (DBUS_INTERFACE_VERSION,
                              DBUS_INTERFACE_REVISION)
        elif prop == "state":
            return self.fw.get_state()
        else:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.AccessDenied: "
                "Property '%s' isn't exported (or may not exist)" % prop)

    @dbus.service.method(dbus.PROPERTIES_IFACE, in_signature='ss',
                         out_signature='v')
    @dbus_handle_exceptions
    def Get(self, interface_name, property_name):
        # get a property
        log.debug1("Get('%s', '%s')", interface_name, property_name)

        if interface_name != DBUS_INTERFACE:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.UnknownInterface: "
                "FirewallD does not implement %s" % interface_name)

        return self._get_property(property_name)

    @dbus.service.method(dbus.PROPERTIES_IFACE, in_signature='s',
                         out_signature='a{sv}')
    @dbus_handle_exceptions
    def GetAll(self, interface_name):
        log.debug1("GetAll('%s')", interface_name)

        if interface_name != DBUS_INTERFACE:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.UnknownInterface: "
                "FirewallD does not implement %s" % interface_name)

        return {
            'version': self._get_property("version"),
            'interface_version': self._get_property("interface_version"),
            'state': self._get_property("state"),
        }
        

    @dbus.service.method(dbus.PROPERTIES_IFACE, in_signature='ssv')
    @dbus_handle_exceptions
    def Set(self, interface_name, property_name, new_value):
        log.debug1("Set('%s', '%s', '%s')", interface_name, property_name,
                   new_value)

        if interface_name != DBUS_INTERFACE:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.UnknownInterface: "
                "FirewallD does not implement %s" % interface_name)

        raise dbus.exceptions.DBusException(
            "org.freedesktop.DBus.Error.AccessDenied: "
            "Property '%s' is not settable" % property_name)

    @dbus.service.signal(dbus.PROPERTIES_IFACE, signature='sa{sv}as')
    def PropertiesChanged(self, interface_name, changed_properties,
                          invalidated_properties):
        pass

    # reload

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE, in_signature='', out_signature='')
    @dbus_handle_exceptions
    def reload(self, sender=None):
        """Reload the firewall rules.
        """
        log.debug1("reload()")

        # cleanup timeouts in zones
        self.cleanup_timeouts()

        self.fw.reload()
        self.Reloaded()

    # complete_reload

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE, in_signature='', out_signature='')
    @dbus_handle_exceptions
    def completeReload(self, sender=None):
        """Completely reload the firewall.

        Completely reload the firewall: Stops firewall, unloads modules and 
        starts the firewall again.
        """
        log.debug1("completeReload()")

        self.fw.reload(True)
        self.Reloaded()

    @dbus.service.signal(DBUS_INTERFACE)
    @dbus_handle_exceptions
    def Reloaded(self):
        log.debug1("Reloaded()")
        pass

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # PANIC

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE, in_signature='', out_signature='')
    @dbus_handle_exceptions
    def enablePanicMode(self, sender=None):
        """Enable panic mode.
        
        All ingoing and outgoing connections and packets will be blocked.
        """
        log.debug1("enablePanicMode()")
        self.fw.enable_panic_mode()
        self.PanicModeEnabled()

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE, in_signature='', out_signature='')
    @dbus_handle_exceptions
    def disablePanicMode(self, sender=None):
        """Disable panic mode.

        Enables normal mode: Allowed ingoing and outgoing connections 
        will not be blocked anymore
        """
        log.debug1("disablePanicMode()")
        self.fw.disable_panic_mode()
        self.PanicModeDisabled()

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE, in_signature='', out_signature='b')
    @dbus_handle_exceptions
    def queryPanicMode(self, sender=None):
        # returns True if in panic mode
        log.debug1("queryPanicMode()")
        return self.fw.query_panic_mode()

    @dbus.service.signal(DBUS_INTERFACE, signature='')
    @dbus_handle_exceptions
    def PanicModeEnabled(self):
        log.debug1("PanicModeEnabled()")
        pass

    @dbus.service.signal(DBUS_INTERFACE, signature='')
    @dbus_handle_exceptions
    def PanicModeDisabled(self):
        log.debug1("PanicModeDisabled()")
        pass

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # DEFAULT ZONE

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE, in_signature='', out_signature='s')
    @dbus_handle_exceptions
    def getDefaultZone(self, sender=None):
        # returns the system default zone
        log.debug1("getDefaultZone()")
        return self.fw.get_default_zone()

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE, in_signature='s', out_signature='')
    @dbus_handle_exceptions
    def setDefaultZone(self, zone, sender=None):
        # set the system default zone
        log.debug1("setDefaultZone('%s')" % zone)
        self.fw.set_default_zone(zone)
        self.DefaultZoneChanged(zone)

    @dbus.service.signal(DBUS_INTERFACE, signature='s')
    @dbus_handle_exceptions
    def DefaultZoneChanged(self, zone):
        log.debug1("DefaultZoneChanged('%s')" % (zone))
        pass

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # ZONE INTERFACE
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # ZONES

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='',
                         out_signature='as')
    @dbus_handle_exceptions
    def getZones(self, sender=None):
        # returns the list of zones
        log.debug1("zone.getZones()")
        return self.fw.zone.get_zones()

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='',
                         out_signature='a{sas}')
    @dbus_handle_exceptions
    def getActiveZones(self, sender=None):
        # returns the list of active zones
        log.debug1("zone.getActiveZones()")
        zones = { }
        for zone in self.fw.zone.get_zones():
            interfaces = self.fw.zone.get_zone(zone).interfaces
            if len(interfaces) > 0:
                zones[zone] = interfaces
        return zones

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='s')
    @dbus_handle_exceptions
    def getZoneOfInterface(self, interface, sender=None):
        """Return the zone an interface belongs to.

        :Parameters:
            `interface` : str
                Name of the interface
        :Retruns: str. The name of the zone.
        """
        log.debug1("zone.getZoneOfInterface('%s')" % interface)
        zone = self.fw.zone.get_zone_of_interface(interface)
        if zone:
            return zone
        raise FirewallError(UNKNOWN_INTERFACE)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # INTERFACES

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='ss',
                         out_signature='s')
    @dbus_handle_exceptions
    def addInterface(self, zone, interface, sender=None):
        """Add an interface to a zone.
        If zone is empty, use default zone.
        """
        interface = str(interface)
        log.debug1("zone.addInterface('%s', '%s')" % (zone, interface))
        _zone = self.fw.zone.add_interface(zone, interface, sender)

        self.InterfaceAdded(_zone, interface)
        return _zone

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='ss',
                         out_signature='s')
    @dbus_handle_exceptions
    def removeInterface(self, zone, interface, sender=None):
        """Remove interface from a zone.
        If zone is empty, use default zone.
        """
        interface = str(interface)
        log.debug1("zone.removeInterface('%s', '%s')" % (zone, interface))
        _zone = self.fw.zone.remove_interface(zone, interface)

        self.InterfaceRemoved(_zone, interface)
        return _zone

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='ss',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryInterface(self, zone, interface, sender=None):
        """Return true if an interface is in a zone.
        If zone is empty, use default zone.
        """
        interface = str(interface)
        log.debug1("zone.queryInterface('%s', '%s')" % (zone, interface))
        return self.fw.zone.query_interface(zone, interface)

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='as')
    @dbus_handle_exceptions
    def getInterfaces(self, zone, sender=None):
        """Return the list of interfaces of a zone.
        If zone is empty, use default zone.
        """
        log.debug1("zone.getInterfaces('%s')" % (zone))
        return self.fw.zone.get_interfaces(zone)

    @dbus.service.signal(DBUS_INTERFACE_ZONE, signature='ss')
    @dbus_handle_exceptions
    def InterfaceAdded(self, zone, interface):
        log.debug1("zone.InterfaceAdded('%s', '%s')" % (zone, interface))
        pass

    @dbus.service.signal(DBUS_INTERFACE_ZONE, signature='ss')
    @dbus_handle_exceptions
    def InterfaceRemoved(self, zone, interface):
        log.debug1("zone.InterfaceRemoved('%s', '%s')" % (zone, interface))
        pass

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # SERVICES

    @dbus_handle_exceptions
    def disableTimedService(self, zone, service):
        log.debug1("zone.disableTimedService('%s', '%s')" % (zone, service))
        del self._timeouts[zone][service]
        self.fw.zone.remove_service(zone, service)
        self.ServiceRemoved(zone, service)

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='ssi',
                         out_signature='s')
    @dbus_handle_exceptions
    def addService(self, zone, service, timeout, sender=None):
        # enables service <service> if not enabled already for zone
        service = str(service)
        timeout = int(timeout)
        log.debug1("zone.addService('%s', '%s', %d)" % (zone, service, timeout))

        _zone = self.fw.zone.add_service(zone, service, timeout, sender)

        if timeout > 0:
            tag = glib.timeout_add_seconds(timeout, self.disableTimedService,
                                           _zone, service)
            self.addTimeout(_zone, service, tag)

        self.ServiceAdded(_zone, service, timeout)
        return _zone

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='ss',
                         out_signature='s')
    @dbus_handle_exceptions
    def removeService(self, zone, service, sender=None):
        # disables service for zone
        service = str(service)
        log.debug1("zone.removeService('%s', '%s')" % (zone, service))

        _zone = self.fw.zone.remove_service(zone, service)

        self.removeTimeout(_zone, service)
        self.ServiceRemoved(_zone, service)
        return _zone

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='ss',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryService(self, zone, service, sender=None):
        # returns true if a service is enabled for zone
        service = str(service)
        log.debug1("zone.queryService('%s', '%s')" % (zone, service))
        return self.fw.zone.query_service(zone, service)

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='as')
    @dbus_handle_exceptions
    def getServices(self, zone, sender=None):
        # returns the list of enabled services for zone
        log.debug1("zone.getServices('%s')" % (zone))
        return self.fw.zone.get_services(zone)

    @dbus.service.signal(DBUS_INTERFACE_ZONE, signature='ssi')
    @dbus_handle_exceptions
    def ServiceAdded(self, zone, service, timeout):
        log.debug1("zone.ServiceAdded('%s', '%s', %d)" % \
                       (zone, service, timeout))
        pass

    @dbus.service.signal(DBUS_INTERFACE_ZONE, signature='ss')
    @dbus_handle_exceptions
    def ServiceRemoved(self, zone, service):
        log.debug1("zone.ServiceRemoved('%s', '%s')" % (zone, service))
        pass


    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # PORTS

    @dbus_handle_exceptions
    def disableTimedPort(self, zone, port, protocol):
        log.debug1("zone.disableTimedPort('%s', '%s', '%s')" % \
                       (zone, port, protocol))
        del self._timeouts[zone][(port, protocol)]
        self.fw.zone.remove_port(zone, port, protocol)
        self.PortRemoved(zone, port, protocol)

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='sssi',
                         out_signature='s')
    @dbus_handle_exceptions
    def addPort(self, zone, port, protocol, timeout, sender=None):
        # adds port <port> <protocol> if not enabled already to zone
        port = str(port)
        protocol = str(protocol)
        timeout = int(timeout)
        log.debug1("zone.enablePort('%s', '%s', '%s')" % \
                       (zone, port, protocol))
        _zone = self.fw.zone.add_port(zone, port, protocol, timeout, sender)

        if timeout > 0:
            tag = glib.timeout_add_seconds(timeout, self.disableTimedPort,
                                           _zone, port, protocol)
            self.addTimeout(_zone, (port, protocol), tag)

        self.PortAdded(_zone, port, protocol, timeout)
        return _zone

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='sss',
                         out_signature='s')
    @dbus_handle_exceptions
    def removePort(self, zone, port, protocol, sender=None):
        # removes port<port> <protocol> if enabled from zone
        port = str(port)
        protocol = str(protocol)
        log.debug1("zone.removePort('%s', '%s', '%s')" % \
                       (zone, port, protocol))
        _zone= self.fw.zone.remove_port(zone, port, protocol)

        self.removeTimeout(_zone, (port, protocol))
        self.PortRemoved(_zone, port, protocol)
        return _zone

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='sss',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryPort(self, zone, port, protocol, sender=None):
        # returns true if a port is enabled for zone
        port = str(port)
        protocol = str(protocol)
        log.debug1("zone.queryPort('%s', '%s', '%s')" % (zone, port, protocol))
        return self.fw.zone.query_port(zone, port, protocol)

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='aas')
    @dbus_handle_exceptions
    def getPorts(self, zone, sender=None):
        # returns the list of enabled ports
        log.debug1("zone.getPorts('%s')" % (zone))
        return self.fw.zone.get_ports(zone)

    @dbus.service.signal(DBUS_INTERFACE_ZONE, signature='sssi')
    @dbus_handle_exceptions
    def PortAdded(self, zone, port, protocol, timeout=0):
        log.debug1("zone.PortAdded('%s', '%s', '%s', %d)" % \
                       (zone, port, protocol, timeout))
        pass

    @dbus.service.signal(DBUS_INTERFACE_ZONE, signature='sss')
    @dbus_handle_exceptions
    def PortRemoved(self, zone, port, protocol):
        log.debug1("zone.PortRemoved('%s', '%s', '%s')" % \
                       (zone, port, protocol))
        pass

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # MASQUERADE

    @dbus_handle_exceptions
    def disable_masquerade(self, zone):
        del self._timeouts[zone]["masquerade"]
        self.fw.zone.disable_masquerade(zone)
        self.MasqueradeDisabled(zone)

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='si',
                         out_signature='s')
    @dbus_handle_exceptions
    def enableMasquerade(self, zone, timeout, sender=None):
        # enables masquerade if not enabled already
        timeout = int(timeout)
        log.debug1("zone.enableMasquerade('%s')" % (zone))
        _zone = self.fw.zone.enable_masquerade(zone, timeout, sender)
        
        if timeout > 0:
            tag = glib.timeout_add_seconds(timeout, self.disable_masquerade,
                                           _zone)
            self.addTimeout(_zone, "masquerade", tag)

        self.MasqueradeEnabled(_zone, timeout)
        return _zone

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='s')
    @dbus_handle_exceptions
    def disableMasquerade(self, zone, sender=None):
        # disables masquerade
        log.debug1("zone.disableMasquerade('%s')" % (zone))
        _zone = self.fw.zone.disable_masquerade(zone)

        self.removeTimeout(_zone, "masquerade")
        self.MasqueradeDisabled(_zone)
        return _zone

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryMasquerade(self, zone, sender=None):
        # returns true if a masquerade is enabled
        log.debug1("zone.queryMasquerade('%s')" % (zone))
        return self.fw.zone.query_masquerade(zone)

    @dbus.service.signal(DBUS_INTERFACE_ZONE, signature='si')
    @dbus_handle_exceptions
    def MasqueradeEnabled(self, zone, timeout=0):
        log.debug1("zone.MasqueradeEnabled('%s', %d)" % (zone, timeout))
        pass

    @dbus.service.signal(DBUS_INTERFACE_ZONE, signature='s')
    @dbus_handle_exceptions
    def MasqueradeDisabled(self, zone):
        log.debug1("zone.MasqueradeDisabled('%s')" % (zone))
        pass

    # forward ports

    def _disable_forward_port(self, interface, port, protocol, toport, toaddr):
        self.fw.disable_forward_port(interface, port, protocol, toport, toaddr)
        self.ForwardPortSignal(interface, port, protocol, toport, toaddr, False)

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='sssssi',
                         out_signature='i')
    def enableForwardPort(self, interface, port, protocol, toport, toaddr,
                          timeout):
        # enables forward port if not enabled already
        log.debug1("enableForwardPort(%s, %s, %s, %s, %s)" % (interface, port,
                                                       protocol, toport,
                                                       toaddr))
        try:
            self.fw.enable_forward_port(interface, port, protocol, toport,
                                        toaddr)
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR

        if timeout > 0:
            log.debug1("adding timeout %d seconds" % timeout)
            tag = glib.timeout_add_seconds(timeout,
                                           self._disable_forward_port,
                                           interface, port, protocol, toport,
                                           toaddr)
        self.ForwardPortSignal(interface, port, protocol, toport, toaddr, True,
                               timeout)
        return NO_ERROR

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='sssss',
                         out_signature='i')
    def disableForwardPort(self, interface, port, protocol, toport, toaddr):
        # disables forward port
        log.debug1("disableForwardPort(%s, %s, %s, %s, %s)" % (interface, port,
                                                        protocol, toport,
                                                        toaddr))
        try:
            self.fw.disable_forward_port(interface, port, protocol, toport,
                                         toaddr)
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR

        self.ForwardPortSignal(interface, port, protocol, toport, toaddr, False)
        return NO_ERROR

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='sssss',
                         out_signature='i')
    def queryForwardPort(self, interface, port, protocol, toport, toaddr):
        # returns true if a forward port is enabled
        log.debug1("queryForwardPort(%s, %s, %s, %s, %s)" % (interface, port,
                                                      protocol, toport,
                                                      toaddr))
        try:
            enabled = self.fw.query_forward_port(interface, port, protocol,
                                                 toport, toaddr)
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR
        return enabled

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='',
                         out_signature='(iaas)')
    def getForwardPorts(self):
        # returns the list of enabled ports
        log.debug1("getForwardPorts()")
        ports = [ ]
        try:
            ports = self.fw.get_forward_ports()
        except FirewallError, error:
            return (error.code, [])
        except Exception, msg:
            log.debug1(msg)
            return (UNKNOWN_ERROR, [])
        return (len(ports), ports)

    @dbus.service.signal(DBUS_INTERFACE)
    def ForwardPortSignal(self, interface, port, protocol, toport, toaddr,
                          enable, timeout=0):
        log.debug1("ForwardPortSignal(%s, %s, %s, %s, %s, %s, %d)" % (interface, port,
            protocol, toport, toaddr, enable, timeout))
        pass

    # icmp block

    def _disable_icmp_block(self, icmp):
        self.fw.disable_icmp_block(icmp)
        self.IcmpBlockSignal(icmp, False)

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='si', out_signature='i')
    def enableIcmpBlock(self, icmp, timeout):
        # enables icmpblock <icmp> if not enabled already
        log.debug1("enableIcmpBlock('%s')" % icmp)
        try:
            self.fw.enable_icmp_block(icmp)
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR

        if timeout > 0:
            log.debug1("adding timeout %d seconds" % timeout)
            tag = glib.timeout_add_seconds(timeout, self._disable_icmp_block,
                                           icmp)
        self.IcmpBlockSignal(icmp, True, timeout)
        return NO_ERROR

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='s', out_signature='i')
    def disableIcmpBlock(self, icmp):
        # disables icmpBlock
        log.debug1("disableIcmpBlock('%s')" % icmp)
        try:
            self.fw.disable_icmp_block(icmp)
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR

        self.IcmpBlockSignal(icmp, False)
        return NO_ERROR

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='s', out_signature='i')
    def queryIcmpBlock(self, icmp):
        # returns true if a icmp is enabled
        log.debug1("queryIcmpBlock('%s')" % icmp)
        try:
            enabled = self.fw.query_icmp_block(icmp)
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR
        return enabled

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='', out_signature='(ias)')
    def getIcmpBlocks(self):
        # returns the list of enabled icmpblocks
        log.debug1("getIcmpBlocks()")
        icmp_blocks = [ ]
        try:
            icmp_blocks = self.fw.get_icmp_blocks()
        except FirewallError, error:
            return (error.code, [])
        except Exception, msg:
            log.debug1(msg)
            return (UNKNOWN_ERROR, [])
        return (len(icmp_blocks), icmp_blocks)

    @dbus.service.signal(DBUS_INTERFACE)
    def IcmpBlockSignal(self, icmp, enable, timeout=0):
        log.debug1("IcmpBlockSignal(%s, %s, %d)" % (icmp, enable, timeout))
        pass

    # custom

    def _disable_custom(self, table, chain, src, src_port, dst, dst_port,
                        protocol, iface_in, iface_out, phydev_in, physdev_out,
                        target):
        self.fw.disable_custom(table, chain, src, src_port, dst, dst_port,
                               protocol, iface_in, iface_out, phydev_in,
                               physdev_out, target)
        self.CustomSignal(table, chain, src, src_port, dst, dst_port,
                          protocol, iface_in, iface_out, phydev_in,
                          physdev_out, target, False)

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='ssssssssssssi',
                         out_signature='i')
    def enableCustom(self, table, chain, src, src_port, dst, dst_port, protocol,
                     iface_in, iface_out, phydev_in, physdev_out, target,
                     timeout):
        # enables custom if not enabled already
        log.debug1("enableCustom(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)" % \
                (table, chain, src, src_port, dst, dst_port, protocol,
                 iface_in, iface_out, phydev_in, physdev_out, target))

        try:
            self.fw.enable_custom(table, chain, src, src_port, dst, dst_port,
                                  protocol, iface_in, iface_out, phydev_in,
                                  physdev_out, target)
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR

        if timeout > 0:
            log.debug1("adding timeout %d seconds" % timeout)
            tag = glib.timeout_add_seconds(timeout,
                                           self._disable_custom,
                                           table, chain, src, src_port, dst,
                                           dst_port,
                                           protocol, iface_in, iface_out,
                                           phydev_in, physdev_out, target)
        self.CustomSignal(table, chain, src, src_port, dst, dst_port,
                          protocol, iface_in, iface_out, phydev_in,
                          physdev_out, target, True, timeout)
        return NO_ERROR


    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='ssssssssssss',
                         out_signature='i')
    def disableCustom(self, table, chain, src, src_port, dst, dst_port,
                      protocol, iface_in, iface_out, phydev_in, physdev_out,
                      target):
        # disables custom
        log.debug1("disableCustom(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)" %\
                (table, chain, src, src_port, dst, dst_port, protocol,
                 iface_in, iface_out, phydev_in, physdev_out, target))

        try:
            self.fw.disable_custom(table, chain, src, src_port, dst, dst_port,
                                   protocol, iface_in, iface_out, phydev_in,
                                   physdev_out, target)
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR

        self.CustomSignal(table, chain, src, src_port, dst, dst_port,
                          protocol, iface_in, iface_out, phydev_in,
                          physdev_out, target, False)
        return NO_ERROR

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='ssssssssssss',
                         out_signature='(bs)')
    def queryCustom(self, table, chain, src, src_port, dst, dst_port,
                    protocol, iface_in, iface_out, phydev_in, physdev_out,
                    target):
        # returns true if a custom is enabled
        log.debug1("queryCustom(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)" % \
                (table, chain, src, src_port, dst, dst_port, protocol,
                 iface_in, iface_out, phydev_in, physdev_out, target))
        try:
            enabled = self.fw.query_custom(table, chain, src, src_port,
                                           dst, dst_port, protocol,
                                           iface_in, iface_out,
                                           phydev_in, physdev_out, target)
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR
        return enabled

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='',
                         out_signature='(iaas)')
    def getCustoms(self):
        # returns the list of enabled ports
        log.debug1("getCustoms()")
        custom_rules = [ ]
        try:
            custom_rules = self.fw.get_customs()
        except FirewallError, error:
            return (error.code, [])
        except Exception, msg:
            log.debug1(msg)
            return (UNKNOWN_ERROR, [])
        return (len(custom_rules), custom_rules)

    @dbus.service.signal(DBUS_INTERFACE)
    def CustomSignal(self, table, chain, src, src_port, dst, dst_port,
                     protocol, iface_in, iface_out, phydev_in, physdev_out,
                     target, enable, timeout=0):
        log.debug1("CustomSignal(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %d)" % (table, chain, src, src_port, dst, dst_port, protocol, iface_in, iface_out, phydev_in, physdev_out, target, enable, timeout))
        pass

    # virt

    def _virt_disable_rule(self, table, chain, args):
        self.fw.virt_delete_rule(table, chain, args)
        # no signal so far

    @slip.dbus.polkit.require_auth(PK_ACTION_DIRECT)
    @dbus.service.method(DBUS_INTERFACE, in_signature='sssasi', out_signature='i')
    def virtInsertRule(self, ipv, table, chain, args, timeout):
        # inserts virt rule
        log.debug1("virtInsertRule('%s','%s', '%s'" % table, chain, "','". join(args))
        try:
            self.fw.virt_insert_rule(ipv, table, chain, args)
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR

        if timeout > 0:
            log.debug1("adding timeout %d seconds" % timeout)
            tag = glib.timeout_add_seconds(timeout, self._virt_disable_rule, 
                                           table, chain, args)
        # no signal so far
        return NO_ERROR

    @slip.dbus.polkit.require_auth(PK_ACTION_DIRECT)
    @dbus.service.method(DBUS_INTERFACE, in_signature='sssas', out_signature='i')
    def virtDeleteRule(self, ipv, table, chain, args):
        # disables icmpBlock
        log.debug1("virtDeleteRule('%s','%s', '%s'" % table, chain, "','". join(args))
        try:
            self.fw.virt_delete_rule(ipv, table, chain, args)
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR

        # no signal so far
        return NO_ERROR
    
    @slip.dbus.polkit.require_auth(PK_ACTION_DIRECT)
    @dbus.service.method(DBUS_INTERFACE, in_signature='sssas', out_signature='i')
    def virtQueryRule(self, ipv, table, chain, args):
        # returns true if a icmp is enabled
        log.debug1("queryIcmpBlock('%s')" % icmp)
        try:
            enabled = self.fw.virt_query_rule(ipv, table, chain, args)
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR
        return enabled

