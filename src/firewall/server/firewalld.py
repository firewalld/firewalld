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

from gi.repository import GLib
import dbus
import dbus.service
import slip.dbus
import slip.dbus.service

from firewall.config import *
from firewall.config.dbus import *
from firewall.core.fw import Firewall
from firewall.core.logger import log
from firewall.server.decorators import *
from firewall.server.config import FirewallDConfig
from firewall.errors import *

############################################################################
#
# class FirewallD
#
############################################################################

class FirewallD(slip.dbus.service.Object):
    """FirewallD main class"""

    persistent = True
    """ Make FirewallD persistent. """
    default_polkit_auth_required = PK_ACTION_INFO
    """ Use PK_ACTION_INFO as a default """

    @handle_exceptions
    def __init__(self, *args, **kwargs):
        super(FirewallD, self).__init__(*args, **kwargs)
        self.fw = Firewall()
        self.path = args[0]
        self.start()
        self.config = FirewallDConfig(self.fw.config, self.path,
                                      DBUS_PATH_CONFIG)

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
            GLib.source_remove(self._timeouts[zone][x])
            del self._timeouts[zone][x]

    @dbus_handle_exceptions
    def cleanup_timeouts(self):
        # cleanup timeouts
        for zone in self._timeouts:
            for x in self._timeouts[zone]:
                GLib.source_remove(self._timeouts[zone][x])
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
        

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
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

        self.fw.reload()
        self.config.reload()
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

    @slip.dbus.polkit.require_auth(PK_ACTION_INFO)
    @dbus_service_method(DBUS_INTERFACE, in_signature='', out_signature='')
    @dbus_handle_exceptions
    def enablePanicMode(self, sender=None):
        """Enable panic mode.
        
        All ingoing and outgoing connections and packets will be blocked.
        """
        log.debug1("enablePanicMode()")
        self.fw.enable_panic_mode()
        self.PanicModeEnabled()

    @slip.dbus.polkit.require_auth(PK_ACTION_INFO)
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

    @slip.dbus.polkit.require_auth(PK_ACTION_INFO)
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

    # list functions

    @slip.dbus.polkit.require_auth(PK_ACTION_INFO)
    @dbus_service_method(DBUS_INTERFACE, in_signature='',
                         out_signature='as')
    @dbus_handle_exceptions
    def listServices(self, sender=None):
        # returns the list of services
        log.debug1("listServices()")
        return self.fw.service.get_services()

    @slip.dbus.polkit.require_auth(PK_ACTION_INFO)
    @dbus_service_method(DBUS_INTERFACE, in_signature='',
                         out_signature='as')
    @dbus_handle_exceptions
    def listIcmpTypes(self, sender=None):
        # returns the list of services
        log.debug1("listServices()")
        return self.fw.icmptype.get_icmptypes()

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # DEFAULT ZONE

    @slip.dbus.polkit.require_auth(PK_ACTION_INFO)
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

    @slip.dbus.polkit.require_auth(PK_ACTION_INFO)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='',
                         out_signature='as')
    @dbus_handle_exceptions
    def getZones(self, sender=None):
        # returns the list of zones
        log.debug1("zone.getZones()")
        return self.fw.zone.get_zones()

    @slip.dbus.polkit.require_auth(PK_ACTION_INFO)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='',
                         out_signature='a{sas}')
    @dbus_handle_exceptions
    def getActiveZones(self, sender=None):
        # returns the list of active zones
        log.debug1("zone.getActiveZones()")
        zones = { }
        for zone in self.fw.zone.get_zones():
            interfaces = self.fw.zone.get_interfaces(zone)
            if len(interfaces) > 0:
                zones[zone] = interfaces
        return zones

    @slip.dbus.polkit.require_auth(PK_ACTION_INFO)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='s')
    @dbus_handle_exceptions
    def getZoneOfInterface(self, interface, sender=None):
        """Return the zone an interface belongs to.

        :Parameters:
            `interface` : str
                Name of the interface
        :Returns: str. The name of the zone.
        """
        log.debug1("zone.getZoneOfInterface('%s')" % interface)
        zone = self.fw.zone.get_zone_of_interface(interface)
        if zone:
            return zone
        raise FirewallError(UNKNOWN_INTERFACE, interface)

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='b')
    @dbus_handle_exceptions
    def isImmutable(self, zone, sender=None):
        # immutable zones: block, drop, trusted
        log.debug1("zone.isImmutable('%s')" % zone)
        return self.fw.zone.is_immutable(zone)

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
    def changeZone(self, zone, interface, sender=None):
        """Change a zone an interface is part of.
        If zone is empty, use default zone.
        """
        interface = str(interface)
        log.debug1("zone.changeZone('%s', '%s')" % (zone, interface))
        _zone = self.fw.zone.change_zone(zone, interface, sender)

        self.ZoneChanged(_zone, interface)
        return _zone

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='ss',
                         out_signature='s')
    @dbus_handle_exceptions
    def removeInterface(self, zone, interface, sender=None):
        """Remove interface from a zone.
        If zone is empty, remove from zone the interface belongs to.
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
    def ZoneChanged(self, zone, interface):
        log.debug1("zone.ZoneChanged('%s', '%s')" % (zone, interface))
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
            tag = GLib.timeout_add_seconds(timeout, self.disableTimedService,
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
            tag = GLib.timeout_add_seconds(timeout, self.disableTimedPort,
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
    def disableTimedMasquerade(self, zone):
        del self._timeouts[zone]["masquerade"]
        self.fw.zone.remove_masquerade(zone)
        self.MasqueradeRemoved(zone)

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='si',
                         out_signature='s')
    @dbus_handle_exceptions
    def addMasquerade(self, zone, timeout, sender=None):
        # adds masquerade if not added already
        timeout = int(timeout)
        log.debug1("zone.addMasquerade('%s')" % (zone))
        _zone = self.fw.zone.add_masquerade(zone, timeout, sender)
        
        if timeout > 0:
            tag = GLib.timeout_add_seconds(timeout, self.disableTimedMasquerade,
                                           _zone)
            self.addTimeout(_zone, "masquerade", tag)

        self.MasqueradeAdded(_zone, timeout)
        return _zone

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='s')
    @dbus_handle_exceptions
    def removeMasquerade(self, zone, sender=None):
        # removes masquerade
        log.debug1("zone.removeMasquerade('%s')" % (zone))
        _zone = self.fw.zone.remove_masquerade(zone)

        self.removeTimeout(_zone, "masquerade")
        self.MasqueradeRemoved(_zone)
        return _zone

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryMasquerade(self, zone, sender=None):
        # returns true if a masquerade is added
        log.debug1("zone.queryMasquerade('%s')" % (zone))
        return self.fw.zone.query_masquerade(zone)

    @dbus.service.signal(DBUS_INTERFACE_ZONE, signature='si')
    @dbus_handle_exceptions
    def MasqueradeAdded(self, zone, timeout=0):
        log.debug1("zone.MasqueradeAdded('%s', %d)" % (zone, timeout))
        pass

    @dbus.service.signal(DBUS_INTERFACE_ZONE, signature='s')
    @dbus_handle_exceptions
    def MasqueradeRemoved(self, zone):
        log.debug1("zone.MasqueradeRemoved('%s')" % (zone))
        pass

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # FORWARD PORT

    @dbus_handle_exceptions
    def disable_forward_port(self, zone, port, protocol, toport, toaddr):
        del self._timeouts[zone][(port, protocol, toport, toaddr)]
        self.fw.zone.remove_forward_port(zone, port, protocol, toport, toaddr)
        self.ForwardPortRemoved(zone, port, protocol, toport, toaddr)

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='sssssi',
                         out_signature='s')
    @dbus_handle_exceptions
    def addForwardPort(self, zone, port, protocol, toport, toaddr, timeout,
                       sender=None):
        # add forward port if not enabled already for zone
        port = str(port)
        protocol = str(protocol)
        toport = str(toport)
        toaddr = str(toaddr)
        timeout = int(timeout)
        log.debug1("zone.addForwardPort('%s', '%s', '%s', '%s', '%s')" % \
                       (zone, port, protocol, toport, toaddr))
        _zone = self.fw.zone.add_forward_port(zone, port, protocol, toport,
                                              toaddr, timeout, sender)

        if timeout > 0:
            tag = GLib.timeout_add_seconds(timeout,
                                           self.disable_forward_port,
                                           _zone, port, protocol, toport,
                                           toaddr)
            self.addTimeout(_zone, (port, protocol, toport, toaddr), tag)

        self.ForwardPortAdded(_zone, port, protocol, toport, toaddr, timeout)
        return _zone

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='sssss',
                         out_signature='s')
    @dbus_handle_exceptions
    def removeForwardPort(self, zone, port, protocol, toport, toaddr,
                          sender=None):
        # remove forward port from zone
        port = str(port)
        protocol = str(protocol)
        toport = str(toport)
        toaddr = str(toaddr)
        log.debug1("zone.removeForwardPort('%s', '%s', '%s', '%s', '%s')" % \
                       (zone, port, protocol, toport, toaddr))
        _zone = self.fw.zone.remove_forward_port(zone, port, protocol, toport,
                                                 toaddr)

        self.removeTimeout(_zone, (port, protocol, toport, toaddr))
        self.ForwardPortRemoved(_zone, port, protocol, toport, toaddr)
        return _zone

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='sssss',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryForwardPort(self, zone, port, protocol, toport, toaddr,
                         sender=None):
        # returns true if a forward port is enabled for zone
        port = str(port)
        protocol = str(protocol)
        toport = str(toport)
        toaddr = str(toaddr)
        log.debug1("zone.queryForwardPort('%s', '%s', '%s', '%s', '%s')" % \
                       (zone, port, protocol, toport, toaddr))
        return self.fw.zone.query_forward_port(zone, port, protocol, toport,
                                               toaddr)

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='aas')
    @dbus_handle_exceptions
    def getForwardPorts(self, zone, sender=None):
        # returns the list of enabled ports for zone
        log.debug1("zone.getForwardPorts('%s')" % (zone))
        return self.fw.zone.get_forward_ports(zone)

    @dbus.service.signal(DBUS_INTERFACE_ZONE, signature='sssssi')
    @dbus_handle_exceptions
    def ForwardPortAdded(self, zone, port, protocol, toport, toaddr,
                         timeout=0):
        log.debug1("zone.ForwardPortAdded('%s', '%s', '%s', '%s', '%s', %d)" % \
                       (zone, port, protocol, toport, toaddr, timeout))
        pass

    @dbus.service.signal(DBUS_INTERFACE_ZONE, signature='sssss')
    @dbus_handle_exceptions
    def ForwardPortRemoved(self, zone, port, protocol, toport, toaddr):
        log.debug1("zone.ForwardPortRemoved('%s', '%s', '%s', '%s', '%s')" % \
                       (zone, port, protocol, toport, toaddr))
        pass

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # ICMP BLOCK

    @dbus_handle_exceptions
    def disableTimedIcmpBlock(self, zone, icmp, sender):
        log.debug1("zone.disableTimedIcmpBlock('%s', '%s')" % (zone, icmp))
        del self._timeouts[zone][icmp]
        self.fw.zone.remove_icmp_block(zone, icmp)
        self.IcmpBlockRemoved(zone, icmp)

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='ssi',
                         out_signature='s')
    @dbus_handle_exceptions
    def addIcmpBlock(self, zone, icmp, timeout, sender=None):
        # add icmpblock <icmp> if not enabled already for zone
        icmp = str(icmp)
        timeout = int(timeout)
        log.debug1("zone.enableIcmpBlock('%s', '%s')" % (zone, icmp))
        _zone = self.fw.zone.add_icmp_block(zone, icmp, timeout, sender)

        if timeout > 0:
            tag = GLib.timeout_add_seconds(timeout, self.disableTimedIcmpBlock,
                                           _zone, icmp, sender)
            self.addTimeout(_zone, icmp, tag)

        self.IcmpBlockAdded(_zone, icmp, timeout)
        return _zone

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='ss',
                         out_signature='s')
    @dbus_handle_exceptions
    def removeIcmpBlock(self, zone, icmp, sender=None):
        # removes icmpBlock from zone
        icmp = str(icmp)
        log.debug1("zone.removeIcmpBlock('%s', '%s')" % (zone, icmp))
        _zone = self.fw.zone.remove_icmp_block(zone, icmp)

        self.removeTimeout(_zone, icmp)
        self.IcmpBlockRemoved(_zone, icmp)
        return _zone

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='ss',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryIcmpBlock(self, zone, icmp, sender=None):
        # returns true if a icmp is enabled for zone
        icmp = str(icmp)
        log.debug1("zone.queryIcmpBlock('%s', '%s')" % (zone, icmp))
        return self.fw.zone.query_icmp_block(zone, icmp)

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus_service_method(DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='as')
    @dbus_handle_exceptions
    def getIcmpBlocks(self, zone, sender=None):
        # returns the list of enabled icmpblocks
        log.debug1("zone.getIcmpBlocks('%s')" % (zone))
        return self.fw.zone.get_icmp_blocks(zone)

    @dbus.service.signal(DBUS_INTERFACE_ZONE, signature='ssi')
    @dbus_handle_exceptions
    def IcmpBlockAdded(self, zone, icmp, timeout=0):
        log.debug1("zone.IcmpBlockAdded('%s', '%s', %d)" % \
                       (zone, icmp, timeout))
        pass

    @dbus.service.signal(DBUS_INTERFACE_ZONE, signature='ss')
    @dbus_handle_exceptions
    def IcmpBlockRemoved(self, zone, icmp):
        log.debug1("zone.IcmpBlockRemoved('%s', '%s')" % (zone, icmp))
        pass

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # DIRECT INTERFACE
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # DIRECT CHAIN

    @slip.dbus.polkit.require_auth(PK_ACTION_DIRECT)
    @dbus_service_method(DBUS_INTERFACE_DIRECT, in_signature='sss',
                         out_signature='')
    @dbus_handle_exceptions
    def addChain(self, ipv, table, chain, sender=None):
        # inserts direct chain
        ipv = str(ipv)
        table = str(table)
        chain = str(chain)
        log.debug1("direct.addChain('%s', '%s', '%s')" % (ipv, table, chain))
        self.fw.direct.add_chain(ipv, table, chain)
        self.ChainAdded(ipv, table, chain)

    @slip.dbus.polkit.require_auth(PK_ACTION_DIRECT)
    @dbus_service_method(DBUS_INTERFACE_DIRECT, in_signature='sss',
                         out_signature='')
    @dbus_handle_exceptions
    def removeChain(self, ipv, table, chain, sender=None):
        # removes direct chain
        ipv = str(ipv)
        table = str(table)
        chain = str(chain)
        log.debug1("direct.removeChain('%s', '%s', '%s')" % (ipv, table, chain))
        self.fw.direct.remove_chain(ipv, table, chain)
        self.ChainRemoved(ipv, table, chain)
    
    @slip.dbus.polkit.require_auth(PK_ACTION_DIRECT)
    @dbus_service_method(DBUS_INTERFACE_DIRECT, in_signature='sss',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryChain(self, ipv, table, chain, sender=None):
        # returns true if a chain is enabled
        ipv = str(ipv)
        table = str(table)
        chain = str(chain)
        log.debug1("direct.queryChain('%s', '%s', '%s')" % (ipv, table, chain))
        return self.fw.direct.query_chain(ipv, table, chain)

    @slip.dbus.polkit.require_auth(PK_ACTION_DIRECT)
    @dbus_service_method(DBUS_INTERFACE_DIRECT, in_signature='ss',
                         out_signature='as')
    @dbus_handle_exceptions
    def getChains(self, ipv, table, sender=None):
        # returns list of added chains
        ipv = str(ipv)
        table = str(table)
        log.debug1("direct.getChains('%s', '%s')" % (ipv, table))
        return self.fw.direct.get_chains(ipv, table)

    @dbus.service.signal(DBUS_INTERFACE_DIRECT, signature='sss')
    @dbus_handle_exceptions
    def ChainAdded(self, ipv, table, chain):
        log.debug1("direct.ChainAdded('%s', '%s', '%s')" % (ipv, table, chain))
        pass

    @dbus.service.signal(DBUS_INTERFACE_DIRECT, signature='sss')
    @dbus_handle_exceptions
    def ChainRemoved(self, ipv, table, chain):
        log.debug1("direct.ChainRemoved('%s', '%s', '%s')" % (ipv, table, chain))
        pass

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # DIRECT RULE

    @slip.dbus.polkit.require_auth(PK_ACTION_DIRECT)
    @dbus_service_method(DBUS_INTERFACE_DIRECT, in_signature='sssias',
                         out_signature='')
    @dbus_handle_exceptions
    def addRule(self, ipv, table, chain, priority, args, sender=None):
        # inserts direct rule
        ipv = str(ipv)
        table = str(table)
        chain = str(chain)
        priority = int(priority)
        args = tuple( str(i) for i in args )
        log.debug1("direct.addRule('%s', '%s', '%s', '%s')" % \
                       (ipv, table, chain, "','".join(args)))
        self.fw.direct.add_rule(ipv, table, chain, priority, args)
        self.RuleAdded(ipv, table, chain, args)

    @slip.dbus.polkit.require_auth(PK_ACTION_DIRECT)
    @dbus_service_method(DBUS_INTERFACE_DIRECT, in_signature='sssas',
                         out_signature='')
    @dbus_handle_exceptions
    def removeRule(self, ipv, table, chain, args, sender=None):
        # removes direct rule
        ipv = str(ipv)
        table = str(table)
        chain = str(chain)
        args = tuple( str(i) for i in args )
        log.debug1("direct.removeRule('%s', '%s', '%s', '%s')" % \
                       (ipv, table, chain, "','".join(args)))
        self.fw.direct.remove_rule(ipv, table, chain, args)
        self.RuleRemoved(ipv, table, chain, args)
    
    @slip.dbus.polkit.require_auth(PK_ACTION_DIRECT)
    @dbus_service_method(DBUS_INTERFACE_DIRECT, in_signature='sssas',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryRule(self, ipv, table, chain, args, sender=None):
        # returns true if a rule is enabled
        ipv = str(ipv)
        table = str(table)
        chain = str(chain)
        args = tuple( str(i) for i in args )
        log.debug1("directQueryRule('%s','%s', '%s')" % (table, chain,
                                                         "','".join(args)))
        return self.fw.direct.query_rule(ipv, table, chain, args)

    @slip.dbus.polkit.require_auth(PK_ACTION_DIRECT)
    @dbus_service_method(DBUS_INTERFACE_DIRECT, in_signature='sss',
                         out_signature='aas')
    @dbus_handle_exceptions
    def getRules(self, ipv, table, chain, sender=None):
        # returns list of added rules
        log.debug1("direct.getRules('%s', '%s', '%s')" % (ipv, table, chain))
        return self.fw.direct.get_rules(ipv, table, chain)

    @dbus.service.signal(DBUS_INTERFACE_DIRECT, signature='sssas')
    @dbus_handle_exceptions
    def RuleAdded(self, ipv, table, chain, args):
        log.debug1("direct.RuleAdded('%s', '%s', '%s')" % (table, chain,
                   "','".join(args)))
        pass

    @dbus.service.signal(DBUS_INTERFACE_DIRECT, signature='sssas')
    @dbus_handle_exceptions
    def RuleRemoved(self, ipv, table, chain, args):
        log.debug1("direct.RuleRemoved('%s', '%s', '%s')" % (table, chain,
                                                             "','".join(args)))
        pass

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # DIRECT PASSTHROUGH

    @slip.dbus.polkit.require_auth(PK_ACTION_DIRECT)
    @dbus_service_method(DBUS_INTERFACE_DIRECT, in_signature='sas',
                         out_signature='s')
    @dbus_handle_exceptions
    def passthrough(self, ipv, args, sender=None):
        # inserts direct rule
        ipv = str(ipv)
        args = tuple( str(i) for i in args )
        log.debug1("direct.passthrough('%s', '%s')" % (ipv, "','".join(args)))
        return self.fw.direct.passthrough(ipv, args)
