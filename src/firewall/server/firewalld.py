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
# signal handling and run_server derived from setroubleshoot
# Copyright (C) 2006,2007,2008,2009 Red Hat, Inc.
# Authors:
#   John Dennis <jdennis@redhat.com>
#   Thomas Liu  <tliu@redhat.com>
#   Dan Walsh <dwalsh@redhat.com>

import os, sys

import signal
from gi.repository import GObject
import glib
import dbus
import dbus.service
from dbus.exceptions import DBusException
import dbus.mainloop.glib
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
    def __init__(self, *args, **kwargs):
        super(FirewallD, self).__init__(*args, **kwargs)
        self.persistent = True
        self.fw = Firewall()
        self.start()

    def __del__(self):
        self.stop()

    def start(self):
        # tests if iptables and ip6tables are usable using test functions
        # loads default firewall rules for iptables and ip6tables
        log.debug1("start()")
        self._by_key = { }
        self._enabled_services = { }
        self._timeouts = { }
        
        return self.fw.start()

    def stop(self):
        # stops firewall: unloads firewall modules, flushes chains and tables,
        #   resets policies
        log.debug1("stop()")
        return self.fw.stop()

    # reload

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='', out_signature='i')
    def reload(self):
        # reloads firewall rules
        log.debug1("reload()")
        try:
            self.fw.reload()
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR
        return NO_ERROR

    # restart

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='', out_signature='i')
    def restart(self):
        # stops firewall: unloads firewall modules
        # starts firewall
        log.debug1("restart()")
        try:
            self.fw.restart()
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR
        return NO_ERROR

    # status

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='', out_signature='i')
    def status(self):
        # returns firewall state: panic, ipv4, ipv6, ..
        # enabled or disabled, why?
        log.debug1("status()")
        try:
            status = self.fw.status()
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR
        return NO_ERROR

    # panic

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='', out_signature='i')
    def enablePanicMode(self):
        # enables panic mode
        log.debug1("enablePanicMode()")
        try:
            self.fw.enable_panic_mode()
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR

        self.PanicSignal(True)
        return NO_ERROR

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='', out_signature='i')
    def disablePanicMode(self):
        # enables normal mode: return from panic mode
        log.debug1("disablePanicMode()")
        try:
            self.fw.disable_panic_mode()
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR

        self.PanicSignal(False)
        return NO_ERROR

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='', out_signature='i')
    def queryPanicMode(self):
        # returns True if in panic mode
        log.debug1("queryPanicMode()")
        try:
            enabled = self.fw.query_panic_mode()
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR
        return enabled

    @dbus.service.signal(DBUS_INTERFACE)
    def PanicSignal(self, enabled):
        log.debug1("PanicSignal(%s)" % enabled)
        pass

    # services

    def _disable_service(self, service):
        self.fw.disable_service(service)
        self.ServiceSignal(service, False)

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='si', out_signature='i')
    def enableService(self, service, timeout):
        # enables service <service> if not enabled already
        log.debug1("enableService('%s')" % service)
        try:
            self.fw.enable_service(service)
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR

        if timeout > 0:
            log.debug1("adding timeout %d seconds" % timeout)
            tag = glib.timeout_add_seconds(timeout, self._disable_service,
                                           service)
            self._timeouts[service] = tag

#        key = self.__new_key()
#        self._enabled_services[service] = key
#        self._by_key[key] = service

        self.ServiceSignal(service, True, timeout)
        return NO_ERROR

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='s', out_signature='i')
    def disableService(self, service):
        # disables service
        log.debug1("disableService('%s')" % service)
        try:
            self.fw.disable_service(service)
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR

        if service in self._timeouts:
            glib.source_remove(self._timeouts[service])
            del self._timeouts[service]

#        key = self._enabled_services[service]
#        del self._by_key[key]
#        del self._enabled_services[service]

        self.ServiceSignal(service, False)
        return NO_ERROR

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='s', out_signature='i')
    def queryService(self, service):
        # returns true if a service is enabled
        log.debug1("queryService('%s')" % service)
        try:
            enabled = self.fw.query_service(service)
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR
        return enabled

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='', out_signature='(ias)')
    def getServices(self):
        # returns the list of enabled services
        log.debug1("getServices()")
        services = [ ]
        try:
            services = self.fw.get_services()
        except FirewallError, error:
            return (error.code, [])
        except Exception, msg:
            log.debug1(msg)
            return (UNKNOWN_ERROR, [])
        return (len(services), services)

    @dbus.service.signal(DBUS_INTERFACE)
    def ServiceSignal(self, service, enable, timeout=0):
        log.debug1("ServiceSignal(%s, %s, %d)" % (service, enable, timeout))
        pass

    # ports

    def _disable_port(self, port, protocol):
        self.fw.disable_port(port, protocol)
        self.PortSignal(port, protocol, False)

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='ssi', out_signature='i')
    def enablePort(self, port, protocol, timeout):
        # enables port <port> <protocol> if not enabled already
        log.debug1("enablePort(%s, %s)" % (port, protocol))
        try:
            self.fw.enable_port(port, protocol)
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR

        if timeout > 0:
            log.debug1("adding timeout %d seconds" % timeout)
            tag = glib.timeout_add_seconds(timeout, self._disable_port,
                                           port, protocol)

        self.PortSignal(port, protocol, True, timeout)
        return NO_ERROR

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='ss', out_signature='i')
    def disablePort(self, port, protocol):
        # disables port
        log.debug1("disablePort(%s, %s)" % (port, protocol))
        try:
            self.fw.disable_port(port, protocol)
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR

        self.PortSignal(port, protocol, False)
        return NO_ERROR

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='ss', out_signature='i')
    def queryPort(self, port, protocol):
        # returns true if a port is enabled
        log.debug1("queryPort(%s, %s)" % (port, protocol))
        try:
            enabled = self.fw.query_port(port, protocol)
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR
        return enabled

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='',
                         out_signature='(iaas)')
    def getPorts(self):
        # returns the list of enabled ports
        log.debug1("getPorts()")
        ports = [ ]
        try:
            ports = self.fw.get_ports()
        except FirewallError, error:
            return (error.code, [])
        except Exception, msg:
            log.debug1(msg)
            return (UNKNOWN_ERROR, [])
        return (len(ports), ports)

    @dbus.service.signal(DBUS_INTERFACE)
    def PortSignal(self, port, protocol, enable, timeout=0):
        log.debug1("PortSignal(%s, %s, %s, %d)" % (port, protocol, enable, timeout))
        pass

    # trusted

    def _disable_trusted(self, trusted):
        self.fw.disable_trusted(trusted)
        self.TrustedSignal(trusted, False)

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='si', out_signature='i')
    def enableTrusted(self, trusted, timeout):
        # enables trusted <trusted> if not enabled already
        log.debug1("enableTrusted('%s')" % trusted)
        try:
            self.fw.enable_trusted(trusted)
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR

        if timeout > 0:
            log.debug1("adding timeout %d seconds" % timeout)
            tag = glib.timeout_add_seconds(timeout, self._disable_trusted,
                                           trusted)
        self.TrustedSignal(trusted, True, timeout)
        return NO_ERROR

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='s', out_signature='i')
    def disableTrusted(self, trusted):
        # disables trusted
        log.debug1("disableTrusted('%s')" % trusted)
        try:
            self.fw.disable_trusted(trusted)
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR

        self.TrustedSignal(trusted, False)
        return NO_ERROR

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='s', out_signature='i')
    def queryTrusted(self, trusted):
        # returns true if a trusted is enabled
        log.debug1("queryTrusted('%s')" % trusted)
        try:
            enabled = self.fw.query_trusted(trusted)
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR
        return enabled

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='', out_signature='(ias)')
    def getTrusted(self):
        # returns the list trusted
        log.debug1("getTrusted()")
        trusted = [ ]
        try:
            trusted = self.fw.get_trusted()
        except FirewallError, error:
            return (error.code, [])
        except Exception, msg:
            log.debug1(msg)
            return (UNKNOWN_ERROR, [])
        return (len(trusted), trusted)

    @dbus.service.signal(DBUS_INTERFACE)
    def TrustedSignal(self, trusted, enable, timeout=0):
        log.debug1("TrustedSignal(%s, %s, %d)" % (trusted, enable, timeout))
        pass

    # masquerade

    def _disable_masquerade(self, masquerade):
        self.fw.disable_masquerade(masquerade)
        self.MasqueradeSignal(masquerade, False)

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='si', out_signature='i')
    def enableMasquerade(self, masquerade, timeout):
        # enables masquerade <masquerade> if not enabled already
        log.debug1("enableMasquerade('%s')" % masquerade)
        try:
            self.fw.enable_masquerade(masquerade)
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR

        if timeout > 0:
            log.debug1("adding timeout %d seconds" % timeout)
            tag = glib.timeout_add_seconds(timeout, self._disable_masquerade,
                                           masquerade)
        self.MasqueradeSignal(masquerade, True, timeout)
        return NO_ERROR

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='s', out_signature='i')
    def disableMasquerade(self, masquerade):
        # disables masquerade
        log.debug1("disableMasquerade('%s')" % masquerade)
        try:
            self.fw.disable_masquerade(masquerade)
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR

        self.MasqueradeSignal(masquerade, False)
        return NO_ERROR

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='s', out_signature='i')
    def queryMasquerade(self, masquerade):
        # returns true if a masquerade is enabled
        log.debug1("queryMasquerade('%s')" % masquerade)
        try:
            enabled = self.fw.query_masquerade(masquerade)
        except FirewallError, error:
            return error.code
        except Exception, msg:
            log.debug1(msg)
            return UNKNOWN_ERROR
        return enabled

    @slip.dbus.polkit.require_auth(PK_ACTION_CONFIG)
    @dbus.service.method(DBUS_INTERFACE, in_signature='', out_signature='(ias)')
    def getMasquerades(self):
        # returns the list of enabled masquerades
        log.debug1("getMasquerades()")
        masquerade = [ ]
        try:
            masquerade = self.fw.get_masquerades()
        except FirewallError, error:
            return (error.code, [])
        except Exception, msg:
            log.debug1(msg)
            return (UNKNOWN_ERROR, [])
        return (len(masquerade), masquerade)

    @dbus.service.signal(DBUS_INTERFACE)
    def MasqueradeSignal(self, masquerade, enable, timeout=0):
        log.debug1("MasqueradeSignal(%s, %s, %d)" % (masquerade, enable, timeout))
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

    # net

############################################################################
#
# signal handler
#
############################################################################

def sighandler(signum, frame):
    """ signal handler
    """
    # reloading over dbus is not working server is not responding anymore
    # therefore using external firewall-cmd 
    if signum == signal.SIGHUP:
        os.system("firewall-cmd --reload &")
        return

    sys.exit()

############################################################################
#
# run_server function
#
############################################################################

def run_server():
    """ Main function for firewall server. Handles D-BUS and GLib mainloop.
    """
    signal.signal(signal.SIGHUP, sighandler)
    signal.signal(signal.SIGQUIT, sighandler)
    signal.signal(signal.SIGTERM, sighandler)
    signal.signal(signal.SIGALRM, sighandler)

    service = None

    try:
        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        bus = dbus.SystemBus()
        name = dbus.service.BusName(DBUS_INTERFACE, bus=bus)
        service = FirewallD(name, DBUS_PATH)

        mainloop = GObject.MainLoop()
        slip.dbus.service.set_mainloop(mainloop)
        mainloop.run()

    except KeyboardInterrupt, e:
        log.warning("KeyboardInterrupt in run_server")

    except SystemExit, e:
        log.error("Raising SystemExit in run_server")

    except Exception, e:
        log.error("Exception %s: %s", e.__class__.__name__, str(e))

    if service:
       service.stop()
