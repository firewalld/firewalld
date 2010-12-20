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
import dbus
import pickle

#

#INTERFACE_VERSION = "2.0"

#

DBUS_INTERFACE = "org.fedoraproject.FirewallD"
DBUS_PATH = "/org/fedoraproject/FirewallD"
POLKIT_DOMAIN = "org.fedoraproject.FirewallD"

#

class Firewall_Client(object):
    def __init__(self, bus=None):
        if not bus:
            try:
                self.bus = slip.dbus.SystemBus()
                self.bus.default_timeout = None
            except:
                print "Not using slip"
                self.bus = dbus.SystemBus()
        else:
            self.bus = bus
        self.dbus_obj = self.bus.get_object(DBUS_INTERFACE, DBUS_PATH)
        self.fw = dbus.Interface(self.dbus_obj, dbus_interface=DBUS_INTERFACE)

    @slip.dbus.polkit.enable_proxy
    def reload(self):
        return self.fw.reload()

    @slip.dbus.polkit.enable_proxy
    def restart(self):
        return self.fw.restart()

    @slip.dbus.polkit.enable_proxy
    def status(self):
        return self.fw.status()

    # panic mode

    @slip.dbus.polkit.enable_proxy
    def enablePanicMode(self):
        return self.fw.enablePanicMode()
    
    @slip.dbus.polkit.enable_proxy
    def disablePanicMode(self):
        return self.fw.disablePanicMode()

    @slip.dbus.polkit.enable_proxy
    def queryPanicMode(self):
        return self.fw.queryPanicMode()

    # services

    @slip.dbus.polkit.enable_proxy
    def enableService(self, service, timeout=0):
        return self.fw.enableService(service, timeout)

    @slip.dbus.polkit.enable_proxy
    def getServices(self):
        (status, services) = self.fw.getServices()
        if status < 0:
            return None
        return [ str(item) for item in services ]

    @slip.dbus.polkit.enable_proxy
    def queryService(self, service):
        return self.fw.queryService(service)

    @slip.dbus.polkit.enable_proxy
    def disableService(self, service):
        return self.fw.disableService(service)

    # ports

    @slip.dbus.polkit.enable_proxy
    def enablePort(self, port, protocol, timeout=0):
        return self.fw.enablePort(port, protocol, timeout)

    @slip.dbus.polkit.enable_proxy
    def getPorts(self):
        (status, ports) = self.fw.getPorts()
        if status < 0:
            return None
        return [ (str(port), str(proto)) for (port, proto) in ports ]

    @slip.dbus.polkit.enable_proxy
    def queryPort(self, port, protocol):
        return self.fw.queryPort(port, protocol)

    @slip.dbus.polkit.enable_proxy
    def disablePort(self, port, protocol):
        return self.fw.disablePort(port, protocol)

    # trusted

    @slip.dbus.polkit.enable_proxy
    def enableTrusted(self, trusted, timeout=0):
        return self.fw.enableTrusted(trusted, timeout)

    @slip.dbus.polkit.enable_proxy
    def getTrusted(self):
        (status, trusted) =  self.fw.getTrusted()
        if status < 0:
            return None
        return [ str(item) for item in trusted ]

    @slip.dbus.polkit.enable_proxy
    def queryTrusted(self, trusted):
        return self.fw.queryTrusted(trusted)

    @slip.dbus.polkit.enable_proxy
    def disableTrusted(self, trusted):
        return self.fw.disableTrusted(trusted)

    # masquerade

    @slip.dbus.polkit.enable_proxy
    def enableMasquerade(self, masquerade, timeout=0):
        return self.fw.enableMasquerade(masquerade, timeout)

    @slip.dbus.polkit.enable_proxy
    def getMasquerades(self):
        (status, masqueraded) = self.fw.getMasquerades()
        if status < 0:
            return None
        return [ str(item) for item in masqueraded ]

    @slip.dbus.polkit.enable_proxy
    def queryMasquerade(self, masquerade):
        return self.fw.queryMasquerade(masquerade)

    @slip.dbus.polkit.enable_proxy
    def disableMasquerade(self, masquerade):
        return self.fw.disableMasquerade(masquerade)

    # forward ports

    @slip.dbus.polkit.enable_proxy
    def enableForwardPort(self, interface, port, protocol, toport, toaddr,
                          timeout=0):
        return self.fw.enableForwardPort(interface, port, protocol, toport,
                                         toaddr, timeout)

    @slip.dbus.polkit.enable_proxy
    def getForwardPorts(self):
        (status, ports) = self.fw.getForwardPorts()
        if status < 0:
            return None
        return [ (str(interface), str(port), str(protocol), str(toport),
                  str(toaddr)) 
                 for (interface, port, protocol, toport, toaddr) in ports ]

    @slip.dbus.polkit.enable_proxy
    def queryForwardPort(self, interface, port, protocol, toport, toaddr):
        return self.fw.queryForwardPort(interface, port, protocol, toport,
                                        toaddr)

    @slip.dbus.polkit.enable_proxy
    def disableForwardPort(self, interface, port, protocol, toport, toaddr):
        return self.fw.disableForwardPort(interface, port, protocol, toport,
                                          toaddr)

    # icmpblock

    @slip.dbus.polkit.enable_proxy
    def enableIcmpBlock(self, icmp, timeout=0):
        return self.fw.enableIcmpBlock(icmp, timeout)

    @slip.dbus.polkit.enable_proxy
    def getIcmpBlocks(self):
        (status, icmp_blocks) = self.fw.getIcmpBlocks()
        if status < 0:
            return None
        return icmp_blocks

    @slip.dbus.polkit.enable_proxy
    def queryIcmpBlock(self, icmp):
        return self.fw.queryIcmpBlock(icmp)

    @slip.dbus.polkit.enable_proxy
    def disableIcmpBlock(self, icmp):
        return self.fw.disableIcmpBlock(icmp)

    ##############################
    # custom

    @slip.dbus.polkit.enable_proxy
    def enableCustom(self, table="filter", chain="INPUT", src=None,
                     src_port=None, dst=None, dst_port=None,
                     protocol=None, iface_in=None, out_if=None,
                     physdev_in=None, physdev_out=None, target="ACCEPT",
                     timeout=0):
        return self.fw.enableCustom(
            table, chain, src, src_port, dst, dst_port, protocol,
            iface_in, out_if, physdev_in, physdev_out, target, timeout)

    @slip.dbus.polkit.enable_proxy
    def getCustoms(self):
        (status, customs) = self.fw.getCustoms()
        if status < 0:
            return None
        return [ (str(table), str(chain), str(src), str(src_port), str(dst),
                  str(dst_port), str(protocol), str(iface_in), str(out_if),
                  str(physdev_in), str(physdev_out), str(target)) 
                 for (table, chain, src, src_port, dst, dst_port, protocol,
                      iface_in, out_if, physdev_in, physdev_out, target)
                 in customs ]

    @slip.dbus.polkit.enable_proxy
    def queryCustom(self,  table="filter", chain="INPUT", src=None,
                    src_port=None, dst=None, dst_port=None,
                    protocol=None, iface_in=None, out_if=None,
                    physdev_in=None, physdev_out=None, target="ACCEPT",
                    timeout=0):
        return self.fw.queryCustom(table, chain, src, src_port,
                                   dst, dst_port, protocol, iface_in, out_if,
                                   physdev_in, physdev_out, target)

    @slip.dbus.polkit.enable_proxy
    def disableCustom(self, table="filter", chain="INPUT", src=None,
                      src_port=None, dst=None, dst_port=None,
                      protocol=None, iface_in=None, out_if=None,
                      physdev_in=None, physdev_out=None, target="ACCEPT",
                      timeout=0):
        return self.fw.disableCustom(table, chain, src, src_port,
                                     dst, dst_port, protocol,
                                     iface_in, out_if,
                                     physdev_in, physdev_out, target)
