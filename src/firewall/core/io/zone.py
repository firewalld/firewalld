# -*- coding: utf-8 -*-
#
# Copyright (C) 2011-2012 Red Hat, Inc.
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

import xml.sax as sax
import os
import shutil

from firewall.config import _
from firewall.errors import *
from firewall import functions
from firewall.core.base import DEFAULT_ZONE_TARGET, ZONE_TARGETS
from firewall.core.io.io_object import *
from firewall.core.logger import log

class Zone(IO_Object):
    """ Zone class """

    IMPORT_EXPORT_STRUCTURE = (
        ( "version",  "" ),                            # s
        ( "short", "" ),                               # s
        ( "description", "" ),                         # s
        ( "immutable", False ),                        # b
        ( "target", "" ),                              # s
        ( "services", [ "", ], ),                      # as
        ( "ports", [ ( "", "" ), ], ),                 # a(ss)
        ( "icmp_blocks", [ "", ], ),                   # as
        ( "masquerade", False ),                       # b
        ( "forward_ports", [ ( "", "", "", "" ), ], ), # a(ssss)
        )
    DBUS_SIGNATURE = '(sssbsasa(ss)asba(ssss))'
    ADDITIONAL_ALNUM_CHARS = [ "_" ]
    PARSER_REQUIRED_ELEMENT_ATTRS = {
        "short": None,
        "description": None,
        "zone": None,
        "service": [ "name" ],
        "port": [ "port", "protocol" ],
        "icmp-block": [ "name" ],
        "masquerade": [ "enabled" ],
        "forward-port": [ "port", "protocol" ],
        }
    PARSER_OPTIONAL_ELEMENT_ATTRS = {
        "zone": [ "name", "immutable", "target", "version" ],
        "forward-port": [ "to-port", "to-addr" ],
        }

    def __init__(self):
        super(Zone, self).__init__()
        self.version = ""
        self.short = ""
        self.description = ""
        self.immutable = False
        self.target = DEFAULT_ZONE_TARGET
        self.services = [ ]
        self.ports = [ ]
        self.icmp_blocks = [ ]
        self.masquerade = False
        self.forward_ports = [ ]

    def _check_config(self, config, item):
        if item == "ports":
            for port in config:
                check_port(port[0])
                check_protocol(port[1])
        if item == "forward_ports":
            for fwd_port in config:
                check_port(fwd_port[0])
                check_protocol(fwd_port[1])
                if not fwd_port[2] and not fwd_port[3]:
                    raise FirewallError(INVALID_FORWARD, fwd_port)
                if fwd_port[2]:
                    check_port(fwd_port[2])
                if fwd_port[3]:
                    if not functions.checkIP(fwd_port[3]):
                        raise FirewallError(INVALID_ADDR, fwd_port[3])

# PARSER

class zone_ContentHandler(IO_Object_ContentHandler):
    def startElement(self, name, attrs):
        self.item.parser_check_element_attrs(name, attrs)

        if name == "zone":
            if "name" in attrs:
                log.warning("Ignoring deprecated attribute name='%s'" % 
                            attrs["name"])
            if "version" in attrs:
                self.item.version = str(attrs["version"])
            if "immutable" in attrs and \
                    attrs["immutable"].lower() in [ "yes", "true" ]:
                self.item.immutable = True
            if "target" in attrs:
                target = str(attrs["target"])
                if target not in ZONE_TARGETS:
                    raise FirewallError(INVALID_TARGET, target)
                if target != "" and target != DEFAULT_ZONE_TARGET:
                    self.item.target = target
        elif name == "short":
            self._element = self.item.short
        elif name == "description":
            self._element = self.item.description
        elif name == "service":
            if str(attrs["name"]) not in self.item.services:
                self.item.services.append(str(attrs["name"]))
        elif name == "port":
            # TODO: fix port string according to fw_zone.__port_id()
            entry = (str(attrs["port"]), str(attrs["protocol"]))
            if entry not in self.item.ports:
                self.item.ports.append(entry)
        elif name == "icmp-block":
            if str(attrs["name"]) not in self.item.icmp_blocks:
                self.item.icmp_blocks.append(str(attrs["name"]))
        elif name == "masquerade" and \
                attrs["enabled"].lower() in [ "yes", "true" ]:
            self.item.masquerade = True
        elif name == "forward-port":
            to_port = ""
            if "to-port" in attrs:
                to_port = str(attrs["to-port"])
            to_addr = ""
            if "to-addr" in attrs:
                to_addr = str(attrs["to-addr"])
            # TODO: fix port string according to fw_zone.__forward_port_id()
            entry = (str(attrs["port"]), str(attrs["protocol"]), to_port,
                     to_addr)
            if entry not in self.item.forward_ports:
                self.item.forward_ports.append(entry)

def zone_reader(filename, path):
    name = "%s/%s" % (path, filename)
    zone = Zone()
    if not filename.endswith(".xml"):
        raise FirewallError(INVALID_NAME, filename)
    zone.name = filename[:-4]
    zone.check_name(zone.name)
    zone.filename = filename
    zone.path = path
    handler = zone_ContentHandler(zone)
    parser = sax.make_parser()
    parser.setContentHandler(handler)
    parser.parse(name)
    return zone

def zone_writer(zone, path=None):
    if path:
        _path = path
    else:
        _path = zone.path

    if zone.filename:
        name = "%s/%s" % (_path, zone.filename)
    else:
        name = "%s/%s.xml" % (_path, zone.name)

    if os.path.exists(name):
        try:
            shutil.copy2(name, "%s.old" % name)
        except Exception, msg:
            raise IOError, "Backup of '%s' failed: %s" % (name, msg)

    fd = open(name, "w")
    handler = IO_Object_XMLGenerator(fd)
    handler.startDocument()

    # start zone element
    attrs = {}
    if zone.version and zone.version != "":
        attrs["version"] = zone.version
    if zone.immutable:
        attrs["immutable"] = "yes"
    if zone.target != DEFAULT_ZONE_TARGET:
        attrs["target"] = zone.target
    handler.startElement("zone", attrs)
    handler.ignorableWhitespace("\n")

    # short
    if zone.short and zone.short != "":
        handler.ignorableWhitespace("  ")
        handler.startElement("short", { })
        handler.characters(zone.short)
        handler.endElement("short")
        handler.ignorableWhitespace("\n")

    # description
    if zone.description and zone.description != "":
        handler.ignorableWhitespace("  ")
        handler.startElement("description", { })
        handler.characters(zone.description)
        handler.endElement("description")
        handler.ignorableWhitespace("\n")

    # services
    for service in set(zone.services):
        handler.ignorableWhitespace("  ")
        handler.simpleElement("service", { "name": service })
        handler.ignorableWhitespace("\n")

    # ports
    for port in set(zone.ports):
        handler.ignorableWhitespace("  ")
        handler.simpleElement("port", { "port": port[0], "protocol": port[1] })
        handler.ignorableWhitespace("\n")

    # icmp-blocks
    for icmp in set(zone.icmp_blocks):
        handler.ignorableWhitespace("  ")
        handler.simpleElement("icmp-block", { "name": icmp })
        handler.ignorableWhitespace("\n")

    # masquerade
    if zone.masquerade:
        handler.ignorableWhitespace("  ")
        handler.simpleElement("masquerade", { "enabled": "Yes" })
        handler.ignorableWhitespace("\n")

    # forward-ports
    for forward in set(zone.forward_ports):
        handler.ignorableWhitespace("  ")
        attrs = { "port": forward[0], "protocol": forward[1] }
        if forward[2] and forward[2] != "" :
            attrs["to-port"] = forward[2]
        if forward[3] and forward[3] != "" :
            attrs["to-addr"] = forward[3]
        handler.simpleElement("forward-port", attrs)
        handler.ignorableWhitespace("\n")

    # end zone element
    handler.endElement('zone')
    handler.endDocument()
    fd.close()
