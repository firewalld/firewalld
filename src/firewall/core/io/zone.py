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
import xml.sax.saxutils as saxutils

from firewall.config import _
from firewall.core.base import DEFAULT_ZONE_TARGET

class Zone(object):
    def __init__(self):
        self.filename = ""
        self.path = ""
        self.name = ""
        self.short = ""
        self.version = ""
        self.immutable = False
        self.target = DEFAULT_ZONE_TARGET
        self.description = ""
        self.services = [ ]
        self.ports = [ ]
        self.icmp_blocks = [ ]
        self.masquerade = False
        self.forward_ports = [ ]
        self.custom_rules = [ ]

# PARSER

class UnexpectedElementError(Exception):
    def __init__(self, name):
        self.name = name
    def __str__(self):
        return _("Unexpected element '%s'") % (self.name)

class MissingAttributeError(Exception):
    def __init__(self, name, attribute):
        self.name = name
        self.attribute = attribute
    def __str__(self):
        return _("Element '%s': missing '%s' attribute") % \
            (self.name, self.attribute)

class UnexpectedAttributeError(Exception):
    def __init__(self, name, attribute):
        self.name = name
        self.attribute = attribute
    def __str__(self):
        return _("Element '%s': unexpected attribute '%s'") % \
            (self.name, self.attribute)

class zone_ContentHandler(sax.handler.ContentHandler):
    def __init__(self, zone):
        self._element = None
        self.zone = zone

        # required element and attributes
        self.__required_element_attrs = {
            "short": None,
            "description": None,
            "zone": [ "name" ],
            "service": [ "name" ],
            "port": [ "port", "protocol" ],
            "icmp-block": [ "name" ],
            "masquerade": [ "enabled" ],
            "forward-port": [ "port", "protocol" ],
        }
        # optional element attributes
        self.__optional_element_attrs = {
            "zone": [ "immutable", "target", "version" ],
            "forward-port": [ "to-port", "to-addr" ],
        }

    # check required elements and attributes and also optional attributes
    def __check_element_attrs(self, name, attrs):
        _attrs = attrs.getNames()

        found = False
        if name in self.__required_element_attrs:
            found = True
            if self.__required_element_attrs[name] == None:
                if len(_attrs) > 0:
                    raise UnexpectedAttributeError(name, _attrs)
            else:
                for x in self.__required_element_attrs[name]:
                    if x in _attrs:
                        _attrs.remove(x)
                    else:
                        raise MissingAttributeError(name, x)                    
        if name in self.__optional_element_attrs:
            found = True
            for x in self.__optional_element_attrs[name]:
                if x in _attrs:
                    _attrs.remove(x)
        if not found:
            raise UnexpectedElementError(name)
        # raise attributes[0]
        for x in _attrs:
            raise UnexpectedAttributeError(name, x)

    def startElement(self, name, attrs):
        self.__check_element_attrs(name, attrs)

        if name == "zone":
            self.zone.name = attrs["name"]
            if "version" in attrs:
                self.zone.version = attrs["version"]
            if "immutable" in attrs and \
                    attrs["immutable"].lower() in [ "yes", "true" ]:
                self.zone.immutable = True
            if "target" in attrs:
                self.zone.target = attrs["target"]
        elif name == "short":
            self._element = self.zone.short
        elif name == "description":
            self._element = self.zone.description
        elif name == "service":
            self.zone.services.append(attrs["name"])
        elif name == "port":
            # TODO: fix port string according to fw_zone.__port_id()
            self.zone.ports.append((attrs["port"], attrs["protocol"]))
        elif name == "icmp-block":
            self.zone.icmp_blocks.append(attrs["name"])
        elif name == "masquerade" and \
                attrs["enabled"].lower() in [ "yes", "true" ]:
            self.zone.masquerade = True
        elif name == "forward-port":
            to_port = None
            if "to-port" in attrs:
                to_port = attrs["to-port"]
            to_addr = None
            if "to-addr" in attrs:
                to_addr = attrs["to-addr"]
            # TODO: fix port string according to fw_zone.__forward_port_id()
            self.zone.forward_ports.append((attrs["port"], attrs["protocol"],
                                            to_port, to_addr))

    def endElement(self, name): 
        if name == "short":
            self.zone.short = self._element
            self._element = None
        elif name == "description":
            self.zone.description = self._element
            self._element = None

    def characters(self, content):
        if self._element != None:
            self._element += content.replace('\n', ' ')

class zone_XMLGenerator(saxutils.XMLGenerator):
    def __init__(self, out):
        saxutils.XMLGenerator.__init__(self, out, "utf-8")

    def simpleElement(self, name, attrs):
        self._write('<' + name)
        for (name, value) in attrs.items():
            self._write(' %s=%s' % (name, saxutils.quoteattr(value)))
        self._write('/>')

def zone_reader(filename, path):
    name = "%s/%s" % (path, filename)
    zone = Zone()
    zone.filename = filename
    zone.path = path
    handler = zone_ContentHandler(zone)
    parser = sax.make_parser()
    parser.setContentHandler(handler)
    parser.parse(name)
    return zone

def zone_writer(zone, path=""):
    if zone.filename:
        name = "%s/%s" % (path, zone.filename)
    else:
        name = "%s/%s.xml" % (path, zone.name)
    fd = open(name, "w")
    handler = zone_XMLGenerator(fd)
    handler.startDocument()

    # start zone element
    attrs = { "name": zone.name }
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
    for service in zone.services:
        handler.ignorableWhitespace("  ")
        handler.simpleElement("service", { "name": service })
        handler.ignorableWhitespace("\n")

    # ports
    for port in zone.ports:
        handler.ignorableWhitespace("  ")
        handler.simpleElement("port", { "port": port[0], "protocol": port[1] })
        handler.ignorableWhitespace("\n")

    # icmp-blocks
    for icmp in zone.icmp_blocks:
        handler.ignorableWhitespace("  ")
        handler.simpleElement("icmp-block", { "name": icmp })
        handler.ignorableWhitespace("\n")

    # masquerade
    if zone.masquerade:
        handler.ignorableWhitespace("  ")
        handler.simpleElement("masquerade", { "enabled": "Yes" })
        handler.ignorableWhitespace("\n")

    # forward-ports
    for forward in zone.forward_ports:
        handler.ignorableWhitespace("  ")
        attrs = { "port": port[0], "protocol": port[1] }
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

