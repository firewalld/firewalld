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

class Service(object):
    def __init__(self):
        self.filename = ""
        self.path = ""
        self.name = ""
        self.version = ""
        self.short = ""
        self.description = ""
        self.ports = [ ]
        self.modules = [ ]
        self.destination = { }

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

class service_ContentHandler(sax.handler.ContentHandler):
    def __init__(self, service):
        self._element = None
        self.service = service

        # required element and attributes
        self.__required_element_attrs = {
            "short": None,
            "description": None,
            "service": [ "name" ],
        }
        # optional element attributes
        self.__optional_element_attrs = {
            "service": [ "version" ],
            "port": [ "port", "protocol" ],
            "module": [ "name" ],
            "destination": [ "ipv4", "ipv6" ],
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

        if name == "service":
            self.service.name = attrs["name"]
            if "version" in attrs:
                self.service.version = attrs["version"]
        elif name == "short":
            self._element = self.service.short
        elif name == "description":
            self._element = self.service.description
        elif name == "port":
            self.service.ports.append((attrs["port"], attrs["protocol"]))
        elif name == "destination":
            for x in [ "ipv4", "ipv6" ]:
                if x in attrs:
                    self.service.destination[x] = attrs[x]
        elif name == "module":
            self.service.modules.append(attrs["name"])

    def endElement(self, name): 
        if name == "short":
            self.service.short = self._element
            self._element = None
        elif name == "description":
            self.service.description = self._element
            self._element = None

    def characters(self, content):
        if self._element != None:
            self._element += content.replace('\n', ' ')

class service_XMLGenerator(saxutils.XMLGenerator):
    def __init__(self, out):
        saxutils.XMLGenerator.__init__(self, out, "utf-8")

    def simpleElement(self, name, attrs):
        self._write('<' + name)
        for (name, value) in attrs.items():
            self._write(' %s=%s' % (name, saxutils.quoteattr(value)))
        self._write('/>')

def service_reader(filename, path):
    name = "%s/%s" % (path, filename)
    service = Service()
    service.filename = filename
    service.path = path
    handler = service_ContentHandler(service)
    parser = sax.make_parser()
    parser.setContentHandler(handler)
    parser.parse(name)
    return service

def service_writer(service, path=""):
    if service.filename:
        name = "%s/%s" % (path, service.filename)
    else:
        name = "%s/%s.xml" % (path, service.name)
    fd = open(name, "w")
    handler = service_XMLGenerator(fd)
    handler.startDocument()

    # start service element
    attrs = { "name": service.name }
    if service.version and service.version != "":
        attrs["version"] = service.version
    handler.startElement("service", attrs)
    handler.ignorableWhitespace("\n")

    # short
    if service.short and service.short != "":
        handler.ignorableWhitespace("  ")
        handler.startElement("short", { })
        handler.characters(service.short)
        handler.endElement("short")
        handler.ignorableWhitespace("\n")

    # description
    if service.description and service.description != "":
        handler.ignorableWhitespace("  ")
        handler.startElement("description", { })
        handler.characters(service.description)
        handler.endElement("description")
        handler.ignorableWhitespace("\n")

    # ports
    for port in service.ports:
        handler.ignorableWhitespace("  ")
        handler.simpleElement("port", { "port": port[0], "protocol": port[1] })
        handler.ignorableWhitespace("\n")

    # modules
    for module in service.modules:
        handler.ignorableWhitespace("  ")
        handler.simpleElement("module", { "name": module })
        handler.ignorableWhitespace("\n")

    # destination
    if len(service.destination) > 0:
        handler.ignorableWhitespace("  ")
        handler.simpleElement("destination", service.destination)
        handler.ignorableWhitespace("\n")

    # end service element
    handler.endElement('service')
    handler.endDocument()
    fd.close()

