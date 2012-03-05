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

class ICMPType(object):
    def __init__(self):
        self.filename = ""
        self.path = ""
        self.name = ""
        self.version = ""
        self.short = ""
        self.description = ""
        self.destination = [ ]

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

class icmptype_ContentHandler(sax.handler.ContentHandler):
    def __init__(self, icmptype):
        self._element = None
        self.icmptype = icmptype

        # required element and attributes
        self.__required_element_attrs = {
            "icmptype": [ "name" ],
            "short": None,
            "description": None,
        }
        # optional element attributes
        self.__optional_element_attrs = {
            "icmptype": [ "version" ],
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

        if name == "icmptype":
            self.icmptype.name = attrs["name"]
            if "version" in attrs:
                self.icmptype.version = attrs["version"]
        elif name == "short":
            self._element = self.icmptype.short
        elif name == "description":
            self._element = self.icmptype.description
        elif name == "destination":
            for x in [ "ipv4", "ipv6" ]:
                if x in attrs and \
                        attrs[x].lower() in [ "yes", "true" ]:
                    self.icmptype.destination.append(x)

    def endElement(self, name): 
        if name == "short":
            self.icmptype.short = self._element
            self._element = None
        elif name == "description":
            self.icmptype.description = self._element
            self._element = None

    def characters(self, content):
        if self._element != None:
            self._element += content.replace('\n', ' ')

class icmptype_XMLGenerator(saxutils.XMLGenerator):
    def __init__(self, out):
        saxutils.XMLGenerator.__init__(self, out, "utf-8")

    def simpleElement(self, name, attrs):
        self._write('<' + name)
        for (name, value) in attrs.items():
            self._write(' %s=%s' % (name, saxutils.quoteattr(value)))
        self._write('/>')

def icmptype_reader(filename, path):
    name = "%s/%s" % (path, filename)
    icmptype = ICMPType()
    icmptype.filename = filename
    icmptype.path = path
    handler = icmptype_ContentHandler(icmptype)
    parser = sax.make_parser()
    parser.setContentHandler(handler)
    parser.parse(name)
    return icmptype

def icmptype_writer(icmptype, path=""):
    if icmptype.filename:
        name = "%s/%s" % (path, icmptype.filename)
    else:
        name = "%s/%s.xml" % (path, icmptype.name)
    fd = open(name, "w")
    handler = icmptype_XMLGenerator(fd)
    handler.startDocument()

    # start icmptype element
    attrs = { "name": icmptype.name }
    if icmptype.version and icmptype.version != "":
        attrs["version"] = icmptype.version
    handler.startElement("icmptype", attrs)
    handler.ignorableWhitespace("\n")

    # short
    if icmptype.short and icmptype.short != "":
        handler.ignorableWhitespace("  ")
        handler.startElement("short", { })
        handler.characters(icmptype.short)
        handler.endElement("short")
        handler.ignorableWhitespace("\n")

    # description
    if icmptype.description and icmptype.description != "":
        handler.ignorableWhitespace("  ")
        handler.startElement("description", { })
        handler.characters(icmptype.description)
        handler.endElement("description")
        handler.ignorableWhitespace("\n")

    # destination
    if icmptype.destination:
        handler.ignorableWhitespace("  ")
        attrs = { }
        for x in icmptype.destination:
            attrs[x] = "yes"
        handler.simpleElement("destination", attrs)
        handler.ignorableWhitespace("\n")

    # end icmptype element
    handler.endElement('icmptype')
    handler.endDocument()
    fd.close()
