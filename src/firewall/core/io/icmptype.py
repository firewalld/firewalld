# -*- coding: utf-8 -*-
#
# Copyright (C) 2011-2016 Red Hat, Inc.
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

__all__ = [ "IcmpType", "icmptype_reader", "icmptype_writer" ]

import xml.sax as sax
import os
import io
import shutil

from firewall import config
from firewall.core.io.io_object import IO_Object, \
    IO_Object_ContentHandler, IO_Object_XMLGenerator
from firewall.core.logger import log
from firewall import errors
from firewall.errors import FirewallError

class IcmpType(IO_Object):
    IMPORT_EXPORT_STRUCTURE = (
        ( "version",  "" ),          # s
        ( "short", "" ),             # s
        ( "description", "" ),       # s
        ( "destination", [ "", ], ), # as
        )
    DBUS_SIGNATURE = '(sssas)'
    ADDITIONAL_ALNUM_CHARS = [ "_", "-" ]
    PARSER_REQUIRED_ELEMENT_ATTRS = {
        "short": None,
        "description": None,
        "icmptype": None,
        }
    PARSER_OPTIONAL_ELEMENT_ATTRS = {
        "icmptype": [ "name", "version" ],
        "destination": [ "ipv4", "ipv6" ],
        }

    def __init__(self):
        super(IcmpType, self).__init__()
        self.version = ""
        self.short = ""
        self.description = ""
        self.destination = [ ]

    def cleanup(self):
        self.version = ""
        self.short = ""
        self.description = ""
        del self.destination[:]

    def _check_config(self, config, item, all_config):
        if item == "destination":
            for destination in config:
                if destination not in [ "ipv4", "ipv6" ]:
                    raise FirewallError(errors.INVALID_DESTINATION,
                                        "'%s' not from {'ipv4'|'ipv6'}" % \
                                        destination)

# PARSER

class icmptype_ContentHandler(IO_Object_ContentHandler):
    def startElement(self, name, attrs):
        IO_Object_ContentHandler.startElement(self, name, attrs)
        self.item.parser_check_element_attrs(name, attrs)

        if name == "icmptype":
            if "name" in attrs:
                log.warning("Ignoring deprecated attribute name='%s'" %
                            attrs["name"])
            if "version" in attrs:
                self.item.version = attrs["version"]
        elif name == "short":
            pass
        elif name == "description":
            pass
        elif name == "destination":
            for x in [ "ipv4", "ipv6" ]:
                if x in attrs and \
                        attrs[x].lower() in [ "yes", "true" ]:
                    self.item.destination.append(str(x))

def icmptype_reader(filename, path):
    icmptype = IcmpType()
    if not filename.endswith(".xml"):
        raise FirewallError(errors.INVALID_NAME,
                            "%s is missing .xml suffix" % filename)
    icmptype.name = filename[:-4]
    icmptype.check_name(icmptype.name)
    icmptype.filename = filename
    icmptype.path = path
    icmptype.builtin = False if path.startswith(config.ETC_FIREWALLD) else True
    icmptype.default = icmptype.builtin
    handler = icmptype_ContentHandler(icmptype)
    parser = sax.make_parser()
    parser.setContentHandler(handler)
    name = "%s/%s" % (path, filename)
    with open(name, "rb") as f:
        source = sax.InputSource(None)
        source.setByteStream(f)
        try:
            parser.parse(source)
        except sax.SAXParseException as msg:
            raise FirewallError(errors.INVALID_ICMPTYPE,
                                "not a valid icmptype file: %s" % \
                                msg.getException())
    del handler
    del parser
    return icmptype

def icmptype_writer(icmptype, path=None):
    _path = path if path else icmptype.path

    if icmptype.filename:
        name = "%s/%s" % (_path, icmptype.filename)
    else:
        name = "%s/%s.xml" % (_path, icmptype.name)

    if os.path.exists(name):
        try:
            shutil.copy2(name, "%s.old" % name)
        except Exception as msg:
            log.error("Backup of file '%s' failed: %s", name, msg)

    dirpath = os.path.dirname(name)
    if dirpath.startswith(config.ETC_FIREWALLD) and not os.path.exists(dirpath):
        if not os.path.exists(config.ETC_FIREWALLD):
            os.mkdir(config.ETC_FIREWALLD, 0o750)
        os.mkdir(dirpath, 0o750)

    f = io.open(name, mode='wt', encoding='UTF-8')
    handler = IO_Object_XMLGenerator(f)
    handler.startDocument()

    # start icmptype element
    attrs = {}
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
    handler.ignorableWhitespace("\n")
    handler.endDocument()
    f.close()
    del handler
