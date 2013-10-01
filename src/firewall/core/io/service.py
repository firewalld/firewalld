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

from firewall.config import ETC_FIREWALLD
from firewall.errors import *
from firewall import functions
from firewall.core.io.io_object import *
from firewall.core.logger import log

class Service(IO_Object):
    IMPORT_EXPORT_STRUCTURE = (
        ( "version",  "" ),              # s
        ( "short", "" ),                 # s
        ( "description", "" ),           # s
        ( "ports", [ ( "", "" ), ], ),   # a(ss)
        ( "modules", [ "", ], ),         # as
        ( "destination", { "": "", }, ), # a{ss}
        )
    DBUS_SIGNATURE = '(sssa(ss)asa{ss})'
    ADDITIONAL_ALNUM_CHARS = [ "_", "-" ]
    PARSER_REQUIRED_ELEMENT_ATTRS = {
        "short": None,
        "description": None,
        "service": None,
        }
    PARSER_OPTIONAL_ELEMENT_ATTRS = {
        "service": [ "name", "version" ],
        "port": [ "port", "protocol" ],
        "module": [ "name" ],
        "destination": [ "ipv4", "ipv6" ],
        }

    def __init__(self):
        super(Service, self).__init__()
        self.version = ""
        self.short = ""
        self.description = ""
        self.ports = [ ]
        self.modules = [ ]
        self.destination = { }

    def _check_config(self, config, item):
        if item == "ports":
            for port in config:
                if port[0] != "":
                    check_port(port[0])
                    check_protocol(port[1])
                else:
                    # only protocol
                    if not functions.checkProtocol(port[1]):
                        raise FirewallError(INVALID_PROTOCOL, port[1])

        elif item == "destination":
            for destination in config:
                if destination not in [ "ipv4", "ipv6" ]:
                    raise FirewallError(INVALID_DESTINATION, destination)
                if not functions.check_address(destination, config[destination]):
                    raise FirewallError(INVALID_ADDRESS, config[destination])
                    

# PARSER

class service_ContentHandler(IO_Object_ContentHandler):
    def startElement(self, name, attrs):
        self.item.parser_check_element_attrs(name, attrs)

        if name == "service":
            if "name" in attrs:
                log.warning("Ignoring deprecated attribute name='%s'" % 
                            attrs["name"])
            if "version" in attrs:
                self.item.version = str(attrs["version"])
        elif name == "short":
            pass
        elif name == "description":
            pass
        elif name == "port":
            self.item.ports.append((str(attrs["port"]),
                                       str(attrs["protocol"])))
        elif name == "destination":
            for x in [ "ipv4", "ipv6" ]:
                if x in attrs:
                    s = str(attrs[x])
                    if x == "ipv4" and not functions.checkIPnMask(s):
                        raise FirewallError(INVALID_DESTINATION, s)
                    if x == "ipv6" and not functions.checkIP6nMask(s):
                        raise FirewallError(INVALID_DESTINATION, s)
                    self.item.destination[x] = str(attrs[x])
        elif name == "module":
            self.item.modules.append(str(attrs["name"]))

def service_reader(filename, path):
    service = Service()
    if not filename.endswith(".xml"):
        raise FirewallError(INVALID_NAME, filename)
    service.name = filename[:-4]
    service.check_name(service.name)
    service.filename = filename
    service.path = path
    service.default = False if path.startswith(ETC_FIREWALLD) else True
    handler = service_ContentHandler(service)
    parser = sax.make_parser()
    parser.setContentHandler(handler)
    name = "%s/%s" % (path, filename)
    with open(name, "r") as f:
        parser.parse(f)
    return service

def service_writer(service, path=None):
    _path = path if path else service.path

    if service.filename:
        name = "%s/%s" % (_path, service.filename)
    else:
        name = "%s/%s.xml" % (_path, service.name)

    if os.path.exists(name):
        try:
            shutil.copy2(name, "%s.old" % name)
        except Exception, msg:
            raise IOError("Backup of '%s' failed: %s" % (name, msg))

    fd = open(name, "w")
    handler = IO_Object_XMLGenerator(fd)
    handler.startDocument()

    # start service element
    attrs = {}
    if service.version and service.version != "":
        attrs["version"] = service.version
    handler.startElement("service", attrs)
    handler.ignorableWhitespace("\n")

    # short
    if service.short and service.short != "":
        handler.ignorableWhitespace("  ")
        handler.startElement("short", { })
        handler.characters(service.short.decode('utf-8')
                           if isinstance(service.short, bytes)
                           else service.short)
        handler.endElement("short")
        handler.ignorableWhitespace("\n")

    # description
    if service.description and service.description != "":
        handler.ignorableWhitespace("  ")
        handler.startElement("description", { })
        handler.characters(service.description.decode('utf-8')
                           if isinstance(service.description, bytes)
                           else service.description)
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
    handler.ignorableWhitespace("\n")
    handler.endDocument()
    fd.close()
