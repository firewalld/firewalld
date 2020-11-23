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

__all__ = [ "Service", "service_reader", "service_writer" ]

import xml.sax as sax
import os
import io
import shutil

from firewall import config
from firewall.core.io.io_object import IO_Object, \
    IO_Object_ContentHandler, IO_Object_XMLGenerator, check_port, \
    check_tcpudp, check_protocol, check_address
from firewall.core.logger import log
from firewall import errors
from firewall.errors import FirewallError

class Service(IO_Object):
    IMPORT_EXPORT_STRUCTURE = (
        ( "version",  "" ),
        ( "short", "" ),
        ( "description", "" ),
        ( "ports", [ ( "", "" ), ], ),
        ( "modules", [ "", ], ),
        ( "destination", { "": "", }, ),
        ( "protocols", [ "", ], ),
        ( "source_ports", [ ( "", "" ), ], ),
        ( "includes", [ "" ], ),
        ( "helpers", [ "", ], ),
        )
    ADDITIONAL_ALNUM_CHARS = [ "_", "-" ]
    PARSER_REQUIRED_ELEMENT_ATTRS = {
        "short": None,
        "description": None,
        "service": None,
        }
    PARSER_OPTIONAL_ELEMENT_ATTRS = {
        "service": [ "name", "version" ],
        "port": [ "port", "protocol" ],
        "protocol": [ "value" ],
        "module": [ "name" ],
        "destination": [ "ipv4", "ipv6" ],
        "source-port": [ "port", "protocol" ],
        "include": [ "service" ],
        "helper": [ "name" ],
        }

    def __init__(self):
        super(Service, self).__init__()
        self.version = ""
        self.short = ""
        self.description = ""
        self.ports = [ ]
        self.protocols = [ ]
        self.modules = [ ]
        self.destination = { }
        self.source_ports = [ ]
        self.includes = [ ]
        self.helpers = [ ]

    def cleanup(self):
        self.version = ""
        self.short = ""
        self.description = ""
        del self.ports[:]
        del self.protocols[:]
        del self.modules[:]
        self.destination.clear()
        del self.source_ports[:]
        del self.includes[:]
        del self.helpers[:]

    def _check_config(self, config, item, all_config):
        if item == "ports":
            for port in config:
                if port[0] != "":
                    check_port(port[0])
                    check_tcpudp(port[1])
                else:
                    # only protocol
                    check_protocol(port[1])

        elif item == "protocols":
            for proto in config:
                check_protocol(proto)

        elif item == "source_ports":
            for port in config:
                check_port(port[0])
                check_tcpudp(port[1])

        elif item == "destination":
            for destination in config:
                if destination not in [ "ipv4", "ipv6" ]:
                    raise FirewallError(errors.INVALID_DESTINATION,
                                        "'%s' not in {'ipv4'|'ipv6'}" % \
                                        destination)
                check_address(destination, config[destination])

        elif item == "modules":
            for module in config:
                if module.startswith("nf_conntrack_"):
                    module = module.replace("nf_conntrack_", "")
                    if "_" in module:
                        module = module.replace("_", "-")
                if len(module) < 2:
                    raise FirewallError(errors.INVALID_MODULE, module)

# PARSER

class service_ContentHandler(IO_Object_ContentHandler):
    def startElement(self, name, attrs):
        IO_Object_ContentHandler.startElement(self, name, attrs)
        self.item.parser_check_element_attrs(name, attrs)
        if name == "service":
            if "name" in attrs:
                log.warning("Ignoring deprecated attribute name='%s'",
                            attrs["name"])
            if "version" in attrs:
                self.item.version = attrs["version"]
        elif name == "short":
            pass
        elif name == "description":
            pass
        elif name == "port":
            if attrs["port"] != "":
                check_port(attrs["port"])
                check_tcpudp(attrs["protocol"])
                entry = (attrs["port"], attrs["protocol"])
                if entry not in self.item.ports:
                    self.item.ports.append(entry)
                else:
                    log.warning("Port '%s/%s' already set, ignoring.",
                                attrs["port"], attrs["protocol"])
            else:
                check_protocol(attrs["protocol"])
                if attrs["protocol"] not in self.item.protocols:
                    self.item.protocols.append(attrs["protocol"])
                else:
                    log.warning("Protocol '%s' already set, ignoring.",
                                attrs["protocol"])
        elif name == "protocol":
            check_protocol(attrs["value"])
            if attrs["value"] not in self.item.protocols:
                self.item.protocols.append(attrs["value"])
            else:
                log.warning("Protocol '%s' already set, ignoring.",
                            attrs["value"])
        elif name == "source-port":
            check_port(attrs["port"])
            check_tcpudp(attrs["protocol"])
            entry = (attrs["port"], attrs["protocol"])
            if entry not in self.item.source_ports:
                self.item.source_ports.append(entry)
            else:
                log.warning("SourcePort '%s/%s' already set, ignoring.",
                            attrs["port"], attrs["protocol"])
        elif name == "destination":
            for x in [ "ipv4", "ipv6" ]:
                if x in attrs:
                    check_address(x, attrs[x])
                    if x in self.item.destination:
                        log.warning("Destination address for '%s' already set, ignoring",
                                    x)
                    else:
                        self.item.destination[x] = attrs[x]
        elif name == "module":
            module = attrs["name"]
            if module.startswith("nf_conntrack_"):
                module = module.replace("nf_conntrack_", "")
                if "_" in module:
                    module = module.replace("_", "-")
            if module not in self.item.modules:
                self.item.modules.append(module)
            else:
                log.warning("Module '%s' already set, ignoring.",
                            module)
        elif name == "include":
            if attrs["service"] not in self.item.includes:
                self.item.includes.append(attrs["service"])
            else:
                log.warning("Include '%s' already set, ignoring.",
                            attrs["service"])
        elif name == "helper":
            if attrs["name"] not in self.item.helpers:
                self.item.helpers.append(attrs["name"])
            else:
                log.warning("Helper '%s' already set, ignoring.",
                            attrs["name"])


def service_reader(filename, path):
    service = Service()
    if not filename.endswith(".xml"):
        raise FirewallError(errors.INVALID_NAME,
                            "'%s' is missing .xml suffix" % filename)
    service.name = filename[:-4]
    service.check_name(service.name)
    service.filename = filename
    service.path = path
    service.builtin = False if path.startswith(config.ETC_FIREWALLD) else True
    service.default = service.builtin
    handler = service_ContentHandler(service)
    parser = sax.make_parser()
    parser.setContentHandler(handler)
    name = "%s/%s" % (path, filename)
    with open(name, "rb") as f:
        source = sax.InputSource(None)
        source.setByteStream(f)
        try:
            parser.parse(source)
        except sax.SAXParseException as msg:
            raise FirewallError(errors.INVALID_SERVICE,
                                "not a valid service file: %s" % \
                                msg.getException())
    del handler
    del parser
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

    # protocols
    for protocol in service.protocols:
        handler.ignorableWhitespace("  ")
        handler.simpleElement("protocol", { "value": protocol })
        handler.ignorableWhitespace("\n")

    # source ports
    for port in service.source_ports:
        handler.ignorableWhitespace("  ")
        handler.simpleElement("source-port", { "port": port[0],
                                               "protocol": port[1] })
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

    # includes
    for include in service.includes:
        handler.ignorableWhitespace("  ")
        handler.simpleElement("include", { "service": include })
        handler.ignorableWhitespace("\n")

    # helpers
    for helper in service.helpers:
        handler.ignorableWhitespace("  ")
        handler.simpleElement("helper", { "name": helper })
        handler.ignorableWhitespace("\n")

    # end service element
    handler.endElement('service')
    handler.ignorableWhitespace("\n")
    handler.endDocument()
    f.close()
    del handler
