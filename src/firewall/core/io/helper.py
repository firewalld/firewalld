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

__all__ = [ "Helper", "helper_reader", "helper_writer" ]

import xml.sax as sax
import os
import io
import shutil

from firewall import config
from firewall.core.io.io_object import IO_Object, \
    IO_Object_ContentHandler, IO_Object_XMLGenerator, check_port, \
    check_tcpudp
from firewall.core.logger import log
from firewall import errors
from firewall.errors import FirewallError

class Helper(IO_Object):
    IMPORT_EXPORT_STRUCTURE = (
        ( "version",  "" ),                   # s
        ( "short", "" ),                      # s
        ( "description", "" ),                # s
        ( "family", "", ),                    # s
        ( "module", "", ),                    # s
        ( "ports", [ ( "", "" ), ], ),        # a(ss)
        )
    DBUS_SIGNATURE = '(sssssa(ss))'
    ADDITIONAL_ALNUM_CHARS = [ "-", "." ]
    PARSER_REQUIRED_ELEMENT_ATTRS = {
        "short": None,
        "description": None,
        "helper": [ "module" ],
        }
    PARSER_OPTIONAL_ELEMENT_ATTRS = {
        "helper": [ "name", "version", "family" ],
        "port": [ "port", "protocol" ],
        }

    def __init__(self):
        super(Helper, self).__init__()
        self.version = ""
        self.short = ""
        self.description = ""
        self.module = ""
        self.family = ""
        self.ports = [ ]

    def cleanup(self):
        self.version = ""
        self.short = ""
        self.description = ""
        self.module = ""
        self.family = ""
        del self.ports[:]

    def check_ipv(self, ipv):
        ipvs = [ 'ipv4', 'ipv6' ]
        if ipv not in ipvs:
            raise FirewallError(errors.INVALID_IPV,
                                "'%s' not in '%s'" % (ipv, ipvs))

    def _check_config(self, config, item, all_config):
        if item == "ports":
            for port in config:
                check_port(port[0])
                check_tcpudp(port[1])
        elif item == "module":
            if not config.startswith("nf_conntrack_"):
                raise FirewallError(
                    errors.INVALID_MODULE,
                    "'%s' does not start with 'nf_conntrack_'" % config)
            if len(config.replace("nf_conntrack_", "")) < 1:
                raise FirewallError(errors.INVALID_MODULE,
                                    "Module name '%s' too short" % config)

# PARSER

class helper_ContentHandler(IO_Object_ContentHandler):
    def startElement(self, name, attrs):
        IO_Object_ContentHandler.startElement(self, name, attrs)
        self.item.parser_check_element_attrs(name, attrs)
        if name == "helper":
            if "version" in attrs:
                self.item.version = attrs["version"]
            if "family" in attrs:
                self.item.check_ipv(attrs["family"])
                self.item.family = attrs["family"]
            if "module" in attrs:
                if not attrs["module"].startswith("nf_conntrack_"):
                    raise FirewallError(
                        errors.INVALID_MODULE,
                        "'%s' does not start with 'nf_conntrack_'" % \
                        attrs["module"])
                if len(attrs["module"].replace("nf_conntrack_", "")) < 1:
                    raise FirewallError(
                        errors.INVALID_MODULE,
                        "Module name '%s' too short" % attrs["module"])
                self.item.module = attrs["module"]
        elif name == "short":
            pass
        elif name == "description":
            pass
        elif name == "port":
            check_port(attrs["port"])
            check_tcpudp(attrs["protocol"])
            entry = (attrs["port"], attrs["protocol"])
            if entry not in self.item.ports:
                self.item.ports.append(entry)
            else:
                log.warning("Port '%s/%s' already set, ignoring.",
                            attrs["port"], attrs["protocol"])

def helper_reader(filename, path):
    helper = Helper()
    if not filename.endswith(".xml"):
        raise FirewallError(errors.INVALID_NAME,
                            "'%s' is missing .xml suffix" % filename)
    helper.name = filename[:-4]
    helper.check_name(helper.name)
    helper.filename = filename
    helper.path = path
    helper.builtin = False if path.startswith(config.ETC_FIREWALLD) else True
    helper.default = helper.builtin
    handler = helper_ContentHandler(helper)
    parser = sax.make_parser()
    parser.setContentHandler(handler)
    name = "%s/%s" % (path, filename)
    with open(name, "rb") as f:
        source = sax.InputSource(None)
        source.setByteStream(f)
        try:
            parser.parse(source)
        except sax.SAXParseException as msg:
            raise FirewallError(errors.INVALID_HELPER,
                                "not a valid helper file: %s" % \
                                msg.getException())
    del handler
    del parser
    return helper

def helper_writer(helper, path=None):
    _path = path if path else helper.path

    if helper.filename:
        name = "%s/%s" % (_path, helper.filename)
    else:
        name = "%s/%s.xml" % (_path, helper.name)

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

    # start helper element
    attrs = {}
    attrs["module"] = helper.module
    if helper.version and helper.version != "":
        attrs["version"] = helper.version
    if helper.family and helper.family != "":
        attrs["family"] = helper.family
    handler.startElement("helper", attrs)
    handler.ignorableWhitespace("\n")

    # short
    if helper.short and helper.short != "":
        handler.ignorableWhitespace("  ")
        handler.startElement("short", { })
        handler.characters(helper.short)
        handler.endElement("short")
        handler.ignorableWhitespace("\n")

    # description
    if helper.description and helper.description != "":
        handler.ignorableWhitespace("  ")
        handler.startElement("description", { })
        handler.characters(helper.description)
        handler.endElement("description")
        handler.ignorableWhitespace("\n")

    # ports
    for port in helper.ports:
        handler.ignorableWhitespace("  ")
        handler.simpleElement("port", { "port": port[0], "protocol": port[1] })
        handler.ignorableWhitespace("\n")

    # end helper element
    handler.endElement('helper')
    handler.ignorableWhitespace("\n")
    handler.endDocument()
    f.close()
    del handler
