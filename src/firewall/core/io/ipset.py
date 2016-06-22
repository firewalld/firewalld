# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2016 Red Hat, Inc.
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

"""ipset io XML handler, reader, writer"""

__all__ = [ "IPSet", "ipset_reader", "ipset_writer" ]

import xml.sax as sax
import os
import io
import shutil

from firewall.config import ETC_FIREWALLD
from firewall.functions import checkIP, checkIP6, checkIPnMask, checkIP6nMask, \
    u2b_if_py2, check_mac
from firewall.core.io.io_object import PY2, IO_Object, \
    IO_Object_ContentHandler, IO_Object_XMLGenerator
from firewall.core.ipset import IPSET_TYPES
from firewall.core.logger import log
from firewall import errors
from firewall.errors import FirewallError

class IPSet(IO_Object):
    IMPORT_EXPORT_STRUCTURE = (
        ( "version",  "" ),              # s
        ( "short", "" ),                 # s
        ( "description", "" ),           # s
        ( "type", "" ),                  # s
        ( "options", { "": "", }, ),     # a{ss}
        ( "entries", [ "" ], ),          # as
    )
    DBUS_SIGNATURE = '(ssssa{ss}as)'
    ADDITIONAL_ALNUM_CHARS = [ "_", "-", ":", "." ]
    PARSER_REQUIRED_ELEMENT_ATTRS = {
        "short": None,
        "description": None,
        "ipset": [ "type" ],
        "option": [ "name" ],
        "entry": None,
    }
    PARSER_OPTIONAL_ELEMENT_ATTRS = {
        "ipset": [ "version" ],
        "option": [ "value" ],
    }

    def __init__(self):
        super(IPSet, self).__init__()
        self.version = ""
        self.short = ""
        self.description = ""
        self.type = ""
        self.entries = [ ]
        self.options = { }
        self.applied = False

    def cleanup(self):
        self.version = ""
        self.short = ""
        self.description = ""
        self.type = ""
        del self.entries[:]
        self.options.clear()
        self.applied = False

    def encode_strings(self):
        """ HACK. I haven't been able to make sax parser return
            strings encoded (because of python 2) instead of in unicode.
            Get rid of it once we throw out python 2 support."""
        self.version = u2b_if_py2(self.version)
        self.short = u2b_if_py2(self.short)
        self.description = u2b_if_py2(self.description)
        self.type = u2b_if_py2(self.type)
        self.options = { u2b_if_py2(k):u2b_if_py2(v)
                         for k, v in self.options.items() }
        self.entries = [ u2b_if_py2(e) for e in self.entries ]

    @staticmethod
    def check_entry(entry, options, ipset_type):
        family = "ipv4"
        if "family" in options:
            if options["family"] == "inet6":
                family = "ipv6"

        if ipset_type == "hash:ip":
            if "-" in entry:
                splits = entry.split("-")
                if len(splits) != 2:
                    raise FirewallError(
                        errors.INVALID_ENTRY,
                        "entry '%s' does not match ipset type '%s'" % \
                        (entry, ipset_type))
                for split in splits:
                    if (family == "ipv4" and not checkIP(split)) or \
                       (family == "ipv6" and not checkIP6(split)):
                        raise FirewallError(
                            errors.INVALID_ENTRY,
                            "entry '%s' does not match ipset type '%s'" % \
                            (entry, ipset_type))
            else:
                if (family == "ipv4" and not checkIPnMask(entry)) or \
                   (family == "ipv6" and not checkIP6nMask(entry)):
                    raise FirewallError(
                        errors.INVALID_ENTRY,
                        "entry '%s' does not match ipset type '%s'" % \
                        (entry, ipset_type))
        elif ipset_type == "hash:net":
            if (family == "ipv4" and not checkIPnMask(entry)) or \
               (family == "ipv6" and not checkIP6nMask(entry)):
                raise FirewallError(
                    errors.INVALID_ENTRY,
                    "entry '%s' does not match ipset type '%s'" % \
                    (entry, ipset_type))
        elif ipset_type == "hash:mac":
            # ipset does not allow to add 00:00:00:00:00:00
            if not check_mac(entry) or entry == "00:00:00:00:00:00":
                raise FirewallError(
                    errors.INVALID_ENTRY,
                    "entry '%s' does not match ipset type '%s'" % \
                    (entry, ipset_type))
        else:
            raise FirewallError(errors.INVALID_IPSET,
                                "ipset type '%s' not usable" % ipset_type)

    def _check_config(self, config, item):
        if item == "type":
            if config not in IPSET_TYPES:
                raise FirewallError(errors.INVALID_TYPE,
                                    "'%s' is not valid ipset type" % config)

    def import_config(self, config):
        for entry in config[5]:
            IPSet.check_entry(entry, config[4], config[3])
        super(IPSet, self).import_config(config)

# PARSER

class ipset_ContentHandler(IO_Object_ContentHandler):
    def startElement(self, name, attrs):
        IO_Object_ContentHandler.startElement(self, name, attrs)
        self.item.parser_check_element_attrs(name, attrs)
        if name == "ipset":
            if "type" in attrs:
                self.item.type = attrs["type"]
            if "version" in attrs:
                self.item.version = attrs["version"]
        elif name == "short":
            pass
        elif name == "description":
            pass
        elif name == "option":
            value = ""
            if "value" in attrs:
                value = attrs["value"]

            if attrs["name"] not in \
               [ "family", "timeout", "hashsize", "maxelem" ]:
                raise FirewallError(
                    errors.INVALID_OPTION,
                    "Unknown option '%s'" % attrs["name"])
            if self.item.type == "hash:mac" and attrs["name"] in [ "family" ]:
                raise FirewallError(
                    errors.INVALID_OPTION,
                    "Unsupported option '%s' for type '%s'" % \
                    (attrs["name"], self.item.type))
            if attrs["name"] in [ "family", "timeout", "hashsize", "maxelem" ] \
               and not value:
                raise FirewallError(
                    errors.INVALID_OPTION,
                    "Missing mandatory value of option '%s'" % attrs["name"])
            if attrs["name"] in [ "timeout", "hashsize", "maxelem" ]:
                try:
                    int(value)
                except ValueError:
                    raise FirewallError(
                        errors.INVALID_VALUE,
                        "Option '%s': Value '%s' is not an integer" % \
                        (attrs["name"], value))
            if attrs["name"] not in self.item.options:
                self.item.options[attrs["name"]] = value
            else:
                log.warning("Option %s already set, ignoring.", attrs["name"])
        elif name == "entry":
            pass
    def endElement(self, name):
        IO_Object_ContentHandler.endElement(self, name)
        if name == "entry":
            if self._element not in self.item.entries:
                self.item.entries.append(self._element)
            else:
                log.warning("Entry %s already set, ignoring.", self._element)

def ipset_reader(filename, path):
    ipset = IPSet()
    if not filename.endswith(".xml"):
        raise FirewallError(errors.INVALID_NAME,
                            "'%s' is missing .xml suffix" % filename)
    ipset.name = filename[:-4]
    ipset.check_name(ipset.name)
    ipset.filename = filename
    ipset.path = path
    ipset.builtin = False if path.startswith(ETC_FIREWALLD) else True
    ipset.default = ipset.builtin
    handler = ipset_ContentHandler(ipset)
    parser = sax.make_parser()
    parser.setContentHandler(handler)
    name = "%s/%s" % (path, filename)
    with open(name, "r") as f:
        parser.parse(f)
    del handler
    del parser
    if "timeout" in ipset.options and len(ipset.entries) > 0:
        # no entries visible for ipsets with timeout
        log.warning("ipset '%s': timeout option is set, entries are ignored",
                    ipset.name)
        del ipset.entries[:]
    i = 0
    while i < len(ipset.entries):
        try:
            ipset.check_entry(ipset.entries[i], ipset.options, ipset.type)
        except FirewallError as e:
            log.warning("%s, ignoring.", e)
            ipset.entries.pop(i)
        else:
            i += 1
    if PY2:
        ipset.encode_strings()

    return ipset

def ipset_writer(ipset, path=None):
    _path = path if path else ipset.path

    if ipset.filename:
        name = "%s/%s" % (_path, ipset.filename)
    else:
        name = "%s/%s.xml" % (_path, ipset.name)

    if os.path.exists(name):
        try:
            shutil.copy2(name, "%s.old" % name)
        except Exception as msg:
            log.error("Backup of file '%s' failed: %s", name, msg)

    dirpath = os.path.dirname(name)
    if dirpath.startswith(ETC_FIREWALLD) and not os.path.exists(dirpath):
        if not os.path.exists(ETC_FIREWALLD):
            os.mkdir(ETC_FIREWALLD, 0o750)
        os.mkdir(dirpath, 0o750)

    f = io.open(name, mode='wt', encoding='UTF-8')
    handler = IO_Object_XMLGenerator(f)
    handler.startDocument()

    # start ipset element
    attrs = { "type": ipset.type }
    if ipset.version and ipset.version != "":
        attrs["version"] = ipset.version
    handler.startElement("ipset", attrs)
    handler.ignorableWhitespace("\n")

    # short
    if ipset.short and ipset.short != "":
        handler.ignorableWhitespace("  ")
        handler.startElement("short", { })
        handler.characters(ipset.short)
        handler.endElement("short")
        handler.ignorableWhitespace("\n")

    # description
    if ipset.description and ipset.description != "":
        handler.ignorableWhitespace("  ")
        handler.startElement("description", { })
        handler.characters(ipset.description)
        handler.endElement("description")
        handler.ignorableWhitespace("\n")

    # options
    for key,value in ipset.options.items():
        handler.ignorableWhitespace("  ")
        if value != "":
            handler.simpleElement("option", { "name": key, "value": value })
        else:
            handler.simpleElement("option", { "name": key })
        handler.ignorableWhitespace("\n")

    # entries
    for entry in ipset.entries:
        handler.ignorableWhitespace("  ")
        handler.startElement("entry", { })
        handler.characters(entry)
        handler.endElement("entry")
        handler.ignorableWhitespace("\n")

    # end ipset element
    handler.endElement('ipset')
    handler.ignorableWhitespace("\n")
    handler.endDocument()
    f.close()
    del handler
