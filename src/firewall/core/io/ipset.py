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

from firewall import config
from firewall.functions import checkIP, checkIP6, checkIPnMask, \
    checkIP6nMask, check_mac, check_port, checkInterface, \
    checkProtocol
from firewall.core.io.io_object import IO_Object, \
    IO_Object_ContentHandler, IO_Object_XMLGenerator
from firewall.core.ipset import IPSET_TYPES, IPSET_CREATE_OPTIONS
from firewall.core.icmp import check_icmp_name, check_icmp_type, \
    check_icmpv6_name, check_icmpv6_type
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

    @staticmethod
    def check_entry(entry, options, ipset_type):
        family = "ipv4"
        if "family" in options:
            if options["family"] == "inet6":
                family = "ipv6"

        if not ipset_type.startswith("hash:"):
            raise FirewallError(errors.INVALID_IPSET,
                                "ipset type '%s' not usable" % ipset_type)
        flags = ipset_type[5:].split(",")
        items = entry.split(",")

        if len(flags) != len(items) or len(flags) < 1:
            raise FirewallError(
                errors.INVALID_ENTRY,
                "entry '%s' does not match ipset type '%s'" % \
                (entry, ipset_type))

        for i in range(len(flags)):
            flag = flags[i]
            item = items[i]

            if flag == "ip":
                if "-" in item and family == "ipv4":
                    # IP ranges only with plain IPs, no masks
                    if i > 1:
                        raise FirewallError(
                            errors.INVALID_ENTRY,
                            "invalid address '%s' in '%s'[%d]" % \
                            (item, entry, i))
                    splits = item.split("-")
                    if len(splits) != 2:
                        raise FirewallError(
                            errors.INVALID_ENTRY,
                            "invalid address range '%s' in '%s' for %s (%s)" % \
                            (item, entry, ipset_type, family))
                    for _split in splits:
                        if (family == "ipv4" and not checkIP(_split)) or \
                           (family == "ipv6" and not checkIP6(_split)):
                            raise FirewallError(
                                errors.INVALID_ENTRY,
                                "invalid address '%s' in '%s' for %s (%s)" % \
                                (_split, entry, ipset_type, family))
                else:
                    # IPs with mask only allowed in the first
                    # position of the type
                    if family == "ipv4":
                        if item == "0.0.0.0":
                            raise FirewallError(
                                errors.INVALID_ENTRY,
                                "invalid address '%s' in '%s' for %s (%s)" % \
                                (item, entry, ipset_type, family))
                        if i == 0:
                            ip_check = checkIPnMask
                        else:
                            ip_check = checkIP
                    else:
                        ip_check = checkIP6
                    if not ip_check(item):
                        raise FirewallError(
                            errors.INVALID_ENTRY,
                            "invalid address '%s' in '%s' for %s (%s)" % \
                            (item, entry, ipset_type, family))
            elif flag == "net":
                if "-" in item:
                    # IP ranges only with plain IPs, no masks
                    splits = item.split("-")
                    if len(splits) != 2:
                        raise FirewallError(
                            errors.INVALID_ENTRY,
                            "invalid address range '%s' in '%s' for %s (%s)" % \
                            (item, entry, ipset_type, family))
                    # First part can only be a plain IP
                    if (family == "ipv4" and not checkIP(splits[0])) or \
                       (family == "ipv6" and not checkIP6(splits[0])):
                        raise FirewallError(
                            errors.INVALID_ENTRY,
                            "invalid address '%s' in '%s' for %s (%s)" % \
                            (splits[0], entry, ipset_type, family))
                    # Second part can also have a mask
                    if (family == "ipv4" and not checkIPnMask(splits[1])) or \
                       (family == "ipv6" and not checkIP6nMask(splits[1])):
                        raise FirewallError(
                            errors.INVALID_ENTRY,
                            "invalid address '%s' in '%s' for %s (%s)" % \
                            (splits[1], entry, ipset_type, family))
                else:
                    # IPs with mask allowed in all positions, but no /0
                    if item.endswith("/0"):
                        if not (family == "ipv6" and i == 0 and
                                ipset_type == "hash:net,iface"):
                            raise FirewallError(
                                errors.INVALID_ENTRY,
                                "invalid address '%s' in '%s' for %s (%s)" % \
                                (item, entry, ipset_type, family))
                    if (family == "ipv4" and not checkIPnMask(item)) or \
                       (family == "ipv6" and not checkIP6nMask(item)):
                        raise FirewallError(
                            errors.INVALID_ENTRY,
                            "invalid address '%s' in '%s' for %s (%s)" % \
                            (item, entry, ipset_type, family))
            elif flag == "mac":
                # ipset does not allow to add 00:00:00:00:00:00
                if not check_mac(item) or item == "00:00:00:00:00:00":
                    raise FirewallError(
                        errors.INVALID_ENTRY,
                        "invalid mac address '%s' in '%s'" % (item, entry))
            elif flag == "port":
                if ":" in item:
                    splits = item.split(":")
                    if len(splits) != 2:
                        raise FirewallError(
                            errors.INVALID_ENTRY,
                            "invalid port '%s'" % (item))
                    if splits[0] == "icmp":
                        if family != "ipv4":
                            raise FirewallError(
                                errors.INVALID_ENTRY,
                                "invalid protocol for family '%s' in '%s'" % \
                                (family, entry))
                        if not check_icmp_name(splits[1]) and not \
                           check_icmp_type(splits[1]):
                            raise FirewallError(
                                errors.INVALID_ENTRY,
                                "invalid icmp type '%s' in '%s'" % \
                                (splits[1], entry))
                    elif splits[0] in [ "icmpv6", "ipv6-icmp" ]:
                        if family != "ipv6":
                            raise FirewallError(
                                errors.INVALID_ENTRY,
                                "invalid protocol for family '%s' in '%s'" % \
                                (family, entry))
                        if not check_icmpv6_name(splits[1]) and not \
                           check_icmpv6_type(splits[1]):
                            raise FirewallError(
                                errors.INVALID_ENTRY,
                                "invalid icmpv6 type '%s' in '%s'" % \
                                (splits[1], entry))
                    elif splits[0] not in [ "tcp", "sctp", "udp", "udplite" ] \
                       and not checkProtocol(splits[0]):
                        raise FirewallError(
                            errors.INVALID_ENTRY,
                            "invalid protocol '%s' in '%s'" % (splits[0],
                                                               entry))
                    elif not check_port(splits[1]):
                        raise FirewallError(
                            errors.INVALID_ENTRY,
                            "invalid port '%s'in '%s'" % (splits[1], entry))
                else:
                    if not check_port(item):
                        raise FirewallError(
                            errors.INVALID_ENTRY,
                            "invalid port '%s' in '%s'" % (item, entry))
            elif flag == "mark":
                if item.startswith("0x"):
                    try:
                        int_val = int(item, 16)
                    except ValueError:
                        raise FirewallError(
                            errors.INVALID_ENTRY,
                            "invalid mark '%s' in '%s'" % (item, entry))
                else:
                    try:
                        int_val = int(item)
                    except ValueError:
                        raise FirewallError(
                            errors.INVALID_ENTRY,
                            "invalid mark '%s' in '%s'" % (item, entry))
                if int_val < 0 or int_val > 4294967295:
                    raise FirewallError(
                        errors.INVALID_ENTRY,
                        "invalid mark '%s' in '%s'" % (item, entry))
            elif flag == "iface":
                if not checkInterface(item) or len(item) > 15:
                    raise FirewallError(
                        errors.INVALID_ENTRY,
                        "invalid interface '%s' in '%s'" % (item, entry))
            else:
                raise FirewallError(errors.INVALID_IPSET,
                                    "ipset type '%s' not usable" % ipset_type)

    def _check_config(self, config, item, all_config):
        if item == "type":
            if config not in IPSET_TYPES:
                raise FirewallError(errors.INVALID_TYPE,
                                    "'%s' is not valid ipset type" % config)
        if item == "options":
            for key in config.keys():
                if key not in IPSET_CREATE_OPTIONS:
                    raise FirewallError(errors.INVALID_IPSET,
                                        "ipset invalid option '%s'" % key)
                if key in [ "timeout", "hashsize", "maxelem" ]:
                    try:
                        int_value = int(config[key])
                    except ValueError:
                        raise FirewallError(
                            errors.INVALID_VALUE,
                            "Option '%s': Value '%s' is not an integer" % \
                            (key, config[key]))
                    if int_value < 0:
                        raise FirewallError(
                            errors.INVALID_VALUE,
                            "Option '%s': Value '%s' is negative" % \
                            (key, config[key]))
                elif key == "family" and \
                     config[key] not in [ "inet", "inet6" ]:
                    raise FirewallError(errors.INVALID_FAMILY, config[key])

    def import_config(self, config):
        if "timeout" in config[4] and config[4]["timeout"] != "0":
            if len(config[5]) != 0:
                raise FirewallError(errors.IPSET_WITH_TIMEOUT)
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
                if attrs["type"] not in IPSET_TYPES:
                    raise FirewallError(errors.INVALID_TYPE, "%s" % attrs["type"])
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
                    int_value = int(value)
                except ValueError:
                    raise FirewallError(
                        errors.INVALID_VALUE,
                        "Option '%s': Value '%s' is not an integer" % \
                        (attrs["name"], value))
                if int_value < 0:
                    raise FirewallError(
                        errors.INVALID_VALUE,
                        "Option '%s': Value '%s' is negative" % \
                        (attrs["name"], value))
            if attrs["name"] == "family" and value not in [ "inet", "inet6" ]:
                raise FirewallError(errors.INVALID_FAMILY, value)
            if attrs["name"] not in self.item.options:
                self.item.options[attrs["name"]] = value
            else:
                log.warning("Option %s already set, ignoring.", attrs["name"])
        # nothing to do for entry and entries here

    def endElement(self, name):
        IO_Object_ContentHandler.endElement(self, name)
        if name == "entry":
            self.item.entries.append(self._element)

def ipset_reader(filename, path):
    ipset = IPSet()
    if not filename.endswith(".xml"):
        raise FirewallError(errors.INVALID_NAME,
                            "'%s' is missing .xml suffix" % filename)
    ipset.name = filename[:-4]
    ipset.check_name(ipset.name)
    ipset.filename = filename
    ipset.path = path
    ipset.builtin = False if path.startswith(config.ETC_FIREWALLD) else True
    ipset.default = ipset.builtin
    handler = ipset_ContentHandler(ipset)
    parser = sax.make_parser()
    parser.setContentHandler(handler)
    name = "%s/%s" % (path, filename)
    with open(name, "rb") as f:
        source = sax.InputSource(None)
        source.setByteStream(f)
        try:
            parser.parse(source)
        except sax.SAXParseException as msg:
            raise FirewallError(errors.INVALID_IPSET,
                                "not a valid ipset file: %s" % \
                                msg.getException())
    del handler
    del parser
    if "timeout" in ipset.options and ipset.options["timeout"] != "0" and \
       len(ipset.entries) > 0:
        # no entries visible for ipsets with timeout
        log.warning("ipset '%s': timeout option is set, entries are ignored",
                    ipset.name)
        del ipset.entries[:]
    i = 0
    entries_set = set()
    while i < len(ipset.entries):
        if ipset.entries[i] in entries_set:
            log.warning("Entry %s already set, ignoring.", ipset.entries[i])
            ipset.entries.pop(i)
        else:
            try:
                ipset.check_entry(ipset.entries[i], ipset.options, ipset.type)
            except FirewallError as e:
                log.warning("%s, ignoring.", e)
                ipset.entries.pop(i)
            else:
                entries_set.add(ipset.entries[i])
                i += 1
    del entries_set

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
    if dirpath.startswith(config.ETC_FIREWALLD) and not os.path.exists(dirpath):
        if not os.path.exists(config.ETC_FIREWALLD):
            os.mkdir(config.ETC_FIREWALLD, 0o750)
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
