# -*- coding: utf-8 -*-
#
# Copyright (C) 2011-2013 Red Hat, Inc.
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
from firewall.functions import checkIP, uniqify, max_zone_name_len
from firewall.core.base import DEFAULT_ZONE_TARGET, ZONE_TARGETS
from firewall.core.io.io_object import *
from firewall.core.rich import *
from firewall.core.logger import log

class Zone(IO_Object):
    """ Zone class """

    IMPORT_EXPORT_STRUCTURE = (
        ( "version",  "" ),                            # s
        ( "short", "" ),                               # s
        ( "description", "" ),                         # s
        ( "UNUSED", False ),                           # b
        ( "target", "" ),                              # s
        ( "services", [ "", ], ),                      # as
        ( "ports", [ ( "", "" ), ], ),                 # a(ss)
        ( "icmp_blocks", [ "", ], ),                   # as
        ( "masquerade", False ),                       # b
        ( "forward_ports", [ ( "", "", "", "" ), ], ), # a(ssss)
        ( "interfaces", [ "" ] ),                      # as
        ( "sources", [ "" ] ),                         # as
        ( "rules_str", [ "" ] ),                       # as
        )
    DBUS_SIGNATURE = '(sssbsasa(ss)asba(ssss)asasas)'
    ADDITIONAL_ALNUM_CHARS = [ "_" ]
    PARSER_REQUIRED_ELEMENT_ATTRS = {
        "short": None,
        "description": None,
        "zone": None,
        "service": [ "name" ],
        "port": [ "port", "protocol" ],
        "icmp-block": [ "name" ],
        "forward-port": [ "port", "protocol" ],
        "interface": [ "name" ],
        "rule": None,
        "source": [ "address" ],
        "destination": [ "address" ],
        "protocol": [ "value" ],
        "log":  None,
        "audit": None,
        "accept": None,
        "reject": None,
        "drop": None,
        "limit": [ "value" ],
        }
    PARSER_OPTIONAL_ELEMENT_ATTRS = {
        "zone": [ "name", "immutable", "target", "version" ],
        "masquerade": [ "enabled" ],
        "forward-port": [ "to-port", "to-addr" ],
        "rule": [ "family" ],
        "source": [ "invert", "family" ],
        "destination": [ "invert" ],
        "log": [ "prefix", "level" ],
        "reject": [ "type" ],
        }

    @staticmethod
    def index_of (element):
        for i, (el, val) in enumerate(Zone.IMPORT_EXPORT_STRUCTURE):
            if el == element:
                return i
        raise FirewallError(UNKNOWN_ERROR)

    def __init__(self):
        super(Zone, self).__init__()
        self.version = ""
        self.short = ""
        self.description = ""
        self.UNUSED = False
        self.target = DEFAULT_ZONE_TARGET
        self.services = [ ]
        self.ports = [ ]
        self.icmp_blocks = [ ]
        self.masquerade = False
        self.forward_ports = [ ]
        self.interfaces = [ ]
        self.sources = [ ]
        self.fw_config = None # to be able to check services and a icmp_blocks
        self.rules = [ ]
        self.combined = False

    def __getattr__(self, name):
        if name == "rules_str":
            rules_str = [str(rule) for rule in self.rules]
            return rules_str
        else:
            return object.__getattr__(self, name)

    def __setattr__(self, name, value):
        if name == "rules_str":
            self.rules = [Rich_Rule(rule_str=str) for str in value]
        else:
            object.__setattr__(self, name, value)

    def _check_config(self, config, item):
        if item == "services" and self.fw_config:
            existing_services = self.fw_config.get_services()
            for service in config:
                if not service in existing_services:
                    raise FirewallError(INVALID_SERVICE, service)
        elif item == "ports":
            for port in config:
                check_port(port[0])
                check_protocol(port[1])
        elif item == "icmp_blocks" and self.fw_config:
            existing_icmptypes = self.fw_config.get_icmptypes()
            for icmptype in config:
                if not icmptype in existing_icmptypes:
                    raise FirewallError(INVALID_ICMPTYPE, icmptype)
        elif item == "forward_ports":
            for fwd_port in config:
                check_port(fwd_port[0])
                check_protocol(fwd_port[1])
                if not fwd_port[2] and not fwd_port[3]:
                    raise FirewallError(INVALID_FORWARD, fwd_port)
                if fwd_port[2]:
                    check_port(fwd_port[2])
                if fwd_port[3]:
                    if not checkIP(fwd_port[3]):
                        raise FirewallError(INVALID_ADDR, fwd_port[3])

    def combine(self, zone):
        self.combined = True
        self.filename = None
        self.version = ""
        self.short = ""
        self.description = ""

        for interface in zone.interfaces:
            if interface not in self.interfaces:
                self.interfaces.append(interface)
        for source in zone.sources:
            if source not in self.sources:
                self.sources.append(source)
        for service in zone.services:
            if service not in self.services:
                self.services.append(service)
        for port in zone.ports:
            if port not in self.ports:
                self.ports.append(port)
        for icmp in zone.icmp_blocks:
            if icmp not in self.icmp_blocks:
                self.icmp_blocks.append(icmp)
        if zone.masquerade:
            self.masquerade = True
        for forward in zone.forward_ports:
            if forward not in self.forward_ports:
                self.forward_ports.append(forward)
        for rule in zone.rules:
            self.rules.append(rule)

# PARSER

class zone_ContentHandler(IO_Object_ContentHandler):
    def __init__(self, item):
        IO_Object_ContentHandler.__init__(self, item)
        self._rule = None
        self._rule_error = False
        self._limit_ok = None

    def startElement(self, name, attrs):
        if self._rule_error:
            return

        self.item.parser_check_element_attrs(name, attrs)

        if name == "zone":
            if "name" in attrs:
                log.warning("Ignoring deprecated attribute name='%s'" % 
                            attrs["name"])
            if "version" in attrs:
                self.item.version = str(attrs["version"])
            if "immutable" in attrs:
                log.warning("Ignoring deprecated attribute immutable='%s'" % 
                            attrs["immutable"])
            if "target" in attrs:
                target = str(attrs["target"])
                if target not in ZONE_TARGETS:
                    raise FirewallError(INVALID_TARGET, target)
                if target != "" and target != DEFAULT_ZONE_TARGET:
                    self.item.target = target

        elif name == "short":
            pass
        elif name == "description":
            pass
        elif name == "service":
            if self._rule:
                if self._rule.element:
                    log.error('Invalid rule: More than one element, ignoring.')
                    self._rule_error = True
                    return
                self._rule.element = Rich_Service(str(attrs["name"]))
                return
            if str(attrs["name"]) not in self.item.services:
                self.item.services.append(str(attrs["name"]))
        elif name == "port":
            if self._rule:
                if self._rule.element:
                    log.error('Invalid rule: More than one element, ignoring.')
                    self._rule_error = True
                    return
                self._rule.element = Rich_Port(str(attrs["port"]),
                                               str(attrs["protocol"]))
                return
            # TODO: fix port string according to fw_zone.__port_id()
            entry = (str(attrs["port"]), str(attrs["protocol"]))
            if entry not in self.item.ports:
                self.item.ports.append(entry)
        elif name == "protocol":
            if self._rule:
                if self._rule.element:
                    log.error('Invalid rule: More than one element, ignoring.')
                    self._rule_error = True
                    return
                self._rule.element = Rich_Protocol(str(attrs["value"]))
            else:
                log.error('Protocol allowed only in rule.')
        elif name == "icmp-block":
            if self._rule:
                if self._rule.element:
                    log.error('Invalid rule: More than one element, ignoring.')
                    self._rule_error = True
                    return
                self._rule.element = Rich_IcmpBlock(str(attrs["name"]))
                return
            if str(attrs["name"]) not in self.item.icmp_blocks:
                self.item.icmp_blocks.append(str(attrs["name"]))
        elif name == "masquerade":
            if self._rule:
                if "enabled" in attrs:
                    log.warning('Invalid rule: Masquerade attribute ignored in rule.')
                if self._rule.element:
                    log.error('Invalid rule: More than one element, ignoring.')
                    self._rule_error = True
                    return
                self._rule.element = Rich_Masquerade()
                return
            if attrs["enabled"].lower() in [ "yes", "true" ]:
                self.item.masquerade = True
        elif name == "forward-port":
            to_port = ""
            if "to-port" in attrs:
                to_port = str(attrs["to-port"])
            to_addr = ""
            if "to-addr" in attrs:
                to_addr = str(attrs["to-addr"])

            if self._rule:
                if self._rule.element:
                    log.error('Invalid rule: More than one element, ignoring.')
                    self._rule_error = True
                    return
                self._rule.element = Rich_ForwardPort(str(attrs["port"]),
                                                      str(attrs["protocol"]),
                                                      to_port, to_addr)
                return
            # TODO: fix port string according to fw_zone.__forward_port_id()
            entry = (str(attrs["port"]), str(attrs["protocol"]), to_port,
                     to_addr)
            if entry not in self.item.forward_ports:
                self.item.forward_ports.append(entry)

        elif name == "interface":
            if self._rule:
                log.error('Invalid rule: interface use in rule.')
                self._rule_error = True
                return
            # zone bound to interface
            if not "name" in attrs:
                log.error('Invalid interface: Name missing.')
                self._rule_error = True
                return
            name = str(attrs["name"])
            if name not in self.item.interfaces:
                self.item.interfaces.append(name)
            
        elif name == "source":
            if self._rule:
                if self._rule.source:
                    log.error('Invalid rule: More than one source')
                    self._rule_error = True
                    return
                invert = False
                if "invert" in attrs and \
                        attrs["invert"].lower() in [ "yes", "true" ]:
                    invert = True
                self._rule.source = Rich_Source(str(attrs["address"]), invert)
                return
            # zone bound to source
            if not "address" in attrs:
                log.error('Invalid source: Address missing.')
                return
            if "family" in attrs:
                log.warning("Ignoring deprecated attribute family='%s'" %
                            attrs["family"])
            if "invert" in attrs:
                log.error('Invalid source: Invertion not allowed here.')
                return
            entry = str(attrs["address"])
            if entry not in self.item.sources:
                self.item.sources.append(entry)

        elif name == "destination":
            if not self._rule:
                log.error('Invalid rule: Destination outside of rule')
                self._rule_error = True
                return
            if self._rule.destination:
                log.error('Invalid rule: More than one destination')
                return
            invert = False
            if "invert" in attrs and \
                    attrs["invert"].lower() in [ "yes", "true" ]:
                invert = True
            self._rule.destination = Rich_Destination(str(attrs["address"]),
                                                      invert)

        elif name in [ "accept", "reject", "drop" ]:
            if not self._rule:
                log.error('Invalid rule: Action outside of rule')
                self._rule_error = True
                return
            if self._rule.action:
                log.error('Invalid rule: More than one action')
                self._rule_error = True
                return
            if name == "accept":
                self._rule.action = Rich_Accept()
            if name == "reject":
                _type = None
                if "type" in attrs:
                    _type = str(attrs["type"])
                self._rule.action = Rich_Reject(_type)
            if name == "drop":
                self._rule.action = Rich_Drop()
            self._limit_ok = self._rule.action

        elif name == "log":
            if not self._rule:
                log.error('Invalid rule: Log outside of rule')
                return
            if self._rule.log:
                log.error('Invalid rule: More than one log')
                return
            level = None
            if "level" in attrs:
                level = str(attrs["level"])
                if level not in [ "emerg", "alert", "crit", "error",
                                  "warning", "notice", "info", "debug" ]:
                    log.error('Invalid rule: Invalid log level')
                    self._rule_error = True
                    return
            prefix = str(attrs["prefix"]) if "prefix" in attrs else None
            self._rule.log = Rich_Log(prefix, level)
            self._limit_ok = self._rule.log

        elif name == "audit":
            if not self._rule:
                log.error('Invalid rule: Audit outside of rule')
                return
            if self._rule.audit:
                log.error('Invalid rule: More than one audit')
                self._rule_error = True
                return            
            self._rule.audit = Rich_Audit()
            self._limit_ok = self._rule.audit

        elif name == "rule":
            family = None
            if "family" in attrs:
                family = attrs["family"]
                if family not in [ "ipv4", "ipv6" ]:
                    log.error('Invalid rule: Rule family "%s" invalid' % 
                              attrs["family"])
                    self._rule_error = True
                    return
            self._rule = Rich_Rule(family)
            self.item.rules.append(self._rule)

        elif name == "limit":
            if not self._limit_ok:
                log.error('Invalid rule: Limit outside of action, log and audit')
                self._rule_error = True
                return
            if self._limit_ok.limit:
                log.error('Invalid rule: More than one limit')
                self._rule_error = True
                return
            value = str(attrs["value"])
            self._limit_ok.limit = Rich_Limit(value)

        else:
            log.error('Unknown XML element %s' % name)
            return

    def endElement(self, name):
        IO_Object_ContentHandler.endElement(self, name)

        if name == "rule":
            if not self._rule_error:
                try:
                    self._rule.check()
                except Exception as e:
                    log.error("%s: %s" % (e, str(self._rule)))
                    self._rule_error = True
            if self._rule_error and self._rule in self.item.rules:
                self.item.rules.remove(self._rule)
            self._rule = None
            self._rule_error = False
        elif name in [ "accept", "reject", "drop", "log", "audit" ]:
            self._limit_ok = None

def zone_reader(filename, path):
    zone = Zone()
    if not filename.endswith(".xml"):
        raise FirewallError(INVALID_NAME, filename)
    zone.name = filename[:-4]
    if len(zone.name) > max_zone_name_len():
        raise FirewallError(INVALID_NAME, filename)
    zone.check_name(zone.name)
    zone.filename = filename
    zone.path = path
    zone.default = False if path.startswith(ETC_FIREWALLD) else True
    handler = zone_ContentHandler(zone)
    parser = sax.make_parser()
    parser.setContentHandler(handler)
    name = "%s/%s" % (path, filename)
    with open(name, "r") as f:
        parser.parse(f)
    return zone

def zone_writer(zone, path=None):
    _path = path if path else zone.path

    if zone.filename:
        name = "%s/%s" % (_path, zone.filename)
    else:
        name = "%s/%s.xml" % (_path, zone.name)

    if os.path.exists(name):
        try:
            shutil.copy2(name, "%s.old" % name)
        except Exception, msg:
            raise IOError("Backup of '%s' failed: %s" % (name, msg))

    fd = open(name, "w")
    handler = IO_Object_XMLGenerator(fd)
    handler.startDocument()

    # start zone element
    attrs = {}
    if zone.version and zone.version != "":
        attrs["version"] = zone.version
    if zone.target != DEFAULT_ZONE_TARGET:
        attrs["target"] = zone.target
    handler.startElement("zone", attrs)
    handler.ignorableWhitespace("\n")

    # short
    if zone.short and zone.short != "":
        handler.ignorableWhitespace("  ")
        handler.startElement("short", { })
        handler.characters(zone.short.decode('utf-8')
                           if isinstance(zone.short, bytes)
                           else zone.short)
        handler.endElement("short")
        handler.ignorableWhitespace("\n")

    # description
    if zone.description and zone.description != "":
        handler.ignorableWhitespace("  ")
        handler.startElement("description", { })
        handler.characters(zone.description.decode('utf-8')
                           if isinstance(zone.description, bytes)
                           else zone.description)
        handler.endElement("description")
        handler.ignorableWhitespace("\n")

    # interfaces
    for interface in uniqify(zone.interfaces):
        handler.ignorableWhitespace("  ")
        handler.simpleElement("interface", { "name": interface })
        handler.ignorableWhitespace("\n")

    # source
    for source in uniqify(zone.sources):
        handler.ignorableWhitespace("  ")
        handler.simpleElement("source", { "address": source })
        handler.ignorableWhitespace("\n")

    # services
    for service in uniqify(zone.services):
        handler.ignorableWhitespace("  ")
        handler.simpleElement("service", { "name": service })
        handler.ignorableWhitespace("\n")

    # ports
    for port in uniqify(zone.ports):
        handler.ignorableWhitespace("  ")
        handler.simpleElement("port", { "port": port[0], "protocol": port[1] })
        handler.ignorableWhitespace("\n")

    # icmp-blocks
    for icmp in uniqify(zone.icmp_blocks):
        handler.ignorableWhitespace("  ")
        handler.simpleElement("icmp-block", { "name": icmp })
        handler.ignorableWhitespace("\n")

    # masquerade
    if zone.masquerade:
        handler.ignorableWhitespace("  ")
        handler.simpleElement("masquerade", { "enabled": "Yes" })
        handler.ignorableWhitespace("\n")

    # forward-ports
    for forward in uniqify(zone.forward_ports):
        handler.ignorableWhitespace("  ")
        attrs = { "port": forward[0], "protocol": forward[1] }
        if forward[2] and forward[2] != "" :
            attrs["to-port"] = forward[2]
        if forward[3] and forward[3] != "" :
            attrs["to-addr"] = forward[3]
        handler.simpleElement("forward-port", attrs)
        handler.ignorableWhitespace("\n")

    # rules
    for rule in zone.rules:
        attrs = { }
        if rule.family:
            attrs["family"] = rule.family
        handler.ignorableWhitespace("  ")
        handler.startElement("rule", attrs)
        handler.ignorableWhitespace("\n")

        # source
        if rule.source:
            attrs = { "address": rule.source.addr }
            if rule.source.invert:
                attrs["invert"] = "True"
            handler.ignorableWhitespace("    ")
            handler.simpleElement("source", attrs)
            handler.ignorableWhitespace("\n")

        # destination
        if rule.destination:
            attrs = { "address": rule.destination.addr }
            if rule.destination.invert:
                attrs["invert"] = "True"
            handler.ignorableWhitespace("    ")
            handler.simpleElement("destination", attrs)
            handler.ignorableWhitespace("\n")

        # element
        if rule.element:
            element = ""
            attrs = { }

            if type(rule.element) == Rich_Service:
                element = "service"
                attrs["name"] = rule.element.name
            elif type(rule.element) == Rich_Port:
                element = "port"
                attrs["port"] = rule.element.port
                attrs["protocol"] = rule.element.protocol
            elif type(rule.element) == Rich_Protocol:
                element = "protocol"
                attrs["value"] = rule.element.value
            elif type(rule.element) == Rich_Masquerade:
                element = "masquerade"
            elif type(rule.element) == Rich_IcmpBlock:
                element = "icmp-block"
                attrs["name"] = rule.element.name
            elif type(rule.element) == Rich_ForwardPort:
                element = "forward-port"
                attrs["port"] = rule.element.port
                attrs["protocol"] = rule.element.protocol
                if rule.element.to_port != "":
                    attrs["to-port"] = rule.element.to_port
                if rule.element.to_address != "":
                    attrs["to-addr"] = rule.element.to_address
            else:
                log.error('Unknown element "%s"' % type(rule.element))

            handler.ignorableWhitespace("    ")
            handler.simpleElement(element, attrs)
            handler.ignorableWhitespace("\n")

        # rule.element

        # log
        if rule.log:
            attrs = { }
            if rule.log.prefix:
                attrs["prefix"] = rule.log.prefix
            if rule.log.level:
                attrs["level"] = rule.log.level
            if rule.log.limit:
                handler.ignorableWhitespace("    ")
                handler.startElement("log", attrs)
                handler.ignorableWhitespace("\n      ")
                handler.simpleElement("limit",
                                      { "value": rule.log.limit.value })
                handler.ignorableWhitespace("\n    ")
                handler.endElement("log")
            else:
                handler.ignorableWhitespace("    ")
                handler.simpleElement("log", attrs)
            handler.ignorableWhitespace("\n")

        # audit
        if rule.audit:
            if rule.audit.limit:
                handler.ignorableWhitespace("    ")
                handler.startElement("audit", { })
                handler.ignorableWhitespace("\n      ")
                handler.simpleElement("limit",
                                      { "value": rule.audit.limit.value })
                handler.ignorableWhitespace("\n    ")
                handler.endElement("audit")
            else:
                handler.ignorableWhitespace("    ")
                handler.simpleElement("audit", attrs)
            handler.ignorableWhitespace("\n")

        # action
        if rule.action:
            action = ""
            attrs = { }
            if type(rule.action) == Rich_Accept:
                action = "accept"
            elif type(rule.action) == Rich_Reject:
                action = "reject"
                if rule.action.type:
                    attrs["type"] = rule.action.type
            elif type(rule.action) == Rich_Drop:
                action = "drop"
            else:
                log.error('Unknown action "%s"' % type(rule.action))
            if rule.action.limit:
                handler.ignorableWhitespace("    ")
                handler.startElement(action, attrs)
                handler.ignorableWhitespace("\n      ")
                handler.simpleElement("limit",
                                      { "value": rule.action.limit.value })
                handler.ignorableWhitespace("\n    ")
                handler.endElement(action)
            else:
                handler.ignorableWhitespace("    ")
                handler.simpleElement(action, attrs)
            handler.ignorableWhitespace("\n")

        handler.ignorableWhitespace("  ")
        handler.endElement("rule")
        handler.ignorableWhitespace("\n")

    # end zone element
    handler.endElement("zone")
    handler.ignorableWhitespace("\n")
    handler.endDocument()
    fd.close()
