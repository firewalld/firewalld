# -*- coding: utf-8 -*-
#
# SPDX-License-Identifier: GPL-2.0-or-later

__all__ = [ "Policy", "policy_reader", "policy_writer" ]

import xml.sax as sax
import os
import io
import shutil
import copy
from collections import OrderedDict

from firewall import config
from firewall.functions import checkIP, checkIP6
from firewall.functions import uniqify, max_policy_name_len, portStr
from firewall.core.base import DEFAULT_POLICY_TARGET, POLICY_TARGETS
from firewall.core.io.io_object import IO_Object, \
    IO_Object_ContentHandler, IO_Object_XMLGenerator, check_port, \
    check_tcpudp, check_protocol
from firewall.core import rich
from firewall.core.logger import log
from firewall import errors
from firewall.errors import FirewallError

class Policy(IO_Object):
    priority_min = -32768
    priority_max =  32767
    priority_default = -1
    ADDITIONAL_ALNUM_CHARS = [ "_", "-", "/" ]
    PARSER_REQUIRED_ELEMENT_ATTRS = {
        "short": None,
        "description": None,
        "policy": ["target"],
        "service": [ "name" ],
        "port": [ "port", "protocol" ],
        "icmp-block": [ "name" ],
        "icmp-type": [ "name" ],
        "forward-port": [ "port", "protocol" ],
        "rule": None,
        "destination": [ "address" ],
        "protocol": [ "value" ],
        "source-port": [ "port", "protocol" ],
        "log":  None,
        "audit": None,
        "accept": None,
        "reject": None,
        "drop": None,
        "mark": [ "set" ],
        "limit": [ "value" ],
        "ingress-zone": None,
        "egress-zone": None,
        }
    PARSER_OPTIONAL_ELEMENT_ATTRS = {
        "policy": [ "version", "priority" ],
        "forward-port": [ "to-port", "to-addr" ],
        "rule": [ "family", "priority" ],
        "destination": [ "invert" ],
        "log": [ "prefix", "level" ],
        "reject": [ "type" ],
        }

    def __init__(self):
        super(Policy, self).__init__()
        self.version = ""
        self.short = ""
        self.description = ""
        self.target = DEFAULT_POLICY_TARGET
        self.services = [ ]
        self.ports = [ ]
        self.protocols = [ ]
        self.icmp_blocks = [ ]
        self.masquerade = False
        self.forward_ports = [ ]
        self.source_ports = [ ]
        self.fw_config = None # to be able to check services and a icmp_blocks
        self.rules = [ ]
        self.combined = False
        self.applied = False
        self.priority = self.priority_default
        self.derived_from_zone = None
        self.ingress_zones = []
        self.egress_zones = []

    def cleanup(self):
        self.version = ""
        self.short = ""
        self.description = ""
        self.target = DEFAULT_POLICY_TARGET
        del self.services[:]
        del self.ports[:]
        del self.protocols[:]
        del self.icmp_blocks[:]
        self.masquerade = False
        del self.forward_ports[:]
        del self.source_ports[:]
        self.fw_config = None # to be able to check services and a icmp_blocks
        del self.rules[:]
        self.combined = False
        self.applied = False
        self.priority = self.priority_default
        del self.ingress_zones[:]
        del self.egress_zones[:]

    def __getattr__(self, name):
        if name == "rules_str":
            rules_str = [str(rule) for rule in self.rules]
            return rules_str
        else:
            return getattr(super(Policy, self), name)

    def __setattr__(self, name, value):
        if name == "rules_str":
            self.rules = [rich.Rich_Rule(rule_str=s) for s in value]
        else:
            super(Policy, self).__setattr__(name, value)

    def _check_config(self, config, item):
        if item == "services" and self.fw_config:
            existing_services = self.fw_config.get_services()
            for service in config:
                if service not in existing_services:
                    raise FirewallError(errors.INVALID_SERVICE,
                                        "'%s' not among existing services" % \
                                        service)
        elif item == "ports":
            for port in config:
                check_port(port[0])
                check_tcpudp(port[1])
        elif item == "protocols":
            for proto in config:
                check_protocol(proto)
        elif item == "icmp_blocks" and self.fw_config:
            existing_icmptypes = self.fw_config.get_icmptypes()
            for icmptype in config:
                if icmptype not in existing_icmptypes:
                    raise FirewallError(errors.INVALID_ICMPTYPE,
                                        "'%s' not among existing icmp types" % \
                                        icmptype)
        elif item == "forward_ports":
            for fwd_port in config:
                check_port(fwd_port[0])
                check_tcpudp(fwd_port[1])
                if not fwd_port[2] and not fwd_port[3]:
                    raise FirewallError(
                        errors.INVALID_FORWARD,
                        "'%s' is missing to-port AND to-addr " % fwd_port)
                if fwd_port[2]:
                    check_port(fwd_port[2])
                if fwd_port[3]:
                    if not checkIP(fwd_port[3]) and not checkIP6(fwd_port[3]):
                        raise FirewallError(
                            errors.INVALID_ADDR,
                            "to-addr '%s' is not a valid address" % fwd_port[3])
        elif item == "source_ports":
            for port in config:
                check_port(port[0])
                check_tcpudp(port[1])
        elif item == "target":
            if config not in POLICY_TARGETS:
                raise FirewallError(errors.INVALID_TARGET, config)
        elif item == "rules_str":
            for rule in config:
                rich.Rich_Rule(rule_str=rule)
        elif item in ["ingress-zone", "egress-zone"] and self.fw_config:
            existing_zones = self.fw_config.get_zones()
            for zone in config:
                if zone not in existing_zones:
                    raise FirewallError(errors.INVALID_SERVICE,
                                        "'%s' not among existing zones" % zone)

    def check_name(self, name):
        super(Policy, self).check_name(name)
        if name.startswith('/'):
            raise FirewallError(errors.INVALID_NAME,
                                "'%s' can't start with '/'" % name)
        elif name.endswith('/'):
            raise FirewallError(errors.INVALID_NAME,
                                "'%s' can't end with '/'" % name)
        elif name.count('/') > 1:
            raise FirewallError(errors.INVALID_NAME,
                                "more than one '/' in '%s'" % name)
        else:
            if "/" in name:
                checked_name = name[:name.find('/')]
            else:
                checked_name = name
            if len(checked_name) > max_policy_name_len():
                raise FirewallError(errors.INVALID_NAME,
                                    "Policy of '%s' has %d chars, max is %d %s" % (
                                    name, len(checked_name),
                                    max_policy_name_len(),
                                    self.combined))

    def import_config(self, conf):
        self.check_config(conf)

        # FIXME: 
        for key in conf:
            if not hasattr(self, key):
                raise FirewallError(errors.UNKNOWN_ERROR, "Internal error. '{}' is not a valid attribute".format(key))
            if isinstance(conf[key], list):
                # maintain list order while removing duplicates
                setattr(self, key, list(OrderedDict.fromkeys(copy.deepcopy(conf[key]))))
            else:
                setattr(self, key, copy.deepcopy(conf[key]))

    def export_config(self):
        conf = {}
        # FIXME
        type_formats = dict([(x[0], x[1]) for x in self.IMPORT_EXPORT_STRUCTURE])
        for key in type_formats:
            if getattr(self, key):
                conf[key] = copy.deepcopy(getattr(self, key))
        return conf

    def check_config(self, conf):
        # FIXME
        type_formats = dict([(x[0], x[1]) for x in self.IMPORT_EXPORT_STRUCTURE])
        for key in conf:
            if key not in [x for (x,y) in self.IMPORT_EXPORT_STRUCTURE]:
                raise FirewallError(errors.INVALID_OPTION, "policy option '{}' is not valid".format(key))
            self._check_config_structure(conf[key], type_formats[key])
            self._check_config(conf[key], key)

# PARSER

class policy_ContentHandler(IO_Object_ContentHandler):
    def __init__(self, item):
        IO_Object_ContentHandler.__init__(self, item)
        self._rule = None
        self._rule_error = False
        self._limit_ok = None

    def startElement(self, name, attrs):
        IO_Object_ContentHandler.startElement(self, name, attrs)
        if self._rule_error:
            return

        self.item.parser_check_element_attrs(name, attrs)

        if name == "policy":
            if "version" in attrs:
                self.item.version = attrs["version"]
            if "priority" in attrs:
                self.item.priority = int(attrs["priority"])
            target = attrs["target"]
            if target not in POLICY_TARGETS:
                raise FirewallError(errors.INVALID_TARGET, target)

        elif name == "short":
            pass
        elif name == "description":
            pass
        elif name == "service":
            if self._rule:
                if self._rule.element:
                    log.warning("Invalid rule: More than one element in rule '%s', ignoring.",
                                str(self._rule))
                    self._rule_error = True
                    return
                self._rule.element = rich.Rich_Service(attrs["name"])
                return
            if attrs["name"] not in self.item.services:
                self.item.services.append(attrs["name"])
            else:
                log.warning("Service '%s' already set, ignoring.",
                            attrs["name"])
        elif name == "ingress-zone":
            if attrs["name"] not in self.item.ingress_zones:
                self.item.ingress_zones.append(attrs["name"])
            else:
                log.warning("Ingress zone '%s' already set, ignoring.", attrs["name"])
        elif name == "egress-zone":
            if attrs["name"] not in self.item.egress_zones:
                self.item.egress_zones.append(attrs["name"])
            else:
                log.warning("Egress zone '%s' already set, ignoring.", attrs["name"])

        elif name == "port":
            if self._rule:
                if self._rule.element:
                    log.warning("Invalid rule: More than one element in rule '%s', ignoring.",
                                str(self._rule))
                    self._rule_error = True
                    return
                self._rule.element = rich.Rich_Port(attrs["port"],
                                                    attrs["protocol"])
                return
            check_port(attrs["port"])
            check_tcpudp(attrs["protocol"])
            entry = (portStr(attrs["port"], "-"), attrs["protocol"])
            if entry not in self.item.ports:
                self.item.ports.append(entry)
            else:
                log.warning("Port '%s/%s' already set, ignoring.",
                            attrs["port"], attrs["protocol"])

        elif name == "protocol":
            if self._rule:
                if self._rule.element:
                    log.warning("Invalid rule: More than one element in rule '%s', ignoring.",
                                str(self._rule))
                    self._rule_error = True
                    return
                self._rule.element = rich.Rich_Protocol(attrs["value"])
            else:
                check_protocol(attrs["value"])
                if attrs["value"] not in self.item.protocols:
                    self.item.protocols.append(attrs["value"])
                else:
                    log.warning("Protocol '%s' already set, ignoring.",
                                attrs["value"])
        elif name == "icmp-block":
            if self._rule:
                if self._rule.element:
                    log.warning("Invalid rule: More than one element in rule '%s', ignoring.",
                                str(self._rule))
                    self._rule_error = True
                    return
                self._rule.element = rich.Rich_IcmpBlock(attrs["name"])
                return
            if attrs["name"] not in self.item.icmp_blocks:
                self.item.icmp_blocks.append(attrs["name"])
            else:
                log.warning("icmp-block '%s' already set, ignoring.",
                            attrs["name"])

        elif name == "icmp-type":
            if self._rule:
                if self._rule.element:
                    log.warning("Invalid rule: More than one element in rule '%s', ignoring.",
                                str(self._rule))
                    self._rule_error = True
                    return
                self._rule.element = rich.Rich_IcmpType(attrs["name"])
                return
            else:
                log.warning("Invalid rule: icmp-block '%s' outside of rule",
                            attrs["name"])

        elif name == "masquerade":
            if self._rule:
                if self._rule.element:
                    log.warning("Invalid rule: More than one element in rule '%s', ignoring.",
                                str(self._rule))
                    self._rule_error = True
                    return
                self._rule.element = rich.Rich_Masquerade()
            else:
                if self.item.masquerade:
                    log.warning("Masquerade already set, ignoring.")
                else:
                    self.item.masquerade = True

        elif name == "forward-port":
            to_port = ""
            if "to-port" in attrs:
                to_port = attrs["to-port"]
            to_addr = ""
            if "to-addr" in attrs:
                to_addr = attrs["to-addr"]

            if self._rule:
                if self._rule.element:
                    log.warning("Invalid rule: More than one element in rule '%s', ignoring.",
                                str(self._rule))
                    self._rule_error = True
                    return
                self._rule.element = rich.Rich_ForwardPort(attrs["port"],
                                                           attrs["protocol"],
                                                           to_port, to_addr)
                return

            check_port(attrs["port"])
            check_tcpudp(attrs["protocol"])
            if to_port:
                check_port(to_port)
            if to_addr:
                if not checkIP(to_addr) and not checkIP6(to_addr):
                    raise FirewallError(errors.INVALID_ADDR,
                                        "to-addr '%s' is not a valid address" \
                                        % to_addr)
            entry = (portStr(attrs["port"], "-"), attrs["protocol"],
                     portStr(to_port, "-"), str(to_addr))
            if entry not in self.item.forward_ports:
                self.item.forward_ports.append(entry)
            else:
                log.warning("Forward port %s/%s%s%s already set, ignoring.",
                            attrs["port"], attrs["protocol"],
                            " >%s" % to_port if to_port else "",
                            " @%s" % to_addr if to_addr else "")

        elif name == "source-port":
            if self._rule:
                if self._rule.element:
                    log.warning("Invalid rule: More than one element in rule '%s', ignoring.",
                                str(self._rule))
                    self._rule_error = True
                    return
                self._rule.element = rich.Rich_SourcePort(attrs["port"],
                                                          attrs["protocol"])
                return
            check_port(attrs["port"])
            check_tcpudp(attrs["protocol"])
            entry = (portStr(attrs["port"], "-"), attrs["protocol"])
            if entry not in self.item.source_ports:
                self.item.source_ports.append(entry)
            else:
                log.warning("Source port '%s/%s' already set, ignoring.",
                            attrs["port"], attrs["protocol"])

        elif name == "destination":
            if not self._rule:
                log.warning('Invalid rule: Destination outside of rule')
                self._rule_error = True
                return
            if self._rule.destination:
                log.warning("Invalid rule: More than one destination in rule '%s', ignoring.",
                            str(self._rule))
                return
            invert = False
            if "invert" in attrs and \
                    attrs["invert"].lower() in [ "yes", "true" ]:
                invert = True
            self._rule.destination = rich.Rich_Destination(attrs["address"],
                                                           invert)

        elif name in [ "accept", "reject", "drop", "mark" ]:
            if not self._rule:
                log.warning('Invalid rule: Action outside of rule')
                self._rule_error = True
                return
            if self._rule.action:
                log.warning('Invalid rule: More than one action')
                self._rule_error = True
                return
            if name == "accept":
                self._rule.action = rich.Rich_Accept()
            elif name == "reject":
                _type = None
                if "type" in attrs:
                    _type = attrs["type"]
                self._rule.action = rich.Rich_Reject(_type)
            elif name == "drop":
                self._rule.action = rich.Rich_Drop()
            elif name == "mark":
                _set = attrs["set"]
                self._rule.action = rich.Rich_Mark(_set)
            self._limit_ok = self._rule.action

        elif name == "log":
            if not self._rule:
                log.warning('Invalid rule: Log outside of rule')
                return
            if self._rule.log:
                log.warning('Invalid rule: More than one log')
                return
            level = None
            if "level" in attrs:
                level = attrs["level"]
                if level not in [ "emerg", "alert", "crit", "error",
                                  "warning", "notice", "info", "debug" ]:
                    log.warning('Invalid rule: Invalid log level')
                    self._rule_error = True
                    return
            prefix = attrs["prefix"] if "prefix" in attrs else None
            self._rule.log = rich.Rich_Log(prefix, level)
            self._limit_ok = self._rule.log

        elif name == "audit":
            if not self._rule:
                log.warning('Invalid rule: Audit outside of rule')
                return
            if self._rule.audit:
                log.warning("Invalid rule: More than one audit in rule '%s', ignoring.",
                            str(self._rule))
                self._rule_error = True
                return
            self._rule.audit = rich.Rich_Audit()
            self._limit_ok = self._rule.audit

        elif name == "rule":
            family = None
            priority = 0
            if "family" in attrs:
                family = attrs["family"]
                if family not in [ "ipv4", "ipv6" ]:
                    log.warning('Invalid rule: Rule family "%s" invalid',
                                attrs["family"])
                    self._rule_error = True
                    return
            if "priority" in attrs:
                priority = int(attrs["priority"])
            self._rule = rich.Rich_Rule(family=family, priority=priority)

        elif name == "limit":
            if not self._limit_ok:
                log.warning('Invalid rule: Limit outside of action, log and audit')
                self._rule_error = True
                return
            if self._limit_ok.limit:
                log.warning("Invalid rule: More than one limit in rule '%s', ignoring.",
                            str(self._rule))
                self._rule_error = True
                return
            value = attrs["value"]
            self._limit_ok.limit = rich.Rich_Limit(value)

        else:
            log.warning("Unknown XML element '%s'", name)
            return

    def endElement(self, name):
        IO_Object_ContentHandler.endElement(self, name)

        if name == "rule":
            if not self._rule_error:
                try:
                    self._rule.check()
                except Exception as e:
                    log.warning("%s: %s", e, str(self._rule))
                else:
                    if str(self._rule) not in \
                       [ str(x) for x in self.item.rules ]:
                        self.item.rules.append(self._rule)
                    else:
                        log.warning("Rule '%s' already set, ignoring.",
                                    str(self._rule))
            self._rule = None
            self._rule_error = False
        elif name in [ "accept", "reject", "drop", "mark", "log", "audit" ]:
            self._limit_ok = None

def policy_reader(filename, path, no_check_name=False):
    policy = Policy()
    if not filename.endswith(".xml"):
        raise FirewallError(errors.INVALID_NAME,
                            "'%s' is missing .xml suffix" % filename)
    policy.name = filename[:-4]
    if not no_check_name:
        policy.check_name(policy.name)
    policy.filename = filename
    policy.path = path
    policy.builtin = False if path.startswith(config.ETC_FIREWALLD) else True
    policy.default = policy.builtin
    handler = policy_ContentHandler(policy)
    parser = sax.make_parser()
    parser.setContentHandler(handler)
    name = "%s/%s" % (path, filename)
    with open(name, "rb") as f:
        source = sax.InputSource(None)
        source.setByteStream(f)
        try:
            parser.parse(source)
        except sax.SAXParseException as msg:
            raise FirewallError(errors.INVALID_ZONE,
                                "not a valid policy file: %s" % \
                                msg.getException())
    del handler
    del parser
    return policy

def policy_writer(policy, path=None):
    _path = path if path else policy.path

    if policy.filename:
        name = "%s/%s" % (_path, policy.filename)
    else:
        name = "%s/%s.xml" % (_path, policy.name)

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

    # start policy element
    attrs = {}
    if policy.version and policy.version != "":
        attrs["version"] = policy.version
    if policy.priority != policy.priority_default:
        attrs["priority"] = str(policy.priority)
    attrs["target"] = policy.target
    handler.startElement("policy", attrs)
    handler.ignorableWhitespace("\n")

    # short
    if policy.short and policy.short != "":
        handler.ignorableWhitespace("  ")
        handler.startElement("short", { })
        handler.characters(policy.short)
        handler.endElement("short")
        handler.ignorableWhitespace("\n")

    # description
    if policy.description and policy.description != "":
        handler.ignorableWhitespace("  ")
        handler.startElement("description", { })
        handler.characters(policy.description)
        handler.endElement("description")
        handler.ignorableWhitespace("\n")

    # services
    for service in uniqify(policy.services):
        handler.ignorableWhitespace("  ")
        handler.simpleElement("service", { "name": service })
        handler.ignorableWhitespace("\n")

    # ingress-zones
    for zone in uniqify(policy.ingress_zones):
        handler.ignorableWhitespace("  ")
        handler.simpleElement("ingress-zone", { "name": zone })
        handler.ignorableWhitespace("\n")

    # egress-zones
    for zone in uniqify(policy.ingress_zones):
        handler.ignorableWhitespace("  ")
        handler.simpleElement("egress-zone", { "name": zone })
        handler.ignorableWhitespace("\n")

    # ports
    for port in uniqify(policy.ports):
        handler.ignorableWhitespace("  ")
        handler.simpleElement("port", { "port": port[0], "protocol": port[1] })
        handler.ignorableWhitespace("\n")

    # protocols
    for protocol in uniqify(policy.protocols):
        handler.ignorableWhitespace("  ")
        handler.simpleElement("protocol", { "value": protocol })
        handler.ignorableWhitespace("\n")

    # icmp-blocks
    for icmp in uniqify(policy.icmp_blocks):
        handler.ignorableWhitespace("  ")
        handler.simpleElement("icmp-block", { "name": icmp })
        handler.ignorableWhitespace("\n")

    # masquerade
    if policy.masquerade:
        handler.ignorableWhitespace("  ")
        handler.simpleElement("masquerade", { })
        handler.ignorableWhitespace("\n")

    # forward-ports
    for forward in uniqify(policy.forward_ports):
        handler.ignorableWhitespace("  ")
        attrs = { "port": forward[0], "protocol": forward[1] }
        if forward[2] and forward[2] != "" :
            attrs["to-port"] = forward[2]
        if forward[3] and forward[3] != "" :
            attrs["to-addr"] = forward[3]
        handler.simpleElement("forward-port", attrs)
        handler.ignorableWhitespace("\n")

    # source-ports
    for port in uniqify(policy.source_ports):
        handler.ignorableWhitespace("  ")
        handler.simpleElement("source-port", { "port": port[0],
                                               "protocol": port[1] })
        handler.ignorableWhitespace("\n")

    # rules
    for rule in policy.rules:
        attrs = { }
        if rule.family:
            attrs["family"] = rule.family
        if rule.priority != 0:
            attrs["priority"] = str(rule.priority)
        handler.ignorableWhitespace("  ")
        handler.startElement("rule", attrs)
        handler.ignorableWhitespace("\n")

        # source
        if rule.source:
            attrs = { }
            if rule.source.addr:
                attrs["address"] = rule.source.addr
            if rule.source.mac:
                attrs["mac"] = rule.source.mac
            if rule.source.ipset:
                attrs["ipset"] = rule.source.ipset
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

            if type(rule.element) == rich.Rich_Service:
                element = "service"
                attrs["name"] = rule.element.name
            elif type(rule.element) == rich.Rich_Port:
                element = "port"
                attrs["port"] = rule.element.port
                attrs["protocol"] = rule.element.protocol
            elif type(rule.element) == rich.Rich_Protocol:
                element = "protocol"
                attrs["value"] = rule.element.value
            elif type(rule.element) == rich.Rich_Masquerade:
                element = "masquerade"
            elif type(rule.element) == rich.Rich_IcmpBlock:
                element = "icmp-block"
                attrs["name"] = rule.element.name
            elif type(rule.element) == rich.Rich_IcmpType:
                element = "icmp-type"
                attrs["name"] = rule.element.name
            elif type(rule.element) == rich.Rich_ForwardPort:
                element = "forward-port"
                attrs["port"] = rule.element.port
                attrs["protocol"] = rule.element.protocol
                if rule.element.to_port != "":
                    attrs["to-port"] = rule.element.to_port
                if rule.element.to_address != "":
                    attrs["to-addr"] = rule.element.to_address
            elif type(rule.element) == rich.Rich_SourcePort:
                element = "source-port"
                attrs["port"] = rule.element.port
                attrs["protocol"] = rule.element.protocol
            else:
                raise FirewallError(
                    errors.INVALID_OBJECT,
                    "Unknown element '%s' in policy_writer" % type(rule.element))

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
            attrs = {}
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
            if type(rule.action) == rich.Rich_Accept:
                action = "accept"
            elif type(rule.action) == rich.Rich_Reject:
                action = "reject"
                if rule.action.type:
                    attrs["type"] = rule.action.type
            elif type(rule.action) == rich.Rich_Drop:
                action = "drop"
            elif type(rule.action) == rich.Rich_Mark:
                action = "mark"
                attrs["set"] = rule.action.set
            else:
                log.warning("Unknown action '%s'", type(rule.action))
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

    # end policy element
    handler.endElement("policy")
    handler.ignorableWhitespace("\n")
    handler.endDocument()
    f.close()
    del handler
