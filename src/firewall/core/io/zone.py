# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2011-2016 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>

import xml.sax as sax
import os
import io
import shutil
import dataclasses

from firewall import config
from firewall.functions import (
    checkIPnMask,
    checkIP6nMask,
    checkInterface,
    uniqify,
    max_zone_name_len,
    check_mac,
)
from firewall.core.base import DEFAULT_ZONE_TARGET, ZONE_TARGETS, DEFAULT_ZONE_PRIORITY
from firewall.core.io.io_object import (
    IO_Object,
    IO_Object_ContentHandler,
    IO_Object_XMLGenerator,
)
from firewall.core.io.policy import (
    common_startElement,
    common_endElement,
    common_check_config,
    common_writer,
)
from firewall.core import rich
from firewall.core.logger import log
from firewall import errors
from firewall.errors import FirewallError


class Zone(IO_Object):
    """Zone class"""

    priority_min = -32768
    priority_max = 32767
    priority_default = DEFAULT_ZONE_PRIORITY

    IMPORT_EXPORT_STRUCTURE = {
        "version": "",  # s
        "short": "",  # s
        "description": "",  # s
        "UNUSED": False,  # b
        "target": "",  # s
        "services": [""],  # as
        "ports": [("", "")],  # a(ss)
        "icmp_blocks": [""],  # as
        "masquerade": False,  # b
        "forward_ports": [("", "", "", "")],  # a(ssss)
        "interfaces": [""],  # as
        "sources": [""],  # as
        "rules_str": [""],  # as
        "protocols": [""],  # as
        "source_ports": [("", "")],  # a(ss)
        "icmp_block_inversion": False,  # b
        "forward": True,  # b
        "ingress_priority": 0,  # i
        "egress_priority": 0,  # i
    }
    ADDITIONAL_ALNUM_CHARS = ["_", "-", "/"]
    PARSER_REQUIRED_ELEMENT_ATTRS = {
        "short": None,
        "description": None,
        "zone": None,
        "service": ["name"],
        "port": ["port", "protocol"],
        "icmp-block": ["name"],
        "icmp-type": ["name"],
        "forward": None,
        "forward-port": ["port", "protocol"],
        "interface": ["name"],
        "rule": None,
        "source": None,
        "destination": None,
        "protocol": ["value"],
        "source-port": ["port", "protocol"],
        "log": None,
        "nflog": None,
        "audit": None,
        "accept": None,
        "reject": None,
        "drop": None,
        "mark": ["set"],
        "limit": ["value"],
        "icmp-block-inversion": None,
    }
    PARSER_OPTIONAL_ELEMENT_ATTRS = {
        "zone": [
            "name",
            "immutable",
            "target",
            "version",
            "ingress-priority",
            "egress-priority",
        ],
        "masquerade": ["enabled"],
        "forward-port": ["to-port", "to-addr"],
        "rule": ["family", "priority"],
        "source": ["address", "mac", "invert", "family", "ipset"],
        "destination": ["address", "invert", "ipset"],
        "log": ["prefix", "level"],
        "nflog": ["group", "prefix", "queue-size"],
        "reject": ["type"],
        "limit": ["burst"],
        "tcp-mss-clamp": ["value"],
    }

    @staticmethod
    def index_of(element):
        for i, el in enumerate(Zone.IMPORT_EXPORT_STRUCTURE):
            if el == element:
                return i
        raise FirewallError(errors.UNKNOWN_ERROR, "index_of()")

    def __init__(self):
        super(Zone, self).__init__()
        self.version = ""
        self.short = ""
        self.description = ""
        self.UNUSED = False
        self.target = DEFAULT_ZONE_TARGET
        self.services = []
        self.ports = []
        self.protocols = []
        self.icmp_blocks = []
        self.forward = True
        self.masquerade = False
        self.forward_ports = []
        self.source_ports = []
        self.interfaces = []
        self.sources = []
        self.rules = set()
        self.icmp_block_inversion = False
        self.combined = False
        self.applied = False
        self.ingress_priority = self.priority_default
        self.egress_priority = self.priority_default

    def cleanup(self):
        self.version = ""
        self.short = ""
        self.description = ""
        self.UNUSED = False
        self.target = DEFAULT_ZONE_TARGET
        del self.services[:]
        del self.ports[:]
        del self.protocols[:]
        del self.icmp_blocks[:]
        self.forward = True
        self.masquerade = False
        del self.forward_ports[:]
        del self.source_ports[:]
        del self.interfaces[:]
        del self.sources[:]
        self.rules.clear()
        self.icmp_block_inversion = False
        self.combined = False
        self.applied = False
        self.ingress_priority = self.priority_default
        self.egress_priority = self.priority_default

    def __getattr__(self, name):
        if name == "rules_str":
            return [str(r) for r in sorted(self.rules)]
        else:
            return getattr(super(Zone, self), name)

    def __setattr__(self, name, value):
        if name == "rules_str":
            self.rules = set([rich.Rich_Rule(rule_str=s) for s in value])
        else:
            super(Zone, self).__setattr__(name, value)

    def export_config_dict(self):
        conf = super(Zone, self).export_config_dict()
        del conf["UNUSED"]
        return conf

    def _check_config(self, config, item, all_config, all_io_objects):
        common_check_config(self, config, item, all_config, all_io_objects)

        if self.name in all_io_objects["policies"]:
            raise FirewallError(
                errors.NAME_CONFLICT,
                "Zone '{}': Can't have the same name as a policy.".format(self.name),
            )

        if item == "target":
            if config not in ZONE_TARGETS:
                raise FirewallError(
                    errors.INVALID_TARGET,
                    "Zone '{}': invalid target '{}'".format(self.name, config),
                )
        elif item == "interfaces":
            for interface in config:
                if not checkInterface(interface):
                    raise FirewallError(
                        errors.INVALID_INTERFACE,
                        "Zone '{}': invalid interface '{}'".format(
                            self.name, interface
                        ),
                    )
                for zone in all_io_objects["zones"]:
                    if zone == self.name:
                        continue
                    if interface in all_io_objects["zones"][zone].interfaces:
                        raise FirewallError(
                            errors.INVALID_INTERFACE,
                            "Zone '{}': interface '{}' already bound to zone '{}'".format(
                                self.name, interface, zone
                            ),
                        )
        elif item == "sources":
            for source in config:
                if (
                    not checkIPnMask(source)
                    and not checkIP6nMask(source)
                    and not check_mac(source)
                    and not source.startswith("ipset:")
                ):
                    raise FirewallError(
                        errors.INVALID_ADDR,
                        "Zone '{}': invalid source '{}'".format(self.name, source),
                    )
                for zone in all_io_objects["zones"]:
                    if zone == self.name:
                        continue
                    if source in all_io_objects["zones"][zone].sources:
                        raise FirewallError(
                            errors.INVALID_ADDR,
                            "Zone '{}': source '{}' already bound to zone '{}'".format(
                                self.name, source, zone
                            ),
                        )
        elif item in ["ingress_priority", "egress_priority"]:
            if config > self.priority_max or config < self.priority_min:
                raise FirewallError(
                    errors.INVALID_PRIORITY,
                    f"Zone '{self.name}': {config} is an invalid priority value. "
                    f"Must be in range [{self.priority_min}, {self.priority_max}].",
                )

    def check_name(self, name):
        super(Zone, self).check_name(name)
        if name.startswith("/"):
            raise FirewallError(
                errors.INVALID_NAME, "Zone '{}': name can't start with '/'".format(name)
            )
        elif name.endswith("/"):
            raise FirewallError(
                errors.INVALID_NAME, "Zone '{}': name can't end with '/'".format(name)
            )
        elif name.count("/") > 1:
            raise FirewallError(
                errors.INVALID_NAME,
                "Zone '{}': name has more than one '/'".format(name),
            )
        else:
            if "/" in name:
                checked_name = name[: name.find("/")]
            else:
                checked_name = name
            if len(checked_name) > max_zone_name_len():
                raise FirewallError(
                    errors.INVALID_NAME,
                    "Zone '{}': name has {} chars, max is {}".format(
                        name, len(checked_name), max_zone_name_len()
                    ),
                )

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
        for proto in zone.protocols:
            if proto not in self.protocols:
                self.protocols.append(proto)
        for icmp in zone.icmp_blocks:
            if icmp not in self.icmp_blocks:
                self.icmp_blocks.append(icmp)
        if zone.forward:
            self.forward = True
        if zone.masquerade:
            self.masquerade = True
        for forward in zone.forward_ports:
            if forward not in self.forward_ports:
                self.forward_ports.append(forward)
        for port in zone.source_ports:
            if port not in self.source_ports:
                self.source_ports.append(port)
        for rule in zone.rules:
            self.rules.add(rule)
        if zone.icmp_block_inversion:
            self.icmp_block_inversion = True


# PARSER


class zone_ContentHandler(IO_Object_ContentHandler):
    def __init__(self, item):
        IO_Object_ContentHandler.__init__(self, item)
        self._rule = None
        self._limit_ok = None

    def startElement(self, name, attrs):
        IO_Object_ContentHandler.startElement(self, name, attrs)

        self.item.parser_check_element_attrs(name, attrs)

        if common_startElement(self, name, attrs):
            return

        elif name == "zone":
            if "name" in attrs:
                log.warning("Ignoring deprecated attribute name='%s'", attrs["name"])
            if "version" in attrs:
                self.item.version = attrs["version"]
            if "immutable" in attrs:
                log.warning(
                    "Ignoring deprecated attribute immutable='%s'", attrs["immutable"]
                )
            if "target" in attrs:
                target = attrs["target"]
                if target not in ZONE_TARGETS:
                    raise FirewallError(errors.INVALID_TARGET, target)
                if target != "" and target != DEFAULT_ZONE_TARGET:
                    self.item.target = target
            if "ingress-priority" in attrs:
                self.item.ingress_priority = int(attrs["ingress-priority"])
            if "egress-priority" in attrs:
                self.item.egress_priority = int(attrs["egress-priority"])

        elif name == "forward":
            self.item.forward = True

        elif name == "interface":
            if self._rule:
                raise FirewallError(
                    errors.INVALID_RULE,
                    f"Interface is not valid in rule '{str(self._rule)}'.",
                )
            if attrs["name"] not in self.item.interfaces:
                self.item.interfaces.append(attrs["name"])

        elif name == "source":
            if self._rule:
                if self._rule.source:
                    raise FirewallError(
                        errors.INVALID_RULE,
                        f"More than one source in rule '{str(self._rule)}'.",
                    )
                invert = False
                if "invert" in attrs and attrs["invert"].lower() in ["yes", "true"]:
                    invert = True
                addr = mac = ipset = None
                if "address" in attrs:
                    addr = attrs["address"]
                if "mac" in attrs:
                    mac = attrs["mac"]
                if "ipset" in attrs:
                    ipset = attrs["ipset"]
                self._rule = dataclasses.replace(
                    self._rule, source=rich.Rich_Source(addr, mac, ipset, invert=invert)
                )
                return
            # zone bound to source
            if "address" not in attrs and "ipset" not in attrs:
                raise FirewallError(
                    errors.INVALID_SOURCE, "No address or ipset specified."
                )
            if "address" in attrs and "ipset" in attrs:
                raise FirewallError(
                    errors.INVALID_SOURCE, "Both address and ipset (can only use one)."
                )
            if "family" in attrs:
                log.warning(
                    "Ignoring deprecated attribute family='%s'", attrs["family"]
                )
            if "invert" in attrs:
                raise FirewallError(errors.INVALID_SOURCE, "Invert not allowed.")
                return
            if "address" in attrs:
                if (
                    not checkIPnMask(attrs["address"])
                    and not checkIP6nMask(attrs["address"])
                    and not check_mac(attrs["address"])
                ):
                    raise FirewallError(errors.INVALID_ADDR, attrs["address"])
            if "ipset" in attrs:
                entry = "ipset:%s" % attrs["ipset"]
                if entry not in self.item.sources:
                    self.item.sources.append(entry)
            if "address" in attrs:
                entry = attrs["address"]
                if entry not in self.item.sources:
                    self.item.sources.append(entry)

        elif name == "icmp-block-inversion":
            self.item.icmp_block_inversion = True

        else:
            raise FirewallError(errors.INVALID_ZONE, f"Unknown XML element '{name}'.")
            return

    def endElement(self, name):
        IO_Object_ContentHandler.endElement(self, name)

        common_endElement(self, name)


def zone_reader(filename, path, no_check_name=False):
    zone = Zone()
    if not filename.endswith(".xml"):
        raise FirewallError(
            errors.INVALID_NAME, "'%s' is missing .xml suffix" % filename
        )
    zone.name = filename[:-4]
    if not no_check_name:
        zone.check_name(zone.name)
    zone.filename = filename
    zone.path = path
    zone.builtin = False if path.startswith(config.ETC_FIREWALLD) else True
    zone.default = zone.builtin
    # new Zone() objects default this to True, but if reading on disk
    # configuration we have to assume False, because the absence of
    # <forward> element indicates False. Presence indicates True.
    zone.forward = False
    handler = zone_ContentHandler(zone)
    parser = sax.make_parser()
    parser.setContentHandler(handler)
    name = "%s/%s" % (path, filename)
    with open(name, "rb") as f:
        source = sax.InputSource(None)
        source.setByteStream(f)
        try:
            parser.parse(source)
        except sax.SAXParseException as msg:
            raise FirewallError(
                errors.INVALID_ZONE, "not a valid zone file: %s" % msg.getException()
            )
    del handler
    del parser
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
        except Exception as msg:
            log.error("Backup of file '%s' failed: %s", name, msg)

    dirpath = os.path.dirname(name)
    if dirpath.startswith(config.ETC_FIREWALLD) and not os.path.exists(dirpath):
        if not os.path.exists(config.ETC_FIREWALLD):
            os.mkdir(config.ETC_FIREWALLD, 0o750)
        os.mkdir(dirpath, 0o750)

    f = io.open(name, mode="wt", encoding="UTF-8")
    handler = IO_Object_XMLGenerator(f)
    handler.startDocument()

    # start zone element
    attrs = {}
    if zone.version and zone.version != "":
        attrs["version"] = zone.version
    if zone.target != DEFAULT_ZONE_TARGET:
        attrs["target"] = zone.target
    if zone.ingress_priority != zone.priority_default:
        attrs["ingress-priority"] = str(zone.ingress_priority)
    if zone.egress_priority != zone.priority_default:
        attrs["egress-priority"] = str(zone.egress_priority)
    handler.startElement("zone", attrs)
    handler.ignorableWhitespace("\n")

    common_writer(zone, handler)

    # interfaces
    for interface in uniqify(zone.interfaces):
        handler.ignorableWhitespace("  ")
        handler.simpleElement("interface", {"name": interface})
        handler.ignorableWhitespace("\n")

    # source
    for source in uniqify(zone.sources):
        handler.ignorableWhitespace("  ")
        if "ipset:" in source:
            handler.simpleElement("source", {"ipset": source[6:]})
        else:
            handler.simpleElement("source", {"address": source})
        handler.ignorableWhitespace("\n")

    # icmp-block-inversion
    if zone.icmp_block_inversion:
        handler.ignorableWhitespace("  ")
        handler.simpleElement("icmp-block-inversion", {})
        handler.ignorableWhitespace("\n")

    # forward
    if zone.forward:
        handler.ignorableWhitespace("  ")
        handler.simpleElement("forward", {})
        handler.ignorableWhitespace("\n")

    # end zone element
    handler.endElement("zone")
    handler.ignorableWhitespace("\n")
    handler.endDocument()
    f.close()
    del handler
