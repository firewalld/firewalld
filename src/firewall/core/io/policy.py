#
# SPDX-License-Identifier: GPL-2.0-or-later

import xml.sax as sax
import os
import io
import shutil
import dataclasses

from firewall import config
from firewall.functions import (
    checkIP,
    checkIP6,
    coalescePortRange,
    max_policy_name_len,
    portInPortRange,
    portStr,
    uniqify,
)
from firewall.core.base import (
    DEFAULT_POLICY_TARGET,
    POLICY_TARGETS,
    DEFAULT_POLICY_PRIORITY,
)
from firewall.core.io.io_object import (
    IO_Object,
    IO_Object_ContentHandler,
    IO_Object_XMLGenerator,
    check_port,
    check_tcpudp,
    check_protocol,
)
from firewall.core import rich
from firewall.core.logger import log
from firewall import errors
from firewall.errors import FirewallError


def common_startElement(obj, name, attrs):
    if name == "short":
        pass
    elif name == "description":
        pass

    elif name == "service":
        if obj._rule:
            if obj._rule.element:
                raise FirewallError(
                    errors.INVALID_RULE,
                    f"More than one element in rule '{str(obj._rule)}'.",
                )
            obj._rule = dataclasses.replace(
                obj._rule, element=rich.Rich_Service(attrs["name"])
            )
            return True
        if attrs["name"] not in obj.item.services:
            obj.item.services.append(attrs["name"])

    elif name == "port":
        if obj._rule:
            if obj._rule.element:
                raise FirewallError(
                    errors.INVALID_RULE,
                    f"More than one element in rule '{str(obj._rule)}'.",
                )
            obj._rule = dataclasses.replace(
                obj._rule, element=rich.Rich_Port(attrs["port"], attrs["protocol"])
            )
            return True
        check_port(attrs["port"])
        check_tcpudp(attrs["protocol"])

        # coalesce and warn about overlapping ranges
        new_port_id = (portStr(attrs["port"], "-"), attrs["protocol"])
        existing_port_ids = list(
            filter(lambda x: x[1] == attrs["protocol"], obj.item.ports)
        )
        for port_id in existing_port_ids:
            if portInPortRange(new_port_id[0], port_id[0]):
                # the range is wholly contained already; ignore
                break  # for
        else:
            # the range can be coalesced into the existing set
            added_ranges, removed_ranges = coalescePortRange(
                new_port_id[0], [_port for (_port, _protocol) in existing_port_ids]
            )

            for _range in removed_ranges:
                entry = (portStr(_range, "-"), attrs["protocol"])
                obj.item.ports.remove(entry)
            for _range in added_ranges:
                entry = (portStr(_range, "-"), attrs["protocol"])
                obj.item.ports.append(entry)

    elif name == "protocol":
        if obj._rule:
            if obj._rule.element:
                raise FirewallError(
                    errors.INVALID_RULE,
                    f"More than one element in rule '{str(obj._rule)}'.",
                )
            obj._rule = dataclasses.replace(
                obj._rule, element=rich.Rich_Protocol(attrs["value"])
            )
        else:
            check_protocol(attrs["value"])
            if attrs["value"] not in obj.item.protocols:
                obj.item.protocols.append(attrs["value"])

    elif name == "tcp-mss-clamp":
        if obj._rule:
            if obj._rule.element:
                raise FirewallError(
                    errors.INVALID_RULE,
                    f"More than one element in rule '{str(obj._rule)}'.",
                )
            _value = "pmtu"
            if "value" in attrs and attrs["value"] not in [None, "None"]:
                _value = attrs["value"]
            obj._rule = dataclasses.replace(
                obj._rule, element=rich.Rich_Tcp_Mss_Clamp(_value)
            )
        else:
            raise FirewallError(errors.INVALID_RULE, "tcp-mss-clamp outside of rule.")

    elif name == "icmp-block":
        if obj._rule:
            if obj._rule.element:
                raise FirewallError(
                    errors.INVALID_RULE,
                    f"More than one element in rule '{str(obj._rule)}'.",
                )
            obj._rule = dataclasses.replace(
                obj._rule, element=rich.Rich_IcmpBlock(attrs["name"])
            )
            return True
        if attrs["name"] not in obj.item.icmp_blocks:
            obj.item.icmp_blocks.append(attrs["name"])

    elif name == "icmp-type":
        if obj._rule:
            if obj._rule.element:
                raise FirewallError(
                    errors.INVALID_RULE,
                    f"More than one element in rule '{str(obj._rule)}'.",
                )
            obj._rule = dataclasses.replace(
                obj._rule, element=rich.Rich_IcmpType(attrs["name"])
            )
            return True
        else:
            raise FirewallError(errors.INVALID_RULE, "icmp-block outside of rule.")

    elif name == "masquerade":
        if obj._rule:
            if obj._rule.element:
                raise FirewallError(
                    errors.INVALID_RULE,
                    f"More than one element in rule '{str(obj._rule)}'.",
                )
            obj._rule = dataclasses.replace(obj._rule, element=rich.Rich_Masquerade())
        else:
            obj.item.masquerade = True

    elif name == "forward-port":
        to_port = ""
        if "to-port" in attrs:
            to_port = attrs["to-port"]
        to_addr = ""
        if "to-addr" in attrs:
            to_addr = attrs["to-addr"]

        if obj._rule:
            if obj._rule.element:
                raise FirewallError(
                    errors.INVALID_RULE,
                    f"More than one element in rule '{str(obj._rule)}'.",
                )
            obj._rule = dataclasses.replace(
                obj._rule,
                element=rich.Rich_ForwardPort(
                    attrs["port"], attrs["protocol"], to_port, to_addr
                ),
            )
            return True

        check_port(attrs["port"])
        check_tcpudp(attrs["protocol"])
        if to_port:
            check_port(to_port)
        if to_addr:
            if not checkIP(to_addr) and not checkIP6(to_addr):
                raise FirewallError(
                    errors.INVALID_ADDR, "to-addr '%s' is not a valid address" % to_addr
                )
        entry = (
            portStr(attrs["port"], "-"),
            attrs["protocol"],
            portStr(to_port, "-"),
            str(to_addr),
        )
        if entry not in obj.item.forward_ports:
            obj.item.forward_ports.append(entry)

    elif name == "source-port":
        if obj._rule:
            if obj._rule.element:
                raise FirewallError(
                    errors.INVALID_RULE,
                    f"More than one element in rule '{str(obj._rule)}'.",
                )
            obj._rule = dataclasses.replace(
                obj._rule,
                element=rich.Rich_SourcePort(attrs["port"], attrs["protocol"]),
            )
            return True
        check_port(attrs["port"])
        check_tcpudp(attrs["protocol"])

        # coalesce and warn about overlapping ranges
        new_port_id = (portStr(attrs["port"], "-"), attrs["protocol"])
        existing_port_ids = list(
            filter(lambda x: x[1] == attrs["protocol"], obj.item.source_ports)
        )
        for port_id in existing_port_ids:
            if portInPortRange(new_port_id[0], port_id[0]):
                # the range is wholly contained already; ignore
                break  # for
        else:
            # the range can be coalesced into the existing set
            added_ranges, removed_ranges = coalescePortRange(
                new_port_id[0], [_port for (_port, _protocol) in existing_port_ids]
            )

            for _range in removed_ranges:
                entry = (portStr(_range, "-"), attrs["protocol"])
                obj.item.source_ports.remove(entry)
            for _range in added_ranges:
                entry = (portStr(_range, "-"), attrs["protocol"])
                obj.item.source_ports.append(entry)

    elif name == "destination":
        if not obj._rule:
            raise FirewallError(
                errors.INVALID_RULE, "Destination outside of rich rule."
            )
        if obj._rule.destination:
            raise FirewallError(
                errors.INVALID_RULE,
                f"More than one destination in rule '{str(obj._rule)}'.",
            )
        invert = False
        address = None
        if "address" in attrs:
            address = attrs["address"]
        ipset = None
        if "ipset" in attrs:
            ipset = attrs["ipset"]
        if "invert" in attrs and attrs["invert"].lower() in ["yes", "true"]:
            invert = True
        obj._rule = dataclasses.replace(
            obj._rule, destination=rich.Rich_Destination(address, ipset, invert)
        )

    elif name in ["accept", "reject", "drop", "mark"]:
        if not obj._rule:
            raise FirewallError(errors.INVALID_RULE, "Action outside of rich rule.")
        if obj._rule.action:
            raise FirewallError(
                errors.INVALID_RULE, f"More than one action in rule '{str(obj._rule)}'."
            )
        if name == "accept":
            obj._rule = dataclasses.replace(obj._rule, action=rich.Rich_Accept())
        elif name == "reject":
            _type = None
            if "type" in attrs:
                _type = attrs["type"]
            obj._rule = dataclasses.replace(obj._rule, action=rich.Rich_Reject(_type))
        elif name == "drop":
            obj._rule = dataclasses.replace(obj._rule, action=rich.Rich_Drop())
        elif name == "mark":
            _set = attrs["set"]
            obj._rule = dataclasses.replace(obj._rule, action=rich.Rich_Mark(_set))
        obj._limit_ok = obj._rule.action

    elif name == "log":
        if not obj._rule:
            raise FirewallError(errors.INVALID_RULE, "Log outside of rich rule.")
        if obj._rule.log:
            raise FirewallError(
                errors.INVALID_RULE, f"More than one log in rule '{str(obj._rule)}'."
            )
        level = None
        if "level" in attrs:
            level = attrs["level"]
        prefix = None
        if "prefix" in attrs:
            prefix = attrs["prefix"]
        obj._rule = dataclasses.replace(obj._rule, log=rich.Rich_Log(prefix, level))
        obj._limit_ok = obj._rule.log

    elif name == "nflog":
        if not obj._rule:
            raise FirewallError(errors.INVALID_RULE, "Log outside of rule.")
        if obj._rule.log:
            raise FirewallError(
                errors.INVALID_RULE, f"More than one log in rule '{str(obj._rule)}'."
            )
        group = None
        if "group" in attrs:
            group = attrs["group"]
        prefix = None
        if "prefix" in attrs:
            prefix = attrs["prefix"]
        threshold = None
        if "queue-size" in attrs:
            threshold = attrs["queue-size"]
        obj._rule = dataclasses.replace(
            obj._rule, log=rich.Rich_NFLog(group, prefix, threshold)
        )
        obj._limit_ok = obj._rule.log

    elif name == "audit":
        if not obj._rule:
            raise FirewallError(errors.INVALID_RULE, "Audit outside of rule.")
        if obj._rule.audit:
            raise FirewallError(
                errors.INVALID_RULE, f"More than one audit in rule '{str(obj._rule)}'."
            )
        obj._rule = dataclasses.replace(obj._rule, audit=rich.Rich_Audit())
        obj._limit_ok = obj._rule.audit

    elif name == "rule":
        family = None
        priority = 0
        if "family" in attrs:
            family = attrs["family"]
        if "priority" in attrs:
            priority = int(attrs["priority"])
        obj._rule = rich.Rich_Rule(family=family, priority=priority)

    elif name == "limit":
        if not obj._limit_ok:
            raise FirewallError(
                errors.INVALID_RULE, "Limit outside of action, log and audit."
            )
        if obj._limit_ok.limit:
            raise FirewallError(
                errors.INVALID_RULE, f"More than one limit in rule '{str(obj._rule)}'."
            )
        value = attrs["value"]
        obj._limit_ok = dataclasses.replace(
            obj._limit_ok, limit=rich.Rich_Limit(value, attrs.get("burst"))
        )
        if isinstance(obj._limit_ok, rich.Rich_Audit):
            obj._rule = dataclasses.replace(obj._rule, audit=obj._limit_ok)
        elif isinstance(obj._limit_ok, (rich.Rich_Log, rich.Rich_NFLog)):
            obj._rule = dataclasses.replace(obj._rule, log=obj._limit_ok)
        elif isinstance(
            obj._limit_ok,
            (rich.Rich_Accept, rich.Rich_Reject, rich.Rich_Drop, rich.Rich_Mark),
        ):
            obj._rule = dataclasses.replace(obj._rule, action=obj._limit_ok)
    else:
        return False

    return True


def common_endElement(obj, name):
    if name == "rule":
        obj._rule.check()
        obj.item.rules.add(obj._rule)
        obj._rule = None
    elif name in ["accept", "reject", "drop", "mark", "log", "audit"]:
        obj._limit_ok = None


def common_check_config(obj, config, item, all_config, all_io_objects):
    obj_type = "Policy" if isinstance(obj, Policy) else "Zone"

    if item == "services" and "services" in all_io_objects:
        existing_services = all_io_objects["services"]
        for service in config:
            if service not in existing_services:
                raise FirewallError(
                    errors.INVALID_SERVICE,
                    "{} '{}': '{}' not among existing services".format(
                        obj_type, obj.name, service
                    ),
                )
    elif item == "ports":
        for port in config:
            check_port(port[0])
            check_tcpudp(port[1])
    elif item == "protocols":
        for proto in config:
            check_protocol(proto)
    elif item == "icmp_blocks" and "icmptypes" in all_io_objects:
        existing_icmptypes = all_io_objects["icmptypes"]
        for icmptype in config:
            if icmptype not in existing_icmptypes:
                ex = FirewallError(
                    errors.INVALID_ICMPTYPE,
                    "{} '{}': '{}' not among existing ICMP types".format(
                        obj_type, obj.name, icmptype
                    ),
                )
                if icmptype in all_io_objects.get("runtime", {}).get(
                    "icmptypes_unsupported", {}
                ):
                    log.debug1("{} (unsupported)".format(ex))
                else:
                    raise ex

    elif item == "forward_ports":
        for fwd_port in config:
            check_port(fwd_port[0])
            check_tcpudp(fwd_port[1])
            if not fwd_port[2] and not fwd_port[3]:
                raise FirewallError(
                    errors.INVALID_FORWARD,
                    "{} '{}': '{}' is missing to-port AND to-addr ".format(
                        obj_type, obj.name, fwd_port
                    ),
                )
            if fwd_port[2]:
                check_port(fwd_port[2])
            if fwd_port[3]:
                if not checkIP(fwd_port[3]) and not checkIP6(fwd_port[3]):
                    raise FirewallError(
                        errors.INVALID_ADDR,
                        "{} '{}': to-addr '{}' is not a valid address".format(
                            obj_type, obj.name, fwd_port[3]
                        ),
                    )
    elif item == "source_ports":
        for port in config:
            check_port(port[0])
            check_tcpudp(port[1])
    elif item in ["rules_str", "rich_rules"]:
        for rule in config:
            obj_rich = rich.Rich_Rule(rule_str=rule)
            if (
                obj_rich.element
                and "icmptypes" in all_io_objects
                and (
                    isinstance(obj_rich.element, rich.Rich_IcmpBlock)
                    or isinstance(obj_rich.element, rich.Rich_IcmpType)
                )
            ):
                existing_icmptypes = all_io_objects["icmptypes"]
                if obj_rich.element.name not in existing_icmptypes:
                    ex = FirewallError(
                        errors.INVALID_ICMPTYPE,
                        "{} '{}': '{}' not among existing ICMP types".format(
                            obj_type, obj.name, obj_rich.element.name
                        ),
                    )
                    if obj_rich.element.name in all_io_objects.get("runtime", {}).get(
                        "icmptypes_unsupported", {}
                    ):
                        log.debug1("{} (unsupported)".format(ex))
                    else:
                        raise ex
                elif obj_rich.family:
                    ict = all_io_objects["icmptypes"][obj_rich.element.name]
                    if ict.destination and obj_rich.family not in ict.destination:
                        ex = FirewallError(
                            errors.INVALID_ICMPTYPE,
                            "{} '{}': rich rule family '{}' conflicts with icmp type '{}'".format(
                                obj_type,
                                obj.name,
                                obj_rich.family,
                                obj_rich.element.name,
                            ),
                        )
                        ict_unsupported = (
                            all_io_objects.get("runtime", {})
                            .get("icmptypes_unsupported", {})
                            .get(obj_rich.element.name)
                        )
                        if (
                            ict_unsupported
                            and ict_unsupported.destination
                            and obj_rich.family in ict_unsupported.destination
                        ):
                            log.debug1("{} (unsupported)".format(ex))
                        else:
                            raise ex
            elif isinstance(obj_rich.element, rich.Rich_Service):
                if obj_rich.element.name not in all_io_objects["services"]:
                    raise FirewallError(
                        errors.INVALID_SERVICE,
                        "{} '{}': '{}' not among existing services".format(
                            obj_type, obj.name, obj_rich.element.name
                        ),
                    )
            elif obj_rich.source and obj_rich.source.ipset:
                if obj_rich.source.ipset not in all_io_objects["ipsets"]:
                    raise FirewallError(
                        errors.INVALID_IPSET,
                        "{} '{}': '{}' not among existing ipsets".format(
                            obj_type, obj.name, obj_rich.source.ipset
                        ),
                    )
            elif obj_rich.destination and obj_rich.destination.ipset:
                if obj_rich.destination.ipset not in all_io_objects["ipsets"]:
                    raise FirewallError(
                        errors.INVALID_IPSET,
                        "{} '{}': '{}' not among existing ipsets".format(
                            obj_type, obj.name, obj_rich.destination.ipset
                        ),
                    )


def _handler_add_rich_limit(handler, limit):
    d = {"value": limit.value}
    burst = limit.burst
    if burst is not None:
        d["burst"] = str(burst)
    handler.simpleElement("limit", d)


def common_writer(obj, handler):
    # short
    if obj.short and obj.short != "":
        handler.ignorableWhitespace("  ")
        handler.startElement("short", {})
        handler.characters(obj.short)
        handler.endElement("short")
        handler.ignorableWhitespace("\n")

    # description
    if obj.description and obj.description != "":
        handler.ignorableWhitespace("  ")
        handler.startElement("description", {})
        handler.characters(obj.description)
        handler.endElement("description")
        handler.ignorableWhitespace("\n")

    # services
    for service in uniqify(obj.services):
        handler.ignorableWhitespace("  ")
        handler.simpleElement("service", {"name": service})
        handler.ignorableWhitespace("\n")

    # ports
    for port in uniqify(obj.ports):
        handler.ignorableWhitespace("  ")
        handler.simpleElement("port", {"port": port[0], "protocol": port[1]})
        handler.ignorableWhitespace("\n")

    # protocols
    for protocol in uniqify(obj.protocols):
        handler.ignorableWhitespace("  ")
        handler.simpleElement("protocol", {"value": protocol})
        handler.ignorableWhitespace("\n")

    # icmp-blocks
    for icmp in uniqify(obj.icmp_blocks):
        handler.ignorableWhitespace("  ")
        handler.simpleElement("icmp-block", {"name": icmp})
        handler.ignorableWhitespace("\n")

    # masquerade
    if obj.masquerade:
        handler.ignorableWhitespace("  ")
        handler.simpleElement("masquerade", {})
        handler.ignorableWhitespace("\n")

    # forward-ports
    for forward in uniqify(obj.forward_ports):
        handler.ignorableWhitespace("  ")
        attrs = {"port": forward[0], "protocol": forward[1]}
        if forward[2] and forward[2] != "":
            attrs["to-port"] = forward[2]
        if forward[3] and forward[3] != "":
            attrs["to-addr"] = forward[3]
        handler.simpleElement("forward-port", attrs)
        handler.ignorableWhitespace("\n")

    # source-ports
    for port in uniqify(obj.source_ports):
        handler.ignorableWhitespace("  ")
        handler.simpleElement("source-port", {"port": port[0], "protocol": port[1]})
        handler.ignorableWhitespace("\n")

    # rules
    # Use sorted() to stabilize the XML, i.e. diffable
    for rule in sorted(obj.rules):
        attrs = {}
        if rule.family:
            attrs["family"] = rule.family
        if rule.priority != 0:
            attrs["priority"] = str(rule.priority)
        handler.ignorableWhitespace("  ")
        handler.startElement("rule", attrs)
        handler.ignorableWhitespace("\n")

        # source
        if rule.source:
            attrs = {}
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
            attrs = {}
            if rule.destination.addr:
                attrs["address"] = rule.destination.addr
            if rule.destination.ipset:
                attrs["ipset"] = rule.destination.ipset
            if rule.destination.invert:
                attrs["invert"] = "True"
            handler.ignorableWhitespace("    ")
            handler.simpleElement("destination", attrs)
            handler.ignorableWhitespace("\n")

        # element
        if rule.element:
            element = ""
            attrs = {}

            if isinstance(rule.element, rich.Rich_Service):
                element = "service"
                attrs["name"] = rule.element.name
            elif isinstance(rule.element, rich.Rich_Port):
                element = "port"
                attrs["port"] = rule.element.port
                attrs["protocol"] = rule.element.protocol
            elif isinstance(rule.element, rich.Rich_Protocol):
                element = "protocol"
                attrs["value"] = rule.element.value
            elif isinstance(rule.element, rich.Rich_Tcp_Mss_Clamp):
                element = "tcp-mss-clamp"
                if rule.element.value and rule.element.value != "pmtu":
                    attrs["value"] = rule.element.value
            elif isinstance(rule.element, rich.Rich_Masquerade):
                element = "masquerade"
            elif isinstance(rule.element, rich.Rich_IcmpBlock):
                element = "icmp-block"
                attrs["name"] = rule.element.name
            elif isinstance(rule.element, rich.Rich_IcmpType):
                element = "icmp-type"
                attrs["name"] = rule.element.name
            elif isinstance(rule.element, rich.Rich_ForwardPort):
                element = "forward-port"
                attrs["port"] = rule.element.port
                attrs["protocol"] = rule.element.protocol
                if rule.element.to_port != "":
                    attrs["to-port"] = rule.element.to_port
                if rule.element.to_address != "":
                    attrs["to-addr"] = rule.element.to_address
            elif isinstance(rule.element, rich.Rich_SourcePort):
                element = "source-port"
                attrs["port"] = rule.element.port
                attrs["protocol"] = rule.element.protocol
            else:
                raise FirewallError(
                    errors.INVALID_OBJECT,
                    "Unknown element '%s' in obj_writer" % type(rule.element),
                )

            handler.ignorableWhitespace("    ")
            handler.simpleElement(element, attrs)
            handler.ignorableWhitespace("\n")

        # rule.element

        # log
        if rule.log:
            if isinstance(rule.log, rich.Rich_Log):
                attrs = {}
                if rule.log.prefix:
                    attrs["prefix"] = rule.log.prefix
                if rule.log.level:
                    attrs["level"] = rule.log.level
                handler.ignorableWhitespace("    ")
                if rule.log.limit:
                    handler.startElement("log", attrs)
                    handler.ignorableWhitespace("\n      ")
                    _handler_add_rich_limit(handler, rule.log.limit)
                    handler.ignorableWhitespace("\n    ")
                    handler.endElement("log")
                else:
                    handler.simpleElement("log", attrs)
                handler.ignorableWhitespace("\n")
            else:
                attrs = {}
                if rule.log.group:
                    attrs["group"] = str(rule.log.group)
                if rule.log.prefix:
                    attrs["prefix"] = rule.log.prefix
                if rule.log.threshold:
                    attrs["queue-size"] = str(rule.log.threshold)
                handler.ignorableWhitespace("    ")
                if rule.log.limit:
                    handler.startElement("nflog", attrs)
                    handler.ignorableWhitespace("\n      ")
                    _handler_add_rich_limit(handler, rule.log.limit)
                    handler.ignorableWhitespace("\n    ")
                    handler.endElement("nflog")
                else:
                    handler.simpleElement("nflog", attrs)
                handler.ignorableWhitespace("\n")

        # audit
        if rule.audit:
            attrs = {}
            handler.ignorableWhitespace("    ")
            if rule.audit.limit:
                handler.startElement("audit", {})
                handler.ignorableWhitespace("\n      ")
                _handler_add_rich_limit(handler, rule.audit.limit)
                handler.ignorableWhitespace("\n    ")
                handler.endElement("audit")
            else:
                handler.simpleElement("audit", attrs)
            handler.ignorableWhitespace("\n")

        # action
        if rule.action:
            action = ""
            attrs = {}
            if isinstance(rule.action, rich.Rich_Accept):
                action = "accept"
            elif isinstance(rule.action, rich.Rich_Reject):
                action = "reject"
                if rule.action.type:
                    attrs["type"] = rule.action.type
            elif isinstance(rule.action, rich.Rich_Drop):
                action = "drop"
            elif isinstance(rule.action, rich.Rich_Mark):
                action = "mark"
                attrs["set"] = rule.action.set
            else:
                raise FirewallError(
                    errors.INVALID_RULE, f"Unknown action in rule '{str(obj._rule)}'."
                )
            handler.ignorableWhitespace("    ")
            if rule.action.limit:
                handler.startElement(action, attrs)
                handler.ignorableWhitespace("\n      ")
                _handler_add_rich_limit(handler, rule.action.limit)
                handler.ignorableWhitespace("\n    ")
                handler.endElement(action)
            else:
                handler.simpleElement(action, attrs)
            handler.ignorableWhitespace("\n")

        handler.ignorableWhitespace("  ")
        handler.endElement("rule")
        handler.ignorableWhitespace("\n")


class Policy(IO_Object):
    priority_min = -32768
    priority_max = 32767
    priority_default = DEFAULT_POLICY_PRIORITY
    priority_reserved = [0]

    IMPORT_EXPORT_STRUCTURE = {
        "version": "",  # s
        "short": "",  # s
        "description": "",  # s
        "target": "",  # s
        "services": [""],  # as
        "ports": [("", "")],  # a(ss)
        "icmp_blocks": [""],  # as
        "masquerade": False,  # b
        "forward_ports": [("", "", "", "")],  # a(ssss)
        "rich_rules": [""],  # as
        "protocols": [""],  # as
        "source_ports": [("", "")],  # a(ss)
        "priority": 0,  # i
        "ingress_zones": [""],  # as
        "egress_zones": [""],  # as
        "disable": False,  # b
    }
    ADDITIONAL_ALNUM_CHARS = ["_", "-", "/"]
    PARSER_REQUIRED_ELEMENT_ATTRS = {
        "short": None,
        "description": None,
        "policy": ["target"],
        "service": ["name"],
        "port": ["port", "protocol"],
        "icmp-block": ["name"],
        "icmp-type": ["name"],
        "masquerade": None,
        "forward-port": ["port", "protocol"],
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
        "ingress-zone": ["name"],
        "egress-zone": ["name"],
        "disable": None,
    }
    PARSER_OPTIONAL_ELEMENT_ATTRS = {
        "policy": ["version", "priority"],
        "forward-port": ["to-port", "to-addr"],
        "rule": ["family", "priority"],
        "source": ["address", "mac", "invert", "family", "ipset"],
        "destination": ["address", "invert", "ipset"],
        "log": ["prefix", "level"],
        "nflog": ["group", "prefix", "queue-size"],
        "reject": ["type"],
        "tcp-mss-clamp": ["value"],
        "limit": ["burst"],
    }

    def __init__(self):
        super(Policy, self).__init__()
        self.version = ""
        self.short = ""
        self.description = ""
        self.target = DEFAULT_POLICY_TARGET
        self.services = []
        self.ports = []
        self.protocols = []
        self.icmp_blocks = []
        self.icmp_block_inversion = False  # for zones, not written to policy config
        self.masquerade = False
        self.forward_ports = []
        self.source_ports = []
        self.rules = set()
        self.applied = False
        self.priority = self.priority_default
        self.derived_from_zone = None
        self.ingress_zones = []
        self.egress_zones = []
        self.disable = False

    def cleanup(self):
        self.version = ""
        self.short = ""
        self.description = ""
        self.target = DEFAULT_POLICY_TARGET
        del self.services[:]
        del self.ports[:]
        del self.protocols[:]
        del self.icmp_blocks[:]
        self.icmp_block_inversion = False
        self.masquerade = False
        del self.forward_ports[:]
        del self.source_ports[:]
        self.rules.clear()
        self.applied = False
        self.priority = self.priority_default
        del self.ingress_zones[:]
        del self.egress_zones[:]
        self.disable = False

    def __getattr__(self, name):
        if name == "rich_rules":
            return [str(r) for r in sorted(self.rules)]
        else:
            return getattr(super(Policy, self), name)

    def __setattr__(self, name, value):
        if name == "rich_rules":
            self.rules = set([rich.Rich_Rule(rule_str=s) for s in value])
        else:
            super(Policy, self).__setattr__(name, value)

    def _check_config(self, config, item, all_config, all_io_objects):
        common_check_config(self, config, item, all_config, all_io_objects)

        if self.name in all_io_objects["zones"]:
            raise FirewallError(
                errors.NAME_CONFLICT,
                "Policy '{}': Can't have the same name as a zone.".format(self.name),
            )

        if item == "target":
            if config not in POLICY_TARGETS:
                raise FirewallError(
                    errors.INVALID_TARGET,
                    "Policy '{}': '{}' is invalid target".format(self.name, config),
                )
        elif item == "priority":
            if (
                config in self.priority_reserved
                or config > self.priority_max
                or config < self.priority_min
            ):
                raise FirewallError(
                    errors.INVALID_PRIORITY,
                    "Policy '{}': {} is invalid priority. Must be in range [{}, {}]. The following are reserved: {}".format(
                        self.name,
                        config,
                        self.priority_min,
                        self.priority_max,
                        self.priority_reserved,
                    ),
                )
        elif item in ["ingress_zones", "egress_zones"]:
            existing_zones = ["ANY", "HOST"] + list(all_io_objects["zones"].keys())
            for zone in config:
                if zone not in existing_zones:
                    raise FirewallError(
                        errors.INVALID_ZONE,
                        "Policy '{}': '{}' not among existing zones".format(
                            self.name, zone
                        ),
                    )
                if (
                    zone not in ["ANY", "HOST"] and (set(["ANY", "HOST"]) & set(config))
                ) or (zone in ["ANY", "HOST"] and (set(config) - set([zone]))):
                    raise FirewallError(
                        errors.INVALID_ZONE,
                        "Policy '{}': '{}' may only contain one of: many regular zones, ANY, or HOST".format(
                            self.name, item
                        ),
                    )
                if zone == "HOST" and (
                    (
                        item == "ingress_zones"
                        and "egress_zones" in all_config
                        and "HOST" in all_config["egress_zones"]
                    )
                    or (
                        item == "egress_zones"
                        and "ingress_zones" in all_config
                        and "HOST" in all_config["ingress_zones"]
                    )
                ):
                    raise FirewallError(
                        errors.INVALID_ZONE,
                        "Policy '{}': 'HOST' can only appear in either ingress or egress zones, but not both".format(
                            self.name
                        ),
                    )
        elif item == "masquerade" and config:
            if "egress_zones" in all_config and "HOST" in all_config["egress_zones"]:
                raise FirewallError(
                    errors.INVALID_ZONE,
                    "Policy '{}': 'masquerade' is invalid for egress zone 'HOST'".format(
                        self.name
                    ),
                )
            elif "ingress_zones" in all_config:
                if "HOST" in all_config["ingress_zones"]:
                    raise FirewallError(
                        errors.INVALID_ZONE,
                        "Policy '{}': 'masquerade' is invalid for ingress zone 'HOST'".format(
                            self.name
                        ),
                    )
                for zone in all_config["ingress_zones"]:
                    if zone == "ANY":
                        continue
                    if zone not in all_io_objects["zones"]:
                        raise FirewallError(
                            errors.INVALID_ZONE,
                            "Policy '{}': Zone '{}' does not exist.".format(
                                self.name, zone
                            ),
                        )
                    if (
                        all_io_objects["conf"].get("FirewallBackend") != "nftables"
                        and all_io_objects["zones"][zone].interfaces
                    ):
                        raise FirewallError(
                            errors.INVALID_ZONE,
                            "Policy '{}': 'masquerade' cannot be used because ingress zone '{}' has assigned interfaces. ".format(
                                self.name, zone
                            ),
                        )
        elif item == "rich_rules":
            for rule in config:
                obj = rich.Rich_Rule(rule_str=rule)
                if obj.element and isinstance(obj.element, rich.Rich_Masquerade):
                    if (
                        "egress_zones" in all_config
                        and "HOST" in all_config["egress_zones"]
                    ):
                        raise FirewallError(
                            errors.INVALID_ZONE,
                            "Policy '{}': 'masquerade' is invalid for egress zone 'HOST'".format(
                                self.name
                            ),
                        )
                    elif "ingress_zones" in all_config:
                        if "HOST" in all_config["ingress_zones"]:
                            raise FirewallError(
                                errors.INVALID_ZONE,
                                "Policy '{}': 'masquerade' is invalid for ingress zone 'HOST'".format(
                                    self.name
                                ),
                            )
                        for zone in all_config["ingress_zones"]:
                            if zone == "ANY":
                                continue
                            if zone not in all_io_objects["zones"]:
                                raise FirewallError(
                                    errors.INVALID_ZONE,
                                    "Policy '{}': Zone '{}' does not exist.".format(
                                        self.name, zone
                                    ),
                                )
                            if (
                                all_io_objects["conf"].get("FirewallBackend")
                                != "nftables"
                                and all_io_objects["zones"][zone].interfaces
                            ):
                                raise FirewallError(
                                    errors.INVALID_ZONE,
                                    "Policy '{}': 'masquerade' cannot be used because ingress zone '{}' has assigned interfaces. ".format(
                                        self.name, zone
                                    ),
                                )
                elif obj.element and isinstance(obj.element, rich.Rich_ForwardPort):
                    if "egress_zones" in all_config:
                        if all_config["egress_zones"]:
                            if (
                                "HOST" not in all_config["egress_zones"]
                                and not obj.element.to_address
                            ):
                                raise FirewallError(
                                    errors.INVALID_FORWARD,
                                    "Policy '{}': 'forward-port' requires 'to-addr' if egress zone is 'ANY' or a zone".format(
                                        self.name
                                    ),
                                )
                            for zone in all_config["egress_zones"]:
                                if zone in ("HOST", "ANY"):
                                    continue
                                if zone not in all_io_objects["zones"]:
                                    raise FirewallError(
                                        errors.INVALID_ZONE,
                                        "Policy '{}': Zone '{}' does not exist.".format(
                                            self.name, zone
                                        ),
                                    )
                                if all_io_objects["zones"][zone].interfaces:
                                    raise FirewallError(
                                        errors.INVALID_ZONE,
                                        "Policy '{}': 'forward-port' cannot be used because egress zone '{}' has assigned interfaces".format(
                                            self.name, zone
                                        ),
                                    )
                elif obj.action and isinstance(obj.action, rich.Rich_Mark):
                    if "egress_zones" in all_config:
                        for zone in all_config["egress_zones"]:
                            if zone in ["ANY", "HOST"]:
                                continue
                            if zone not in all_io_objects["zones"]:
                                raise FirewallError(
                                    errors.INVALID_ZONE,
                                    "Policy '{}': Zone '{}' does not exist.".format(
                                        self.name, zone
                                    ),
                                )
                            if all_io_objects["zones"][zone].interfaces:
                                raise FirewallError(
                                    errors.INVALID_ZONE,
                                    "Policy '{}': 'mark' action cannot be used because egress zone '{}' has assigned interfaces".format(
                                        self.name, zone
                                    ),
                                )
        elif item == "forward_ports":
            for fwd_port in config:
                if "egress_zones" in all_config:
                    if all_config["egress_zones"]:
                        if "HOST" not in all_config["egress_zones"] and not fwd_port[3]:
                            raise FirewallError(
                                errors.INVALID_FORWARD,
                                "Policy '{}': 'forward-port' requires 'to-addr' if egress zone is 'ANY' or a zone".format(
                                    self.name
                                ),
                            )
                        for zone in all_config["egress_zones"]:
                            if zone in ("HOST", "ANY"):
                                continue
                            if zone not in all_io_objects["zones"]:
                                raise FirewallError(
                                    errors.INVALID_ZONE,
                                    "Policy '{}': Zone '{}' does not exist.".format(
                                        self.name, zone
                                    ),
                                )
                            if all_io_objects["zones"][zone].interfaces:
                                raise FirewallError(
                                    errors.INVALID_ZONE,
                                    "Policy '{}': 'forward-port' cannot be used because egress zone '{}' has assigned interfaces".format(
                                        self.name, zone
                                    ),
                                )

    def check_name(self, name):
        super(Policy, self).check_name(name)
        if name.startswith("/"):
            raise FirewallError(
                errors.INVALID_NAME,
                "Policy '{}': name can't start with '/'".format(name),
            )
        elif name.endswith("/"):
            raise FirewallError(
                errors.INVALID_NAME, "Policy '{}': name can't end with '/'".format(name)
            )
        elif name.count("/") > 1:
            raise FirewallError(
                errors.INVALID_NAME,
                "Policy '{}': name has more than one '/'".format(name),
            )
        else:
            if "/" in name:
                checked_name = name[: name.find("/")]
            else:
                checked_name = name
            if len(checked_name) > max_policy_name_len():
                raise FirewallError(
                    errors.INVALID_NAME,
                    "Policy '{}': name has {} chars, max is {}".format(
                        name, len(checked_name), max_policy_name_len()
                    ),
                )


# PARSER


class policy_ContentHandler(IO_Object_ContentHandler):
    def __init__(self, item):
        IO_Object_ContentHandler.__init__(self, item)
        self._rule = None
        self._limit_ok = None

    def startElement(self, name, attrs):
        IO_Object_ContentHandler.startElement(self, name, attrs)

        self.item.parser_check_element_attrs(name, attrs)

        if common_startElement(self, name, attrs):
            return

        elif name == "policy":
            if "version" in attrs:
                self.item.version = attrs["version"]
            if "priority" in attrs:
                self.item.priority = int(attrs["priority"])
            if "target" in attrs:
                target = attrs["target"]
                if target not in POLICY_TARGETS:
                    raise FirewallError(errors.INVALID_TARGET, target)
                if target:
                    self.item.target = target

        elif name == "ingress-zone":
            if attrs["name"] not in self.item.ingress_zones:
                self.item.ingress_zones.append(attrs["name"])

        elif name == "egress-zone":
            if attrs["name"] not in self.item.egress_zones:
                self.item.egress_zones.append(attrs["name"])

        elif name == "source":
            if not self._rule:
                raise FirewallError(errors.INVALID_RULE, "Source outside of rule.")

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

        elif name == "disable":
            self.item.disable = True

        else:
            raise FirewallError(errors.INVALID_POLICY, f"Unknown XML element '{name}'.")

    def endElement(self, name):
        IO_Object_ContentHandler.endElement(self, name)

        common_endElement(self, name)


def policy_reader(filename, path, no_check_name=False):
    policy = Policy()
    if not filename.endswith(".xml"):
        raise FirewallError(
            errors.INVALID_NAME, "'%s' is missing .xml suffix" % filename
        )
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
            raise FirewallError(
                errors.INVALID_POLICY,
                "not a valid policy file: %s" % msg.getException(),
            )
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

    f = io.open(name, mode="wt", encoding="UTF-8")
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

    common_writer(policy, handler)

    # ingress-zones
    for zone in uniqify(policy.ingress_zones):
        handler.ignorableWhitespace("  ")
        handler.simpleElement("ingress-zone", {"name": zone})
        handler.ignorableWhitespace("\n")

    # egress-zones
    for zone in uniqify(policy.egress_zones):
        handler.ignorableWhitespace("  ")
        handler.simpleElement("egress-zone", {"name": zone})
        handler.ignorableWhitespace("\n")

    if policy.disable:
        handler.ignorableWhitespace("  ")
        handler.simpleElement("disable", {})
        handler.ignorableWhitespace("\n")

    # end policy element
    handler.endElement("policy")
    handler.ignorableWhitespace("\n")
    handler.endDocument()
    f.close()
    del handler
