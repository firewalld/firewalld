# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2013-2016 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>

from typing import ClassVar
from dataclasses import dataclass, field, InitVar

from firewall import functions
from firewall.core.ipset import check_ipset_name
from firewall.core.base import REJECT_TYPES
from firewall import errors
from firewall.errors import FirewallError, BugError


# Dummy class for EOL singleton instance. It's a class, so we
# can overwrite __repr__().
class _EOLType:
    def __repr__(self):
        # The string representation is the full name of the instance.
        return "firewall.core.rich.EOL"


# A EndOfLine singleton instance to indicate EOL token.
EOL = _EOLType()


def lt_objects(left, right):
    if left is None and right is not None:
        return True
    elif left is not None and right is None:
        return False
    elif left is None and right is None:
        return False
    elif type(left) is type(right):
        return left < right
    else:
        return type(left).__name__ < type(right).__name__


def lt_family(left, right):
    return left.family < right.family


def lt_priority(left, right):
    return left.priority < right.priority


def lt_source(left, right):
    return lt_objects(left.source, right.source)


def lt_destination(left, right):
    return lt_objects(left.destination, right.destination)


def lt_element(left, right):
    return lt_objects(left.element, right.element)


def lt_log(left, right):
    return lt_objects(left.log, right.log)


def lt_audit(left, right):
    return lt_objects(left.audit, right.audit)


def lt_action(left, right):
    return lt_objects(left.action, right.action)


@dataclass(frozen=True, order=True)
class Rich_Source:
    """This object only holds data and is read-only after init. It is also
    hashable and can be used as a dictionary key."""

    addr: str
    mac: str
    ipset: str
    invert: bool = False

    def __post_init__(self):
        if not any([self.addr, self.mac, self.ipset]):
            raise FirewallError(errors.INVALID_RULE, "no address, mac and ipset")

        if self.addr is None:
            object.__setattr__(self, "addr", "")
        if self.mac is None:
            object.__setattr__(self, "mac", "")
        if self.ipset is None:
            object.__setattr__(self, "ipset", "")

        if self.addr:
            if self.mac:
                raise FirewallError(errors.INVALID_RULE, "address and mac")
            if self.ipset:
                raise FirewallError(errors.INVALID_RULE, "address and ipset")
        elif self.mac:
            if self.ipset:
                raise FirewallError(errors.INVALID_RULE, "mac and ipset")
            if not functions.check_mac(self.mac):
                raise FirewallError(errors.INVALID_MAC, str(self.mac))
        elif self.ipset:
            if not check_ipset_name(self.ipset):
                raise FirewallError(errors.INVALID_IPSET, str(self.ipset))

    def __str__(self):
        ret = "source%s " % (" NOT" if self.invert else "")
        if self.addr:
            return ret + 'address="%s"' % self.addr
        elif self.mac:
            return ret + 'mac="%s"' % self.mac
        elif self.ipset:
            return ret + 'ipset="%s"' % self.ipset


@dataclass(frozen=True, order=True)
class Rich_Destination:
    """This object only holds data and is read-only after init. It is also
    hashable and can be used as a dictionary key."""

    addr: str
    ipset: str
    invert: bool = False

    def __post_init__(self):
        if not any([self.addr, self.ipset]):
            raise FirewallError(errors.INVALID_DESTINATION, "no address or ipset")

        if self.addr is None:
            object.__setattr__(self, "addr", "")
        if self.ipset is None:
            object.__setattr__(self, "ipset", "")

        if self.addr:
            if self.ipset:
                raise FirewallError(errors.INVALID_DESTINATION, "address and ipset")
        elif self.ipset:
            if not check_ipset_name(self.ipset):
                raise FirewallError(errors.INVALID_IPSET, str(self.ipset))

    def __str__(self):
        ret = "destination%s " % (" NOT" if self.invert else "")
        if self.addr:
            return ret + 'address="%s"' % self.addr
        elif self.ipset:
            return ret + 'ipset="%s"' % self.ipset


@dataclass(frozen=True, order=True)
class Rich_Service:
    """This object only holds data and is read-only after init. It is also
    hashable and can be used as a dictionary key."""

    name: str

    def __str__(self):
        return 'service name="%s"' % (self.name)


@dataclass(frozen=True, order=True)
class Rich_Port:
    """This object only holds data and is read-only after init. It is also
    hashable and can be used as a dictionary key."""

    port: str
    protocol: str

    def __post_init__(self):
        if not functions.check_port(self.port):
            raise FirewallError(errors.INVALID_PORT, self.port)
        if self.protocol not in ["tcp", "udp", "sctp", "dccp"]:
            raise FirewallError(errors.INVALID_PROTOCOL, self.protocol)

    def __str__(self):
        return 'port port="%s" protocol="%s"' % (self.port, self.protocol)


@dataclass(frozen=True, order=True)
class Rich_SourcePort:
    """This object only holds data and is read-only after init. It is also
    hashable and can be used as a dictionary key."""

    port: str
    protocol: str

    def __post_init__(self):
        if not functions.check_port(self.port):
            raise FirewallError(errors.INVALID_PORT, self.port)
        if self.protocol not in ["tcp", "udp", "sctp", "dccp"]:
            raise FirewallError(errors.INVALID_PROTOCOL, self.protocol)

    def __str__(self):
        return 'source-port port="%s" protocol="%s"' % (self.port, self.protocol)


@dataclass(frozen=True, order=True)
class Rich_Protocol:
    """This object only holds data and is read-only after init. It is also
    hashable and can be used as a dictionary key."""

    value: str

    def __post_init__(self):
        if not functions.checkProtocol(self.value):
            raise FirewallError(errors.INVALID_PROTOCOL, self.value)

    def __str__(self):
        return 'protocol value="%s"' % (self.value)


@dataclass(frozen=True)
class Rich_Masquerade:
    """This object only holds data and is read-only after init. It is also
    hashable and can be used as a dictionary key."""

    def __str__(self):
        return "masquerade"


@dataclass(frozen=True, order=True)
class Rich_IcmpBlock:
    """This object only holds data and is read-only after init. It is also
    hashable and can be used as a dictionary key."""

    name: str

    def __post_init__(self):
        if self.name is None or len(self.name) < 1:
            raise FirewallError(errors.INVALID_ICMPTYPE, str(self.name))

    def __str__(self):
        return 'icmp-block name="%s"' % (self.name)


@dataclass(frozen=True, order=True)
class Rich_IcmpType:
    """This object only holds data and is read-only after init. It is also
    hashable and can be used as a dictionary key."""

    name: str

    def __post_init__(self):
        if self.name is None or len(self.name) < 1:
            raise FirewallError(errors.INVALID_ICMPTYPE, str(self.name))

    def __str__(self):
        return 'icmp-type name="%s"' % (self.name)


@dataclass(frozen=True, order=True)
class Rich_Tcp_Mss_Clamp:
    """This object only holds data and is read-only after init. It is also
    hashable and can be used as a dictionary key."""

    value: str

    def __post_init__(self):
        if self.value is None:
            object.__setattr__(self, "value", "")

        if self.value:
            if not functions.checkTcpMssClamp(self.value):
                raise FirewallError(errors.INVALID_RULE, str(self))

    def __str__(self):
        if self.value:
            return 'tcp-mss-clamp value="%s"' % (self.value)
        else:
            return "tcp-mss-clamp"


@dataclass(frozen=True, order=True)
class Rich_ForwardPort:
    """This object only holds data and is read-only after init. It is also
    hashable and can be used as a dictionary key."""

    port: str
    protocol: str
    to_port: str
    to_address: str

    def __post_init__(self):
        if self.to_port is None:
            object.__setattr__(self, "to_port", "")
        if self.to_address is None:
            object.__setattr__(self, "to_address", "")

        if not functions.check_port(self.port):
            raise FirewallError(errors.INVALID_PORT, self.port)
        if self.protocol not in ["tcp", "udp", "sctp", "dccp"]:
            raise FirewallError(errors.INVALID_PROTOCOL, self.protocol)
        if not self.to_port and not self.to_address:
            raise FirewallError(errors.INVALID_PORT, self.to_port)
        if self.to_port and not functions.check_port(self.to_port):
            raise FirewallError(errors.INVALID_PORT, self.to_port)

    def __str__(self):
        return 'forward-port port="%s" protocol="%s"%s%s' % (
            self.port,
            self.protocol,
            ' to-port="%s"' % self.to_port if self.to_port != "" else "",
            ' to-addr="%s"' % self.to_address if self.to_address != "" else "",
        )


DURATION_TO_MULT = {
    "s": 1,
    "m": 60,
    "h": 60 * 60,
    "d": 24 * 60 * 60,
}


@dataclass(frozen=True, order=True)
class Rich_Limit:
    """This object only holds data and is read-only after init. It is also
    hashable and can be used as a dictionary key."""

    value: InitVar[str]  # init only, use rate and duration
    burst: int = 0
    rate: int = field(init=False)
    duration: str = field(init=False)

    def __post_init__(self, value):
        rate, duration = self._value_parse(value)
        object.__setattr__(self, "rate", rate)
        object.__setattr__(self, "duration", duration)
        object.__setattr__(self, "burst", self._burst_parse(self.burst))
        object.__setattr__(self, "value", f"{self.rate}/{self.duration}")

    def _value_parse(self, value):
        splits = None
        if "/" in value:
            splits = value.split("/")
        if not splits or len(splits) != 2:
            raise FirewallError(errors.INVALID_LIMIT, value)
        (rate, duration) = splits
        try:
            rate = int(rate)
        except:
            raise FirewallError(errors.INVALID_LIMIT, value)

        duration = duration.strip()

        if duration in ["second", "minute", "hour", "day"]:
            duration = duration[:1]

        if rate < 1 or duration not in ["s", "m", "h", "d"]:
            raise FirewallError(errors.INVALID_LIMIT, value)

        if 10000 * DURATION_TO_MULT[duration] // rate == 0:
            raise FirewallError(errors.INVALID_LIMIT, f"{value} too fast")

        if rate == 1 and duration == "d":
            # iptables (v1.4.21) doesn't accept 1/d
            raise FirewallError(errors.INVALID_LIMIT, f"{value} too slow")

        return rate, duration

    def _burst_parse(self, burst):
        if burst is None:
            return 0

        try:
            b = int(burst)
        except:
            raise FirewallError(errors.INVALID_LIMIT, burst)

        if b < 0 or b > 10_000_000:
            raise FirewallError(errors.INVALID_LIMIT, burst)

        return b

    def __str__(self):
        s = f'limit value="{self.value}"'
        if self.burst:
            s += f" burst={self.burst}"
        return s


@dataclass(frozen=True)
class Rich_Log:
    """This object only holds data and is read-only after init. It is also
    hashable and can be used as a dictionary key."""

    prefix: str = ""
    level: str = ""
    limit: Rich_Limit = None

    def __post_init__(self):
        if self.prefix is None:
            object.__setattr__(self, "prefix", "")
        if self.level is None:
            object.__setattr__(self, "level", "")

        if self.prefix and len(self.prefix) > 127:
            raise FirewallError(
                errors.INVALID_LOG_PREFIX, "maximum accepted length of 'prefix' is 127."
            )

        if self.level and self.level not in [
            "emerg",
            "alert",
            "crit",
            "error",
            "warning",
            "notice",
            "info",
            "debug",
        ]:
            raise FirewallError(errors.INVALID_LOG_LEVEL, self.level)

    def __lt__(self, other):
        if self.prefix < other.prefix:
            return True
        elif self.level < other.level:
            return True
        elif lt_objects(self.limit, other.limit):
            return True

        return False

    def __str__(self):
        return "log%s%s%s" % (
            ' prefix="%s"' % (self.prefix) if self.prefix else "",
            ' level="%s"' % (self.level) if self.level else "",
            " %s" % self.limit if self.limit else "",
        )


@dataclass(frozen=True)
class Rich_NFLog:
    """This object only holds data and is read-only after init. It is also
    hashable and can be used as a dictionary key."""

    group: int
    prefix: str
    threshold: int
    limit: Rich_Limit = None

    def __post_init__(self):
        if self.group is None:
            object.__setattr__(self, "group", 0)
        if self.prefix is None:
            object.__setattr__(self, "prefix", "")
        if self.threshold is None:
            object.__setattr__(self, "threshold", 0)

        if self.group and not functions.checkUINT16(self.group):
            raise FirewallError(
                errors.INVALID_NFLOG_GROUP,
                "nflog 'group' must be an integer between 0 and 65535.",
            )
        object.__setattr__(self, "group", int(str(self.group), 0))

        if self.prefix and len(self.prefix) > 127:
            raise FirewallError(
                errors.INVALID_LOG_PREFIX, "maximum accepted length of 'prefix' is 127."
            )

        if self.threshold and not functions.checkUINT16(self.threshold):
            raise FirewallError(
                errors.INVALID_NFLOG_QUEUE,
                "nflog 'queue-size' must be an integer between 0 and 65535.",
            )
        object.__setattr__(self, "threshold", int(str(self.threshold), 0))

    def __lt__(self, other):
        if self.group < other.group:
            return True
        elif self.prefix < other.prefix:
            return True
        elif self.threshold < other.threshold:
            return True
        elif lt_objects(self.limit, other.limit):
            return True

        return False

    def __str__(self):
        return "nflog%s%s%s%s" % (
            ' group="%s"' % (self.group) if self.group else "",
            ' prefix="%s"' % (self.prefix) if self.prefix else "",
            ' queue-size="%s"' % (self.threshold) if self.threshold else "",
            " %s" % self.limit if self.limit else "",
        )


@dataclass(frozen=True)
class Rich_Audit:
    """This object only holds data and is read-only after init. It is also
    hashable and can be used as a dictionary key."""

    limit: Rich_Limit = None

    def __lt__(self, other):
        if lt_objects(self.limit, other.limit):
            return True

        return False

    def __str__(self):
        return "audit%s" % (" %s" % self.limit if self.limit else "")


@dataclass(frozen=True)
class Rich_Accept:
    """This object only holds data and is read-only after init. It is also
    hashable and can be used as a dictionary key."""

    limit: Rich_Limit = None

    def __lt__(self, other):
        if lt_objects(self.limit, other.limit):
            return True

        return False

    def __str__(self):
        return "accept%s" % (" %s" % self.limit if self.limit else "")


@dataclass(frozen=True)
class Rich_Reject:
    """This object only holds data and is read-only after init. It is also
    hashable and can be used as a dictionary key."""

    type: str = ""
    limit: Rich_Limit = None

    def __lt__(self, other):
        if self.type < other.type:
            return True
        elif lt_objects(self.limit, other.limit):
            return True

        return False

    def __str__(self):
        return "reject%s%s" % (
            ' type="%s"' % self.type if self.type else "",
            " %s" % self.limit if self.limit else "",
        )


@dataclass(frozen=True)
class Rich_Drop:
    """This object only holds data and is read-only after init. It is also
    hashable and can be used as a dictionary key."""

    limit: Rich_Limit = None

    def __lt__(self, other):
        if lt_objects(self.limit, other.limit):
            return True

        return False

    def __str__(self):
        return "drop%s" % (" %s" % self.limit if self.limit else "")


@dataclass(frozen=True)
class Rich_Mark:
    """This object only holds data and is read-only after init. It is also
    hashable and can be used as a dictionary key."""

    set: str
    limit: Rich_Limit = None

    def __post_init__(self):
        if self.set is not None:
            x = self.set
        else:
            raise FirewallError(errors.INVALID_MARK, "no value set")

        if "/" in x:
            splits = x.split("/")
            if len(splits) != 2:
                raise FirewallError(errors.INVALID_MARK, x)
            if not functions.checkUINT32(splits[0]) or not functions.checkUINT32(
                splits[1]
            ):
                # value and mask are uint32
                raise FirewallError(errors.INVALID_MARK, x)
        else:
            if not functions.checkUINT32(x):
                # value is uint32
                raise FirewallError(errors.INVALID_MARK, x)

    def __lt__(self, other):
        if self.set < other.set:
            return True
        elif lt_objects(self.limit, other.limit):
            return True

        return False

    def __str__(self):
        return "mark set=%s%s" % (self.set, " %s" % self.limit if self.limit else "")


@dataclass(frozen=True)
class Rich_Rule:
    """This object only holds data and is read-only after init. It is also
    hashable and can be used as a dictionary key."""

    priority_min: ClassVar[int] = -32768
    priority_max: ClassVar[int] = 32767

    rule_str: InitVar[str] = None
    family: str = ""
    priority: int = 0
    source: Rich_Source = None
    destination: Rich_Destination = None
    element: [
        Rich_Protocol,
        Rich_Tcp_Mss_Clamp,
        Rich_Service,
        Rich_Port,
        Rich_SourcePort,
        Rich_ForwardPort,
        Rich_IcmpBlock,
        Rich_IcmpType,
        Rich_Masquerade,
    ] = None
    log: Rich_Log = None
    audit: Rich_Audit = None
    action: [Rich_Accept, Rich_Reject, Rich_Drop, Rich_Mark] = None

    def __post_init__(self, rule_str):
        if self.family is None:
            object.__setattr__(self, "family", "")
        if self.priority is None:
            object.__setattr__(self, "priority", 0)

        if rule_str is not None:
            # If we're being built from a rule_str then we should not be passed
            # other arguments.
            if any(
                [
                    self.family,
                    self.priority,
                    self.source,
                    self.destination,
                    self.element,
                    self.log,
                    self.audit,
                    self.action,
                ]
            ):
                raise BugError(
                    "May not specify other arguments if constructing object using 'rule_str'."
                )

            self._import_from_string(rule_str)
            self.check()

    def __lt__(self, other):
        lt_functions = [
            lt_priority,
            lt_family,
            lt_source,
            lt_destination,
            lt_element,
            lt_log,
            lt_audit,
            lt_action,
        ]

        for _lt in lt_functions:
            if _lt(self, other):
                return True
            elif _lt(other, self):
                return False

        return False

    @staticmethod
    def _lexer(rule_str):
        """Lexical analysis"""
        tokens = []

        for r in functions.splitArgs(rule_str):
            if "=" in r:
                attr = r.split("=")
                if len(attr) != 2 or not attr[0] or not attr[1]:
                    raise FirewallError(
                        errors.INVALID_RULE, "internal error in _lexer(): %s" % r
                    )
                tokens.append({"attr_name": attr[0], "attr_value": attr[1]})
            else:
                tokens.append({"element": r})
        tokens.append({"element": EOL})

        return tokens

    def _import_from_string(self, rule_str):
        if not rule_str:
            raise FirewallError(errors.INVALID_RULE, "empty rule")

        rule_str = functions.stripNonPrintableCharacters(rule_str)

        tokens = self._lexer(rule_str)
        if tokens and tokens[0].get("element") is EOL:
            raise FirewallError(errors.INVALID_RULE, "empty rule")

        attrs = {}  # attributes of elements
        in_elements = []  # stack with elements we are in
        index = 0  # index into tokens
        while not (tokens[index].get("element") is EOL and in_elements == ["rule"]):
            current_element = tokens[index].get("element")
            attr_name = tokens[index].get("attr_name")
            attr_value = tokens[index].get("attr_value")
            # print ("in_elements: ", in_elements)
            # print ("index: %s, element: %s, attribute: %s=%s" % (index, element, attr_name, attr_value))
            if attr_name:  # attribute
                if attr_name not in [
                    "priority",
                    "family",
                    "address",
                    "mac",
                    "ipset",
                    "invert",
                    "value",
                    "port",
                    "protocol",
                    "to-port",
                    "to-addr",
                    "name",
                    "group",
                    "prefix",
                    "level",
                    "queue-size",
                    "type",
                    "set",
                    "burst",
                ]:
                    raise FirewallError(
                        errors.INVALID_RULE, "bad attribute '%s'" % attr_name
                    )
            else:  # element
                if current_element in [
                    "rule",
                    "source",
                    "destination",
                    "protocol",
                    "service",
                    "port",
                    "icmp-block",
                    "icmp-type",
                    "masquerade",
                    "forward-port",
                    "source-port",
                    "log",
                    "nflog",
                    "audit",
                    "accept",
                    "drop",
                    "reject",
                    "mark",
                    "limit",
                    "not",
                    "NOT",
                    EOL,
                    "tcp-mss-clamp",
                ]:
                    if current_element == "source" and self.source:
                        raise FirewallError(
                            errors.INVALID_RULE, "more than one 'source' element"
                        )
                    elif current_element == "destination" and self.destination:
                        raise FirewallError(
                            errors.INVALID_RULE, "more than one 'destination' element"
                        )
                    elif (
                        current_element
                        in [
                            "protocol",
                            "service",
                            "port",
                            "icmp-block",
                            "icmp-type",
                            "masquerade",
                            "forward-port",
                            "source-port",
                        ]
                        and self.element
                    ):
                        raise FirewallError(
                            errors.INVALID_RULE,
                            "more than one element. There cannot be both '%s' and '%s' in one rule."
                            % (current_element, self.element),
                        )
                    elif current_element in ["log", "nflog"] and self.log:
                        raise FirewallError(
                            errors.INVALID_RULE, "more than one logging element"
                        )
                    elif current_element == "audit" and self.audit:
                        raise FirewallError(
                            errors.INVALID_RULE, "more than one 'audit' element"
                        )
                    elif (
                        current_element in ["accept", "drop", "reject", "mark"]
                        and self.action
                    ):
                        raise FirewallError(
                            errors.INVALID_RULE,
                            "more than one 'action' element. There cannot be both '%s' and '%s' in one rule."
                            % (current_element, self.action),
                        )
                else:
                    raise FirewallError(
                        errors.INVALID_RULE, "unknown element %s" % current_element
                    )

            in_element = (
                in_elements[len(in_elements) - 1] if len(in_elements) > 0 else ""
            )

            if in_element == "":
                if not current_element and attr_name:
                    if attr_name == "family":
                        raise FirewallError(
                            errors.INVALID_RULE,
                            "'family' outside of rule. Use 'rule family=...'.",
                        )
                    elif attr_name == "priority":
                        raise FirewallError(
                            errors.INVALID_RULE,
                            "'priority' outside of rule. Use 'rule priority=...'.",
                        )
                    else:
                        raise FirewallError(
                            errors.INVALID_RULE,
                            "'%s' outside of any element. Use 'rule <element> %s= ...'."
                            % (attr_name, attr_name),
                        )
                elif "rule" not in current_element:
                    raise FirewallError(
                        errors.INVALID_RULE,
                        "'%s' outside of rule. Use 'rule ... %s ...'."
                        % (current_element, current_element),
                    )
                else:
                    in_elements.append("rule")  # push into stack
            elif in_element == "rule":
                if attr_name == "family":
                    if attr_value not in ["ipv4", "ipv6"]:
                        raise FirewallError(
                            errors.INVALID_RULE,
                            "'family' attribute cannot have '%s' value. Use 'ipv4' or 'ipv6' instead."
                            % attr_value,
                        )
                    object.__setattr__(self, "family", attr_value)
                elif attr_name == "priority":
                    try:
                        object.__setattr__(self, "priority", int(attr_value))
                    except ValueError:
                        raise FirewallError(
                            errors.INVALID_PRIORITY,
                            "invalid 'priority' attribute value '%s'." % attr_value,
                        )
                elif attr_name:
                    if attr_name == "protocol":
                        err_msg = "wrong 'protocol' usage. Use either 'rule protocol value=...' or  'rule [forward-]port protocol=...'."
                    else:
                        err_msg = (
                            "attribute '%s' outside of any element. Use 'rule <element> %s= ...'."
                            % (attr_name, attr_name)
                        )
                    raise FirewallError(errors.INVALID_RULE, err_msg)
                else:
                    in_elements.append(current_element)  # push into stack
            elif in_element == "source":
                if attr_name in ["address", "mac", "ipset", "invert"]:
                    attrs[attr_name] = attr_value
                elif current_element in ["not", "NOT"]:
                    attrs["invert"] = True
                else:
                    object.__setattr__(
                        self,
                        "source",
                        Rich_Source(
                            attrs.get("address"),
                            attrs.get("mac"),
                            attrs.get("ipset"),
                            attrs.get("invert", False),
                        ),
                    )
                    in_elements.pop()  # source
                    attrs.clear()
                    index = index - 1  # return token to input
            elif in_element == "destination":
                if attr_name in ["address", "ipset", "invert"]:
                    attrs[attr_name] = attr_value
                elif current_element in ["not", "NOT"]:
                    attrs["invert"] = True
                else:
                    object.__setattr__(
                        self,
                        "destination",
                        Rich_Destination(
                            attrs.get("address"),
                            attrs.get("ipset"),
                            attrs.get("invert", False),
                        ),
                    )
                    in_elements.pop()  # destination
                    attrs.clear()
                    index = index - 1  # return token to input
            elif in_element == "protocol":
                if attr_name == "value":
                    object.__setattr__(self, "element", Rich_Protocol(attr_value))
                    in_elements.pop()  # protocol
                else:
                    raise FirewallError(
                        errors.INVALID_RULE, "invalid 'protocol' element"
                    )
            elif in_element == "tcp-mss-clamp":
                if attr_name == "value":
                    attrs[attr_name] = attr_value
                else:
                    object.__setattr__(
                        self, "element", Rich_Tcp_Mss_Clamp(attrs.get("value"))
                    )
                    in_elements.pop()
                    attrs.clear()
                    index = index - 1
            elif in_element == "service":
                if attr_name == "name":
                    object.__setattr__(self, "element", Rich_Service(attr_value))
                    in_elements.pop()  # service
                else:
                    raise FirewallError(
                        errors.INVALID_RULE, "invalid 'service' element"
                    )
            elif in_element == "port":
                if attr_name in ["port", "protocol"]:
                    attrs[attr_name] = attr_value
                else:
                    object.__setattr__(
                        self,
                        "element",
                        Rich_Port(attrs.get("port"), attrs.get("protocol")),
                    )
                    in_elements.pop()  # port
                    attrs.clear()
                    index = index - 1  # return token to input
            elif in_element == "icmp-block":
                if attr_name == "name":
                    object.__setattr__(self, "element", Rich_IcmpBlock(attr_value))
                    in_elements.pop()  # icmp-block
                else:
                    raise FirewallError(
                        errors.INVALID_RULE, "invalid 'icmp-block' element"
                    )
            elif in_element == "icmp-type":
                if attr_name == "name":
                    object.__setattr__(self, "element", Rich_IcmpType(attr_value))
                    in_elements.pop()  # icmp-type
                else:
                    raise FirewallError(
                        errors.INVALID_RULE, "invalid 'icmp-type' element"
                    )
            elif in_element == "masquerade":
                object.__setattr__(self, "element", Rich_Masquerade())
                in_elements.pop()
                attrs.clear()
                index = index - 1  # return token to input
            elif in_element == "forward-port":
                if attr_name in ["port", "protocol", "to-port", "to-addr"]:
                    attrs[attr_name] = attr_value
                else:
                    object.__setattr__(
                        self,
                        "element",
                        Rich_ForwardPort(
                            attrs.get("port"),
                            attrs.get("protocol"),
                            attrs.get("to-port"),
                            attrs.get("to-addr"),
                        ),
                    )
                    in_elements.pop()  # forward-port
                    attrs.clear()
                    index = index - 1  # return token to input
            elif in_element == "source-port":
                if attr_name in ["port", "protocol"]:
                    attrs[attr_name] = attr_value
                else:
                    object.__setattr__(
                        self,
                        "element",
                        Rich_SourcePort(attrs.get("port"), attrs.get("protocol")),
                    )
                    in_elements.pop()  # source-port
                    attrs.clear()
                    index = index - 1  # return token to input
            elif in_element == "log":
                if attr_name in ["prefix", "level"]:
                    attrs[attr_name] = attr_value
                elif current_element == "limit":
                    in_elements.append("limit")
                else:
                    object.__setattr__(
                        self,
                        "log",
                        Rich_Log(
                            attrs.get("prefix"), attrs.get("level"), attrs.get("limit")
                        ),
                    )
                    in_elements.pop()  # log
                    attrs.clear()
                    index = index - 1  # return token to input
            elif in_element == "nflog":
                if attr_name in ["group", "prefix", "queue-size"]:
                    attrs[attr_name] = attr_value
                elif current_element == "limit":
                    in_elements.append("limit")
                else:
                    object.__setattr__(
                        self,
                        "log",
                        Rich_NFLog(
                            attrs.get("group"),
                            attrs.get("prefix"),
                            attrs.get("queue-size"),
                            attrs.get("limit"),
                        ),
                    )
                    in_elements.pop()  # nflog
                    attrs.clear()
                    index = index - 1  # return token to input
            elif in_element == "audit":
                if current_element == "limit":
                    in_elements.append("limit")
                else:
                    object.__setattr__(self, "audit", Rich_Audit(attrs.get("limit")))
                    in_elements.pop()  # audit
                    attrs.clear()
                    index = index - 1  # return token to input
            elif in_element == "accept":
                if current_element == "limit":
                    in_elements.append("limit")
                else:
                    object.__setattr__(self, "action", Rich_Accept(attrs.get("limit")))
                    in_elements.pop()  # accept
                    attrs.clear()
                    index = index - 1  # return token to input
            elif in_element == "drop":
                if current_element == "limit":
                    in_elements.append("limit")
                else:
                    object.__setattr__(self, "action", Rich_Drop(attrs.get("limit")))
                    in_elements.pop()  # drop
                    attrs.clear()
                    index = index - 1  # return token to input
            elif in_element == "reject":
                if attr_name == "type":
                    attrs[attr_name] = attr_value
                elif current_element == "limit":
                    in_elements.append("limit")
                else:
                    object.__setattr__(
                        self,
                        "action",
                        Rich_Reject(attrs.get("type"), attrs.get("limit")),
                    )
                    in_elements.pop()  # accept
                    attrs.clear()
                    index = index - 1  # return token to input
            elif in_element == "mark":
                if attr_name == "set":
                    attrs[attr_name] = attr_value
                elif current_element == "limit":
                    in_elements.append("limit")
                else:
                    object.__setattr__(
                        self, "action", Rich_Mark(attrs.get("set"), attrs.get("limit"))
                    )
                    in_elements.pop()  # accept
                    attrs.clear()
                    index = index - 1  # return token to input
            elif in_element == "limit":
                if attr_name in ["value", "burst"]:
                    attrs[f"limit.{attr_name}"] = attr_value
                else:
                    if "limit.value" not in attrs:
                        raise FirewallError(
                            errors.INVALID_RULE, "invalid 'limit' element"
                        )
                    attrs["limit"] = Rich_Limit(
                        attrs["limit.value"], attrs.get("limit.burst")
                    )
                    attrs.pop("limit.value", "")
                    attrs.pop("limit.burst", "")
                    in_elements.pop()  # limit
                    index = index - 1  # return token to input

            index = index + 1

    def check(self):
        if self.family:
            if self.family not in ["ipv4", "ipv6"]:
                raise FirewallError(errors.INVALID_FAMILY, self.family)
        else:
            if (
                self.source is not None and self.source.addr
            ) or self.destination is not None:
                raise FirewallError(errors.MISSING_FAMILY)
            if isinstance(self.element, Rich_ForwardPort):
                raise FirewallError(errors.MISSING_FAMILY)

        if self.priority < self.priority_min or self.priority > self.priority_max:
            raise FirewallError(
                errors.INVALID_PRIORITY,
                "'priority' attribute must be between %d and %d."
                % (self.priority_min, self.priority_max),
            )

        if self.element is None and (
            self.log is None or (self.log is not None and self.priority == 0)
        ):
            if self.action is None:
                raise FirewallError(errors.INVALID_RULE, "no element, no action")
            if self.source is None and self.destination is None and self.priority == 0:
                raise FirewallError(
                    errors.INVALID_RULE, "no element, no source, no destination"
                )

        if type(self.element) not in [
            Rich_IcmpBlock,
            Rich_ForwardPort,
            Rich_Masquerade,
            Rich_Tcp_Mss_Clamp,
        ]:
            if self.log is None and self.audit is None and self.action is None:
                raise FirewallError(errors.INVALID_RULE, "no action, no log, no audit")

        if self.source and self.source.addr:
            if not self.family:
                raise FirewallError(errors.INVALID_FAMILY)
            if not functions.check_address(self.family, self.source.addr):
                raise FirewallError(errors.INVALID_ADDR, str(self.source.addr))

        if self.destination and self.destination.addr:
            if not functions.check_address(self.family, self.destination.addr):
                raise FirewallError(errors.INVALID_ADDR, str(self.destination.addr))

        if isinstance(self.element, Rich_Masquerade):
            if self.action is not None:
                raise FirewallError(errors.INVALID_RULE, "masquerade and action")
            if self.source is not None and self.source.mac:
                raise FirewallError(errors.INVALID_RULE, "masquerade and mac source")
        elif isinstance(self.element, Rich_IcmpBlock):
            if self.action:
                raise FirewallError(errors.INVALID_RULE, "icmp-block and action")
        elif isinstance(self.element, Rich_ForwardPort):
            if self.element.to_address != "" and not functions.check_single_address(
                self.family, self.element.to_address
            ):
                raise FirewallError(errors.INVALID_ADDR, self.element.to_address)
            if not self.family:
                raise FirewallError(errors.INVALID_FAMILY)
            if self.action is not None:
                raise FirewallError(errors.INVALID_RULE, "forward-port and action")
        elif isinstance(self.element, Rich_Tcp_Mss_Clamp):
            if self.action is not None:
                raise FirewallError(
                    errors.INVALID_RULE,
                    "tcp-mss-clamp and %s are mutually exclusive" % self.action,
                )

        if self.audit is not None:
            if type(self.action) not in [Rich_Accept, Rich_Reject, Rich_Drop]:
                raise FirewallError(errors.INVALID_AUDIT_TYPE, type(self.action))

        if isinstance(self.action, Rich_Reject):
            if self.action.type:
                if self.family not in ["ipv4", "ipv6"]:
                    raise FirewallError(
                        errors.INVALID_RULE,
                        "When using reject type you must specify also rule family.",
                    )
                if self.action.type not in REJECT_TYPES[self.family]:
                    valid_types = ", ".join(REJECT_TYPES[self.family])
                    raise FirewallError(
                        errors.INVALID_RULE,
                        "Wrong reject type %s.\nUse one of: %s."
                        % (self.action.type, valid_types),
                    )

    def __str__(self):
        ret = "rule"
        if self.priority:
            ret += ' priority="%d"' % self.priority
        if self.family:
            ret += ' family="%s"' % self.family
        if self.source:
            ret += " %s" % self.source
        if self.destination:
            ret += " %s" % self.destination
        if self.element:
            ret += " %s" % self.element
        if self.log:
            ret += " %s" % self.log
        if self.audit:
            ret += " %s" % self.audit
        if self.action:
            ret += " %s" % self.action

        return ret
