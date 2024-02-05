# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2013-2016 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>

from firewall import functions
from firewall.core.ipset import check_ipset_name
from firewall.core.base import REJECT_TYPES
from firewall import errors
from firewall.errors import FirewallError


# Dummy class for EOL singleton instance. It's a class, so we
# can overwrite __repr__().
class _EOLType:
    def __repr__(self):
        # The string representation is the full name of the instance.
        return "firewall.core.rich.EOL"


# A EndOfLine singleton instance to indicate EOL token.
EOL = _EOLType()


class _Rich_Entry:
    def check(self, family=None):
        pass


class _Rich_EntryWithLimit(_Rich_Entry):
    def __init__(self, limit=None):
        self.limit = limit

    def check(self, family=None):
        if self.limit is not None:
            self.limit.check(family=family)


class _Rich_Element(_Rich_Entry):
    pass


class _Rich_Action(_Rich_EntryWithLimit):
    pass


class _Rich_Log(_Rich_EntryWithLimit):
    pass


class Rich_Source(_Rich_Entry):
    def __init__(self, addr, mac, ipset, invert=False):
        self.addr = addr
        if self.addr == "":
            self.addr = None
        self.mac = mac
        if self.mac == "" or self.mac is None:
            self.mac = None
        elif self.mac is not None:
            self.mac = self.mac.upper()
        self.ipset = ipset
        if self.ipset == "":
            self.ipset = None
        self.invert = invert
        if self.addr is None and self.mac is None and self.ipset is None:
            raise FirewallError(errors.INVALID_RULE, "no address, mac and ipset")

    def __str__(self):
        ret = "source%s " % (" NOT" if self.invert else "")
        if self.addr is not None:
            return ret + 'address="%s"' % self.addr
        elif self.mac is not None:
            return ret + 'mac="%s"' % self.mac
        elif self.ipset is not None:
            return ret + 'ipset="%s"' % self.ipset
        raise FirewallError(errors.INVALID_RULE, "no address, mac and ipset")

    def check(self, family=None):
        if self.addr is not None:
            if family is None:
                raise FirewallError(errors.INVALID_FAMILY)
            if self.mac is not None:
                raise FirewallError(errors.INVALID_RULE, "address and mac")
            if self.ipset is not None:
                raise FirewallError(errors.INVALID_RULE, "address and ipset")
            if not functions.check_address(family, self.addr):
                raise FirewallError(errors.INVALID_ADDR, str(self.addr))
        elif self.mac is not None:
            if self.ipset is not None:
                raise FirewallError(errors.INVALID_RULE, "mac and ipset")
            if not functions.check_mac(self.mac):
                raise FirewallError(errors.INVALID_MAC, str(self.mac))
        elif self.ipset is not None:
            if not check_ipset_name(self.ipset):
                raise FirewallError(errors.INVALID_IPSET, str(self.ipset))
        else:
            raise FirewallError(errors.INVALID_RULE, "invalid source")


class Rich_Destination(_Rich_Entry):
    def __init__(self, addr, ipset, invert=False):
        self.addr = addr
        if self.addr == "":
            self.addr = None
        self.ipset = ipset
        if self.ipset == "":
            self.ipset = None
        self.invert = invert
        if self.addr is None and self.ipset is None:
            raise FirewallError(errors.INVALID_RULE, "no address and ipset")

    def __str__(self):
        ret = "destination%s " % (" NOT" if self.invert else "")
        if self.addr is not None:
            return ret + 'address="%s"' % self.addr
        elif self.ipset is not None:
            return ret + 'ipset="%s"' % self.ipset
        raise FirewallError(errors.INVALID_RULE, "no address and ipset")

    def check(self, family=None):
        if self.addr is not None:
            if family is None:
                raise FirewallError(errors.INVALID_FAMILY)
            if self.ipset is not None:
                raise FirewallError(errors.INVALID_DESTINATION, "address and ipset")
            if not functions.check_address(family, self.addr):
                raise FirewallError(errors.INVALID_ADDR, str(self.addr))
        elif self.ipset is not None:
            if not check_ipset_name(self.ipset):
                raise FirewallError(errors.INVALID_IPSET, str(self.ipset))
        else:
            raise FirewallError(errors.INVALID_RULE, "invalid destination")


class Rich_Service(_Rich_Element):
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return 'service name="%s"' % (self.name)

    def check(self, family=None):
        if self.name is None or len(self.name) < 1:
            raise FirewallError(errors.INVALID_SERVICE, str(self.name))


class Rich_Port(_Rich_Element):
    def __init__(self, port, protocol):
        self.port = port
        self.protocol = protocol

    def __str__(self):
        return 'port port="%s" protocol="%s"' % (self.port, self.protocol)

    def check(self, family=None):
        if not functions.check_port(self.port):
            raise FirewallError(errors.INVALID_PORT, self.port)
        if self.protocol not in ["tcp", "udp", "sctp", "dccp"]:
            raise FirewallError(errors.INVALID_PROTOCOL, self.protocol)


class Rich_SourcePort(_Rich_Element):
    def __init__(self, port, protocol):
        self.port = port
        self.protocol = protocol

    def __str__(self):
        return 'source-port port="%s" protocol="%s"' % (self.port, self.protocol)

    def check(self, family=None):
        if not functions.check_port(self.port):
            raise FirewallError(errors.INVALID_PORT, self.port)
        if self.protocol not in ["tcp", "udp", "sctp", "dccp"]:
            raise FirewallError(errors.INVALID_PROTOCOL, self.protocol)


class Rich_Protocol(_Rich_Element):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return 'protocol value="%s"' % (self.value)

    def check(self, family=None):
        if not functions.checkProtocol(self.value):
            raise FirewallError(errors.INVALID_PROTOCOL, self.value)


class Rich_Masquerade(_Rich_Element):
    def __str__(self):
        return "masquerade"


class Rich_IcmpBlock(_Rich_Element):
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return 'icmp-block name="%s"' % (self.name)

    def check(self, family=None):
        if self.name is None or len(self.name) < 1:
            raise FirewallError(errors.INVALID_ICMPTYPE, str(self.name))


class Rich_IcmpType(_Rich_Element):
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return 'icmp-type name="%s"' % (self.name)

    def check(self, family=None):
        if self.name is None or len(self.name) < 1:
            raise FirewallError(errors.INVALID_ICMPTYPE, str(self.name))


class Rich_Tcp_Mss_Clamp(_Rich_Element):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        if self.value:
            return 'tcp-mss-clamp value="%s"' % (self.value)
        else:
            return "tcp-mss-clamp"

    def check(self, family=None):
        if self.value:
            if not functions.checkTcpMssClamp(self.value):
                raise FirewallError(errors.INVALID_RULE, self.value)


class Rich_ForwardPort(_Rich_Element):
    def __init__(self, port, protocol, to_port, to_address):
        self.port = port
        self.protocol = protocol
        self.to_port = to_port
        self.to_address = to_address
        # replace None with "" in to_port and/or to_address
        if self.to_port is None:
            self.to_port = ""
        if self.to_address is None:
            self.to_address = ""

    def __str__(self):
        return 'forward-port port="%s" protocol="%s"%s%s' % (
            self.port,
            self.protocol,
            ' to-port="%s"' % self.to_port if self.to_port != "" else "",
            ' to-addr="%s"' % self.to_address if self.to_address != "" else "",
        )

    def check(self, family=None):
        if not functions.check_port(self.port):
            raise FirewallError(errors.INVALID_PORT, self.port)
        if self.protocol not in ["tcp", "udp", "sctp", "dccp"]:
            raise FirewallError(errors.INVALID_PROTOCOL, self.protocol)
        if self.to_port == "" and self.to_address == "":
            raise FirewallError(errors.INVALID_PORT, self.to_port)
        if self.to_port != "" and not functions.check_port(self.to_port):
            raise FirewallError(errors.INVALID_PORT, self.to_port)
        if self.to_address != "" and not functions.check_single_address(
            family, self.to_address
        ):
            raise FirewallError(errors.INVALID_ADDR, self.to_address)
        if family is None:
            raise FirewallError(errors.INVALID_FAMILY)


class Rich_Log(_Rich_Log):
    def __init__(self, prefix=None, level=None, limit=None):
        super().__init__(limit=limit)
        # TODO check default level in iptables
        self.prefix = prefix
        self.level = level

    def __str__(self):
        return "log%s%s%s" % (
            ' prefix="%s"' % (self.prefix) if self.prefix else "",
            ' level="%s"' % (self.level) if self.level else "",
            " %s" % self.limit if self.limit else "",
        )

    def check(self, family=None):
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

        super().check(family=family)


class Rich_NFLog(_Rich_Log):
    def __init__(self, group=None, prefix=None, queue_size=None, limit=None):
        super().__init__(limit=limit)
        self.group = group
        self.prefix = prefix
        self.threshold = queue_size

    def __str__(self):
        return "nflog%s%s%s%s" % (
            ' group="%s"' % (self.group) if self.group else "",
            ' prefix="%s"' % (self.prefix) if self.prefix else "",
            ' queue-size="%s"' % (self.threshold) if self.threshold else "",
            " %s" % self.limit if self.limit else "",
        )

    def check(self, family=None):
        if self.group and not functions.checkUINT16(self.group):
            raise FirewallError(
                errors.INVALID_NFLOG_GROUP,
                "nflog 'group' must be an integer between 0 and 65535.",
            )

        if self.prefix and len(self.prefix) > 127:
            raise FirewallError(
                errors.INVALID_LOG_PREFIX, "maximum accepted length of 'prefix' is 127."
            )

        if self.threshold and not functions.checkUINT16(self.threshold):
            raise FirewallError(
                errors.INVALID_NFLOG_QUEUE,
                "nflog 'queue-size' must be an integer between 0 and 65535.",
            )

        super().check(family=family)


class Rich_Audit(_Rich_EntryWithLimit):
    def __init__(self, limit=None):
        # TODO check default level in iptables
        super().__init__(limit=limit)

    def __str__(self):
        return "audit%s" % (" %s" % self.limit if self.limit else "")


class Rich_Accept(_Rich_Action):
    def __init__(self, limit=None):
        super().__init__(limit=limit)

    def __str__(self):
        return "accept%s" % (" %s" % self.limit if self.limit else "")


class Rich_Reject(_Rich_Action):
    def __init__(self, _type=None, limit=None):
        super().__init__(limit=limit)
        self.type = _type

    def __str__(self):
        return "reject%s%s" % (
            ' type="%s"' % self.type if self.type else "",
            " %s" % self.limit if self.limit else "",
        )

    def check(self, family=None):
        if self.type:
            if family not in ["ipv4", "ipv6"]:
                raise FirewallError(
                    errors.INVALID_RULE,
                    "When using reject type you must specify also rule family.",
                )
            if self.type not in REJECT_TYPES[family]:
                valid_types = ", ".join(REJECT_TYPES[family])
                raise FirewallError(
                    errors.INVALID_RULE,
                    "Wrong reject type %s.\nUse one of: %s." % (self.type, valid_types),
                )

        super().check(family=family)


class Rich_Drop(_Rich_Action):
    def __init__(self, limit=None):
        super().__init__(limit=limit)

    def __str__(self):
        return "drop%s" % (" %s" % self.limit if self.limit else "")


class Rich_Mark(_Rich_Action):
    def __init__(self, _set, limit=None):
        super().__init__(limit=limit)
        self.set = _set

    def __str__(self):
        return "mark set=%s%s" % (self.set, " %s" % self.limit if self.limit else "")

    def check(self, family=None):
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

        super().check(family=family)


class Rich_Limit(_Rich_Entry):
    def __init__(self, value):
        self.value = value
        if "/" in self.value:
            splits = self.value.split("/")
            if len(splits) == 2 and splits[1] in ["second", "minute", "hour", "day"]:
                self.value = "%s/%s" % (splits[0], splits[1][:1])

    def check(self, family=None):
        splits = None
        if "/" in self.value:
            splits = self.value.split("/")
        if not splits or len(splits) != 2:
            raise FirewallError(errors.INVALID_LIMIT, self.value)
        (rate, duration) = splits
        try:
            rate = int(rate)
        except:
            raise FirewallError(errors.INVALID_LIMIT, self.value)

        if rate < 1 or duration not in ["s", "m", "h", "d"]:
            raise FirewallError(errors.INVALID_LIMIT, self.value)

        mult = 1
        if duration == "s":
            mult = 1
        elif duration == "m":
            mult = 60
        elif duration == "h":
            mult = 60 * 60
        elif duration == "d":
            mult = 24 * 60 * 60

        if 10000 * mult // rate == 0:
            raise FirewallError(errors.INVALID_LIMIT, "%s too fast" % self.value)

        if rate == 1 and duration == "d":
            # iptables (v1.4.21) doesn't accept 1/d
            raise FirewallError(errors.INVALID_LIMIT, "%s too slow" % self.value)

    def __str__(self):
        return 'limit value="%s"' % (self.value)

    def command(self):
        return ""


class Rich_Rule:
    priority_min = -32768
    priority_max = 32767

    def __init__(self, family=None, rule_str=None, priority=None):
        self.family = None
        self.priority = 0
        self.source = None
        self.destination = None
        self.element = None
        self.log = None
        self.audit = None
        self.action = None

        if rule_str is not None:
            self._import_from_string(rule_str)

        if priority is not None:
            self.priority = priority

        if family is not None:
            family = str(family)
            if self.family is None:
                self.family = family
            elif self.family != family:
                raise FirewallError(errors.INVALID_FAMILY, family)

        if rule_str is not None:
            self.check()

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
            element = tokens[index].get("element")
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
                ]:
                    raise FirewallError(
                        errors.INVALID_RULE, "bad attribute '%s'" % attr_name
                    )
            else:  # element
                if element in [
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
                    if element == "source" and self.source:
                        raise FirewallError(
                            errors.INVALID_RULE, "more than one 'source' element"
                        )
                    elif element == "destination" and self.destination:
                        raise FirewallError(
                            errors.INVALID_RULE, "more than one 'destination' element"
                        )
                    elif (
                        element
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
                            % (element, self.element),
                        )
                    elif element in ["log", "nflog"] and self.log:
                        raise FirewallError(
                            errors.INVALID_RULE, "more than one logging element"
                        )
                    elif element == "audit" and self.audit:
                        raise FirewallError(
                            errors.INVALID_RULE, "more than one 'audit' element"
                        )
                    elif (
                        element in ["accept", "drop", "reject", "mark"] and self.action
                    ):
                        raise FirewallError(
                            errors.INVALID_RULE,
                            "more than one 'action' element. There cannot be both '%s' and '%s' in one rule."
                            % (element, self.action),
                        )
                else:
                    raise FirewallError(
                        errors.INVALID_RULE, "unknown element %s" % element
                    )

            in_element = (
                in_elements[len(in_elements) - 1] if len(in_elements) > 0 else ""
            )

            if in_element == "":
                if not element and attr_name:
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
                elif "rule" not in element:
                    raise FirewallError(
                        errors.INVALID_RULE,
                        "'%s' outside of rule. Use 'rule ... %s ...'."
                        % (element, element),
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
                    self.family = attr_value
                elif attr_name == "priority":
                    try:
                        self.priority = int(attr_value)
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
                    in_elements.append(element)  # push into stack
            elif in_element == "source":
                if attr_name in ["address", "mac", "ipset", "invert"]:
                    attrs[attr_name] = attr_value
                elif element in ["not", "NOT"]:
                    attrs["invert"] = True
                else:
                    self.source = Rich_Source(
                        attrs.get("address"),
                        attrs.get("mac"),
                        attrs.get("ipset"),
                        attrs.get("invert", False),
                    )
                    in_elements.pop()  # source
                    attrs.clear()
                    index = index - 1  # return token to input
            elif in_element == "destination":
                if attr_name in ["address", "ipset", "invert"]:
                    attrs[attr_name] = attr_value
                elif element in ["not", "NOT"]:
                    attrs["invert"] = True
                else:
                    self.destination = Rich_Destination(
                        attrs.get("address"),
                        attrs.get("ipset"),
                        attrs.get("invert", False),
                    )
                    in_elements.pop()  # destination
                    attrs.clear()
                    index = index - 1  # return token to input
            elif in_element == "protocol":
                if attr_name == "value":
                    self.element = Rich_Protocol(attr_value)
                    in_elements.pop()  # protocol
                else:
                    raise FirewallError(
                        errors.INVALID_RULE, "invalid 'protocol' element"
                    )
            elif in_element == "tcp-mss-clamp":
                if attr_name == "value":
                    attrs[attr_name] = attr_value
                else:
                    self.element = Rich_Tcp_Mss_Clamp(attrs.get("value"))
                    in_elements.pop()
                    attrs.clear()
                    index = index - 1
            elif in_element == "service":
                if attr_name == "name":
                    self.element = Rich_Service(attr_value)
                    in_elements.pop()  # service
                else:
                    raise FirewallError(
                        errors.INVALID_RULE, "invalid 'service' element"
                    )
            elif in_element == "port":
                if attr_name in ["port", "protocol"]:
                    attrs[attr_name] = attr_value
                else:
                    self.element = Rich_Port(attrs.get("port"), attrs.get("protocol"))
                    in_elements.pop()  # port
                    attrs.clear()
                    index = index - 1  # return token to input
            elif in_element == "icmp-block":
                if attr_name == "name":
                    self.element = Rich_IcmpBlock(attr_value)
                    in_elements.pop()  # icmp-block
                else:
                    raise FirewallError(
                        errors.INVALID_RULE, "invalid 'icmp-block' element"
                    )
            elif in_element == "icmp-type":
                if attr_name == "name":
                    self.element = Rich_IcmpType(attr_value)
                    in_elements.pop()  # icmp-type
                else:
                    raise FirewallError(
                        errors.INVALID_RULE, "invalid 'icmp-type' element"
                    )
            elif in_element == "masquerade":
                self.element = Rich_Masquerade()
                in_elements.pop()
                attrs.clear()
                index = index - 1  # return token to input
            elif in_element == "forward-port":
                if attr_name in ["port", "protocol", "to-port", "to-addr"]:
                    attrs[attr_name] = attr_value
                else:
                    self.element = Rich_ForwardPort(
                        attrs.get("port"),
                        attrs.get("protocol"),
                        attrs.get("to-port"),
                        attrs.get("to-addr"),
                    )
                    in_elements.pop()  # forward-port
                    attrs.clear()
                    index = index - 1  # return token to input
            elif in_element == "source-port":
                if attr_name in ["port", "protocol"]:
                    attrs[attr_name] = attr_value
                else:
                    self.element = Rich_SourcePort(
                        attrs.get("port"), attrs.get("protocol")
                    )
                    in_elements.pop()  # source-port
                    attrs.clear()
                    index = index - 1  # return token to input
            elif in_element == "log":
                if attr_name in ["prefix", "level"]:
                    attrs[attr_name] = attr_value
                elif element == "limit":
                    in_elements.append("limit")
                else:
                    self.log = Rich_Log(
                        attrs.get("prefix"), attrs.get("level"), attrs.get("limit")
                    )
                    in_elements.pop()  # log
                    attrs.clear()
                    index = index - 1  # return token to input
            elif in_element == "nflog":
                if attr_name in ["group", "prefix", "queue-size"]:
                    attrs[attr_name] = attr_value
                elif element == "limit":
                    in_elements.append("limit")
                else:
                    self.log = Rich_NFLog(
                        attrs.get("group"),
                        attrs.get("prefix"),
                        attrs.get("queue-size"),
                        attrs.get("limit"),
                    )
                    in_elements.pop()  # nflog
                    attrs.clear()
                    index = index - 1  # return token to input
            elif in_element == "audit":
                if element == "limit":
                    in_elements.append("limit")
                else:
                    self.audit = Rich_Audit(attrs.get("limit"))
                    in_elements.pop()  # audit
                    attrs.clear()
                    index = index - 1  # return token to input
            elif in_element == "accept":
                if element == "limit":
                    in_elements.append("limit")
                else:
                    self.action = Rich_Accept(attrs.get("limit"))
                    in_elements.pop()  # accept
                    attrs.clear()
                    index = index - 1  # return token to input
            elif in_element == "drop":
                if element == "limit":
                    in_elements.append("limit")
                else:
                    self.action = Rich_Drop(attrs.get("limit"))
                    in_elements.pop()  # drop
                    attrs.clear()
                    index = index - 1  # return token to input
            elif in_element == "reject":
                if attr_name == "type":
                    attrs[attr_name] = attr_value
                elif element == "limit":
                    in_elements.append("limit")
                else:
                    self.action = Rich_Reject(attrs.get("type"), attrs.get("limit"))
                    in_elements.pop()  # accept
                    attrs.clear()
                    index = index - 1  # return token to input
            elif in_element == "mark":
                if attr_name == "set":
                    attrs[attr_name] = attr_value
                elif element == "limit":
                    in_elements.append("limit")
                else:
                    self.action = Rich_Mark(attrs.get("set"), attrs.get("limit"))
                    in_elements.pop()  # accept
                    attrs.clear()
                    index = index - 1  # return token to input
            elif in_element == "limit":
                if attr_name == "value":
                    attrs["limit"] = Rich_Limit(attr_value)
                    in_elements.pop()  # limit
                else:
                    raise FirewallError(errors.INVALID_RULE, "invalid 'limit' element")

            index = index + 1

    def _check_entry(self, entry):
        if entry is not None:
            entry.check(family=self.family)

    def check(self):
        if self.family is not None:
            if self.family not in ["ipv4", "ipv6"]:
                raise FirewallError(errors.INVALID_FAMILY, self.family)
        else:
            if (
                self.source is not None and self.source.addr is not None
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

        self._check_entry(self.source)
        self._check_entry(self.destination)

        self._check_entry(self.element)

        if isinstance(self.element, Rich_Masquerade):
            if self.action is not None:
                raise FirewallError(errors.INVALID_RULE, "masquerade and action")
            if self.source is not None and self.source.mac is not None:
                raise FirewallError(errors.INVALID_RULE, "masquerade and mac source")
        elif isinstance(self.element, Rich_IcmpBlock):
            if self.action:
                raise FirewallError(errors.INVALID_RULE, "icmp-block and action")
        elif isinstance(self.element, Rich_ForwardPort):
            if self.action is not None:
                raise FirewallError(errors.INVALID_RULE, "forward-port and action")
        elif isinstance(self.element, Rich_Tcp_Mss_Clamp):
            if self.action is not None:
                raise FirewallError(
                    errors.INVALID_RULE,
                    "tcp-mss-clamp and %s are mutually exclusive" % self.action,
                )

        self._check_entry(self.log)

        if self.audit is not None:
            if type(self.action) not in [Rich_Accept, Rich_Reject, Rich_Drop]:
                raise FirewallError(errors.INVALID_AUDIT_TYPE, type(self.action))

        self._check_entry(self.audit)
        self._check_entry(self.action)

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


# class Rich_RawRule:
# class Rich_RuleSet:
# class Rich_AddressList:
