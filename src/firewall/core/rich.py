# -*- coding: utf-8 -*-
#
# Copyright (C) 2013-2016 Red Hat, Inc.
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

__all__ = [ "Rich_Source", "Rich_Destination", "Rich_Service", "Rich_Port",
            "Rich_Protocol", "Rich_Masquerade", "Rich_IcmpBlock",
            "Rich_IcmpType",
            "Rich_SourcePort", "Rich_ForwardPort", "Rich_Log", "Rich_Audit",
            "Rich_Accept", "Rich_Reject", "Rich_Drop", "Rich_Mark",
            "Rich_Limit", "Rich_Rule", "Rich_Tcp_Mss_Clamp" ]

from firewall import functions
from firewall.core.ipset import check_ipset_name
from firewall.core.base import REJECT_TYPES
from firewall import errors
from firewall.errors import FirewallError

class Rich_Source(object):
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
            raise FirewallError(errors.INVALID_RULE,
                                "no address, mac and ipset")

    def __str__(self):
        ret = 'source%s ' % (" NOT" if self.invert else "")
        if self.addr is not None:
            return ret + 'address="%s"' % self.addr
        elif self.mac is not None:
            return ret + 'mac="%s"' % self.mac
        elif self.ipset is not None:
            return ret + 'ipset="%s"' % self.ipset
        else:
            raise FirewallError(errors.INVALID_RULE,
                                "no address, mac and ipset")

class Rich_Destination(object):
    def __init__(self, addr, ipset, invert=False):
        self.addr = addr
        if self.addr == "":
            self.addr = None
        self.ipset = ipset
        if self.ipset == "":
            self.ipset = None
        self.invert = invert
        if self.addr is None and self.ipset is None:
            raise FirewallError(errors.INVALID_RULE,
                                "no address and ipset")

    def __str__(self):
        ret = 'destination%s ' % (" NOT" if self.invert else "")
        if self.addr is not None:
            return ret + 'address="%s"' % self.addr
        elif self.ipset is not None:
            return ret + 'ipset="%s"' % self.ipset
        else:
            raise FirewallError(errors.INVALID_RULE,
                                "no address and ipset")

class Rich_Service(object):
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return 'service name="%s"' % (self.name)

class Rich_Port(object):
    def __init__(self, port, protocol):
        self.port = port
        self.protocol = protocol

    def __str__(self):
        return 'port port="%s" protocol="%s"' % (self.port, self.protocol)

class Rich_SourcePort(Rich_Port):
    def __str__(self):
        return 'source-port port="%s" protocol="%s"' % (self.port,
                                                        self.protocol)

class Rich_Protocol(object):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return 'protocol value="%s"' % (self.value)

class Rich_Masquerade(object):
    def __init__(self):
        pass

    def __str__(self):
        return 'masquerade'

class Rich_IcmpBlock(object):
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return 'icmp-block name="%s"' % (self.name)

class Rich_IcmpType(object):
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return 'icmp-type name="%s"' % (self.name)

class Rich_Tcp_Mss_Clamp(object):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return 'tcp-mss-clamp value="%s"' % (self.value)

class Rich_ForwardPort(object):
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
        return 'forward-port port="%s" protocol="%s"%s%s' % \
            (self.port, self.protocol,
             ' to-port="%s"' % self.to_port if self.to_port != "" else '',
             ' to-addr="%s"' % self.to_address if self.to_address != "" else '')

class Rich_Log(object):
    def __init__(self, prefix=None, level=None, limit=None):
        #TODO check default level in iptables
        self.prefix = prefix
        self.level = level
        self.limit = limit

    def __str__(self):
        return 'log%s%s%s' % \
            (' prefix="%s"' % (self.prefix) if self.prefix else "",
             ' level="%s"' % (self.level) if self.level else "",
             " %s" % self.limit if self.limit else "")

class Rich_Audit(object):
    def __init__(self, limit=None):
        #TODO check default level in iptables
        self.limit = limit

    def __str__(self):
        return 'audit%s' % (" %s" % self.limit if self.limit else "")

class Rich_Accept(object):
    def __init__(self, limit=None):
        self.limit = limit

    def __str__(self):
        return "accept%s" % (" %s" % self.limit if self.limit else "")

class Rich_Reject(object):
    def __init__(self, _type=None, limit=None):
        self.type = _type
        self.limit = limit

    def __str__(self):
        return "reject%s%s" % (' type="%s"' % self.type if self.type else "",
                               " %s" % self.limit if self.limit else "")

    def check(self, family):
        if self.type:
            if not family:
                raise FirewallError(errors.INVALID_RULE, "When using reject type you must specify also rule family.")
            if family in ['ipv4', 'ipv6'] and \
               self.type not in REJECT_TYPES[family]:
                valid_types = ", ".join(REJECT_TYPES[family])
                raise FirewallError(errors.INVALID_RULE, "Wrong reject type %s.\nUse one of: %s." % (self.type, valid_types))

class Rich_Drop(Rich_Accept):
    def __str__(self):
        return "drop%s" % (" %s" % self.limit if self.limit else "")


class Rich_Mark(object):
    def __init__(self, _set, limit=None):
        self.set = _set
        self.limit = limit

    def __str__(self):
        return "mark set=%s%s" % (self.set,
                                  " %s" % self.limit if self.limit else "")

    def check(self):
        if self.set is not None:
            x = self.set
        else:
            raise FirewallError(errors.INVALID_MARK, "no value set")

        if "/" in x:
            splits = x.split("/")
            if len(splits) != 2:
                raise FirewallError(errors.INVALID_MARK, x)
            if not functions.checkUINT32(splits[0]) or \
               not functions.checkUINT32(splits[1]):
                # value and mask are uint32
                raise FirewallError(errors.INVALID_MARK, x)
        else:
            if not functions.checkUINT32(x):
                # value is uint32
                raise FirewallError(errors.INVALID_MARK, x)

class Rich_Limit(object):
    def __init__(self, value):
        self.value = value
        if "/" in self.value:
            splits = self.value.split("/")
            if len(splits) == 2 and \
               splits[1] in [ "second", "minute", "hour", "day" ]:
                self.value = "%s/%s" % (splits[0], splits[1][:1])

    def check(self):
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

        if rate < 1 or duration not in [ "s", "m", "h", "d" ]:
            raise FirewallError(errors.INVALID_LIMIT, self.value)

        mult = 1
        if duration == "s":
            mult = 1
        elif duration == "m":
            mult = 60
        elif duration == "h":
            mult = 60*60
        elif duration == "d":
            mult = 24*60*60

        if 10000 * mult / rate == 0:
            raise FirewallError(errors.INVALID_LIMIT,
                                "%s too fast" % self.value)

        if rate == 1 and duration == "d":
            # iptables (v1.4.21) doesn't accept 1/d
            raise FirewallError(errors.INVALID_LIMIT,
                                "%s too slow" % self.value)

    def __str__(self):
        return 'limit value="%s"' % (self.value)

    def command(self):
        return ''

class Rich_Rule(object):
    priority_min = -32768
    priority_max =  32767

    def __init__(self, family=None, rule_str=None, priority=0):
        if family is not None:
            self.family = str(family)
        else:
            self.family = None

        self.priority = priority
        self.source = None
        self.destination = None
        self.element = None
        self.log = None
        self.audit = None
        self.action = None

        if rule_str:
            self._import_from_string(rule_str)

    def _lexer(self, rule_str):
        """ Lexical analysis """
        tokens = []

        for r in functions.splitArgs(rule_str):
            if "=" in r:
                attr = r.split('=')
                if len(attr) != 2 or not attr[0] or not attr[1]:
                    raise FirewallError(errors.INVALID_RULE,
                                        'internal error in _lexer(): %s' % r)
                tokens.append({'attr_name':attr[0], 'attr_value':attr[1]})
            else:
                tokens.append({'element':r})
        tokens.append({'element':'EOL'})

        return tokens

    def _import_from_string(self, rule_str):
        if not rule_str:
            raise FirewallError(errors.INVALID_RULE, 'empty rule')

        rule_str = functions.stripNonPrintableCharacters(rule_str)

        self.priority = 0
        self.family = None
        self.source = None
        self.destination = None
        self.element = None
        self.log = None
        self.audit = None
        self.action = None

        tokens = self._lexer(rule_str)
        if tokens and tokens[0].get('element')  == 'EOL':
            raise FirewallError(errors.INVALID_RULE, 'empty rule')

        attrs = {}       # attributes of elements
        in_elements = [] # stack with elements we are in
        index = 0        # index into tokens
        while not (tokens[index].get('element')  == 'EOL' and in_elements == ['rule']):
            element = tokens[index].get('element')
            attr_name = tokens[index].get('attr_name')
            attr_value = tokens[index].get('attr_value')
            #print ("in_elements: ", in_elements)
            #print ("index: %s, element: %s, attribute: %s=%s" % (index, element, attr_name, attr_value))
            if attr_name:     # attribute
                if attr_name not in ['priority', 'family', 'address', 'mac', 'ipset',
                                     'invert', 'value',
                                     'port', 'protocol', 'to-port', 'to-addr',
                                     'name', 'prefix', 'level', 'type',
                                     'set']:
                    raise FirewallError(errors.INVALID_RULE, "bad attribute '%s'" % attr_name)
            else:             # element
                if element in ['rule', 'source', 'destination', 'protocol',
                               'service', 'port', 'icmp-block', 'icmp-type', 'masquerade',
                               'forward-port', 'source-port', 'log', 'audit',
                               'accept', 'drop', 'reject', 'mark', 'limit', 'not', 'NOT', 'EOL', 'tcp-mss-clamp']:
                    if element == 'source' and self.source:
                        raise FirewallError(errors.INVALID_RULE, "more than one 'source' element")
                    elif element == 'destination' and self.destination:
                        raise FirewallError(errors.INVALID_RULE, "more than one 'destination' element")
                    elif element in ['protocol', 'service', 'port',
                                     'icmp-block', 'icmp-type',
                                     'masquerade', 'forward-port',
                                     'source-port'] and self.element:
                        raise FirewallError(errors.INVALID_RULE, "more than one element. There cannot be both '%s' and '%s' in one rule." % (element, self.element))
                    elif element == 'log' and self.log:
                        raise FirewallError(errors.INVALID_RULE, "more than one 'log' element")
                    elif element == 'audit' and self.audit:
                        raise FirewallError(errors.INVALID_RULE, "more than one 'audit' element")
                    elif element in ['accept', 'drop', 'reject', 'mark'] and self.action:
                        raise FirewallError(errors.INVALID_RULE, "more than one 'action' element. There cannot be both '%s' and '%s' in one rule." % (element, self.action))
                else:
                    raise FirewallError(errors.INVALID_RULE, "unknown element %s" % element)

            in_element = in_elements[len(in_elements)-1] if len(in_elements) > 0 else ''

            if in_element == '':
                if not element and attr_name:
                    if attr_name == 'family':
                        raise FirewallError(errors.INVALID_RULE, "'family' outside of rule. Use 'rule family=...'.")
                    elif attr_name == 'priority':
                        raise FirewallError(errors.INVALID_RULE, "'priority' outside of rule. Use 'rule priority=...'.")
                    else:
                        raise FirewallError(errors.INVALID_RULE, "'%s' outside of any element. Use 'rule <element> %s= ...'." % (attr_name, attr_name))
                elif 'rule' not in element:
                    raise FirewallError(errors.INVALID_RULE, "'%s' outside of rule. Use 'rule ... %s ...'." % (element, element))
                else:
                    in_elements.append('rule') # push into stack
            elif in_element == 'rule':
                if attr_name == 'family':
                    if attr_value not in ['ipv4', 'ipv6']:
                        raise FirewallError(errors.INVALID_RULE, "'family' attribute cannot have '%s' value. Use 'ipv4' or 'ipv6' instead." % attr_value)
                    self.family = attr_value
                elif attr_name == 'priority':
                    try:
                        self.priority = int(attr_value)
                    except ValueError:
                        raise FirewallError(errors.INVALID_PRIORITY, "invalid 'priority' attribute value '%s'." % attr_value)
                elif attr_name:
                    if attr_name == 'protocol':
                        err_msg = "wrong 'protocol' usage. Use either 'rule protocol value=...' or  'rule [forward-]port protocol=...'."
                    else:
                        err_msg = "attribute '%s' outside of any element. Use 'rule <element> %s= ...'." % (attr_name, attr_name)
                    raise FirewallError(errors.INVALID_RULE, err_msg)
                else:
                    in_elements.append(element) # push into stack
            elif in_element == 'source':
                if attr_name in ['address', 'mac', 'ipset', 'invert']:
                    attrs[attr_name] = attr_value
                elif element in ['not', 'NOT']:
                    attrs['invert'] = True
                else:
                    self.source = Rich_Source(attrs.get('address'), attrs.get('mac'), attrs.get('ipset'), attrs.get('invert', False))
                    in_elements.pop() # source
                    attrs.clear()
                    index = index -1 # return token to input
            elif in_element == 'destination':
                if attr_name in ['address', 'ipset', 'invert']:
                    attrs[attr_name] = attr_value
                elif element in ['not', 'NOT']:
                    attrs['invert'] = True
                else:
                    self.destination = Rich_Destination(attrs.get('address'), attrs.get('ipset'), attrs.get('invert', False))
                    in_elements.pop() # destination
                    attrs.clear()
                    index = index -1 # return token to input
            elif in_element == 'protocol':
                if attr_name == 'value':
                    self.element = Rich_Protocol(attr_value)
                    in_elements.pop() # protocol
                else:
                    raise FirewallError(errors.INVALID_RULE, "invalid 'protocol' element")
            elif in_element == 'tcp-mss-clamp':
                if attr_name == 'value':
                    attrs[attr_name] = attr_value
                else:
                    self.element = Rich_Tcp_Mss_Clamp(attrs.get('value'))
                    in_elements.pop()
                    attrs.clear()
                    index = index -1
            elif in_element == 'service':
                if attr_name == 'name':
                    self.element = Rich_Service(attr_value)
                    in_elements.pop() # service
                else:
                    raise FirewallError(errors.INVALID_RULE, "invalid 'service' element")
            elif in_element == 'port':
                if attr_name in ['port', 'protocol']:
                    attrs[attr_name] = attr_value
                else:
                    self.element = Rich_Port(attrs.get('port'), attrs.get('protocol'))
                    in_elements.pop() # port
                    attrs.clear()
                    index = index -1 # return token to input
            elif in_element == 'icmp-block':
                if attr_name == 'name':
                    self.element = Rich_IcmpBlock(attr_value)
                    in_elements.pop() # icmp-block
                else:
                    raise FirewallError(errors.INVALID_RULE, "invalid 'icmp-block' element")
            elif in_element == 'icmp-type':
                if attr_name == 'name':
                    self.element = Rich_IcmpType(attr_value)
                    in_elements.pop() # icmp-type
                else:
                    raise FirewallError(errors.INVALID_RULE, "invalid 'icmp-type' element")
            elif in_element == 'masquerade':
                self.element = Rich_Masquerade()
                in_elements.pop()
                attrs.clear()
                index = index -1 # return token to input
            elif in_element == 'forward-port':
                if attr_name in ['port', 'protocol', 'to-port', 'to-addr']:
                    attrs[attr_name] = attr_value
                else:
                    self.element = Rich_ForwardPort(attrs.get('port'), attrs.get('protocol'), attrs.get('to-port'), attrs.get('to-addr'))
                    in_elements.pop() # forward-port
                    attrs.clear()
                    index = index -1 # return token to input
            elif in_element == 'source-port':
                if attr_name in ['port', 'protocol']:
                    attrs[attr_name] = attr_value
                else:
                    self.element = Rich_SourcePort(attrs.get('port'), attrs.get('protocol'))
                    in_elements.pop() # source-port
                    attrs.clear()
                    index = index -1 # return token to input
            elif in_element == 'log':
                if attr_name in ['prefix', 'level']:
                    attrs[attr_name] = attr_value
                elif element == 'limit':
                    in_elements.append('limit')
                else:
                    self.log = Rich_Log(attrs.get('prefix'), attrs.get('level'), attrs.get('limit'))
                    in_elements.pop() # log
                    attrs.clear()
                    index = index -1 # return token to input
            elif in_element == 'audit':
                if element == 'limit':
                    in_elements.append('limit')
                else:
                    self.audit = Rich_Audit(attrs.get('limit'))
                    in_elements.pop() # audit
                    attrs.clear()
                    index = index -1 # return token to input
            elif in_element == 'accept':
                if element == 'limit':
                    in_elements.append('limit')
                else:
                    self.action = Rich_Accept(attrs.get('limit'))
                    in_elements.pop() # accept
                    attrs.clear()
                    index = index -1 # return token to input
            elif in_element == 'drop':
                if element == 'limit':
                    in_elements.append('limit')
                else:
                    self.action = Rich_Drop(attrs.get('limit'))
                    in_elements.pop() # drop
                    attrs.clear()
                    index = index -1 # return token to input
            elif in_element == 'reject':
                if attr_name == 'type':
                    attrs[attr_name] = attr_value
                elif element == 'limit':
                    in_elements.append('limit')
                else:
                    self.action = Rich_Reject(attrs.get('type'), attrs.get('limit'))
                    in_elements.pop() # accept
                    attrs.clear()
                    index = index -1 # return token to input
            elif in_element == 'mark':
                if attr_name == 'set':
                    attrs[attr_name] = attr_value
                elif element == 'limit':
                    in_elements.append('limit')
                else:
                    self.action = Rich_Mark(attrs.get('set'),
                                            attrs.get('limit'))
                    in_elements.pop() # accept
                    attrs.clear()
                    index = index -1 # return token to input
            elif in_element == 'limit':
                if attr_name == 'value':
                    attrs['limit'] = Rich_Limit(attr_value)
                    in_elements.pop() # limit
                else:
                    raise FirewallError(errors.INVALID_RULE, "invalid 'limit' element")

            index = index + 1

        self.check()

    def check(self):
        if self.family is not None and self.family not in [ "ipv4", "ipv6" ]:
            raise FirewallError(errors.INVALID_FAMILY, self.family)
        if self.family is None:
            if (self.source is not None and self.source.addr is not None) or \
               self.destination is not None:
                raise FirewallError(errors.MISSING_FAMILY)
            if type(self.element) == Rich_ForwardPort:
                raise FirewallError(errors.MISSING_FAMILY)

        if self.priority < self.priority_min or self.priority > self.priority_max:
            raise FirewallError(errors.INVALID_PRIORITY, "'priority' attribute must be between %d and %d." \
                                                         % (self.priority_min, self.priority_max))

        if self.element is None and \
           (self.log is None or (self.log is not None and self.priority == 0)):
            if self.action is None:
                raise FirewallError(errors.INVALID_RULE, "no element, no action")
            if self.source is None and self.destination is None and self.priority == 0:
                raise FirewallError(errors.INVALID_RULE, "no element, no source, no destination")

        if type(self.element) not in [ Rich_IcmpBlock,
                                       Rich_ForwardPort,
                                       Rich_Masquerade,
                                       Rich_Tcp_Mss_Clamp ]:
            if self.log is None and self.audit is None and \
                    self.action is None:
                raise FirewallError(errors.INVALID_RULE, "no action, no log, no audit")

        # source
        if self.source is not None:
            if self.source.addr is not None:
                if self.family is None:
                    raise FirewallError(errors.INVALID_FAMILY)
                if self.source.mac is not None:
                    raise FirewallError(errors.INVALID_RULE, "address and mac")
                if self.source.ipset is not None:
                    raise FirewallError(errors.INVALID_RULE, "address and ipset")
                if not functions.check_address(self.family, self.source.addr):
                    raise FirewallError(errors.INVALID_ADDR, str(self.source.addr))

            elif self.source.mac is not None:
                if self.source.ipset is not None:
                    raise FirewallError(errors.INVALID_RULE, "mac and ipset")
                if not functions.check_mac(self.source.mac):
                    raise FirewallError(errors.INVALID_MAC, str(self.source.mac))

            elif self.source.ipset is not None:
                if not check_ipset_name(self.source.ipset):
                    raise FirewallError(errors.INVALID_IPSET, str(self.source.ipset))

            else:
                raise FirewallError(errors.INVALID_RULE, "invalid source")

        # destination
        if self.destination is not None:
            if self.destination.addr is not None:
                if self.family is None:
                    raise FirewallError(errors.INVALID_FAMILY)
                if self.destination.ipset is not None:
                    raise FirewallError(errors.INVALID_DESTINATION, "address and ipset")
                if not functions.check_address(self.family, self.destination.addr):
                    raise FirewallError(errors.INVALID_ADDR, str(self.destination.addr))

            elif self.destination.ipset is not None:
                if not check_ipset_name(self.destination.ipset):
                    raise FirewallError(errors.INVALID_IPSET, str(self.destination.ipset))

            else:
                raise FirewallError(errors.INVALID_RULE, "invalid destination")

        # service
        if type(self.element) == Rich_Service:
            # service availability needs to be checked in Firewall, here is no
            # knowledge about this, therefore only simple check
            if self.element.name is None or len(self.element.name) < 1:
                raise FirewallError(errors.INVALID_SERVICE, str(self.element.name))

        # port
        elif type(self.element) == Rich_Port:
            if not functions.check_port(self.element.port):
                raise FirewallError(errors.INVALID_PORT, self.element.port)
            if self.element.protocol not in [ "tcp", "udp", "sctp", "dccp" ]:
                raise FirewallError(errors.INVALID_PROTOCOL, self.element.protocol)

        # protocol
        elif type(self.element) == Rich_Protocol:
            if not functions.checkProtocol(self.element.value):
                raise FirewallError(errors.INVALID_PROTOCOL, self.element.value)

        # masquerade
        elif type(self.element) == Rich_Masquerade:
            if self.action is not None:
                raise FirewallError(errors.INVALID_RULE, "masquerade and action")
            if self.source is not None and self.source.mac is not None:
                raise FirewallError(errors.INVALID_RULE, "masquerade and mac source")

        # icmp-block
        elif type(self.element) == Rich_IcmpBlock:
            # icmp type availability needs to be checked in Firewall, here is no
            # knowledge about this, therefore only simple check
            if self.element.name is None or len(self.element.name) < 1:
                raise FirewallError(errors.INVALID_ICMPTYPE, str(self.element.name))
            if self.action:
                raise FirewallError(errors.INVALID_RULE, "icmp-block and action")

        # icmp-type
        elif type(self.element) == Rich_IcmpType:
            # icmp type availability needs to be checked in Firewall, here is no
            # knowledge about this, therefore only simple check
            if self.element.name is None or len(self.element.name) < 1:
                raise FirewallError(errors.INVALID_ICMPTYPE, str(self.element.name))

        # forward-port
        elif type(self.element) == Rich_ForwardPort:
            if not functions.check_port(self.element.port):
                raise FirewallError(errors.INVALID_PORT, self.element.port)
            if self.element.protocol not in [ "tcp", "udp", "sctp", "dccp" ]:
                raise FirewallError(errors.INVALID_PROTOCOL, self.element.protocol)
            if self.element.to_port == "" and self.element.to_address == "":
                raise FirewallError(errors.INVALID_PORT, self.element.to_port)
            if self.element.to_port != "" and \
                    not functions.check_port(self.element.to_port):
                raise FirewallError(errors.INVALID_PORT, self.element.to_port)
            if self.element.to_address != "" and \
                    not functions.check_single_address(self.family,
                                                       self.element.to_address):
                raise FirewallError(errors.INVALID_ADDR, self.element.to_address)
            if self.family is None:
                raise FirewallError(errors.INVALID_FAMILY)
            if self.action is not None:
                raise FirewallError(errors.INVALID_RULE, "forward-port and action")

        # source-port
        elif type(self.element) == Rich_SourcePort:
            if not functions.check_port(self.element.port):
                raise FirewallError(errors.INVALID_PORT, self.element.port)
            if self.element.protocol not in [ "tcp", "udp", "sctp", "dccp" ]:
                raise FirewallError(errors.INVALID_PROTOCOL, self.element.protocol)

        # tcp-mss-clamp
        elif type(self.element) == Rich_Tcp_Mss_Clamp:
            if self.action is not None:
                raise FirewallError(errors.INVALID_RULE, "tcp-mss-clamp and %s are mutually exclusive" % self.action)
            if self.element.value:
                if not functions.checkTcpMssClamp(self.element.value):
                    raise FirewallError(errors.INVALID_RULE, self.element.value)

        # other element and not empty?
        elif self.element is not None:
            raise FirewallError(errors.INVALID_RULE, "Unknown element %s" % 
                                type(self.element))

        # log
        if self.log is not None:
            if self.log.level and \
               self.log.level not in [ "emerg", "alert", "crit", "error",
                                       "warning", "notice", "info", "debug" ]:
                raise FirewallError(errors.INVALID_LOG_LEVEL, self.log.level)

            if self.log.limit is not None:
                self.log.limit.check()

        # audit
        if self.audit is not None:
            if type(self.action) not in [ Rich_Accept, Rich_Reject, Rich_Drop ]:
                raise FirewallError(errors.INVALID_AUDIT_TYPE, type(self.action))

            if self.audit.limit is not None:
                self.audit.limit.check()

        # action
        if self.action is not None:
            if type(self.action) == Rich_Reject:
                self.action.check(self.family)
            elif type(self.action) == Rich_Mark:
                self.action.check()

            if self.action.limit is not None:
                self.action.limit.check()

    def __str__(self):
        ret = 'rule'
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


#class Rich_RawRule(object):
#class Rich_RuleSet(object):
#class Rich_AddressList(object):
