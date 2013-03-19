# -*- coding: utf-8 -*-
#
# Copyright (C) 2013 Red Hat, Inc.
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

from firewall.core.logger import log

class Rich_Source(object):
    def __init__(self, addr, invert=False):
        self.addr = addr
        self.invert = invert

    def __str__(self):
        return 'source %saddress="%s"' % ("NOT " if self.invert else "",
                                          self.addr)

class Rich_Destination(Rich_Source):
    def __str__(self):
        return 'destination %saddress="%s"' % ("NOT " if self.invert else "",
                                               self.addr)

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

class Rich_ForwardPort(object):
    def __init__(self, port, protocol, to_port, to_address):
        self.port = port
        self.protocol = protocol
        self.to_port = to_port
        self.to_address = to_address

    def __str__(self):
        return 'forward-port port="%s" protocol="%s"%s%s' % \
            (self.port, self.protocol,
             ' to-port="%s"' % self.to_port if self.to_port != "" else '',
             ' to-address="%s"' % self.to_address if self.to_address != "" else '')

class Rich_Log(object):
    def __init__(self, prefix=None, level=None):
        #TODO check default level in iptables
        self.prefix = prefix
        self.level = level
        self.limit = None

    def __str__(self):
        return 'log%s%s%s' % \
            (' prefix="%s"' % (self.prefix) if self.prefix else "",
             ' level="%s"' % (self.level) if self.level else "",
             " { %s }" % self.limit if self.limit else "")

class Rich_Audit(object):
    def __init__(self, _type):
        #TODO check default level in iptables
        self.type = str(_type)
        self.limit = None

    def __str__(self):
        return 'audit type="%s"%s' % \
            (self.type, " { %s }" % self.limit if self.limit else "")

class Rich_Accept(object):
    def __init__(self):
        self.limit = None

    def __str__(self):
        return "accept%s" % (" { %s }" % self.limit if self.limit else "")

class Rich_Reject(object):
    def __init__(self, _type=None):
        self.type = _type
        self.limit = None

    def __str__(self):
        return "reject%s%s" % (' type="%s"' if self.type else "",
                               " { %s }" % self.limit if self.limit else "")

class Rich_Drop(Rich_Accept):
    def __str__(self):
        return "drop%s" % (" { %s }" % self.limit if self.limit else "")


class Rich_Limit(object):
    def __init__(self, value):
        self.value = value

    def check(self):
        splits = None
        if "/" in self.value:
            splits = value.split("/")
        if not splits or len(splits) != 2:
            raise FirewallError(INVALID_LIMIT,
                                "Invalid value (rate/duration): %s" % 
                                self.value)
        (rate, duration) = splits
        try:
            rate = int(rate)
        except:
            raise FirewallError(INVALID_LIMIT, "Invalid rate: %s" % rate)
        if rate < 0:
            raise FirewallError(INVALID_LIMIT, "Invalid rate: %s" % rate)

        if duration not in [ "s", "m", "h", "d" ]:
            raise FirewallError(INVALID_LIMIT, "Invalid duration: %s" %
                                duration)

        mult = 1
        if self.duration == "s":
            mult = 1
        elif self.duration == "m":
            mult = 60
        elif self.duration == "h":
            mult = 60*60
        elif self.duration == "d":
            mult = 24*60*60

        if 10000 * mult / r == 0:
            raise FirewallError(INVALID_LIMIT,
                                "Limit rate/duration too fast %d/%s" % \
                                    (rate, duration))

    def __str__(self):
        return 'limit rate="%s"' % (self.value)

    def command(self):
        return ''

class Rich_Rule(object):
    def __init__(self, family=None):
        if family != None:
            self.family = str(family)
        else:
            self.family = None

        self.source = None
        self.destination = None
        self.element = None
        self.log = None
        self.audit = None
        self.action = None

    def check(self):
        if self.family != None and self.family not in [ "ipv4", "ipv6" ]:
            log.error('Invalid family "%s"' % self.family)
            return False

        if self.log == None and self.audit == None and \
                self.action == None and \
                type(self.element) not in [ Rich_IcmpBlock,
                                            Rich_ForwardPort,
                                            Rich_Masquerade ]:
            log.error("Invalid rule: %s: No action, log or audit" % \
                          str(self._rule))
            return False

        return True

    def __str__(self):
        ret = "rule "
        if self.family:
            ret += 'family="%s" ' % self.family
        ret += "{ "
        if self.source:
            ret += "%s " % self.source
        if self.destination:
            ret += "%s " % self.destination
        ret += "%s " % self.element
        if self.log:
            ret += "%s " % self.log
        if self.audit:
            ret += "%s " % self.audit
        if self.action:
            ret += "%s " % self.action
        ret += "}"

        return ret

#class Rich_RawRule(object):
#class Rich_RuleSet(object):
#class Rich_AddressList(object):
