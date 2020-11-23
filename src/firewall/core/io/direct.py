# -*- coding: utf-8 -*-
#
# Copyright (C) 2011-2016 Red Hat, Inc.
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
import io
import shutil

from firewall import config
from firewall.fw_types import LastUpdatedOrderedDict
from firewall.functions import splitArgs, joinArgs
from firewall.core.io.io_object import IO_Object, IO_Object_ContentHandler, \
    IO_Object_XMLGenerator
from firewall.core.logger import log
from firewall.core import ipXtables
from firewall.core import ebtables
from firewall import errors
from firewall.errors import FirewallError


class direct_ContentHandler(IO_Object_ContentHandler):
    def __init__(self, item):
        IO_Object_ContentHandler.__init__(self, item)
        self.direct = False

    def startElement(self, name, attrs):
        IO_Object_ContentHandler.startElement(self, name, attrs)
        self.item.parser_check_element_attrs(name, attrs)

        if name == "direct":
            if self.direct:
                raise FirewallError(errors.PARSE_ERROR,
                                    "More than one direct tag.")
            self.direct = True

        elif name == "chain":
            if not self.direct:
                log.error("Parse Error: chain outside of direct")
                return
            ipv = attrs["ipv"]
            table = attrs["table"]
            chain = attrs["chain"]
            self.item.add_chain(ipv, table, chain)

        elif name == "rule":
            if not self.direct:
                log.error("Parse Error: rule outside of direct")
                return
            ipv = attrs["ipv"]
            if ipv not in [ "ipv4", "ipv6", "eb" ]:
                raise FirewallError(errors.INVALID_IPV,
                                    "'%s' not from {'ipv4'|'ipv6'|'eb'}" % ipv)
            table = attrs["table"]
            chain = attrs["chain"]
            try:
                priority = int(attrs["priority"])
            except ValueError:
                log.error("Parse Error: %s is not a valid priority" %
                          attrs["priority"])
                return
            self._rule = [ ipv, table, chain, priority ]

        elif name == "passthrough":
            if not self.direct:
                log.error("Parse Error: command outside of direct")
                return
            ipv = attrs["ipv"]
            self._passthrough = [ ipv ]

        else:
            log.error('Unknown XML element %s' % name)
            return

    def endElement(self, name):
        IO_Object_ContentHandler.endElement(self, name)

        if name == "rule":
            if self._element:
                # add arguments
                self._rule.append(splitArgs(self._element))
                self.item.add_rule(*self._rule)
            else:
                log.error("Error: rule does not have any arguments, ignoring.")
            self._rule = None
        elif name == "passthrough":
            if self._element:
                # add arguments
                self._passthrough.append(splitArgs(self._element))
                self.item.add_passthrough(*self._passthrough)
            else:
                log.error("Error: passthrough does not have any arguments, " +
                          "ignoring.")
            self._passthrough = None

class Direct(IO_Object):
    """ Direct class """

    IMPORT_EXPORT_STRUCTURE = (
        # chain: [ ipv, table, [ chain ] ]
        ( "chains", [ ( "", "", "" ), ], ),                   # a(sss)
        # rule: [ ipv, table, chain, [ priority, [ arg ] ] ]
        ( "rules", [ ( "", "", "", 0, [ "" ] ), ], ),         # a(sssias)
        # passthrough: [ ipv, [ [ arg ] ] ]
        ( "passthroughs", [ ( "", [ "" ]), ], ),              # a(sas)
        )
    DBUS_SIGNATURE = '(a(sss)a(sssias)a(sas))'
    PARSER_REQUIRED_ELEMENT_ATTRS = {
        "direct": None,
        "chain": [ "ipv", "table", "chain" ],
        "rule": [ "ipv", "table", "chain", "priority" ],
        "passthrough": [ "ipv" ]
        }
    PARSER_OPTIONAL_ELEMENT_ATTRS = {
        }

    def __init__(self, filename):
        super(Direct, self).__init__()
        self.filename = filename
        self.chains = LastUpdatedOrderedDict()
        self.rules = LastUpdatedOrderedDict()
        self.passthroughs = LastUpdatedOrderedDict()

    def _check_config(self, conf, item, all_conf):
        pass
        # check arg lists

    def export_config(self):
        ret = [ ]
        x = [ ]
        for key in self.chains:
            for chain in self.chains[key]:
                x.append(tuple(list(key) + list([chain])))
        ret.append(x)
        x = [ ]
        for key in self.rules:
            for rule in self.rules[key]:
                x.append(tuple((key[0], key[1], key[2], rule[0],
                                list(rule[1]))))
        ret.append(x)
        x = [ ]
        for key in self.passthroughs:
            for rule in self.passthroughs[key]:
                x.append(tuple((key, list(rule))))
        ret.append(x)
        return tuple(ret)

    def import_config(self, conf):
        self.cleanup()
        self.check_config(conf)
        for i,(element,dummy) in enumerate(self.IMPORT_EXPORT_STRUCTURE):
            if element == "chains":
                for x in conf[i]:
                    self.add_chain(*x)
            if element == "rules":
                for x in conf[i]:
                    self.add_rule(*x)
            if element == "passthroughs":
                for x in conf[i]:
                    self.add_passthrough(*x)

    def cleanup(self):
        self.chains.clear()
        self.rules.clear()
        self.passthroughs.clear()

    def output(self):
        print("chains")
        for key in self.chains:
            print("  (%s, %s): %s" % (key[0], key[1],
                                      ",".join(self.chains[key])))
        print("rules")
        for key in self.rules:
            print("  (%s, %s, %s):" % (key[0], key[1], key[2]))
            for (priority,args) in self.rules[key]:
                print("    (%d, ('%s'))" % (priority, "','".join(args)))
        print("passthroughs")
        for key in self.passthroughs:
            print("  %s:" % (key))
            for args in self.passthroughs[key]:
                print("    ('%s')" % ("','".join(args)))

    def _check_ipv(self, ipv):
        ipvs = ['ipv4', 'ipv6', 'eb']
        if ipv not in ipvs:
            raise FirewallError(errors.INVALID_IPV,
                                "'%s' not in '%s'" % (ipv, ipvs))

    def _check_ipv_table(self, ipv, table):
        self._check_ipv(ipv)

        tables = ipXtables.BUILT_IN_CHAINS.keys() if ipv in ['ipv4', 'ipv6'] \
                                         else ebtables.BUILT_IN_CHAINS.keys()
        if table not in tables:
            raise FirewallError(errors.INVALID_TABLE,
                                "'%s' not in '%s'" % (table, tables))

    # chains

    def add_chain(self, ipv, table, chain):
        self._check_ipv_table(ipv, table)
        key = (ipv, table)
        if key not in self.chains:
            self.chains[key] = [ ]
        if chain not in self.chains[key]:
            self.chains[key].append(chain)
        else:
            log.warning("Chain '%s' for table '%s' with ipv '%s' " % \
                        (chain, table, ipv) + "already in list, ignoring")

    def remove_chain(self, ipv, table, chain):
        self._check_ipv_table(ipv, table)
        key = (ipv, table)
        if key in self.chains and chain in self.chains[key]:
            self.chains[key].remove(chain)
            if len(self.chains[key]) == 0:
                del self.chains[key]
        else:
            raise ValueError( \
                "Chain '%s' with table '%s' with ipv '%s' not in list" % \
                (chain, table, ipv))

    def query_chain(self, ipv, table, chain):
        self._check_ipv_table(ipv, table)
        key = (ipv, table)
        return (key in self.chains and chain in self.chains[key])

    def get_chains(self, ipv, table):
        self._check_ipv_table(ipv, table)
        key = (ipv, table)
        if key in self.chains:
            return self.chains[key]
        else:
            raise ValueError("No chains for table '%s' with ipv '%s'" % \
                             (table, ipv))

    def get_all_chains(self):
        return self.chains

    # rules

    def add_rule(self, ipv, table, chain, priority, args):
        self._check_ipv_table(ipv, table)
        key = (ipv, table, chain)
        if key not in self.rules:
            self.rules[key] = LastUpdatedOrderedDict()
        value = (priority, tuple(args))
        if value not in self.rules[key]:
            self.rules[key][value] = priority
        else:
            log.warning("Rule '%s' for table '%s' and chain '%s' " % \
                        ("',".join(args), table, chain) +
                        "with ipv '%s' and priority %d " % (ipv, priority) +
                        "already in list, ignoring")

    def remove_rule(self, ipv, table, chain, priority, args):
        self._check_ipv_table(ipv, table)
        key = (ipv, table, chain)
        value = (priority, tuple(args))
        if key in self.rules and value in self.rules[key]:
            del self.rules[key][value]
            if len(self.rules[key]) == 0:
                del self.rules[key]
        else:
            raise ValueError("Rule '%s' for table '%s' and chain '%s' " % \
                ("',".join(args), table, chain) + \
                "with ipv '%s' and priority %d not in list" % (ipv, priority))

    def remove_rules(self, ipv, table, chain):
        self._check_ipv_table(ipv, table)
        key = (ipv, table, chain)
        if key in self.rules:
            for value in self.rules[key].keys():
                del self.rules[key][value]
            if len(self.rules[key]) == 0:
                del self.rules[key]

    def query_rule(self, ipv, table, chain, priority, args):
        self._check_ipv_table(ipv, table)
        key = (ipv, table, chain)
        value = (priority, tuple(args))
        return (key in self.rules and value in self.rules[key])

    def get_rules(self, ipv, table, chain):
        self._check_ipv_table(ipv, table)
        key = (ipv, table, chain)
        if key in self.rules:
            return self.rules[key]
        else:
            raise ValueError("No rules for table '%s' and chain '%s' " %\
                             (table, chain) + "with ipv '%s'" % (ipv))

    def get_all_rules(self):
        return self.rules

#    # passthrough
#
    def add_passthrough(self, ipv, args):
        self._check_ipv(ipv)
        if ipv not in self.passthroughs:
            self.passthroughs[ipv] = [ ]
        if args not in self.passthroughs[ipv]:
            self.passthroughs[ipv].append(args)
        else:
            log.warning("Passthrough '%s' for ipv '%s'" % \
                        ("',".join(args), ipv) + "already in list, ignoring")

    def remove_passthrough(self, ipv, args):
        self._check_ipv(ipv)
        if ipv in self.passthroughs and args in self.passthroughs[ipv]:
            self.passthroughs[ipv].remove(args)
            if len(self.passthroughs[ipv]) == 0:
                del self.passthroughs[ipv]
        else:
            raise ValueError("Passthrough '%s' for ipv '%s'" % \
                             ("',".join(args), ipv) + "not in list")

    def query_passthrough(self, ipv, args):
        self._check_ipv(ipv)
        return ipv in self.passthroughs and args in self.passthroughs[ipv]

    def get_passthroughs(self, ipv):
        self._check_ipv(ipv)
        if ipv in self.passthroughs:
            return self.passthroughs[ipv]
        else:
            raise ValueError("No passthroughs for ipv '%s'" % (ipv))

    def get_all_passthroughs(self):
        return self.passthroughs

    # read

    def read(self):
        self.cleanup()
        if not self.filename.endswith(".xml"):
            raise FirewallError(errors.INVALID_NAME,
                                "'%s' is missing .xml suffix" % self.filename)
        handler = direct_ContentHandler(self)
        parser = sax.make_parser()
        parser.setContentHandler(handler)
        with open(self.filename, "rb") as f:
            source = sax.InputSource(None)
            source.setByteStream(f)
            try:
                parser.parse(source)
            except sax.SAXParseException as msg:
                raise FirewallError(errors.INVALID_TYPE,
                                    "Not a valid file: %s" % \
                                    msg.getException())

    def write(self):
        if os.path.exists(self.filename):
            try:
                shutil.copy2(self.filename, "%s.old" % self.filename)
            except Exception as msg:
                raise IOError("Backup of '%s' failed: %s" % (self.filename, msg))

        if not os.path.exists(config.ETC_FIREWALLD):
            os.mkdir(config.ETC_FIREWALLD, 0o750)

        f = io.open(self.filename, mode='wt', encoding='UTF-8')
        handler = IO_Object_XMLGenerator(f)
        handler.startDocument()

        # start whitelist element
        handler.startElement("direct", { })
        handler.ignorableWhitespace("\n")

        # chains
        for key in self.chains:
            (ipv, table) = key
            for chain in self.chains[key]:
                handler.ignorableWhitespace("  ")
                handler.simpleElement("chain", { "ipv": ipv, "table": table,
                                                 "chain": chain })
                handler.ignorableWhitespace("\n")

        # rules
        for key in self.rules:
            (ipv, table, chain) = key
            for (priority, args) in self.rules[key]:
                if len(args) < 1:
                    continue
                handler.ignorableWhitespace("  ")
                handler.startElement("rule", { "ipv": ipv, "table": table,
                                               "chain": chain,
                                               "priority": "%d" % priority })
                handler.ignorableWhitespace(sax.saxutils.escape(joinArgs(args)))
                handler.endElement("rule")
                handler.ignorableWhitespace("\n")

        # passthroughs
        for ipv in self.passthroughs:
            for args in self.passthroughs[ipv]:
                if len(args) < 1:
                    continue
                handler.ignorableWhitespace("  ")
                handler.startElement("passthrough", { "ipv": ipv })
                handler.ignorableWhitespace(sax.saxutils.escape(joinArgs(args)))
                handler.endElement("passthrough")
                handler.ignorableWhitespace("\n")

        # end zone element
        handler.endElement("direct")
        handler.ignorableWhitespace("\n")
        handler.endDocument()
        f.close()
        del handler
