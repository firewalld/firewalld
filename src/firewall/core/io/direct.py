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

from firewall.config import _
from firewall.fw_types import *
from firewall.errors import *
from firewall.core.io.io_object import *
from firewall.core.logger import log

class direct_ContentHandler(IO_Object_ContentHandler):
    def __init__(self, item):
        IO_Object_ContentHandler.__init__(self, item)
        self.direct = False

    def startElement(self, name, attrs):
        self.item.parser_check_element_attrs(name, attrs)

        if name == "direct":
            if self.direct:
                raise FirewallError(PARSE_ERROR, "More than one direct tag.")
            self.direct = True

        elif name == "chain":
            if not self.direct:
                log.error("Parse Error: command outside of direct")
                return
            ipv = str(attrs["ipv"])
            table = str(attrs["table"])
            chain = str(attrs["chain"])
            self.item.add_chain(ipv, table, chain)

        elif name == "rule":
            if not self.direct:
                log.error("Parse Error: command outside of direct")
                return
            ipv = str(attrs["ipv"])
            if ipv not in [ "ipv4", "ipv6", "eb" ]:
                raise FirewallError(INVALID_IPV, ipv)
            table = str(attrs["table"])
            chain = str(attrs["chain"])
            try:
                priority = int(str(attrs["priority"]))
            except:
                log.error("Parse Error: %s is not a valid priority" % 
                          attrs["priority"])
                return
            args = [ ]
            self._rule = (ipv, table, chain, priority, args)
            self._args = args

#        elif name == "passthrough":
#            if not self.direct:
#                log.error("Parse Error: command outside of direct")
#                return
#            ipv = str(attrs["ipv"])
#            args = [ ]
#            self._passthrough = (ipv, args)
#            self._args = args

        elif name == "arg":
            if self._args == None:
                log.error("Parse Error: arg element unexpected")
                return
            # start new arg stored in _element
            self._element = u""

        else:
            log.error('Unknown XML element %s' % name)
            return

    def endElement(self, name):
        IO_Object_ContentHandler.endElement(self, name)

        if name == "arg":
            if self._element != None:
                self._args.append(self._element.strip()) # TODO: no strip?
                self._element = None
        if name == "rule":
            if len(self._args) < 1:
                log.error("Error: rule does not have any arguments, ignoring.")
            else:
                self.item.add_rule(*self._rule)
            self._rule = None
            self._args = None
#        elif name == "passthrough":
#            if len(self._args) < 1:
#                log.error("Error: passthrough does not have any arguments, " +
#                          "ignoring.")
#            else:
#                self.item.add_passthrough(*self._passthrough)
#            self._passthrough = None
#            self._args = None

class Direct(IO_Object):
    """ Direct class """

    IMPORT_EXPORT_STRUCTURE = (
        # chain: [ ipv, table, chain ]
        ( "chain", [ "", "", "" ] ),                    # a(sss)
        # rule: [ ipv, table, chain, priority, [ arg ]
        ( "rule", [ "", "", "", 0, [ "" ] ] ),          # a(sssdas)
#        # passthrough: [ ipv, [ arg ]
#        ( "passthough", [ "", [ "" ] ] ),               # a(sas)
        )
    DBUS_SIGNATURE = '(a(sss)a(sssdas)a(sas)'
    PARSER_REQUIRED_ELEMENT_ATTRS = {
        "direct": None,
        "chain": [ "ipv", "table", "chain" ],
        "rule": [ "ipv", "table", "chain", "priority" ],
#        "passthrough": [ "ipv" ],
        "arg": None
        }
    PARSER_OPTIONAL_ELEMENT_ATTRS = {
        }

    def __init__(self, filename):
        super(Direct, self).__init__()
        self.filename = filename
        self.clear()

    def _check_config(self, config, item):
        pass
        # check arg lists

    def clear(self):
        self.chains = LastUpdatedOrderedDict()
        self.rules = LastUpdatedOrderedDict()
#        self.passthroughs = LastUpdatedOrderedDict()

    def output(self):
        print ("chains")
        for key in self.chains:
            print ("  (%s, %s): %s" % (key[0], key[1], ",".join(self.chains[key])))
        print ("rules")
        for key in self.rules:
            print ("  (%s, %s, %s):" % (key[0], key[1], key[2]))
            for (priority,args) in self.rules[key]:
                print ("    (%d, ('%s'))" % (priority, "','".join(args)))
#        print ("passthroughs")
#        for key in self.passthroughs:
#            print ("  %s:" % (key))
#            for args in self.passthroughs[key]:
#                print ("    ('%s')" % ("','".join(args)))

    # chains

    def add_chain(self, ipv, table, chain):
        key = (ipv, table)
        if key not in self.chains:
            self.chains[key] = [ ]
        if chain not in self.chains[key]:
            self.chains[key].append(chain)
        else:
            log.warning("Chain '%s' for table '%s' with ipv '%s' " % \
                            (chain, table, ipv)
                        + "already in list, ignoring")

    def remove_chain(self, ipv, table, chain):
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
        key = (ipv, table)
        return (key in self.chains and chain in self.chains[key])

    def get_chains(self, ipv, table):
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
        key = (ipv, table, chain)
        if key not in self.rules:
            self.rules[key] = LastUpdatedOrderedDict()
        value = (priority, tuple(args))
        if value not in self.rules[key]:
            self.rules[key][value] = priority
        else:
            log.warning("Rule '%s' for table '%s' and chain '%s' " % \
                            ("',".join(args), table, chain)
                        + "with ipv '%s' and priority %d " % (ipv, priority)
                        + "already in list, ignoring")

    def remove_rule(self, ipv, table, chain, priority, args):
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

    def query_rule(self, ipv, table, chain, priority, args):
        key = (ipv, table, chain)
        value = (priority, tuple(args))
        return (key in self.rules and value in self.rules[key])

    def get_rules(self, ipv, table, chain):
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
#    def add_passthrough(self, ipv, args):
#        if ipv not in self.passthroughs:
#            self.passthroughs[ipv] = [ ]
#        if args not in self.passthroughs[ipv]:
#            self.passthroughs[ipv].append(args)
#        else:
#            log.warning("Passthrough '%s' for ipv '%s'" % \
#                            ("',".join(args), ipv)
#                        + "already in list, ignoring")
#
#    def remove_passthrough(self, ipv, args):
#        if ipv in self.passthroughs and args in self.passthroughs[ipv]:
#            self.passthroughs[ipv].remove(args)
#            if len(self.passthroughs[ipv]) == 0:
#                del self.passthroughs[ipv]
#        else:
#            raise ValueError, "Passthrough '%s' for ipv '%s'" % \
#                ("',".join(args), ipv) + "not in list"
#
#    def query_passthrough(self, ipv, args):
#        return (ipv in self.passthroughs and args in self.passthroughs[ipv])
#
#    def get_passthroughs(self, ipv):
#        if ipv in self.passthroughs:
#            return self.passthroughs[ipv]
#        else:
#            raise ValueError, "No passthroughs for ipv '%s'" % (ipv)
#
#    def get_all_passthroughs(self):
#        return self.passthroughs

    # read

    def read(self):
        self.clear()
        if not self.filename.endswith(".xml"):
            raise FirewallError(INVALID_NAME, self.filename)
        handler = direct_ContentHandler(self)
        parser = sax.make_parser()
        parser.setContentHandler(handler)
        parser.parse(self.filename)

    def write(self):
        if os.path.exists(self.filename):
            try:
                shutil.copy2(self.filename, "%s.old" % self.filename)
            except Exception as msg:
                raise IOError("Backup of '%s' failed: %s" % (self.filename, msg))

        fd = open(self.filename, "w")
        handler = IO_Object_XMLGenerator(fd)
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
                handler.ignorableWhitespace("\n")
                for arg in args:
                    # use start/stop elements if '"' is in arg, else simple
                    # elements
                    handler.ignorableWhitespace("    ")
                    handler.startElement("arg", { })
                    handler.ignorableWhitespace(arg)
                    handler.endElement("arg")
                    handler.ignorableWhitespace("\n")

                handler.ignorableWhitespace("  ")
                handler.endElement("rule")
                handler.ignorableWhitespace("\n")

#        # passthroughs
#        for ipv in self.passthroughs:
#            for args in self.passthroughs[ipv]:
#                if len(args) < 1:
#                    continue
#                handler.ignorableWhitespace("  ")
#                handler.startElement("passthrough", { "ipv": ipv })
#                handler.ignorableWhitespace("\n")
#                for arg in args:
#                    # use start/stop elements if '"' is in arg, else simple
#                    # elements
#                    handler.ignorableWhitespace("    ")
#                    handler.startElement("arg", { })
#                    handler.ignorableWhitespace(arg)
#                    handler.endElement("arg")
#                    handler.ignorableWhitespace("\n")
#                handler.ignorableWhitespace("  ")
#                handler.endElement("passthrough")
#                handler.ignorableWhitespace("\n")

        # end zone element
        handler.endElement("direct")
        handler.ignorableWhitespace("\n")
        handler.endDocument()
        fd.close()
