# -*- coding: utf-8 -*-
#
# Copyright (C) 2010-2016 Red Hat, Inc.
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

__all__ = [ "ebtables" ]

import os.path
from firewall.core.prog import runProg
from firewall.core.logger import log
from firewall.functions import tempFile, readfile, splitArgs
from firewall.config import COMMANDS
from firewall.core import ipXtables # some common stuff lives there
from firewall.errors import FirewallError, INVALID_IPV
import string

BUILT_IN_CHAINS = {
    "broute": [ "BROUTING" ],
    "nat": [ "PREROUTING", "POSTROUTING", "OUTPUT" ],
    "filter": [ "INPUT", "OUTPUT", "FORWARD" ],
}

DEFAULT_RULES = { }
LOG_RULES = { }
OUR_CHAINS = {}  # chains created by firewalld

for table in BUILT_IN_CHAINS.keys():
    DEFAULT_RULES[table] = [ ]
    OUR_CHAINS[table] = set()
    for chain in BUILT_IN_CHAINS[table]:
        DEFAULT_RULES[table].append("-N %s_direct" % chain)
        DEFAULT_RULES[table].append("-I %s 1 -j %s_direct" % (chain, chain))
        DEFAULT_RULES[table].append("-I %s_direct 1 -j RETURN" % chain)
        OUR_CHAINS[table].add("%s_direct" % chain)

class ebtables(object):
    ipv = "eb"
    name = "ebtables"
    policies_supported = False # ebtables only supported with direct interface

    def __init__(self):
        self._command = COMMANDS[self.ipv]
        self._restore_command = COMMANDS["%s-restore" % self.ipv]
        self.restore_noflush_option = self._detect_restore_noflush_option()
        self.concurrent_option = self._detect_concurrent_option()
        self.fill_exists()
        self.available_tables = []

    def fill_exists(self):
        self.command_exists = os.path.exists(self._command)
        self.restore_command_exists = os.path.exists(self._restore_command)

    def _detect_concurrent_option(self):
        # Do not change any rules, just try to use the --concurrent option
        # with -L
        concurrent_option = ""
        ret = runProg(self._command, ["--concurrent", "-L"])
        if ret[0] == 0:
            concurrent_option = "--concurrent"  # concurrent for ebtables lock

        return concurrent_option

    def _detect_restore_noflush_option(self):
        # Do not change any rules, just try to use the restore command
        # with --noflush
        rules = [ ]
        try:
            self.set_rules(rules, "off")
        except ValueError:
            return False
        return True

    def __run(self, args):
        # convert to string list
        _args = [ ]
        if self.concurrent_option and self.concurrent_option not in args:
            _args.append(self.concurrent_option)
        _args += ["%s" % item for item in args]
        log.debug2("%s: %s %s", self.__class__, self._command, " ".join(_args))
        (status, ret) = runProg(self._command, _args)
        if status != 0:
            raise ValueError("'%s %s' failed: %s" % (self._command,
                                                     " ".join(args), ret))
        return ret

    def _rule_validate(self, rule):
        for str in ["%%REJECT%%", "%%ICMP%%", "%%LOGTYPE%%"]:
            if str in rule:
                raise FirewallError(INVALID_IPV,
                        "'%s' invalid for ebtables" % str)

    def is_chain_builtin(self, ipv, table, chain):
        return table in BUILT_IN_CHAINS and \
               chain in BUILT_IN_CHAINS[table]

    def build_chain_rules(self, add, table, chain):
        rules = []

        if add:
            rules.append([ "-t", table, "-N", chain ])
            rules.append([ "-t", table, "-I", chain, "1", "-j", "RETURN" ])
        else:
            rules.append([ "-t", table, "-X", chain ])

        return rules

    def build_rule(self, add, table, chain, index, args):
        rule = [ "-t", table ]
        if add:
            rule += [ "-I", chain, str(index) ]
        else:
            rule += [ "-D", chain ]
        rule += args
        return rule

    def reverse_rule(self, args):
        return ipXtables.common_reverse_rule(args)

    def check_passthrough(self, args):
        ipXtables.common_check_passthrough(args)

    def reverse_passthrough(self, args):
        return ipXtables.common_reverse_passthrough(args)

    def set_rules(self, rules, log_denied):
        temp_file = tempFile()

        table = "filter"
        table_rules = { }
        for _rule in rules:
            rule = _rule[:]

            self._rule_validate(rule)

            # get table form rule
            for opt in [ "-t", "--table" ]:
                try:
                    i = rule.index(opt)
                except ValueError:
                    pass
                else:
                    if len(rule) >= i+1:
                        rule.pop(i)
                        table = rule.pop(i)

            # we can not use joinArgs here, because it would use "'" instead
            # of '"' for the start and end of the string, this breaks
            # iptables-restore
            for i in range(len(rule)):
                for c in string.whitespace:
                    if c in rule[i] and not (rule[i].startswith('"') and
                                             rule[i].endswith('"')):
                        rule[i] = '"%s"' % rule[i]

            table_rules.setdefault(table, []).append(rule)

        for table in table_rules:
            temp_file.write("*%s\n" % table)
            for rule in table_rules[table]:
                temp_file.write(" ".join(rule) + "\n")

        temp_file.close()

        stat = os.stat(temp_file.name)
        log.debug2("%s: %s %s", self.__class__, self._restore_command,
                   "%s: %d" % (temp_file.name, stat.st_size))
        args = [ ]
        args.append("--noflush")

        (status, ret) = runProg(self._restore_command, args,
                                stdin=temp_file.name)

        if log.getDebugLogLevel() > 2:
            lines = readfile(temp_file.name)
            if lines is not None:
                i = 1
                for line in lines:
                    log.debug3("%8d: %s" % (i, line), nofmt=1, nl=0)
                    if not line.endswith("\n"):
                        log.debug3("", nofmt=1)
                    i += 1

        os.unlink(temp_file.name)

        if status != 0:
            raise ValueError("'%s %s' failed: %s" % (self._restore_command,
                                                     " ".join(args), ret))

    def set_rule(self, rule, log_denied):
        self._rule_validate(rule)
        return self.__run(rule)

    def get_available_tables(self, table=None):
        ret = []
        tables = [ table ] if table else BUILT_IN_CHAINS.keys()
        for table in tables:
            if table in self.available_tables:
                ret.append(table)
            else:
                try:
                    self.__run(["-t", table, "-L"])
                    self.available_tables.append(table)
                    ret.append(table)
                except ValueError:
                    log.debug1("ebtables table '%s' does not exist." % table)

        return ret

    def get_zone_table_chains(self, table):
        return {}

    def build_flush_rules(self):
        rules = []
        for table in BUILT_IN_CHAINS.keys():
            if table not in self.get_available_tables():
                continue
            # Flush firewall rules: -F
            # Delete firewall chains: -X
            # Set counter to zero: -Z
            for flag in [ "-F", "-X", "-Z" ]:
                rules.append(["-t", table, flag])
        return rules

    def build_set_policy_rules(self, policy):
        rules = []
        _policy = "DROP" if policy == "PANIC" else policy
        for table in BUILT_IN_CHAINS.keys():
            if table not in self.get_available_tables():
                continue
            for chain in BUILT_IN_CHAINS[table]:
                rules.append(["-t", table, "-P", chain, _policy])
        return rules

    def build_default_tables(self):
        # nothing to do, they always exist
        return []

    def build_default_rules(self, log_denied="off"):
        default_rules = []
        for table in DEFAULT_RULES:
            if table not in self.get_available_tables():
                continue
            _default_rules = DEFAULT_RULES[table][:]
            if log_denied != "off" and table in LOG_RULES:
                _default_rules.extend(LOG_RULES[table])
            prefix = [ "-t", table ]
            for rule in _default_rules:
                if type(rule) == list:
                    default_rules.append(prefix + rule)
                else:
                    default_rules.append(prefix + splitArgs(rule))
        return default_rules

    def is_ipv_supported(self, ipv):
        return ipv == self.ipv
