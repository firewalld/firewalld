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

import os.path

from firewall.core.prog import runProg
from firewall.core.logger import log
from firewall.functions import tempFile, readfile, splitArgs
from firewall import config
import string

PROC_IPxTABLE_NAMES = {
    "ipv4": "/proc/net/ip_tables_names",
    "ipv6": "/proc/net/ip6_tables_names",
}

BUILT_IN_CHAINS = {
    "security": [ "INPUT", "OUTPUT", "FORWARD" ],
    "raw": [ "PREROUTING", "OUTPUT" ],
    "mangle": [ "PREROUTING", "POSTROUTING", "INPUT", "OUTPUT", "FORWARD" ],
    "nat": [ "PREROUTING", "POSTROUTING", "OUTPUT" ],
    "filter": [ "INPUT", "OUTPUT", "FORWARD" ],
}

DEFAULT_REJECT_TYPE = {
    "ipv4": "icmp-host-prohibited",
    "ipv6": "icmp6-adm-prohibited",
}

ICMP = {
    "ipv4": "icmp",
    "ipv6": "ipv6-icmp",
}

DEFAULT_RULES = { }
LOG_RULES = { }
OUR_CHAINS = {} # chains created by firewalld

DEFAULT_RULES["security"] = [ ]
OUR_CHAINS["security"] = set()
for chain in BUILT_IN_CHAINS["security"]:
    DEFAULT_RULES["security"].append("-N %s_direct" % chain)
    DEFAULT_RULES["security"].append("-I %s 1 -j %s_direct" % (chain, chain))
    OUR_CHAINS["security"].add("%s_direct" % chain)

DEFAULT_RULES["raw"] = [ ]
OUR_CHAINS["raw"] = set()
for chain in BUILT_IN_CHAINS["raw"]:
    DEFAULT_RULES["raw"].append("-N %s_direct" % chain)
    DEFAULT_RULES["raw"].append("-I %s 1 -j %s_direct" % (chain, chain))
    OUR_CHAINS["raw"].add("%s_direct" % chain)

    if chain == "PREROUTING":
        DEFAULT_RULES["raw"].append("-N %s_ZONES_SOURCE" % chain)
        DEFAULT_RULES["raw"].append("-N %s_ZONES" % chain)
        DEFAULT_RULES["raw"].append("-I %s 2 -j %s_ZONES_SOURCE" % (chain, chain))
        DEFAULT_RULES["raw"].append("-I %s 3 -j %s_ZONES" % (chain, chain))
        OUR_CHAINS["raw"].update(set(["%s_ZONES_SOURCE" % chain, "%s_ZONES" % chain]))

DEFAULT_RULES["mangle"] = [ ]
OUR_CHAINS["mangle"] = set()
for chain in BUILT_IN_CHAINS["mangle"]:
    DEFAULT_RULES["mangle"].append("-N %s_direct" % chain)
    DEFAULT_RULES["mangle"].append("-I %s 1 -j %s_direct" % (chain, chain))
    OUR_CHAINS["mangle"].add("%s_direct" % chain)

    if chain == "PREROUTING":
        DEFAULT_RULES["mangle"].append("-N %s_ZONES_SOURCE" % chain)
        DEFAULT_RULES["mangle"].append("-N %s_ZONES" % chain)
        DEFAULT_RULES["mangle"].append("-I %s 2 -j %s_ZONES_SOURCE" % (chain, chain))
        DEFAULT_RULES["mangle"].append("-I %s 3 -j %s_ZONES" % (chain, chain))
        OUR_CHAINS["mangle"].update(set(["%s_ZONES_SOURCE" % chain, "%s_ZONES" % chain]))

DEFAULT_RULES["nat"] = [ ]
OUR_CHAINS["nat"] = set()
for chain in BUILT_IN_CHAINS["nat"]:
    DEFAULT_RULES["nat"].append("-N %s_direct" % chain)
    DEFAULT_RULES["nat"].append("-I %s 1 -j %s_direct" % (chain, chain))
    OUR_CHAINS["nat"].add("%s_direct" % chain)

    if chain in [ "PREROUTING", "POSTROUTING" ]:
        DEFAULT_RULES["nat"].append("-N %s_ZONES_SOURCE" % chain)
        DEFAULT_RULES["nat"].append("-N %s_ZONES" % chain)
        DEFAULT_RULES["nat"].append("-I %s 2 -j %s_ZONES_SOURCE" % (chain, chain))
        DEFAULT_RULES["nat"].append("-I %s 3 -j %s_ZONES" % (chain, chain))
        OUR_CHAINS["nat"].update(set(["%s_ZONES_SOURCE" % chain, "%s_ZONES" % chain]))

DEFAULT_RULES["filter"] = [
    "-N INPUT_direct",
    "-N INPUT_ZONES_SOURCE",
    "-N INPUT_ZONES",

    "-I INPUT 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
    "-I INPUT 2 -i lo -j ACCEPT",
    "-I INPUT 3 -j INPUT_direct",
    "-I INPUT 4 -j INPUT_ZONES_SOURCE",
    "-I INPUT 5 -j INPUT_ZONES",
    "-I INPUT 6 -m conntrack --ctstate INVALID -j DROP",
    "-I INPUT 7 -j %%REJECT%%",

    "-N FORWARD_direct",
    "-N FORWARD_IN_ZONES_SOURCE",
    "-N FORWARD_IN_ZONES",
    "-N FORWARD_OUT_ZONES_SOURCE",
    "-N FORWARD_OUT_ZONES",

    "-I FORWARD 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
    "-I FORWARD 2 -i lo -j ACCEPT",
    "-I FORWARD 3 -j FORWARD_direct",
    "-I FORWARD 4 -j FORWARD_IN_ZONES_SOURCE",
    "-I FORWARD 5 -j FORWARD_IN_ZONES",
    "-I FORWARD 6 -j FORWARD_OUT_ZONES_SOURCE",
    "-I FORWARD 7 -j FORWARD_OUT_ZONES",
    "-I FORWARD 8 -m conntrack --ctstate INVALID -j DROP",
    "-I FORWARD 9 -j %%REJECT%%",

    "-N OUTPUT_direct",

    "-I OUTPUT 1 -j OUTPUT_direct",
]

LOG_RULES["filter"] = [
    "-I INPUT 6 -m conntrack --ctstate INVALID %%LOGTYPE%% -j LOG --log-prefix 'STATE_INVALID_DROP: '",
    "-I INPUT 8 %%LOGTYPE%% -j LOG --log-prefix 'FINAL_REJECT: '",

    "-I FORWARD 8 -m conntrack --ctstate INVALID %%LOGTYPE%% -j LOG --log-prefix 'STATE_INVALID_DROP: '",
    "-I FORWARD 10 %%LOGTYPE%% -j LOG --log-prefix 'FINAL_REJECT: '",
]

OUR_CHAINS["filter"] = set(["INPUT_direct", "INPUT_ZONES_SOURCE", "INPUT_ZONES",
                            "FORWARD_direct", "FORWARD_IN_ZONES_SOURCE",
                            "FORWARD_IN_ZONES", "FORWARD_OUT_ZONES_SOURCE",
                            "FORWARD_OUT_ZONES", "OUTPUT_direct"])

class ip4tables(object):
    ipv = "ipv4"

    def __init__(self):
        self._command = config.COMMANDS[self.ipv]
        self._restore_command = config.COMMANDS["%s-restore" % self.ipv]
        self.wait_option = self._detect_wait_option()
        self.restore_wait_option = self._detect_restore_wait_option()
        self.fill_exists()

    def fill_exists(self):
        self.command_exists = os.path.exists(self._command)
        self.restore_command_exists = os.path.exists(self._restore_command)

    def __run(self, args):
        # convert to string list
        if self.wait_option and self.wait_option not in args:
            _args = [self.wait_option] + ["%s" % item for item in args]
        else:
            _args = ["%s" % item for item in args]
        log.debug2("%s: %s %s", self.__class__, self._command, " ".join(_args))
        (status, ret) = runProg(self._command, _args)
        if status != 0:
            raise ValueError("'%s %s' failed: %s" % (self._command,
                                                     " ".join(_args), ret))
        return ret

    def split_value(self, rules, opts=None):
        """Split values combined with commas for options in opts"""

        if opts is None:
            return rules

        out_rules = [ ]
        for rule in rules:
            processed = False
            for opt in opts:
                try:
                    i = rule.index(opt)
                except ValueError:
                    pass
                else:
                    if len(rule) > i and "," in rule[i+1]:
                        # For all items in the comma separated list in index
                        # i of the rule, a new rule is created with a single
                        # item from this list
                        processed = True
                        items = rule[i+1].split(",")
                        for item in items:
                            _rule = rule[:]
                            _rule[i+1] = item
                            out_rules.append(_rule)
            if not processed:
                out_rules.append(rule)

        return out_rules

    def _rule_replace(self, rule, pattern, replacement):
        try:
            i = rule.index(pattern)
        except ValueError:
            return False
        else:
            rule[i:i+1] = replacement
            return True

    def set_rules(self, rules, flush=False, log_denied="off"):
        temp_file = tempFile()

        table_rules = { }
        for _rule in rules:
            rule = _rule[:]

            # replace %%REJECT%%
            self._rule_replace(rule, "%%REJECT%%", \
                    ["REJECT", "--reject-with", DEFAULT_REJECT_TYPE[self.ipv]])

            # replace %%ICMP%%
            self._rule_replace(rule, "%%ICMP%%", [ICMP[self.ipv]])

            # replace %%LOGTYPE%%
            try:
                i = rule.index("%%LOGTYPE%%")
            except ValueError:
                pass
            else:
                if log_denied == "off":
                    continue
                if log_denied in [ "unicast", "broadcast", "multicast" ]:
                    rule[i:i+1] = [ "-m", "pkttype", "--pkt-type", log_denied ]
                else:
                    rule.pop(i)

            table = "filter"
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
            rules = table_rules[table]
            rules = self.split_value(rules, [ "-s", "--source" ])
            rules = self.split_value(rules, [ "-d", "--destination" ])

            temp_file.write("*%s\n" % table)
            for rule in rules:
                temp_file.write(" ".join(rule) + "\n")
            temp_file.write("COMMIT\n")

        temp_file.close()

        stat = os.stat(temp_file.name)
        log.debug2("%s: %s %s", self.__class__, self._restore_command,
                   "%s: %d" % (temp_file.name, stat.st_size))
        args = [ ]
        if self.restore_wait_option:
            args.append(self.restore_wait_option)
        if not flush:
            args.append("-n")

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
        return ret

    def set_rule(self, rule, log_denied="off"):
        # replace %%REJECT%%
        self._rule_replace(rule, "%%REJECT%%", \
                ["REJECT", "--reject-with", DEFAULT_REJECT_TYPE[self.ipv]])

        # replace %%ICMP%%
        self._rule_replace(rule, "%%ICMP%%", [ICMP[self.ipv]])

        # replace %%LOGTYPE%%
        try:
            i = rule.index("%%LOGTYPE%%")
        except ValueError:
            pass
        else:
            if log_denied == "off":
                return ""
            if log_denied in [ "unicast", "broadcast", "multicast" ]:
                rule[i:i+1] = [ "-m", "pkttype", "--pkt-type",
                                self._log_denied ]
            else:
                rule.pop(i)

        return self.__run(rule)

    def append_rule(self, rule):
        self.__run([ "-A" ] + rule)

    def delete_rule(self, rule):
        self.__run([ "-D" ] + rule)

    def available_tables(self, table=None):
        ret = []
        tables = [ table ] if table else BUILT_IN_CHAINS.keys()
        for table in tables:
            try:
                self.__run(["-t", table, "-L", "-n"])
                ret.append(table)
            except ValueError:
                log.debug1("%s table '%s' does not exist (or not enough permission to check)." % (self.ipv, table))

        return ret

    def used_tables(self):
        tables = [ ]
        filename = PROC_IPxTABLE_NAMES[self.ipv]

        if os.path.exists(filename):
            with open(filename, "r") as f:
                for line in f.readlines():
                    if not line:
                        break
                    tables.append(line.strip())

        return tables

    def _detect_wait_option(self):
        wait_option = ""
        ret = runProg(self._command, ["-w", "-L", "-n"])  # since iptables-1.4.20
        if ret[0] == 0:
            wait_option = "-w"  # wait for xtables lock
            ret = runProg(self._command, ["-w2", "-L", "-n"])  # since iptables > 1.4.21
            if ret[0] == 0:
                wait_option = "-w2"  # wait max 2 seconds
            log.debug2("%s: %s will be using %s option.", self.__class__, self._command, wait_option)

        return wait_option

    def _detect_restore_wait_option(self):
        temp_file = tempFile()
        temp_file.write("#foo")
        temp_file.close()

        wait_option = ""
        for test_option in ["-w", "--wait=2"]:
            ret = runProg(self._restore_command, [test_option], stdin=temp_file.name)
            if ret[0] == 0 and "invalid option" not in ret[1] \
                           and "unrecognized option" not in ret[1]:
                wait_option = test_option
                break

        log.debug2("%s: %s will be using %s option.", self.__class__, self._restore_command, wait_option)

        os.unlink(temp_file.name)

        return wait_option

    def flush(self, transaction=None):
        tables = self.used_tables()
        for table in tables:
            # Flush firewall rules: -F
            # Delete firewall chains: -X
            # Set counter to zero: -Z
            for flag in [ "-F", "-X", "-Z" ]:
                if transaction is not None:
                    transaction.add_rule(self.ipv, [ "-t", table, flag ])
                else:
                    self.__run([ "-t", table, flag ])

    def set_policy(self, policy, which="used", transaction=None):
        if which == "used":
            tables = self.used_tables()
        else:
            tables = list(BUILT_IN_CHAINS.keys())

        for table in tables:
            if table == "nat":
                continue
            for chain in BUILT_IN_CHAINS[table]:
                if transaction is not None:
                    transaction.add_rule(self.ipv,
                                         [ "-t", table, "-P", chain, policy ])
                else:
                    self.__run([ "-t", table, "-P", chain, policy ])

    def supported_icmp_types(self):
        """Return ICMP types that are supported by the iptables/ip6tables command and kernel"""
        ret = [ ]
        output = ""
        try:
            output = self.__run(["-p",
                                 "icmp" if self.ipv == "ipv4" else "ipv6-icmp",
                                 "--help"])
        except ValueError as ex:
            if self.ipv == "ipv4":
                log.debug1("iptables error: %s" % ex)
            else:
                log.debug1("ip6tables error: %s" % ex)
        lines = output.splitlines()

        in_types = False
        for line in lines:
            #print(line)
            if in_types:
                line = line.strip().lower()
                splits = line.split()
                for split in splits:
                    if split.startswith("(") and split.endswith(")"):
                        x = split[1:-1]
                    else:
                        x = split
                    if x not in ret:
                        ret.append(x)
            if self.ipv == "ipv4" and line.startswith("Valid ICMP Types:") or \
               self.ipv == "ipv6" and line.startswith("Valid ICMPv6 Types:"):
                in_types = True
        return ret

    def apply_default_rules(self, transaction, log_denied="off"):
        for table in DEFAULT_RULES:
            if table not in self.available_tables():
                continue
            default_rules = DEFAULT_RULES[table][:]
            if log_denied != "off" and table in LOG_RULES:
                default_rules.extend(LOG_RULES[table])
            prefix = [ "-t", table ]
            for rule in default_rules:
                if type(rule) == list:
                    _rule = prefix + rule
                else:
                    _rule = prefix + splitArgs(rule)
                transaction.add_rule(self.ipv, _rule)

class ip6tables(ip4tables):
    ipv = "ipv6"

    def apply_rpfilter_rules(self, transaction, log_denied=False):
            transaction.add_rule(self.ipv,
                                 [ "-I", "PREROUTING", "1", "-t", "raw",
                                   "-p", "ipv6-icmp",
                                   "--icmpv6-type=router-advertisement",
                                   "-j", "ACCEPT" ]) # RHBZ#1058505
            transaction.add_rule(self.ipv,
                                 [ "-I", "PREROUTING", "2", "-t", "raw",
                                   "-m", "rpfilter", "--invert", "-j", "DROP" ])
            if log_denied != "off":
                transaction.add_rule(self.ipv,
                                     [ "-I", "PREROUTING", "2", "-t", "raw",
                                       "-m", "rpfilter", "--invert",
                                       "-j", "LOG",
                                       "--log-prefix", "rpfilter_DROP: " ])

# ipv ebtables also uses this
#
def reverse_rule(self, args):
    """ Inverse valid rule """

    replace_args = {
        # Append
        "-A": "-D",
        "--append": "--delete",
        # Insert
        "-I": "-D",
        "--insert": "--delete",
        # New chain
        "-N": "-X",
        "--new-chain": "--delete-chain",
    }

    ret_args = args[:]

    for arg in replace_args:
        try:
            idx = ret_args.index(arg)
        except Exception:
            continue

        if arg in [ "-I", "--insert" ]:
            # With insert rulenum, then remove it if it is a number
            # Opt at position idx, chain at position idx+1, [rulenum] at
            # position idx+2
            try:
                int(ret_args[idx+2])
            except Exception:
                pass
            else:
                ret_args.pop(idx+2)

        ret_args[idx] = replace_args[arg]
    return ret_args
