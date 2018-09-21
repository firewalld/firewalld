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

from firewall.core.base import SHORTCUTS, DEFAULT_ZONE_TARGET
from firewall.core.prog import runProg
from firewall.core.logger import log
from firewall.functions import tempFile, readfile, splitArgs, check_mac, portStr, \
                               check_single_address
from firewall import config
from firewall.errors import FirewallError, INVALID_PASSTHROUGH, INVALID_RULE
from firewall.core.rich import Rich_Accept, Rich_Reject, Rich_Drop, Rich_Mark
import string

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

# ipv ebtables also uses this
#
def common_reverse_rule(args):
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

def common_reverse_passthrough(args):
    """ Reverse valid passthough rule """

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

    for x in replace_args:
        try:
            idx = ret_args.index(x)
        except ValueError:
            continue

        if x in [ "-I", "--insert" ]:
            # With insert rulenum, then remove it if it is a number
            # Opt at position idx, chain at position idx+1, [rulenum] at
            # position idx+2
            try:
                int(ret_args[idx+2])
            except ValueError:
                pass
            else:
                ret_args.pop(idx+2)

        ret_args[idx] = replace_args[x]
        return ret_args

    raise FirewallError(INVALID_PASSTHROUGH,
                        "no '-A', '-I' or '-N' arg")

# ipv ebtables also uses this
#
def common_check_passthrough(args):
    """ Check if passthough rule is valid (only add, insert and new chain
    rules are allowed) """

    args = set(args)
    not_allowed = set(["-C", "--check",           # check rule
                       "-D", "--delete",          # delete rule
                       "-R", "--replace",         # replace rule
                       "-L", "--list",            # list rule
                       "-S", "--list-rules",      # print rules
                       "-F", "--flush",           # flush rules
                       "-Z", "--zero",            # zero rules
                       "-X", "--delete-chain",    # delete chain
                       "-P", "--policy",          # policy
                       "-E", "--rename-chain"])   # rename chain)
    # intersection of args and not_allowed is not empty, i.e.
    # something from args is not allowed
    if len(args & not_allowed) > 0:
        raise FirewallError(INVALID_PASSTHROUGH,
                            "arg '%s' is not allowed" %
                            list(args & not_allowed)[0])

    # args need to contain one of -A, -I, -N
    needed = set(["-A", "--append",
                  "-I", "--insert",
                  "-N", "--new-chain"])
    # empty intersection of args and needed, i.e.
    # none from args contains any needed command
    if len(args & needed) == 0:
        raise FirewallError(INVALID_PASSTHROUGH,
                            "no '-A', '-I' or '-N' arg")

class ip4tables(object):
    ipv = "ipv4"
    name = "ip4tables"
    zones_supported = True

    def __init__(self, fw):
        self._fw = fw
        self._command = config.COMMANDS[self.ipv]
        self._restore_command = config.COMMANDS["%s-restore" % self.ipv]
        self.wait_option = self._detect_wait_option()
        self.restore_wait_option = self._detect_restore_wait_option()
        self.fill_exists()
        self.available_tables = []

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

    def is_chain_builtin(self, ipv, table, chain):
        return table in BUILT_IN_CHAINS and \
               chain in BUILT_IN_CHAINS[table]

    def build_chain_rules(self, add, table, chain):
        rule = [ "-t", table ]
        if add:
            rule.append("-N")
        else:
            rule.append("-X")
        rule.append(chain)
        return [rule]

    def build_rule(self, add, table, chain, index, args):
        rule = [ "-t", table ]
        if add:
            rule += [ "-I", chain, str(index) ]
        else:
            rule += [ "-D", chain ]
        rule += args
        return rule

    def reverse_rule(self, args):
        return common_reverse_rule(args)

    def check_passthrough(self, args):
        common_check_passthrough(args)

    def reverse_passthrough(self, args):
        return common_reverse_passthrough(args)

    def passthrough_parse_table_chain(self, args):
        table = "filter"
        try:
            i = args.index("-t")
        except ValueError:
            pass
        else:
            if len(args) >= i+1:
                table = args[i+1]
        chain = None
        for opt in [ "-A", "--append",
                     "-I", "--insert",
                     "-N", "--new-chain" ]:
            try:
                i = args.index(opt)
            except ValueError:
                pass
            else:
                if len(args) >= i+1:
                    chain = args[i+1]
        return (table, chain)

    def set_rules(self, rules, log_denied):
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

    def set_rule(self, rule, log_denied):
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

    def get_available_tables(self, table=None):
        ret = []
        tables = [ table ] if table else BUILT_IN_CHAINS.keys()
        for table in tables:
            if table in self.available_tables:
                ret.append(table)
            else:
                try:
                    self.__run(["-t", table, "-L", "-n"])
                    self.available_tables.append(table)
                    ret.append(table)
                except ValueError:
                    log.debug1("%s table '%s' does not exist (or not enough permission to check)." % (self.ipv, table))

        return ret

    def _detect_wait_option(self):
        wait_option = ""
        ret = runProg(self._command, ["-w", "-L", "-n"])  # since iptables-1.4.20
        if ret[0] == 0:
            wait_option = "-w"  # wait for xtables lock
            ret = runProg(self._command, ["-w10", "-L", "-n"])  # since iptables > 1.4.21
            if ret[0] == 0:
                wait_option = "-w10"  # wait max 10 seconds
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

    def build_flush_rules(self):
        rules = []
        for table in BUILT_IN_CHAINS.keys():
            # Flush firewall rules: -F
            # Delete firewall chains: -X
            # Set counter to zero: -Z
            for flag in [ "-F", "-X", "-Z" ]:
                rules.append(["-t", table, flag])
        return rules

    def build_set_policy_rules(self, policy):
        rules = []
        for table in BUILT_IN_CHAINS.keys():
            if table == "nat":
                continue
            for chain in BUILT_IN_CHAINS[table]:
                rules.append(["-t", table, "-P", chain, policy])
        return rules

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

    def get_zone_table_chains(self, table):
        if table == "filter":
            return { "INPUT", "FORWARD_IN", "FORWARD_OUT" }
        if table == "mangle":
            if "mangle" in self.get_available_tables() and \
               "nat" in self.get_available_tables():
                return { "PREROUTING" }
        if table == "nat":
            if "nat" in self.get_available_tables():
                return { "PREROUTING", "POSTROUTING" }
        if table == "raw":
            if "raw" in self.get_available_tables():
                return { "PREROUTING" }

        return {}

    def build_zone_source_interface_rules(self, enable, zone, zone_target,
                                          interface, table, chain,
                                          append=False):
        # handle all zones in the same way here, now
        # trust and block zone targets are handled now in __chain
        opt = {
            "PREROUTING": "-i",
            "POSTROUTING": "-o",
            "INPUT": "-i",
            "FORWARD_IN": "-i",
            "FORWARD_OUT": "-o",
            "OUTPUT": "-o",
        }[chain]

        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS[chain], zone=zone)
        if zone_target == DEFAULT_ZONE_TARGET:
            action = "-g"
        else:
            action = "-j"
        if enable and not append:
            rule = [ "-I", "%s_ZONES" % chain, "1" ]
        elif enable:
            rule = [ "-A", "%s_ZONES" % chain ]
        else:
            rule = [ "-D", "%s_ZONES" % chain ]
        rule += [ "-t", table, opt, interface, action, target ]
        return [rule]

    def build_zone_source_address_rules(self, enable, zone, zone_target,
                                        address, table, chain):
        add_del = { True: "-A", False: "-D" }[enable]

        opt = {
            "PREROUTING": "-s",
            "POSTROUTING": "-d",
            "INPUT": "-s",
            "FORWARD_IN": "-s",
            "FORWARD_OUT": "-d",
            "OUTPUT": "-d",
        }[chain]

        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS[chain], zone=zone)
        if zone_target == DEFAULT_ZONE_TARGET:
            action = "-g"
        else:
            action = "-j"

        if address.startswith("ipset:"):
            name = address[6:]
            if opt == "-d":
                opt = "dst"
            else:
                opt = "src"
            flags = ",".join([opt] * self._fw.ipset.get_dimension(name))
            rule = [ add_del,
                     "%s_ZONES_SOURCE" % chain, "-t", table,
                     "-m", "set", "--match-set", name,
                     flags, action, target ]
        else:
            if check_mac(address):
                # outgoing can not be set
                if opt == "-d":
                    return ""
                rule = [ add_del,
                         "%s_ZONES_SOURCE" % chain, "-t", table,
                         "-m", "mac", "--mac-source", address.upper(),
                         action, target ]
            else:
                rule = [ add_del,
                         "%s_ZONES_SOURCE" % chain, "-t", table,
                         opt, address, action, target ]
        return [rule]

    def build_zone_chain_rules(self, zone, table, chain):
        _zone = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS[chain], zone=zone)

        OUR_CHAINS[table].update(set([_zone,
                                      "%s_log" % _zone,
                                      "%s_deny" % _zone,
                                      "%s_allow" % _zone]))

        rules = []
        rules.append([ "-N", _zone, "-t", table ])
        rules.append([ "-N", "%s_log" % _zone, "-t", table ])
        rules.append([ "-N", "%s_deny" % _zone, "-t", table ])
        rules.append([ "-N", "%s_allow" % _zone, "-t", table ])
        rules.append([ "-I", _zone, "1", "-t", table, "-j", "%s_log" % _zone ])
        rules.append([ "-I", _zone, "2", "-t", table, "-j", "%s_deny" % _zone ])
        rules.append([ "-I", _zone, "3", "-t", table, "-j", "%s_allow" % _zone ])

        # Handle trust, block and drop zones:
        # Add an additional rule with the zone target (accept, reject
        # or drop) to the base zone only in the filter table.
        # Otherwise it is not be possible to have a zone with drop
        # target, that is allowing traffic that is locally initiated
        # or that adds additional rules. (RHBZ#1055190)
        target = self._fw.zone._zones[zone].target
        if table == "filter" and \
           target in [ "ACCEPT", "REJECT", "%%REJECT%%", "DROP" ] and \
           chain in [ "INPUT", "FORWARD_IN", "FORWARD_OUT", "OUTPUT" ]:
            rules.append([ "-I", _zone, "4", "-t", table, "-j", target ])

        if self._fw.get_log_denied() != "off":
            if table == "filter" and \
               chain in [ "INPUT", "FORWARD_IN", "FORWARD_OUT", "OUTPUT" ]:
                if target in [ "REJECT", "%%REJECT%%" ]:
                    rules.append([ "-I", _zone, "4", "-t", table, "%%LOGTYPE%%",
                                   "-j", "LOG", "--log-prefix",
                                   "\"%s_REJECT: \"" % _zone ])
                if target == "DROP":
                    rules.append([ "-I", _zone, "4", "-t", table, "%%LOGTYPE%%",
                                   "-j", "LOG", "--log-prefix",
                                   "\"%s_DROP: \"" % _zone ])
        return rules

    def _rule_limit(self, limit):
        if limit:
            return [ "-m", "limit", "--limit", limit.value ]
        return []

    def _rich_rule_log(self, rich_rule, enable, table, target, rule_fragment):
        if not rich_rule.log:
            return []

        add_del = { True: "-A", False: "-D" }[enable]

        rule = [ add_del, "%s_log" % (target), "-t", table]
        rule += rule_fragment + [ "-j", "LOG" ]
        if rich_rule.log.prefix:
            rule += [ "--log-prefix", "'%s'" % rich_rule.log.prefix ]
        if rich_rule.log.level:
            rule += [ "--log-level", "%s" % rich_rule.log.level ]
        rule += self._rule_limit(rich_rule.log.limit)

        return rule

    def _rich_rule_audit(self, rich_rule, enable, table, target, rule_fragment):
        if not rich_rule.audit:
            return []

        add_del = { True: "-A", False: "-D" }[enable]

        rule = [add_del, "%s_log" % (target), "-t", table] + rule_fragment
        if type(rich_rule.action) == Rich_Accept:
            _type = "accept"
        elif type(rich_rule.action) == Rich_Reject:
            _type = "reject"
        elif type(rich_rule.action) ==  Rich_Drop:
            _type = "drop"
        else:
            _type = "unknown"
        rule += [ "-j", "AUDIT", "--type", _type ]
        rule += self._rule_limit(rich_rule.audit.limit)

        return rule

    def _rich_rule_action(self, zone, rich_rule, enable, table, target, rule_fragment):
        if not rich_rule.action:
            return []

        add_del = { True: "-A", False: "-D" }[enable]

        if type(rich_rule.action) == Rich_Accept:
            chain = "%s_allow" % target
            rule_action = [ "-j", "ACCEPT" ]
        elif type(rich_rule.action) == Rich_Reject:
            chain = "%s_deny" % target
            rule_action = [ "-j", "REJECT" ]
            if rich_rule.action.type:
                rule_action += [ "--reject-with", rich_rule.action.type ]
        elif type(rich_rule.action) ==  Rich_Drop:
            chain = "%s_deny" % target
            rule_action = [ "-j", "DROP" ]
        elif type(rich_rule.action) == Rich_Mark:
            chain = "%s_allow" % target
            table = "mangle"
            target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["PREROUTING"],
                                                zone=zone)
            rule_action = [ "-j", "MARK", "--set-xmark", rich_rule.action.set ]
        else:
            raise FirewallError(INVALID_RULE,
                                "Unknown action %s" % type(rich_rule.action))

        rule = [ add_del, chain, "-t", table ]
        rule += rule_fragment + rule_action
        rule += self._rule_limit(rich_rule.action.limit)

        return rule

    def _rich_rule_destination_fragment(self, rich_dest):
        if not rich_dest:
            return []

        rule_fragment = []
        if rich_dest.invert:
            rule_fragment.append("!")
        rule_fragment += [ "-d", rich_dest.addr ]

        return rule_fragment

    def _rich_rule_source_fragment(self, rich_source):
        if not rich_source:
            return []

        rule_fragment = []
        if rich_source.addr:
            if rich_source.invert:
                rule_fragment.append("!")
            rule_fragment += [ "-s", rich_source.addr ]
        elif hasattr(rich_source, "mac") and rich_source.mac:
            rule_fragment += [ "-m", "mac" ]
            if rich_source.invert:
                rule_fragment.append("!")
            rule_fragment += [ "--mac-source", rich_source.mac ]
        elif hasattr(rich_source, "ipset") and rich_source.ipset:
            rule_fragment += [ "-m", "set" ]
            if rich_source.invert:
                rule_fragment.append("!")
            flags = self._fw.zone._ipset_match_flags(rich_source.ipset, "src")
            rule_fragment += [ "--match-set", rich_source.ipset, flags ]

        return rule_fragment

    def build_zone_ports_rules(self, enable, zone, proto, port, destination=None, rich_rule=None):
        add_del = { True: "-A", False: "-D" }[enable]
        table = "filter"
        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["INPUT"],
                                            zone=zone)

        rule_fragment = [ "-p", proto ]
        if port:
            rule_fragment += [ "--dport", "%s" % portStr(port) ]
        if destination:
            rule_fragment += [ "-d", destination ]
        if rich_rule:
            rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
            rule_fragment += self._rich_rule_source_fragment(rich_rule.source)
        if not rich_rule or rich_rule.action != Rich_Mark:
            rule_fragment += [ "-m", "conntrack", "--ctstate", "NEW,UNTRACKED" ]

        rules = []
        if rich_rule:
            rules.append(self._rich_rule_log(rich_rule, enable, table, target, rule_fragment))
            rules.append(self._rich_rule_audit(rich_rule, enable, table, target, rule_fragment))
            rules.append(self._rich_rule_action(zone, rich_rule, enable, table, target, rule_fragment))
        else:
            rules.append([add_del, "%s_allow" % (target), "-t", table] +
                         rule_fragment + [ "-j", "ACCEPT" ])

        return rules

    def build_zone_protocol_rules(self, enable, zone, protocol, destination=None, rich_rule=None):
        add_del = { True: "-A", False: "-D" }[enable]
        table = "filter"
        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["INPUT"], zone=zone)

        rule_fragment = [ "-p", protocol ]
        if destination:
            rule_fragment += [ "-d", destination ]
        if rich_rule:
            rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
            rule_fragment += self._rich_rule_source_fragment(rich_rule.source)
        if not rich_rule or rich_rule.action != Rich_Mark:
            rule_fragment += [ "-m", "conntrack", "--ctstate", "NEW,UNTRACKED" ]

        rules = []
        if rich_rule:
            rules.append(self._rich_rule_log(rich_rule, enable, table, target, rule_fragment))
            rules.append(self._rich_rule_audit(rich_rule, enable, table, target, rule_fragment))
            rules.append(self._rich_rule_action(zone, rich_rule, enable, table, target, rule_fragment))
        else:
            rules.append([add_del, "%s_allow" % (target), "-t", table] +
                         rule_fragment + [ "-j", "ACCEPT" ])

        return rules

    def build_zone_source_ports_rules(self, enable, zone, proto, port,
                                     destination=None, rich_rule=None):
        add_del = { True: "-A", False: "-D" }[enable]
        table = "filter"
        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["INPUT"], zone=zone)

        rule_fragment = [ "-p", proto ]
        if port:
            rule_fragment += [ "--sport", "%s" % portStr(port) ]
        if destination:
            rule_fragment += [ "-d", destination ]
        if rich_rule:
            rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
            rule_fragment += self._rich_rule_source_fragment(rich_rule.source)
        if not rich_rule or rich_rule.action != Rich_Mark:
            rule_fragment += [ "-m", "conntrack", "--ctstate", "NEW,UNTRACKED" ]

        rules = []
        if rich_rule:
            rules.append(self._rich_rule_log(rich_rule, enable, table, target, rule_fragment))
            rules.append(self._rich_rule_audit(rich_rule, enable, table, target, rule_fragment))
            rules.append(self._rich_rule_action(zone, rich_rule, enable, table, target, rule_fragment))
        else:
            rules.append([add_del, "%s_allow" % (target), "-t", table] +
                         rule_fragment + [ "-j", "ACCEPT" ])

        return rules

    def build_zone_helper_ports_rules(self, enable, zone, proto, port,
                                      destination, helper_name):
        add_del = { True: "-A", False: "-D" }[enable]
        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["PREROUTING"],
                                            zone=zone)
        rule = [ add_del, "%s_allow" % (target), "-t", "raw", "-p", proto ]
        if port:
            rule += [ "--dport", "%s" % portStr(port) ]
        if destination:
            rule += [ "-d",  destination ]
        rule += [ "-j", "CT", "--helper", helper_name ]

        return [rule]

    def build_zone_masquerade_rules(self, enable, zone, rich_rule=None):
        add_del = { True: "-A", False: "-D" }[enable]
        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["POSTROUTING"],
                                            zone=zone)
        rule_fragment = []
        if rich_rule:
            rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
            rule_fragment += self._rich_rule_source_fragment(rich_rule.source)

        rules = []
        rules.append([ add_del, "%s_allow" % (target), "-t", "nat" ]
                     + rule_fragment +
                     [ "!", "-o", "lo", "-j", "MASQUERADE" ])
        # FORWARD_OUT
        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["FORWARD_OUT"],
                                            zone=zone)
        rule_fragment = []
        if rich_rule:
            rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
            rule_fragment += self._rich_rule_source_fragment(rich_rule.source)

        rules.append([ add_del, "%s_allow" % (target), "-t", "filter"]
                     + rule_fragment +
                     ["-m", "conntrack", "--ctstate", "NEW,UNTRACKED", "-j", "ACCEPT" ])

        return rules

    def build_zone_forward_port_rules(self, enable, zone, filter_chain, port,
                                      protocol, toport, toaddr, mark_id, rich_rule=None):
        add_del = { True: "-A", False: "-D" }[enable]

        mark_str = "0x%x" % mark_id
        mark = [ "-m", "mark", "--mark", mark_str ]

        to = ""
        if toaddr:
            if check_single_address("ipv6", toaddr):
                to += "[%s]" % toaddr
            else:
                to += toaddr
        if toport and toport != "":
            to += ":%s" % portStr(toport, "-")

        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["PREROUTING"],
                                            zone=zone)

        rule_fragment = [ "-p", protocol, "--dport", portStr(port) ]
        if rich_rule:
            rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
            rule_fragment += self._rich_rule_source_fragment(rich_rule.source)

        rules = []
        if rich_rule:
            rules.append(self._rich_rule_log(rich_rule, enable, "mangle", target, rule_fragment))
        rules.append([ add_del, "%s_allow" % (target), "-t", "mangle"]
                     + rule_fragment + 
                     [ "-j", "MARK", "--set-mark", mark_str ])

        # local and remote
        rules.append([ add_del, "%s_allow" % (target), "-t", "nat",
                     "-p", protocol ] + mark +
                     [ "-j", "DNAT", "--to-destination", to ])

        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS[filter_chain],
                                            zone=zone)
        rules.append([ add_del, "%s_allow" % (target),
                     "-t", "filter", "-m", "conntrack",
                     "--ctstate", "NEW,UNTRACKED" ] +
                     mark + [ "-j", "ACCEPT" ])

        return rules

    def build_zone_icmp_block_rules(self, enable, zone, ict, rich_rule=None):
        table = "filter"
        add_del = { True: "-A", False: "-D" }[enable]

        if self.ipv == "ipv4":
            proto = [ "-p", "icmp" ]
            match = [ "-m", "icmp", "--icmp-type", ict.name ]
        else:
            proto = [ "-p", "ipv6-icmp" ]
            match = [ "-m", "icmp6", "--icmpv6-type", ict.name ]

        rules = []
        for chain in ["INPUT", "FORWARD_IN"]:
            target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS[chain],
                                                zone=zone)
            if self._fw.zone.query_icmp_block_inversion(zone):
                final_chain = "%s_allow" % target
                final_target = "ACCEPT"
            else:
                final_chain = "%s_deny" % target
                final_target = "%%REJECT%%"

            rule_fragment = []
            if rich_rule:
                rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
                rule_fragment += self._rich_rule_source_fragment(rich_rule.source)
            rule_fragment += proto + match

            if rich_rule:
                rules.append(self._rich_rule_log(rich_rule, enable, table, target, rule_fragment))
                rules.append(self._rich_rule_audit(rich_rule, enable, table, target, rule_fragment))
                if rich_rule.action:
                    rules.append(self._rich_rule_action(zone, rich_rule, enable, table, target, rule_fragment))
                else:
                    rules.append([ add_del, "%s_deny" % target, "-t", table ]
                                 + rule_fragment +
                                 [ "-j", "%%REJECT%%" ])
            else:
                if self._fw.get_log_denied() != "off" and final_target != "ACCEPT":
                    rules.append([ add_del, final_chain, "-t", table ]
                                 + rule_fragment +
                                 [ "%%LOGTYPE%%", "-j", "LOG",
                                   "--log-prefix", "\"%s_ICMP_BLOCK: \"" % zone ])
                rules.append([ add_del, final_chain, "-t", table ]
                             + rule_fragment +
                             [ "-j", final_target ])

        return rules

    def build_zone_icmp_block_inversion_rules(self, enable, zone):
        table = "filter"
        rules = []
        for chain in [ "INPUT", "FORWARD_IN" ]:
            rule_idx = 4
            _zone = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS[chain],
                                               zone=zone)

            if self._fw.zone.query_icmp_block_inversion(zone):
                ibi_target = "%%REJECT%%"

                if self._fw.get_log_denied() != "off":
                    if enable:
                        rule = [ "-I", _zone, str(rule_idx) ]
                    else:
                        rule = [ "-D", _zone ]

                    rule = rule + [ "-t", table, "-p", "%%ICMP%%",
                                  "%%LOGTYPE%%",
                                  "-j", "LOG", "--log-prefix",
                                  "\"%s_ICMP_BLOCK: \"" % _zone ]
                    rules.append(rule)
                    rule_idx += 1
            else:
                ibi_target = "ACCEPT"

            if enable:
                rule = [ "-I", _zone, str(rule_idx) ]
            else:
                rule = [ "-D", _zone ]
            rule = rule + [ "-t", table, "-p", "%%ICMP%%", "-j", ibi_target ]
            rules.append(rule)

        return rules

    def build_zone_rich_source_destination_rules(self, enable, zone, rich_rule):
        table = "filter"
        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["INPUT"],
                                            zone=zone)

        rule_fragment = []
        rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
        rule_fragment += self._rich_rule_source_fragment(rich_rule.source)

        rules = []
        rules.append(self._rich_rule_log(rich_rule, enable, table, target, rule_fragment))
        rules.append(self._rich_rule_audit(rich_rule, enable, table, target, rule_fragment))
        rules.append(self._rich_rule_action(zone, rich_rule, enable, table, target, rule_fragment))

        return rules

    def is_ipv_supported(self, ipv):
        return ipv == self.ipv

class ip6tables(ip4tables):
    ipv = "ipv6"
    name = "ip6tables"

    def build_rpfilter_rules(self, log_denied=False):
        rules = []
        rules.append([ "-I", "PREROUTING", "1", "-t", "raw",
                       "-p", "ipv6-icmp",
                       "--icmpv6-type=neighbour-solicitation",
                       "-j", "ACCEPT" ]) # RHBZ#1575431, kernel bug in 4.16-4.17
        rules.append([ "-I", "PREROUTING", "2", "-t", "raw",
                       "-p", "ipv6-icmp",
                       "--icmpv6-type=router-advertisement",
                       "-j", "ACCEPT" ]) # RHBZ#1058505
        rules.append([ "-I", "PREROUTING", "3", "-t", "raw",
                       "-m", "rpfilter", "--invert", "-j", "DROP" ])
        if log_denied != "off":
            rules.append([ "-I", "PREROUTING", "3", "-t", "raw",
                           "-m", "rpfilter", "--invert",
                           "-j", "LOG",
                           "--log-prefix", "rpfilter_DROP: " ])
        return rules
