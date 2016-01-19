# -*- coding: utf-8 -*-
#
# Copyright (C) 2010-2012 Red Hat, Inc.
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
from firewall.functions import tempFile, readfile

COMMAND = {
    "ipv4": "/sbin/iptables",
    "ipv6": "/sbin/ip6tables",
}

RESTORE_COMMAND = {
    "ipv4": "/sbin/iptables-restore",
    "ipv6": "/sbin/ip6tables-restore",
}

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
    "-I INPUT 6 -p %%ICMP%% -j ACCEPT",
    "-I INPUT 7 -m conntrack --ctstate INVALID -j DROP",
    "-I INPUT 8 -j %%REJECT%%",

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
    "-I FORWARD 8 -p %%ICMP%% -j ACCEPT",
    "-I FORWARD 9 -m conntrack --ctstate INVALID -j DROP",
    "-I FORWARD 10 -j %%REJECT%%",

    "-N OUTPUT_direct",

    "-I OUTPUT 1 -j OUTPUT_direct",
]
OUR_CHAINS["filter"] = set(["INPUT_direct", "INPUT_ZONES_SOURCE", "INPUT_ZONES",
                            "FORWARD_direct", "FORWARD_IN_ZONES_SOURCE",
                            "FORWARD_IN_ZONES", "FORWARD_OUT_ZONES_SOURCE",
                            "FORWARD_OUT_ZONES", "OUTPUT_direct"])

class ip4tables(object):
    ipv = "ipv4"

    def __init__(self):
        self._command = COMMAND[self.ipv]
        self._restore_command = RESTORE_COMMAND[self.ipv]
        self.wait_option = self._detect_wait_option()

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

    def set_rules(self, rules, flush=False):
        temp_file = tempFile()

        table = None
        table_rules = { }
        for rule in rules:
            try:
                i = rule.index("-t")
            except:
                pass
            else:
                if len(rule) >= i+1:
                    rule.pop(i)
                    table = rule.pop(i)

            table_rules.setdefault(table, []).append(rule)

        for table in table_rules:
            temp_file.write("*%s\n" % table)
            for rule in table_rules[table]:
                temp_file.write(" ".join(rule) + "\n")
            temp_file.write("COMMIT\n")

        temp_file.close()

        stat = os.stat(temp_file.name)
        log.debug2("%s: %s %s", self.__class__, self._restore_command,
                   "%s: %d" % (temp_file.name, stat.st_size))
        args = [ ]
        if not flush:
            args.append("-n")

        (status, ret) = runProg(self._restore_command, args,
                                stdin=temp_file.name)

        if log.getDebugLogLevel() > 2:
            try:
                lines = readfile(temp_file.name)
            except:
                pass
            else:
                i = 1
                for line in readfile(temp_file.name):
                    log.debug3("%8d: %s" % (i, line), nofmt=1, nl=0)
                    if not line.endswith("\n"):
                        log.debug3("", nofmt=1)
                    i += 1

        os.unlink(temp_file.name)

        if status != 0:
            raise ValueError("'%s %s' failed: %s" % (self._restore_command,
                                                     " ".join(args), ret))
        return ret

    def set_rule(self, rule):
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
        (status, ret) = runProg(self._command, ["-w", "-L", "-n"])  # since iptables-1.4.20
        if status == 0:
            wait_option = "-w"  # wait for xtables lock
            (status, ret) = runProg(self._command, ["-w2", "-L", "-n"])  # since iptables > 1.4.21
            if status == 0:
                wait_option = "-w2"  # wait max 2 seconds
            log.debug2("%s: %s will be using %s option.", self.__class__, self._command, wait_option)

        return wait_option

    def flush(self, individual=False):
        tables = self.used_tables()
        rules = [ ]
        for table in tables:
            # Flush firewall rules: -F
            # Delete firewall chains: -X
            # Set counter to zero: -Z
            for flag in [ "-F", "-X", "-Z" ]:
                if individual:
                    self.__run([ "-t", table, flag ])
                else:
                    rules.append([ "-t", table, flag ])
        if len(rules) > 0:
            self.set_rules(rules)

    def set_policy(self, policy, which="used", individual=False):
        if which == "used":
            tables = self.used_tables()
        else:
            tables = list(BUILT_IN_CHAINS.keys())

        if "nat" in tables:
            tables.remove("nat") # nat can not set policies in nat table

        rules = [ ]
        for table in tables:
            for chain in BUILT_IN_CHAINS[table]:
                if individual:
                    self.__run([ "-t", table, "-P", chain, policy ])
                else:
                    rules.append([ "-t", table, "-P", chain, policy ])
        if len(rules) > 0:
            self.set_rules(rules)

class ip6tables(ip4tables):
    ipv = "ipv6"

ip4tables_available_tables = ip4tables().available_tables()
ip6tables_available_tables = ip6tables().available_tables()
