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

import os.path, errno
from firewall.core.prog import runProg
from firewall.core.logger import log
from firewall.functions import tempFile

PROC_IPxTABLE_NAMES = {
}

BUILT_IN_CHAINS = {
    "broute": [ "BROUTING" ],
    "nat": [ "PREROUTING", "POSTROUTING", "OUTPUT" ],
    "filter": [ "INPUT", "OUTPUT", "FORWARD" ],
}

DEFAULT_RULES = { }
OUR_CHAINS = {}  # chains created by firewalld

for table in BUILT_IN_CHAINS.keys():
    DEFAULT_RULES[table] = [ ]
    OUR_CHAINS[table] = set()
    for chain in BUILT_IN_CHAINS[table]:
        DEFAULT_RULES[table].append("-N %s_direct -P RETURN" % chain)
        DEFAULT_RULES[table].append("-I %s 1 -j %s_direct" % (chain, chain))
        OUR_CHAINS[table].add("%s_direct" % chain)

class ebtables(object):
    def __init__(self):
        command_path = lambda cmd: cmd if os.path.exists(cmd) else "/usr" + cmd
        self._command = command_path("/sbin/ebtables")
        self._restore_command = command_path("/sbin/ebtables-restore")
        self.ebtables_lock = "/var/lib/ebtables/lock"
        self.__remove_dangling_lock()

    def __remove_dangling_lock(self):
        if os.path.exists(self.ebtables_lock):
            (status, ret) = runProg("pidof", [ "-s", "ebtables" ])
            if ret == "":
                log.warning("Removing dangling ebtables lock file: '%s'" %
                            self.ebtables_lock)
                try:
                    os.unlink(self.ebtables_lock)
                except OSError as e:
                    if e.errno != errno.ENOENT:
                        raise

    def __run(self, args):
        # convert to string list
        _args = ["--concurrent"] + ["%s" % item for item in args]
        log.debug2("%s: %s %s", self.__class__, self._command, " ".join(_args))
        self.__remove_dangling_lock()
        (status, ret) = runProg(self._command, _args)
        if status != 0:
            raise ValueError("'%s %s' failed: %s" % (self._command,
                                                     " ".join(args), ret))
        return ret

    def set_rules(self, rules, flush=False):
        temp_file = tempFile()

        table = None
        for rule in rules:
            try:
                i = rule.index("-t")
            except:
                pass
            else:
                if len(rule) >= i+1:
                    rule.pop(i)
                    _table = rule.pop(i)
                    if _table != table:
                        table = _table
                        temp_file.write("*%s\n" % table)
                temp_file.write(" ".join(rule) + "\n")
        temp_file.close()

        log.debug2("%s: %s %s", self.__class__, self._restore_command, "...")
        (status, ret) = runProg(self._restore_command, [ ],
                                stdin=temp_file.name)
        if status != 0:
            os.unlink(temp_file.name)
            raise ValueError("'%s %s' failed: %s" % (self._restore_command,
                                                     " ".join(args), ret))
        os.unlink(temp_file.name)
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
                self.__run(["-t", table, "-L"])
                ret.append(table)
            except ValueError:
                log.debug1("ebtables table '%s' does not exist." % table)

        return ret

    def used_tables(self):
        return list(BUILT_IN_CHAINS.keys())

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

        rules = [ ]
        for table in tables:
            for chain in BUILT_IN_CHAINS[table]:
                if individual:
                    self.__run([ "-t", table, "-P", chain, policy ])
                else:
                    rules.append([ "-t", table, "-P", chain, policy ])
        if len(rules) > 0:
            self.set_rules(rules)

ebtables_available_tables = ebtables().available_tables()
