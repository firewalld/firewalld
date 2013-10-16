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

from firewall.core.prog import runProg
from firewall.core.logger import log

PROC_IPxTABLE_NAMES = {
}

CHAINS = {
    "broute": [ "BROUTING" ],
    "nat": [ "PREROUTING", "POSTROUTING", "OUTPUT" ],
    "filter": [ "INPUT", "OUTPUT", "FORWARD" ],
}

DEFAULT_RULES = { }

class ebtables:
    ipv = "ipv4"

    def __init__(self):
        self._command = "/sbin/ebtables"

    def __run(self, args):
        # convert to string list
        _args = ["%s" % item for item in args]
        log.debug2("%s: %s %s", self.__class__, self._command, " ".join(_args))
        (status, ret) = runProg(self._command, _args)
        if status != 0:
            raise ValueError("'%s %s' failed: %s" % (self._command,
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
        tables = [ table ] if table else CHAINS.keys()
        for table in tables:
            try:
                self.__run(["-t", table, "-L"])
                ret.append(table)
            except ValueError:
                log.warning("ebtables table '%s' does not exist." % table)

        return ret

    def used_tables(self):
        return list(CHAINS.keys())

    def flush(self):
        tables = self.used_tables()
        for table in tables:
            # Flush firewall rules: -F
            # Delete firewall chains: -X
            # Set counter to zero: -Z
            for flag in [ "-F", "-X", "-Z" ]:
                self.__run([ "-t", table, flag ])

    def set_policy(self, policy, which="used"):
        if which == "used":
            tables = self.used_tables()
        else:
            tables = list(CHAINS.keys())

        if "nat" in tables:
            tables.remove("nat") # nat can not set policies in nat table

        for table in tables:
            for chain in CHAINS[table]:
                self.__run([ "-t", table, "-P", chain, policy ])

ebtables_available_tables = ebtables().available_tables()
