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
from firewall.config import *
from firewall import functions
from firewall.core import ipXtables
from firewall.core import ebtables
from firewall.core import modules
from firewall.core.fw_icmptype import FirewallIcmpType
from firewall.core.fw_service import FirewallService
from firewall.core.fw_zone import FirewallZone
from firewall.core.logger import log
from firewall.core.io.firewalld_conf import firewalld_conf
from firewall.core.io.service import service_reader
from firewall.core.io.icmptype import icmptype_reader
from firewall.core.io.zone import zone_reader
from firewall.errors import *

############################################################################
#
# class Firewall
#
############################################################################

class FirewallDirect:
    def __init__(self, fw):
        self._fw = fw
        self.__init_vars()

    def __init_vars(self):
        self._chains = { }
        self._rules = { }
        self._rule_priority_positions = { }

    def cleanup(self):
        self.__init_vars()

    def get_config(self):
        return (self._chains, self._rules)

    def set_config(self, config):
        (_chains, _rules) = config
        for table_id in _chains:
            (ipv, table) = table_id
            for chain in _chains[table_id]:
                self.__chain(True, ipv, table, chain)
        for chain_id in _rules:
            (ipv, table, chain) = chain_id
            for args in _rules[chain_id]:
                priority = _rules[chain_id][args]
                self.__rule(True, ipv, table, chain, priority, args)

    # DIRECT CHAIN

    def __chain(self, add, ipv, table, chain):
        table_id = (ipv, table)

        if add:
            if table_id in self._chains and \
                    chain in self._chains[table_id]:
                raise FirewallError(ALREADY_ENABLED)
        else:
            if table_id not in self._chains or \
                    not chain in self._chains[table_id]:
                raise FirewallError(NOT_ENABLED)

        rule = [ "-t", table ]
        if add:
            rule.append("-N")
        else:
            rule.append("-X")
        rule.append(chain)

        try:
            self._fw.rule(ipv, rule)
        except Exception, msg:
            log.debug2(msg)
            if add:
                raise FirewallError(ENABLE_FAILED, msg)
            else:
                raise FirewallError(DISABLE_FAILED, msg)

        if add:
            self._chains.setdefault(table_id, [ ]).append(chain)
        else:
            self._chains[table_id].remove(chain)
            if len(self._chains[table_id]) == 0:
                del self._chains[table_id]

    def add_chain(self, ipv, table, chain):
        #TODO: policy="ACCEPT"
        self.__chain(True, ipv, table, chain)

    def remove_chain(self, ipv, table, chain):
        self.__chain(False, ipv, table, chain)

    def query_chain(self, ipv, table, chain):
        table_id = (ipv, table)
        return (table_id in self._chains and \
                    chain_id in self._chains[table_id])

    def get_chains(self, ipv, table):
        table_id = (ipv, table)
        if table_id in self._chains:
            return self._chains[table_id]
        else:
            return [ ]

    # DIRECT RULE

    def __rule(self, enable, ipv, table, chain, priority, args):
        _chain = chain
        # use "%s_chain" for built-in chains

        if ipv in [ "ipv4", "ipv6" ]:
            _CHAINS = ipXtables.CHAINS
        else:
            _CHAINS = ebtables.CHAINS

        if table in _CHAINS and chain in _CHAINS[table]:
            _chain = "%s_direct" % (chain)

        chain_id = (ipv, table, _chain)

        if enable:
            if chain_id in self._rules and \
                    args in self._rules[chain_id]:
                raise FirewallError(ALREADY_ENABLED)
        else:
            if not chain_id in self._rules or \
                    not args in self._rules[chain_id]:
                raise FirewallError(NOT_ENABLED)
            # get priority of rule
            priority = self._rules[chain_id][args]

        # sum number of rules for all positions up to position (including)
        # sort used positions
        index = 1
        if chain_id in self._rule_priority_positions:
            positions = sorted(self._rule_priority_positions[chain_id].keys())
            j = 0
            while j < len(positions) and priority >= positions[j]:
                index += self._rule_priority_positions[chain_id][positions[j]]
                j += 1

        rule = [ "-t", table ]
        if enable:
            rule += [ "-I", _chain, index ]
        else:
            rule += [ "-D", _chain ]
        rule += args

        try:
            self._fw.rule(ipv, rule)
        except Exception, msg:
            log.debug2(msg)
            if enable:
                raise FirewallError(ENABLE_FAILED, msg)
            else:
                raise FirewallError(DISABLE_FAILED, msg)

        if enable:
            if not chain_id in self._rules:
                self._rules[chain_id] = { }
            self._rules[chain_id][args] = priority
            if chain_id not in self._rule_priority_positions:
                self._rule_priority_positions[chain_id] = { }

            if priority in self._rule_priority_positions[chain_id]:
                self._rule_priority_positions[chain_id][priority] += 1
            else:
                self._rule_priority_positions[chain_id][priority] = 1
        else:
            del self._rules[chain_id][args]
            if len(self._rules[chain_id]) == 0:
                del self._rules[chain_id]
            self._rule_priority_positions[chain_id][priority] -= 1

    def add_rule(self, ipv, table, chain, priority, args):
        self.__rule(True, ipv, table, chain, priority, args)

    def remove_rule(self, ipv, table, chain, args):
        # priority of rule will be gathered in __rule
        self.__rule(False, ipv, table, chain, 0, args)

    def query_rule(self, ipv, table, chain, args):
        _chain = chain
        # use "%s_chain" for built-in chains
        if ipv in [ "ipv4", "ipv6" ]:
            _CHAINS = ipXtables.CHAINS
        else:
            _CHAINS = ebtables.CHAINS
        if table in _CHAINS and chain in _CHAINS[table]:
            _chain = "%s_direct" % (chain)
        chain_id = (ipv, table, _chain)
        return (chain_id in self._rules and \
                    args in self._rules[chain_id])

    def get_rules(self, ipv, table, chain):
        _chain = chain
        # use "%s_chain" for built-in chains
        if ipv in [ "ipv4", "ipv6" ]:
            _CHAINS = ipXtables.CHAINS
        else:
            _CHAINS = ebtables.CHAINS
        if table in _CHAINS and chain in _CHAINS[table]:
            _chain = "%s_direct" % (chain)
        chain_id = (ipv, table, _chain)

        if chain_id in self._rules:
            return self._rules[chain_id]
        return [ ]

    # DIRECT PASSTROUGH

    def passthrough(self, ipv, args):
        try:
            return self._fw.rule(ipv, args)
        except Exception, msg:
            log.debug2(msg)
            raise FirewallError(COMMAND_FAILED, msg)
