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

__all__ = [ "FirewallDirectIPTables" ]

from firewall.fw_types import *
from firewall.core import ipXtables
from firewall.core import ebtables
from firewall.core.fw_transaction import FirewallTransaction
from firewall.core.logger import log
from firewall import errors
from firewall.errors import FirewallError

############################################################################
#
# class Firewall
#
############################################################################

class FirewallDirect(object):
    def __init__(self, fw):
        self._fw = fw
        self.__init_vars()

    def __repr__(self):
        return '%s(%r, %r, %r)' % (self.__class__, self._chains, self._rules,
                                   self._rule_priority_positions)

    def __init_vars(self):
        self._chains = { }
        self._rules = { }
        self._rule_priority_positions = { }
        self._passthroughs = { }
        self._obj = None

    def cleanup(self):
        self.__init_vars()

    # transaction

    def new_transaction(self):
        return FirewallTransaction(self._fw)

    # configuration

    def set_permanent_config(self, obj):
        self._obj = obj

    def has_configuration(self):
        if len(self._chains) + len(self._rules) + len(self._passthroughs) > 0:
            return True
        if len(self._obj.get_all_chains()) + \
           len(self._obj.get_all_rules()) + \
           len(self._obj.get_all_passthroughs()) > 0:
            return True
        return False

    def apply_direct(self, use_transaction=None):
        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        # Apply permanent configuration and save the obj to be able to
        # remove permanent configuration settings within get_runtime_config
        # for use in firewalld reload.
        self.set_config((self._obj.get_all_chains(),
                         self._obj.get_all_rules(),
                         self._obj.get_all_passthroughs()),
                        transaction)

        if use_transaction is None:
            transaction.execute(True)

    def get_runtime_config(self):
        # Return only runtime changes
        # Remove all chains, rules and passthroughs that are in self._obj
        # (permanent config applied in firewalld _start.
        chains = { }
        rules = { }
        passthroughs = { }

        for table_id in self._chains:
            (ipv, table) = table_id
            for chain in self._chains[table_id]:
                if not self._obj.query_chain(ipv, table, chain):
                    chains.setdefault(table_id, [ ]).append(chain)

        for chain_id in self._rules:
            (ipv, table, chain) = chain_id
            for (priority, args) in self._rules[chain_id]:
                if not self._obj.query_rule(ipv, table, chain, priority, args):
                    if chain_id not in rules:
                        rules[chain_id] = LastUpdatedOrderedDict()
                    rules[chain_id][(priority, args)] = priority

        for ipv in self._passthroughs:
            for args in self._passthroughs[ipv]:
                if not self._obj.query_passthrough(ipv, args):
                    if ipv not in passthroughs:
                        passthroughs[ipv] = [ ]
                    passthroughs[ipv].append(args)

        return (chains, rules, passthroughs)

    def get_config(self):
        return (self._chains, self._rules, self._passthroughs)

    def set_config(self, conf, use_transaction=None):
        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        (_chains, _rules, _passthroughs) = conf
        for table_id in _chains:
            (ipv, table) = table_id
            for chain in _chains[table_id]:
                if not self.query_chain(ipv, table, chain):
                    try:
                        self.add_chain(ipv, table, chain,
                                       use_transaction=transaction)
                    except FirewallError as error:
                        log.warning(str(error))

        for chain_id in _rules:
            (ipv, table, chain) = chain_id
            for (priority, args) in _rules[chain_id]:
                if not self.query_rule(ipv, table, chain, priority, args):
                    try:
                        self.add_rule(ipv, table, chain, priority, args,
                                      use_transaction=transaction)
                    except FirewallError as error:
                        log.warning(str(error))

        for ipv in _passthroughs:
            for args in _passthroughs[ipv]:
                if not self.query_passthrough(ipv, args):
                    try:
                        self.add_passthrough(ipv, args,
                                             use_transaction=transaction)
                    except FirewallError as error:
                        log.warning(str(error))

        if use_transaction is None:
            transaction.execute(True)

    def _check_ipv(self, ipv):
        ipvs = ['ipv4', 'ipv6', 'eb']
        if ipv not in ipvs:
            raise FirewallError(errors.INVALID_IPV,
                                "'%s' not in '%s'" % (ipv, ipvs))

    def _check_ipv_table(self, ipv, table):
        self._check_ipv(ipv)

        tables = ipXtables.BUILT_IN_CHAINS.keys() if ipv in [ 'ipv4', 'ipv6' ] \
                                         else ebtables.BUILT_IN_CHAINS.keys()
        if table not in tables:
            raise FirewallError(errors.INVALID_TABLE,
                                "'%s' not in '%s'" % (table, tables))

    def _check_builtin_chain(self, ipv, table, chain):
        if ipv in ['ipv4', 'ipv6']:
            built_in_chains = ipXtables.BUILT_IN_CHAINS[table]
            our_chains = ipXtables.OUR_CHAINS[table]
        else:
            built_in_chains = ebtables.BUILT_IN_CHAINS[table]
            our_chains = ebtables.OUR_CHAINS[table]
        if chain in built_in_chains:
            raise FirewallError(errors.BUILTIN_CHAIN,
                                "chain '%s' is built-in chain" % chain)
        if chain in our_chains:
            raise FirewallError(errors.BUILTIN_CHAIN,
                                "chain '%s' is reserved" % chain)
        if ipv in [ "ipv4", "ipv6" ]:
            if self._fw.zone.zone_from_chain(chain) != None:
                raise FirewallError(errors.INVALID_CHAIN,
                                    "Chain '%s' is reserved" % chain)


    def _register_chain(self, table_id, chain, add):
        if add:
            self._chains.setdefault(table_id, [ ]).append(chain)
        else:
            self._chains[table_id].remove(chain)
            if len(self._chains[table_id]) == 0:
                del self._chains[table_id]

    def add_chain(self, ipv, table, chain, use_transaction=None):
        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        #TODO: policy="ACCEPT"
        self._chain(True, ipv, table, chain, transaction)

        if use_transaction is None:
            transaction.execute(True)

    def remove_chain(self, ipv, table, chain, use_transaction=None):
        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        self._chain(False, ipv, table, chain, transaction)

        if use_transaction is None:
            transaction.execute(True)

    def query_chain(self, ipv, table, chain):
        self._check_ipv_table(ipv, table)
        self._check_builtin_chain(ipv, table, chain)
        table_id = (ipv, table)
        return (table_id in self._chains and
                chain in self._chains[table_id])

    def get_chains(self, ipv, table):
        self._check_ipv_table(ipv, table)
        table_id = (ipv, table)
        if table_id in self._chains:
            return self._chains[table_id]
        return [ ]

    def get_all_chains(self):
        r = [ ]
        for key in self._chains:
            (ipv, table) = key
            for chain in self._chains[key]:
                r.append((ipv, table, chain))
        return r


    def add_rule(self, ipv, table, chain, priority, args, use_transaction=None):
        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        self._rule(True, ipv, table, chain, priority, args, transaction)

        if use_transaction is None:
            transaction.execute(True)

    def remove_rule(self, ipv, table, chain, priority, args,
                    use_transaction=None):
        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        self._rule(False, ipv, table, chain, priority, args, transaction)

        if use_transaction is None:
            transaction.execute(True)

    def query_rule(self, ipv, table, chain, priority, args):
        self._check_ipv_table(ipv, table)
        chain_id = (ipv, table, chain)
        return chain_id in self._rules and \
            (priority, args) in self._rules[chain_id]

    def get_rules(self, ipv, table, chain):
        self._check_ipv_table(ipv, table)
        chain_id = (ipv, table, chain)
        if chain_id in self._rules:
            return list(self._rules[chain_id].keys())
        return [ ]

    def get_all_rules(self):
        r = [ ]
        for key in self._rules:
            (ipv, table, chain) = key
            for (priority, args) in self._rules[key]:
                r.append((ipv, table, chain, priority, list(args)))
        return r

    def _register_rule(self, rule_id, chain_id, priority, enable):
        if enable:
            if chain_id not in self._rules:
                self._rules[chain_id] = LastUpdatedOrderedDict()
            self._rules[chain_id][rule_id] = priority
            if chain_id not in self._rule_priority_positions:
                self._rule_priority_positions[chain_id] = { }

            if priority in self._rule_priority_positions[chain_id]:
                self._rule_priority_positions[chain_id][priority] += 1
            else:
                self._rule_priority_positions[chain_id][priority] = 1
        else:
            del self._rules[chain_id][rule_id]
            if len(self._rules[chain_id]) == 0:
                del self._rules[chain_id]
            self._rule_priority_positions[chain_id][priority] -= 1

    # DIRECT PASSTHROUGH (untracked)

    def passthrough(self, ipv, args):
        try:
            return self._fw.rule(ipv, args)
        except Exception as msg:
            log.debug2(msg)
            raise FirewallError(errors.COMMAND_FAILED, msg)


    def _register_passthrough(self, ipv, args, enable):
        if enable:
            if ipv not in self._passthroughs:
                self._passthroughs[ipv] = [ ]
            self._passthroughs[ipv].append(args)
        else:
            self._passthroughs[ipv].remove(args)
            if len(self._passthroughs[ipv]) == 0:
                del self._passthroughs[ipv]

    def add_passthrough(self, ipv, args, use_transaction=None):
        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        self._passthrough(True, ipv, list(args), transaction)

        if use_transaction is None:
            transaction.execute(True)

    def remove_passthrough(self, ipv, args, use_transaction=None):
        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        self._passthrough(False, ipv, list(args), transaction)

        if use_transaction is None:
            transaction.execute(True)

    def query_passthrough(self, ipv, args):
        return ipv in self._passthroughs and \
            tuple(args) in self._passthroughs[ipv]

    def get_all_passthroughs(self):
        r = [ ]
        for ipv in self._passthroughs:
            for args in self._passthroughs[ipv]:
                r.append((ipv, list(args)))
        return r

    def get_passthroughs(self, ipv):
        r = [ ]
        if ipv in self._passthroughs:
            for args in self._passthroughs[ipv]:
                r.append(list(args))
        return r

class FirewallDirectIPTables(FirewallDirect):
    def _rule(self, enable, ipv, table, chain, priority, args, transaction):
        self._check_ipv_table(ipv, table)
        if ipv in [ "ipv4", "ipv6" ]:
            self._fw.zone.create_zone_base_by_chain(ipv, table, chain,
                                                    transaction)

        _chain = chain

        if ipv in [ "ipv4", "ipv6" ]:
            _CHAINS = ipXtables.BUILT_IN_CHAINS
        else:
            _CHAINS = ebtables.BUILT_IN_CHAINS

        if table in _CHAINS and chain in _CHAINS[table]:
            _chain = "%s_direct" % (chain)

        chain_id = (ipv, table, chain)
        rule_id = (priority, args)

        if enable:
            if chain_id in self._rules and \
                    rule_id in self._rules[chain_id]:
                raise FirewallError(errors.ALREADY_ENABLED,
                                    "rule '%s' already is in '%s:%s:%s'" % \
                                    (args, ipv, table, chain))
        else:
            if chain_id not in self._rules or \
                    rule_id not in self._rules[chain_id]:
                raise FirewallError(errors.NOT_ENABLED,
                                    "rule '%s' is not in '%s:%s:%s'" % \
                                    (args, ipv, table, chain))

            # get priority of rule
            priority = self._rules[chain_id][rule_id]

        # If a rule gets added, the initial rule index position within the
        # ipv, table and chain combination (chain_id) is 1.
        # Tf the chain_id exists in _rule_priority_positions, there are already
        # other rules for this chain_id. The number of rules for a priority
        # less or equal to the priority of the new rule will increase the
        # index of the new rule. The index is the ip*tables -I insert rule
        # number.
        #
        # Example: We have the following rules for chain_id (ipv4, filter,
        # INPUT) already:
        #   ipv4, filter, INPUT, 1, -i, foo1, -j, ACCEPT
        #   ipv4, filter, INPUT, 2, -i, foo2, -j, ACCEPT
        #   ipv4, filter, INPUT, 2, -i, foo2_1, -j, ACCEPT
        #   ipv4, filter, INPUT, 3, -i, foo3, -j, ACCEPT
        # This results in the following _rule_priority_positions structure:
        #   _rule_priority_positions[(ipv4,filter,INPUT)][1] = 1
        #   _rule_priority_positions[(ipv4,filter,INPUT)][2] = 2
        #   _rule_priority_positions[(ipv4,filter,INPUT)][3] = 1
        # The new rule
        #   ipv4, filter, INPUT, 2, -i, foo2_2, -j, ACCEPT
        # has the same pritority as the second rule before and will be added
        # right after it.
        # The initial index is 1 and the chain_id is already in
        # _rule_priority_positions. Therefore the index will increase for
        # the number of rules in every rule position in
        # _rule_priority_positions[(ipv4,filter,INPUT)].keys()
        # where position is smaller or equal to the entry in keys.
        # With the example from above:
        # The priority of the new rule is 2. Therefore for all keys in
        # _rule_priority_positions[chain_id] where priority is 1 or 2, the
        # number of the rules will increase the index of the rule.
        # For _rule_priority_positions[chain_id][1]: index += 1
        # _rule_priority_positions[chain_id][2]: index += 2
        # index will be 4 in the end and the rule in the table chain
        # combination will be added at index 4.
        # If there are no rules in the table chain combination, a new rule
        # has index 1.

        index = 1
        if chain_id in self._rule_priority_positions:
            positions = sorted(self._rule_priority_positions[chain_id].keys())
            j = 0
            while j < len(positions) and priority >= positions[j]:
                index += self._rule_priority_positions[chain_id][positions[j]]
                j += 1

        rule = [ "-t", table ]
        if enable:
            rule += [ "-I", _chain, str(index) ]
        else:
            rule += [ "-D", _chain ]
        rule += args

        transaction.add_rule(ipv, rule)

        self._register_rule(rule_id, chain_id, priority, enable)
        transaction.add_fail(self._register_rule,
                             rule_id, chain_id, priority, not enable)

    def _chain(self, add, ipv, table, chain, transaction):
        self._check_ipv_table(ipv, table)
        self._check_builtin_chain(ipv, table, chain)
        table_id = (ipv, table)

        if add:
            if table_id in self._chains and \
                    chain in self._chains[table_id]:
                raise FirewallError(errors.ALREADY_ENABLED,
                                    "chain '%s' already is in '%s:%s'" % \
                                    (chain, ipv, table))
        else:
            if table_id not in self._chains or \
                    chain not in self._chains[table_id]:
                raise FirewallError(errors.NOT_ENABLED,
                                    "chain '%s' is not in '%s:%s'" % \
                                    (chain, ipv, table))

        rule = [ "-t", table ]
        if add:
            rule.append("-N")
        else:
            rule.append("-X")
        rule.append(chain)
        if add and ipv == "eb":
            rule += [ "-P", "RETURN" ]

        transaction.add_rule(ipv, rule)

        self._register_chain(table_id, chain, add)
        transaction.add_fail(self._register_chain, table_id, chain, not add)

    def _passthrough(self, enable, ipv, args, transaction):
        self._check_ipv(ipv)

        tuple_args = tuple(args)
        if enable:
            if ipv in self._passthroughs and \
               tuple_args in self._passthroughs[ipv]:
                raise FirewallError(errors.ALREADY_ENABLED,
                                    "passthrough '%s', '%s'" % (ipv, args))
        else:
            if ipv not in self._passthroughs or \
               tuple_args not in self._passthroughs[ipv]:
                raise FirewallError(errors.NOT_ENABLED,
                                    "passthrough '%s', '%s'" % (ipv, args))

        if enable:
            self.check_passthrough(args)
            # try to find out if a zone chain should be used
            if ipv in [ "ipv4", "ipv6" ]:
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
                if table and chain:
                    self._fw.zone.create_zone_base_by_chain(ipv, table, chain)
            _args = args
        else:
            _args = self.reverse_passthrough(args)
        transaction.add_rule(ipv, _args)

        self._register_passthrough(ipv, tuple_args, enable)
        transaction.add_fail(self._register_passthrough, ipv, tuple_args,
                             not enable)

    def check_passthrough(self, args):
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
            raise FirewallError(errors.INVALID_PASSTHROUGH,
                                "arg '%s' is not allowed" %
                                list(args & not_allowed)[0])

        # args need to contain one of -A, -I, -N
        needed = set(["-A", "--append",
                      "-I", "--insert",
                      "-N", "--new-chain"])
        # empty intersection of args and needed, i.e.
        # none from args contains any needed command
        if len(args & needed) == 0:
            raise FirewallError(errors.INVALID_PASSTHROUGH,
                                "no '-A', '-I' or '-N' arg")

    def reverse_passthrough(self, args):
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

        raise FirewallError(errors.INVALID_PASSTHROUGH,
                            "no '-A', '-I' or '-N' arg")
