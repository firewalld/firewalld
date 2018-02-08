# -*- coding: utf-8 -*-
#
# Copyright (C) 2016 Red Hat, Inc.
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

"""Transaction classes for firewalld"""

__all__ = [ "FirewallTransaction", "FirewallZoneTransaction" ]

from firewall.core.logger import log
from firewall import errors
from firewall.errors import FirewallError
from firewall.fw_types import LastUpdatedOrderedDict
from firewall.core.ipXtables import reverse_rule

class SimpleFirewallTransaction(object):
    """Base class for FirewallTransaction and FirewallZoneTransaction"""

    def __init__(self, fw):
        self.fw = fw
        self.rules = { } # [ ( ipv, [ rule,.. ] ),.. ]
        self.pre_funcs = [ ] # [ (func, args),.. ]
        self.post_funcs = [ ] # [ (func, args),.. ]
        self.fail_funcs = [ ] # [ (func, args),.. ]

    def clear(self):
        self.rules.clear()
        del self.pre_funcs[:]
        del self.post_funcs[:]
        del self.fail_funcs[:]

    def add_rule(self, ipv, rule):
        self.rules.setdefault(ipv, [ ]).append(rule)

    def query_rule(self, ipv, rule):
        return ipv in self.rules and rule in self.rules[ipv]

    def remove_rule(self, ipv, rule):
        if ipv in self.rules and rule in self.rules[ipv]:
            self.rules[ipv].remove(rule)

    def add_pre(self, func, *args):
        self.pre_funcs.append((func, args))

    def add_post(self, func, *args):
        self.post_funcs.append((func, args))

    def add_fail(self, func, *args):
        self.fail_funcs.append((func, args))

    def prepare(self, enable, rules=None, modules=None):
        log.debug4("%s.prepare(%s, %s)" % (type(self), enable, "..."))

        if rules is None:
            rules = { }
        if modules is None:
            modules = [ ]

        if not enable:
            # reverse rule order for cleanup
            for ipv in self.rules:
                for rule in reversed(self.rules[ipv]):
                    rules.setdefault(ipv, [ ]).append(reverse_rule(rule))
        else:
            for ipv in self.rules:
                rules.setdefault(ipv, [ ]).extend(self.rules[ipv])

        return rules, modules

    def execute(self, enable):
        log.debug4("%s.execute(%s)" % (type(self), enable))

        rules, modules = self.prepare(enable)

        # pre
        self.pre()

        # stage 1: apply rules
        error = False
        errorMsg = ""
        done = [ ]
        for ipv in rules:
            try:
                self.fw.rules(ipv, rules[ipv])
            except Exception as msg:
                error = True
                errorMsg = msg
                log.error(msg)
            else:
                done.append(ipv)

        # stage 2: load modules
        if not error:
            module_return = self.fw.handle_modules(modules, enable)
            if module_return:
                (cleanup_modules, msg) = module_return
                if cleanup_modules is not None:
                    error = True
                    errorMsg = msg
                    self.fw.handle_modules(cleanup_modules, not enable)

        # error case: revert rules
        if error:
            undo_rules = { }
            for ipv in done:
                undo_rules[ipv] = [ ]
                for rule in reversed(rules[ipv]):
                    undo_rules[ipv].append(reverse_rule(rule))
            for ipv in undo_rules:
                try:
                    self.fw.rules(ipv, undo_rules[ipv])
                except Exception as msg:
                    log.error(msg)
            # call failure functions
            for (func, args) in self.fail_funcs:
                try:
                    func(*args)
                except Exception as msg:
                    log.error("Calling fail func %s(%s) failed: %s" % \
                              (func, args, msg))

            raise FirewallError(errors.COMMAND_FAILED, errorMsg)

        # post
        self.post()

    def pre(self):
        log.debug4("%s.pre()" % type(self))

        for (func, args) in self.pre_funcs:
            try:
                func(*args)
            except Exception as msg:
                log.error("Calling pre func %s(%s) failed: %s" % \
                          (func, args, msg))

    def post(self):
        log.debug4("%s.post()" % type(self))

        for (func, args) in self.post_funcs:
            try:
                func(*args)
            except Exception as msg:
                log.error("Calling post func %s(%s) failed: %s" % \
                          (func, args, msg))

# class FirewallTransaction

class FirewallTransaction(SimpleFirewallTransaction):
    """General FirewallTransaction, contains also zone transactions"""

    def __init__(self, fw):
        super(FirewallTransaction, self).__init__(fw)
        self.zone_transactions = LastUpdatedOrderedDict() # { zone: transaction, .. }

    def clear(self):
        super(FirewallTransaction, self).clear()
        self.zone_transactions.clear()

    def zone_transaction(self, zone):
        if zone not in self.zone_transactions:
            self.zone_transactions[zone] = FirewallZoneTransaction(
                self.fw, zone)
        return self.zone_transactions[zone]

    def prepare(self, enable, rules=None, modules=None):
        log.debug4("%s.prepare(%s, %s)" % (type(self), enable, "..."))

        rules, modules = super(FirewallTransaction, self).prepare(
            enable, rules, modules)

        for zone in self.zone_transactions:
            try:
                self.zone_transactions[zone].prepare(enable, rules)
                for module in self.zone_transactions[zone].modules:
                    if module not in modules:
                        modules.append(module)
            except FirewallError as msg:
                log.error("Failed to prepare transaction rules for zone '%s'",
                          str(msg))

        return rules, modules

    def pre(self):
        log.debug4("%s.pre()" % type(self))

        super(FirewallTransaction, self).pre()

        for zone in self.zone_transactions:
            self.zone_transactions[zone].pre()

    def post(self):
        log.debug4("%s.post()" % type(self))

        super(FirewallTransaction, self).post()

        for zone in self.zone_transactions:
            self.zone_transactions[zone].post()

# class FirewallZoneTransaction

class FirewallZoneTransaction(SimpleFirewallTransaction):
    """Zone transaction with additional chain and module interface"""

    def __init__(self, fw, zone):
        super(FirewallZoneTransaction, self).__init__(fw)
        self.zone = zone
        self.chains = [ ] # [ (table, chain),.. ]
        self.modules = [ ] # [ module,.. ]

    def clear(self):
        super(FirewallZoneTransaction, self).clear()
        del self.chains[:]
        del self.modules[:]

    def prepare(self, enable, rules=None, modules=None):
        log.debug4("%s.prepare(%s, %s)" % (type(self), enable, "..."))

        rules, modules = super(FirewallZoneTransaction, self).prepare(
            enable, rules, modules)

        for module in self.modules:
            if module not in modules:
                modules.append(module)

        return rules, modules

    def add_chain(self, table, chain):
        table_chain = (table, chain)
        if table_chain not in self.chains:
            self.fw.zone.gen_chain_rules(self.zone, True, [table_chain], self)
            self.chains.append(table_chain)

    def remove_chain(self, table, chain):
        table_chain = (table, chain)
        if table_chain in self.chains:
            self.chains.remove(table_chain)

    def add_chains(self, chains):
        for table_chain in chains:
            if table_chain not in self.chains:
                self.add_chain(table_chain[0], table_chain[1])

    def remove_chains(self, chains):
        for table_chain in chains:
            if table_chain in self.chains:
                self.chains.remove(table_chain)

    def add_module(self, module):
        if module not in self.modules:
            self.modules.append(module)

    def remove_module(self, module):
        if module in self.modules:
            self.modules.remove(module)

    def add_modules(self, modules):
        for module in modules:
            self.add_module(module)

    def remove_modules(self, modules):
        for module in modules:
            self.remove_module(module)
