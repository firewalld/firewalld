# -*- coding: utf-8 -*-
#
# Copyright (C) 2018 Red Hat, Inc.
#
# Authors:
# Eric Garver <e@erig.me>
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
from firewall.functions import splitArgs, check_mac, portStr, \
                               check_single_address, check_address
from firewall import config
from firewall.core import ipXtables, ebtables
from firewall.errors import FirewallError, UNKNOWN_ERROR, INVALID_RULE
from firewall.core.rich import Rich_Accept, Rich_Reject, Rich_Drop, Rich_Mark

TABLE_NAME = "firewalld"

# Map iptables (table, chain) to hooks and priorities.
# These are well defined by NF_IP_PRI_* defines in netfilter.
#
IPTABLES_TO_NFT_HOOK = {
    "security": {
        "INPUT": ("input", 50),
        "OUTPUT": ("output", 50),
        "FORWARD": ("forward", 50),
    },
    "raw": {
        "PREROUTING": ("prerouting", -300),
        "OUTPUT": ("output", -300),
    },
    "mangle": {
        "PREROUTING": ("prerouting", -150),
        "POSTROUTING": ("postrouting", -150),
        "INPUT": ("input", -150),
        "OUTPUT": ("output", -150),
        "FORWARD": ("forward", -150),
    },
    "nat": {
        "PREROUTING": ("prerouting", -100),
        "POSTROUTING": ("postrouting", 100),
        "INPUT": ("input", 100),
        "OUTPUT": ("output", -100),
    },
    "filter": {
        "INPUT": ("input", 0),
        "OUTPUT": ("output", 0),
        "FORWARD": ("forward", 0),
    },
}

EBTABLES_TO_NFT_HOOK = {
    # FIXME: ebtables broute/brouting equivalent not supported
    "nat": {
        "PREROUTING": ("prerouting", -100),
        "POSTROUTING": ("postrouting", 100),
        "OUTPUT": ("output", -100),
    },
    "filter": {
        "INPUT": ("input", 0),
        "OUTPUT": ("output", 0),
        "FORWARD": ("forward", 0),
    },
}

OUR_CHAINS = { # chains created by firewalld
    # family: { chains ...}
    "bridge": {},
    "inet": {},
    "ip": {},
    "ip6": {},
}

class nftables(object):
    ipv = "nft"
    name = "nftables"
    zones_supported = True

    def __init__(self, fw):
        self._fw = fw
        self._command = config.COMMANDS[self.ipv]
        self.fill_exists()
        self.available_tables = []
        self.rule_to_handle = {}
        self.rule_ref_count = {}

    def fill_exists(self):
        self.command_exists = os.path.exists(self._command)
        self.restore_command_exists = False

    def __run(self, args):
        nft_opts = ["--echo", "--handle"]
        _args = args[:]

        # If we're deleting a table (i.e. build_flush_rules())
        # then check if its exist first to avoid nft throwing an error
        if _args[0] == "delete" and _args[1] == "table":
            _args_test = _args[:]
            _args_test[0] = "list"
            (status, output) = runProg(self._command, nft_opts + _args_test)
            if status != 0:
                return ""

        rule_key = None
        if _args[0] in ["add", "insert"] and _args[1] == "rule":
            rule_add = True
            rule_key = _args[2:]
            if rule_key[3] == "position":
                # strip "position #"
                # "insert rule family table chain position <num>"
                #              ^^ rule_key starts here
                try:
                    int(rule_key[4])
                except Exception:
                    raise FirewallError(INVALID_RULE, "position without a number")
                else:
                    rule_key.pop(3)
                    rule_key.pop(3)
            rule_key = " ".join(rule_key)
        elif _args[0] in ["delete"] and _args[1] == "rule":
            rule_add = False
            rule_key = _args[2:]
            rule_key = " ".join(rule_key)
            # delete using rule handle
            _args = ["delete", "rule"] + _args[2:5] + \
                    ["handle", self.rule_to_handle[rule_key]]

        _args_str = " ".join(_args)

        # rule deduplication
        if rule_key in self.rule_ref_count:
            if rule_add:
                self.rule_ref_count[rule_key] += 1
                return ""
            elif self.rule_ref_count[rule_key] > 0:
                self.rule_ref_count[rule_key] -= 1
            else:
                raise FirewallError(UNKNOWN_ERROR, "rule ref count bug: rule_key '%s', cnt %d"
                                                   % (rule_key, self.rule_ref_count[rule_key]))
            log.debug2("%s: rule ref cnt %d, %s %s", self.__class__,
                       self.rule_ref_count[rule_key], self._command, _args_str)

        if not rule_key or (not rule_add and self.rule_ref_count[rule_key] == 0) \
                        or (    rule_add and rule_key not in self.rule_ref_count):
            log.debug2("%s: %s %s", self.__class__, self._command, _args_str)
            (status, output) = runProg(self._command, nft_opts + _args)
            if status != 0:
                raise ValueError("'%s %s' failed: %s" % (self._command,
                                                         _args_str, output))
            # nft requires deleting rules by handle. So we must cache the rule
            # handle when adding/inserting rules.
            #
            if rule_key:
                if rule_add:
                    str = "# handle "
                    offset = output.index(str) + len(str)
                    self.rule_to_handle[rule_key] = output[offset:].strip()
                    self.rule_ref_count[rule_key] = 1
                else:
                    del self.rule_to_handle[rule_key]
                    del self.rule_ref_count[rule_key]

        return output

    def _rule_replace(self, rule, pattern, replacement):
        try:
            i = rule.index(pattern)
        except ValueError:
            return False
        else:
            rule[i:i+1] = replacement
            return True

    def is_chain_builtin(self, ipv, table, chain):
        if ipv == "eb":
            return table in ebtables.BUILT_IN_CHAINS and \
                   chain in ebtables.BUILT_IN_CHAINS[table]
        else:
            return table in ipXtables.BUILT_IN_CHAINS and \
                   chain in ipXtables.BUILT_IN_CHAINS[table]

    def build_chain(self, add, table, chain):
        raise FirewallError(UNKNOWN_ERROR, "FIXME: not implemented")

        # FIXME: What if they want to be in the nat table? family needs to be
        # different. Likely need two rules, ip and ip6
        if add:
            rule = ["add"]
        else:
            rule = ["delete"]
        rule.extend(["chain", "inet", "%s" % TABLE_NAME,
                     "%s_%s" % (table, chain)])
        return rule

    def build_rule(self, add, table, chain, index, args):
        raise FirewallError(UNKNOWN_ERROR, "FIXME: not implemented")

        # FIXME: What if they want to be in the nat table? family needs to be
        # different. Likely need two rules, ip and ip6
        if add:
            rule = ["add", "rule", "inet", "%s" % TABLE_NAME,
                    "%s_%s" % (table, chain)]
            rule += args
        else:
            # FIXME: delete needs to use/lookup handle
            handle = "" # FIXME
            rule = ["delete", "rule", "inet", "%s" % TABLE_NAME,
                    "%s_%s" % (table, chain), "handle", handle]

        return rule

    def reverse_rule(self, args):
        ret_args = args[:]
        ret_args[0] = "delete"
        return ret_args

    def check_passthrough(self, args):
        raise FirewallError(UNKNOWN_ERROR, "FIXME: not implemented")

    def reverse_passthrough(self, args):
        raise FirewallError(UNKNOWN_ERROR, "FIXME: not implemented")

    def passthrough_parse_table_chain(self, args):
        raise FirewallError(UNKNOWN_ERROR, "FIXME: not implemented")

    def set_rules(self, rules, flush=False, log_denied="off"):
        # We can't support using "nft -f" because we need to retrieve the
        # handles for each rules so we can delete them later on.
        # See also: self.restore_command_exists
        #
        # We can implement this once libnftables in ready.
        #
        raise FirewallError(UNKNOWN_ERROR, "not implemented")

    def set_rule(self, rule, log_denied="off"):
        # replace %%REJECT%%
        self._rule_replace(rule, "%%REJECT%%",
                           ["reject", "with", "icmpx", "type", "admin-prohibited"])

        # replace %%ICMP%%
        self._rule_replace(rule, "%%ICMP%%", ["meta", "l4proto", "{icmp, icmpv6}"])

        # replace %%LOGTYPE%%
        try:
            i = rule.index("%%LOGTYPE%%")
        except ValueError:
            pass
        else:
            if log_denied == "off":
                return ""
            if log_denied in ["unicast", "broadcast", "multicast"]:
                rule[i:i+1] = ["pkttype", self._log_denied]
            else:
                rule.pop(i)

        return self.__run(rule)

    def get_available_tables(self, table=None):
        # Tables always exist in nftables
        return [table] if table else ipXtables.BUILT_IN_CHAINS.keys()

    def used_tables(self):
        tables = []
        # FIXME: get used tables from nft
        # I assume "used" means it has rules.
        #
        # Maybe this is okay?
        return OUR_CHAINS.keys()

        return tables

    def build_flush_rules(self):
        self.rule_to_handle = {}
        self.rule_ref_count = {}

        rules = []
        for family in ["inet", "ip", "ip6", "bridge"]:
            rules.append(["delete", "table", family, "%s" % TABLE_NAME])
        return rules

    def build_set_policy_rules(self, policy, which="used"):
        # FIXME: remove HACK
        return []

        # FIXME: Not sure how to handle this since the tables don't always
        # exist. Might have to keep the tables around with the base chains just
        # to implement this.
        #
        if which == "used":
            tables = self.used_tables()
        else:
            # FIXME: ebtables.BUILT_IN_CHAINS
            tables = list(ipXtables.BUILT_IN_CHAINS.keys())

        rules = []
        for table in tables:
            if table == "nat":
                continue
            # FIXME: ebtables.BUILT_IN_CHAINS
            for chain in ipXtables.BUILT_IN_CHAINS[table]:
                rules.append(["-t", table, "-P", chain, policy])
        return rules

    def supported_icmp_types(self):
        supported = [# types
                     "echo-reply",
                     "destination-unreachable",
                     "source-quench",
                     "redirect",
                     "echo-request",
                     "router-advertisement",
                     "router-solicitation",
                     "time-exceeded",
                     "parameter-problem",
                     "timestamp-request",
                     "timestamp-reply",
                     "info-request",
                     "info-reply",
                     "address-mask-request",
                     "address-mask-reply",
                     # codes
                     "net-unreachable",
                     "host-unreachable",
                     "prot-unreachable",
                     "port-unreachable",
                     "net-prohibited",
                     "host-prohibited",
                     "admin-prohibited",
                    ]
        # FIXME: should probably do a real probe kernel probe for the above to
        # make sure the kernel supports them.
        return supported

    def build_default_rules(self, log_denied="off"):
        default_rules = [
            "add table inet %s" % (TABLE_NAME),
            "add table ip %s" % (TABLE_NAME), # nat requires family specific tables
            "add table ip6 %s" % (TABLE_NAME),
            "add table bridge %s" % (TABLE_NAME),
        ]

        OUR_CHAINS["bridge"]["filter"] = set()
        for chain in ebtables.BUILT_IN_CHAINS["filter"]:
            default_rules.append("' add chain bridge %s filter_%s { type filter hook %s priority %d ; } '" %
                                 (TABLE_NAME, chain,
                                  EBTABLES_TO_NFT_HOOK["filter"][chain][0],
                                  EBTABLES_TO_NFT_HOOK["filter"][chain][1]))
            # FIXME: set %s_direct policy RETURN
            default_rules.append("add chain bridge %s filter_%s_direct" % (TABLE_NAME, chain))
            default_rules.append("add rule bridge %s filter_%s jump filter_%s_direct" % (TABLE_NAME, chain, chain))
            OUR_CHAINS["bridge"]["filter"].add("filter_%s_direct" % chain)

        OUR_CHAINS["bridge"]["nat"] = set()
        for chain in ebtables.BUILT_IN_CHAINS["nat"]:
            default_rules.append("' add chain bridge %s nat_%s { type filter hook %s priority %d ; } '" %
                                 (TABLE_NAME, chain,
                                  EBTABLES_TO_NFT_HOOK["nat"][chain][0],
                                  EBTABLES_TO_NFT_HOOK["nat"][chain][1]))
            # FIXME: set %s_direct policy RETURN
            default_rules.append("add chain bridge %s nat_%s_direct" % (TABLE_NAME, chain))
            default_rules.append("add rule bridge %s nat_%s jump nat_%s_direct" % (TABLE_NAME, chain, chain))
            OUR_CHAINS["bridge"]["nat"].add("nat_%s_direct" % chain)

        OUR_CHAINS["inet"]["security"] = set()
        for chain in ipXtables.BUILT_IN_CHAINS["security"]:
            default_rules.append("' add chain inet %s security_%s { type filter hook %s priority %d ; } '" %
                                 (TABLE_NAME, chain,
                                  IPTABLES_TO_NFT_HOOK["security"][chain][0],
                                  IPTABLES_TO_NFT_HOOK["security"][chain][1]))
            default_rules.append("add chain inet %s security_%s_direct" % (TABLE_NAME, chain))
            default_rules.append("add rule inet %s security_%s jump security_%s_direct" % (TABLE_NAME, chain, chain))
            OUR_CHAINS["inet"]["security"].add("%s_direct" % chain)

        OUR_CHAINS["inet"]["raw"] = set()
        for chain in ipXtables.BUILT_IN_CHAINS["raw"]:
            default_rules.append("' add chain inet %s raw_%s { type filter hook %s priority %d ; } '" %
                                 (TABLE_NAME, chain,
                                  IPTABLES_TO_NFT_HOOK["raw"][chain][0],
                                  IPTABLES_TO_NFT_HOOK["raw"][chain][1]))
            default_rules.append("add chain inet %s raw_%s_direct" % (TABLE_NAME, chain))
            default_rules.append("add rule inet %s raw_%s jump raw_%s_direct" % (TABLE_NAME, chain, chain))
            OUR_CHAINS["inet"]["raw"].add("%s_direct" % chain)

            if chain == "PREROUTING":
                default_rules.append("add chain inet %s raw_%s_ZONES_SOURCE" % (TABLE_NAME, chain))
                default_rules.append("add chain inet %s raw_%s_ZONES" % (TABLE_NAME, chain))
                default_rules.append("add rule inet %s raw_%s jump raw_%s_ZONES_SOURCE" % (TABLE_NAME, chain, chain))
                default_rules.append("add rule inet %s raw_%s jump raw_%s_ZONES" % (TABLE_NAME, chain, chain))
                OUR_CHAINS["inet"]["raw"].update(set(["%s_ZONES_SOURCE" % chain, "%s_ZONES" % chain]))

        OUR_CHAINS["inet"]["mangle"] = set()
        for chain in ipXtables.BUILT_IN_CHAINS["mangle"]:
            default_rules.append("' add chain inet %s mangle_%s { type filter hook %s priority %d ; } '" %
                                 (TABLE_NAME, chain,
                                  IPTABLES_TO_NFT_HOOK["mangle"][chain][0],
                                  IPTABLES_TO_NFT_HOOK["mangle"][chain][1]))
            default_rules.append("add chain inet %s mangle_%s_direct" % (TABLE_NAME, chain))
            default_rules.append("add rule inet %s mangle_%s jump mangle_%s_direct" % (TABLE_NAME, chain, chain))
            OUR_CHAINS["inet"]["mangle"].add("%s_direct" % chain)

            if chain == "PREROUTING":
                default_rules.append("add chain inet %s mangle_%s_ZONES_SOURCE" % (TABLE_NAME, chain))
                default_rules.append("add chain inet %s mangle_%s_ZONES" % (TABLE_NAME, chain))
                default_rules.append("add rule inet %s mangle_%s jump mangle_%s_ZONES_SOURCE" % (TABLE_NAME, chain, chain))
                default_rules.append("add rule inet %s mangle_%s jump mangle_%s_ZONES" % (TABLE_NAME, chain, chain))
                OUR_CHAINS["inet"]["mangle"].update(set(["%s_ZONES_SOURCE" % chain, "%s_ZONES" % chain]))

        OUR_CHAINS["ip"]["nat"] = set()
        OUR_CHAINS["ip6"]["nat"] = set()
        for family in ["ip", "ip6"]:
            for chain in ipXtables.BUILT_IN_CHAINS["nat"]:
                default_rules.append("' add chain %s %s nat_%s { type nat hook %s priority %d ; } '" %
                                     (family, TABLE_NAME, chain,
                                      IPTABLES_TO_NFT_HOOK["nat"][chain][0],
                                      IPTABLES_TO_NFT_HOOK["nat"][chain][1]))
                default_rules.append("add chain %s %s nat_%s_direct" % (family, TABLE_NAME, chain))
                default_rules.append("add rule %s %s nat_%s jump nat_%s_direct" % (family, TABLE_NAME, chain, chain))
                OUR_CHAINS[family]["nat"].add("%s_direct" % chain)

                if chain in ["PREROUTING", "POSTROUTING"]:
                    default_rules.append("add chain %s %s nat_%s_ZONES_SOURCE" % (family, TABLE_NAME, chain))
                    default_rules.append("add chain %s %s nat_%s_ZONES" % (family, TABLE_NAME, chain))
                    default_rules.append("add rule %s %s nat_%s jump nat_%s_ZONES_SOURCE" % (family, TABLE_NAME, chain, chain))
                    default_rules.append("add rule %s %s nat_%s jump nat_%s_ZONES" % (family, TABLE_NAME, chain, chain))
                    OUR_CHAINS[family]["nat"].update(set(["%s_ZONES_SOURCE" % chain, "%s_ZONES" % chain]))

        OUR_CHAINS["inet"]["filter"] = set()
        for chain in ipXtables.BUILT_IN_CHAINS["filter"]:
            default_rules.append("' add chain inet %s filter_%s { type filter hook %s priority %d ; } '" %
                                 (TABLE_NAME, chain,
                                  IPTABLES_TO_NFT_HOOK["filter"][chain][0],
                                  IPTABLES_TO_NFT_HOOK["filter"][chain][1]))
            # FIXME: chain policy? (for this and others)
            default_rules.append("add chain inet %s filter_%s_direct" % (TABLE_NAME, chain))
            default_rules.append("add rule inet %s filter_%s jump filter_%s_direct" % (TABLE_NAME, chain, chain))
            OUR_CHAINS["inet"]["filter"].add("%s_direct" % chain)

        # filter, INPUT
        default_rules.append("add chain inet %s filter_%s_ZONES_SOURCE" % (TABLE_NAME, "INPUT"))
        default_rules.append("add chain inet %s filter_%s_ZONES" % (TABLE_NAME, "INPUT"))
        default_rules.append("add rule inet %s filter_%s ct state established,related accept" % (TABLE_NAME, "INPUT"))
        default_rules.append("add rule inet %s filter_%s iifname lo accept" % (TABLE_NAME, "INPUT"))
        default_rules.append("add rule inet %s filter_%s jump filter_%s_ZONES_SOURCE" % (TABLE_NAME, "INPUT", "INPUT"))
        default_rules.append("add rule inet %s filter_%s jump filter_%s_ZONES" % (TABLE_NAME, "INPUT", "INPUT"))
        if log_denied != "off":
            default_rules.append("add rule inet %s filter_%s ct state invalid log prefix 'STATE_INVALID_DROP: '" % (TABLE_NAME, "INPUT"))
        default_rules.append("add rule inet %s filter_%s ct state invalid drop" % (TABLE_NAME, "INPUT"))
        if log_denied != "off":
            default_rules.append("add rule inet %s filter_%s log prefix 'FINAL_REJECT: '" % (TABLE_NAME, "INPUT"))
        default_rules.append("add rule inet %s filter_%s reject with icmpx type admin-prohibited" % (TABLE_NAME, "INPUT"))

        # filter, FORWARD
        default_rules.append("add chain inet %s filter_%s_IN_ZONES_SOURCE" % (TABLE_NAME, "FORWARD"))
        default_rules.append("add chain inet %s filter_%s_IN_ZONES" % (TABLE_NAME, "FORWARD"))
        default_rules.append("add chain inet %s filter_%s_OUT_ZONES_SOURCE" % (TABLE_NAME, "FORWARD"))
        default_rules.append("add chain inet %s filter_%s_OUT_ZONES" % (TABLE_NAME, "FORWARD"))
        default_rules.append("add rule inet %s filter_%s ct state established,related accept" % (TABLE_NAME, "FORWARD"))
        default_rules.append("add rule inet %s filter_%s iifname lo accept" % (TABLE_NAME, "FORWARD"))
        default_rules.append("add rule inet %s filter_%s jump filter_%s_IN_ZONES_SOURCE" % (TABLE_NAME, "FORWARD", "FORWARD"))
        default_rules.append("add rule inet %s filter_%s jump filter_%s_IN_ZONES" % (TABLE_NAME, "FORWARD", "FORWARD"))
        default_rules.append("add rule inet %s filter_%s jump filter_%s_OUT_ZONES_SOURCE" % (TABLE_NAME, "FORWARD", "FORWARD"))
        default_rules.append("add rule inet %s filter_%s jump filter_%s_OUT_ZONES" % (TABLE_NAME, "FORWARD", "FORWARD"))
        if log_denied != "off":
            default_rules.append("add rule inet %s filter_%s ct state invalid log prefix 'STATE_INVALID_DROP: '" % (TABLE_NAME, "FORWARD"))
        default_rules.append("add rule inet %s filter_%s ct state invalid drop" % (TABLE_NAME, "FORWARD"))
        if log_denied != "off":
            default_rules.append("add rule inet %s filter_%s log prefix 'FINAL_REJECT: '" % (TABLE_NAME, "FORWARD"))
        default_rules.append("add rule inet %s filter_%s reject with icmpx type admin-prohibited" % (TABLE_NAME, "FORWARD"))

        OUR_CHAINS["inet"]["filter"] = set(["INPUT_direct", "INPUT_ZONES_SOURCE", "INPUT_ZONES",
                                            "FORWARD_direct", "FORWARD_IN_ZONES_SOURCE",
                                            "FORWARD_IN_ZONES", "FORWARD_OUT_ZONES_SOURCE",
                                            "FORWARD_OUT_ZONES", "OUTPUT_direct"])

        return map(splitArgs, default_rules)

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
                                          append=False, family="inet"):
        # nat tables needs to use ip/ip6 family
        if table == "nat" and family == "inet":
            rules = []
            rules.extend(self.build_zone_source_interface_rules(enable, zone,
                            zone_target, interface, table, chain, append, "ip"))
            rules.extend(self.build_zone_source_interface_rules(enable, zone,
                            zone_target, interface, table, chain, append, "ip6"))
            return rules

        # handle all zones in the same way here, now
        # trust and block zone targets are handled now in __chain
        opt = {
            "PREROUTING": "iifname",
            "POSTROUTING": "oifname",
            "INPUT": "iifname",
            "FORWARD_IN": "iifname",
            "FORWARD_OUT": "oifname",
            "OUTPUT": "oifname",
        }[chain]

        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS[chain], zone=zone)
        if zone_target == DEFAULT_ZONE_TARGET:
            action = "goto"
        else:
            action = "jump"
        if enable and not append:
            rule = ["insert", "rule", family, "%s" % TABLE_NAME, "%s_%s_ZONES" % (table, chain)]
        elif enable:
            rule = ["add", "rule", family, "%s" % TABLE_NAME, "%s_%s_ZONES" % (table, chain)]
        else:
            rule = ["delete", "rule", family, "%s" % TABLE_NAME, "%s_%s_ZONES" % (table, chain)]
        if interface == "+":
            rule += [action, "%s_%s" % (table, target)]
        else:
            rule += [opt, interface, action, "%s_%s" % (table, target)]
        return [rule]

    def build_zone_source_address_rules(self, enable, zone, zone_target,
                                        address, table, chain, family="inet"):
        # nat tables needs to use ip/ip6 family
        if table == "nat" and family == "inet":
            rules = []
            if check_address("ipv4", address) or check_mac(address):
                rules.extend(self.build_zone_source_address_rules(enable, zone,
                                    zone_target, address, table, chain, "ip"))
            if check_address("ipv6", address) or check_mac(address):
                rules.extend(self.build_zone_source_address_rules(enable, zone,
                                    zone_target, address, table, chain, "ip6"))
            return rules

        add_del = { True: "add", False: "delete" }[enable]

        opt = {
            "PREROUTING": "saddr",
            "POSTROUTING": "daddr",
            "INPUT": "saddr",
            "FORWARD_IN": "saddr",
            "FORWARD_OUT": "daddr",
            "OUTPUT": "daddr",
        }[chain]

        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS[chain], zone=zone)
        if zone_target == DEFAULT_ZONE_TARGET:
            action = "goto"
        else:
            action = "jump"

        if address.startswith("ipset:"):
            # FIXME: ipset support
            FirewallError(UNKNOWN_ERROR, "not implemented")
        else:
            if check_mac(address):
                # outgoing can not be set
                if opt == "daddr":
                    return ""
                rule_family = "ether"
            elif check_address("ipv4", address):
                rule_family = "ip"
            else:
                rule_family = "ip6"

            rule = [add_del, "rule", family, "%s" % TABLE_NAME,
                    "%s_%s_ZONES_SOURCE" % (table, chain),
                    rule_family, opt, address, action, "%s_%s" % (table, target)]
        return [rule]

    def build_zone_chain_rules(self, zone, table, chain, family="inet"):
        # nat tables needs to use ip/ip6 family
        if table == "nat" and family == "inet":
            rules = []
            rules.extend(self.build_zone_chain_rules(zone, table, chain, "ip"))
            rules.extend(self.build_zone_chain_rules(zone, table, chain, "ip6"))
            return rules

        _zone = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS[chain], zone=zone)

        OUR_CHAINS[family][table].update(set([_zone,
                                         "%s_log" % _zone,
                                         "%s_deny" % _zone,
                                         "%s_allow" % _zone]))

        rules = []
        rules.append(["add", "chain", family, "%s" % TABLE_NAME,
                      "%s_%s" % (table, _zone)])
        rules.append(["add", "chain", family, "%s" % TABLE_NAME,
                      "%s_%s_log" % (table, _zone)])
        rules.append(["add", "chain", family, "%s" % TABLE_NAME,
                      "%s_%s_deny" % (table, _zone)])
        rules.append(["add", "chain", family, "%s" % TABLE_NAME,
                      "%s_%s_allow" % (table, _zone)])

        rules.append(["add", "rule", family, "%s" % TABLE_NAME,
                      "%s_%s" % (table, _zone),
                      "jump", "%s_%s_log" % (table, _zone)])
        rules.append(["add", "rule", family, "%s" % TABLE_NAME,
                      "%s_%s" % (table, _zone),
                      "jump", "%s_%s_deny" % (table, _zone)])
        rules.append(["add", "rule", family, "%s" % TABLE_NAME,
                      "%s_%s" % (table, _zone),
                      "jump", "%s_%s_allow" % (table, _zone)])

        target = self._fw.zone._zones[zone].target

        if self._fw.get_log_denied() != "off":
            if table == "filter" and \
               chain in ["INPUT", "FORWARD_IN", "FORWARD_OUT", "OUTPUT"]:
                log_suffix = "DROP"
                if target in ["REJECT", "%%REJECT%%"]:
                    log_suffix = "REJECT"
                rules.append(["add", "rule", family, "%s" % TABLE_NAME,
                              "%s_%s" % (table, _zone), "type", "%%LOGTYPE%%",
                              "log", "prefix",
                              "\"filter_%s_%s\"" % (_zone, log_suffix)])

        # Handle trust, block and drop zones:
        # Add an additional rule with the zone target (accept, reject
        # or drop) to the base zone only in the filter table.
        # Otherwise it is not be possible to have a zone with drop
        # target, that is allowing traffic that is locally initiated
        # or that adds additional rules. (RHBZ#1055190)
        if table == "filter" and \
           target in ["ACCEPT", "REJECT", "%%REJECT%%", "DROP"] and \
           chain in ["INPUT", "FORWARD_IN", "FORWARD_OUT", "OUTPUT"]:
            rules.append(["add", "rule", family, "%s" % TABLE_NAME,
                          "%s_%s" % (table, _zone), target.lower()])

        return rules

    def _rich_rule_limit_fragment(self, limit):
        if limit:
            return ["limit", "rate", limit.value]
        return []

    def _rich_rule_log(self, rich_rule, enable, table, target, rule_fragment):
        if not rich_rule.log:
            return []

        add_del = { True: "add", False: "delete" }[enable]

        rule = [add_del, "rule", "inet", "%s" % TABLE_NAME,
                "%s_%s_allow" % (table, target)]
        rule += rule_fragment + ["log"]
        if rich_rule.log.prefix:
            rule += ["prefix", '"%s"' % rich_rule.log.prefix]
        if rich_rule.log.level:
            rule += ["level", '"%s"' % rich_rule.log.level]
        rule += self._rich_rule_limit_fragment(rich_rule.log.limit)

        return rule

    def _rich_rule_audit(self, rich_rule, enable, table, target, rule_fragment):
        if not rich_rule.audit:
            return []
        # FIXME: nftables does not support AUDIT, need to complain loudly
        FirewallError(UNKNOWN_ERROR, "not implemented")

    def _rich_rule_action(self, zone, rich_rule, enable, table, target, rule_fragment):
        if not rich_rule.action:
            return []

        add_del = { True: "add", False: "delete" }[enable]

        if type(rich_rule.action) == Rich_Accept:
            chain = "%s_%s_allow" % (table, target)
            rule_action = ["accept"]
        elif type(rich_rule.action) == Rich_Reject:
            chain = "%s_%s_deny" % (table, target)
            rule_action = ["reject"]
            if rich_rule.action.type:
                rule_action += ["with", "icmpx", "type", rich_rule.action.type]
        elif type(rich_rule.action) ==  Rich_Drop:
            chain = "%s_%s_deny" % (table, target)
            rule_action = ["drop"]
        elif type(rich_rule.action) == Rich_Mark:
            table = "mangle"
            chain = "%s_%s_allow" % (table, target)
            target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["PREROUTING"],
                                                zone=zone)
            rule_action = ["meta", "mark", "set", rich_rule.action.set]
        else:
            raise FirewallError(INVALID_RULE,
                                "Unknown action %s" % type(rich_rule.action))

        rule = [add_del, "rule", "inet", "%s" % TABLE_NAME, chain]
        rule += rule_fragment + rule_action
        rule += self._rich_rule_limit_fragment(rich_rule.action.limit)

        return rule

    def _rich_rule_destination_fragment(self, rich_dest):
        if not rich_dest:
            return []

        rule_fragment = []
        if check_single_address("ipv4", rich_dest.addr):
            rule_fragment += ["ip"]
        else:
            rule_fragment += ["ip6"]

        if rich_dest.invert:
            rule_fragment += ["daddr", "!=", rich_dest.addr]
        else:
            rule_fragment += ["daddr", rich_dest.addr]

        return rule_fragment

    def _rich_rule_source_fragment(self, rich_source):
        if not rich_source:
            return []

        rule_fragment = []
        if rich_source.addr:
            if check_single_address("ipv4", rich_source.addr):
                rule_fragment += ["ip"]
            else:
                rule_fragment += ["ip6"]

            if rich_source.invert:
                rule_fragment += ["saddr", "!=", rich_source.addr]
            else:
                rule_fragment += ["saddr", rich_source.addr]
        elif hasattr(rich_source, "mac") and rich_source.mac:
            if rich_source.invert:
                rule_fragment += ["ether", "saddr", "!=", rich_source.mac]
            else:
                rule_fragment += ["ether", "saddr", rich_source.mac]
        elif hasattr(rich_source, "ipset") and rich_source.ipset:
            # FIXME: ipset support
            FirewallError(UNKNOWN_ERROR, "not implemented")

        return rule_fragment

    def build_zone_ports_rules(self, enable, zone, proto, port, destination=None, rich_rule=None):
        add_del = { True: "add", False: "delete" }[enable]
        table = "filter"
        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["INPUT"], zone=zone)

        rule_fragment = []
        if destination:
            if check_single_address("ipv4", destination):
                rule_fragment += ["ip"]
            else:
                rule_fragment += ["ip6"]
            rule_fragment += ["daddr", destination]
        if rich_rule:
            rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
            rule_fragment += self._rich_rule_source_fragment(rich_rule.source)
        rule_fragment += [proto, "dport", "%s" % portStr(port, "-")]

        rules = []
        if rich_rule:
            rules.append(self._rich_rule_log(rich_rule, enable, table, target, rule_fragment))
            rules.append(self._rich_rule_audit(rich_rule, enable, table, target, rule_fragment))
            rules.append(self._rich_rule_action(zone, rich_rule, enable, table, target, rule_fragment))
        else:
            rules.append([add_del, "rule", "inet", "%s" % TABLE_NAME,
                          "%s_%s_allow" % (table, target)] +
                          rule_fragment + ["ct", "state", "new", "accept"])

        return rules

    def build_zone_protocol_rules(self, enable, zone, protocol, rich_rule=None):
        add_del = { True: "add", False: "delete" }[enable]
        table = "filter"
        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["INPUT"], zone=zone)

        rule_fragment = []
        if rich_rule:
            rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
            rule_fragment += self._rich_rule_source_fragment(rich_rule.source)
        rule_fragment = ["meta", "l4proto", protocol]

        rules = []
        if rich_rule:
            rules.append(self._rich_rule_log(rich_rule, enable, table, target, rule_fragment))
            rules.append(self._rich_rule_audit(rich_rule, enable, table, target, rule_fragment))
            rules.append(self._rich_rule_action(zone, rich_rule, enable, table, target, rule_fragment))
        else:
            rules.append([add_del, "rule", "inet", "%s" % TABLE_NAME,
                          "filter_%s_allow" % (target)] +
                          rule_fragment + ["ct", "state", "new", "accept"])

        return rules

    def build_zone_source_ports_rules(self, enable, zone, proto, port,
                                      destination=None, rich_rule=None):
        add_del = { True: "add", False: "delete" }[enable]
        table = "filter"
        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["INPUT"], zone=zone)

        rule_fragment = []
        if destination:
            if check_single_address("ipv4", destination):
                rule_fragment += ["ip"]
            else:
                rule_fragment += ["ip6"]
            rule_fragment += ["daddr", destination]
        if rich_rule:
            rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
            rule_fragment += self._rich_rule_source_fragment(rich_rule.source)
        rule_fragment += [proto, "sport", "%s" % portStr(port, "-")]

        rules = []
        if rich_rule:
            rules.append(self._rich_rule_log(rich_rule, enable, table, target, rule_fragment))
            rules.append(self._rich_rule_audit(rich_rule, enable, table, target, rule_fragment))
            rules.append(self._rich_rule_action(zone, rich_rule, enable, table, target, rule_fragment))
        else:
            rules.append([add_del, "rule", "inet", "%s" % TABLE_NAME,
                          "%s_%s_allow" % (table, target)] +
                          rule_fragment + ["ct", "state", "new", "accept"])

        return rules

    def build_zone_helper_ports_rule(self, enable, zone, proto, port,
                                     destination, helper_name):
        add_del = { True: "add", False: "delete" }[enable]
        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["PREROUTING"],
                                            zone=zone)
        rule = [add_del, "rule", "inet", "%s" % TABLE_NAME,
                "raw_%s_allow" % (target), proto]
        if destination:
            if check_single_address("ipv4", destination):
                rule += ["ip"]
            else:
                rule += ["ip6"]
            rule += ["daddr", destination]
        rule += ["dport", "%s" % portStr(port, "-")]
        rule += ["ct", "state", "new", "accept"]

        return rule

    def _build_zone_masquerade_nat_rules(self, enable, zone, family, rich_rule=None):
        add_del = { True: "add", False: "delete" }[enable]
        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["POSTROUTING"],
                                            zone=zone)

        rule_fragment = []
        if rich_rule:
            rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
            rule_fragment += self._rich_rule_source_fragment(rich_rule.source)

        return [[add_del, "rule", family, "%s" % TABLE_NAME,
                "nat_%s_allow" % (target)]
                + rule_fragment + ["oifname", "!=", "lo", "masquerade"]]

    def build_zone_masquerade_rules(self, enable, zone, rich_rule=None):
        # nat tables needs to use ip/ip6 family
        rules = []
        if rich_rule and (rich_rule.family and rich_rule.family == "ipv6"
           or rich_rule.source and check_single_address("ipv6", rich_rule.source)):
            rules.extend(self._build_zone_masquerade_nat_rules(enable, zone, "ip6", rich_rule))
        if rich_rule and (rich_rule.family and rich_rule.family == "ipv4"
           or rich_rule.source and check_single_address("ipv4", rich_rule.source)):
            rules.extend(self._build_zone_masquerade_nat_rules(enable, zone, "ip", rich_rule))
        else:
            rules.extend(self._build_zone_masquerade_nat_rules(enable, zone, "ip6", rich_rule))
            rules.extend(self._build_zone_masquerade_nat_rules(enable, zone, "ip", rich_rule))

        add_del = { True: "add", False: "delete" }[enable]
        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["FORWARD_OUT"],
                                            zone=zone)

        rule_fragment = []
        if rich_rule:
            rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
            rule_fragment += self._rich_rule_source_fragment(rich_rule.source)

        rules.append([add_del, "rule", "inet", "%s" % TABLE_NAME,
                      "filter_%s_allow" % (target)]
                      + rule_fragment + ["ct", "state", "new", "accept"])

        return rules

    def _build_zone_forward_port_nat_rules(self, enable, zone, protocol,
                                           mark_fragment, toaddr, toport,
                                           family):
        add_del = { True: "add", False: "delete" }[enable]
        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["PREROUTING"],
                                            zone=zone)

        dnat_fragment = []
        if toaddr:
            dnat_fragment += ["dnat", "to", toaddr]
        else:
            dnat_fragment += ["redirect", "to"]

        if toport and toport != "":
            dnat_fragment += [":%s" % portStr(toport, "-")]

        return [[add_del, "rule", family, "%s" % TABLE_NAME,
                "nat_%s_allow" % (target), "meta", "l4proto", protocol]
                + mark_fragment + dnat_fragment]

    def build_zone_forward_port_rules(self, enable, zone, filter_chain, port,
                                      protocol, toport, toaddr, mark_id, rich_rule=None):
        add_del = { True: "add", False: "delete" }[enable]

        mark_str = "0x%x" % mark_id
        mark_fragment = ["meta", "mark", mark_str]

        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["PREROUTING"],
                                            zone=zone)
        rule_fragment = []
        if rich_rule:
            rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
            rule_fragment += self._rich_rule_source_fragment(rich_rule.source)

        rules = []
        rules.append([add_del, "rule", "inet", "%s" % TABLE_NAME,
                      "mangle_%s_allow" % (target), protocol]
                      + rule_fragment +
                      ["dport", port, "meta", "mark", "set", mark_str])

        if rich_rule and (rich_rule.family and rich_rule.family == "ipv6"
           or toaddr and check_single_address("ipv6", toaddr)):
            rules.extend(self._build_zone_forward_port_nat_rules(enable, zone,
                                protocol, mark_fragment, toaddr, toport, "ip6"))
        if rich_rule and (rich_rule.family and rich_rule.family == "ipv4"
           or toaddr and check_single_address("ipv4", toaddr)):
            rules.extend(self._build_zone_forward_port_nat_rules(enable, zone,
                                protocol, mark_fragment, toaddr, toport, "ip"))
        else:
            if not toaddr or check_single_address("ipv6", toaddr):
                rules.extend(self._build_zone_forward_port_nat_rules(enable, zone,
                                    protocol, mark_fragment, toaddr, toport, "ip6"))
            if not toaddr or check_single_address("ipv4", toaddr):
                rules.extend(self._build_zone_forward_port_nat_rules(enable, zone,
                                    protocol, mark_fragment, toaddr, toport, "ip"))

        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS[filter_chain],
                                            zone=zone)
        rules.append([add_del, "rule", "inet", "%s" % TABLE_NAME,
                      "filter_%s_allow" % (target), "ct", "state", "new"]
                      + mark_fragment + ["accept"])

        return rules

    def build_zone_icmp_block_rules(self, enable, zone, icmp, rich_rule=None):
        table = "filter"
        add_del = { True: "add", False: "delete" }[enable]

        rules = []
        for icmp_ver in ["icmp", "icmpv6"]:
            for chain in ["INPUT", "FORWARD_IN"]:
                target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS[chain],
                                                    zone=zone)
                if self._fw.zone.query_icmp_block_inversion(zone):
                    final_chain = "%s_%s_allow" % (table, target)
                    final_target = "accept"
                else:
                    final_chain = "%s_%s_deny" % (table, target)
                    final_target = "%%REJECT%%"

                rule_fragment = []
                if rich_rule:
                    rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
                    rule_fragment += self._rich_rule_source_fragment(rich_rule.source)
                rule_fragment += [icmp_ver, "type", icmp]

                if rich_rule:
                    rules.append(self._rich_rule_log(rich_rule, enable, table, target, rule_fragment))
                    rules.append(self._rich_rule_audit(rich_rule, enable, table, target, rule_fragment))
                    if rich_rule.action:
                        rules.append(self._rich_rule_action(zone, rich_rule, enable, table, target, rule_fragment))
                    else:
                        rules.append([add_del, "rule", "inet", "%s" % TABLE_NAME,
                                      "%s_%s_deny" % (table, target)]
                                      + rule_fragment + ["%%REJECT%%"])
                else:
                    if self._fw.get_log_denied() != "off" and final_target != "accept":
                        rules.append([add_del, "rule", "inet", "%s" % TABLE_NAME,
                                      final_chain] + rule_fragment + ["log",
                                      "prefix", "\"%s_%s_ICMP_BLOCK: \"" % (table, zone)])
                    rules.append([add_del, "rule", "inet", "%s" % TABLE_NAME,
                                  final_chain] + rule_fragment + [final_target])

        return rules

    def build_zone_icmp_block_inversion_rules(self, enable, zone):
        table = "filter"
        rules = []
        for chain in ["INPUT", "FORWARD_IN"]:
            _zone = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS[chain],
                                               zone=zone)
            # HACK: nft position is actually a handle, so we need to lookup the
            # handle of the rule we want to insert this after.
            #
            # This must be kept in sync with build_zone_chain_rules()
            #
            # WARN: This does not work if we haven't executed the transaction
            # yet, because we don't have a handle for our rule_key!! As such,
            # we execute transactions before calling this function.
            #
            rule_key = " ".join(["inet", "%s" % TABLE_NAME,
                                 "%s_%s" % (table, _zone),
                                 "jump", "%s_%s_allow" % (table, _zone)])
            rule_handle = self.rule_to_handle[rule_key]

            if self._fw.zone.query_icmp_block_inversion(zone):
                ibi_target = "%%REJECT%%"
            else:
                ibi_target = "accept"

            if enable:
                # FIXME: can we get rid of position ?
                rule = ["add", "rule", "inet", "%s" % TABLE_NAME,
                        "%s_%s" % (table, _zone), "position", rule_handle]
            else:
                rule = ["delete", "rule", "inet", "%s" % TABLE_NAME,
                        "%s_%s" % (table, _zone)]
            rule += ["%%ICMP%%", ibi_target]
            rules.append(rule)

            if self._fw.zone.query_icmp_block_inversion(zone):
                if self._fw.get_log_denied() != "off":
                    if enable:
                        # FIXME: can we get rid of position ?
                        rule = ["add", "rule", "inet", "%s" % TABLE_NAME,
                                "%s_%s" % (table, _zone), "position", rule_handle]
                    else:
                        rule = ["delete", "rule", "inet", "%s" % TABLE_NAME,
                                "%s_%s" % (table, _zone)]
                    rule += ["%%ICMP%%", "%%LOGTYPE%%", "log", "prefix",
                             "\"%s_%s_ICMP_BLOCK: \"" % (table, _zone)]
                    rules.append(rule)

        return rules

    def build_rpfilter_rules(self, log_denied=False):
        rules = []
        rules.append(["insert", "rule", "inet", "%s" % TABLE_NAME,
                      "raw_%s" % "PREROUTING",
                      "meta", "nfproto", "ipv6", "fib", "saddr", ".", "iif",
                      "oif", "missing", "drop"])
        if log_denied != "off":
            rules.append(["insert", "rule", "inet", "%s" % TABLE_NAME,
                          "raw_%s" % "PREROUTING",
                          "meta", "nfproto", "ipv6" "fib", "saddr", ".", "iif",
                          "oif", "missing", "log", "prefix", "rpfilter_DROP: "])
        rules.append(["insert", "rule", "inet", "%s" % TABLE_NAME,
                      "raw_%s" % "PREROUTING",
                      "icmpv6", "type", "nd-router-advert", "accept"]) # RHBZ#1058505
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
