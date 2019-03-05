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
import copy

from firewall.core.base import SHORTCUTS, DEFAULT_ZONE_TARGET
from firewall.core.prog import runProg
from firewall.core.logger import log
from firewall.functions import splitArgs, check_mac, portStr, \
                               check_single_address, check_address
from firewall import config
from firewall.errors import FirewallError, UNKNOWN_ERROR, INVALID_RULE, \
                            INVALID_ICMPTYPE, INVALID_TYPE, INVALID_ENTRY
from firewall.core.rich import Rich_Accept, Rich_Reject, Rich_Drop, Rich_Mark, \
                               Rich_Masquerade, Rich_ForwardPort, Rich_IcmpBlock

TABLE_NAME = "firewalld"

# Map iptables (table, chain) to hooks and priorities.
# These are well defined by NF_IP_PRI_* defines in netfilter.
#
# This is analogous to ipXtables.BUILT_IN_CHAINS, but we omit the chains that
# are only used for direct rules.
#
# Note: All hooks use their standard position + NFT_HOOK_OFFSET. This means
# iptables will have DROP precedence. It also means that even if iptables
# ACCEPTs a packet it may still be dropped later by firewalld's rules.
#
NFT_HOOK_OFFSET = 10
IPTABLES_TO_NFT_HOOK = {
    #"security": {
    #    "INPUT": ("input", 50 + NFT_HOOK_OFFSET),
    #    "OUTPUT": ("output", 50 + NFT_HOOK_OFFSET),
    #    "FORWARD": ("forward", 50 + NFT_HOOK_OFFSET),
    #},
    "raw": {
        "PREROUTING": ("prerouting", -300 + NFT_HOOK_OFFSET),
    #   "OUTPUT": ("output", -300 + NFT_HOOK_OFFSET),
    },
    "mangle": {
        "PREROUTING": ("prerouting", -150 + NFT_HOOK_OFFSET),
    #    "POSTROUTING": ("postrouting", -150 + NFT_HOOK_OFFSET),
    #    "INPUT": ("input", -150 + NFT_HOOK_OFFSET),
    #    "OUTPUT": ("output", -150 + NFT_HOOK_OFFSET),
    #    "FORWARD": ("forward", -150 + NFT_HOOK_OFFSET),
    },
    "nat": {
        "PREROUTING": ("prerouting", -100 + NFT_HOOK_OFFSET),
        "POSTROUTING": ("postrouting", 100 + NFT_HOOK_OFFSET),
    #    "INPUT": ("input", 100 + NFT_HOOK_OFFSET),
    #    "OUTPUT": ("output", -100 + NFT_HOOK_OFFSET),
    },
    "filter": {
        "INPUT": ("input", 0 + NFT_HOOK_OFFSET),
        "FORWARD": ("forward", 0 + NFT_HOOK_OFFSET),
        "OUTPUT": ("output", 0 + NFT_HOOK_OFFSET),
    },
}

# Most ICMP types are provided by nft, but for the codes we have to use numeric
# values.
#
ICMP_TYPES_FRAGMENT = {
    "ipv4" : {
        "communication-prohibited" :    ["icmp", "type", "destination-unreachable", "icmp", "code", "13"],
        "destination-unreachable" :     ["icmp", "type", "destination-unreachable"],
        "echo-reply" :                  ["icmp", "type", "echo-reply"],
        "echo-request" :                ["icmp", "type", "echo-request"],
        "fragmentation-needed" :        ["icmp", "type", "destination-unreachable", "icmp", "code", "4"],
        "host-precedence-violation" :   ["icmp", "type", "destination-unreachable", "icmp", "code", "14"],
        "host-prohibited" :             ["icmp", "type", "destination-unreachable", "icmp", "code", "10"],
        "host-redirect" :               ["icmp", "type", "redirect", "icmp", "code", "1"],
        "host-unknown" :                ["icmp", "type", "destination-unreachable", "icmp", "code", "7"],
        "host-unreachable" :            ["icmp", "type", "destination-unreachable", "icmp", "code", "1"],
        "ip-header-bad" :               ["icmp", "type", "parameter-problem", "icmp", "code", "1"],
        "network-prohibited" :          ["icmp", "type", "destination-unreachable", "icmp", "code", "8"],
        "network-redirect" :            ["icmp", "type", "redirect", "icmp", "code", "0"],
        "network-unknown" :             ["icmp", "type", "destination-unreachable", "icmp", "code", "6"],
        "network-unreachable" :         ["icmp", "type", "destination-unreachable", "icmp", "code", "0"],
        "parameter-problem" :           ["icmp", "type", "parameter-problem"],
        "port-unreachable" :            ["icmp", "type", "destination-unreachable", "icmp", "code", "3"],
        "precedence-cutoff" :           ["icmp", "type", "destination-unreachable", "icmp", "code", "15"],
        "protocol-unreachable" :        ["icmp", "type", "destination-unreachable", "icmp", "code", "2"],
        "redirect" :                    ["icmp", "type", "redirect"],
        "required-option-missing" :     ["icmp", "type", "parameter-problem", "icmp", "code", "1"],
        "router-advertisement" :        ["icmp", "type", "router-advertisement"],
        "router-solicitation" :         ["icmp", "type", "router-solicitation"],
        "source-quench" :               ["icmp", "type", "source-quench"],
        "source-route-failed" :         ["icmp", "type", "destination-unreachable", "icmp", "code", "5"],
        "time-exceeded" :               ["icmp", "type", "time-exceeded"],
        "timestamp-reply" :             ["icmp", "type", "timestamp-reply"],
        "timestamp-request" :           ["icmp", "type", "timestamp-request"],
        "tos-host-redirect" :           ["icmp", "type", "redirect", "icmp", "code", "3"],
        "tos-host-unreachable" :        ["icmp", "type", "destination-unreachable", "icmp", "code", "12"],
        "tos-network-redirect" :        ["icmp", "type", "redirect", "icmp", "code", "2"],
        "tos-network-unreachable" :     ["icmp", "type", "destination-unreachable", "icmp", "code", "11"],
        "ttl-zero-during-reassembly" :  ["icmp", "type", "time-exceeded", "icmp", "code", "1"],
        "ttl-zero-during-transit" :     ["icmp", "type", "time-exceeded", "icmp", "code", "0"],
    },

    "ipv6" : {
        "address-unreachable" :         ["icmpv6", "type", "destination-unreachable", "icmpv6", "code", "3"],
        "bad-header" :                  ["icmpv6", "type", "parameter-problem", "icmpv6", "code", "0"],
        "beyond-scope" :                ["icmpv6", "type", "destination-unreachable", "icmpv6", "code", "2"],
        "communication-prohibited" :    ["icmpv6", "type", "destination-unreachable", "icmpv6", "code", "1"],
        "destination-unreachable" :     ["icmpv6", "type", "destination-unreachable"],
        "echo-reply" :                  ["icmpv6", "type", "echo-reply"],
        "echo-request" :                ["icmpv6", "type", "echo-request"],
        "failed-policy" :               ["icmpv6", "type", "destination-unreachable", "icmpv6", "code", "5"],
        "neighbour-advertisement" :     ["icmpv6", "type", "nd-neighbor-advert"],
        "neighbour-solicitation" :      ["icmpv6", "type", "nd-neighbor-solicit"],
        "no-route" :                    ["icmpv6", "type", "destination-unreachable", "icmpv6", "code", "0"],
        "packet-too-big" :              ["icmpv6", "type", "packet-too-big"],
        "parameter-problem" :           ["icmpv6", "type", "parameter-problem"],
        "port-unreachable" :            ["icmpv6", "type", "destination-unreachable", "icmpv6", "code", "4"],
        "redirect" :                    ["icmpv6", "type", "nd-redirect"],
        "reject-route" :                ["icmpv6", "type", "destination-unreachable", "icmpv6", "code", "6"],
        "router-advertisement" :        ["icmpv6", "type", "nd-router-advert"],
        "router-solicitation" :         ["icmpv6", "type", "nd-router-solicit"],
        "time-exceeded" :               ["icmpv6", "type", "time-exceeded"],
        "ttl-zero-during-reassembly" :  ["icmpv6", "type", "time-exceeded", "icmpv6", "code", "1"],
        "ttl-zero-during-transit" :     ["icmpv6", "type", "time-exceeded", "icmpv6", "code", "0"],
        "unknown-header-type" :         ["icmpv6", "type", "parameter-problem", "icmpv6", "code", "1"],
        "unknown-option" :              ["icmpv6", "type", "parameter-problem", "icmpv6", "code", "2"],
    }
}

class nftables(object):
    name = "nftables"
    zones_supported = True

    def __init__(self, fw):
        self._fw = fw
        self._command = config.COMMANDS["nft"]
        self.fill_exists()
        self.available_tables = []
        self.rule_to_handle = {}
        self.rule_ref_count = {}
        self.rich_rule_priority_counts = {}
        self.our_chains = { # chains created by firewalld
            # family: { chains ...}
            "inet": {},
            "ip": {},
            "ip6": {},
        }

    def fill_exists(self):
        self.command_exists = os.path.exists(self._command)
        self.restore_command_exists = False

    def __run(self, args):
        nft_opts = ["--echo", "--handle"]
        _args = args[:]

        def rule_key_from_rule(rule):
            rule_key = rule[2:]
            # "insert rule family table chain index <num>"
            #              ^^ rule_key starts here
            if rule_key[3] in ["position", "handle"]:
                raise FirewallError(INVALID_RULE, "position/handle not allowed in rule")
            return " ".join([str(x) for x in rule_key])

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
            rule_key = rule_key_from_rule(_args)
        elif _args[0] in ["delete"] and _args[1] == "rule":
            rule_add = False
            rule_key = rule_key_from_rule(_args)

        # rule deduplication
        if rule_key in self.rule_ref_count:
            if rule_add:
                self.rule_ref_count[rule_key] += 1
                return ""
            if not rule_add and self.rule_ref_count[rule_key] > 1:
                self.rule_ref_count[rule_key] -= 1
                return ""
            elif self.rule_ref_count[rule_key] == 1:
                self.rule_ref_count[rule_key] -= 1
            else:
                raise FirewallError(UNKNOWN_ERROR, "rule ref count bug: rule_key '%s', cnt %d"
                                                   % (rule_key, self.rule_ref_count[rule_key]))
            log.debug2("%s: rule ref cnt %d, %s %s", self.__class__,
                       self.rule_ref_count[rule_key], self._command,
                       " ".join([str(x) for x in _args]))

        # replace %%RICH_RULE_PRIORITY%%
        if rule_key:
            rich_rule_priority_counts = self.rich_rule_priority_counts
            try:
                i = _args.index("%%RICH_RULE_PRIORITY%%")
            except ValueError:
                pass
            else:
                rich_rule_priority_counts = copy.deepcopy(self.rich_rule_priority_counts)
                _args.pop(i)
                priority = _args.pop(i)
                if type(priority) != int:
                    raise FirewallError(INVALID_RULE, "rich rule priority must be followed by a number")
                chain = (_args[2], _args[4]) # family, chain
                # Add the rule to the priority counts. We don't need to store the
                # rule, just bump the ref count for the priority value.
                if not rule_add:
                    if chain not in rich_rule_priority_counts or \
                       priority not in rich_rule_priority_counts[chain] or \
                       rich_rule_priority_counts[chain][priority] <= 0:
                        raise FirewallError(UNKNOWN_ERROR, "nonexistent or underflow of rich rule priority count")

                    rich_rule_priority_counts[chain][priority] -= 1
                else:
                    if chain not in rich_rule_priority_counts:
                        rich_rule_priority_counts[chain] = {}
                    if priority not in rich_rule_priority_counts[chain]:
                        rich_rule_priority_counts[chain][priority] = 0

                    # calculate index of new rule
                    index = 0
                    for p in sorted(rich_rule_priority_counts[chain].keys()):
                        if p == priority and _args[0] == "insert":
                            break
                        index += rich_rule_priority_counts[chain][p]
                        if p == priority and _args[0] == "add":
                            break

                    rich_rule_priority_counts[chain][priority] += 1

                    if index == 0:
                        _args[0] = "insert"
                    else:
                        index -= 1 # point to the rule before insertion point
                        _args[0] = "add"
                        _args.insert(i, "index")
                        _args.insert(i+1, "%d" % index)

        if not rule_key or (not rule_add and self.rule_ref_count[rule_key] == 0) \
                        or (    rule_add and rule_key not in self.rule_ref_count):

            # delete using rule handle
            if rule_key and not rule_add:
                _args = ["delete", "rule"] + _args[2:5] + \
                    ["handle", self.rule_to_handle[rule_key]]

            _args_str = " ".join(_args)
            log.debug2("%s: %s %s", self.__class__, self._command, _args_str)
            (status, output) = runProg(self._command, nft_opts + _args)
            if status != 0:
                raise ValueError("'%s %s' failed: %s" % (self._command,
                                                         _args_str, output))

            if rule_key:
                self.rich_rule_priority_counts = rich_rule_priority_counts

            # nft requires deleting rules by handle. So we must cache the rule
            # handle when adding/inserting rules.
            #
            if rule_key:
                if rule_add:
                    handle_str = "# handle "
                    offset = output.index(handle_str) + len(handle_str)
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

    def reverse_rule(self, args):
        ret_args = args[:]
        ret_args[0] = "delete"
        return ret_args

    def set_rules(self, rules, log_denied):
        # We can't support using "nft -f" because we need to retrieve the
        # handles for each rules so we can delete them later on.
        # See also: self.restore_command_exists
        #
        # We can implement this once libnftables in ready.
        #
        raise FirewallError(UNKNOWN_ERROR, "not implemented")

    def set_rule(self, rule, log_denied):
        # replace %%REJECT%%
        #
        # HACK: work around nft bug in which icmpx does not work if the rule
        # has qualified the ip family.
        icmp_keyword = "icmpx"
        if "ipv4" in rule or "ip" in rule or "icmp" in rule:
            icmp_keyword = "icmp"
        elif "ipv6" in rule or "ip6" in rule or "icmpv6" in rule:
            icmp_keyword = "icmpv6"
        self._rule_replace(rule, "%%REJECT%%",
                           ["reject", "with", icmp_keyword, "type", "admin-prohibited"])

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
                rule[i:i+1] = ["pkttype", log_denied]
            else:
                rule.pop(i)

        return self.__run(rule)

    def get_available_tables(self, table=None):
        # Tables always exist in nftables
        return [table] if table else IPTABLES_TO_NFT_HOOK.keys()

    def build_flush_rules(self):
        self.rule_to_handle = {}
        self.rule_ref_count = {}
        self.rich_rule_priority_counts = {}

        rules = []
        for family in self.our_chains.keys():
            rules.append(["delete", "table", family, "%s" % TABLE_NAME])
        return rules

    def build_set_policy_rules(self, policy):
        # Policy is not exposed to the user. It's only to make sure we DROP
        # packets while initially starting and for panic mode. As such, using
        # hooks with a higher priority than our base chains is sufficient.
        #
        table_name = TABLE_NAME + "_" + "policy_drop"

        rules = []
        if policy == "DROP":
            rules.append(["add", "table", "inet", table_name])

            # To drop everything we need to use the "raw" priority. These occur
            # before conntrack, mangle, nat, etc
            for hook in ["prerouting", "output"]:
                _add_chain = "add chain inet %s %s_%s '{ type filter hook %s priority %d ; policy drop ; }'" % \
                             (table_name, "raw", hook, hook, -300 + NFT_HOOK_OFFSET - 1)
                rules.append(splitArgs(_add_chain))
        elif policy == "ACCEPT":
            rules.append(["delete", "table", "inet", table_name])
        else:
            FirewallError(UNKNOWN_ERROR, "not implemented")

        return rules

    def supported_icmp_types(self):
        # nftables supports any icmp_type via arbitrary type/code matching.
        # We just need a translation for it in ICMP_TYPES_FRAGMENT.
        supported = set()

        for ipv in ICMP_TYPES_FRAGMENT.keys():
            supported.update(ICMP_TYPES_FRAGMENT[ipv].keys())

        return list(supported)

    def build_default_tables(self):
        default_tables = []
        for family in self.our_chains.keys():
            default_tables.append("add table %s %s" % (family, TABLE_NAME))
        return map(splitArgs, default_tables)

    def build_default_rules(self, log_denied="off"):
        default_rules = []
        self.our_chains["inet"]["raw"] = set()
        for chain in IPTABLES_TO_NFT_HOOK["raw"].keys():
            default_rules.append("add chain inet %s raw_%s '{ type filter hook %s priority %d ; }'" %
                                 (TABLE_NAME, chain,
                                  IPTABLES_TO_NFT_HOOK["raw"][chain][0],
                                  IPTABLES_TO_NFT_HOOK["raw"][chain][1]))

        for chain in ["PREROUTING"]:
            default_rules.append("add chain inet %s raw_%s_ZONES_SOURCE" % (TABLE_NAME, chain))
            default_rules.append("add chain inet %s raw_%s_ZONES" % (TABLE_NAME, chain))
            default_rules.append("add rule inet %s raw_%s jump raw_%s_ZONES_SOURCE" % (TABLE_NAME, chain, chain))
            default_rules.append("add rule inet %s raw_%s jump raw_%s_ZONES" % (TABLE_NAME, chain, chain))
            self.our_chains["inet"]["raw"].update(set(["%s_ZONES_SOURCE" % chain, "%s_ZONES" % chain]))

        self.our_chains["inet"]["mangle"] = set()
        for chain in IPTABLES_TO_NFT_HOOK["mangle"].keys():
            default_rules.append("add chain inet %s mangle_%s '{ type filter hook %s priority %d ; }'" %
                                 (TABLE_NAME, chain,
                                  IPTABLES_TO_NFT_HOOK["mangle"][chain][0],
                                  IPTABLES_TO_NFT_HOOK["mangle"][chain][1]))

            default_rules.append("add chain inet %s mangle_%s_ZONES_SOURCE" % (TABLE_NAME, chain))
            default_rules.append("add chain inet %s mangle_%s_ZONES" % (TABLE_NAME, chain))
            default_rules.append("add rule inet %s mangle_%s jump mangle_%s_ZONES_SOURCE" % (TABLE_NAME, chain, chain))
            default_rules.append("add rule inet %s mangle_%s jump mangle_%s_ZONES" % (TABLE_NAME, chain, chain))
            self.our_chains["inet"]["mangle"].update(set(["%s_ZONES_SOURCE" % chain, "%s_ZONES" % chain]))

        self.our_chains["ip"]["nat"] = set()
        self.our_chains["ip6"]["nat"] = set()
        for family in ["ip", "ip6"]:
            for chain in IPTABLES_TO_NFT_HOOK["nat"].keys():
                default_rules.append("add chain %s %s nat_%s '{ type nat hook %s priority %d ; }'" %
                                     (family, TABLE_NAME, chain,
                                      IPTABLES_TO_NFT_HOOK["nat"][chain][0],
                                      IPTABLES_TO_NFT_HOOK["nat"][chain][1]))

                default_rules.append("add chain %s %s nat_%s_ZONES_SOURCE" % (family, TABLE_NAME, chain))
                default_rules.append("add chain %s %s nat_%s_ZONES" % (family, TABLE_NAME, chain))
                default_rules.append("add rule %s %s nat_%s jump nat_%s_ZONES_SOURCE" % (family, TABLE_NAME, chain, chain))
                default_rules.append("add rule %s %s nat_%s jump nat_%s_ZONES" % (family, TABLE_NAME, chain, chain))
                self.our_chains[family]["nat"].update(set(["%s_ZONES_SOURCE" % chain, "%s_ZONES" % chain]))

        self.our_chains["inet"]["filter"] = set()
        for chain in IPTABLES_TO_NFT_HOOK["filter"].keys():
            default_rules.append("add chain inet %s filter_%s '{ type filter hook %s priority %d ; }'" %
                                 (TABLE_NAME, chain,
                                  IPTABLES_TO_NFT_HOOK["filter"][chain][0],
                                  IPTABLES_TO_NFT_HOOK["filter"][chain][1]))

        # filter, INPUT
        default_rules.append("add chain inet %s filter_%s_ZONES_SOURCE" % (TABLE_NAME, "INPUT"))
        default_rules.append("add chain inet %s filter_%s_ZONES" % (TABLE_NAME, "INPUT"))
        default_rules.append("add rule inet %s filter_%s ct state established,related accept" % (TABLE_NAME, "INPUT"))
        default_rules.append("add rule inet %s filter_%s iifname lo accept" % (TABLE_NAME, "INPUT"))
        default_rules.append("add rule inet %s filter_%s jump filter_%s_ZONES_SOURCE" % (TABLE_NAME, "INPUT", "INPUT"))
        default_rules.append("add rule inet %s filter_%s jump filter_%s_ZONES" % (TABLE_NAME, "INPUT", "INPUT"))
        if log_denied != "off":
            default_rules.append("add rule inet %s filter_%s ct state invalid %%%%LOGTYPE%%%% log prefix '\"STATE_INVALID_DROP: \"'" % (TABLE_NAME, "INPUT"))
        default_rules.append("add rule inet %s filter_%s ct state invalid drop" % (TABLE_NAME, "INPUT"))
        if log_denied != "off":
            default_rules.append("add rule inet %s filter_%s %%%%LOGTYPE%%%% log prefix '\"FINAL_REJECT: \"'" % (TABLE_NAME, "INPUT"))
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
            default_rules.append("add rule inet %s filter_%s ct state invalid %%%%LOGTYPE%%%% log prefix '\"STATE_INVALID_DROP: \"'" % (TABLE_NAME, "FORWARD"))
        default_rules.append("add rule inet %s filter_%s ct state invalid drop" % (TABLE_NAME, "FORWARD"))
        if log_denied != "off":
            default_rules.append("add rule inet %s filter_%s %%%%LOGTYPE%%%% log prefix '\"FINAL_REJECT: \"'" % (TABLE_NAME, "FORWARD"))
        default_rules.append("add rule inet %s filter_%s reject with icmpx type admin-prohibited" % (TABLE_NAME, "FORWARD"))

        # filter, OUTPUT
        default_rules.append("add rule inet %s filter_%s oifname lo accept" % (TABLE_NAME, "OUTPUT"))

        self.our_chains["inet"]["filter"] = set(["INPUT_ZONES_SOURCE",
                                                 "INPUT_ZONES",
                                                 "FORWARD_IN_ZONES_SOURCE",
                                                 "FORWARD_IN_ZONES",
                                                 "FORWARD_OUT_ZONES_SOURCE",
                                                 "FORWARD_OUT_ZONES"])

        return map(splitArgs, default_rules)

    def get_zone_table_chains(self, table):
        if table == "filter":
            return ["INPUT", "FORWARD_IN", "FORWARD_OUT"]
        if table == "mangle":
            return ["PREROUTING"]
        if table == "nat":
            return ["PREROUTING", "POSTROUTING"]
        if table == "raw":
            return ["PREROUTING"]

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

        if interface[len(interface)-1] == "+":
            interface = interface[:len(interface)-1] + "*"

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
        if interface == "*":
            rule += [action, "%s_%s" % (table, target)]
        else:
            rule += [opt, "\"" + interface + "\"", action, "%s_%s" % (table, target)]
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
            ipset = address[len("ipset:"):]
            rule_family = self._set_get_family(ipset)
            address = "@" + ipset
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

        self.our_chains[family][table].update(set([_zone,
                                         "%s_log" % _zone,
                                         "%s_deny" % _zone,
                                         "%s_pre" % _zone,
                                         "%s_post" % _zone,
                                         "%s_allow" % _zone]))

        rules = []
        rules.append(["add", "chain", family, "%s" % TABLE_NAME,
                      "%s_%s" % (table, _zone)])
        rules.append(["add", "chain", family, "%s" % TABLE_NAME,
                      "%s_%s_pre" % (table, _zone)])
        rules.append(["add", "chain", family, "%s" % TABLE_NAME,
                      "%s_%s_log" % (table, _zone)])
        rules.append(["add", "chain", family, "%s" % TABLE_NAME,
                      "%s_%s_deny" % (table, _zone)])
        rules.append(["add", "chain", family, "%s" % TABLE_NAME,
                      "%s_%s_allow" % (table, _zone)])
        rules.append(["add", "chain", family, "%s" % TABLE_NAME,
                      "%s_%s_post" % (table, _zone)])

        rules.append(["add", "rule", family, "%s" % TABLE_NAME,
                      "%s_%s" % (table, _zone),
                      "jump", "%s_%s_pre" % (table, _zone)])
        rules.append(["add", "rule", family, "%s" % TABLE_NAME,
                      "%s_%s" % (table, _zone),
                      "jump", "%s_%s_log" % (table, _zone)])
        rules.append(["add", "rule", family, "%s" % TABLE_NAME,
                      "%s_%s" % (table, _zone),
                      "jump", "%s_%s_deny" % (table, _zone)])
        rules.append(["add", "rule", family, "%s" % TABLE_NAME,
                      "%s_%s" % (table, _zone),
                      "jump", "%s_%s_allow" % (table, _zone)])
        rules.append(["add", "rule", family, "%s" % TABLE_NAME,
                      "%s_%s" % (table, _zone),
                      "jump", "%s_%s_post" % (table, _zone)])

        target = self._fw.zone._zones[zone].target

        if self._fw.get_log_denied() != "off":
            if table == "filter" and \
               chain in ["INPUT", "FORWARD_IN", "FORWARD_OUT", "OUTPUT"]:
                if target in ["REJECT", "%%REJECT%%", "DROP"]:
                    log_suffix = target
                    if target == "%%REJECT%%":
                        log_suffix = "REJECT"
                    rules.append(["add", "rule", family, "%s" % TABLE_NAME,
                                  "%s_%s" % (table, _zone), "%%LOGTYPE%%",
                                  "log", "prefix",
                                  "\"filter_%s_%s: \"" % (_zone, log_suffix)])

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
                          "%s_%s" % (table, _zone),
                          target.lower() if target != "%%REJECT%%" else "%%REJECT%%"])

        return rules

    def _reject_types_fragment(self, reject_type):
        frags = {
            # REJECT_TYPES              : <nft reject rule fragment>
            "icmp-host-prohibited"      : ["with", "icmp",   "type", "host-prohibited"],
            "host-prohib"               : ["with", "icmp",   "type", "host-prohibited"],
            "icmp-net-prohibited"       : ["with", "icmp",   "type", "net-prohibited"],
            "net-prohib"                : ["with", "icmp",   "type", "net-prohibited"],
            "icmp-admin-prohibited"     : ["with", "icmp",   "type", "admin-prohibited"],
            "admin-prohib"              : ["with", "icmp",   "type", "admin-prohibited"],
            "icmp6-adm-prohibited"      : ["with", "icmpv6", "type", "admin-prohibited"],
            "adm-prohibited"            : ["with", "icmpv6", "type", "admin-prohibited"],

            "icmp-net-unreachable"      : ["with", "icmp",   "type", "net-unreachable"],
            "net-unreach"               : ["with", "icmp",   "type", "net-unreachable"],
            "icmp-host-unreachable"     : ["with", "icmp",   "type", "host-unreachable"],
            "host-unreach"              : ["with", "icmp",   "type", "host-unreachable"],
            "icmp-port-unreachable"     : ["with", "icmp",   "type", "port-unreachable"],
            "icmp6-port-unreachable"    : ["with", "icmpv6", "type", "port-unreachable"],
            "port-unreach"              : ["with", "icmpx",  "type", "port-unreachable"],
            "icmp-proto-unreachable"    : ["with", "icmp",   "type", "prot-unreachable"],
            "proto-unreach"             : ["with", "icmp",   "type", "prot-unreachable"],
            "icmp6-addr-unreachable"    : ["with", "icmpv6", "type", "addr-unreachable"],
            "addr-unreach"              : ["with", "icmpv6", "type", "addr-unreachable"],

            "icmp6-no-route"            : ["with", "icmpv6", "type", "no-route"],
            "no-route"                  : ["with", "icmpv6", "type", "no-route"],

            "tcp-reset"                 : ["with", "tcp",    "reset"],
            "tcp-rst"                   : ["with", "tcp",    "reset"],
        }
        return frags[reject_type]

    def _rich_rule_limit_fragment(self, limit):
        if not limit:
            return []

        rich_to_nft = {
            "s" : "second",
            "m" : "minute",
            "h" : "hour",
            "d" : "day",
        }

        try:
            i = limit.value.index("/")
        except ValueError:
            raise FirewallError(INVALID_RULE, "Expected '/' in limit")

        return ["limit", "rate", limit.value[0:i], "/",
                rich_to_nft[limit.value[i+1]]]

    def _rich_rule_chain_suffix(self, rich_rule):
        if type(rich_rule.element) in [Rich_Masquerade, Rich_ForwardPort, Rich_IcmpBlock]:
            # These are special and don't have an explicit action
            pass
        elif rich_rule.action:
            if type(rich_rule.action) not in [Rich_Accept, Rich_Reject, Rich_Drop, Rich_Mark]:
                raise FirewallError(INVALID_RULE, "Unknown action %s" % type(rich_rule.action))
        else:
            raise FirewallError(INVALID_RULE, "No rule action specified.")

        if rich_rule.priority == 0:
            if type(rich_rule.element) in [Rich_Masquerade, Rich_ForwardPort] or \
               type(rich_rule.action) in [Rich_Accept, Rich_Mark]:
                return "allow"
            elif type(rich_rule.element) in [Rich_IcmpBlock] or \
                 type(rich_rule.action) in [Rich_Reject, Rich_Drop]:
                return "deny"
        elif rich_rule.priority < 0:
            return "pre"
        else:
            return "post"

    def _rich_rule_chain_suffix_from_log(self, rich_rule):
        if not rich_rule.log and not rich_rule.audit:
            raise FirewallError(INVALID_RULE, "Not log or audit")

        if rich_rule.priority == 0:
            return "log"
        elif rich_rule.priority < 0:
            return "pre"
        else:
            return "post"

    def _rich_rule_priority_fragment(self, rich_rule):
        if rich_rule.priority == 0:
            return []
        return ["%%RICH_RULE_PRIORITY%%", rich_rule.priority]

    def _rich_rule_log(self, rich_rule, enable, table, target, rule_fragment):
        if not rich_rule.log:
            return []

        add_del = { True: "add", False: "delete" }[enable]

        chain_suffix = self._rich_rule_chain_suffix_from_log(rich_rule)
        rule = [add_del, "rule", "inet", "%s" % TABLE_NAME,
                "%s_%s_%s" % (table, target, chain_suffix)]
        rule += self._rich_rule_priority_fragment(rich_rule)
        rule += rule_fragment + ["log"]
        if rich_rule.log.prefix:
            rule += ["prefix", "\"%s\"" % rich_rule.log.prefix]
        if rich_rule.log.level:
            rule += ["level", '"%s"' % rich_rule.log.level]
        rule += self._rich_rule_limit_fragment(rich_rule.log.limit)

        return rule

    def _rich_rule_audit(self, rich_rule, enable, table, target, rule_fragment):
        if not rich_rule.audit:
            return []

        add_del = { True: "add", False: "delete" }[enable]

        chain_suffix = self._rich_rule_chain_suffix_from_log(rich_rule)
        rule = [add_del, "rule", "inet", "%s" % TABLE_NAME,
                "%s_%s_%s" % (table, target, chain_suffix)]
        rule += self._rich_rule_priority_fragment(rich_rule)
        rule += rule_fragment + ["log", "level", "audit"]
        rule += self._rich_rule_limit_fragment(rich_rule.audit.limit)

        return rule

    def _rich_rule_action(self, zone, rich_rule, enable, table, target, rule_fragment):
        if not rich_rule.action:
            return []

        add_del = { True: "add", False: "delete" }[enable]

        chain_suffix = self._rich_rule_chain_suffix(rich_rule)
        chain = "%s_%s_%s" % (table, target, chain_suffix)
        if type(rich_rule.action) == Rich_Accept:
            rule_action = ["accept"]
        elif type(rich_rule.action) == Rich_Reject:
            rule_action = ["reject"]
            if rich_rule.action.type:
                rule_action += self._reject_types_fragment(rich_rule.action.type)
        elif type(rich_rule.action) ==  Rich_Drop:
            rule_action = ["drop"]
        elif type(rich_rule.action) == Rich_Mark:
            target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["PREROUTING"],
                                                zone=zone)
            table = "mangle"
            chain = "%s_%s_%s" % (table, target, chain_suffix)
            rule_action = ["meta", "mark", "set", rich_rule.action.set]
        else:
            raise FirewallError(INVALID_RULE,
                                "Unknown action %s" % type(rich_rule.action))

        rule = [add_del, "rule", "inet", "%s" % TABLE_NAME, chain]
        rule += self._rich_rule_priority_fragment(rich_rule)
        rule += rule_fragment
        rule += self._rich_rule_limit_fragment(rich_rule.action.limit)
        rule += rule_action

        return rule

    def _rich_rule_family_fragment(self, rich_family):
        if not rich_family:
            return []
        if rich_family == "ipv4":
            return ["meta", "nfproto", "ipv4"]
        if rich_family == "ipv6":
            return ["meta", "nfproto", "ipv6"]
        raise FirewallError(INVALID_RULE,
                            "Invalid family" % rich_family)

    def _rich_rule_destination_fragment(self, rich_dest):
        if not rich_dest:
            return []

        rule_fragment = []
        if check_address("ipv4", rich_dest.addr):
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
            if check_address("ipv4", rich_source.addr):
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
            family = self._set_get_family(rich_source.ipset)
            if rich_source.invert:
                rule_fragment += [family, "saddr", "!=", "@" + rich_source.ipset]
            else:
                rule_fragment += [family, "saddr", "@" + rich_source.ipset]

        return rule_fragment

    def build_zone_ports_rules(self, enable, zone, proto, port, destination=None, rich_rule=None):
        add_del = { True: "add", False: "delete" }[enable]
        table = "filter"
        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["INPUT"], zone=zone)

        rule_fragment = []
        if rich_rule:
            rule_fragment += self._rich_rule_family_fragment(rich_rule.family)
        if destination:
            if check_address("ipv4", destination):
                rule_fragment += ["ip"]
            else:
                rule_fragment += ["ip6"]
            rule_fragment += ["daddr", destination]
        if rich_rule:
            rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
            rule_fragment += self._rich_rule_source_fragment(rich_rule.source)
        rule_fragment += [proto, "dport", "%s" % portStr(port, "-")]
        rule_fragment += ["ct", "state", "new,untracked"]

        rules = []
        if rich_rule:
            rules.append(self._rich_rule_log(rich_rule, enable, table, target, rule_fragment))
            rules.append(self._rich_rule_audit(rich_rule, enable, table, target, rule_fragment))
            rules.append(self._rich_rule_action(zone, rich_rule, enable, table, target, rule_fragment))
        else:
            rules.append([add_del, "rule", "inet", "%s" % TABLE_NAME,
                          "%s_%s_allow" % (table, target)] +
                          rule_fragment + ["accept"])

        return rules

    def build_zone_protocol_rules(self, enable, zone, protocol, destination=None, rich_rule=None):
        add_del = { True: "add", False: "delete" }[enable]
        table = "filter"
        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["INPUT"], zone=zone)

        rule_fragment = []
        if rich_rule:
            rule_fragment += self._rich_rule_family_fragment(rich_rule.family)
        if destination:
            if check_address("ipv4", destination):
                rule_fragment += ["ip"]
            else:
                rule_fragment += ["ip6"]
            rule_fragment += ["daddr", destination]
        if rich_rule:
            rule_fragment += self._rich_rule_family_fragment(rich_rule.family)
            rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
            rule_fragment += self._rich_rule_source_fragment(rich_rule.source)
        rule_fragment = ["meta", "l4proto", protocol]
        rule_fragment += ["ct", "state", "new,untracked"]

        rules = []
        if rich_rule:
            rules.append(self._rich_rule_log(rich_rule, enable, table, target, rule_fragment))
            rules.append(self._rich_rule_audit(rich_rule, enable, table, target, rule_fragment))
            rules.append(self._rich_rule_action(zone, rich_rule, enable, table, target, rule_fragment))
        else:
            rules.append([add_del, "rule", "inet", "%s" % TABLE_NAME,
                          "filter_%s_allow" % (target)] +
                          rule_fragment + ["accept"])

        return rules

    def build_zone_source_ports_rules(self, enable, zone, proto, port,
                                      destination=None, rich_rule=None):
        add_del = { True: "add", False: "delete" }[enable]
        table = "filter"
        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["INPUT"], zone=zone)

        rule_fragment = []
        if rich_rule:
            rule_fragment += self._rich_rule_family_fragment(rich_rule.family)
        if destination:
            if check_address("ipv4", destination):
                rule_fragment += ["ip"]
            else:
                rule_fragment += ["ip6"]
            rule_fragment += ["daddr", destination]
        if rich_rule:
            rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
            rule_fragment += self._rich_rule_source_fragment(rich_rule.source)
        rule_fragment += [proto, "sport", "%s" % portStr(port, "-")]
        rule_fragment += ["ct", "state", "new,untracked"]

        rules = []
        if rich_rule:
            rules.append(self._rich_rule_log(rich_rule, enable, table, target, rule_fragment))
            rules.append(self._rich_rule_audit(rich_rule, enable, table, target, rule_fragment))
            rules.append(self._rich_rule_action(zone, rich_rule, enable, table, target, rule_fragment))
        else:
            rules.append([add_del, "rule", "inet", "%s" % TABLE_NAME,
                          "%s_%s_allow" % (table, target)] +
                          rule_fragment + ["accept"])

        return rules

    def build_zone_helper_ports_rules(self, enable, zone, proto, port,
                                      destination, helper_name):
        add_del = { True: "add", False: "delete" }[enable]
        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["PREROUTING"],
                                            zone=zone)
        rule = [add_del, "rule", "inet", "%s" % TABLE_NAME,
                "raw_%s_allow" % (target), proto]
        if destination:
            if check_address("ipv4", destination):
                rule += ["ip"]
            else:
                rule += ["ip6"]
            rule += ["daddr", destination]
        rule += ["dport", "%s" % portStr(port, "-")]
        rule += ["ct", "helper", helper_name]

        return [rule]

    def _build_zone_masquerade_nat_rules(self, enable, zone, family, rich_rule=None):
        add_del = { True: "add", False: "delete" }[enable]
        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["POSTROUTING"],
                                            zone=zone)

        rule_fragment = []
        if rich_rule:
            rule_fragment += self._rich_rule_priority_fragment(rich_rule)
            rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
            rule_fragment += self._rich_rule_source_fragment(rich_rule.source)
            chain_suffix = self._rich_rule_chain_suffix(rich_rule)
        else:
            chain_suffix = "allow"

        return [[add_del, "rule", family, "%s" % TABLE_NAME,
                "nat_%s_%s" % (target, chain_suffix)]
                + rule_fragment + ["oifname", "!=", "lo", "masquerade"]]

    def build_zone_masquerade_rules(self, enable, zone, rich_rule=None):
        # nat tables needs to use ip/ip6 family
        rules = []
        if rich_rule and (rich_rule.family and rich_rule.family == "ipv6"
           or rich_rule.source and check_address("ipv6", rich_rule.source.addr)):
            rules.extend(self._build_zone_masquerade_nat_rules(enable, zone, "ip6", rich_rule))
        elif rich_rule and (rich_rule.family and rich_rule.family == "ipv4"
           or rich_rule.source and check_address("ipv4", rich_rule.source.addr)):
            rules.extend(self._build_zone_masquerade_nat_rules(enable, zone, "ip", rich_rule))
        else:
            rules.extend(self._build_zone_masquerade_nat_rules(enable, zone, "ip6", rich_rule))
            rules.extend(self._build_zone_masquerade_nat_rules(enable, zone, "ip", rich_rule))

        add_del = { True: "add", False: "delete" }[enable]
        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["FORWARD_OUT"],
                                            zone=zone)

        rule_fragment = []
        if rich_rule:
            rule_fragment += self._rich_rule_priority_fragment(rich_rule)
            rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
            rule_fragment += self._rich_rule_source_fragment(rich_rule.source)
            chain_suffix = self._rich_rule_chain_suffix(rich_rule)
        else:
            chain_suffix = "allow"

        rules.append([add_del, "rule", "inet", "%s" % TABLE_NAME,
                      "filter_%s_%s" % (target, chain_suffix)]
                      + rule_fragment + ["ct", "state", "new,untracked", "accept"])

        return rules

    def _build_zone_forward_port_nat_rules(self, enable, zone, protocol,
                                           mark_fragment, toaddr, toport,
                                           family, rich_rule=None):
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

        rich_rule_priority_fragment = []
        if rich_rule:
            rich_rule_priority_fragment += self._rich_rule_priority_fragment(rich_rule)
            chain_suffix = self._rich_rule_chain_suffix(rich_rule)
        else:
            chain_suffix = "allow"

        return [[add_del, "rule", family, "%s" % TABLE_NAME,
                "nat_%s_%s" % (target, chain_suffix)]
                + rich_rule_priority_fragment +
                ["meta", "l4proto", protocol]
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
            rule_fragment += self._rich_rule_priority_fragment(rich_rule)
            rule_fragment += self._rich_rule_family_fragment(rich_rule.family)
            rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
            rule_fragment += self._rich_rule_source_fragment(rich_rule.source)
            chain_suffix = self._rich_rule_chain_suffix(rich_rule)
        else:
            chain_suffix = "allow"

        rules = []
        rules.append([add_del, "rule", "inet", "%s" % TABLE_NAME,
                      "mangle_%s_%s" % (target, chain_suffix)]
                      + rule_fragment +
                      [protocol, "dport", port, "meta", "mark", "set", mark_str])

        if rich_rule and (rich_rule.family and rich_rule.family == "ipv6"
           or toaddr and check_single_address("ipv6", toaddr)):
            rules.extend(self._build_zone_forward_port_nat_rules(enable, zone,
                                protocol, mark_fragment, toaddr, toport, "ip6", rich_rule))
        elif rich_rule and (rich_rule.family and rich_rule.family == "ipv4"
           or toaddr and check_single_address("ipv4", toaddr)):
            rules.extend(self._build_zone_forward_port_nat_rules(enable, zone,
                                protocol, mark_fragment, toaddr, toport, "ip", rich_rule))
        else:
            if not toaddr or check_single_address("ipv6", toaddr):
                rules.extend(self._build_zone_forward_port_nat_rules(enable, zone,
                                    protocol, mark_fragment, toaddr, toport, "ip6", rich_rule))
            if not toaddr or check_single_address("ipv4", toaddr):
                rules.extend(self._build_zone_forward_port_nat_rules(enable, zone,
                                    protocol, mark_fragment, toaddr, toport, "ip", rich_rule))

        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS[filter_chain],
                                            zone=zone)
        rule_fragment = []
        if rich_rule:
            rule_fragment += self._rich_rule_priority_fragment(rich_rule)
        rules.append([add_del, "rule", "inet", "%s" % TABLE_NAME,
                      "filter_%s_%s" % (target, chain_suffix)]
                      + rule_fragment +
                      ["ct", "state", "new,untracked"]
                      + mark_fragment + ["accept"])

        return rules

    def _icmp_types_to_nft_fragment(self, ipv, icmp_type):
        if icmp_type in ICMP_TYPES_FRAGMENT[ipv]:
            return ICMP_TYPES_FRAGMENT[ipv][icmp_type]
        else:
            raise FirewallError(INVALID_ICMPTYPE,
                                "ICMP type '%s' not supported by %s" % (icmp_type, self.name))

    def build_zone_icmp_block_rules(self, enable, zone, ict, rich_rule=None):
        table = "filter"
        add_del = { True: "add", False: "delete" }[enable]

        if rich_rule and rich_rule.ipvs:
            ipvs = rich_rule.ipvs
        elif ict.destination:
            ipvs = []
            if "ipv4" in ict.destination:
                ipvs.append("ipv4")
            if "ipv6" in ict.destination:
                ipvs.append("ipv6")
        else:
            ipvs = ["ipv4", "ipv6"]

        rules = []
        for ipv in ipvs:
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
                    rule_fragment += self._rich_rule_family_fragment(rich_rule.family)
                    rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
                    rule_fragment += self._rich_rule_source_fragment(rich_rule.source)
                rule_fragment += self._icmp_types_to_nft_fragment(ipv, ict.name)

                if rich_rule:
                    rules.append(self._rich_rule_log(rich_rule, enable, table, target, rule_fragment))
                    rules.append(self._rich_rule_audit(rich_rule, enable, table, target, rule_fragment))
                    if rich_rule.action:
                        rules.append(self._rich_rule_action(zone, rich_rule, enable, table, target, rule_fragment))
                    else:
                        chain_suffix = self._rich_rule_chain_suffix(rich_rule)
                        rules.append([add_del, "rule", "inet", "%s" % TABLE_NAME,
                                      "%s_%s_%s" % (table, target, chain_suffix)]
                                      + self._rich_rule_priority_fragment(rich_rule)
                                      + rule_fragment + ["%%REJECT%%"])
                else:
                    if self._fw.get_log_denied() != "off" and final_target != "accept":
                        rules.append([add_del, "rule", "inet", "%s" % TABLE_NAME,
                                      final_chain] + rule_fragment +
                                     ["%%LOGTYPE%%", "log", "prefix",
                                      "\"%s_%s_ICMP_BLOCK: \"" % (table, zone)])
                    rules.append([add_del, "rule", "inet", "%s" % TABLE_NAME,
                                  final_chain] + rule_fragment + [final_target])

        return rules

    def build_zone_icmp_block_inversion_rules(self, enable, zone):
        table = "filter"
        rules = []
        add_del = { True: "add", False: "delete" }[enable]

        for chain in ["INPUT", "FORWARD_IN"]:
            _zone = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS[chain],
                                               zone=zone)

            if self._fw.zone.query_icmp_block_inversion(zone):
                ibi_target = "%%REJECT%%"
            else:
                ibi_target = "accept"

            # WARN: index must be kept in sync with build_zone_chain_rules()
            rules.append([add_del, "rule", "inet", "%s" % TABLE_NAME,
                          "%s_%s" % (table, _zone), "index", "4",
                          "%%ICMP%%", ibi_target])

            if self._fw.zone.query_icmp_block_inversion(zone):
                if self._fw.get_log_denied() != "off":
                    # WARN: index must be kept in sync with build_zone_chain_rules()
                    rules.append([add_del, "rule", "inet", "%s" % TABLE_NAME,
                                  "%s_%s" % (table, _zone), "index", "4",
                                  "%%ICMP%%", "%%LOGTYPE%%", "log", "prefix",
                                  "\"%s_%s_ICMP_BLOCK: \"" % (table, _zone)])

        return rules

    def build_rpfilter_rules(self, log_denied=False):
        rule_fragment = ["meta", "nfproto", "ipv6", "fib", "saddr", ".", "iif",
                         "oif", "missing"]
        if log_denied != "off":
            rule_fragment += ["log", "prefix", "\"rpfilter_DROP: \""]
        rule_fragment += ["drop"]

        rules = []
        rules.append(["insert", "rule", "inet", "%s" % TABLE_NAME,
                      "raw_%s" % "PREROUTING"] + rule_fragment)
        rules.append(["insert", "rule", "inet", "%s" % TABLE_NAME,
                      "raw_%s" % "PREROUTING",
                      "icmpv6", "type", "{ nd-router-advert, nd-neighbor-solicit }",
                      "accept"]) # RHBZ#1058505, RHBZ#1575431 (bug in kernel 4.16-4.17)
        return rules

    def build_rfc3964_ipv4_rules(self):
        daddr_set = ["{",
                     "::0.0.0.0/96,", # IPv4 compatible
                     "::ffff:0.0.0.0/96,", # IPv4 mapped
                     "2002:0000::/24,", # 0.0.0.0/8 (the system has no address assigned yet)
                     "2002:0a00::/24,", # 10.0.0.0/8 (private)
                     "2002:7f00::/24,", # 127.0.0.0/8 (loopback)
                     "2002:ac10::/28,", # 172.16.0.0/12 (private)
                     "2002:c0a8::/32,", # 192.168.0.0/16 (private)
                     "2002:a9fe::/32,", # 169.254.0.0/16 (IANA Assigned DHCP link-local)
                     "2002:e000::/19,", # 224.0.0.0/4 (multicast), 240.0.0.0/4 (reserved and broadcast)
                     "}"]

        rule_fragment = ["ip6", "daddr"] + daddr_set
        if self._fw._log_denied in ["unicast", "all"]:
            rule_fragment += ["log", "prefix", "\"RFC3964_IPv4_REJECT: \""]
        rule_fragment += ["reject"]
        rule_fragment += self._reject_types_fragment("addr-unreach")

        rules = []
        # WARN: index must be kept in sync with build_default_rules()
        rules.append(["add", "rule", "inet", "%s" % TABLE_NAME,
                      "filter_OUTPUT", "index", "0"] + rule_fragment)
        rules.append(["add", "rule", "inet", "%s" % TABLE_NAME,
                      "filter_FORWARD", "index", "1"] + rule_fragment)
        return rules

    def build_zone_rich_source_destination_rules(self, enable, zone, rich_rule):
        table = "filter"
        target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["INPUT"],
                                            zone=zone)

        rule_fragment = []
        rule_fragment += self._rich_rule_family_fragment(rich_rule.family)
        rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
        rule_fragment += self._rich_rule_source_fragment(rich_rule.source)

        rules = []
        rules.append(self._rich_rule_log(rich_rule, enable, table, target, rule_fragment))
        rules.append(self._rich_rule_audit(rich_rule, enable, table, target, rule_fragment))
        rules.append(self._rich_rule_action(zone, rich_rule, enable, table, target, rule_fragment))

        return rules

    def is_ipv_supported(self, ipv):
        if ipv in ["ipv4", "ipv6", "eb"]:
            return True
        return False

    def _set_type_fragment(self, ipv, type):
        ipv_addr = {
            "ipv4" : "ipv4_addr",
            "ipv6" : "ipv6_addr",
        }
        types = {
            "hash:ip" : [ipv_addr[ipv]],
            "hash:ip,port" : [ipv_addr[ipv], ". inet_proto", ". inet_service"],
            "hash:ip,port,ip" : [ipv_addr[ipv], ". inet_proto", ". inet_service .", ipv_addr[ipv]],
            "hash:ip,port,net" : [ipv_addr[ipv], ". inet_proto", ". inet_service .", ipv_addr[ipv]],
            "hash:ip,mark" : [ipv_addr[ipv], ". mark"],

            "hash:net" : [ipv_addr[ipv]],
            "hash:net,port" : [ipv_addr[ipv], ". inet_proto", ". inet_service"],
            "hash:net,port,ip" : [ipv_addr[ipv], ". inet_proto", ". inet_service .", ipv_addr[ipv]],
            "hash:net,port,net" : [ipv_addr[ipv], ". inet_proto", ". inet_service .", ipv_addr[ipv]],
            "hash:net,iface" : [ipv_addr[ipv], ". ifname"],

            "hash:mac" : ["ether_addr"],
        }
        try:
            return ["type"] + types[type] + [";"]
        except KeyError:
            raise FirewallError(INVALID_TYPE,
                                "ipset type name '%s' is not valid" % type)

    def set_create(self, name, type, options=None):
        if options and "family" in options and options["family"] == "inet6":
            ipv = "ipv6"
        else:
            ipv = "ipv4"

        cmd = [name, "{"]
        cmd += self._set_type_fragment(ipv, type)
        if options:
            if "timeout" in options:
                cmd += ["timeout", options["timeout"]+ "s", ";"]
            if "maxelem" in options:
                cmd += ["size", options["maxelem"], ";"]
        # flag "interval" currently does not work with timeouts or
        # concatenations. See rhbz 1576426, 1576430.
        if (not options or "timeout" not in options) \
           and "," not in type: # e.g. hash:net,port
            cmd += ["flags", "interval", ";"]
        cmd += ["}"]

        for family in ["inet", "ip", "ip6"]:
            self.__run(["add", "set", family, TABLE_NAME] + cmd)

    def set_destroy(self, name):
        for family in ["inet", "ip", "ip6"]:
            self.__run(["delete", "set", family, TABLE_NAME, name])

    def _set_entry_fragment(self, name, entry):
        # convert something like
        #    1.2.3.4,sctp:8080 (type hash:ip,port)
        # to
        #    1.2.3.4 . sctp . 8080
        type_format = self._fw.ipset.get_type(name).split(":")[1].split(",")
        entry_tokens = entry.split(",")
        if len(type_format) != len(entry_tokens):
            raise FirewallError(INVALID_ENTRY,
                                "Number of values does not match ipset type.")
        fragment = []
        for i in range(len(type_format)):
            if type_format[i] == "port":
                try:
                    index = entry_tokens[i].index(":")
                except ValueError:
                    # no protocol means default tcp
                    fragment += ["tcp", ".", entry_tokens[i]]
                else:
                    fragment += [entry_tokens[i][:index], ".", entry_tokens[i][index+1:]]
            else:
                fragment.append(entry_tokens[i])
            fragment.append(".")
        return fragment[:-1] # snip last concat operator

    def set_add(self, name, entry):
        for family in ["inet", "ip", "ip6"]:
            self.__run(["add", "element", family, TABLE_NAME, name, "{"]
                       + self._set_entry_fragment(name, entry) + ["}"])

    def set_delete(self, name, entry):
        for family in ["inet", "ip", "ip6"]:
            self.__run(["delete", "element", family, TABLE_NAME, name, "{"]
                       + self._set_entry_fragment(name, entry) + ["}"])

    def set_flush(self, name):
        for family in ["inet", "ip", "ip6"]:
            self.__run(["flush", "set", family, TABLE_NAME, name])

    def _set_get_family(self, name):
        ipset = self._fw.ipset.get_ipset(name)

        if ipset.type == "hash:mac":
            family = "ether"
        elif ipset.options and "family" in ipset.options \
             and ipset.options["family"] == "inet6":
            family = "ip6"
        else:
            family = "ip"

        return family
