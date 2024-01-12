# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2018-2023 Red Hat, Inc.
#
# Authors:
# Eric Garver <eric@garver.life>

import copy
import json
import ipaddress

from firewall.core.logger import log
from firewall.functions import (
    check_mac,
    getPortRange,
    normalizeIP6,
    check_single_address,
    check_address,
)
from firewall.errors import (
    FirewallError,
    UNKNOWN_ERROR,
    INVALID_RULE,
    INVALID_ICMPTYPE,
    INVALID_TYPE,
    INVALID_ENTRY,
    INVALID_PORT,
)
from firewall.core.rich import (
    Rich_Accept,
    Rich_Reject,
    Rich_Drop,
    Rich_Mark,
    Rich_Masquerade,
    Rich_ForwardPort,
    Rich_IcmpBlock,
    Rich_Tcp_Mss_Clamp,
    Rich_NFLog,
)
from firewall.core.base import DEFAULT_ZONE_TARGET
from nftables.nftables import Nftables

TABLE_NAME = "firewalld"
TABLE_NAME_POLICY = TABLE_NAME + "_" + "policy_drop"
POLICY_CHAIN_PREFIX = "policy_"

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
    # "security": {
    #    "INPUT": ("input", 50 + NFT_HOOK_OFFSET),
    #    "OUTPUT": ("output", 50 + NFT_HOOK_OFFSET),
    #    "FORWARD": ("forward", 50 + NFT_HOOK_OFFSET),
    # },
    "raw": {
        # "PREROUTING": ("prerouting", -300 + NFT_HOOK_OFFSET),
        # "OUTPUT": ("output", -300 + NFT_HOOK_OFFSET),
    },
    "mangle": {
        "PREROUTING": ("prerouting", -150 + NFT_HOOK_OFFSET),
        # "POSTROUTING": ("postrouting", -150 + NFT_HOOK_OFFSET),
        # "INPUT": ("input", -150 + NFT_HOOK_OFFSET),
        # "OUTPUT": ("output", -150 + NFT_HOOK_OFFSET),
        # "FORWARD": ("forward", -150 + NFT_HOOK_OFFSET),
    },
    "nat": {
        "PREROUTING": ("prerouting", -100 + NFT_HOOK_OFFSET),
        "POSTROUTING": ("postrouting", 100 + NFT_HOOK_OFFSET),
        # "INPUT": ("input", 100 + NFT_HOOK_OFFSET),
        "OUTPUT": ("output", -100 + NFT_HOOK_OFFSET),
    },
    "filter": {
        "PREROUTING": ("prerouting", 0 + NFT_HOOK_OFFSET),
        "INPUT": ("input", 0 + NFT_HOOK_OFFSET),
        "FORWARD": ("forward", 0 + NFT_HOOK_OFFSET),
        "OUTPUT": ("output", 0 + NFT_HOOK_OFFSET),
    },
}


def _icmp_types_fragments(protocol, type, code=None):
    fragments = [
        {
            "match": {
                "left": {"payload": {"protocol": protocol, "field": "type"}},
                "op": "==",
                "right": type,
            }
        }
    ]
    if code is not None:
        fragments.append(
            {
                "match": {
                    "left": {"payload": {"protocol": protocol, "field": "code"}},
                    "op": "==",
                    "right": code,
                }
            }
        )
    return fragments


# Most ICMP types are provided by nft, but for the codes we have to use numeric
# values.
#
ICMP_TYPES_FRAGMENTS = {
    "ipv4": {
        "communication-prohibited": _icmp_types_fragments(
            "icmp", "destination-unreachable", 13
        ),
        "destination-unreachable": _icmp_types_fragments(
            "icmp", "destination-unreachable"
        ),
        "echo-reply": _icmp_types_fragments("icmp", "echo-reply"),
        "echo-request": _icmp_types_fragments("icmp", "echo-request"),
        "fragmentation-needed": _icmp_types_fragments(
            "icmp", "destination-unreachable", 4
        ),
        "host-precedence-violation": _icmp_types_fragments(
            "icmp", "destination-unreachable", 14
        ),
        "host-prohibited": _icmp_types_fragments("icmp", "destination-unreachable", 10),
        "host-redirect": _icmp_types_fragments("icmp", "redirect", 1),
        "host-unknown": _icmp_types_fragments("icmp", "destination-unreachable", 7),
        "host-unreachable": _icmp_types_fragments("icmp", "destination-unreachable", 1),
        "ip-header-bad": _icmp_types_fragments("icmp", "parameter-problem", 1),
        "network-prohibited": _icmp_types_fragments(
            "icmp", "destination-unreachable", 8
        ),
        "network-redirect": _icmp_types_fragments("icmp", "redirect", 0),
        "network-unknown": _icmp_types_fragments("icmp", "destination-unreachable", 6),
        "network-unreachable": _icmp_types_fragments(
            "icmp", "destination-unreachable", 0
        ),
        "parameter-problem": _icmp_types_fragments("icmp", "parameter-problem"),
        "port-unreachable": _icmp_types_fragments("icmp", "destination-unreachable", 3),
        "precedence-cutoff": _icmp_types_fragments(
            "icmp", "destination-unreachable", 15
        ),
        "protocol-unreachable": _icmp_types_fragments(
            "icmp", "destination-unreachable", 2
        ),
        "redirect": _icmp_types_fragments("icmp", "redirect"),
        "required-option-missing": _icmp_types_fragments(
            "icmp", "parameter-problem", 1
        ),
        "router-advertisement": _icmp_types_fragments("icmp", "router-advertisement"),
        "router-solicitation": _icmp_types_fragments("icmp", "router-solicitation"),
        "source-quench": _icmp_types_fragments("icmp", "source-quench"),
        "source-route-failed": _icmp_types_fragments(
            "icmp", "destination-unreachable", 5
        ),
        "time-exceeded": _icmp_types_fragments("icmp", "time-exceeded"),
        "timestamp-reply": _icmp_types_fragments("icmp", "timestamp-reply"),
        "timestamp-request": _icmp_types_fragments("icmp", "timestamp-request"),
        "tos-host-redirect": _icmp_types_fragments("icmp", "redirect", 3),
        "tos-host-unreachable": _icmp_types_fragments(
            "icmp", "destination-unreachable", 12
        ),
        "tos-network-redirect": _icmp_types_fragments("icmp", "redirect", 2),
        "tos-network-unreachable": _icmp_types_fragments(
            "icmp", "destination-unreachable", 11
        ),
        "ttl-zero-during-reassembly": _icmp_types_fragments("icmp", "time-exceeded", 1),
        "ttl-zero-during-transit": _icmp_types_fragments("icmp", "time-exceeded", 0),
    },
    "ipv6": {
        "address-unreachable": _icmp_types_fragments(
            "icmpv6", "destination-unreachable", 3
        ),
        "bad-header": _icmp_types_fragments("icmpv6", "parameter-problem", 0),
        "beyond-scope": _icmp_types_fragments("icmpv6", "destination-unreachable", 2),
        "communication-prohibited": _icmp_types_fragments(
            "icmpv6", "destination-unreachable", 1
        ),
        "destination-unreachable": _icmp_types_fragments(
            "icmpv6", "destination-unreachable"
        ),
        "echo-reply": _icmp_types_fragments("icmpv6", "echo-reply"),
        "echo-request": _icmp_types_fragments("icmpv6", "echo-request"),
        "failed-policy": _icmp_types_fragments("icmpv6", "destination-unreachable", 5),
        "mld-listener-done": _icmp_types_fragments("icmpv6", "mld-listener-done"),
        "mld-listener-query": _icmp_types_fragments("icmpv6", "mld-listener-query"),
        "mld-listener-report": _icmp_types_fragments("icmpv6", "mld-listener-report"),
        "mld2-listener-report": _icmp_types_fragments("icmpv6", "mld2-listener-report"),
        "neighbour-advertisement": _icmp_types_fragments(
            "icmpv6", "nd-neighbor-advert"
        ),
        "neighbour-solicitation": _icmp_types_fragments(
            "icmpv6", "nd-neighbor-solicit"
        ),
        "no-route": _icmp_types_fragments("icmpv6", "destination-unreachable", 0),
        "packet-too-big": _icmp_types_fragments("icmpv6", "packet-too-big"),
        "parameter-problem": _icmp_types_fragments("icmpv6", "parameter-problem"),
        "port-unreachable": _icmp_types_fragments(
            "icmpv6", "destination-unreachable", 4
        ),
        "redirect": _icmp_types_fragments("icmpv6", "nd-redirect"),
        "reject-route": _icmp_types_fragments("icmpv6", "destination-unreachable", 6),
        "router-advertisement": _icmp_types_fragments("icmpv6", "nd-router-advert"),
        "router-solicitation": _icmp_types_fragments("icmpv6", "nd-router-solicit"),
        "time-exceeded": _icmp_types_fragments("icmpv6", "time-exceeded"),
        "ttl-zero-during-reassembly": _icmp_types_fragments(
            "icmpv6", "time-exceeded", 1
        ),
        "ttl-zero-during-transit": _icmp_types_fragments("icmpv6", "time-exceeded", 0),
        "unknown-header-type": _icmp_types_fragments("icmpv6", "parameter-problem", 1),
        "unknown-option": _icmp_types_fragments("icmpv6", "parameter-problem", 2),
    },
}


class nftables:
    name = "nftables"
    policies_supported = True

    def __init__(self, fw):
        self._fw = fw
        self.restore_command_exists = True
        self.available_tables = []
        self.rule_to_handle = {}
        self.rule_ref_count = {}
        self.rich_rule_priority_counts = {}
        self.policy_dispatch_index_cache = {}

        self.nftables = Nftables()
        self.nftables.set_echo_output(True)
        self.nftables.set_handle_output(True)

    def _set_rule_sort_policy_dispatch(self, rule, policy_dispatch_index_cache):
        for verb in ["add", "insert", "delete"]:
            if verb in rule:
                break

        try:
            sort_tuple = rule[verb]["rule"].pop("%%POLICY_SORT_KEY%%")
        except KeyError:
            return

        chain = (rule[verb]["rule"]["family"], rule[verb]["rule"]["chain"])

        if verb == "delete":
            if (
                chain in policy_dispatch_index_cache
                and sort_tuple in policy_dispatch_index_cache[chain]
            ):
                policy_dispatch_index_cache[chain].remove(sort_tuple)
        else:
            if chain not in policy_dispatch_index_cache:
                policy_dispatch_index_cache[chain] = []

            # We only have to track the sort key as it's unique. The actual
            # rule/json is not necessary.
            #
            # We only insert the tuple if it's not present. This is because we
            # do rule de-duplication in set_rules().
            if sort_tuple not in policy_dispatch_index_cache[chain]:
                policy_dispatch_index_cache[chain].append(sort_tuple)
                policy_dispatch_index_cache[chain].sort()

            index = policy_dispatch_index_cache[chain].index(sort_tuple)

            _verb_snippet = rule[verb]
            del rule[verb]
            if index == 0:
                rule["insert"] = _verb_snippet
            else:
                index -= 1  # point to the rule before insertion point
                rule["add"] = _verb_snippet
                rule["add"]["rule"]["index"] = index

    def _set_rule_replace_priority(self, rule, priority_counts, token):
        for verb in ["add", "insert", "delete"]:
            if verb in rule:
                break

        if token in rule[verb]["rule"]:
            priority = rule[verb]["rule"][token]
            del rule[verb]["rule"][token]
            if not isinstance(priority, int):
                raise FirewallError(
                    INVALID_RULE, "priority must be followed by a number"
                )
            chain = (
                rule[verb]["rule"]["family"],
                rule[verb]["rule"]["chain"],
            )  # family, chain
            # Add the rule to the priority counts. We don't need to store the
            # rule, just bump the ref count for the priority value.
            if verb == "delete":
                if (
                    chain not in priority_counts
                    or priority not in priority_counts[chain]
                    or priority_counts[chain][priority] <= 0
                ):
                    raise FirewallError(
                        UNKNOWN_ERROR, "nonexistent or underflow of priority count"
                    )

                priority_counts[chain][priority] -= 1
            else:
                if chain not in priority_counts:
                    priority_counts[chain] = {}
                if priority not in priority_counts[chain]:
                    priority_counts[chain][priority] = 0

                # calculate index of new rule
                index = 0
                for p in sorted(priority_counts[chain].keys()):
                    if p == priority and verb == "insert":
                        break
                    index += priority_counts[chain][p]
                    if p == priority and verb == "add":
                        break

                priority_counts[chain][priority] += 1

                _verb_snippet = rule[verb]
                del rule[verb]
                if index == 0:
                    rule["insert"] = _verb_snippet
                else:
                    index -= 1  # point to the rule before insertion point
                    rule["add"] = _verb_snippet
                    rule["add"]["rule"]["index"] = index

    def _get_rule_key(self, rule):
        for verb in ["add", "insert", "delete"]:
            if verb in rule and "rule" in rule[verb]:
                # str(rule_key) is insufficient because dictionary order is
                # not stable.. so abuse the JSON library
                rule_key = json.dumps(rule[verb]["rule"], sort_keys=True)
                return rule_key
        # Not a rule (it's a table, chain, etc)
        return None

    def set_rules(self, rules, log_denied):
        _valid_verbs = ["add", "insert", "delete", "flush", "replace"]
        _valid_add_verbs = ["add", "insert", "replace"]
        _deduplicated_rules = []
        _deduplicated_rules_keys = []
        _executed_rules = []
        rich_rule_priority_counts = copy.deepcopy(self.rich_rule_priority_counts)
        policy_dispatch_index_cache = copy.deepcopy(self.policy_dispatch_index_cache)
        rule_ref_count = self.rule_ref_count.copy()
        for rule in rules:
            if not isinstance(rule, dict):
                raise FirewallError(
                    UNKNOWN_ERROR, "rule must be a dictionary, rule: %s" % (rule)
                )

            for verb in _valid_verbs:
                if verb in rule:
                    break
            if verb not in rule:
                raise FirewallError(
                    INVALID_RULE, "no valid verb found, rule: %s" % (rule)
                )

            rule_key = self._get_rule_key(rule)

            # rule deduplication
            if rule_key in rule_ref_count:
                log.debug2(
                    "%s: prev rule ref cnt %d, verb %s %s",
                    self.__class__,
                    rule_ref_count[rule_key],
                    verb,
                    rule_key,
                )
                if verb != "delete":
                    rule_ref_count[rule_key] += 1
                    continue
                elif rule_ref_count[rule_key] > 1:
                    rule_ref_count[rule_key] -= 1
                    continue
                elif rule_ref_count[rule_key] == 1:
                    rule_ref_count[rule_key] -= 1
                else:
                    raise FirewallError(
                        UNKNOWN_ERROR,
                        "rule ref count bug: rule_key '%s', cnt %d"
                        % (rule_key, rule_ref_count[rule_key]),
                    )
            elif rule_key and verb != "delete":
                rule_ref_count[rule_key] = 1
                log.debug2(
                    "%s: new rule ref cnt %d, verb %s %s",
                    self.__class__,
                    rule_ref_count[rule_key],
                    verb,
                    rule_key,
                )
            elif rule_key:
                raise FirewallError(
                    UNKNOWN_ERROR,
                    f"rule ref count bug, missing ref count: rule_key '{rule_key}'",
                )

            _deduplicated_rules.append(rule)
            _deduplicated_rules_keys.append(rule_key)

            if rule_key:
                # filter empty rule expressions. Rich rules add quite a bit of
                # them, but it makes the rest of the code simpler. libnftables
                # does not tolerate them.
                rule[verb]["rule"]["expr"] = list(
                    filter(None, rule[verb]["rule"]["expr"])
                )

                if self._fw._nftables_counters:
                    # -1 inserts just before the verdict
                    rule[verb]["rule"]["expr"].insert(-1, {"counter": None})

                self._set_rule_replace_priority(
                    rule, rich_rule_priority_counts, "%%RICH_RULE_PRIORITY%%"
                )
                self._set_rule_sort_policy_dispatch(rule, policy_dispatch_index_cache)

                # delete using rule handle
                if verb == "delete":
                    rule = {
                        "delete": {
                            "rule": {
                                "family": rule["delete"]["rule"]["family"],
                                "table": rule["delete"]["rule"]["table"],
                                "chain": rule["delete"]["rule"]["chain"],
                                "handle": self.rule_to_handle[rule_key],
                            }
                        }
                    }

            _executed_rules.append(rule)

        json_blob = {
            "nftables": [{"metainfo": {"json_schema_version": 1}}] + _executed_rules
        }
        if log.getDebugLogLevel() >= 3:
            # guarded with if statement because json.dumps() is expensive.
            log.debug3(
                "%s: calling python-nftables with JSON blob: %s",
                self.__class__,
                json.dumps(json_blob),
            )
        rc, output, error = self.nftables.json_cmd(json_blob)
        if rc != 0:
            raise ValueError(
                "'%s' failed: %s\nJSON blob:\n%s"
                % ("python-nftables", error, json.dumps(json_blob))
            )

        self.rich_rule_priority_counts = rich_rule_priority_counts
        self.policy_dispatch_index_cache = policy_dispatch_index_cache
        self.rule_ref_count = rule_ref_count

        index = 0
        for rule in _deduplicated_rules:
            rule_key = _deduplicated_rules_keys[index]
            index += 1  # +1 due to metainfo

            if not rule_key:
                continue

            if "delete" in rule and self.rule_ref_count[rule_key] <= 0:
                del self.rule_to_handle[rule_key]
                del self.rule_ref_count[rule_key]
                continue

            for verb in _valid_add_verbs:
                if verb in output["nftables"][index]:
                    break
            else:
                continue

            # don't bother tracking handles for the policy table as we simply
            # delete the entire table.
            if TABLE_NAME_POLICY == output["nftables"][index][verb]["rule"]["table"]:
                continue

            self.rule_to_handle[rule_key] = output["nftables"][index][verb]["rule"][
                "handle"
            ]

    def set_rule(self, rule, log_denied):
        self.set_rules([rule], log_denied)
        return ""

    def get_available_tables(self, table=None):
        # Tables always exist in nftables
        return [table] if table else IPTABLES_TO_NFT_HOOK.keys()

    def _build_delete_table_rules(self, table):
        # To avoid nftables returning ENOENT we always add the table before
        # deleting to guarantee it will exist.
        #
        # In the future, this add+delete should be replaced with "destroy", but
        # that verb is too new to rely upon.
        return [
            {"add": {"table": {"family": "inet", "name": table}}},
            {"delete": {"table": {"family": "inet", "name": table}}},
        ]

    def build_flush_rules(self):
        self.rule_to_handle = {}
        self.rule_ref_count = {}
        self.rich_rule_priority_counts = {}
        self.policy_dispatch_index_cache = {}

        return self._build_delete_table_rules(TABLE_NAME)

    def _build_set_policy_rules_ct_rule(self, enable, hook):
        add_del = {True: "add", False: "delete"}[enable]
        return {
            add_del: {
                "rule": {
                    "family": "inet",
                    "table": TABLE_NAME_POLICY,
                    "chain": "%s_%s" % ("filter", hook),
                    "expr": [
                        {
                            "match": {
                                "left": {"ct": {"key": "state"}},
                                "op": "in",
                                "right": {"set": ["established", "related"]},
                            }
                        },
                        {"accept": None},
                    ],
                }
            }
        }

    def build_set_policy_rules(self, policy, policy_details):
        # Policy is not exposed to the user. It's only to make sure we DROP
        # packets while reloading and for panic mode. As such, using hooks with
        # a higher priority than our base chains is sufficient.
        rules = []
        if policy == "PANIC":
            rules.append(
                {"add": {"table": {"family": "inet", "name": TABLE_NAME_POLICY}}}
            )

            # Use "raw" priority for panic mode. This occurs before
            # conntrack, mangle, nat, etc
            for hook in ["prerouting", "output"]:
                rules.append(
                    {
                        "add": {
                            "chain": {
                                "family": "inet",
                                "table": TABLE_NAME_POLICY,
                                "name": "%s_%s" % ("raw", hook),
                                "type": "filter",
                                "hook": hook,
                                "prio": -300 + NFT_HOOK_OFFSET - 1,
                                "policy": "drop",
                            }
                        }
                    }
                )
        elif policy == "DROP":
            rules.append(
                {"add": {"table": {"family": "inet", "name": TABLE_NAME_POLICY}}}
            )

            # To drop everything except existing connections we use
            # "filter" because it occurs _after_ conntrack.
            for hook in ("INPUT", "FORWARD", "OUTPUT"):
                d_policy = policy_details[hook]
                assert d_policy in ("ACCEPT", "REJECT", "DROP")
                hook = hook.lower()
                chain_name = f"filter_{hook}"

                rules.append(
                    {
                        "add": {
                            "chain": {
                                "family": "inet",
                                "table": TABLE_NAME_POLICY,
                                "name": chain_name,
                                "type": "filter",
                                "hook": hook,
                                "prio": 0 + NFT_HOOK_OFFSET - 1,
                                "policy": "drop",
                            }
                        }
                    }
                )

                rules.append(self._build_set_policy_rules_ct_rule(True, hook))

                if d_policy == "ACCEPT":
                    expr_fragment = {"accept": None}
                elif d_policy == "DROP":
                    expr_fragment = {"drop": None}
                else:
                    expr_fragment = {
                        "reject": {"type": "icmpx", "expr": "admin-prohibited"}
                    }

                rules.append(
                    {
                        "add": {
                            "rule": {
                                "family": "inet",
                                "table": TABLE_NAME_POLICY,
                                "chain": chain_name,
                                "expr": [expr_fragment],
                            }
                        }
                    }
                )
        elif policy == "ACCEPT":
            rules += self._build_delete_table_rules(TABLE_NAME_POLICY)
        else:
            raise FirewallError(UNKNOWN_ERROR, "not implemented")

        return rules

    def supported_icmp_types(self, ipv=None):
        # nftables supports any icmp_type via arbitrary type/code matching.
        # We just need a translation for it in ICMP_TYPES_FRAGMENTS.
        supported = set()

        for _ipv in [ipv] if ipv else ICMP_TYPES_FRAGMENTS.keys():
            supported.update(ICMP_TYPES_FRAGMENTS[_ipv].keys())

        return list(supported)

    def build_default_tables(self):
        default_tables = []
        default_tables.append(
            {"add": {"table": {"family": "inet", "name": TABLE_NAME}}}
        )
        return default_tables

    def build_default_rules(self, log_denied="off"):
        default_rules = []
        for chain in IPTABLES_TO_NFT_HOOK["mangle"].keys():
            default_rules.append(
                {
                    "add": {
                        "chain": {
                            "family": "inet",
                            "table": TABLE_NAME,
                            "name": "mangle_%s" % chain,
                            "type": "filter",
                            "hook": "%s" % IPTABLES_TO_NFT_HOOK["mangle"][chain][0],
                            "prio": IPTABLES_TO_NFT_HOOK["mangle"][chain][1],
                        }
                    }
                }
            )
            default_rules.append(
                {
                    "add": {
                        "chain": {
                            "family": "inet",
                            "table": TABLE_NAME,
                            "name": "mangle_%s_POLICIES" % (chain),
                        }
                    }
                }
            )
            default_rules.append(
                {
                    "add": {
                        "rule": {
                            "family": "inet",
                            "table": TABLE_NAME,
                            "chain": "mangle_%s" % chain,
                            "expr": [
                                {"jump": {"target": "mangle_%s_POLICIES" % (chain)}}
                            ],
                        }
                    }
                }
            )

        for chain in IPTABLES_TO_NFT_HOOK["nat"].keys():
            default_rules.append(
                {
                    "add": {
                        "chain": {
                            "family": "inet",
                            "table": TABLE_NAME,
                            "name": "nat_%s" % chain,
                            "type": "nat",
                            "hook": "%s" % IPTABLES_TO_NFT_HOOK["nat"][chain][0],
                            "prio": IPTABLES_TO_NFT_HOOK["nat"][chain][1],
                        }
                    }
                }
            )

            default_rules.append(
                {
                    "add": {
                        "chain": {
                            "family": "inet",
                            "table": TABLE_NAME,
                            "name": "nat_%s_POLICIES" % (chain),
                        }
                    }
                }
            )
            default_rules.append(
                {
                    "add": {
                        "rule": {
                            "family": "inet",
                            "table": TABLE_NAME,
                            "chain": "nat_%s" % chain,
                            "expr": [{"jump": {"target": "nat_%s_POLICIES" % (chain)}}],
                        }
                    }
                }
            )

        for chain in IPTABLES_TO_NFT_HOOK["filter"].keys():
            default_rules.append(
                {
                    "add": {
                        "chain": {
                            "family": "inet",
                            "table": TABLE_NAME,
                            "name": "filter_%s" % chain,
                            "type": "filter",
                            "hook": "%s" % IPTABLES_TO_NFT_HOOK["filter"][chain][0],
                            "prio": IPTABLES_TO_NFT_HOOK["filter"][chain][1],
                        }
                    }
                }
            )

        # filter, INPUT
        default_rules.append(
            {
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": TABLE_NAME,
                        "chain": "filter_%s" % "INPUT",
                        "expr": [
                            {
                                "match": {
                                    "left": {"ct": {"key": "state"}},
                                    "op": "in",
                                    "right": {"set": ["established", "related"]},
                                }
                            },
                            {"accept": None},
                        ],
                    }
                }
            }
        )
        default_rules.append(
            {
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": TABLE_NAME,
                        "chain": "filter_%s" % "INPUT",
                        "expr": [
                            {
                                "match": {
                                    "left": {"ct": {"key": "status"}},
                                    "op": "in",
                                    "right": "dnat",
                                }
                            },
                            {"accept": None},
                        ],
                    }
                }
            }
        )
        default_rules.append(
            {
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": TABLE_NAME,
                        "chain": "filter_%s" % "INPUT",
                        "expr": [
                            {
                                "match": {
                                    "left": {"meta": {"key": "iifname"}},
                                    "op": "==",
                                    "right": "lo",
                                }
                            },
                            {"accept": None},
                        ],
                    }
                }
            }
        )
        if log_denied != "off":
            default_rules.append(
                {
                    "add": {
                        "rule": {
                            "family": "inet",
                            "table": TABLE_NAME,
                            "chain": "filter_%s" % "INPUT",
                            "expr": [
                                {
                                    "match": {
                                        "left": {"ct": {"key": "state"}},
                                        "op": "in",
                                        "right": {"set": ["invalid"]},
                                    }
                                },
                                self._pkttype_match_fragment(log_denied),
                                {"log": {"prefix": "STATE_INVALID_DROP: "}},
                            ],
                        }
                    }
                }
            )
        default_rules.append(
            {
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": TABLE_NAME,
                        "chain": "filter_%s" % "INPUT",
                        "expr": [
                            {
                                "match": {
                                    "left": {"ct": {"key": "state"}},
                                    "op": "in",
                                    "right": {"set": ["invalid"]},
                                }
                            },
                            {"drop": None},
                        ],
                    }
                }
            }
        )
        default_rules.append(
            {
                "add": {
                    "chain": {
                        "family": "inet",
                        "table": TABLE_NAME,
                        "name": "filter_INPUT_POLICIES",
                    }
                }
            }
        )
        default_rules.append(
            {
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": TABLE_NAME,
                        "chain": "filter_%s" % "INPUT",
                        "expr": [{"jump": {"target": "filter_INPUT_POLICIES"}}],
                    }
                }
            }
        )
        if log_denied != "off":
            default_rules.append(
                {
                    "add": {
                        "rule": {
                            "family": "inet",
                            "table": TABLE_NAME,
                            "chain": "filter_%s" % "INPUT",
                            "expr": [
                                self._pkttype_match_fragment(log_denied),
                                {"log": {"prefix": "FINAL_REJECT: "}},
                            ],
                        }
                    }
                }
            )
        default_rules.append(
            {
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": TABLE_NAME,
                        "chain": "filter_%s" % "INPUT",
                        "expr": [
                            {"reject": {"type": "icmpx", "expr": "admin-prohibited"}}
                        ],
                    }
                }
            }
        )

        # filter, FORWARD
        if self._fw._nftables_flowtable != "off":
            default_rules.append(
                {
                    "add": {
                        "flowtable": {
                            "family": "inet",
                            "table": TABLE_NAME,
                            "name": "fastpath",
                            "hook": "ingress",
                            "prio": NFT_HOOK_OFFSET,
                            "dev": self._fw._nftables_flowtable.split(),
                        }
                    }
                }
            )
            default_rules.append(
                {
                    "add": {
                        "rule": {
                            "family": "inet",
                            "table": TABLE_NAME,
                            "chain": "filter_%s" % "FORWARD",
                            "expr": [
                                {
                                    "match": {
                                        "left": {"ct": {"key": "state"}},
                                        "op": "in",
                                        "right": {"set": ["established", "related"]},
                                    }
                                },
                                {
                                    "match": {
                                        "left": {"meta": {"key": "l4proto"}},
                                        "op": "==",
                                        "right": {"set": ["tcp", "udp"]},
                                    }
                                },
                                {"flow": {"op": "add", "flowtable": "@fastpath"}},
                            ],
                        }
                    }
                }
            )
        default_rules.append(
            {
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": TABLE_NAME,
                        "chain": "filter_%s" % "FORWARD",
                        "expr": [
                            {
                                "match": {
                                    "left": {"ct": {"key": "state"}},
                                    "op": "in",
                                    "right": {"set": ["established", "related"]},
                                }
                            },
                            {"accept": None},
                        ],
                    }
                }
            }
        )
        default_rules.append(
            {
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": TABLE_NAME,
                        "chain": "filter_%s" % "FORWARD",
                        "expr": [
                            {
                                "match": {
                                    "left": {"ct": {"key": "status"}},
                                    "op": "in",
                                    "right": "dnat",
                                }
                            },
                            {"accept": None},
                        ],
                    }
                }
            }
        )
        default_rules.append(
            {
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": TABLE_NAME,
                        "chain": "filter_%s" % "FORWARD",
                        "expr": [
                            {
                                "match": {
                                    "left": {"meta": {"key": "iifname"}},
                                    "op": "==",
                                    "right": "lo",
                                }
                            },
                            {"accept": None},
                        ],
                    }
                }
            }
        )
        if log_denied != "off":
            default_rules.append(
                {
                    "add": {
                        "rule": {
                            "family": "inet",
                            "table": TABLE_NAME,
                            "chain": "filter_%s" % "FORWARD",
                            "expr": [
                                {
                                    "match": {
                                        "left": {"ct": {"key": "state"}},
                                        "op": "in",
                                        "right": {"set": ["invalid"]},
                                    }
                                },
                                self._pkttype_match_fragment(log_denied),
                                {"log": {"prefix": "STATE_INVALID_DROP: "}},
                            ],
                        }
                    }
                }
            )
        default_rules.append(
            {
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": TABLE_NAME,
                        "chain": "filter_%s" % "FORWARD",
                        "expr": [
                            {
                                "match": {
                                    "left": {"ct": {"key": "state"}},
                                    "op": "in",
                                    "right": {"set": ["invalid"]},
                                }
                            },
                            {"drop": None},
                        ],
                    }
                }
            }
        )
        default_rules.append(
            {
                "add": {
                    "chain": {
                        "family": "inet",
                        "table": TABLE_NAME,
                        "name": "filter_FORWARD_POLICIES",
                    }
                }
            }
        )
        default_rules.append(
            {
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": TABLE_NAME,
                        "chain": "filter_FORWARD",
                        "expr": [{"jump": {"target": "filter_FORWARD_POLICIES"}}],
                    }
                }
            }
        )
        if log_denied != "off":
            default_rules.append(
                {
                    "add": {
                        "rule": {
                            "family": "inet",
                            "table": TABLE_NAME,
                            "chain": "filter_%s" % "FORWARD",
                            "expr": [
                                self._pkttype_match_fragment(log_denied),
                                {"log": {"prefix": "FINAL_REJECT: "}},
                            ],
                        }
                    }
                }
            )
        default_rules.append(
            {
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": TABLE_NAME,
                        "chain": "filter_%s" % "FORWARD",
                        "expr": [
                            {"reject": {"type": "icmpx", "expr": "admin-prohibited"}}
                        ],
                    }
                }
            }
        )

        # filter, OUTPUT
        default_rules.append(
            {
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": TABLE_NAME,
                        "chain": "filter_%s" % "OUTPUT",
                        "expr": [
                            {
                                "match": {
                                    "left": {"ct": {"key": "state"}},
                                    "op": "in",
                                    "right": {"set": ["established", "related"]},
                                }
                            },
                            {"accept": None},
                        ],
                    }
                }
            }
        )
        default_rules.append(
            {
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": TABLE_NAME,
                        "chain": "filter_OUTPUT",
                        "expr": [
                            {
                                "match": {
                                    "left": {"meta": {"key": "oifname"}},
                                    "op": "==",
                                    "right": "lo",
                                }
                            },
                            {"accept": None},
                        ],
                    }
                }
            }
        )
        default_rules.append(
            {
                "add": {
                    "chain": {
                        "family": "inet",
                        "table": TABLE_NAME,
                        "name": "filter_OUTPUT_POLICIES",
                    }
                }
            }
        )
        default_rules.append(
            {
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": TABLE_NAME,
                        "chain": "filter_OUTPUT",
                        "expr": [{"jump": {"target": "filter_OUTPUT_POLICIES"}}],
                    }
                }
            }
        )

        return default_rules

    def get_zone_table_chains(self, table):
        if table == "filter":
            return ["INPUT", "FORWARD"]
        if table == "mangle":
            return ["PREROUTING"]
        if table == "nat":
            return ["PREROUTING", "POSTROUTING"]

        return []

    def _policy_dispatch_sort_key(
        self,
        policy,
        ingress_zone,
        egress_zone,
        ingress_interface,
        ingress_source,
        egress_interface,
        egress_source,
        priority,
        last=False,
        prerouting=False,
        postrouting=False,
        log_denied=False,
    ):
        p_obj = self._fw.policy.get_policy(policy)
        ingress_priority = (
            0
            if ingress_zone == "HOST"
            else self._fw.zone.get_zone(ingress_zone).ingress_priority
        )
        egress_priority = (
            0
            if egress_zone == "HOST"
            else self._fw.zone.get_zone(egress_zone).egress_priority
        )

        ingress_sort_order = 0  # 0 means output chain
        if ingress_source:
            ingress_sort_order = 1
        elif ingress_interface:
            ingress_sort_order = 2

        egress_sort_order = 0  # 0 means input chain
        if egress_source:
            egress_sort_order = 1
        elif egress_interface or (p_obj.derived_from_zone and prerouting):
            egress_sort_order = 2
            if prerouting:
                egress_zone = ""
                egress_interface = ""

        # default zone is always sorted to last as it's a "catch-all"
        if ingress_interface == "*":
            ingress_priority = self._fw.zone.get_zone(ingress_zone).priority_max + 1
        if egress_interface == "*":
            egress_priority = self._fw.zone.get_zone(egress_zone).priority_max + 1

        last_sort_order = 0
        if last:
            if log_denied:
                last_sort_order = 1
            else:
                last_sort_order = 2

        ingress = (
            ingress_priority,
            ingress_sort_order,
            ingress_zone,
            ingress_source,
            ingress_interface,
        )
        egress = (
            egress_priority,
            egress_sort_order,
            egress_zone,
            egress_source,
            egress_interface,
        )
        suffix = (last_sort_order, priority)

        if postrouting:
            return {"%%POLICY_SORT_KEY%%": egress + ingress + suffix}
        else:
            return {"%%POLICY_SORT_KEY%%": ingress + egress + suffix}

    def build_policy_ingress_egress_pair_rules(
        self,
        enable,
        policy,
        table,
        chain,
        ingress_zone,
        egress_zone,
        ingress_interface,
        ingress_source,
        egress_interface,
        egress_source,
        last=False,
    ):
        add_del = {True: "add", False: "delete"}[enable]
        p_obj = self._fw.policy.get_policy(policy)
        isSNAT = True if (table == "nat" and chain == "POSTROUTING") else False
        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX, isSNAT
        )
        prerouting = True if chain == "PREROUTING" else False
        postrouting = True if chain == "POSTROUTING" else False

        if ingress_interface and ingress_interface[len(ingress_interface) - 1] == "+":
            ingress_interface = ingress_interface[: len(ingress_interface) - 1] + "*"
        if egress_interface and egress_interface[len(egress_interface) - 1] == "+":
            egress_interface = egress_interface[: len(egress_interface) - 1] + "*"

        rules = []
        expr_fragments = []
        if ingress_interface and ingress_interface != "*":
            expr_fragments.append(
                {
                    "match": {
                        "left": {"meta": {"key": "iifname"}},
                        "op": "==",
                        "right": ingress_interface,
                    }
                }
            )
        if egress_interface and egress_interface != "*" and not prerouting:
            expr_fragments.append(
                {
                    "match": {
                        "left": {"meta": {"key": "oifname"}},
                        "op": "==",
                        "right": egress_interface,
                    }
                }
            )
        if ingress_source:
            expr_fragments.append(self._rule_addr_fragment("saddr", ingress_source))
        if egress_source:
            expr_fragments.append(self._rule_addr_fragment("daddr", egress_source))

        if not last:
            expr_fragments.append({"jump": {"target": "%s_%s" % (table, _policy)}})
        elif table != "filter" or chain in ["PREROUTING", "OUTPUT"]:
            expr_fragments.append({"return": None})
        elif p_obj.target in [
            DEFAULT_ZONE_TARGET,
            "ACCEPT",
            "REJECT",
            "%%REJECT%%",
            "DROP",
        ]:
            # The "last" rule for filter tables implements the zone's
            # --set-target instead of simply returning.
            #
            if self._fw.get_log_denied() != "off" and p_obj.target in [
                DEFAULT_ZONE_TARGET,
                "%%REJECT%%",
                "REJECT",
                "DROP",
            ]:
                _log_suffix = "DROP" if p_obj.target == "DROP" else "REJECT"

                rule = {
                    "family": "inet",
                    "table": TABLE_NAME,
                    "chain": "%s_%s_POLICIES" % (table, chain),
                    "expr": expr_fragments
                    + [
                        self._pkttype_match_fragment(self._fw.get_log_denied()),
                        {"log": {"prefix": "filter_%s_%s: " % (_policy, _log_suffix)}},
                    ],
                }
                rule.update(
                    self._policy_dispatch_sort_key(
                        policy,
                        ingress_zone,
                        egress_zone,
                        ingress_interface,
                        ingress_source,
                        egress_interface,
                        egress_source,
                        p_obj.priority,
                        last=True,
                        log_denied=True,
                        postrouting=postrouting,
                        prerouting=prerouting,
                    )
                )
                rules.append({add_del: {"rule": rule}})

            if p_obj.target in [DEFAULT_ZONE_TARGET, "%%REJECT%%", "REJECT"]:
                expr_fragments.append(self._reject_fragment())
            else:
                expr_fragments.append({p_obj.target.lower(): None})

        rule = {
            "family": "inet",
            "table": TABLE_NAME,
            "chain": "%s_%s_POLICIES" % (table, chain),
            "expr": expr_fragments,
        }
        rule.update(
            self._policy_dispatch_sort_key(
                policy,
                ingress_zone,
                egress_zone,
                ingress_interface,
                ingress_source,
                egress_interface,
                egress_source,
                p_obj.priority,
                last=last,
                postrouting=postrouting,
                prerouting=prerouting,
            )
        )

        rules.append({add_del: {"rule": rule}})

        return rules

    def build_policy_chain_rules(self, enable, policy, table, chain):
        add_del = {True: "add", False: "delete"}[enable]
        isSNAT = True if (table == "nat" and chain == "POSTROUTING") else False
        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX, isSNAT=isSNAT
        )
        p_obj = self._fw.policy.get_policy(policy)

        rules = []
        rules.append(
            {
                add_del: {
                    "chain": {
                        "family": "inet",
                        "table": TABLE_NAME,
                        "name": "%s_%s" % (table, _policy),
                    }
                }
            }
        )
        for chain_suffix in ["pre", "log", "deny", "allow", "post"]:
            rules.append(
                {
                    add_del: {
                        "chain": {
                            "family": "inet",
                            "table": TABLE_NAME,
                            "name": "%s_%s_%s" % (table, _policy, chain_suffix),
                        }
                    }
                }
            )
            rules.append(
                {
                    add_del: {
                        "rule": {
                            "family": "inet",
                            "table": TABLE_NAME,
                            "chain": "%s_%s" % (table, _policy),
                            "expr": [
                                {
                                    "jump": {
                                        "target": "%s_%s_%s"
                                        % (table, _policy, chain_suffix)
                                    }
                                }
                            ],
                        }
                    }
                }
            )

        # real policies have their --set-target inside the policy's chain
        if not p_obj.derived_from_zone and table == "filter":
            target = self._fw.policy._policies[policy].target

            if self._fw.get_log_denied() != "off":
                if target in ["REJECT", "%%REJECT%%", "DROP"]:
                    log_suffix = "REJECT" if target == "%%REJECT%%" else target
                    rules.append(
                        {
                            add_del: {
                                "rule": {
                                    "family": "inet",
                                    "table": TABLE_NAME,
                                    "chain": "%s_%s" % (table, _policy),
                                    "expr": [
                                        self._pkttype_match_fragment(
                                            self._fw.get_log_denied()
                                        ),
                                        {
                                            "log": {
                                                "prefix": "filter_%s_%s: "
                                                % (_policy, log_suffix)
                                            }
                                        },
                                    ],
                                }
                            }
                        }
                    )

            if target in ["ACCEPT", "REJECT", "%%REJECT%%", "DROP"]:
                if target in ["%%REJECT%%", "REJECT"]:
                    target_fragment = self._reject_fragment()
                else:
                    target_fragment = {target.lower(): None}
                rules.append(
                    {
                        add_del: {
                            "rule": {
                                "family": "inet",
                                "table": TABLE_NAME,
                                "chain": "%s_%s" % (table, _policy),
                                "expr": [target_fragment],
                            }
                        }
                    }
                )

        if not enable:
            rules.reverse()

        return rules

    def _pkttype_match_fragment(self, pkttype):
        if pkttype == "all":
            return {}
        elif pkttype in ["unicast", "broadcast", "multicast"]:
            return {
                "match": {
                    "left": {"meta": {"key": "pkttype"}},
                    "op": "==",
                    "right": pkttype,
                }
            }

        raise FirewallError(INVALID_RULE, 'Invalid pkttype "%s"', pkttype)

    def _reject_types_fragment(self, reject_type):
        frags = {
            # REJECT_TYPES              : <nft reject rule fragment>
            "icmp-host-prohibited": {
                "reject": {"type": "icmp", "expr": "host-prohibited"}
            },
            "host-prohib": {"reject": {"type": "icmp", "expr": "host-prohibited"}},
            "icmp-net-prohibited": {
                "reject": {"type": "icmp", "expr": "net-prohibited"}
            },
            "net-prohib": {"reject": {"type": "icmp", "expr": "net-prohibited"}},
            "icmp-admin-prohibited": {
                "reject": {"type": "icmp", "expr": "admin-prohibited"}
            },
            "admin-prohib": {"reject": {"type": "icmp", "expr": "admin-prohibited"}},
            "icmp6-adm-prohibited": {
                "reject": {"type": "icmpv6", "expr": "admin-prohibited"}
            },
            "adm-prohibited": {
                "reject": {"type": "icmpv6", "expr": "admin-prohibited"}
            },
            "icmp-net-unreachable": {
                "reject": {"type": "icmp", "expr": "net-unreachable"}
            },
            "net-unreach": {"reject": {"type": "icmp", "expr": "net-unreachable"}},
            "icmp-host-unreachable": {
                "reject": {"type": "icmp", "expr": "host-unreachable"}
            },
            "host-unreach": {"reject": {"type": "icmp", "expr": "host-unreachable"}},
            "icmp-port-unreachable": {
                "reject": {"type": "icmp", "expr": "port-unreachable"}
            },
            "icmp6-port-unreachable": {
                "reject": {"type": "icmpv6", "expr": "port-unreachable"}
            },
            "port-unreach": {"reject": {"type": "icmpx", "expr": "port-unreachable"}},
            "icmp-proto-unreachable": {
                "reject": {"type": "icmp", "expr": "prot-unreachable"}
            },
            "proto-unreach": {"reject": {"type": "icmp", "expr": "prot-unreachable"}},
            "icmp6-addr-unreachable": {
                "reject": {"type": "icmpv6", "expr": "addr-unreachable"}
            },
            "addr-unreach": {"reject": {"type": "icmpv6", "expr": "addr-unreachable"}},
            "icmp6-no-route": {"reject": {"type": "icmpv6", "expr": "no-route"}},
            "no-route": {"reject": {"type": "icmpv6", "expr": "no-route"}},
            "tcp-reset": {"reject": {"type": "tcp reset"}},
            "tcp-rst": {"reject": {"type": "tcp reset"}},
        }
        return frags[reject_type]

    def _reject_fragment(self):
        return {"reject": {"type": "icmpx", "expr": "admin-prohibited"}}

    def _icmp_match_fragment(self):
        return {
            "match": {
                "left": {"meta": {"key": "l4proto"}},
                "op": "==",
                "right": {"set": ["icmp", "icmpv6"]},
            }
        }

    def _rich_rule_limit_fragment(self, limit):
        if not limit:
            return {}

        rich_to_nft = {
            "s": "second",
            "m": "minute",
            "h": "hour",
            "d": "day",
        }

        try:
            i = limit.value.index("/")
        except ValueError:
            raise FirewallError(INVALID_RULE, "Expected '/' in limit")

        return {
            "limit": {
                "rate": int(limit.value[0:i]),
                "per": rich_to_nft[limit.value[i + 1]],
            }
        }

    def _rich_rule_chain_suffix(self, rich_rule):
        if type(rich_rule.element) in [
            Rich_Masquerade,
            Rich_ForwardPort,
            Rich_IcmpBlock,
            Rich_Tcp_Mss_Clamp,
        ]:
            # These are special and don't have an explicit action
            pass
        elif rich_rule.action:
            if type(rich_rule.action) not in [
                Rich_Accept,
                Rich_Reject,
                Rich_Drop,
                Rich_Mark,
            ]:
                raise FirewallError(
                    INVALID_RULE, "Unknown action %s" % type(rich_rule.action)
                )
        else:
            raise FirewallError(INVALID_RULE, "No rule action specified.")

        if rich_rule.priority == 0:
            if type(rich_rule.element) in [
                Rich_Masquerade,
                Rich_ForwardPort,
                Rich_Tcp_Mss_Clamp,
            ] or type(rich_rule.action) in [Rich_Accept, Rich_Mark]:
                return "allow"
            elif type(rich_rule.element) in [Rich_IcmpBlock] or type(
                rich_rule.action
            ) in [Rich_Reject, Rich_Drop]:
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
        if not rich_rule or rich_rule.priority == 0:
            return {}
        return {"%%RICH_RULE_PRIORITY%%": rich_rule.priority}

    def _rich_rule_log(self, policy, rich_rule, enable, table, expr_fragments):
        if not rich_rule.log:
            return {}

        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX
        )

        add_del = {True: "add", False: "delete"}[enable]

        chain_suffix = self._rich_rule_chain_suffix_from_log(rich_rule)

        log_options = {}
        if isinstance(rich_rule.log, Rich_NFLog):
            log_options["group"] = (
                int(rich_rule.log.group) if rich_rule.log.group else 0
            )
            if rich_rule.log.threshold:
                log_options["queue-threshold"] = int(rich_rule.log.threshold)
        else:
            if rich_rule.log.level:
                level = (
                    "warn" if "warning" == rich_rule.log.level else rich_rule.log.level
                )
                log_options["level"] = "%s" % level

        if rich_rule.log.prefix:
            log_options["prefix"] = "%s" % rich_rule.log.prefix

        rule = {
            "family": "inet",
            "table": TABLE_NAME,
            "chain": "%s_%s_%s" % (table, _policy, chain_suffix),
            "expr": expr_fragments
            + [
                self._rich_rule_limit_fragment(rich_rule.log.limit),
                {"log": log_options},
            ],
        }
        rule.update(self._rich_rule_priority_fragment(rich_rule))
        return {add_del: {"rule": rule}}

    def _rich_rule_audit(self, policy, rich_rule, enable, table, expr_fragments):
        if not rich_rule.audit:
            return {}

        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX
        )

        add_del = {True: "add", False: "delete"}[enable]

        chain_suffix = self._rich_rule_chain_suffix_from_log(rich_rule)
        rule = {
            "family": "inet",
            "table": TABLE_NAME,
            "chain": "%s_%s_%s" % (table, _policy, chain_suffix),
            "expr": expr_fragments
            + [
                self._rich_rule_limit_fragment(rich_rule.audit.limit),
                {"log": {"level": "audit"}},
            ],
        }
        rule.update(self._rich_rule_priority_fragment(rich_rule))
        return {add_del: {"rule": rule}}

    def _rich_rule_action(self, policy, rich_rule, enable, table, expr_fragments):
        if not rich_rule.action:
            return {}

        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX
        )

        add_del = {True: "add", False: "delete"}[enable]

        chain_suffix = self._rich_rule_chain_suffix(rich_rule)
        chain = "%s_%s_%s" % (table, _policy, chain_suffix)
        if isinstance(rich_rule.action, Rich_Accept):
            rule_action = {"accept": None}
        elif isinstance(rich_rule.action, Rich_Reject):
            if rich_rule.action.type:
                rule_action = self._reject_types_fragment(rich_rule.action.type)
            else:
                rule_action = {"reject": None}
        elif isinstance(rich_rule.action, Rich_Drop):
            rule_action = {"drop": None}
        elif isinstance(rich_rule.action, Rich_Mark):
            table = "mangle"
            _policy = self._fw.policy.policy_base_chain_name(
                policy, table, POLICY_CHAIN_PREFIX
            )
            chain = "%s_%s_%s" % (table, _policy, chain_suffix)
            value = rich_rule.action.set.split("/")
            if len(value) > 1:
                rule_action = {
                    "mangle": {
                        "key": {"meta": {"key": "mark"}},
                        "value": {
                            "^": [
                                {"&": [{"meta": {"key": "mark"}}, value[1]]},
                                value[0],
                            ]
                        },
                    }
                }
            else:
                rule_action = {
                    "mangle": {"key": {"meta": {"key": "mark"}}, "value": value[0]}
                }

        else:
            raise FirewallError(
                INVALID_RULE, "Unknown action %s" % type(rich_rule.action)
            )

        rule = {
            "family": "inet",
            "table": TABLE_NAME,
            "chain": chain,
            "expr": expr_fragments
            + [self._rich_rule_limit_fragment(rich_rule.action.limit), rule_action],
        }
        rule.update(self._rich_rule_priority_fragment(rich_rule))
        return {add_del: {"rule": rule}}

    def _rule_addr_fragment(self, addr_field, address, invert=False):
        if address.startswith("ipset:"):
            return self._set_match_fragment(
                address[len("ipset:") :],
                True if "daddr" == addr_field else False,
                invert,
            )
        else:
            if check_mac(address):
                family = "ether"
            elif check_single_address("ipv4", address):
                family = "ip"
            elif check_address("ipv4", address):
                family = "ip"
                normalized_address = ipaddress.IPv4Network(address, strict=False)
                address = {
                    "prefix": {
                        "addr": normalized_address.network_address.compressed,
                        "len": normalized_address.prefixlen,
                    }
                }
            elif check_single_address("ipv6", address):
                family = "ip6"
                address = normalizeIP6(address)
            else:
                family = "ip6"
                addr_len = address.split("/")
                address = {
                    "prefix": {
                        "addr": normalizeIP6(addr_len[0]),
                        "len": int(addr_len[1]),
                    }
                }

            return {
                "match": {
                    "left": {"payload": {"protocol": family, "field": addr_field}},
                    "op": "!=" if invert else "==",
                    "right": address,
                }
            }

    def _rich_rule_family_fragment(self, rich_family):
        if not rich_family:
            return {}
        if rich_family not in ["ipv4", "ipv6"]:
            raise FirewallError(INVALID_RULE, "Invalid family" % rich_family)

        return {
            "match": {
                "left": {"meta": {"key": "nfproto"}},
                "op": "==",
                "right": rich_family,
            }
        }

    def _rich_rule_destination_fragment(self, rich_dest):
        if not rich_dest:
            return {}
        if rich_dest.addr:
            address = rich_dest.addr
        elif rich_dest.ipset:
            address = "ipset:" + rich_dest.ipset

        return self._rule_addr_fragment("daddr", address, invert=rich_dest.invert)

    def _rich_rule_source_fragment(self, rich_source):
        if not rich_source:
            return {}

        if rich_source.addr:
            address = rich_source.addr
        elif hasattr(rich_source, "mac") and rich_source.mac:
            address = rich_source.mac
        elif hasattr(rich_source, "ipset") and rich_source.ipset:
            address = "ipset:" + rich_source.ipset

        return self._rule_addr_fragment("saddr", address, invert=rich_source.invert)

    def _port_fragment(self, port):
        range = getPortRange(port)
        if isinstance(range, int) and range < 0:
            raise FirewallError(INVALID_PORT)
        elif len(range) == 1:
            return range[0]
        else:
            return {"range": [range[0], range[1]]}

    def build_policy_ports_rules(
        self, enable, policy, proto, port, destination=None, rich_rule=None
    ):
        add_del = {True: "add", False: "delete"}[enable]
        table = "filter"
        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX
        )

        expr_fragments = []
        if rich_rule:
            expr_fragments.append(self._rich_rule_family_fragment(rich_rule.family))
        if destination:
            expr_fragments.append(self._rule_addr_fragment("daddr", destination))
        if rich_rule:
            expr_fragments.append(
                self._rich_rule_destination_fragment(rich_rule.destination)
            )
            expr_fragments.append(self._rich_rule_source_fragment(rich_rule.source))

        expr_fragments.append(
            {
                "match": {
                    "left": {"payload": {"protocol": proto, "field": "dport"}},
                    "op": "==",
                    "right": self._port_fragment(port),
                }
            }
        )

        rules = []
        if rich_rule:
            rules.append(
                self._rich_rule_log(policy, rich_rule, enable, table, expr_fragments)
            )
            rules.append(
                self._rich_rule_audit(policy, rich_rule, enable, table, expr_fragments)
            )
            rules.append(
                self._rich_rule_action(policy, rich_rule, enable, table, expr_fragments)
            )
        else:
            rules.append(
                {
                    add_del: {
                        "rule": {
                            "family": "inet",
                            "table": TABLE_NAME,
                            "chain": "%s_%s_allow" % (table, _policy),
                            "expr": expr_fragments + [{"accept": None}],
                        }
                    }
                }
            )

        return rules

    def build_policy_protocol_rules(
        self, enable, policy, protocol, destination=None, rich_rule=None
    ):
        add_del = {True: "add", False: "delete"}[enable]
        table = "filter"
        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX
        )

        expr_fragments = []
        if rich_rule:
            expr_fragments.append(self._rich_rule_family_fragment(rich_rule.family))
        if destination:
            expr_fragments.append(self._rule_addr_fragment("daddr", destination))
        if rich_rule:
            expr_fragments.append(
                self._rich_rule_destination_fragment(rich_rule.destination)
            )
            expr_fragments.append(self._rich_rule_source_fragment(rich_rule.source))

        expr_fragments.append(
            {
                "match": {
                    "left": {"meta": {"key": "l4proto"}},
                    "op": "==",
                    "right": protocol,
                }
            }
        )

        rules = []
        if rich_rule:
            rules.append(
                self._rich_rule_log(policy, rich_rule, enable, table, expr_fragments)
            )
            rules.append(
                self._rich_rule_audit(policy, rich_rule, enable, table, expr_fragments)
            )
            rules.append(
                self._rich_rule_action(policy, rich_rule, enable, table, expr_fragments)
            )
        else:
            rules.append(
                {
                    add_del: {
                        "rule": {
                            "family": "inet",
                            "table": TABLE_NAME,
                            "chain": "%s_%s_allow" % (table, _policy),
                            "expr": expr_fragments + [{"accept": None}],
                        }
                    }
                }
            )

        return rules

    def build_policy_tcp_mss_clamp_rules(
        self, enable, policy, tcp_mss_clamp_value, destination=None, rich_rule=None
    ):
        chain_suffix = "allow"
        table = "filter"
        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX
        )
        add_del = {True: "add", False: "delete"}[enable]

        expr_fragments = []
        if rich_rule:
            expr_fragments.append(
                self._rich_rule_destination_fragment(rich_rule.destination)
            )
            expr_fragments.append(self._rich_rule_source_fragment(rich_rule.source))
            chain_suffix = self._rich_rule_chain_suffix(rich_rule)

        expr_fragments.append(
            {
                "match": {
                    "op": "in",
                    "left": {"payload": {"protocol": "tcp", "field": "flags"}},
                    "right": "syn",
                }
            }
        )

        if tcp_mss_clamp_value == "pmtu" or tcp_mss_clamp_value is None:
            expr_fragments.append(
                {
                    "mangle": {
                        "key": {"tcp option": {"name": "maxseg", "field": "size"}},
                        "value": {"rt": {"key": "mtu"}},
                    }
                }
            )
        else:
            expr_fragments.append(
                {
                    "mangle": {
                        "key": {"tcp option": {"name": "maxseg", "field": "size"}},
                        "value": tcp_mss_clamp_value,
                    }
                }
            )

        return [
            {
                add_del: {
                    "rule": {
                        "family": "inet",
                        "table": TABLE_NAME,
                        "chain": "filter_%s_%s" % (_policy, chain_suffix),
                        "expr": expr_fragments,
                    }
                }
            }
        ]

    def build_policy_source_ports_rules(
        self, enable, policy, proto, port, destination=None, rich_rule=None
    ):
        add_del = {True: "add", False: "delete"}[enable]
        table = "filter"
        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX
        )

        expr_fragments = []
        if rich_rule:
            expr_fragments.append(self._rich_rule_family_fragment(rich_rule.family))
        if destination:
            expr_fragments.append(self._rule_addr_fragment("daddr", destination))
        if rich_rule:
            expr_fragments.append(
                self._rich_rule_destination_fragment(rich_rule.destination)
            )
            expr_fragments.append(self._rich_rule_source_fragment(rich_rule.source))

        expr_fragments.append(
            {
                "match": {
                    "left": {"payload": {"protocol": proto, "field": "sport"}},
                    "op": "==",
                    "right": self._port_fragment(port),
                }
            }
        )

        rules = []
        if rich_rule:
            rules.append(
                self._rich_rule_log(policy, rich_rule, enable, table, expr_fragments)
            )
            rules.append(
                self._rich_rule_audit(policy, rich_rule, enable, table, expr_fragments)
            )
            rules.append(
                self._rich_rule_action(policy, rich_rule, enable, table, expr_fragments)
            )
        else:
            rules.append(
                {
                    add_del: {
                        "rule": {
                            "family": "inet",
                            "table": TABLE_NAME,
                            "chain": "%s_%s_allow" % (table, _policy),
                            "expr": expr_fragments + [{"accept": None}],
                        }
                    }
                }
            )

        return rules

    def build_policy_helper_ports_rules(
        self, enable, policy, proto, port, destination, helper_name, module_short_name
    ):
        table = "filter"
        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX
        )
        add_del = {True: "add", False: "delete"}[enable]
        rules = []

        if enable:
            rules.append(
                {
                    "add": {
                        "ct helper": {
                            "family": "inet",
                            "table": TABLE_NAME,
                            "name": "helper-%s-%s" % (helper_name, proto),
                            "type": module_short_name,
                            "protocol": proto,
                        }
                    }
                }
            )

        expr_fragments = []
        if destination:
            expr_fragments.append(self._rule_addr_fragment("daddr", destination))
        expr_fragments.append(
            {
                "match": {
                    "left": {"payload": {"protocol": proto, "field": "dport"}},
                    "op": "==",
                    "right": self._port_fragment(port),
                }
            }
        )
        expr_fragments.append({"ct helper": "helper-%s-%s" % (helper_name, proto)})
        rules.append(
            {
                add_del: {
                    "rule": {
                        "family": "inet",
                        "table": TABLE_NAME,
                        "chain": "filter_%s_allow" % (_policy),
                        "expr": expr_fragments,
                    }
                }
            }
        )

        return rules

    def build_zone_forward_rules(
        self, enable, zone, policy, table, interface=None, source=None
    ):
        add_del = {True: "add", False: "delete"}[enable]
        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX
        )

        rules = []

        if interface:
            if interface[len(interface) - 1] == "+":
                interface = interface[: len(interface) - 1] + "*"

            expr = [
                {
                    "match": {
                        "left": {"meta": {"key": "oifname"}},
                        "op": "==",
                        "right": interface,
                    }
                },
                {"accept": None},
            ]
        else:  # source
            expr = [self._rule_addr_fragment("daddr", source), {"accept": None}]

        rule = {
            "family": "inet",
            "table": TABLE_NAME,
            "chain": "filter_%s_allow" % (_policy),
            "expr": expr,
        }
        rules.append({add_del: {"rule": rule}})

        return rules

    def build_policy_masquerade_rules(self, enable, policy, rich_rule=None):
        add_del = {True: "add", False: "delete"}[enable]

        rules = []

        expr_fragments = []
        if rich_rule:
            expr_fragments.append(self._rich_rule_family_fragment(rich_rule.family))
            expr_fragments.append(
                self._rich_rule_destination_fragment(rich_rule.destination)
            )
            expr_fragments.append(self._rich_rule_source_fragment(rich_rule.source))
            chain_suffix = self._rich_rule_chain_suffix(rich_rule)
        else:
            expr_fragments.append(
                {
                    "match": {
                        "left": {"meta": {"key": "nfproto"}},
                        "op": "==",
                        "right": "ipv4",
                    }
                }
            )
            chain_suffix = "allow"

        table = "nat"
        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX, isSNAT=True
        )
        rule = {
            "family": "inet",
            "table": TABLE_NAME,
            "chain": "nat_%s_%s" % (_policy, chain_suffix),
            "expr": expr_fragments
            + [
                {
                    "match": {
                        "left": {"meta": {"key": "oifname"}},
                        "op": "!=",
                        "right": "lo",
                    }
                },
                {"masquerade": None},
            ],
        }
        rule.update(self._rich_rule_priority_fragment(rich_rule))
        rules.append({add_del: {"rule": rule}})

        return rules

    def build_policy_forward_port_rules(
        self, enable, policy, port, protocol, toport, toaddr, rich_rule=None
    ):
        table = "nat"
        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX
        )
        add_del = {True: "add", False: "delete"}[enable]

        expr_fragments = []
        if rich_rule:
            expr_fragments.append(self._rich_rule_family_fragment(rich_rule.family))
            expr_fragments.append(
                self._rich_rule_destination_fragment(rich_rule.destination)
            )
            expr_fragments.append(self._rich_rule_source_fragment(rich_rule.source))
            chain_suffix = self._rich_rule_chain_suffix(rich_rule)
        else:
            nfproto = "ipv4"
            if toaddr and check_single_address("ipv6", toaddr):
                nfproto = "ipv6"
            expr_fragments.append(
                {
                    "match": {
                        "left": {"meta": {"key": "nfproto"}},
                        "op": "==",
                        "right": nfproto,
                    }
                }
            )
            chain_suffix = "allow"

        expr_fragments.append(
            {
                "match": {
                    "left": {"payload": {"protocol": protocol, "field": "dport"}},
                    "op": "==",
                    "right": self._port_fragment(port),
                }
            }
        )

        rules = []
        if rich_rule:
            rules.append(
                self._rich_rule_log(policy, rich_rule, enable, table, expr_fragments)
            )

        if toaddr:
            if check_single_address("ipv6", toaddr):
                toaddr = normalizeIP6(toaddr)
            if toport and toport != "":
                expr_fragments.append(
                    {"dnat": {"addr": toaddr, "port": self._port_fragment(toport)}}
                )
            else:
                expr_fragments.append({"dnat": {"addr": toaddr}})
        else:
            expr_fragments.append({"redirect": {"port": self._port_fragment(toport)}})

        rule = {
            "family": "inet",
            "table": TABLE_NAME,
            "chain": "nat_%s_%s" % (_policy, chain_suffix),
            "expr": expr_fragments,
        }
        rule.update(self._rich_rule_priority_fragment(rich_rule))
        rules.append({add_del: {"rule": rule}})

        return rules

    def _icmp_types_to_nft_fragments(self, ipv, icmp_type):
        if icmp_type in ICMP_TYPES_FRAGMENTS[ipv]:
            return ICMP_TYPES_FRAGMENTS[ipv][icmp_type]
        else:
            raise FirewallError(
                INVALID_ICMPTYPE,
                "ICMP type '%s' not supported by %s for %s"
                % (icmp_type, self.name, ipv),
            )

    def build_policy_icmp_block_rules(self, enable, policy, ict, rich_rule=None):
        table = "filter"
        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX
        )
        add_del = {True: "add", False: "delete"}[enable]

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
            if self._fw.policy.query_icmp_block_inversion(policy):
                final_chain = "%s_%s_allow" % (table, _policy)
                target_fragment = {"accept": None}
            else:
                final_chain = "%s_%s_deny" % (table, _policy)
                target_fragment = self._reject_fragment()

            expr_fragments = []
            if rich_rule:
                expr_fragments.append(self._rich_rule_family_fragment(rich_rule.family))
                expr_fragments.append(
                    self._rich_rule_destination_fragment(rich_rule.destination)
                )
                expr_fragments.append(self._rich_rule_source_fragment(rich_rule.source))
            expr_fragments.extend(self._icmp_types_to_nft_fragments(ipv, ict.name))

            if rich_rule:
                rules.append(
                    self._rich_rule_log(
                        policy, rich_rule, enable, table, expr_fragments
                    )
                )
                rules.append(
                    self._rich_rule_audit(
                        policy, rich_rule, enable, table, expr_fragments
                    )
                )
                if rich_rule.action:
                    rules.append(
                        self._rich_rule_action(
                            policy, rich_rule, enable, table, expr_fragments
                        )
                    )
                else:
                    chain_suffix = self._rich_rule_chain_suffix(rich_rule)
                    rule = {
                        "family": "inet",
                        "table": TABLE_NAME,
                        "chain": "%s_%s_%s" % (table, _policy, chain_suffix),
                        "expr": expr_fragments + [self._reject_fragment()],
                    }
                    rule.update(self._rich_rule_priority_fragment(rich_rule))
                    rules.append({add_del: {"rule": rule}})
            else:
                if (
                    self._fw.get_log_denied() != "off"
                    and not self._fw.policy.query_icmp_block_inversion(policy)
                ):
                    rules.append(
                        {
                            add_del: {
                                "rule": {
                                    "family": "inet",
                                    "table": TABLE_NAME,
                                    "chain": final_chain,
                                    "expr": (
                                        expr_fragments
                                        + [
                                            self._pkttype_match_fragment(
                                                self._fw.get_log_denied()
                                            ),
                                            {
                                                "log": {
                                                    "prefix": "%s_%s_ICMP_BLOCK: "
                                                    % (table, policy)
                                                }
                                            },
                                        ]
                                    ),
                                }
                            }
                        }
                    )
                rules.append(
                    {
                        add_del: {
                            "rule": {
                                "family": "inet",
                                "table": TABLE_NAME,
                                "chain": final_chain,
                                "expr": expr_fragments + [target_fragment],
                            }
                        }
                    }
                )

        return rules

    def build_policy_icmp_block_inversion_rules(self, enable, policy):
        table = "filter"
        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX
        )
        rules = []
        add_del = {True: "add", False: "delete"}[enable]

        if self._fw.policy.query_icmp_block_inversion(policy):
            target_fragment = self._reject_fragment()
        else:
            target_fragment = {"accept": None}

        # WARN: The "index" used here must be kept in sync with
        # build_policy_chain_rules()
        #
        rules.append(
            {
                add_del: {
                    "rule": {
                        "family": "inet",
                        "table": TABLE_NAME,
                        "chain": "%s_%s" % (table, _policy),
                        "index": 4,
                        "expr": [self._icmp_match_fragment(), target_fragment],
                    }
                }
            }
        )

        if (
            self._fw.get_log_denied() != "off"
            and self._fw.policy.query_icmp_block_inversion(policy)
        ):
            rules.append(
                {
                    add_del: {
                        "rule": {
                            "family": "inet",
                            "table": TABLE_NAME,
                            "chain": "%s_%s" % (table, _policy),
                            "index": 4,
                            "expr": [
                                self._icmp_match_fragment(),
                                self._pkttype_match_fragment(self._fw.get_log_denied()),
                                {
                                    "log": {
                                        "prefix": "%s_%s_ICMP_BLOCK: " % (table, policy)
                                    }
                                },
                            ],
                        }
                    }
                }
            )
        return rules

    def build_rpfilter_rules(self, log_denied=False):
        rules = []
        expr_fragments = [
            {
                "match": {
                    "left": {"meta": {"key": "nfproto"}},
                    "op": "==",
                    "right": "ipv6",
                }
            },
            {
                "match": {
                    "left": {
                        "fib": {"flags": ["saddr", "iif", "mark"], "result": "oif"}
                    },
                    "op": "==",
                    "right": False,
                }
            },
        ]
        if log_denied != "off":
            expr_fragments.append({"log": {"prefix": "rpfilter_DROP: "}})
        expr_fragments.append({"drop": None})

        rules.append(
            {
                "insert": {
                    "rule": {
                        "family": "inet",
                        "table": TABLE_NAME,
                        "chain": "filter_PREROUTING",
                        "expr": expr_fragments,
                    }
                }
            }
        )
        # RHBZ#1058505, RHBZ#1575431 (bug in kernel 4.16-4.17)
        rules.append(
            {
                "insert": {
                    "rule": {
                        "family": "inet",
                        "table": TABLE_NAME,
                        "chain": "filter_PREROUTING",
                        "expr": [
                            {
                                "match": {
                                    "left": {
                                        "payload": {
                                            "protocol": "icmpv6",
                                            "field": "type",
                                        }
                                    },
                                    "op": "==",
                                    "right": {
                                        "set": [
                                            "nd-router-advert",
                                            "nd-neighbor-solicit",
                                        ]
                                    },
                                }
                            },
                            {"accept": None},
                        ],
                    }
                }
            }
        )
        return rules

    def build_rfc3964_ipv4_rules(self):
        daddr_set = [
            "::0.0.0.0/96",  # IPv4 compatible
            "::ffff:0.0.0.0/96",  # IPv4 mapped
            "2002:0000::/24",  # 0.0.0.0/8 (the system has no address assigned yet)
            "2002:0a00::/24",  # 10.0.0.0/8 (private)
            "2002:7f00::/24",  # 127.0.0.0/8 (loopback)
            "2002:ac10::/28",  # 172.16.0.0/12 (private)
            "2002:c0a8::/32",  # 192.168.0.0/16 (private)
            "2002:a9fe::/32",  # 169.254.0.0/16 (IANA Assigned DHCP link-local)
            "2002:e000::/19",  # 224.0.0.0/4 (multicast), 240.0.0.0/4 (reserved and broadcast)
        ]
        daddr_set = [
            {"prefix": {"addr": x.split("/")[0], "len": int(x.split("/")[1])}}
            for x in daddr_set
        ]

        expr_fragments = [
            {
                "match": {
                    "left": {"payload": {"protocol": "ip6", "field": "daddr"}},
                    "op": "==",
                    "right": {"set": daddr_set},
                }
            }
        ]
        if self._fw._log_denied in ["unicast", "all"]:
            expr_fragments.append({"log": {"prefix": "RFC3964_IPv4_REJECT: "}})
        expr_fragments.append(self._reject_types_fragment("addr-unreach"))

        rules = []
        # WARN: index must be kept in sync with build_default_rules()
        rules.append(
            {
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": TABLE_NAME,
                        "chain": "filter_OUTPUT",
                        "index": 1,
                        "expr": expr_fragments,
                    }
                }
            }
        )
        forward_index = 3
        if self._fw._nftables_flowtable != "off":
            forward_index += 1
        if self._fw.get_log_denied() != "off":
            forward_index += 1
        rules.append(
            {
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": TABLE_NAME,
                        "chain": "filter_FORWARD",
                        "index": forward_index,
                        "expr": expr_fragments,
                    }
                }
            }
        )
        return rules

    def build_policy_rich_source_destination_rules(self, enable, policy, rich_rule):
        table = "filter"

        expr_fragments = []
        expr_fragments.append(self._rich_rule_family_fragment(rich_rule.family))
        expr_fragments.append(
            self._rich_rule_destination_fragment(rich_rule.destination)
        )
        expr_fragments.append(self._rich_rule_source_fragment(rich_rule.source))

        rules = []
        rules.append(
            self._rich_rule_log(policy, rich_rule, enable, table, expr_fragments)
        )
        rules.append(
            self._rich_rule_audit(policy, rich_rule, enable, table, expr_fragments)
        )
        rules.append(
            self._rich_rule_action(policy, rich_rule, enable, table, expr_fragments)
        )

        return rules

    def is_ipv_supported(self, ipv):
        if ipv in ["ipv4", "ipv6", "eb"]:
            return True
        return False

    def _set_type_list(self, ipv, type):
        ipv_addr = {
            "ipv4": "ipv4_addr",
            "ipv6": "ipv6_addr",
        }
        types = {
            "hash:ip": ipv_addr[ipv],
            "hash:ip,port": [ipv_addr[ipv], "inet_proto", "inet_service"],
            "hash:ip,port,ip": [
                ipv_addr[ipv],
                "inet_proto",
                "inet_service",
                ipv_addr[ipv],
            ],
            "hash:ip,port,net": [
                ipv_addr[ipv],
                "inet_proto",
                "inet_service",
                ipv_addr[ipv],
            ],
            "hash:ip,mark": [ipv_addr[ipv], "mark"],
            "hash:net": ipv_addr[ipv],
            "hash:net,net": [ipv_addr[ipv], ipv_addr[ipv]],
            "hash:net,port": [ipv_addr[ipv], "inet_proto", "inet_service"],
            "hash:net,port,net": [
                ipv_addr[ipv],
                "inet_proto",
                "inet_service",
                ipv_addr[ipv],
            ],
            "hash:net,iface": [ipv_addr[ipv], "ifname"],
            "hash:mac": "ether_addr",
        }
        if type in types:
            return types[type]
        else:
            raise FirewallError(
                INVALID_TYPE, "ipset type name '%s' is not valid" % type
            )

    def build_set_create_rules(self, name, type, options=None):
        if options and "family" in options and options["family"] == "inet6":
            ipv = "ipv6"
        else:
            ipv = "ipv4"

        set_dict = {
            "family": "inet",
            "table": TABLE_NAME,
            "name": name,
            "type": self._set_type_list(ipv, type),
        }

        # Some types need the interval flag
        for t in type.split(":")[1].split(","):
            if t in ["ip", "net", "port"]:
                set_dict["flags"] = ["interval"]
                break

        if options:
            if "timeout" in options:
                set_dict["timeout"] = int(options["timeout"])
            if "maxelem" in options:
                set_dict["size"] = int(options["maxelem"])

        return [{"add": {"set": set_dict}}]

    def set_create(self, name, type, options=None):
        rules = self.build_set_create_rules(name, type, options)
        self.set_rules(rules, self._fw.get_log_denied())

    def set_destroy(self, name):
        rule = {
            "delete": {"set": {"family": "inet", "table": TABLE_NAME, "name": name}}
        }
        self.set_rule(rule, self._fw.get_log_denied())

    def _set_match_fragment(self, name, match_dest, invert=False):
        type_format = self._fw.ipset.get_ipset(name).type.split(":")[1].split(",")

        fragments = []
        for format in type_format:
            if format == "port":
                fragments.append({"meta": {"key": "l4proto"}})
                fragments.append(
                    {
                        "payload": {
                            "protocol": "th",
                            "field": "dport" if match_dest else "sport",
                        }
                    }
                )
            elif format in ["ip", "net", "mac"]:
                fragments.append(
                    {
                        "payload": {
                            "protocol": self._set_get_family(name),
                            "field": "daddr" if match_dest else "saddr",
                        }
                    }
                )
            elif format == "iface":
                fragments.append(
                    {"meta": {"key": "iifname" if match_dest else "oifname"}}
                )
            elif format == "mark":
                fragments.append({"meta": {"key": "mark"}})
            else:
                raise FirewallError(
                    INVALID_TYPE,
                    "Unsupported ipset type for match fragment: %s" % (format),
                )

        return {
            "match": {
                "left": {"concat": fragments} if len(type_format) > 1 else fragments[0],
                "op": "!=" if invert else "==",
                "right": "@" + name,
            }
        }

    def _set_entry_fragment(self, name, entry):
        # convert something like
        #    1.2.3.4,sctp:8080 (type hash:ip,port)
        # to
        #    ["1.2.3.4", "sctp", "8080"]
        obj = self._fw.ipset.get_ipset(name)
        type_format = obj.type.split(":")[1].split(",")
        entry_tokens = entry.split(",")
        if len(type_format) != len(entry_tokens):
            raise FirewallError(
                INVALID_ENTRY, "Number of values does not match ipset type."
            )
        fragment = []
        for i, format in enumerate(type_format):
            if format == "port":
                try:
                    index = entry_tokens[i].index(":")
                except ValueError:
                    # no protocol means default tcp
                    fragment.append("tcp")
                    port_str = entry_tokens[i]
                else:
                    fragment.append(entry_tokens[i][:index])
                    port_str = entry_tokens[i][index + 1 :]

                try:
                    index = port_str.index("-")
                except ValueError:
                    fragment.append(port_str)
                else:
                    fragment.append(
                        {"range": [port_str[:index], port_str[index + 1 :]]}
                    )

            elif format in ["ip", "net"]:
                if "-" in entry_tokens[i]:
                    fragment.append({"range": entry_tokens[i].split("-")})
                else:
                    try:
                        index = entry_tokens[i].index("/")
                    except ValueError:
                        addr = entry_tokens[i]
                        if "family" in obj.options and obj.options["family"] == "inet6":
                            addr = normalizeIP6(addr)
                        fragment.append(addr)
                    else:
                        addr = entry_tokens[i][:index]
                        if "family" in obj.options and obj.options["family"] == "inet6":
                            addr = normalizeIP6(addr)
                        fragment.append(
                            {
                                "prefix": {
                                    "addr": addr,
                                    "len": int(entry_tokens[i][index + 1 :]),
                                }
                            }
                        )
            else:
                fragment.append(entry_tokens[i])
        return [{"concat": fragment}] if len(type_format) > 1 else fragment

    def build_set_add_rules(self, name, entry):
        rules = []
        element = self._set_entry_fragment(name, entry)
        rules.append(
            {
                "add": {
                    "element": {
                        "family": "inet",
                        "table": TABLE_NAME,
                        "name": name,
                        "elem": element,
                    }
                }
            }
        )
        return rules

    def set_add(self, name, entry):
        rules = self.build_set_add_rules(name, entry)
        self.set_rules(rules, self._fw.get_log_denied())

    def set_delete(self, name, entry):
        element = self._set_entry_fragment(name, entry)
        rule = {
            "delete": {
                "element": {
                    "family": "inet",
                    "table": TABLE_NAME,
                    "name": name,
                    "elem": element,
                }
            }
        }
        self.set_rule(rule, self._fw.get_log_denied())

    def build_set_flush_rules(self, name):
        return [
            {"flush": {"set": {"family": "inet", "table": TABLE_NAME, "name": name}}}
        ]

    def set_flush(self, name):
        rules = self.build_set_flush_rules(name)
        self.set_rules(rules, self._fw.get_log_denied())

    def _set_get_family(self, name):
        ipset = self._fw.ipset.get_ipset(name)

        if ipset.type == "hash:mac":
            family = "ether"
        elif (
            ipset.options
            and "family" in ipset.options
            and ipset.options["family"] == "inet6"
        ):
            family = "ip6"
        else:
            family = "ip"

        return family

    def set_restore(
        self, set_name, type_name, entries, create_options=None, entry_options=None
    ):
        rules = []
        rules.extend(self.build_set_create_rules(set_name, type_name, create_options))
        rules.extend(self.build_set_flush_rules(set_name))

        # avoid large memory usage by chunking the entries
        chunk = 0
        for entry in entries:
            rules.extend(self.build_set_add_rules(set_name, entry))
            chunk += 1
            if chunk >= 1000:
                self.set_rules(rules, self._fw.get_log_denied())
                rules.clear()
                chunk = 0
        else:
            self.set_rules(rules, self._fw.get_log_denied())
