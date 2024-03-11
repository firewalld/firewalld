import copy

import firewall.core.nftables


def test_set_rule_replace_priority():
    def do_test(rule, priority_counts, expected_rule, expected_priority_counts):
        priority_counts2 = copy.deepcopy(priority_counts)
        rule2 = copy.deepcopy(rule)

        x = firewall.core.nftables.nftables._set_rule_replace_priority(
            rule2, priority_counts2
        )

        assert x is None

        if expected_rule is None:
            assert rule2 == rule
        else:
            assert rule2 == expected_rule

        if expected_priority_counts is None:
            assert priority_counts2 == priority_counts
        else:
            assert priority_counts2 == expected_priority_counts

    do_test(
        {
            "add": {
                "rule": {
                    "family": "inet",
                    "table": "firewalld",
                    "chain": "mangle_PREROUTING",
                    "expr": [{"jump": {"target": "mangle_PREROUTING_POLICIES"}}],
                }
            }
        },
        {},
        None,
        None,
    )

    do_test(
        {
            "add": {
                "rule": {
                    "family": "inet",
                    "table": "firewalld",
                    "chain": "mangle_PREROUTING",
                    "expr": [{"jump": {"target": "mangle_PREROUTING_POLICIES"}}],
                    "%%RICH_RULE_PRIORITY%%": 5,
                }
            }
        },
        {},
        {
            "insert": {
                "rule": {
                    "chain": "mangle_PREROUTING",
                    "expr": [{"jump": {"target": "mangle_PREROUTING_POLICIES"}}],
                    "family": "inet",
                    "table": "firewalld",
                }
            }
        },
        {("inet", "mangle_PREROUTING"): {5: 1}},
    )


def test_set_rule_sort_policy_dispatch():
    def do_test(
        rule,
        policy_dispatch_index_cache,
        expected_rule,
        expected_policy_dispatch_index_cache,
    ):
        rule2 = copy.deepcopy(rule)
        policy_dispatch_index_cache2 = copy.deepcopy(policy_dispatch_index_cache)

        x = firewall.core.nftables.nftables._set_rule_sort_policy_dispatch(
            rule2, policy_dispatch_index_cache2
        )
        assert x is None
        assert rule2 == expected_rule
        assert policy_dispatch_index_cache2 == expected_policy_dispatch_index_cache

    do_test(
        rule={
            "add": {
                "rule": {
                    "family": "inet",
                    "table": "firewalld",
                    "chain": "nat_POSTROUTING_POLICIES",
                    "expr": [{"jump": {"target": "nat_POST_public"}}],
                    "%%POLICY_SORT_KEY%%": (
                        32768,
                        2,
                        "public",
                        "",
                        "*",
                        32768,
                        2,
                        "public",
                        "",
                        "*",
                        0,
                        0,
                    ),
                }
            }
        },
        expected_rule={
            "insert": {
                "rule": {
                    "chain": "nat_POSTROUTING_POLICIES",
                    "expr": [{"jump": {"target": "nat_POST_public"}}],
                    "family": "inet",
                    "table": "firewalld",
                }
            }
        },
        policy_dispatch_index_cache={
            ("inet", "filter_INPUT_POLICIES"): [
                (32768, 2, "public", "", "*", 0, 0, "HOST", "", "", 0, 0),
                (32768, 2, "public", "", "*", 0, 0, "HOST", "", "", 2, 0),
            ],
            ("inet", "filter_OUTPUT_POLICIES"): [
                (0, 0, "HOST", "", "", 32768, 2, "public", "", "*", 0, 0),
                (0, 0, "HOST", "", "", 32768, 2, "public", "", "*", 2, 0),
            ],
            ("inet", "nat_OUTPUT_POLICIES"): [
                (0, 0, "HOST", "", "", 32768, 2, "public", "", "*", 0, 0),
                (0, 0, "HOST", "", "", 32768, 2, "public", "", "*", 2, 0),
            ],
            ("inet", "filter_FORWARD_POLICIES"): [
                (32768, 2, "public", "", "*", 32768, 2, "public", "", "*", 0, 0),
                (32768, 2, "public", "", "*", 32768, 2, "public", "", "*", 2, 0),
            ],
            ("inet", "nat_PREROUTING_POLICIES"): [
                (32768, 2, "public", "", "*", 0, 2, "", "", "", 0, 0),
                (32768, 2, "public", "", "*", 0, 2, "", "", "", 2, 0),
            ],
            ("inet", "mangle_PREROUTING_POLICIES"): [
                (32768, 2, "public", "", "*", 0, 2, "", "", "", 0, 0),
                (32768, 2, "public", "", "*", 0, 2, "", "", "", 2, 0),
            ],
            ("inet", "nat_POSTROUTING_POLICIES"): [
                (32768, 2, "public", "", "*", 32768, 2, "public", "", "*", 2, 0)
            ],
        },
        expected_policy_dispatch_index_cache={
            ("inet", "filter_INPUT_POLICIES"): [
                (32768, 2, "public", "", "*", 0, 0, "HOST", "", "", 0, 0),
                (32768, 2, "public", "", "*", 0, 0, "HOST", "", "", 2, 0),
            ],
            ("inet", "filter_OUTPUT_POLICIES"): [
                (0, 0, "HOST", "", "", 32768, 2, "public", "", "*", 0, 0),
                (0, 0, "HOST", "", "", 32768, 2, "public", "", "*", 2, 0),
            ],
            ("inet", "nat_OUTPUT_POLICIES"): [
                (0, 0, "HOST", "", "", 32768, 2, "public", "", "*", 0, 0),
                (0, 0, "HOST", "", "", 32768, 2, "public", "", "*", 2, 0),
            ],
            ("inet", "filter_FORWARD_POLICIES"): [
                (32768, 2, "public", "", "*", 32768, 2, "public", "", "*", 0, 0),
                (32768, 2, "public", "", "*", 32768, 2, "public", "", "*", 2, 0),
            ],
            ("inet", "nat_PREROUTING_POLICIES"): [
                (32768, 2, "public", "", "*", 0, 2, "", "", "", 0, 0),
                (32768, 2, "public", "", "*", 0, 2, "", "", "", 2, 0),
            ],
            ("inet", "mangle_PREROUTING_POLICIES"): [
                (32768, 2, "public", "", "*", 0, 2, "", "", "", 0, 0),
                (32768, 2, "public", "", "*", 0, 2, "", "", "", 2, 0),
            ],
            ("inet", "nat_POSTROUTING_POLICIES"): [
                (32768, 2, "public", "", "*", 32768, 2, "public", "", "*", 0, 0),
                (32768, 2, "public", "", "*", 32768, 2, "public", "", "*", 2, 0),
            ],
        },
    )
