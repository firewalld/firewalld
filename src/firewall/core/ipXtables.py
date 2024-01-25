# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2010-2016 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>

import os.path
import copy

from firewall.core.prog import runProg
from firewall.core.logger import log
from firewall.functions import (
    tempFile,
    readfile,
    splitArgs,
    check_mac,
    portStr,
    check_single_address,
    check_address,
    normalizeIP6,
)
from firewall import config
from firewall.errors import (
    FirewallError,
    INVALID_PASSTHROUGH,
    INVALID_RULE,
    UNKNOWN_ERROR,
    INVALID_ADDR,
)
from firewall.core.rich import (
    Rich_Accept,
    Rich_Reject,
    Rich_Drop,
    Rich_Mark,
    Rich_NFLog,
    Rich_Masquerade,
    Rich_ForwardPort,
    Rich_IcmpBlock,
    Rich_Tcp_Mss_Clamp,
)
from firewall.core.base import DEFAULT_ZONE_TARGET
import string

POLICY_CHAIN_PREFIX = ""

BUILT_IN_CHAINS = {
    "security": ["INPUT", "OUTPUT", "FORWARD"],
    "raw": ["PREROUTING", "OUTPUT"],
    "mangle": ["PREROUTING", "POSTROUTING", "INPUT", "OUTPUT", "FORWARD"],
    "nat": ["PREROUTING", "POSTROUTING", "OUTPUT"],
    "filter": ["INPUT", "OUTPUT", "FORWARD"],
}

DEFAULT_REJECT_TYPE = {
    "ipv4": "icmp-host-prohibited",
    "ipv6": "icmp6-adm-prohibited",
}

ICMP = {
    "ipv4": "icmp",
    "ipv6": "ipv6-icmp",
}


def common_reverse_passthrough(args):
    """Reverse valid passthough rule"""

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

        if x in ["-I", "--insert"]:
            # With insert rulenum, then remove it if it is a number
            # Opt at position idx, chain at position idx+1, [rulenum] at
            # position idx+2
            try:
                int(ret_args[idx + 2])
            except ValueError:
                pass
            else:
                ret_args.pop(idx + 2)

        ret_args[idx] = replace_args[x]
        return ret_args

    raise FirewallError(INVALID_PASSTHROUGH, "no '-A', '-I' or '-N' arg")


# ipv ebtables also uses this
#
def common_check_passthrough(args):
    """Check if passthough rule is valid (only add, insert and new chain
    rules are allowed)"""

    args = set(args)
    not_allowed = set(
        [
            "-C",
            "--check",  # check rule
            "-D",
            "--delete",  # delete rule
            "-R",
            "--replace",  # replace rule
            "-L",
            "--list",  # list rule
            "-S",
            "--list-rules",  # print rules
            "-F",
            "--flush",  # flush rules
            "-Z",
            "--zero",  # zero rules
            "-X",
            "--delete-chain",  # delete chain
            "-P",
            "--policy",  # policy
            "-E",
            "--rename-chain",
        ]
    )  # rename chain)
    # intersection of args and not_allowed is not empty, i.e.
    # something from args is not allowed
    if len(args & not_allowed) > 0:
        raise FirewallError(
            INVALID_PASSTHROUGH, "arg '%s' is not allowed" % list(args & not_allowed)[0]
        )

    # args need to contain one of -A, -I, -N
    needed = set(["-A", "--append", "-I", "--insert", "-N", "--new-chain"])
    # empty intersection of args and needed, i.e.
    # none from args contains any needed command
    if len(args & needed) == 0:
        raise FirewallError(INVALID_PASSTHROUGH, "no '-A', '-I' or '-N' arg")


class ip4tables:
    ipv = "ipv4"
    name = "ip4tables"
    policies_supported = True

    def __init__(self, fw):
        self._fw = fw
        self._command = config.COMMANDS[self.ipv]
        self._restore_command = config.COMMANDS["%s-restore" % self.ipv]
        self.wait_option = self._detect_wait_option()
        self.restore_wait_option = self._detect_restore_wait_option()
        self.fill_exists()
        self.available_tables = []
        self.rich_rule_priority_counts = {}
        self.policy_dispatch_index_cache = {}
        self.policy_dispatch_index_cache_ref_count = {}
        self.our_chains = {}  # chains created by firewalld

    def fill_exists(self):
        self.command_exists = os.path.exists(self._command)
        self.restore_command_exists = os.path.exists(self._restore_command)

    def __run(self, args):
        # convert to string list
        if self.wait_option and self.wait_option not in args:
            _args = [self.wait_option] + ["%s" % item for item in args]
        else:
            _args = ["%s" % item for item in args]
        log.debug2("%s: %s %s", self.__class__, self._command, " ".join(_args))
        (status, ret) = runProg(self._command, _args)
        if status != 0:
            raise ValueError(
                "'%s %s' failed: %s" % (self._command, " ".join(_args), ret)
            )
        return ret

    def _rule_replace(self, rule, pattern, replacement):
        try:
            i = rule.index(pattern)
        except ValueError:
            return False
        else:
            rule[i : i + 1] = replacement
            return True

    def is_chain_builtin(self, ipv, table, chain):
        return table in BUILT_IN_CHAINS and chain in BUILT_IN_CHAINS[table]

    def build_chain_rules(self, add, table, chain):
        rule = ["-t", table]
        if add:
            rule.append("-N")
        else:
            rule.append("-X")
        rule.append(chain)
        return [rule]

    def build_rule(self, add, table, chain, index, args):
        rule = ["-t", table]
        if add:
            rule += ["-I", chain, str(index)]
        else:
            rule += ["-D", chain]
        rule += args
        return rule

    def check_passthrough(self, args):
        common_check_passthrough(args)

    def reverse_passthrough(self, args):
        return common_reverse_passthrough(args)

    def passthrough_parse_table_chain(self, args):
        table = "filter"
        try:
            i = args.index("-t")
        except ValueError:
            pass
        else:
            if len(args) >= i + 1:
                table = args[i + 1]
        chain = None
        for opt in ["-A", "--append", "-I", "--insert", "-N", "--new-chain"]:
            try:
                i = args.index(opt)
            except ValueError:
                pass
            else:
                if len(args) >= i + 1:
                    chain = args[i + 1]
        return (table, chain)

    def _set_rule_replace_priority(self, rule, priority_counts, token):
        """
        Change something like
          -t filter -I public_IN %%RICH_RULE_PRIORITY%% 123
        or
          -t filter -A public_IN %%RICH_RULE_PRIORITY%% 321
        into
          -t filter -I public_IN 4
        or
          -t filter -I public_IN
        """
        try:
            i = rule.index(token)
        except ValueError:
            pass
        else:
            rule_add = True
            insert = False
            insert_add_index = -1
            rule.pop(i)
            priority = rule.pop(i)
            if not isinstance(priority, int):
                raise FirewallError(
                    INVALID_RULE, "priority must be followed by a number"
                )

            table = "filter"
            for opt in ["-t", "--table"]:
                try:
                    j = rule.index(opt)
                except ValueError:
                    pass
                else:
                    if len(rule) >= j + 1:
                        table = rule[j + 1]
            for opt in ["-A", "--append", "-I", "--insert", "-D", "--delete"]:
                try:
                    insert_add_index = rule.index(opt)
                except ValueError:
                    pass
                else:
                    if len(rule) >= insert_add_index + 1:
                        chain = rule[insert_add_index + 1]

                    if opt in ["-I", "--insert"]:
                        insert = True
                    if opt in ["-D", "--delete"]:
                        rule_add = False

            chain = (table, chain)

            # Add the rule to the priority counts. We don't need to store the
            # rule, just bump the ref count for the priority value.
            if not rule_add:
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
                index = 1
                for p in sorted(priority_counts[chain].keys()):
                    if p == priority and insert:
                        break
                    index += priority_counts[chain][p]
                    if p == priority:
                        break

                priority_counts[chain][priority] += 1

                rule[insert_add_index] = "-I"
                rule.insert(insert_add_index + 2, "%d" % index)

    def _set_rule_sort_policy_dispatch(
        self, rule, policy_dispatch_index_cache, policy_dispatch_index_cache_ref_count
    ):
        try:
            i = rule.index("%%POLICY_SORT_KEY%%")
        except ValueError:
            return False

        rule.pop(i)
        sort_tuple = rule.pop(i)

        delete = False
        verb_index = -1

        table = "filter"
        for opt in ["-t", "--table"]:
            try:
                j = rule.index(opt)
            except ValueError:
                continue

            if len(rule) >= j + 1:
                table = rule[j + 1]
        for opt in ["-A", "--append", "-I", "--insert", "-D", "--delete"]:
            try:
                verb_index = rule.index(opt)
            except ValueError:
                continue

            if len(rule) >= verb_index + 1:
                chain = rule[verb_index + 1]

            if opt in ["-D", "--delete"]:
                delete = True

        chain = (table, chain)

        if delete:
            if (
                chain in policy_dispatch_index_cache
                and sort_tuple in policy_dispatch_index_cache[chain]
            ):
                if (
                    chain in policy_dispatch_index_cache_ref_count
                    and sort_tuple in policy_dispatch_index_cache_ref_count[chain]
                ):
                    if policy_dispatch_index_cache_ref_count[chain][sort_tuple] == 1:
                        del policy_dispatch_index_cache_ref_count[chain][sort_tuple]
                        policy_dispatch_index_cache[chain].remove(sort_tuple)
                        return False
                    else:
                        policy_dispatch_index_cache_ref_count[chain][sort_tuple] -= 1
                        return True
                else:  # only ever one, so no ref count created
                    policy_dispatch_index_cache[chain].remove(sort_tuple)
                    return False
            return True
        else:
            if chain not in policy_dispatch_index_cache:
                policy_dispatch_index_cache[chain] = []

            # rule de-duplication
            if sort_tuple in policy_dispatch_index_cache[chain]:
                if chain not in policy_dispatch_index_cache_ref_count:
                    policy_dispatch_index_cache_ref_count[chain] = {}
                if sort_tuple not in policy_dispatch_index_cache_ref_count[chain]:
                    policy_dispatch_index_cache_ref_count[chain][sort_tuple] = 1

                if sort_tuple in policy_dispatch_index_cache_ref_count[chain]:
                    policy_dispatch_index_cache_ref_count[chain][sort_tuple] += 1

                # Tell caller to skip this rule as we already have one
                return True

            policy_dispatch_index_cache[chain].append(sort_tuple)
            policy_dispatch_index_cache[chain].sort()

            index = policy_dispatch_index_cache[chain].index(sort_tuple)

            rule[verb_index] = "-I"
            rule.insert(verb_index + 2, f"{index + 1}")

            return False

    def set_rules(self, rules, log_denied):
        temp_file = tempFile()

        table_rules = {}
        rich_rule_priority_counts = copy.deepcopy(self.rich_rule_priority_counts)
        policy_dispatch_index_cache = copy.deepcopy(self.policy_dispatch_index_cache)
        policy_dispatch_index_cache_ref_count = copy.deepcopy(
            self.policy_dispatch_index_cache_ref_count
        )
        for _rule in rules:
            rule = _rule[:]

            # replace %%REJECT%%
            self._rule_replace(
                rule,
                "%%REJECT%%",
                ["REJECT", "--reject-with", DEFAULT_REJECT_TYPE[self.ipv]],
            )

            # replace %%ICMP%%
            self._rule_replace(rule, "%%ICMP%%", [ICMP[self.ipv]])

            # replace %%LOGTYPE%%
            try:
                i = rule.index("%%LOGTYPE%%")
            except ValueError:
                pass
            else:
                if log_denied == "off":
                    continue
                if log_denied in ["unicast", "broadcast", "multicast"]:
                    rule[i : i + 1] = ["-m", "pkttype", "--pkt-type", log_denied]
                else:
                    rule.pop(i)

            self._set_rule_replace_priority(
                rule, rich_rule_priority_counts, "%%RICH_RULE_PRIORITY%%"
            )
            skip = self._set_rule_sort_policy_dispatch(
                rule, policy_dispatch_index_cache, policy_dispatch_index_cache_ref_count
            )

            if skip:
                continue

            table = "filter"
            # get table form rule
            for opt in ["-t", "--table"]:
                try:
                    i = rule.index(opt)
                except ValueError:
                    pass
                else:
                    if len(rule) >= i + 1:
                        rule.pop(i)
                        table = rule.pop(i)

            # we can not use joinArgs here, because it would use "'" instead
            # of '"' for the start and end of the string, this breaks
            # iptables-restore
            for i, element in enumerate(rule):
                for c in string.whitespace:
                    if c in element and not (
                        element.startswith('"') and element.endswith('"')
                    ):
                        rule[i] = '"%s"' % element

            table_rules.setdefault(table, []).append(rule)

        for table in table_rules:
            rules = table_rules[table]

            temp_file.write("*%s\n" % table)
            for rule in rules:
                temp_file.write(" ".join(rule) + "\n")
            temp_file.write("COMMIT\n")

        temp_file.close()

        stat = os.stat(temp_file.name)
        log.debug2(
            "%s: %s %s",
            self.__class__,
            self._restore_command,
            "%s: %d" % (temp_file.name, stat.st_size),
        )
        args = []
        if self.restore_wait_option:
            args.append(self.restore_wait_option)
        args.append("-n")

        (status, ret) = runProg(self._restore_command, args, stdin=temp_file.name)

        if log.getDebugLogLevel() > 2:
            lines = readfile(temp_file.name)
            if lines is not None:
                i = 1
                for line in lines:
                    log.debug3("%8d: %s" % (i, line), nofmt=1, nl=0)
                    if not line.endswith("\n"):
                        log.debug3("", nofmt=1)
                    i += 1

        os.unlink(temp_file.name)

        if status != 0:
            raise ValueError(
                "'%s %s' failed: %s" % (self._restore_command, " ".join(args), ret)
            )
        self.rich_rule_priority_counts = rich_rule_priority_counts
        self.policy_dispatch_index_cache = policy_dispatch_index_cache
        self.policy_dispatch_index_cache_ref_count = (
            policy_dispatch_index_cache_ref_count
        )

    def set_rule(self, rule, log_denied):
        # replace %%REJECT%%
        self._rule_replace(
            rule,
            "%%REJECT%%",
            ["REJECT", "--reject-with", DEFAULT_REJECT_TYPE[self.ipv]],
        )

        # replace %%ICMP%%
        self._rule_replace(rule, "%%ICMP%%", [ICMP[self.ipv]])

        # replace %%LOGTYPE%%
        try:
            i = rule.index("%%LOGTYPE%%")
        except ValueError:
            pass
        else:
            if log_denied == "off":
                return ""
            if log_denied in ["unicast", "broadcast", "multicast"]:
                rule[i : i + 1] = ["-m", "pkttype", "--pkt-type", log_denied]
            else:
                rule.pop(i)

        rich_rule_priority_counts = copy.deepcopy(self.rich_rule_priority_counts)
        policy_dispatch_index_cache = copy.deepcopy(self.policy_dispatch_index_cache)
        policy_dispatch_index_cache_ref_count = copy.deepcopy(
            self.policy_dispatch_index_cache_ref_count
        )
        self._set_rule_replace_priority(
            rule, rich_rule_priority_counts, "%%RICH_RULE_PRIORITY%%"
        )
        skip = self._set_rule_sort_policy_dispatch(
            rule, policy_dispatch_index_cache, policy_dispatch_index_cache_ref_count
        )

        output = ""
        if not skip:
            output = self.__run(rule)

        self.rich_rule_priority_counts = rich_rule_priority_counts
        self.policy_dispatch_index_cache = policy_dispatch_index_cache
        self.policy_dispatch_index_cache_ref_count = (
            policy_dispatch_index_cache_ref_count
        )
        return output

    def get_available_tables(self, table=None):
        ret = []
        tables = [table] if table else BUILT_IN_CHAINS.keys()
        for table in tables:
            if table in self.available_tables:
                ret.append(table)
            else:
                try:
                    self.__run(["-t", table, "-L", "-n"])
                    self.available_tables.append(table)
                    ret.append(table)
                except ValueError:
                    log.debug1(
                        "%s table '%s' does not exist (or not enough permission to check)."
                        % (self.ipv, table)
                    )

        return ret

    def _detect_wait_option(self):
        wait_option = ""
        ret = runProg(self._command, ["-w", "-L", "-n"])  # since iptables-1.4.20
        log.debug3(
            '%s: %s: probe for wait option (%s): ret=%u, output="%s"',
            self.__class__,
            self._command,
            "-w",
            ret[0],
            ret[1],
        )
        if ret[0] == 0:
            wait_option = "-w"  # wait for xtables lock
            ret = runProg(
                self._command, ["-w10", "-L", "-n"]
            )  # since iptables > 1.4.21
            log.debug3(
                '%s: %s: probe for wait option (%s): ret=%u, output="%s"',
                self.__class__,
                self._command,
                "-w10",
                ret[0],
                ret[1],
            )
            if ret[0] == 0:
                wait_option = "-w10"  # wait max 10 seconds
            log.debug2(
                "%s: %s will be using %s option.",
                self.__class__,
                self._command,
                wait_option,
            )

        return wait_option

    def _detect_restore_wait_option(self):
        temp_file = tempFile()
        temp_file.write("#foo")
        temp_file.close()

        wait_option = ""
        for test_option in ["-w", "--wait=2"]:
            ret = runProg(self._restore_command, [test_option], stdin=temp_file.name)
            log.debug3(
                '%s: %s: probe for wait option (%s): ret=%u, output="%s"',
                self.__class__,
                self._command,
                test_option,
                ret[0],
                ret[1],
            )
            if (
                ret[0] == 0
                and "invalid option" not in ret[1]
                and "unrecognized option" not in ret[1]
            ):
                wait_option = test_option
                break

        log.debug2(
            "%s: %s will be using %s option.",
            self.__class__,
            self._restore_command,
            wait_option,
        )

        os.unlink(temp_file.name)

        return wait_option

    def build_flush_rules(self):
        self.rich_rule_priority_counts = {}
        self.policy_dispatch_index_cache = {}
        self.policy_dispatch_index_cache_ref_count = {}
        rules = []
        for table in BUILT_IN_CHAINS.keys():
            if not self.get_available_tables(table):
                continue
            # Flush firewall rules: -F
            # Delete firewall chains: -X
            # Set counter to zero: -Z
            for flag in ["-F", "-X", "-Z"]:
                rules.append(["-t", table, flag])
        return rules

    def build_set_policy_rules(self, policy, policy_details):
        rules = []
        _policy = "DROP" if policy == "PANIC" else policy
        for table in BUILT_IN_CHAINS.keys():
            if not self.get_available_tables(table):
                continue
            if table == "nat":
                continue
            for chain in BUILT_IN_CHAINS[table]:
                if table == "filter":
                    p = policy_details[chain]
                    if p == "REJECT":
                        rules.append(["-t", table, "-A", chain, "-j", "REJECT"])
                        p = "DROP"
                else:
                    p = _policy
                rules.append(["-t", table, "-P", chain, p])
        return rules

    def supported_icmp_types(self, ipv=None):
        """Return ICMP types that are supported by the iptables/ip6tables command and kernel"""
        output = ""
        try:
            output = self.__run(
                ["-p", "icmp" if self.ipv == "ipv4" else "ipv6-icmp", "--help"]
            )
        except ValueError as ex:
            if self.ipv == "ipv4":
                log.debug1("iptables error: %s" % ex)
            else:
                log.debug1("ip6tables error: %s" % ex)

        return self._parse_supported_icmp_types(self.ipv, output)

    @staticmethod
    def _parse_supported_icmp_types(ipv, output):
        in_types = False
        ret = []
        for line in output.splitlines():
            if in_types:
                line = line.strip().lower()
                splits = line.split()
                for split in splits:
                    if split.startswith("(") and split.endswith(")"):
                        x = split[1:-1]
                    else:
                        x = split
                    if x not in ret:
                        ret.append(x)
            if (
                ipv == "ipv4"
                and line.startswith("Valid ICMP Types:")
                or ipv == "ipv6"
                and line.startswith("Valid ICMPv6 Types:")
            ):
                in_types = True
        return ret

    def build_default_tables(self):
        # nothing to do, they always exist
        return []

    def build_default_rules(self, log_denied="off"):
        default_rules = {}

        if self.get_available_tables("security"):
            default_rules["security"] = []
            self.our_chains["security"] = set()
            for chain in BUILT_IN_CHAINS["security"]:
                default_rules["security"].append("-N %s_direct" % chain)
                default_rules["security"].append("-A %s -j %s_direct" % (chain, chain))
                self.our_chains["security"].add("%s_direct" % chain)

        if self.get_available_tables("raw"):
            default_rules["raw"] = []
            self.our_chains["raw"] = set()
            for chain in BUILT_IN_CHAINS["raw"]:
                default_rules["raw"].append("-N %s_direct" % chain)
                default_rules["raw"].append("-A %s -j %s_direct" % (chain, chain))
                self.our_chains["raw"].add("%s_direct" % chain)

                if chain == "PREROUTING":
                    default_rules["raw"].append("-N %s_POLICIES" % (chain))
                    self.our_chains["raw"].update(set(["%s_POLICIES" % (chain)]))
                    default_rules["raw"].append("-A %s -j %s_POLICIES" % (chain, chain))

        if self.get_available_tables("mangle"):
            default_rules["mangle"] = []
            self.our_chains["mangle"] = set()
            for chain in BUILT_IN_CHAINS["mangle"]:
                default_rules["mangle"].append("-N %s_direct" % chain)
                default_rules["mangle"].append("-A %s -j %s_direct" % (chain, chain))
                self.our_chains["mangle"].add("%s_direct" % chain)

                if chain == "PREROUTING":
                    default_rules["mangle"].append("-N %s_POLICIES" % (chain))
                    self.our_chains["mangle"].update(set(["%s_POLICIES" % (chain)]))
                    default_rules["mangle"].append(
                        "-A %s -j %s_POLICIES" % (chain, chain)
                    )

        if self.get_available_tables("nat"):
            default_rules["nat"] = []
            self.our_chains["nat"] = set()
            for chain in BUILT_IN_CHAINS["nat"]:
                default_rules["nat"].append("-N %s_direct" % chain)
                default_rules["nat"].append("-A %s -j %s_direct" % (chain, chain))
                self.our_chains["nat"].add("%s_direct" % chain)

                default_rules["nat"].append("-N %s_POLICIES" % (chain))
                self.our_chains["nat"].update(set(["%s_POLICIES" % (chain)]))
                default_rules["nat"].append("-A %s -j %s_POLICIES" % (chain, chain))

        default_rules["filter"] = []
        self.our_chains["filter"] = set()
        default_rules["filter"].append(
            "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED,DNAT -j ACCEPT"
        )
        default_rules["filter"].append("-A INPUT -i lo -j ACCEPT")
        if log_denied != "off":
            default_rules["filter"].append(
                "-A INPUT -m conntrack --ctstate INVALID %%LOGTYPE%% -j LOG --log-prefix 'STATE_INVALID_DROP: '"
            )
        default_rules["filter"].append(
            "-A INPUT -m conntrack --ctstate INVALID -j DROP"
        )
        default_rules["filter"].append("-N INPUT_direct")
        default_rules["filter"].append("-A INPUT -j INPUT_direct")
        self.our_chains["filter"].update(set("INPUT_direct"))
        default_rules["filter"].append("-N INPUT_POLICIES")
        self.our_chains["filter"].update(set("INPUT_POLICIES"))
        default_rules["filter"].append("-A INPUT -j INPUT_POLICIES")
        if log_denied != "off":
            default_rules["filter"].append(
                "-A INPUT %%LOGTYPE%% -j LOG --log-prefix 'FINAL_REJECT: '"
            )
        default_rules["filter"].append("-A INPUT -j %%REJECT%%")

        default_rules["filter"].append(
            "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED,DNAT -j ACCEPT"
        )
        default_rules["filter"].append("-A FORWARD -i lo -j ACCEPT")
        if log_denied != "off":
            default_rules["filter"].append(
                "-A FORWARD -m conntrack --ctstate INVALID %%LOGTYPE%% -j LOG --log-prefix 'STATE_INVALID_DROP: '"
            )
        default_rules["filter"].append(
            "-A FORWARD -m conntrack --ctstate INVALID -j DROP"
        )
        default_rules["filter"].append("-N FORWARD_direct")
        default_rules["filter"].append("-A FORWARD -j FORWARD_direct")
        self.our_chains["filter"].update(set("FORWARD_direct"))
        default_rules["filter"].append("-N FORWARD_POLICIES")
        self.our_chains["filter"].update(set("FORWARD_POLICIES"))
        default_rules["filter"].append("-A FORWARD -j FORWARD_POLICIES")
        if log_denied != "off":
            default_rules["filter"].append(
                "-A FORWARD %%LOGTYPE%% -j LOG --log-prefix 'FINAL_REJECT: '"
            )
        default_rules["filter"].append("-A FORWARD -j %%REJECT%%")

        default_rules["filter"] += [
            "-N OUTPUT_direct",
            "-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A OUTPUT -o lo -j ACCEPT",
            "-A OUTPUT -j OUTPUT_direct",
        ]
        self.our_chains["filter"].update(set("OUTPUT_direct"))
        default_rules["filter"].append("-N OUTPUT_POLICIES")
        default_rules["filter"].append("-A OUTPUT -j OUTPUT_POLICIES")
        self.our_chains["filter"].update(set("OUTPUT_POLICIES"))

        final_default_rules = []
        for table in default_rules:
            if table not in self.get_available_tables():
                continue
            for rule in default_rules[table]:
                final_default_rules.append(["-t", table] + splitArgs(rule))

        return final_default_rules

    def get_zone_table_chains(self, table):
        if table == "filter":
            return {"INPUT", "FORWARD"}
        if table == "mangle":
            if "mangle" in self.get_available_tables():
                return {"PREROUTING"}
        if table == "nat":
            if "nat" in self.get_available_tables():
                return {"PREROUTING", "POSTROUTING"}
        if table == "raw":
            if "raw" in self.get_available_tables():
                return {"PREROUTING"}

        return {}

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
            if postrouting:
                ingress_zone = ""
                ingress_interface = ""

        egress_sort_order = 0  # 0 means input chain
        if egress_source:
            egress_sort_order = 1
        elif egress_interface or (p_obj.derived_from_zone and prerouting):
            egress_sort_order = 2
            if prerouting:
                egress_zone = ""
                egress_interface = ""

        # default zone is always sorted to last as it's a "catch-all"
        if ingress_interface == "+":
            ingress_priority = self._fw.zone.get_zone(ingress_zone).priority_max + 1
        if egress_interface == "+":
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
            return ["%%POLICY_SORT_KEY%%", egress + ingress + suffix + (policy,)]
        else:
            return ["%%POLICY_SORT_KEY%%", ingress + egress + suffix + (policy,)]

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
        add_del = {True: "-I", False: "-D"}[enable]
        p_obj = self._fw.policy.get_policy(policy)
        isSNAT = True if (table == "nat" and chain == "POSTROUTING") else False
        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX, isSNAT
        )
        prerouting = True if chain == "PREROUTING" else False
        postrouting = True if chain == "POSTROUTING" else False

        # iptables can not match a destination MAC
        if check_mac(egress_source) or (postrouting and check_mac(ingress_source)):
            return []

        rules = []

        rule = ["-t", table, add_del, f"{chain}_POLICIES"]

        # iptables-legacy cannot match -i in postrouting
        if ingress_interface and ingress_interface != "+" and not postrouting:
            rule.extend(["-i", ingress_interface])
        if egress_interface and egress_interface != "+" and not prerouting:
            rule.extend(["-o", egress_interface])
        if ingress_source:
            rule.extend(self._rule_addr_fragment("-s", ingress_source))
        if egress_source:
            rule.extend(self._rule_addr_fragment("-d", egress_source))

        if not last:
            rule.extend(["-j", _policy])
        elif table != "filter" or chain in ["PREROUTING", "OUTPUT"]:
            rule.extend(["-j", "RETURN"])
        elif p_obj.target in [
            DEFAULT_ZONE_TARGET,
            "ACCEPT",
            "REJECT",
            "%%REJECT%%",
            "DROP",
        ]:
            if self._fw.get_log_denied() != "off" and p_obj.target in [
                DEFAULT_ZONE_TARGET,
                "%%REJECT%%",
                "REJECT",
                "DROP",
            ]:
                _rule = rule[:]
                _log_suffix = "DROP" if p_obj.target == "DROP" else "REJECT"

                _rule.extend(
                    [
                        "%%LOGTYPE%%",
                        "-j",
                        "LOG",
                        "--log-prefix",
                        f"{_policy}_{_log_suffix}: ",
                    ]
                )
                _rule.extend(
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
                rules.append(_rule)

            if p_obj.target == DEFAULT_ZONE_TARGET:
                rule.extend(["-j", "REJECT"])
            else:
                rule.extend(["-j", p_obj.target])

        rule.extend(
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

        rules.append(rule)

        return rules

    def _rule_addr_fragment(self, opt, address, invert=False):
        if address.startswith("ipset:"):
            name = address[6:]
            if opt == "-d":
                opt = "dst"
            else:
                opt = "src"
            flags = ",".join([opt] * self._fw.ipset.get_dimension(name))
            return ["-m", "set", "--match-set", name, flags]
        elif check_mac(address):
            # outgoing can not be set
            if opt == "-d":
                raise FirewallError(INVALID_ADDR, "Can't match a destination MAC.")
            return ["-m", "mac", "--mac-source", address.upper()]
        else:
            if check_single_address("ipv6", address):
                address = normalizeIP6(address)
            elif check_address("ipv6", address):
                addr_split = address.split("/")
                address = normalizeIP6(addr_split[0]) + "/" + addr_split[1]
            return [opt, address]

    def build_policy_chain_rules(self, enable, policy, table, chain):
        add_del_chain = {True: "-N", False: "-X"}[enable]
        add_del_rule = {True: "-A", False: "-D"}[enable]
        isSNAT = True if (table == "nat" and chain == "POSTROUTING") else False
        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX, isSNAT=isSNAT
        )
        p_obj = self._fw.policy.get_policy(policy)

        self.our_chains[table].update(
            set(
                [
                    _policy,
                    "%s_log" % _policy,
                    "%s_deny" % _policy,
                    "%s_pre" % _policy,
                    "%s_post" % _policy,
                    "%s_allow" % _policy,
                ]
            )
        )

        rules = []
        rules.append([add_del_chain, _policy, "-t", table])
        rules.append([add_del_chain, "%s_pre" % _policy, "-t", table])
        rules.append([add_del_chain, "%s_log" % _policy, "-t", table])
        rules.append([add_del_chain, "%s_deny" % _policy, "-t", table])
        rules.append([add_del_chain, "%s_allow" % _policy, "-t", table])
        rules.append([add_del_chain, "%s_post" % _policy, "-t", table])
        rules.append([add_del_rule, _policy, "-t", table, "-j", "%s_pre" % _policy])
        rules.append([add_del_rule, _policy, "-t", table, "-j", "%s_log" % _policy])
        rules.append([add_del_rule, _policy, "-t", table, "-j", "%s_deny" % _policy])
        rules.append([add_del_rule, _policy, "-t", table, "-j", "%s_allow" % _policy])
        rules.append([add_del_rule, _policy, "-t", table, "-j", "%s_post" % _policy])

        if not p_obj.derived_from_zone and table == "filter":
            target = self._fw.policy._policies[policy].target

            if self._fw.get_log_denied() != "off":
                if target in ["REJECT", "%%REJECT%%"]:
                    rules.append(
                        [
                            add_del_rule,
                            _policy,
                            "-t",
                            table,
                            "%%LOGTYPE%%",
                            "-j",
                            "LOG",
                            "--log-prefix",
                            "%s_REJECT: " % _policy,
                        ]
                    )
                elif target == "DROP":
                    rules.append(
                        [
                            add_del_rule,
                            _policy,
                            "-t",
                            table,
                            "%%LOGTYPE%%",
                            "-j",
                            "LOG",
                            "--log-prefix",
                            "%s_DROP: " % _policy,
                        ]
                    )

            if target in ["ACCEPT", "REJECT", "%%REJECT%%", "DROP"]:
                rules.append([add_del_rule, _policy, "-t", table, "-j", target])

        if not enable:
            rules.reverse()

        return rules

    def _rule_limit(self, limit):
        if limit:
            return ["-m", "limit", "--limit", limit.value]
        return []

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
        if rich_rule.priority == 0:
            return []
        return ["%%RICH_RULE_PRIORITY%%", rich_rule.priority]

    def _rich_rule_log(self, policy, rich_rule, enable, table, rule_fragment):
        if not rich_rule.log:
            return []

        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX
        )

        add_del = {True: "-A", False: "-D"}[enable]

        chain_suffix = self._rich_rule_chain_suffix_from_log(rich_rule)
        rule = ["-t", table, add_del, "%s_%s" % (_policy, chain_suffix)]
        rule += self._rich_rule_priority_fragment(rich_rule)
        if isinstance(rich_rule.log, Rich_NFLog):
            rule += rule_fragment + ["-j", "NFLOG"]
            if rich_rule.log.group:
                rule += ["--nflog-group", rich_rule.log.group]
            if rich_rule.log.prefix:
                rule += ["--nflog-prefix", "%s" % rich_rule.log.prefix]
            if rich_rule.log.threshold:
                rule += ["--nflog-threshold", rich_rule.log.threshold]
        else:
            rule += rule_fragment + ["-j", "LOG"]
            if rich_rule.log.prefix:
                rule += ["--log-prefix", "%s" % rich_rule.log.prefix]
            if rich_rule.log.level:
                rule += ["--log-level", "%s" % rich_rule.log.level]
        rule += self._rule_limit(rich_rule.log.limit)

        return rule

    def _rich_rule_audit(self, policy, rich_rule, enable, table, rule_fragment):
        if not rich_rule.audit:
            return []

        add_del = {True: "-A", False: "-D"}[enable]

        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX
        )

        chain_suffix = self._rich_rule_chain_suffix_from_log(rich_rule)
        rule = ["-t", table, add_del, "%s_%s" % (_policy, chain_suffix)]
        rule += self._rich_rule_priority_fragment(rich_rule)
        rule += rule_fragment
        if isinstance(rich_rule.action, Rich_Accept):
            _type = "accept"
        elif isinstance(rich_rule.action, Rich_Reject):
            _type = "reject"
        elif isinstance(rich_rule.action, Rich_Drop):
            _type = "drop"
        else:
            _type = "unknown"
        rule += ["-j", "AUDIT", "--type", _type]
        rule += self._rule_limit(rich_rule.audit.limit)

        return rule

    def _rich_rule_action(self, policy, rich_rule, enable, table, rule_fragment):
        if not rich_rule.action:
            return []

        add_del = {True: "-A", False: "-D"}[enable]

        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX
        )

        chain_suffix = self._rich_rule_chain_suffix(rich_rule)
        chain = "%s_%s" % (_policy, chain_suffix)
        if isinstance(rich_rule.action, Rich_Accept):
            rule_action = ["-j", "ACCEPT"]
        elif isinstance(rich_rule.action, Rich_Reject):
            rule_action = ["-j", "REJECT"]
            if rich_rule.action.type:
                rule_action += ["--reject-with", rich_rule.action.type]
        elif isinstance(rich_rule.action, Rich_Drop):
            rule_action = ["-j", "DROP"]
        elif isinstance(rich_rule.action, Rich_Mark):
            table = "mangle"
            _policy = self._fw.policy.policy_base_chain_name(
                policy, table, POLICY_CHAIN_PREFIX
            )
            chain = "%s_%s" % (_policy, chain_suffix)
            rule_action = ["-j", "MARK", "--set-xmark", rich_rule.action.set]
        else:
            raise FirewallError(
                INVALID_RULE, "Unknown action %s" % type(rich_rule.action)
            )

        rule = ["-t", table, add_del, chain]
        rule += self._rich_rule_priority_fragment(rich_rule)
        rule += rule_fragment + rule_action
        rule += self._rule_limit(rich_rule.action.limit)

        return rule

    def _rich_rule_destination_fragment(self, rich_dest):
        if not rich_dest:
            return []

        rule_fragment = []
        if rich_dest.addr:
            if rich_dest.invert:
                rule_fragment.append("!")
            if check_single_address("ipv6", rich_dest.addr):
                rule_fragment += ["-d", normalizeIP6(rich_dest.addr)]
            elif check_address("ipv6", rich_dest.addr):
                addr_split = rich_dest.addr.split("/")
                rule_fragment += [
                    "-d",
                    normalizeIP6(addr_split[0]) + "/" + addr_split[1],
                ]
            else:
                rule_fragment += ["-d", rich_dest.addr]
        elif rich_dest.ipset:
            rule_fragment += ["-m", "set"]
            if rich_dest.invert:
                rule_fragment.append("!")
            flags = self._fw.zone._ipset_match_flags(rich_dest.ipset, "dst")
            rule_fragment += ["--match-set", rich_dest.ipset, flags]

        return rule_fragment

    def _rich_rule_source_fragment(self, rich_source):
        if not rich_source:
            return []

        rule_fragment = []
        if rich_source.addr:
            if rich_source.invert:
                rule_fragment.append("!")
            if check_single_address("ipv6", rich_source.addr):
                rule_fragment += ["-s", normalizeIP6(rich_source.addr)]
            elif check_address("ipv6", rich_source.addr):
                addr_split = rich_source.addr.split("/")
                rule_fragment += [
                    "-s",
                    normalizeIP6(addr_split[0]) + "/" + addr_split[1],
                ]
            else:
                rule_fragment += ["-s", rich_source.addr]
        elif hasattr(rich_source, "mac") and rich_source.mac:
            rule_fragment += ["-m", "mac"]
            if rich_source.invert:
                rule_fragment.append("!")
            rule_fragment += ["--mac-source", rich_source.mac]
        elif hasattr(rich_source, "ipset") and rich_source.ipset:
            rule_fragment += ["-m", "set"]
            if rich_source.invert:
                rule_fragment.append("!")
            flags = self._fw.zone._ipset_match_flags(rich_source.ipset, "src")
            rule_fragment += ["--match-set", rich_source.ipset, flags]

        return rule_fragment

    def build_policy_ports_rules(
        self, enable, policy, proto, port, destination=None, rich_rule=None
    ):
        add_del = {True: "-A", False: "-D"}[enable]
        table = "filter"
        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX
        )

        rule_fragment = ["-p", proto]
        if port:
            rule_fragment += ["--dport", "%s" % portStr(port)]
        if destination:
            rule_fragment += ["-d", destination]
        if rich_rule:
            rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
            rule_fragment += self._rich_rule_source_fragment(rich_rule.source)

        rules = []
        if rich_rule:
            rules.append(
                self._rich_rule_log(policy, rich_rule, enable, table, rule_fragment)
            )
            rules.append(
                self._rich_rule_audit(policy, rich_rule, enable, table, rule_fragment)
            )
            rules.append(
                self._rich_rule_action(policy, rich_rule, enable, table, rule_fragment)
            )
        else:
            rules.append(
                [add_del, "%s_allow" % (_policy), "-t", table]
                + rule_fragment
                + ["-j", "ACCEPT"]
            )

        return rules

    def build_policy_protocol_rules(
        self, enable, policy, protocol, destination=None, rich_rule=None
    ):
        add_del = {True: "-A", False: "-D"}[enable]
        table = "filter"
        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX
        )

        rule_fragment = ["-p", protocol]
        if destination:
            rule_fragment += ["-d", destination]
        if rich_rule:
            rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
            rule_fragment += self._rich_rule_source_fragment(rich_rule.source)

        rules = []
        if rich_rule:
            rules.append(
                self._rich_rule_log(policy, rich_rule, enable, table, rule_fragment)
            )
            rules.append(
                self._rich_rule_audit(policy, rich_rule, enable, table, rule_fragment)
            )
            rules.append(
                self._rich_rule_action(policy, rich_rule, enable, table, rule_fragment)
            )
        else:
            rules.append(
                [add_del, "%s_allow" % (_policy), "-t", table]
                + rule_fragment
                + ["-j", "ACCEPT"]
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
        add_del = {True: "-A", False: "-D"}[enable]

        rule_fragment = ["-p", "tcp", "--tcp-flags", "SYN,RST", "SYN"]
        if rich_rule:
            chain_suffix = self._rich_rule_chain_suffix(rich_rule)
            rule_fragment += self._rich_rule_priority_fragment(rich_rule)
            rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
            rule_fragment += self._rich_rule_source_fragment(rich_rule.source)

        if tcp_mss_clamp_value == "pmtu" or tcp_mss_clamp_value is None:
            rule_fragment += ["-j", "TCPMSS", "--clamp-mss-to-pmtu"]
        else:
            rule_fragment += ["-j", "TCPMSS", "--set-mss", tcp_mss_clamp_value]

        return [
            ["-t", "filter", add_del, "%s_%s" % (_policy, chain_suffix)] + rule_fragment
        ]

    def build_policy_source_ports_rules(
        self, enable, policy, proto, port, destination=None, rich_rule=None
    ):
        add_del = {True: "-A", False: "-D"}[enable]
        table = "filter"
        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX
        )

        rule_fragment = ["-p", proto]
        if port:
            rule_fragment += ["--sport", "%s" % portStr(port)]
        if destination:
            rule_fragment += ["-d", destination]
        if rich_rule:
            rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
            rule_fragment += self._rich_rule_source_fragment(rich_rule.source)

        rules = []
        if rich_rule:
            rules.append(
                self._rich_rule_log(policy, rich_rule, enable, table, rule_fragment)
            )
            rules.append(
                self._rich_rule_audit(policy, rich_rule, enable, table, rule_fragment)
            )
            rules.append(
                self._rich_rule_action(policy, rich_rule, enable, table, rule_fragment)
            )
        else:
            rules.append(
                [add_del, "%s_allow" % (_policy), "-t", table]
                + rule_fragment
                + ["-j", "ACCEPT"]
            )

        return rules

    def build_policy_helper_ports_rules(
        self, enable, policy, proto, port, destination, helper_name, module_short_name
    ):
        table = "raw"
        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX
        )
        add_del = {True: "-A", False: "-D"}[enable]

        rule = [add_del, "%s_allow" % (_policy), "-t", "raw", "-p", proto]
        if port:
            rule += ["--dport", "%s" % portStr(port)]
        if destination:
            rule += ["-d", destination]
        rule += ["-j", "CT", "--helper", module_short_name]

        return [rule]

    def build_zone_forward_rules(
        self, enable, zone, policy, table, interface=None, source=None
    ):
        add_del = {True: "-A", False: "-D"}[enable]
        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX
        )

        rules = []
        if interface:
            rules.append(
                [
                    "-t",
                    "filter",
                    add_del,
                    "%s_allow" % _policy,
                    "-o",
                    interface,
                    "-j",
                    "ACCEPT",
                ]
            )
        else:  # source
            # iptables can not match destination MAC
            if check_mac(source):
                return []

            rules.append(
                ["-t", "filter", add_del, "%s_allow" % _policy]
                + self._rule_addr_fragment("-d", source)
                + ["-j", "ACCEPT"]
            )
        return rules

    def build_policy_masquerade_rules(self, enable, policy, rich_rule=None):
        table = "nat"
        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX, isSNAT=True
        )

        add_del = {True: "-A", False: "-D"}[enable]

        rule_fragment = []
        if rich_rule:
            chain_suffix = self._rich_rule_chain_suffix(rich_rule)
            rule_fragment += self._rich_rule_priority_fragment(rich_rule)
            rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
            rule_fragment += self._rich_rule_source_fragment(rich_rule.source)
        else:
            chain_suffix = "allow"

        rules = []
        rules.append(
            ["-t", "nat", add_del, "%s_%s" % (_policy, chain_suffix)]
            + rule_fragment
            + ["!", "-o", "lo", "-j", "MASQUERADE"]
        )

        return rules

    def build_policy_forward_port_rules(
        self, enable, policy, port, protocol, toport, toaddr, rich_rule=None
    ):
        table = "nat"
        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX
        )
        add_del = {True: "-A", False: "-D"}[enable]

        to = ""
        if toaddr:
            if check_single_address("ipv6", toaddr):
                to += "[%s]" % normalizeIP6(toaddr)
            else:
                to += toaddr
        if toport and toport != "":
            to += ":%s" % portStr(toport, "-")

        rules = []
        rule_fragment = []
        port_fragment = ["-p", protocol, "--dport", portStr(port)]
        if rich_rule:
            chain_suffix = self._rich_rule_chain_suffix(rich_rule)
            rule_fragment = self._rich_rule_priority_fragment(rich_rule)
            rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
            rule_fragment += self._rich_rule_source_fragment(rich_rule.source)

            rules.append(
                self._rich_rule_log(
                    policy, rich_rule, enable, "nat", rule_fragment + port_fragment
                )
            )
        else:
            chain_suffix = "allow"

        rules.append(
            ["-t", "nat", add_del, "%s_%s" % (_policy, chain_suffix)]
            + rule_fragment
            + port_fragment
            + ["-j", "DNAT", "--to-destination", to]
        )

        return rules

    def build_policy_icmp_block_rules(self, enable, policy, ict, rich_rule=None):
        table = "filter"
        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX
        )
        add_del = {True: "-A", False: "-D"}[enable]

        if self.ipv == "ipv4":
            proto = ["-p", "icmp"]
            match = ["-m", "icmp", "--icmp-type", ict.name]
        else:
            proto = ["-p", "ipv6-icmp"]
            match = ["-m", "icmp6", "--icmpv6-type", ict.name]

        rules = []
        if self._fw.policy.query_icmp_block_inversion(policy):
            final_chain = "%s_allow" % (_policy)
            final_target = "ACCEPT"
        else:
            final_chain = "%s_deny" % (_policy)
            final_target = "%%REJECT%%"

        rule_fragment = []
        if rich_rule:
            rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
            rule_fragment += self._rich_rule_source_fragment(rich_rule.source)
        rule_fragment += proto + match

        if rich_rule:
            rules.append(
                self._rich_rule_log(policy, rich_rule, enable, table, rule_fragment)
            )
            rules.append(
                self._rich_rule_audit(policy, rich_rule, enable, table, rule_fragment)
            )
            if rich_rule.action:
                rules.append(
                    self._rich_rule_action(
                        policy, rich_rule, enable, table, rule_fragment
                    )
                )
            else:
                chain_suffix = self._rich_rule_chain_suffix(rich_rule)
                rules.append(
                    ["-t", table, add_del, "%s_%s" % (_policy, chain_suffix)]
                    + self._rich_rule_priority_fragment(rich_rule)
                    + rule_fragment
                    + ["-j", "%%REJECT%%"]
                )
        else:
            if self._fw.get_log_denied() != "off" and final_target != "ACCEPT":
                rules.append(
                    [add_del, final_chain, "-t", table]
                    + rule_fragment
                    + [
                        "%%LOGTYPE%%",
                        "-j",
                        "LOG",
                        "--log-prefix",
                        "%s_ICMP_BLOCK: " % policy,
                    ]
                )
            rules.append(
                [add_del, final_chain, "-t", table]
                + rule_fragment
                + ["-j", final_target]
            )

        return rules

    def build_policy_icmp_block_inversion_rules(self, enable, policy):
        table = "filter"
        _policy = self._fw.policy.policy_base_chain_name(
            policy, table, POLICY_CHAIN_PREFIX
        )

        rules = []
        rule_idx = 6

        if self._fw.policy.query_icmp_block_inversion(policy):
            ibi_target = "%%REJECT%%"

            if self._fw.get_log_denied() != "off":
                if enable:
                    rule = ["-I", _policy, str(rule_idx)]
                else:
                    rule = ["-D", _policy]

                rule = rule + [
                    "-t",
                    table,
                    "-p",
                    "%%ICMP%%",
                    "%%LOGTYPE%%",
                    "-j",
                    "LOG",
                    "--log-prefix",
                    "%s_ICMP_BLOCK: " % _policy,
                ]
                rules.append(rule)
                rule_idx += 1
        else:
            ibi_target = "ACCEPT"

        if enable:
            rule = ["-I", _policy, str(rule_idx)]
        else:
            rule = ["-D", _policy]
        rule = rule + ["-t", table, "-p", "%%ICMP%%", "-j", ibi_target]
        rules.append(rule)

        return rules

    def build_policy_rich_source_destination_rules(self, enable, policy, rich_rule):
        table = "filter"

        rule_fragment = []
        rule_fragment += self._rich_rule_destination_fragment(rich_rule.destination)
        rule_fragment += self._rich_rule_source_fragment(rich_rule.source)

        rules = []
        rules.append(
            self._rich_rule_log(policy, rich_rule, enable, table, rule_fragment)
        )
        rules.append(
            self._rich_rule_audit(policy, rich_rule, enable, table, rule_fragment)
        )
        rules.append(
            self._rich_rule_action(policy, rich_rule, enable, table, rule_fragment)
        )

        return rules

    def is_ipv_supported(self, ipv):
        return ipv == self.ipv


class ip6tables(ip4tables):
    ipv = "ipv6"
    name = "ip6tables"

    def build_rpfilter_rules(self, log_denied=False):
        rules = []
        rules.append(
            [
                "-I",
                "PREROUTING",
                "-t",
                "mangle",
                "-m",
                "rpfilter",
                "--invert",
                "--validmark",
                "-j",
                "DROP",
            ]
        )
        if log_denied != "off":
            rules.append(
                [
                    "-I",
                    "PREROUTING",
                    "-t",
                    "mangle",
                    "-m",
                    "rpfilter",
                    "--invert",
                    "--validmark",
                    "-j",
                    "LOG",
                    "--log-prefix",
                    "rpfilter_DROP: ",
                ]
            )
        rules.append(
            [
                "-I",
                "PREROUTING",
                "-t",
                "mangle",
                "-p",
                "ipv6-icmp",
                "--icmpv6-type=neighbour-solicitation",
                "-j",
                "ACCEPT",
            ]
        )  # RHBZ#1575431, kernel bug in 4.16-4.17
        rules.append(
            [
                "-I",
                "PREROUTING",
                "-t",
                "mangle",
                "-p",
                "ipv6-icmp",
                "--icmpv6-type=router-advertisement",
                "-j",
                "ACCEPT",
            ]
        )  # RHBZ#1058505
        return rules

    def build_rfc3964_ipv4_rules(self):
        daddr_list = [
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

        chain_name = "RFC3964_IPv4"
        self.our_chains["filter"].add(chain_name)

        rules = []
        rules.append(["-t", "filter", "-N", chain_name])
        for daddr in daddr_list:
            rules.append(
                [
                    "-t",
                    "filter",
                    "-I",
                    chain_name,
                    "-d",
                    daddr,
                    "-j",
                    "REJECT",
                    "--reject-with",
                    "addr-unreach",
                ]
            )
            if self._fw._log_denied in ["unicast", "all"]:
                rules.append(
                    [
                        "-t",
                        "filter",
                        "-I",
                        chain_name,
                        "-d",
                        daddr,
                        "-j",
                        "LOG",
                        "--log-prefix",
                        "RFC3964_IPv4_REJECT: ",
                    ]
                )

        # Inject into FORWARD and OUTPUT chains
        rules.append(["-t", "filter", "-I", "OUTPUT", "4", "-j", chain_name])
        rules.append(
            [
                "-t",
                "filter",
                "-I",
                "FORWARD",
                "6" if self._fw.get_log_denied() != "off" else "5",
                "-j",
                chain_name,
            ]
        )
        return rules
