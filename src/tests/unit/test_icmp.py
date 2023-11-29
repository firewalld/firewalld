# SPDX-License-Identifier: GPL-2.0-or-later

import os

import firewall.core.icmp
import firewall.core.io.icmptype
import firewall.core.ipXtables
import firewall.core.nftables

from tests.unit import helpers


def test_icmp():
    assert not firewall.core.icmp.check_icmpv6_name("foo")
    assert firewall.core.icmp.check_icmpv6_name("neigbour-solicitation")


###############################################################################


def _iptables_parse_supported_icmp_types_4():
    iptables_output = """iptables v1.8.9 (nf_tables)

Usage: iptables -[ACD] chain rule-specification [options]
       iptables -I chain [rulenum] rule-specification [options]
       iptables -R chain rulenum rule-specification [options]
       iptables -D chain rulenum [options]
       iptables -[LS] [chain [rulenum]] [options]
       iptables -[FZ] [chain] [options]
       iptables -[NX] chain
       iptables -E old-chain-name new-chain-name
       iptables -P chain target [options]
       iptables -h (print this help information)

Commands:
Either long or short options are allowed.
  --append  -A chain\t\tAppend to chain
  --check   -C chain\t\tCheck for the existence of a rule
  --delete  -D chain\t\tDelete matching rule from chain
  --delete  -D chain rulenum
\t\t\t\tDelete rule rulenum (1 = first) from chain
  --insert  -I chain [rulenum]
\t\t\t\tInsert in chain as rulenum (default 1=first)
  --replace -R chain rulenum
\t\t\t\tReplace rule rulenum (1 = first) in chain
  --list    -L [chain [rulenum]]
\t\t\t\tList the rules in a chain or all chains
  --list-rules -S [chain [rulenum]]
\t\t\t\tPrint the rules in a chain or all chains
  --flush   -F [chain]\t\tDelete all rules in  chain or all chains
  --zero    -Z [chain [rulenum]]
\t\t\t\tZero counters in chain or all chains
  --new     -N chain\t\tCreate a new user-defined chain
  --delete-chain
            -X [chain]\t\tDelete a user-defined chain
  --policy  -P chain target
\t\t\t\tChange policy on chain to target
  --rename-chain
            -E old-chain new-chain
\t\t\t\tChange chain name, (moving any references)

Options:
    --ipv4\t-4\t\tNothing (line is ignored by ip6tables-restore)
    --ipv6\t-6\t\tError (line is ignored by iptables-restore)
[!] --protocol\t-p proto\tprotocol: by number or name, eg. `tcp'
[!] --source\t-s address[/mask][...]
\t\t\t\tsource specification
[!] --destination -d address[/mask][...]
\t\t\t\tdestination specification
[!] --in-interface -i input name[+]
\t\t\t\tnetwork interface name ([+] for wildcard)
 --jump\t-j target
\t\t\t\ttarget for rule (may load target extension)
  --goto      -g chain
\t\t\t       jump to chain with no return
  --match\t-m match
\t\t\t\textended match (may load extension)
  --numeric\t-n\t\tnumeric output of addresses and ports
[!] --out-interface -o output name[+]
\t\t\t\tnetwork interface name ([+] for wildcard)
  --table\t-t table\ttable to manipulate (default: `filter')
  --verbose\t-v\t\tverbose mode
  --wait\t-w [seconds]\tmaximum wait to acquire xtables lock before give up
  --line-numbers\t\tprint line numbers when listing
  --exact\t-x\t\texpand numbers (display exact values)
[!] --fragment\t-f\t\tmatch second or further fragments only
  --modprobe=<command>\t\ttry to insert modules using this command
  --set-counters -c PKTS BYTES\tset the counter during insert/append
[!] --version\t-V\t\tprint package version.

icmp match options:
[!] --icmp-type typename\tmatch icmp type
[!] --icmp-type type[/code]\t(or numeric type or type/code)
Valid ICMP Types:
any
echo-reply (pong)
destination-unreachable
   network-unreachable
   host-unreachable
   protocol-unreachable
   port-unreachable
   fragmentation-needed
   source-route-failed
   network-unknown
   host-unknown
   network-prohibited
   host-prohibited
   TOS-network-unreachable
   TOS-host-unreachable
   communication-prohibited
   host-precedence-violation
   precedence-cutoff
source-quench
redirect
   network-redirect
   host-redirect
   TOS-network-redirect
   TOS-host-redirect
echo-request (ping)
router-advertisement
router-solicitation
time-exceeded (ttl-exceeded)
   ttl-zero-during-transit
   ttl-zero-during-reassembly
parameter-problem
   ip-header-bad
   required-option-missing
timestamp-request
timestamp-reply
address-mask-request
address-mask-reply
"""

    r = firewall.core.ipXtables.ip4tables._parse_supported_icmp_types(
        "ipv4", iptables_output
    )
    assert r == [
        "any",
        "echo-reply",
        "pong",
        "destination-unreachable",
        "network-unreachable",
        "host-unreachable",
        "protocol-unreachable",
        "port-unreachable",
        "fragmentation-needed",
        "source-route-failed",
        "network-unknown",
        "host-unknown",
        "network-prohibited",
        "host-prohibited",
        "tos-network-unreachable",
        "tos-host-unreachable",
        "communication-prohibited",
        "host-precedence-violation",
        "precedence-cutoff",
        "source-quench",
        "redirect",
        "network-redirect",
        "host-redirect",
        "tos-network-redirect",
        "tos-host-redirect",
        "echo-request",
        "ping",
        "router-advertisement",
        "router-solicitation",
        "time-exceeded",
        "ttl-exceeded",
        "ttl-zero-during-transit",
        "ttl-zero-during-reassembly",
        "parameter-problem",
        "ip-header-bad",
        "required-option-missing",
        "timestamp-request",
        "timestamp-reply",
        "address-mask-request",
        "address-mask-reply",
    ]

    return r


def _iptables_parse_supported_icmp_types_6():
    iptables_output = """ip6tables v1.8.9 (nf_tables)

Usage: ip6tables -[ACD] chain rule-specification [options]
       ip6tables -I chain [rulenum] rule-specification [options]
       ip6tables -R chain rulenum rule-specification [options]
       ip6tables -D chain rulenum [options]
       ip6tables -[LS] [chain [rulenum]] [options]
       ip6tables -[FZ] [chain] [options]
       ip6tables -[NX] chain
       ip6tables -E old-chain-name new-chain-name
       ip6tables -P chain target [options]
       ip6tables -h (print this help information)

Commands:
Either long or short options are allowed.
  --append  -A chain\t\tAppend to chain
  --check   -C chain\t\tCheck for the existence of a rule
  --delete  -D chain\t\tDelete matching rule from chain
  --delete  -D chain rulenum
\t\t\t\tDelete rule rulenum (1 = first) from chain
  --insert  -I chain [rulenum]
\t\t\t\tInsert in chain as rulenum (default 1=first)
  --replace -R chain rulenum
\t\t\t\tReplace rule rulenum (1 = first) in chain
  --list    -L [chain [rulenum]]
\t\t\t\tList the rules in a chain or all chains
  --list-rules -S [chain [rulenum]]
\t\t\t\tPrint the rules in a chain or all chains
  --flush   -F [chain]\t\tDelete all rules in  chain or all chains
  --zero    -Z [chain [rulenum]]
\t\t\t\tZero counters in chain or all chains
  --new     -N chain\t\tCreate a new user-defined chain
  --delete-chain
            -X [chain]\t\tDelete a user-defined chain
  --policy  -P chain target
\t\t\t\tChange policy on chain to target
  --rename-chain
            -E old-chain new-chain
\t\t\t\tChange chain name, (moving any references)

Options:
    --ipv4\t-4\t\tError (line is ignored by ip6tables-restore)
    --ipv6\t-6\t\tNothing (line is ignored by iptables-restore)
[!] --protocol\t-p proto\tprotocol: by number or name, eg. `tcp'
[!] --source\t-s address[/mask][...]
\t\t\t\tsource specification
[!] --destination -d address[/mask][...]
\t\t\t\tdestination specification
[!] --in-interface -i input name[+]
\t\t\t\tnetwork interface name ([+] for wildcard)
 --jump\t-j target
\t\t\t\ttarget for rule (may load target extension)
  --goto      -g chain
\t\t\t       jump to chain with no return
  --match\t-m match
\t\t\t\textended match (may load extension)
  --numeric\t-n\t\tnumeric output of addresses and ports
[!] --out-interface -o output name[+]
\t\t\t\tnetwork interface name ([+] for wildcard)
  --table\t-t table\ttable to manipulate (default: `filter')
  --verbose\t-v\t\tverbose mode
  --wait\t-w [seconds]\tmaximum wait to acquire xtables lock before give up
  --line-numbers\t\tprint line numbers when listing
  --exact\t-x\t\texpand numbers (display exact values)
  --modprobe=<command>\t\ttry to insert modules using this command
  --set-counters -c PKTS BYTES\tset the counter during insert/append
[!] --version\t-V\t\tprint package version.

icmpv6 match options:
[!] --icmpv6-type typename\tmatch icmpv6 type
\t\t\t\t(or numeric type or type/code)
Valid ICMPv6 Types:
destination-unreachable
   no-route
   communication-prohibited
   beyond-scope
   address-unreachable
   port-unreachable
   failed-policy
   reject-route
packet-too-big
time-exceeded (ttl-exceeded)
   ttl-zero-during-transit
   ttl-zero-during-reassembly
parameter-problem
   bad-header
   unknown-header-type
   unknown-option
echo-request (ping)
echo-reply (pong)
router-solicitation
router-advertisement
neighbour-solicitation (neighbor-solicitation)
neighbour-advertisement (neighbor-advertisement)
redirect
"""

    r = firewall.core.ipXtables.ip4tables._parse_supported_icmp_types(
        "ipv6", iptables_output
    )
    assert r == [
        "destination-unreachable",
        "no-route",
        "communication-prohibited",
        "beyond-scope",
        "address-unreachable",
        "port-unreachable",
        "failed-policy",
        "reject-route",
        "packet-too-big",
        "time-exceeded",
        "ttl-exceeded",
        "ttl-zero-during-transit",
        "ttl-zero-during-reassembly",
        "parameter-problem",
        "bad-header",
        "unknown-header-type",
        "unknown-option",
        "echo-request",
        "ping",
        "echo-reply",
        "pong",
        "router-solicitation",
        "router-advertisement",
        "neighbour-solicitation",
        "neighbor-solicitation",
        "neighbour-advertisement",
        "neighbor-advertisement",
        "redirect",
    ]

    return r


def test_iptables_parse_supported_icmp_types():
    _iptables_parse_supported_icmp_types_4()
    _iptables_parse_supported_icmp_types_6()


###############################################################################


def _get_destination(xmlobj):
    d = xmlobj.destination
    if d == []:
        d = ["ipv4", "ipv6"]

    assert d in (
        ["ipv4"],
        ["ipv6"],
        ["ipv4", "ipv6"],
    )

    return d


def _icmptypes_load_file(dirname, file):
    assert dirname
    assert file
    assert file.endswith(".xml")
    assert "/" not in file

    full_name = os.path.join(dirname, file)

    assert os.path.exists(dirname)
    assert os.path.exists(full_name)

    xmlobj = firewall.core.io.icmptype.icmptype_reader(file, dirname)
    assert xmlobj

    assert xmlobj.name == file[: -len(".xml")]
    assert xmlobj.path == dirname
    _get_destination(xmlobj)
    return xmlobj


def _test_icmptypes_nftables(xmlobjs):
    nft = firewall.core.nftables.ICMP_TYPES_FRAGMENTS
    assert set(nft.keys()) == set(["ipv4", "ipv6"])

    # Check that all .xml files are listed in firewall.core.nftables.ICMP_TYPES_FRAGMENTS
    for xmlobj in xmlobjs:
        for ipx in _get_destination(xmlobj):
            assert xmlobj.name in nft[ipx], (
                f'XML file "{xmlobj.path}/{xmlobj.name}.xml" has no entry '
                f'"{xmlobj.name}" in firewall.core.nftables.ICMP_TYPES_FRAGMENTS["{ipx}"]'
            )

    # Check that all firewall.core.nftables.ICMP_TYPES_FRAGMENTS have an .xml file.
    for ipx in nft:
        assert ipx in ["ipv4", "ipv6"]
        for icmp_type in nft[ipx]:
            l = [xmlobj for xmlobj in xmlobjs if xmlobj.name == icmp_type]
            assert len(l) == 1
            xmlobj = l[0]
            assert ipx in _get_destination(xmlobj)


def _test_icmptypes_ipset(xmlobjs):
    # firewall.core.icmp is only used by src/firewall/core/io/ipset.py, and
    # hard-codes valid ICMP types. It's not used anywhere else.
    #
    # It should still correspond to our XML files, where every entry here has
    # an XML file, but some XML files are not found here.
    types4 = firewall.core.icmp.ICMP_TYPES
    types6 = firewall.core.icmp.ICMPV6_TYPES
    for xmlobj in xmlobjs:
        should_have4 = "ipv4" in _get_destination(xmlobj)
        should_have6 = "ipv6" in _get_destination(xmlobj)
        assert should_have4 or should_have6
        has4 = xmlobj.name in types4
        has6 = xmlobj.name in types6
        if not has4 and not has6:
            # We have XML files for those ICMP types, but they are not in
            # firewall.core.icmp.{ICMP_TYPES,ICMPV6_TYPES}.
            assert xmlobj.name in [
                "beyond-scope",
                "destination-unreachable",
                "failed-policy",
                "mld-listener-done",
                "mld-listener-query",
                "mld-listener-report",
                "mld2-listener-report",
                "parameter-problem",
                "reject-route",
                "time-exceeded",
                "tos-host-redirect",
                "tos-host-unreachable",
                "tos-network-redirect",
                "tos-network-unreachable",
            ]
            continue
        if has4 != should_have4:
            # The file "redirect.xml" is both for IPv4 and IPv6. However, it is
            # only in firewall.core.icmp.ICMPV6_TYPES not
            # firewall.core.icmp.ICMP_TYPES.
            assert xmlobj.name in [
                "redirect",
            ]
            assert should_have4
            assert should_have6
        assert has6 == should_have6


def test_icmptypes():
    dirname = helpers.srcdir("config/icmptypes")
    files = [f for f in os.listdir(dirname) if f.endswith(".xml")]
    assert files
    xmlobjs = []
    for file in files:
        xmlobjs.append(_icmptypes_load_file(dirname, file))

    _test_icmptypes_nftables(xmlobjs)
    _test_icmptypes_ipset(xmlobjs)
