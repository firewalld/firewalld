import pytest

import firewall.errors
import firewall.core.rich


###############################################################################


def _exp_rule_check_1(exp_rule, rule):
    assert (
        exp_rule.rule_str
        == 'rule family="ipv4" source address="10.1.1.0/24" destination address="192.168.1.0/24" accept'
    )
    assert type(rule.action) is firewall.core.rich.Rich_Accept
    assert rule.action.limit is None
    assert rule.priority == 0
    assert rule.element is None


def _exp_rule_check_2(exp_rule, rule):
    assert (
        exp_rule.rule_str
        == 'rule family="ipv6" source address="1:2:3:4:6::" icmp-block name="redirect" log prefix="redirected: " level="info" limit value="4/m"'
    )
    s = rule.element
    assert type(s) is firewall.core.rich.Rich_IcmpBlock
    assert s.name == "redirect"


def _exp_rule_check_3(exp_rule, rule):
    assert (
        exp_rule.rule_str
        == 'rule family="ipv4" port port="3333" protocol="udp" nflog prefix="port-3333: " queue-size=65535 accept priority=5'
    )
    assert rule.family == "ipv4"
    assert rule.priority == 5


class ExpRule:
    def __init__(self, rule_str, rule_id=None, invalid=False, tokens=None, check=None):
        self.rule_str = rule_str
        self.invalid = invalid
        self.tokens = tokens
        self._check = check
        self.rule_id = rule_id

    def check(self, rule):
        if self._check is not None:
            self._check(self, rule)


EXP_RULE_LIST = [
    ExpRule("", invalid=True),
    ExpRule("rule", invalid=True),
    ExpRule(
        'rule protocol value="ah" reject',
        tokens=[
            {"element": "rule"},
            {"element": "protocol"},
            {"attr_name": "value", "attr_value": "ah"},
            {"element": "reject"},
            {"element": firewall.core.rich.EOL},
        ],
    ),
    ExpRule('rule protocol value="esp" accept'),
    ExpRule(
        "rule protocol value=sctp log",
        'rule protocol value="sctp" log',
    ),
    ExpRule('rule protocol value="igmp" log'),
    ExpRule(
        'rule family="ipv4" source address="192.168.0.0/24" service name="tftp" log prefix="tftp: " level="info" limit value="1/m" accept'
    ),
    ExpRule(
        'rule family="ipv4" source not address="192.168.0.0/24" service name="dns" log prefix="dns: " level="info" limit value="2/m" drop'
    ),
    ExpRule(
        'rule family="ipv4" source address="192.168.0.0/24" service name="irc" nflog prefix="irc: " group=1000 queue-size=10 limit value="1/m" accept'
    ),
    ExpRule(
        'rule family="ipv4" source not address="192.168.0.0/24" service name="mysql" nflog prefix="mysql: " queue-size=100 limit value="2/m" drop'
    ),
    ExpRule(
        'rule family="ipv4" port port="2222" protocol="tcp" nflog prefix="port-2222: " queue-size=0 drop'
    ),
    ExpRule(
        'rule family="ipv4" port port="3333" protocol="udp" nflog prefix="port-3333: " queue-size=65535 accept'
    ),
    ExpRule(
        'rule family="ipv4" port port="3333" protocol="udp" nflog prefix="port-3333: " queue-size=65535 accept priority=5',
        check=_exp_rule_check_3,
    ),
    ExpRule(
        'rule family="ipv6" source address="1:2:3:4:6::" service name="radius" log prefix="dns -- " level="info" limit value="3/m" reject type="icmp6-addr-unreachable" limit value="20/m"'
    ),
    ExpRule(
        'rule family="ipv6" source address="1:2:3:4:6::" port port="4011" protocol="tcp" log prefix="port 4011: " level="info" limit value="4/m" drop'
    ),
    ExpRule(
        'rule family="ipv6" source address="1:2:3:4:6::" port port="4011" protocol="tcp" log prefix="port 4011: " level="info" limit value="4000000/m" drop',
        invalid=True,
    ),
    ExpRule(
        'rule family="ipv6" source address="1:2:3:4:6::" forward-port port="4011" protocol="tcp" to-port="4012" to-addr="1::2:3:4:7"'
    ),
    ExpRule(
        'rule family="ipv6" source address="1:2:3:4:6::" icmp-block name="redirect" log prefix="redirected: " level="info" limit value="4/m"',
        check=_exp_rule_check_2,
    ),
    ExpRule(
        'rule family="ipv6" source address="1:2:3:4::/64" destination address="1:2:3:5::/64" accept'
    ),
    ExpRule('rule family="ipv6" masquerade'),
    ExpRule(
        'rule family="ipv4" destination address="1.2.3.4" forward-port port="4011" protocol="tcp" to-port="4012" to-addr="9.8.7.6"'
    ),
    ExpRule(
        'rule family="ipv4" source address="192.168.0.0/24" icmp-block name="source-quench" log prefix="source-quench: " level="info" limit value="4/m"'
    ),
    ExpRule('rule family="ipv4" source address="192.168.1.0/24" masquerade'),
    ExpRule(
        'rule family="ipv4" source address="10.1.1.0/24" destination address="192.168.1.0/24" accept',
        check=_exp_rule_check_1,
    ),
    ExpRule('rule family="ipv4" destination address="192.168.1.0/24" masquerade'),
    ExpRule(
        'rule forward-port port="2222" to-port="22" to-addr="192.168.100.2" protocol="tcp" family="ipv4" source address="192.168.2.100"',
        tokens=[
            {"element": "rule"},
            {"element": "forward-port"},
            {"attr_name": "port", "attr_value": "2222"},
            {"attr_name": "to-port", "attr_value": "22"},
            {"attr_name": "to-addr", "attr_value": "192.168.100.2"},
            {"attr_name": "protocol", "attr_value": "tcp"},
            {"attr_name": "family", "attr_value": "ipv4"},
            {"element": "source"},
            {"attr_name": "address", "attr_value": "192.168.2.100"},
            {"element": firewall.core.rich.EOL},
        ],
    ),
    ExpRule(
        'rule forward-port port="66" to-port="666" to-addr="192.168.100.2" protocol="sctp" family="ipv4" source address="192.168.2.100"'
    ),
    ExpRule(
        'rule forward-port port="99" to-port="999" to-addr="1::2:3:4:7" protocol="dccp" family="ipv6" source address="1:2:3:4:6::"',
        tokens=[
            {"element": "rule"},
            {"element": "forward-port"},
            {"attr_name": "port", "attr_value": "99"},
            {"attr_name": "to-port", "attr_value": "999"},
            {"attr_name": "to-addr", "attr_value": "1::2:3:4:7"},
            {"attr_name": "protocol", "attr_value": "dccp"},
            {"attr_name": "family", "attr_value": "ipv6"},
            {"element": "source"},
            {"attr_name": "address", "attr_value": "1:2:3:4:6::"},
            {"element": firewall.core.rich.EOL},
        ],
    ),
    ExpRule(
        'rule forward-port port="99" to-port="10999" to-addr="1::2:3:4:7" protocol="dccp" family="ipv6" source address="1:2:3:4:6::"',
        tokens=[
            {"element": "rule"},
            {"element": "forward-port"},
            {"attr_name": "port", "attr_value": "99"},
            {"attr_name": "to-port", "attr_value": "10999"},
            {"attr_name": "to-addr", "attr_value": "1::2:3:4:7"},
            {"attr_name": "protocol", "attr_value": "dccp"},
            {"attr_name": "family", "attr_value": "ipv6"},
            {"element": "source"},
            {"attr_name": "address", "attr_value": "1:2:3:4:6::"},
            {"element": firewall.core.rich.EOL},
        ],
    ),
    ExpRule(
        'rule family="ipv4" port port="222" protocol="tcp" mark set="0xff"',
        'rule family="ipv4" port port="222" protocol="tcp" mark set=0xff',
    ),
    ExpRule(
        'rule service name="ftp" audit limit value="1/m" accept',
        'rule service name="ftp" audit limit value="1/m" accept',
        tokens=[
            {"element": "rule"},
            {"element": "service"},
            {"attr_name": "name", "attr_value": "ftp"},
            {"element": "audit"},
            {"element": "limit"},
            {"attr_name": "value", "attr_value": "1/m"},
            {"element": "accept"},
            {"element": firewall.core.rich.EOL},
        ],
    ),
    ExpRule(
        'rule service name="ftp" audit limit value="1 /m" accept',
        'rule service name="ftp" audit limit value="1 /m" accept',
        tokens=[
            {"element": "rule"},
            {"element": "service"},
            {"attr_name": "name", "attr_value": "ftp"},
            {"element": "audit"},
            {"element": "limit"},
            {"attr_name": "value", "attr_value": "1 /m"},
            {"element": "accept"},
            {"element": firewall.core.rich.EOL},
        ],
    ),
    ExpRule('name="dns" accept', invalid=True),
    ExpRule('protocol value="ah" reject', invalid=True),
    ExpRule(
        'rule protocol value="ah" reject type="icmp-host-prohibited"', invalid=True
    ),
    ExpRule('rule family="ipv4" protocol value="ah" reject type="dummy"', invalid=True),
    ExpRule("rule bad_element", invalid=True),
    ExpRule('rule family="ipv5"', invalid=True),
    ExpRule('rule name="dns" accept', invalid=True),
    ExpRule('rule protocol="ah" accept', invalid=True),
    ExpRule(
        'rule protocol value="ah" accept drop',
        invalid=True,
        tokens=[
            {"element": "rule"},
            {"element": "protocol"},
            {"attr_name": "value", "attr_value": "ah"},
            {"element": "accept"},
            {"element": "drop"},
            {"element": firewall.core.rich.EOL},
        ],
    ),
    ExpRule('rule service name="radius" port port="4011" reject', invalid=True),
    ExpRule('rule service bad_attribute="dns"', invalid=True),
    ExpRule('rule protocol value="igmp" log level="eror"', invalid=True),
    ExpRule('family="ipv6" accept', invalid=True),
    ExpRule(
        'rule source address="1:2:3:4:6::" icmp-block name="redirect" log level="info" limit value="1/2m"',
        invalid=True,
    ),
    ExpRule(
        'rule family="ipv6" source address="1:2:3:4:6::" icmp-block name="redirect" log level="info" limit value="1/2m"',
        invalid=True,
    ),
    ExpRule('rule protocol value="esp"', invalid=True),
    ExpRule('rule family="ipv4" masquerade drop', invalid=True),
    ExpRule('rule family="ipv4" icmp-block name="redirect" accept', invalid=True),
    ExpRule(
        'rule forward-port port="2222" to-port="22" protocol="tcp" family="ipv4" accept',
        invalid=True,
    ),
    ExpRule(
        'rule service name="ssh" log prefix="RRClag4hrBx9XZXk+46c6QavQehyRGdy3tjs7gzc+xfSzsd2smjoQ2NCPami6zVyjHtPGziBuqSWT0KII7QbHkwjNMr9pzbcbPue9PMTb5zXlMPphDjeuDdC3QTCH9rGQHooa9LiDWr+DqNPkBs+vb8r50eb+yEQIyhQaiDrQ0sc" drop',
        invalid=True,
    ),
    ExpRule('rule protocol value="sctp" nflog group=-1 drop', invalid=True),
    ExpRule(
        'rule family="ipv4" service name="https" nflog queue-size=-1 drop', invalid=True
    ),
    ExpRule(
        'rule family="ipv6" service name="https" nflog queue-size=65536 drop',
        invalid=True,
    ),
    ExpRule(
        'rule protocol value="igmp" log EOL bogus',
        invalid=True,
        tokens=[
            {"element": "rule"},
            {"element": "protocol"},
            {"attr_name": "value", "attr_value": "igmp"},
            {"element": "log"},
            {"element": "EOL"},
            {"element": "bogus"},
            {"element": firewall.core.rich.EOL},
        ],
    ),
]


def test_rich_rule_lexer():
    # Test lexing rule strings.
    for r in EXP_RULE_LIST:
        s1 = r.rule_str

        tokens = firewall.core.rich.Rich_Rule._lexer(s1)

        assert tokens
        if r.tokens is not None:
            assert tokens == r.tokens


def test_rich_rule_parse():
    for r in EXP_RULE_LIST:
        s1 = r.rule_str

        if r.invalid:
            # This rule is invalid. Check that we fail, and skip.
            with pytest.raises(firewall.errors.FirewallError):
                firewall.core.rich.Rich_Rule(rule_str=s1)
            continue

        rule1 = firewall.core.rich.Rich_Rule(rule_str=s1)

        # Stringify/normalize the rule, and parse that string again. And check
        # that stringifying once more, gives the same again.
        s2 = str(rule1)

        if r.rule_id is not None:
            assert r.rule_id == s2

        rule2 = firewall.core.rich.Rich_Rule(rule_str=s2)
        assert s2 == str(rule2)

        r.check(rule1)


###############################################################################


def test_rich_rule_parse_2():
    rule1 = firewall.core.rich.Rich_Rule(
        family="ipv4",
        priority=44,
        rule_str='rule family="ipv4" port port="3333" protocol="udp" nflog prefix="port-3333: " queue-size=65535 accept priority=5',
    )
    assert rule1.family == "ipv4"
    assert rule1.priority == 44

    rule1 = firewall.core.rich.Rich_Rule(
        family="ipv4",
        priority=44,
        rule_str='rule family="ipv4" port port="3333" protocol="udp" nflog prefix="port-3333: " queue-size=65535 accept',
    )
    assert rule1.family == "ipv4"
    assert rule1.priority == 44

    with pytest.raises(firewall.errors.FirewallError):
        rule1 = firewall.core.rich.Rich_Rule(
            family="ipv6",
            priority=44,
            rule_str='rule family="ipv4" port port="3333" protocol="udp" nflog prefix="port-3333: " queue-size=65535 accept',
        )

    e = firewall.core.rich._Rich_Log()
    assert e.limit is None

    e = firewall.core.rich._Rich_Log(limit=5)
    assert e.limit == 5
