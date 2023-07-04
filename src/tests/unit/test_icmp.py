# SPDX-License-Identifier: GPL-2.0-or-later

import firewall.core.icmp


def test_icmp():
    assert not firewall.core.icmp.check_icmpv6_name("foo")
    assert firewall.core.icmp.check_icmpv6_name("neigbour-solicitation")
