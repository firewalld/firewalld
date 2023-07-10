# SPDX-License-Identifier: GPL-2.0-or-later

import pytest

import firewall.core.ipset
import firewall.errors

###############################################################################


def test_ipset_type_parse():
    with pytest.raises(firewall.errors.FirewallError):
        firewall.core.ipset.ipset_type_parse("foo:")
    with pytest.raises(firewall.errors.FirewallError):
        firewall.core.ipset.ipset_type_parse("hash:")
    assert firewall.core.ipset.ipset_type_parse("hash:net") == ["net"]
    assert firewall.core.ipset.ipset_type_parse("hash:ip,port") == [
        "ip",
        "port",
    ]

    assert firewall.core.ipset.ipset_entry_split_with_type(
        "1.2.3.4,80", "hash:ip,port"
    ) == (["1.2.3.4", "80"], ["ip", "port"])
    with pytest.raises(firewall.errors.FirewallError):
        firewall.core.ipset.ipset_entry_split_with_type("1.2.3.4", "hash:ip,port")
