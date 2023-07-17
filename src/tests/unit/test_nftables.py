# SPDX-License-Identifier: GPL-2.0-or-later

import firewall.core.nftables


###############################################################################


def test_nftables_entry_to_json():
    assert firewall.core.nftables.nftables._entry_to_json(
        "1::2/1,eth0,http", "hash:net,iface,port", "ipv6"
    ) == [
        {
            "concat": [
                {
                    "prefix": {
                        "addr": "1::2",
                        "len": 1,
                    },
                },
                "eth0",
                "tcp",
                "http",
            ],
        },
    ]

    assert firewall.core.nftables.nftables._entry_to_json(
        "1::2/1,eth0,http,1::00-2::,1:0::-3::0/64,udp:70-60",
        "hash:net,iface,port,net,net,port",
        "ipv6",
    ) == [
        {
            "concat": [
                {
                    "prefix": {
                        "addr": "1::2",
                        "len": 1,
                    },
                },
                "eth0",
                "tcp",
                "http",
                {
                    "range": [
                        "1::",
                        "2::",
                    ],
                },
                {
                    "range": [
                        "1::",
                        "3::/64",
                    ],
                },
                "udp",
                {
                    "range": [
                        "60",
                        "70",
                    ],
                },
            ],
        },
    ]

    assert firewall.core.nftables.nftables._entry_to_json(
        "1.2.3.0/24,AA:00:11:22:33:44,0xFc5,eth0,999",
        "hash:ip,mac,mark,iface,mark",
        "ipv4",
    ) == [
        {
            "concat": [
                {
                    "prefix": {
                        "addr": "1.2.3.0",
                        "len": 24,
                    },
                },
                "aa:00:11:22:33:44",
                "0xfc5",
                "eth0",
                "999",
            ],
        },
    ]

    assert firewall.core.nftables.nftables._entry_to_json(
        "1.2.3.0-1.2.5.0/24",
        "hash:net",
        "ipv4",
    ) == [
        {
            "range": [
                "1.2.3.0",
                "1.2.5.0/24",
            ],
        },
    ]
