# SPDX-License-Identifier: GPL-2.0-or-later

import firewall.core.io.firewalld_conf
import firewall.config


def test_reload_policy():
    def t(value, expected_valid=True, **kw):

        expected = {
            "INPUT": "DROP",
            "FORWARD": "DROP",
            "OUTPUT": "DROP",
        }
        for k, v in kw.items():
            assert k in expected
            expected[k] = v

        try:
            parsed = (
                firewall.core.io.firewalld_conf.firewalld_conf._parse_reload_policy(
                    value
                )
            )
        except ValueError:
            assert not expected_valid
            return

        assert parsed == expected
        assert expected_valid

        unparsed = (
            firewall.core.io.firewalld_conf.firewalld_conf._unparse_reload_policy(
                parsed
            )
        )
        parsed2 = firewall.core.io.firewalld_conf.firewalld_conf._parse_reload_policy(
            unparsed
        )
        assert parsed2 == parsed

    t(None)
    t("")
    t("  ")
    t(" input: ACCept ", INPUT="ACCEPT")
    t(
        "forward:DROP,  forward : REJEct; input: ACCept ",
        INPUT="ACCEPT",
        FORWARD="REJECT",
    )
    t(" accept ", INPUT="ACCEPT", FORWARD="ACCEPT", OUTPUT="ACCEPT")
    t("REJECT", INPUT="REJECT", FORWARD="REJECT", OUTPUT="REJECT")
    t("forward=REJECT", FORWARD="REJECT")
    t("forward=REJECT , input=accept", FORWARD="REJECT", INPUT="ACCEPT")
    t("forward=REJECT , xinput=accept", expected_valid=False)
    t("forward=REJECT, ACCEPT", expected_valid=False)

    def _norm(reload_policy):
        parsed = firewall.core.io.firewalld_conf.firewalld_conf._parse_reload_policy(
            reload_policy
        )
        return firewall.core.io.firewalld_conf.firewalld_conf._unparse_reload_policy(
            parsed
        )

    assert firewall.config.FALLBACK_RELOAD_POLICY == _norm(
        firewall.config.FALLBACK_RELOAD_POLICY
    )
