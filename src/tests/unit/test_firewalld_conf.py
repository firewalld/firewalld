# SPDX-License-Identifier: GPL-2.0-or-later

import pytest

import firewall.config
import firewall.core.io.firewalld_conf


def get_valid_key(key):
    return firewall.core.io.firewalld_conf.valid_keys[key]


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
            parsed = firewall.core.io.firewalld_conf._parse_reload_policy(value)
        except ValueError:
            assert not expected_valid
            return

        assert parsed == expected
        assert expected_valid

        unparsed = firewall.core.io.firewalld_conf._unparse_reload_policy(parsed)
        parsed2 = firewall.core.io.firewalld_conf._parse_reload_policy(unparsed)
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
        parsed = firewall.core.io.firewalld_conf._parse_reload_policy(reload_policy)
        return firewall.core.io.firewalld_conf._unparse_reload_policy(parsed)

    assert firewall.config.FALLBACK_RELOAD_POLICY == _norm(
        firewall.config.FALLBACK_RELOAD_POLICY
    )


def test_valid_keys():

    conf = firewall.core.io.firewalld_conf.firewalld_conf("/file/name/nowhere")

    conf.set_defaults()

    keys = sorted(conf._config.keys())
    valid_keys = sorted(firewall.core.io.firewalld_conf.valid_keys)
    assert keys == valid_keys

    assert conf.get("AllowZoneDrifting") == "no"

    assert (
        conf.get("IndividualCalls", bool) is firewall.config.FALLBACK_INDIVIDUAL_CALLS
    )
    assert conf.get("MinimalMark", int) == firewall.config.FALLBACK_MINIMAL_MARK
    assert conf.get("LogDeniedGroup", int) == -1


def test_config_keys():
    for name, keytype in firewall.core.io.firewalld_conf.valid_keys.items():
        assert name == keytype.key
        assert name == name.strip()

        if keytype.key_type is firewall.core.io.firewalld_conf._validate_enum:
            assert keytype._enum_values
            assert isinstance(keytype._enum_values, tuple)
            for f in keytype._enum_values:
                assert isinstance(f, str)
                assert f == f.strip()
                assert f == f.lower()
            assert isinstance(keytype._default, str)
            assert keytype._default in keytype._enum_values
            assert sorted(set(keytype._enum_values)) == sorted(keytype._enum_values)
        else:
            assert keytype._enum_values is None

        if keytype.key_type in (bool, int):
            assert type(keytype._default) is keytype.key_type
        else:
            assert type(keytype._default) is str

        if keytype.key_type in (int,):
            assert keytype._check is None or callable(keytype._check)
        else:
            assert keytype._check is None

        assert keytype.default == keytype.normalize(keytype._default, strict=True)

        if keytype._check is not None:
            assert keytype._check(keytype._default)

        assert keytype.dbus_mode in ("read", "readwrite")


def test_config_normalize():

    assert get_valid_key("MinimalMark").normalize(56) == "56"
    assert get_valid_key("MinimalMark").normalize("  0\n\t ") == "0"

    assert get_valid_key("IndividualCalls").normalize(True) == "yes"
    assert get_valid_key("IndividualCalls").normalize("True") == "yes"
    assert get_valid_key("IndividualCalls").normalize("0") == "no"

    assert get_valid_key("LogDeniedGroup").normalize("-1  ") == "-1"
    with pytest.raises(firewall.errors.FirewallError):
        get_valid_key("LogDeniedGroup").normalize("-2")
    assert get_valid_key("LogDeniedGroup").normalize("-2", strict=False) == "-1"
    assert get_valid_key("LogDeniedGroup").normalize(0xFFFF) == "65535"
    assert get_valid_key("LogDeniedGroup").normalize("65536", strict=False) == "-1"


def test_get_as():

    assert (
        get_valid_key("IndividualCalls").default_as(bool)
        is firewall.config.FALLBACK_INDIVIDUAL_CALLS
    )

    assert get_valid_key("LogDeniedGroup").default == "-1"
    assert get_valid_key("LogDeniedGroup").default_as(int) == -1
