import pytest

import firewall.functions


def test_str_to_bool():

    assert firewall.functions.str_to_bool(True) is True
    assert firewall.functions.str_to_bool(False) is False

    ERR = object()
    DEF = object()

    # falsy
    assert firewall.functions.str_to_bool("0") is False
    assert firewall.functions.str_to_bool("n") is False
    assert firewall.functions.str_to_bool("no") is False
    assert firewall.functions.str_to_bool("false") is False

    # truthy
    assert firewall.functions.str_to_bool("1") is True
    assert firewall.functions.str_to_bool("y") is True
    assert firewall.functions.str_to_bool("yes") is True
    assert firewall.functions.str_to_bool("true") is True

    assert firewall.functions.str_to_bool("bogus", None) is None
    assert firewall.functions.str_to_bool("default", None) is None
    assert firewall.functions.str_to_bool("bogus", ERR) is ERR
    assert firewall.functions.str_to_bool("default", ERR) is ERR

    assert firewall.functions.str_to_bool("bogus", ERR, on_default=DEF) is ERR
    assert firewall.functions.str_to_bool("default", ERR, on_default=DEF) is DEF

    with pytest.raises(TypeError):
        firewall.functions.str_to_bool("default", ERR, on_error=DEF)

    with pytest.raises(ValueError):
        assert firewall.functions.str_to_bool("bogus", on_default=DEF)
    assert firewall.functions.str_to_bool("bogus", on_default=DEF, on_error=ERR) is ERR
    assert firewall.functions.str_to_bool("bogus", on_error=ERR) is ERR
    assert firewall.functions.str_to_bool("default", on_default=DEF) is DEF
    assert (
        firewall.functions.str_to_bool("default", on_default=DEF, on_error=ERR) is DEF
    )
    assert firewall.functions.str_to_bool("default", on_error=ERR) is ERR

    # edge cases
    with pytest.raises(ValueError):
        firewall.functions.str_to_bool(None)
    assert firewall.functions.str_to_bool(None, on_default=DEF) is DEF
    with pytest.raises(ValueError):
        firewall.functions.str_to_bool(0, on_default=DEF)

    obj = object()

    assert firewall.functions.str_to_bool("True", on_default=False) is True

    assert firewall.functions.str_to_bool("", on_default=obj) is obj

    with pytest.raises(ValueError):
        firewall.functions.str_to_bool("")

    assert firewall.functions.str_to_bool(None, on_default=obj) is obj
    assert firewall.functions.str_to_bool("", on_default=obj) is obj
    assert firewall.functions.str_to_bool(" DEFAULT ", on_default=obj) is obj
    assert firewall.functions.str_to_bool(" -1 ", on_default=obj) is obj

    assert firewall.functions.str_to_bool(" -1 ", on_default=DEF) is DEF
    assert firewall.functions.str_to_bool(" -1 ", on_error=ERR) is ERR

    assert firewall.functions.str_to_bool("", on_default=DEF, on_error=ERR) is DEF
    assert firewall.functions.str_to_bool("", on_error=ERR) is ERR

    with pytest.raises(ValueError):
        firewall.functions.str_to_bool("bogus")

    assert firewall.functions.str_to_bool("bogus", on_error=ERR) is ERR
    assert firewall.functions.str_to_bool("bogus", on_default=DEF, on_error=obj) is obj

    assert firewall.functions.bool_to_str(True) == "yes"
    assert firewall.functions.bool_to_str(False) == "no"
    assert firewall.functions.bool_to_str(True, format="yes") == "yes"
    assert firewall.functions.bool_to_str(False, format="yes") == "no"
    with pytest.raises(ValueError):
        firewall.functions.bool_to_str(False, format="bogus")
