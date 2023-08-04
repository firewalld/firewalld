# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
from tests.unit import helpers


def test_helper_str_to_bool():
    # falsey
    assert not helpers.str_to_bool("0")
    assert not helpers.str_to_bool("n")
    assert not helpers.str_to_bool("no")
    assert not helpers.str_to_bool("false")
    # truthy
    assert helpers.str_to_bool("1")
    assert helpers.str_to_bool("y")
    assert helpers.str_to_bool("yes")
    assert helpers.str_to_bool("true")
    # edge cases
    assert not helpers.str_to_bool(None)
    with pytest.raises(ValueError):
        helpers.str_to_bool(0)
