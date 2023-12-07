# SPDX-License-Identifier: GPL-2.0-or-later

import dbus
import pytest

import firewall.dbus_utils


def test_dbus_to_python():
    assert firewall.dbus_utils.dbus_to_python_args(
        [dbus.String("a"), dbus.String("b")], str, str
    ) == ("a", "b")

    assert firewall.dbus_utils.dbus_to_python_args(
        [dbus.String("a"), dbus.ObjectPath("/b")], str, str
    ) == ("a", "/b")

    assert firewall.dbus_utils.dbus_to_python_args(
        [dbus.String("a"), dbus.ObjectPath("/b")],
        dbus.String,
        dbus.ObjectPath,
    ) == ("a", "/b")

    assert firewall.dbus_utils.dbus_to_python_args([]) == ()

    with pytest.raises(TypeError):
        firewall.dbus_utils.dbus_to_python_args([dbus.String("a")], dbus.ObjectPath)

    assert firewall.dbus_utils.dbus_to_python_args([dbus.String("")], dbus.String) == (
        "",
    )

    with pytest.raises(TypeError):
        firewall.dbus_utils.dbus_to_python_args([dbus.String("a")])

    with pytest.raises(TypeError):
        firewall.dbus_utils.dbus_to_python_args([dbus.String("a")], str, str)

    assert firewall.dbus_utils.dbus_to_python_args([dbus.Int16(5)], int) == (5,)
    assert firewall.dbus_utils.dbus_to_python_args([dbus.Int16(5)], dbus.Int16) == (5,)

    assert firewall.dbus_utils.dbus_to_python_args([dbus.Boolean(True)], int) == (True,)
    assert firewall.dbus_utils.dbus_to_python_args([dbus.Boolean(True)], bool) == (
        True,
    )
    assert firewall.dbus_utils.dbus_to_python_args(
        [dbus.Boolean(True)], dbus.Boolean
    ) == (True,)

    with pytest.raises(TypeError):
        firewall.dbus_utils.dbus_to_python_args([dbus.Int16(5)], bool)
