# SPDX-License-Identifier: GPL-2.0-or-later

import warnings

import firewall.dbus_utils
import firewall.config.dbus
import firewall.server.decorators

with warnings.catch_warnings():
    # `from gi.repository import GLib` triggers a warning:
    # https://gitlab.gnome.org/GNOME/pygobject/-/issues/594
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    import firewall.server.config
    import firewall.server.firewalld

###############################################################################


def assert_is_deprecated(fcn):
    interface = fcn._dbus_interface
    name = fcn.__name__

    if getattr(fcn, "_dbus_is_method", None):
        depr = firewall.server.decorators.dbus_service_method_deprecated
    elif getattr(fcn, "_dbus_is_signal", None):
        depr = firewall.server.decorators.dbus_service_signal_deprecated
    else:
        assert False

    depr = depr.deprecated

    assert interface in depr
    assert name in depr[interface]


def get_dbus_functions(obj, *, with_signal=False, with_method=True, interface=None):

    for name in dir(obj):
        fcn = getattr(obj, name)
        is_method = getattr(fcn, "_dbus_is_method", None)
        is_signal = getattr(fcn, "_dbus_is_signal", None)

        if not is_method and not is_signal:
            continue
        if is_method and not with_method:
            continue
        if is_signal and not with_signal:
            continue

        if interface is not None:
            if fcn._dbus_interface != interface:
                continue

        yield fcn


###############################################################################


def test_api_config_policies():
    names = []
    for fcn in get_dbus_functions(
        firewall.server.config.FirewallDConfig,
        with_method=True,
        with_signal=True,
        interface=firewall.config.dbus.DBUS_INTERFACE_CONFIG_POLICIES,
    ):
        assert_is_deprecated(fcn)
        names.append(fcn.__name__)

    assert "setLockdownWhitelist" in names
    assert "LockdownWhitelistUpdated" in names


def test_api_policies():
    names = []
    for fcn in get_dbus_functions(
        firewall.server.firewalld.FirewallD,
        with_method=True,
        with_signal=True,
        interface=firewall.config.dbus.DBUS_INTERFACE_POLICIES,
    ):
        assert_is_deprecated(fcn)
        names.append(fcn.__name__)

    assert "getLockdownWhitelistContexts" in names
    assert "LockdownWhitelistUidAdded" in names
