# -*- coding: utf-8 -*-
#
# SPDX-License-Identifier: GPL-2.0-or-later

import dbus
from firewall import config

class FirewallDBusException(dbus.DBusException):
    """FirewallDBusException"""
    _dbus_error_name = "%s.Exception" % config.dbus.DBUS_INTERFACE

class NotAuthorizedException(dbus.DBusException):
    def __init__(self, action_id, method, *args, **kwargs):
        self._dbus_error_name = config.dbus.DBUS_INTERFACE + ".NotAuthorizedException"
        super().__init__("Not Authorized({}): {}".format(method, action_id))

class DbusServiceObject(dbus.service.Object):
    def __new__(cls, *args, **kwargs):
        # Check each dbus method. If it does not have an explicit polkit auth
        # then implicitly wrap it with the default
        from firewall.server.decorators import dbus_polkit_require_auth
        for attr_name in dir(cls):
            method = getattr(cls, attr_name)
            if hasattr(method, "_dbus_is_method") and \
               not hasattr(method, "_polkit_auth_required"):
                _decorator = dbus_polkit_require_auth(cls.default_polkit_auth_required)
                setattr(cls, attr_name, _decorator(method))

        return super().__new__(cls)
