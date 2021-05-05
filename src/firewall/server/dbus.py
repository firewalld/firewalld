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
