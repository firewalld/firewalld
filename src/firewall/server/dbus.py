# -*- coding: utf-8 -*-
#
# SPDX-License-Identifier: GPL-2.0-or-later

import dbus
from firewall import config

class FirewallDBusException(dbus.DBusException):
    """FirewallDBusException"""
    _dbus_error_name = "%s.Exception" % config.dbus.DBUS_INTERFACE
