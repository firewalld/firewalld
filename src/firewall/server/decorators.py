# -*- coding: utf-8 -*-
#
# Copyright (C) 2012-2016 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""This module contains decorators for use with and without D-Bus"""

__all__ = ["FirewallDBusException", "handle_exceptions",
           "dbus_handle_exceptions", "dbus_service_method"]

import dbus
import dbus.service
from dbus.exceptions import DBusException
from decorator import decorator

from firewall import config
from firewall.errors import FirewallError
from firewall import errors
from firewall.core.logger import log

############################################################################
#
# Exception handler decorators
#
############################################################################

class FirewallDBusException(dbus.DBusException):
    """FirewallDBusException"""
    _dbus_error_name = "%s.Exception" % config.dbus.DBUS_INTERFACE

@decorator
def handle_exceptions(func, *args, **kwargs):
    """Decorator to handle exceptions and log them. Used if not conneced
    to D-Bus.
    """
    try:
        return func(*args, **kwargs)
    except FirewallError as error:
        log.error(error)
    except Exception:  # pylint: disable=W0703
        log.exception()

@decorator
def dbus_handle_exceptions(func, *args, **kwargs):
    """Decorator to handle exceptions, log and report them into D-Bus

    :Raises DBusException: on a firewall error code problems.
    """
    try:
        return func(*args, **kwargs)
    except FirewallError as error:
        code = FirewallError.get_code(str(error))
        if code in [ errors.ALREADY_ENABLED, errors.NOT_ENABLED,
                     errors.ZONE_ALREADY_SET, errors.ALREADY_SET ]:
            log.warning(str(error))
        else:
            log.error(str(error))
        raise FirewallDBusException(str(error))
    except DBusException as ex:
        # only log DBusExceptions once
        raise ex
    except Exception as ex:
        log.exception()
        raise FirewallDBusException(str(ex))

def dbus_service_method(*args, **kwargs):
    """Add sender argument for D-Bus"""
    kwargs.setdefault("sender_keyword", "sender")
    return dbus.service.method(*args, **kwargs)
