# -*- coding: utf-8 -*-
#
# Copyright (C) 2012 Red Hat, Inc.
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

import dbus.service
from dbus.exceptions import DBusException
from decorator import decorator

from firewall.core.logger import log
from firewall.errors import *

############################################################################
#
# Exception handler decorators
#
############################################################################

@decorator
def handle_exceptions(func, *args, **kwargs):
    """Decorator to handle exceptions and log them. Used if not conneced 
    to D-BUS.
    """
    try:
        return func(*args, **kwargs)
    except FirewallError as error:
        log.error(error)
    except Exception as msg:
        log.exception()

@decorator
def dbus_handle_exceptions(func, *args, **kwargs):
    """Decorator to handle exceptions, log and report them into D-BUS

    :Raises DBusException: on a firewall error code problems.
    """
    try:
        return func(*args, **kwargs)
    except FirewallError as error:
        log.error(str(error))
        raise DBusException(str(error))
    except DBusException as e:
        # only log DBusExceptions once
        raise e
    except Exception as e:
        log.exception()
        raise DBusException(str(e))

def dbus_service_method(*args, **kwargs):
    kwargs.setdefault("sender_keyword", "sender")
    return dbus.service.method(*args, **kwargs)
