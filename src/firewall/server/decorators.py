# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2012-2016 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>

"""This module contains decorators for use with and without D-Bus"""

import dbus
import dbus.service
import traceback
import functools
import inspect
from dbus.exceptions import DBusException

from firewall.errors import FirewallError
from firewall import errors
from firewall.core.logger import log
from firewall.server.dbus import FirewallDBusException, NotAuthorizedException
from firewall.dbus_utils import uid_of_sender

############################################################################
#
# Exception handler decorators
#
############################################################################


def handle_exceptions(func):
    """Decorator to handle exceptions and log them. Used if not conneced
    to D-Bus.
    """

    @functools.wraps(func)
    def _impl(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except FirewallError as error:
            log.debug1(traceback.format_exc())
            log.error(error)
        except Exception:  # pylint: disable=W0703
            log.exception()

    return _impl


def dbus_handle_exceptions(func):
    """Decorator to handle exceptions, log and report them into D-Bus

    :Raises DBusException: on a firewall error code problems.
    """

    @functools.wraps(func)
    def _impl(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except FirewallError as error:
            code = FirewallError.get_code(str(error))
            if code in [
                errors.ALREADY_ENABLED,
                errors.NOT_ENABLED,
                errors.ZONE_ALREADY_SET,
                errors.ALREADY_SET,
            ]:
                log.warning(str(error))
            else:
                log.debug1(traceback.format_exc())
                log.error(str(error))
            raise FirewallDBusException(str(error))
        except DBusException as ex:
            # only log DBusExceptions once
            raise ex
        except Exception as ex:
            log.exception()
            raise FirewallDBusException(str(ex))

    # HACK: functools.wraps() does not copy the function signature and
    # dbus-python doesn't support varargs. As such we need to copy the
    # signature from the function to the newly decorated function otherwise the
    # decorators in dbus-python will manipulate the arg stack and fail
    # miserably.
    #
    # Note: This can be removed if we ever stop using dbus-python.
    #
    # Ref: https://gitlab.freedesktop.org/dbus/dbus-python/-/issues/12
    #
    _impl.__signature__ = inspect.signature(func)
    return _impl


def dbus_service_method(
    dbus_interface,
    in_signature="",
    out_signature="",
    *args,
    is_deprecated=False,
    sender_keyword="sender",
    **kwargs,
):
    def decorator(func):
        if is_deprecated:
            dbus_service_method_deprecated.register(dbus_interface, func.__name__)

        dbus_decorator = dbus.service.method(
            dbus_interface,
            in_signature=in_signature,
            out_signature=out_signature,
            *args,
            sender_keyword=sender_keyword,
            **kwargs,
        )
        return dbus_decorator(func)

    return decorator


def dbus_service_signal(
    dbus_interface,
    signature="",
    *args,
    is_deprecated=False,
    **kwargs,
):
    def decorator(func):
        if is_deprecated:
            dbus_service_signal_deprecated.register(dbus_interface, func.__name__)

        dbus_decorator = dbus.service.signal(
            dbus_interface,
            *args,
            signature=signature,
            **kwargs,
        )
        return dbus_decorator(func)

    return decorator


class dbus_service_deprecated:
    """Decorator that maintains a list of deprecated methods in dbus
    interfaces.
    """

    def __init__(self, interface):
        self.interface = interface

    def __call__(self, func):
        self.register(self.interface, func.__name__)
        return func

    @classmethod
    def register(cls, interface, name):
        s = cls.deprecated.get(interface)
        if s is None:
            s = set()
            cls.deprecated[interface] = s
        s.add(name)


class dbus_service_method_deprecated(dbus_service_deprecated):
    """Decorator that maintains a list of deprecated methods in dbus
    interfaces.
    """

    deprecated = {}


class dbus_service_signal_deprecated(dbus_service_deprecated):
    """Decorator that maintains a list of deprecated signals in dbus
    interfaces.
    """

    deprecated = {}


class dbus_polkit_require_auth:
    """Decorator factory that checks if the interface/method can be used by the
    sender/user. Assumes wrapped function is a method inside a class derived
    from DbusServiceObject.
    """

    _polkit_name = "org.freedesktop.PolicyKit1"
    _polkit_path = "/org/freedesktop/PolicyKit1/Authority"
    _polkit_interface = "org.freedesktop.PolicyKit1.Authority"

    _bus = None
    _bus_signal_receiver = None
    _interface_polkit = None

    def __init__(self, polkit_auth_required):
        self._polkit_auth_required = polkit_auth_required

    @classmethod
    def _polkit_name_owner_changed(cls, name, old_owner, new_owner):
        cls._bus.remove_signal_receiver(cls._bus_signal_receiver)
        cls._bus_signal_receiver = None
        cls._interface_polkit = None

    def __call__(self, func):
        @functools.wraps(func)
        def _impl(*args, **kwargs):
            if not type(self)._bus:
                type(self)._bus = dbus.SystemBus()

            if not type(self)._bus_signal_receiver:
                type(self)._bus_signal_receiver = type(self)._bus.add_signal_receiver(
                    handler_function=type(self)._polkit_name_owner_changed,
                    signal_name="NameOwnerChanged",
                    dbus_interface="org.freedesktop.DBus",
                    arg0=self._polkit_name,
                )

            if not type(self)._interface_polkit:
                try:
                    type(self)._interface_polkit = dbus.Interface(
                        type(self)._bus.get_object(
                            type(self)._polkit_name, type(self)._polkit_path
                        ),
                        type(self)._polkit_interface,
                    )
                except dbus.DBusException:
                    # polkit must not be available
                    pass

            action_id = self._polkit_auth_required
            if not action_id:
                raise dbus.DBusException("Not Authorized: No action_id specified.")

            sender = kwargs.get("sender")
            if sender:
                # use polkit if it's available
                if type(self)._interface_polkit:
                    (result, _, _) = type(self)._interface_polkit.CheckAuthorization(
                        ("system-bus-name", {"name": sender}),
                        action_id,
                        {},
                        1,
                        "",
                        timeout=60,
                    )
                    if not result:
                        raise NotAuthorizedException(action_id, "polkit")
                # fallback to checking UID
                else:
                    uid = uid_of_sender(type(self)._bus, sender)

                    if uid != 0:
                        raise NotAuthorizedException(action_id, "uid")

            return func(*args, **kwargs)

        _impl._polkit_auth_required = self._polkit_auth_required
        return _impl
