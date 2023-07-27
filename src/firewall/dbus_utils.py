# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2011-2016 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>

import dbus
import pwd
from xml.dom import minidom

from firewall.core.logger import log


def command_of_pid(pid):
    """Get command for pid from /proc"""
    try:
        with open("/proc/%d/cmdline" % pid, "r") as f:
            cmd = f.readlines()[0].replace("\0", " ").strip()
    except Exception:
        return None
    return cmd


def pid_of_sender(bus, sender):
    """Get pid from sender string using
    org.freedesktop.DBus.GetConnectionUnixProcessID"""

    dbus_obj = bus.get_object("org.freedesktop.DBus", "/org/freedesktop/DBus")
    dbus_iface = dbus.Interface(dbus_obj, "org.freedesktop.DBus")

    try:
        pid = int(dbus_iface.GetConnectionUnixProcessID(sender))
    except ValueError:
        return None
    return pid


def uid_of_sender(bus, sender):
    """Get user id from sender string using
    org.freedesktop.DBus.GetConnectionUnixUser"""

    dbus_obj = bus.get_object("org.freedesktop.DBus", "/org/freedesktop/DBus")
    dbus_iface = dbus.Interface(dbus_obj, "org.freedesktop.DBus")

    try:
        uid = int(dbus_iface.GetConnectionUnixUser(sender))
    except ValueError:
        return None
    return uid


def user_of_uid(uid):
    """Get user for uid from pwd"""

    try:
        pws = pwd.getpwuid(uid)
    except Exception:
        return None
    return pws[0]


def context_of_sender(bus, sender):
    """Get SELinux context from sender string using
    org.freedesktop.DBus.GetConnectionSELinuxSecurityContext"""

    dbus_obj = bus.get_object("org.freedesktop.DBus", "/org/freedesktop/DBus")
    dbus_iface = dbus.Interface(dbus_obj, "org.freedesktop.DBus")

    try:
        context = dbus_iface.GetConnectionSELinuxSecurityContext(sender)
    except Exception:
        return None

    return "".join(map(chr, dbus_to_python(context)))


def command_of_sender(bus, sender):
    """Return command of D-Bus sender"""

    return command_of_pid(pid_of_sender(bus, sender))


def user_of_sender(bus, sender):
    return user_of_uid(uid_of_sender(bus, sender))


def dbus_to_python(obj, expected_type=None):
    if obj is None:
        python_obj = obj
    elif isinstance(obj, dbus.Boolean):
        python_obj = bool(obj)
    elif isinstance(obj, dbus.String):
        python_obj = str(obj)
    elif isinstance(obj, dbus.ObjectPath):
        python_obj = str(obj)
    elif (
        isinstance(obj, dbus.Byte)
        or isinstance(obj, dbus.Int16)
        or isinstance(obj, dbus.Int32)
        or isinstance(obj, dbus.Int64)
        or isinstance(obj, dbus.UInt16)
        or isinstance(obj, dbus.UInt32)
        or isinstance(obj, dbus.UInt64)
    ):
        python_obj = int(obj)
    elif isinstance(obj, dbus.Double):
        python_obj = float(obj)
    elif isinstance(obj, dbus.Array):
        python_obj = [dbus_to_python(x) for x in obj]
    elif isinstance(obj, dbus.Struct):
        python_obj = tuple([dbus_to_python(x) for x in obj])
    elif isinstance(obj, dbus.Dictionary):
        python_obj = {dbus_to_python(k): dbus_to_python(v) for k, v in obj.items()}
    elif (
        isinstance(obj, bool)
        or isinstance(obj, str)
        or isinstance(obj, bytes)
        or isinstance(obj, int)
        or isinstance(obj, float)
        or isinstance(obj, list)
        or isinstance(obj, tuple)
        or isinstance(obj, dict)
    ):
        python_obj = obj
    else:
        raise TypeError("Unhandled %s" % repr(obj))

    if expected_type is None:
        # no type validation requested.
        pass
    elif isinstance(python_obj, expected_type):
        # we are good, the result has the requested type.
        # for example, expected_type is "str"
        pass
    elif isinstance(obj, expected_type):
        # we are also good. The expected_type might be something like
        # dbus.ObjectPath, and the caller asserts that this is an "o"
        # type. The result is of course just a plain "str" type.
        #
        # This allows to check that the type is for example a dbus.ObjectPath
        # and not merely a string (which provides additional consistency
        # guarantees, like not being empty and well-formed).
        pass
    else:
        raise TypeError(
            "%s is %s, expected %s" % (python_obj, type(python_obj), expected_type)
        )

    return python_obj


def dbus_to_python_args(dbus_args, *expected_types):
    # Checks that dbus_args is a list of D-Bus arguments, of the expected type.
    dbus_args = tuple(dbus_args)
    if len(dbus_args) != len(expected_types):
        # The number of arguments must match with the expected_types.
        raise TypeError("Unexpected number of arguments")
    return tuple(dbus_to_python(a, expected_types[i]) for i, a in enumerate(dbus_args))


def dbus_signature(obj):
    if isinstance(obj, dbus.Boolean):
        return "b"
    elif isinstance(obj, dbus.String):
        return "s"
    elif isinstance(obj, dbus.ObjectPath):
        return "o"
    elif isinstance(obj, dbus.Byte):
        return "y"
    elif isinstance(obj, dbus.Int16):
        return "n"
    elif isinstance(obj, dbus.Int32):
        return "i"
    elif isinstance(obj, dbus.Int64):
        return "x"
    elif isinstance(obj, dbus.UInt16):
        return "q"
    elif isinstance(obj, dbus.UInt32):
        return "u"
    elif isinstance(obj, dbus.UInt64):
        return "t"
    elif isinstance(obj, dbus.Double):
        return "d"
    elif isinstance(obj, dbus.Array):
        if len(obj.signature) > 1:
            return "a(%s)" % obj.signature
        else:
            return "a%s" % obj.signature
    elif isinstance(obj, dbus.Struct):
        return "(%s)" % obj.signature
    elif isinstance(obj, dbus.Dictionary):
        return "a{%s}" % obj.signature
    else:
        raise TypeError("Unhandled %s" % repr(obj))


def dbus_introspection_prepare_properties(obj, interface, access=None):
    if access is None:
        access = {}

    if not hasattr(obj, "_fw_dbus_properties"):
        setattr(obj, "_fw_dbus_properties", {})
    dip = getattr(obj, "_fw_dbus_properties")
    dip[interface] = {}

    try:
        _dict = obj.GetAll(interface)
    except Exception:
        _dict = {}
    for key, value in _dict.items():
        dip[interface][key] = {"type": dbus_signature(value)}
        if key in access:
            dip[interface][key]["access"] = access[key]
        else:
            dip[interface][key]["access"] = "read"


def dbus_introspection_add_properties(obj, data, interface):
    doc = minidom.parseString(data)

    if hasattr(obj, "_fw_dbus_properties"):
        for node in doc.getElementsByTagName("interface"):
            if node.hasAttribute("name") and node.getAttribute("name") == interface:
                dip = {}
                if getattr(obj, "_fw_dbus_properties"):
                    dip = getattr(obj, "_fw_dbus_properties")
                if interface in dip:
                    for key, value in dip[interface].items():
                        prop = doc.createElement("property")
                        prop.setAttribute("name", key)
                        prop.setAttribute("type", value["type"])
                        prop.setAttribute("access", value["access"])
                        node.appendChild(prop)

    log.debug10(doc.toxml())
    new_data = doc.toxml()
    doc.unlink()
    return new_data


def dbus_introspection_add_deprecated(
    obj, data, interface, deprecated_methods, deprecated_signals
):
    doc = minidom.parseString(data)

    if interface in deprecated_methods:
        for node in doc.getElementsByTagName("interface"):
            if node.hasAttribute("name") and node.getAttribute("name") == interface:
                for method_node in node.getElementsByTagName("method"):
                    if (
                        method_node.hasAttribute("name")
                        and method_node.getAttribute("name")
                        in deprecated_methods[interface]
                    ):
                        annotation = doc.createElement("annotation")
                        annotation.setAttribute(
                            "name", "org.freedesktop.DBus.Deprecated"
                        )
                        annotation.setAttribute("value", "true")
                        method_node.appendChild(annotation)

    if interface in deprecated_signals:
        for node in doc.getElementsByTagName("interface"):
            if node.hasAttribute("name") and node.getAttribute("name") == interface:
                for signal_node in node.getElementsByTagName("signal"):
                    if (
                        signal_node.hasAttribute("name")
                        and signal_node.getAttribute("name")
                        in deprecated_signals[interface]
                    ):
                        annotation = doc.createElement("annotation")
                        annotation.setAttribute(
                            "name", "org.freedesktop.DBus.Deprecated"
                        )
                        annotation.setAttribute("value", "true")
                        signal_node.appendChild(annotation)

    log.debug10(doc.toxml())
    data = doc.toxml()
    doc.unlink()

    return data
