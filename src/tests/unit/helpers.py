# SPDX-License-Identifier: GPL-2.0-or-later

import os
import re
import socket

###############################################################################


def str_to_bool(val, default_val=False):
    if isinstance(val, str):
        val2 = val.lower().strip()
        if val2 in ("", "default", "-1"):
            return default_val
        if val2 in ("0", "n", "no", "false"):
            return False
        if val2 in ("1", "y", "yes", "true"):
            return True
        # Invalid. Fall through.
    elif val is None:
        return default_val

    # No nonsense.
    raise ValueError(f"Unexpcted value for str_to_bool({repr(val)})")


###############################################################################

_srcdir = os.path.realpath(os.path.dirname(__file__) + "../../../..")


def srcdir(*a, exists=True):
    f = os.path.join(_srcdir, *a)
    if exists:
        assert os.path.exists(f)
    return f


###############################################################################


def ipaddr_to_bin(addr):
    assert addr
    assert isinstance(addr, str)
    family = socket.AF_INET if "." in addr else socket.AF_INET6
    return socket.inet_pton(family, addr)


def ipaddr_from_bin(addr):
    assert addr
    assert isinstance(addr, bytes)
    if len(addr) == 4:
        family = socket.AF_INET
    elif len(addr) == 16:
        family = socket.AF_INET6
    else:
        assert False
    return socket.inet_ntop(family, addr)


###############################################################################


def getservbyname(name, expected=None, maybe_missing=False):
    assert name
    assert isinstance(name, str)

    try:
        p = socket.getservbyname(name)
    except socket.error:
        if not maybe_missing:
            raise
        return None

    assert isinstance(p, int)
    assert p > 0

    if expected is not None:
        assert p == expected

    return p


def getprotobyname(name):
    assert name
    assert isinstance(name, str)
    try:
        return socket.getprotobyname(name)
    except socket.error:
        return None


###############################################################################


def assert_firewall_error(obj, code=None, msg=None):
    import firewall.errors

    assert isinstance(obj, firewall.errors.FirewallError)
    if msg is None:
        pass
    elif isinstance(msg, str):
        assert obj.msg == msg
    else:
        assert isinstance(msg, re.Pattern)
        assert msg.search(obj.msg)
    if code is not None:
        assert obj.code == code
