# SPDX-License-Identifier: GPL-2.0-or-later

import os
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
