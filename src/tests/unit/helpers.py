# SPDX-License-Identifier: GPL-2.0-or-later

import os


_srcdir = os.path.realpath(os.path.dirname(__file__) + "../../../..")


def srcdir(*a, exists=True):
    f = os.path.join(_srcdir, *a)
    if exists:
        assert os.path.exists(f)
    return f
