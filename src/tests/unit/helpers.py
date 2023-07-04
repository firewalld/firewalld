# SPDX-License-Identifier: GPL-2.0-or-later


def str_to_bool(val, default_val=False):
    if isinstance(val, str):
        val = val.lower().strip()
        if val in ("", "default", "-1"):
            return default_val
        if val in ("0", "n", "no", "false"):
            return False
        if val in ("1", "y", "yes", "true"):
            return True
        # Invalid. Fall through.
    elif val is None:
        return default_val

    # No nonsense.
    raise ValueError(f"Unexpcted value for str_to_bool({repr(val)})")
