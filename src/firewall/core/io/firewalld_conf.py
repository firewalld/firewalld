# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2011-2012 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>

import os.path
import io
import tempfile
import shutil
import dbus

import firewall.errors
import firewall.functions
from firewall import config
from firewall.core.logger import log


def _parse_reload_policy(value):
    valid = True
    result = {
        "INPUT": "DROP",
        "FORWARD": "DROP",
        "OUTPUT": "DROP",
    }
    if value:
        value = value.strip()
        v = value.upper()
        if v in ("ACCEPT", "REJECT", "DROP"):
            for k in result:
                result[k] = v
        else:
            for a in value.replace(";", ",").split(","):
                a = a.strip()
                if not a:
                    continue
                a2 = a.replace("=", ":").split(":", 2)
                if len(a2) != 2:
                    valid = False
                    continue
                k = a2[0].strip().upper()
                if k not in result:
                    valid = False
                    continue
                v = a2[1].strip().upper()
                if v not in ("ACCEPT", "REJECT", "DROP"):
                    valid = False
                    continue
                result[k] = v

    if not valid:
        raise ValueError("Invalid ReloadPolicy")

    return result


def _unparse_reload_policy(value):
    return ",".join(f"{k}:{v}" for k, v in value.items())


def _normalize_reload_policy(value):
    return _unparse_reload_policy(_parse_reload_policy(value))


def _validate_bool(value, default):
    valid = True
    try:
        v = firewall.functions.str_to_bool(value, on_default=None)
    except ValueError:
        valid = False
        v = None

    if v is None:
        v = firewall.functions.str_to_bool(default)

    return ("yes" if v else "no"), valid


def _validate_enum(value, enum_values, default):

    if value is None:
        return default, True

    # normalize upper case values to lower-case
    value = value.lower()

    # Enums don't have whitespace. Strip it.
    value = value.strip()

    try:
        idx = enum_values.index(value)
    except ValueError:
        return default, False

    return enum_values[idx], True


class KeyType:
    def __init__(
        self,
        key,
        key_type,
        default,
        *,
        is_deprecated=False,
        dbus_mode="read",
        dbus_type=dbus.String,
        dbus_ignore_set=False,
        enum_values=None,
        check=None,
    ):
        self.key = key
        self.key_type = key_type
        self._default = default
        self.is_deprecated = is_deprecated
        self.dbus_ignore_set = dbus_ignore_set
        self.dbus_mode = dbus_mode
        self.dbus_type = dbus_type
        self._enum_values = tuple(enum_values) if enum_values is not None else None
        self._check = check

    def get_as(self, value, as_type):
        if as_type in (bool, int):
            if self.key_type is not as_type:
                raise ValueError(f"Cannot request {self.key} as {as_type}")
            if as_type is bool:
                return firewall.functions.str_to_bool(value)
            return int(value)
        raise ValueError(
            f'get_as() for "{self.key}" does not support requesting as {as_type}'
        )

    @property
    def default(self):
        if self.key_type is bool:
            v = firewall.functions.str_to_bool(self._default)
            return "yes" if v else "no"
        if self.key_type is int:
            v = int(self._default)
            return str(v)
        return str(self._default)

    def default_as(self, as_type):
        if (
            as_type in (bool, int)
            and self.key_type is as_type
            and type(self._default) is as_type
        ):
            # Optimize common case. We don't need to first convert to string
            # and parse.
            return self._default
        return self.get_as(self.default, as_type)

    def _error_invalid_value(self, value):
        return firewall.errors.FirewallError(
            firewall.errors.INVALID_VALUE,
            "'%s' for %s" % (value, self.key),
        )

    def normalize(self, value, strict=True, log_warn=True):

        if value is None and strict:
            raise self._error_invalid_value(value)

        if self.key_type is bool:
            v, valid = _validate_bool(value, self._default)
            if not valid:
                if strict:
                    raise self._error_invalid_value(value)
                if log_warn:
                    log.warning(
                        f"{self.key} '{value}' is not a valid boolean, using default value '{v}'"
                    )
            return v
        if self.key_type is str:
            if value and isinstance(value, str):
                v = value.strip()
                if v:
                    return v
            if strict:
                raise self._error_invalid_value(value)
            v = self.default
            assert v and isinstance(v, str)
            if value is not None:
                if log_warn:
                    log.warning(f"{self.key} is empty, using default value '{v}'")
            return v
        if self.key_type is int:
            try:
                v = int(value)
                if self._check is not None and not self._check(v):
                    raise ValueError(f"check failed for {v}")
            except (ValueError, TypeError):
                if strict:
                    raise self._error_invalid_value(value)
                v = int(self._default)
                if value is not None:
                    if log_warn:
                        log.warning(
                            f"MinimalMark '{value}' is not valid, using default value '{v}'",
                        )
            return str(v)
        if self.key_type is _validate_enum:
            v, valid = _validate_enum(value, self._enum_values, self._default)
            if not valid:
                if strict:
                    raise self._error_invalid_value(value)
                if log_warn:
                    log.warning(
                        f"{self.key} '{value}' is invalid, using default value '{v}'"
                    )
            assert v
            return v
        if self.key_type in (_normalize_reload_policy,):
            try:
                v = self.key_type(value)
            except ValueError:
                v = self.key_type(self.default)
                if log_warn:
                    log.warning(
                        f"{self.key} '{value}' is not valid, using default value '{v}'"
                    )
            return value

        raise firewall.errors.BugError()


valid_keys = [
    KeyType(
        "DefaultZone",
        key_type=str,
        default=config.FALLBACK_ZONE,
    ),
    KeyType(
        "MinimalMark",
        key_type=int,
        default=config.FALLBACK_MINIMAL_MARK,
        is_deprecated=True,
        dbus_ignore_set=True,
        dbus_mode="readwrite",
        dbus_type=dbus.Int32,
    ),
    KeyType(
        "CleanupOnExit",
        key_type=bool,
        default=config.FALLBACK_CLEANUP_ON_EXIT,
        dbus_mode="readwrite",
    ),
    KeyType(
        "CleanupModulesOnExit",
        key_type=bool,
        default=config.FALLBACK_CLEANUP_MODULES_ON_EXIT,
        dbus_mode="readwrite",
    ),
    KeyType(
        "Lockdown",
        key_type=bool,
        default=config.FALLBACK_LOCKDOWN,
        dbus_mode="readwrite",
    ),
    KeyType(
        "IPv6_rpfilter",
        key_type=bool,
        default=config.FALLBACK_IPV6_RPFILTER,
        dbus_mode="readwrite",
    ),
    KeyType(
        "IndividualCalls",
        key_type=bool,
        default=config.FALLBACK_INDIVIDUAL_CALLS,
        dbus_mode="readwrite",
    ),
    KeyType(
        "LogDenied",
        key_type=_validate_enum,
        default=config.FALLBACK_LOG_DENIED,
        enum_values=config.LOG_DENIED_VALUES,
        dbus_mode="readwrite",
    ),
    KeyType(
        "LogDeniedGroup",
        key_type=int,
        default=-1,
        check=lambda v: (v >= -1 and v <= 0xFFFF),
        dbus_type=dbus.Int32,
        dbus_mode="readwrite",
    ),
    KeyType(
        "AutomaticHelpers",
        key_type=_validate_enum,
        default=config.FALLBACK_AUTOMATIC_HELPERS,
        enum_values=config.AUTOMATIC_HELPERS_VALUES,
        is_deprecated=True,
        dbus_ignore_set=True,
        dbus_mode="readwrite",
    ),
    KeyType(
        "FirewallBackend",
        key_type=_validate_enum,
        default=config.FALLBACK_FIREWALL_BACKEND,
        enum_values=config.FIREWALL_BACKEND_VALUES,
        dbus_mode="readwrite",
    ),
    KeyType(
        "FlushAllOnReload",
        key_type=bool,
        default=config.FALLBACK_FLUSH_ALL_ON_RELOAD,
        dbus_mode="readwrite",
    ),
    KeyType(
        "ReloadPolicy",
        key_type=_normalize_reload_policy,
        default=config.FALLBACK_RELOAD_POLICY,
    ),
    KeyType(
        "RFC3964_IPv4",
        key_type=bool,
        default=config.FALLBACK_RFC3964_IPV4,
        dbus_mode="readwrite",
    ),
    KeyType(
        "AllowZoneDrifting",
        key_type=bool,
        default=config.FALLBACK_ALLOW_ZONE_DRIFTING,
        is_deprecated=True,
        dbus_ignore_set=True,
        dbus_mode="readwrite",
    ),
    KeyType(
        "NftablesFlowtable",
        key_type=str,
        default=config.FALLBACK_NFTABLES_FLOWTABLE,
        dbus_mode="readwrite",
    ),
    KeyType(
        "NftablesCounters",
        key_type=bool,
        default=config.FALLBACK_NFTABLES_COUNTERS,
        dbus_mode="readwrite",
    ),
]

valid_keys = {t.key: t for t in valid_keys}


class firewalld_conf:
    def __init__(self, filename):
        self._config = {}
        self.filename = filename
        self.clear()

    def clear(self):
        self._config = {}

    def cleanup(self):
        self._config.clear()

    def get(self, key, as_type=None):
        v = self._config.get(key)
        if as_type is None:
            return v
        keytype = valid_keys[key]
        return keytype.get_as(v, as_type)

    def set(self, key, value, strict=True, set_default_on_failure=False):
        keytype = valid_keys[key]

        try:
            value2 = keytype.normalize(value, strict=True, log_warn=False)
        except firewall.errors.FirewallError:
            if strict:
                raise
            if not set_default_on_failure:
                # On error, we do nothing. Otherwise, proceed and reset the
                # default value.
                return None
            value2 = keytype.normalize(keytype.default, strict=False, log_warn=False)

        self._config[key] = value2
        return value2

    def __str__(self):
        s = ""
        for key, value in self._config.items():
            if s:
                s += "\n"
            s += "%s=%s" % (key, value)
        return s

    def set_defaults(self):
        for keytype in valid_keys.values():
            self.set(keytype.key, keytype.default)
        self._normalize()

    # load self.filename
    def read(self):
        self.clear()
        try:
            f = open(self.filename, "r")
        except Exception as msg:
            log.error("Failed to load '%s': %s", self.filename, msg)
            self.set_defaults()
            raise

        for line in f:
            if not line:
                break
            line = line.strip()
            if len(line) < 1 or line[0] in ["#", ";"]:
                continue
            # get key/value pair
            pair = [x.strip() for x in line.split("=")]
            if len(pair) != 2:
                log.error("Invalid option definition: '%s'", line.strip())
                continue
            elif pair[0] not in valid_keys:
                log.error("Invalid option: '%s'", line.strip())
                continue
            elif pair[1] == "":
                log.error("Missing value: '%s'", line.strip())
                continue
            elif self._config.get(pair[0]) is not None:
                log.error("Duplicate option definition: '%s'", line.strip())
                continue
            self._config[pair[0]] = pair[1]
        f.close()

        self._normalize()

    def _normalize(self):
        for keytype in valid_keys.values():
            value = self.get(keytype.key)
            value2 = keytype.normalize(value, strict=False)
            if value != value2:
                self.set(keytype.key, value2)

    # save to self.filename if there are key/value changes
    def write(self):
        if len(self._config) < 1:
            # no changes: nothing to do
            return

        # handled keys
        done = []

        if not os.path.exists(config.ETC_FIREWALLD):
            os.mkdir(config.ETC_FIREWALLD, 0o750)

        try:
            temp_file = tempfile.NamedTemporaryFile(
                mode="wt",
                prefix="%s." % os.path.basename(self.filename),
                dir=os.path.dirname(self.filename),
                delete=False,
            )
        except Exception as msg:
            log.error("Failed to open temporary file: %s" % msg)
            raise

        modified = False
        empty = False
        try:
            f = io.open(self.filename, mode="rt", encoding="UTF-8")
        except Exception as msg:
            if os.path.exists(self.filename):
                log.error("Failed to open '%s': %s" % (self.filename, msg))
                raise
            else:
                f = None
        else:
            for line in f:
                if not line:
                    break
                # remove newline
                line = line.strip("\n")

                if len(line) < 1:
                    if not empty:
                        temp_file.write("\n")
                        empty = True
                elif line[0] == "#":
                    empty = False
                    temp_file.write(line)
                    temp_file.write("\n")
                else:
                    p = line.split("=")
                    if len(p) != 2:
                        empty = False
                        temp_file.write(line + "\n")
                        continue
                    key = p[0].strip()
                    value = p[1].strip()
                    # check for modified key/value pairs
                    if key not in done:
                        if key in self._config and self._config[key] != value:
                            empty = False
                            temp_file.write("%s=%s\n" % (key, self._config[key]))
                            modified = True
                        else:
                            empty = False
                            temp_file.write(line + "\n")
                        done.append(key)
                    else:
                        modified = True

        # write remaining key/value pairs
        if len(self._config) > 0:
            for key, value in self._config.items():
                if key in done:
                    continue
                if valid_keys[key].is_deprecated:
                    # omit deprecated from new config
                    continue
                if not empty:
                    temp_file.write("\n")
                    empty = True
                temp_file.write("%s=%s\n" % (key, value))
                modified = True

        if f:
            f.close()
        temp_file.close()

        if not modified:  # not modified: remove tempfile
            os.remove(temp_file.name)
            return
        # make backup
        if os.path.exists(self.filename):
            try:
                shutil.copy2(self.filename, "%s.old" % self.filename)
            except Exception as msg:
                os.remove(temp_file.name)
                raise IOError("Backup of '%s' failed: %s" % (self.filename, msg))

        # copy tempfile
        try:
            shutil.move(temp_file.name, self.filename)
        except Exception as msg:
            os.remove(temp_file.name)
            raise IOError("Failed to create '%s': %s" % (self.filename, msg))
        else:
            os.chmod(self.filename, 0o600)
