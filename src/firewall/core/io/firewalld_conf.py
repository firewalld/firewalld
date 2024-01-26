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

import firewall.errors
import firewall.functions
from firewall import config
from firewall.core.logger import log


def _validate_bool(value, default):
    valid = True
    try:
        v = firewall.functions.str_to_bool(value)
    except ValueError:
        valid = False
        v = firewall.functions.str_to_bool(default)

    return ("yes" if v else "no"), valid


def _validate_enum(value, enum_values, default):

    for f in enum_values:
        assert isinstance(f, str)
        assert f == f.strip()
        assert f == f.lower()

    assert default in enum_values

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


valid_keys = [
    "DefaultZone",
    "MinimalMark",
    "CleanupOnExit",
    "CleanupModulesOnExit",
    "Lockdown",
    "IPv6_rpfilter",
    "IndividualCalls",
    "LogDenied",
    "AutomaticHelpers",
    "FirewallBackend",
    "FlushAllOnReload",
    "ReloadPolicy",
    "RFC3964_IPv4",
    "AllowZoneDrifting",
    "NftablesFlowtable",
    "NftablesCounters",
]


class firewalld_conf:
    def __init__(self, filename):
        self._config = {}
        self._deleted = []
        self.filename = filename
        self.clear()

    def clear(self):
        self._config = {}
        self._deleted = []

    def cleanup(self):
        self._config.clear()
        self._deleted = []

    def get(self, key):
        return self._config.get(key.strip())

    def set(self, key, value):
        _key = key.strip()
        self._config[_key] = value.strip()
        if _key in self._deleted:
            self._deleted.remove(_key)

    def __str__(self):
        s = ""
        for key, value in self._config.items():
            if s:
                s += "\n"
            s += "%s=%s" % (key, value)
        return s

    def set_defaults(self):
        self.set("DefaultZone", config.FALLBACK_ZONE)
        self.set("MinimalMark", str(config.FALLBACK_MINIMAL_MARK))
        self.set("CleanupOnExit", "yes" if config.FALLBACK_CLEANUP_ON_EXIT else "no")
        self.set(
            "CleanupModulesOnExit",
            "yes" if config.FALLBACK_CLEANUP_MODULES_ON_EXIT else "no",
        )
        self.set("Lockdown", "yes" if config.FALLBACK_LOCKDOWN else "no")
        self.set("IPv6_rpfilter", "yes" if config.FALLBACK_IPV6_RPFILTER else "no")
        self.set("IndividualCalls", "yes" if config.FALLBACK_INDIVIDUAL_CALLS else "no")
        self.set("LogDenied", config.FALLBACK_LOG_DENIED)
        self.set("AutomaticHelpers", config.FALLBACK_AUTOMATIC_HELPERS)
        self.set("FirewallBackend", config.FALLBACK_FIREWALL_BACKEND)
        self.set(
            "FlushAllOnReload", "yes" if config.FALLBACK_FLUSH_ALL_ON_RELOAD else "no"
        )
        self.set("ReloadPolicy", config.FALLBACK_RELOAD_POLICY)
        self.set("RFC3964_IPv4", "yes" if config.FALLBACK_RFC3964_IPV4 else "no")
        self.set(
            "AllowZoneDrifting", "yes" if config.FALLBACK_ALLOW_ZONE_DRIFTING else "no"
        )
        self.set("NftablesFlowtable", config.FALLBACK_NFTABLES_FLOWTABLE)
        self.set(
            "NftablesCounters", "yes" if config.FALLBACK_NFTABLES_COUNTERS else "no"
        )

        self._normalize()

    def _normalize_bool(self, property_name, default):
        value0 = self.get(property_name)
        value, valid = _validate_bool(value0, default)
        if not valid:
            log.warning(
                f"{property_name} '{value0}' is not a valid boolean, using default value '{default}'"
            )
        if value0 != value:
            self.set(property_name, value)

    def _normalize_enum(self, property_name, enum_values, default):
        value0 = self.get(property_name)
        value, valid = _validate_enum(value0, enum_values, default)
        if not valid:
            log.warning(
                f"{property_name} '{value0}' is invalid, using default value '{default}'"
            )
        if value0 != value:
            self.set(property_name, value)

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

        if not self.get("DefaultZone"):
            log.error(
                "DefaultZone is not set, using default value '%s'", config.FALLBACK_ZONE
            )
            self.set("DefaultZone", str(config.FALLBACK_ZONE))

        value = self.get("MinimalMark")
        try:
            v = int(value)
        except (ValueError, TypeError):
            v = int(config.FALLBACK_MINIMAL_MARK)
            if value is not None:
                log.warning(
                    f"MinimalMark '{value}' is not valid, using default value '{v}'",
                )
        value2 = str(v)
        if value != value2:
            self.set("MinimalMark", value2)

        self._normalize_bool(
            "CleanupOnExit",
            config.FALLBACK_CLEANUP_ON_EXIT,
        )

        self._normalize_bool(
            "CleanupModulesOnExit",
            config.FALLBACK_CLEANUP_MODULES_ON_EXIT,
        )

        self._normalize_bool(
            "Lockdown",
            config.FALLBACK_LOCKDOWN,
        )

        self._normalize_bool(
            "IPv6_rpfilter",
            config.FALLBACK_IPV6_RPFILTER,
        )

        self._normalize_bool(
            "IndividualCalls",
            config.FALLBACK_INDIVIDUAL_CALLS,
        )

        self._normalize_enum(
            "LogDenied",
            config.LOG_DENIED_VALUES,
            config.FALLBACK_LOG_DENIED,
        )

        self._normalize_enum(
            "AutomaticHelpers",
            config.AUTOMATIC_HELPERS_VALUES,
            config.FALLBACK_AUTOMATIC_HELPERS,
        )

        self._normalize_enum(
            "FirewallBackend",
            config.FIREWALL_BACKEND_VALUES,
            config.FALLBACK_FIREWALL_BACKEND,
        )

        self._normalize_bool(
            "FlushAllOnReload",
            config.FALLBACK_FLUSH_ALL_ON_RELOAD,
        )

        value = self.get("ReloadPolicy")
        try:
            value = self._parse_reload_policy(value)
        except ValueError:
            log.warning(
                f"ReloadPolicy '{value}' is not valid, using default value '{config.FALLBACK_RELOAD_POLICY}'"
            )
            self.set("ReloadPolicy", config.FALLBACK_RELOAD_POLICY)

        self._normalize_bool(
            "RFC3964_IPv4",
            config.FALLBACK_RFC3964_IPV4,
        )

        self._normalize_bool(
            "AllowZoneDrifting",
            config.FALLBACK_ALLOW_ZONE_DRIFTING,
        )

        value = self.get("NftablesFlowtable")
        if value is None:
            self.set("NftablesFlowtable", config.FALLBACK_NFTABLES_FLOWTABLE)

        self._normalize_bool(
            "NftablesCounters",
            config.FALLBACK_NFTABLES_COUNTERS,
        )

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
                        elif key in self._deleted:
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
                if key in [
                    "MinimalMark",
                    "AutomaticHelpers",
                    "AllowZoneDrifting",
                ]:  # omit deprecated from new config
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

    @staticmethod
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

    @staticmethod
    def _unparse_reload_policy(value):
        return ",".join(f"{k}:{v}" for k, v in value.items())
