# -*- coding: utf-8 -*-
#
# Copyright (C) 2011-2012 Red Hat, Inc.
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
#

import os.path
import io
import tempfile
import shutil

from firewall import config
from firewall.core.logger import log

valid_keys = [ "DefaultZone", "MinimalMark", "CleanupOnExit",
               "CleanupModulesOnExit", "Lockdown", "IPv6_rpfilter",
               "IndividualCalls", "LogDenied", "AutomaticHelpers",
               "FirewallBackend", "FlushAllOnReload", "RFC3964_IPv4",
               "AllowZoneDrifting" ]

class firewalld_conf(object):
    def __init__(self, filename):
        self._config = { }
        self._deleted = [ ]
        self.filename = filename
        self.clear()

    def clear(self):
        self._config = { }
        self._deleted = [ ]

    def cleanup(self):
        self._config.clear()
        self._deleted = [ ]

    def get(self, key):
        return self._config.get(key.strip())

    def set(self, key, value):
        _key = key.strip()
        self._config[_key] = value.strip()
        if _key in self._deleted:
            self._deleted.remove(_key)

    def __str__(self):
        s = ""
        for (key,value) in self._config.items():
            if s:
                s += '\n'
            s += '%s=%s' % (key, value)
        return s

    # load self.filename
    def read(self):
        self.clear()
        try:
            f = open(self.filename, "r")
        except Exception as msg:
            log.error("Failed to load '%s': %s", self.filename, msg)
            self.set("DefaultZone", config.FALLBACK_ZONE)
            self.set("MinimalMark", str(config.FALLBACK_MINIMAL_MARK))
            self.set("CleanupOnExit", "yes" if config.FALLBACK_CLEANUP_ON_EXIT else "no")
            self.set("CleanupModulesOnExit", "yes" if config.FALLBACK_CLEANUP_MODULES_ON_EXIT else "no")
            self.set("Lockdown", "yes" if config.FALLBACK_LOCKDOWN else "no")
            self.set("IPv6_rpfilter","yes" if config.FALLBACK_IPV6_RPFILTER else "no")
            self.set("IndividualCalls", "yes" if config.FALLBACK_INDIVIDUAL_CALLS else "no")
            self.set("LogDenied", config.FALLBACK_LOG_DENIED)
            self.set("AutomaticHelpers", config.FALLBACK_AUTOMATIC_HELPERS)
            self.set("FirewallBackend", config.FALLBACK_FIREWALL_BACKEND)
            self.set("FlushAllOnReload", "yes" if config.FALLBACK_FLUSH_ALL_ON_RELOAD else "no")
            self.set("RFC3964_IPv4", "yes" if config.FALLBACK_RFC3964_IPV4 else "no")
            self.set("AllowZoneDrifting", "yes" if config.FALLBACK_ALLOW_ZONE_DRIFTING else "no")
            raise

        for line in f:
            if not line:
                break
            line = line.strip()
            if len(line) < 1 or line[0] in ['#', ';']:
                continue
            # get key/value pair
            pair = [ x.strip() for x in line.split("=") ]
            if len(pair) != 2:
                log.error("Invalid option definition: '%s'", line.strip())
                continue
            elif pair[0] not in valid_keys:
                log.error("Invalid option: '%s'", line.strip())
                continue
            elif pair[1] == '':
                log.error("Missing value: '%s'", line.strip())
                continue
            elif self._config.get(pair[0]) is not None:
                log.error("Duplicate option definition: '%s'", line.strip())
                continue
            self._config[pair[0]] = pair[1]
        f.close()

        # check default zone
        if not self.get("DefaultZone"):
            log.error("DefaultZone is not set, using default value '%s'",
                      config.FALLBACK_ZONE)
            self.set("DefaultZone", str(config.FALLBACK_ZONE))

        # check minimal mark
        value = self.get("MinimalMark")
        try:
            int(value)
        except (ValueError, TypeError):
            if value is not None:
                log.warning("MinimalMark '%s' is not valid, using default "
                            "value '%d'", value if value else '',
                            config.FALLBACK_MINIMAL_MARK)
            self.set("MinimalMark", str(config.FALLBACK_MINIMAL_MARK))

        # check cleanup on exit
        value = self.get("CleanupOnExit")
        if not value or value.lower() not in [ "no", "false", "yes", "true" ]:
            if value is not None:
                log.warning("CleanupOnExit '%s' is not valid, using default "
                            "value %s", value if value else '',
                            config.FALLBACK_CLEANUP_ON_EXIT)
            self.set("CleanupOnExit", "yes" if config.FALLBACK_CLEANUP_ON_EXIT else "no")

        # check module cleanup on exit
        value = self.get("CleanupModulesOnExit")
        if not value or value.lower() not in [ "no", "false", "yes", "true" ]:
            if value is not None:
                log.warning("CleanupModulesOnExit '%s' is not valid, using default "
                            "value %s", value if value else '',
                            config.FALLBACK_CLEANUP_MODULES_ON_EXIT)
            self.set("CleanupModulesOnExit", "yes" if config.FALLBACK_CLEANUP_MODULES_ON_EXIT else "no")

        # check lockdown
        value = self.get("Lockdown")
        if not value or value.lower() not in [ "yes", "true", "no", "false" ]:
            if value is not None:
                log.warning("Lockdown '%s' is not valid, using default "
                            "value %s", value if value else '',
                            config.FALLBACK_LOCKDOWN)
            self.set("Lockdown", "yes" if config.FALLBACK_LOCKDOWN else "no")

        # check ipv6_rpfilter
        value = self.get("IPv6_rpfilter")
        if not value or value.lower() not in [ "yes", "true", "no", "false" ]:
            if value is not None:
                log.warning("IPv6_rpfilter '%s' is not valid, using default "
                            "value %s", value if value else '',
                            config.FALLBACK_IPV6_RPFILTER)
            self.set("IPv6_rpfilter","yes" if config.FALLBACK_IPV6_RPFILTER else "no")

        # check individual calls
        value = self.get("IndividualCalls")
        if not value or value.lower() not in [ "yes", "true", "no", "false" ]:
            if value is not None:
                log.warning("IndividualCalls '%s' is not valid, using default "
                            "value %s", value if value else '',
                            config.FALLBACK_INDIVIDUAL_CALLS)
            self.set("IndividualCalls", "yes" if config.FALLBACK_INDIVIDUAL_CALLS else "no")

        # check log denied
        value = self.get("LogDenied")
        if not value or value not in config.LOG_DENIED_VALUES:
            if value is not None:
                log.warning("LogDenied '%s' is invalid, using default value '%s'",
                            value, config.FALLBACK_LOG_DENIED)
            self.set("LogDenied", str(config.FALLBACK_LOG_DENIED))

        # check automatic helpers
        value = self.get("AutomaticHelpers")
        if not value or value.lower() not in config.AUTOMATIC_HELPERS_VALUES:
            if value is not None:
                log.warning("AutomaticHelpers '%s' is not valid, using default "
                            "value %s", value if value else '',
                            config.FALLBACK_AUTOMATIC_HELPERS)
            self.set("AutomaticHelpers", str(config.FALLBACK_AUTOMATIC_HELPERS))

        value = self.get("FirewallBackend")
        if not value or value.lower() not in config.FIREWALL_BACKEND_VALUES:
            if value is not None:
                log.warning("FirewallBackend '%s' is not valid, using default "
                            "value %s", value if value else '',
                            config.FALLBACK_FIREWALL_BACKEND)
            self.set("FirewallBackend", str(config.FALLBACK_FIREWALL_BACKEND))

        value = self.get("FlushAllOnReload")
        if not value or value.lower() not in [ "yes", "true", "no", "false" ]:
            if value is not None:
                log.warning("FlushAllOnReload '%s' is not valid, using default "
                            "value %s", value if value else '',
                            config.FALLBACK_FLUSH_ALL_ON_RELOAD)
            self.set("FlushAllOnReload", str(config.FALLBACK_FLUSH_ALL_ON_RELOAD))

        value = self.get("RFC3964_IPv4")
        if not value or value.lower() not in [ "yes", "true", "no", "false" ]:
            if value is not None:
                log.warning("RFC3964_IPv4 '%s' is not valid, using default "
                            "value %s", value if value else '',
                            config.FALLBACK_RFC3964_IPV4)
            self.set("RFC3964_IPv4", str(config.FALLBACK_RFC3964_IPV4))

        value = self.get("AllowZoneDrifting")
        if not value or value.lower() not in [ "yes", "true", "no", "false" ]:
            if value is not None:
                log.warning("AllowZoneDrifting '%s' is not valid, using default "
                            "value %s", value if value else '',
                            config.FALLBACK_ALLOW_ZONE_DRIFTING)
            self.set("AllowZoneDrifting", "yes" if config.FALLBACK_ALLOW_ZONE_DRIFTING else "no")

    # save to self.filename if there are key/value changes
    def write(self):
        if len(self._config) < 1:
            # no changes: nothing to do
            return

        # handled keys
        done = [ ]

        if not os.path.exists(config.ETC_FIREWALLD):
            os.mkdir(config.ETC_FIREWALLD, 0o750)

        try:
            temp_file = tempfile.NamedTemporaryFile(mode='wt',
                             prefix="%s." % os.path.basename(self.filename),
                             dir=os.path.dirname(self.filename), delete=False)
        except Exception as msg:
            log.error("Failed to open temporary file: %s" % msg)
            raise

        modified = False
        empty = False
        try:
            f= io.open(self.filename, mode='rt', encoding='UTF-8')
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
                        temp_file.write(u"\n")
                        empty = True
                elif line[0] == '#':
                    empty = False
                    temp_file.write(line)
                    temp_file.write(u"\n")
                else:
                    p = line.split("=")
                    if len(p) != 2:
                        empty = False
                        temp_file.write(line+u"\n")
                        continue
                    key = p[0].strip()
                    value = p[1].strip()
                    # check for modified key/value pairs
                    if key not in done:
                        if (key in self._config and \
                                self._config[key] != value):
                            empty = False
                            temp_file.write(u'%s=%s\n' %
                                            (key, self._config[key]))
                            modified = True
                        elif key in self._deleted:
                            modified = True
                        else:
                            empty = False
                            temp_file.write(line+u"\n")
                        done.append(key)
                    else:
                        modified = True

        # write remaining key/value pairs
        if len(self._config) > 0:
            for (key,value) in self._config.items():
                if key in done:
                    continue
                if key in ["MinimalMark", "AutomaticHelpers", "AllowZoneDrifting"]: # omit deprecated from new config
                    continue
                if not empty:
                    temp_file.write(u"\n")
                    empty = True
                temp_file.write(u'%s=%s\n' % (key, value))
                modified = True

        if f:
            f.close()
        temp_file.close()

        if not modified: # not modified: remove tempfile
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
