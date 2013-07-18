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

import os, os.path
import tempfile
import shutil

from firewall.core.logger import log

valid_keys = ["DefaultZone", "MinimalMark", "CleanupOnExit", "Lockdown"]

class firewalld_conf:
    def __init__(self, filename):
        self.filename = filename
        self.clear()

    def clear(self):
        self._config = { }
        self._deleted = [ ]

    def get(self, key):
        return self._config.get(key.strip())

    def set(self, key, value):
        _key = key.strip()
        self._config[_key] = value.strip()
        if _key in self._deleted:
            self._deleted.remove[_key]

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
            log.error("Failed to open '%s': %s" % (self.filename, msg))
            raise

        for line in f.xreadlines():
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
            elif self._config.get(pair[0]) != None:
                log.error("Duplicate option definition: '%s'", line.strip())
                continue
            self._config[pair[0]] = pair[1]
        f.close()

    # save to self.filename if there are key/value changes
    def write(self):
        if len(self._config) < 1:
            # no changes: nothing to do
            return

        # handled keys
        done = [ ]

        try:
            (temp_file, temp) = tempfile.mkstemp(prefix="%s." % os.path.basename(self.filename),
                                                 dir=os.path.dirname(self.filename))
        except Exception as msg:
            log.error("Failed to open temporary file: %s" % msg)
            raise

        modified = False
        empty = False
        try:
            f = open(self.filename, "r")
        except Exception as msg:
            if os.path.exists(self.filename):
                log.error("Failed to open '%s': %s" % (self.filename, msg))
                raise
            else:
                f = None
        else:
            for line in f.xreadlines():
                if not line:
                    break
                # remove newline
                line = line.strip("\n")

                if len(line) < 1:
                    if not empty:
                        os.write(temp_file, "\n")
                        empty = True
                elif line[0] == '#':
                    empty = False
                    os.write(temp_file, line)
                    os.write(temp_file, "\n")
                else:
                    p = line.split("=")
                    if len(p) != 2:
                        empty = False
                        os.write(temp_file, line+"\n")
                        continue
                    key = p[0].strip()
                    value = p[1].strip()
                    # check for modified key/value pairs
                    if key not in done:
                        if (key in self._config and \
                                self._config[key] != value):
                            empty = False
                            os.write(temp_file, '%s=%s\n' \
                                         % (key, self._config[key]))
                            modified = True
                        elif key in self._deleted:
                            modified = True
                        else:
                            empty = False
                            os.write(temp_file, line+"\n")
                        done.append(key)
                    else:
                        modified = True

        # write remaining key/value pairs
        if len(self._config) > 0:
            for (key,value) in self._config.items():
                if key in done:
                    continue
                if not empty:
                    os.write(temp_file, "\n")
                    empty = True
                os.write(temp_file, '%s=%s\n' % (key, value))
                modified = True

        if f:
            f.close()
        os.close(temp_file)

        if not modified: # not modified: remove tempfile
            os.remove(temp)
            return
        # make backup
        if os.path.exists(self.filename):
            try:
                shutil.copy2(self.filename, "%s.old" % self.filename)
            except Exception as msg:
                os.remove(temp)
                raise IOError("Backup of '%s' failed: %s" % (self.filename, msg))

        # copy tempfile
        try:
            shutil.move(temp, self.filename)
        except Exception as msg:
            os.remove(temp)
            raise IOError("Failed to create '%s': %s" % (self.filename, msg))
        else:
            os.chmod(self.filename, 0600)
