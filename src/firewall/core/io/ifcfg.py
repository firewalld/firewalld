# -*- coding: utf-8 -*-
#
# Copyright (C) 2011-2016 Red Hat, Inc.
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

"""ifcfg file parser"""

__all__ = [ "ifcfg" ]

import os.path
import io
import tempfile
import shutil

from firewall.core.logger import log

class ifcfg(object):
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

    def get(self, key):
        return self._config.get(key.strip())

    def set(self, key, value):
        _key = key.strip()
        self._config[_key] = value.strip()
        if _key in self._deleted:
            self._deleted.remove(_key)

    def __str__(self):
        s = ""
        for (key, value) in self._config.items():
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
            raise

        for line in f:
            if not line:
                break
            line = line.strip()
            if len(line) < 1 or line[0] in ['#', ';']:
                continue
            # get key/value pair
            pair = [ x.strip() for x in line.split("=", 1) ]
            if len(pair) != 2:
                continue
            if len(pair[1]) >= 2 and \
               pair[1].startswith('"') and pair[1].endswith('"'):
                pair[1] = pair[1][1:-1]
            if pair[1] == '':
                continue
            elif self._config.get(pair[0]) is not None:
                log.warning("%s: Duplicate option definition: '%s'", self.filename, line.strip())
                continue
            self._config[pair[0]] = pair[1]
        f.close()

    def write(self):
        if len(self._config) < 1:
            # no changes: nothing to do
            return

        # handled keys
        done = [ ]

        try:
            temp_file = tempfile.NamedTemporaryFile(
                mode='wt',
                prefix="%s." % os.path.basename(self.filename),
                dir=os.path.dirname(self.filename), delete=False)
        except Exception as msg:
            log.error("Failed to open temporary file: %s" % msg)
            raise

        modified = False
        empty = False
        try:
            f = io.open(self.filename, mode='rt', encoding='UTF-8')
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
                    p = line.split("=", 1)
                    if len(p) != 2:
                        empty = False
                        temp_file.write(line+u"\n")
                        continue
                    key = p[0].strip()
                    value = p[1].strip()
                    if len(value) >= 2 and \
                       value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    # check for modified key/value pairs
                    if key not in done:
                        if key in self._config and self._config[key] != value:
                            empty = False
                            temp_file.write(u'%s=%s\n' % (key,
                                                          self._config[key]))
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
            for (key, value) in self._config.items():
                if key in done:
                    continue
                if not empty:
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
                shutil.copy2(self.filename, "%s.bak" % self.filename)
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
