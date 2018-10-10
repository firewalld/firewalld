# -*- coding: utf-8 -*-
#
# Copyright (C) 2012-2016 Red Hat, Inc.
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

__all__ = [ "Watcher" ]

from gi.repository import Gio, GLib

class Watcher(object):
    def __init__(self, callback, timeout):
        self._callback = callback
        self._timeout = timeout
        self._monitors = { }
        self._timeouts = { }
        self._blocked = [ ]

    def add_watch_dir(self, directory):
        gfile = Gio.File.new_for_path(directory)
        self._monitors[directory] = gfile.monitor_directory(\
            Gio.FileMonitorFlags.NONE, None)
        self._monitors[directory].connect("changed", self._file_changed_cb)

    def add_watch_file(self, filename):
        gfile = Gio.File.new_for_path(filename)
        self._monitors[filename] = gfile.monitor_file(\
            Gio.FileMonitorFlags.NONE, None)
        self._monitors[filename].connect("changed", self._file_changed_cb)

    def get_watches(self):
        return self._monitors.keys()
        
    def has_watch(self, filename):
        return filename in self._monitors

    def remove_watch(self, filename):
        del self._monitors[filename]

    def block_source(self, filename):
        if filename not in self._blocked:
            self._blocked.append(filename)

    def unblock_source(self, filename):
        if filename in self._blocked:
            self._blocked.remove(filename)

    def clear_timeouts(self):
        for filename in list(self._timeouts.keys()):
            GLib.source_remove(self._timeouts[filename])
            del self._timeouts[filename]

    def _call_callback(self, filename):
        if filename not in self._blocked:
            self._callback(filename)
        del self._timeouts[filename]

    def _file_changed_cb(self, monitor, gio_file, gio_other_file, event):
        filename = gio_file.get_parse_name()
        if filename in self._blocked:
            if filename in self._timeouts:
                GLib.source_remove(self._timeouts[filename])
                del self._timeouts[filename]
            return

        if event == Gio.FileMonitorEvent.CHANGED or \
                event == Gio.FileMonitorEvent.CREATED or \
                event == Gio.FileMonitorEvent.DELETED or \
                event == Gio.FileMonitorEvent.ATTRIBUTE_CHANGED:
            if filename in self._timeouts:
                GLib.source_remove(self._timeouts[filename])
                del self._timeouts[filename]
            self._timeouts[filename] = GLib.timeout_add_seconds(\
                self._timeout, self._call_callback, filename)
