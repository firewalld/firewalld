# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2012-2016 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>

from gi.repository import Gio, GLib


class Watcher:
    def __init__(self, callback, timeout):
        self._callback = callback
        self._timeout = timeout
        self._monitors = {}
        self._timeouts = {}

    def add_watch_dir(self, directory):
        gfile = Gio.File.new_for_path(directory)
        self._monitors[directory] = gfile.monitor_directory(
            Gio.FileMonitorFlags.NONE, None
        )
        self._monitors[directory].connect("changed", self._file_changed_cb)

    def add_watch_file(self, filename):
        gfile = Gio.File.new_for_path(filename)
        self._monitors[filename] = gfile.monitor_file(Gio.FileMonitorFlags.NONE, None)
        self._monitors[filename].connect("changed", self._file_changed_cb)

    def get_watches(self):
        return self._monitors.keys()

    def has_watch(self, filename):
        return filename in self._monitors

    def remove_watch(self, filename):
        del self._monitors[filename]

    def clear_timeouts(self):
        for filename in list(self._timeouts.keys()):
            GLib.source_remove(self._timeouts[filename])
            del self._timeouts[filename]

    def _call_callback(self, filename):
        del self._timeouts[filename]
        self._callback(filename)

    def _file_changed_cb(self, monitor, gio_file, gio_other_file, event):
        filename = gio_file.get_parse_name()

        if (
            event == Gio.FileMonitorEvent.CHANGED
            or event == Gio.FileMonitorEvent.CREATED
            or event == Gio.FileMonitorEvent.DELETED
            or event == Gio.FileMonitorEvent.ATTRIBUTE_CHANGED
        ):
            if filename in self._timeouts:
                GLib.source_remove(self._timeouts[filename])
                del self._timeouts[filename]
            self._timeouts[filename] = GLib.timeout_add_seconds(
                self._timeout, self._call_callback, filename
            )
