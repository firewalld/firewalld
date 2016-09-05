#!/usr/bin/python -Es
# -*- coding: utf-8 -*-
#
# Copyright (C) 2016 Red Hat, Inc.
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

class NiceExpander(object):
    def __init__(self, expanded_button, unexpanded_button, paned, child):
        self.expanded_button = expanded_button
        self.unexpanded_button = unexpanded_button
        self.paned = paned
        self.child = child
        self.sensitive = True
        self.expanded = False
        self.callback = { }
        self.parent = self.expanded_button.get_parent()

        self.expanded_button.connect("clicked", self.expand_cb)
        self.unexpanded_button.connect("clicked", self.unexpand_cb)

        self.set_expanded(True)

    def expand_cb(self, *args):
        self.expanded = False
        self.expanded_button.hide()
        self.unexpanded_button.show()
        self.child.hide()
        width = self.unexpanded_button.get_allocated_width()
        width += self.parent.get_border_width()*2
        self.paned.set_position(width)
        self.call_notify_expanded()

    def unexpand_cb(self, *args):
        self.expanded = True
        self.expanded_button.show()
        self.unexpanded_button.hide()
        self.child.show()
        width = self.expanded_button.get_allocated_width()
        width += self.parent.get_border_width()*2
        self.paned.set_position(width)
        self.call_notify_expanded()

    def set_expanded(self, flag):
        self.expanded = flag
        if flag:
            self.unexpand_cb()
        else:
            self.expand_cb()

    def get_expanded(self):
        return self.expanded

    def connect(self, name, callback, *args):
        if name == "notify::expanded":
            self.callback[name] = (callback, args)
        else:
            raise ValueError("Unknown callback name '%s'" % name)

    def call_notify_expanded(self):
        name = "notify::expanded"
        if name in self.callback:
            cb = self.callback[name]
            try:
                cb[0](*cb[1])
            except Exception as msg:
                print(msg)

    def set_sensitive(self, value):
        self.expanded_button.set_sensitive(value)
        self.unexpanded_button.set_sensitive(value)
        self.child.set_sensitive(value)

    def get_sensitive(self):
        return self.expanded_button.get_sensitive()

    def is_sensitive(self):
        return self.expanded_button.is_sensitive()
