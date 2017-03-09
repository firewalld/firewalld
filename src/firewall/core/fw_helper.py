# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2016 Red Hat, Inc.
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

"""helper backend"""

__all__ = [ "FirewallHelper" ]

from firewall import errors
from firewall.errors import FirewallError

class FirewallHelper(object):
    def __init__(self, fw):
        self._fw = fw
        self._helpers = { }

    def __repr__(self):
        return '%s(%r)' % (self.__class__, self._helpers)

    # helpers

    def cleanup(self):
        self._helpers.clear()

    def check_helper(self, name):
        if name not in self.get_helpers():
            raise FirewallError(errors.INVALID_HELPER, name)

    def query_helper(self, name):
        return name in self.get_helpers()

    def get_helpers(self):
        return sorted(self._helpers.keys())

    def has_helpers(self):
        return len(self._helpers) > 0

    def get_helper(self, name):
        self.check_helper(name)
        return self._helpers[name]

    def add_helper(self, obj):
        self._helpers[obj.name] = obj

    def remove_helper(self, name):
        if name not in self._helpers:
            raise FirewallError(errors.INVALID_HELPER, name)
        del self._helpers[name]
