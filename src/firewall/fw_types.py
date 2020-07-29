# -*- coding: utf-8 -*-
#
# Copyright (C) 2013-2016 Red Hat, Inc.
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

__all__ = [ "LastUpdatedOrderedDict" ]

class LastUpdatedOrderedDict(object):
    def __init__(self, x=None):
        self._dict = { }
        self._list = [ ]
        if x:
            self.update(x)

    def clear(self):
        del self._list[:]
        self._dict.clear()

    def update(self, x):
        for key,value in x.items():
            self[key] = value

    def items(self):
        return [(key, self[key]) for key in self._list]

    def __delitem__(self, key):
        if key in self._dict:
            self._list.remove(key)
            del self._dict[key]

    def __repr__(self):
        return '%s([%s])' % (self.__class__.__name__, ', '.join(
                ['(%r, %r)' % (key, self[key]) for key in self._list]))

    def __setitem__(self, key, value):
        if key not in self._dict:
            self._list.append(key)
        self._dict[key] = value

    def __getitem__(self, key):
        if type(key) == int:
            return self._list[key]
        else:
            return self._dict[key]

    def __len__(self):
        return len(self._list)

    def copy(self):
        return LastUpdatedOrderedDict(self)

    def keys(self):
        return self._list[:]

    def values(self):
        return [ self[key] for key in self._list ]

    def setdefault(self, key, value=None):
        if key in self:
            return self[key]
        else:
            self[key] = value
            return value
