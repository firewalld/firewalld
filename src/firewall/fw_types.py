# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2013-2016 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>


class LastUpdatedOrderedDict:
    def __init__(self, x=None):
        self._dict = {}
        self._list = []
        if x:
            self.update(x)

    def clear(self):
        del self._list[:]
        self._dict.clear()

    def update(self, x):
        for key, value in x.items():
            self[key] = value

    def items(self):
        return [(key, self[key]) for key in self._list]

    def __delitem__(self, key):
        if key in self._dict:
            self._list.remove(key)
            del self._dict[key]

    def __repr__(self):
        return "%s([%s])" % (
            self.__class__.__name__,
            ", ".join(["(%r, %r)" % (key, self[key]) for key in self._list]),
        )

    def __setitem__(self, key, value):
        if key not in self._dict:
            self._list.append(key)
        self._dict[key] = value

    def __getitem__(self, key):
        if isinstance(key, int):
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
        return [self[key] for key in self._list]

    def setdefault(self, key, value=None):
        if key in self:
            return self[key]
        else:
            self[key] = value
            return value
