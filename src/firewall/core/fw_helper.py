# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2015-2016 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>

"""helper backend"""

from firewall import errors
from firewall.errors import FirewallError


class FirewallHelper:
    def __init__(self, fw):
        self._fw = fw
        self._helpers = {}

    def __repr__(self):
        return "%s(%r)" % (self.__class__, self._helpers)

    # helpers

    def cleanup(self):
        self._helpers.clear()

    def get_helpers(self):
        return sorted(self._helpers)

    def has_helpers(self):
        return len(self._helpers) > 0

    def query_helper(self, name):
        return self.has_helper(name)

    def check_helper(self, name):
        return self.get_helper(name).name

    def has_helper(self, name):
        return self.get_helper(name, required=False) is not None

    def get_helper(self, name, required=True):
        obj = self._helpers.get(name)
        if obj is None and required:
            raise FirewallError(errors.INVALID_HELPER, name)
        return obj

    def add_helper(self, obj):
        self._helpers[obj.name] = obj

    def remove_helper(self, name):
        if name not in self._helpers:
            raise FirewallError(errors.INVALID_HELPER, name)
        del self._helpers[name]
