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
