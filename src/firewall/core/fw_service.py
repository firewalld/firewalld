# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2011-2016 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>

from firewall import errors
from firewall.errors import FirewallError


class FirewallService:
    def __init__(self, fw):
        self._fw = fw
        self._services = {}

    def __repr__(self):
        return "%s(%r)" % (self.__class__, self._services)

    def cleanup(self):
        self._services.clear()

    # zones

    def get_services(self):
        return sorted(self._services.keys())

    def check_service(self, service):
        if service not in self._services:
            raise FirewallError(errors.INVALID_SERVICE, service)

    def get_service(self, service):
        self.check_service(service)
        return self._services[service]

    def add_service(self, obj):
        self._services[obj.name] = obj

    def remove_service(self, service):
        self.check_service(service)
        del self._services[service]
