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
        return self.get_service(service).name

    def get_service(self, service, required=True):
        v = self._services.get(service)
        if v is None and required:
            raise FirewallError(errors.INVALID_SERVICE, service)
        return v

    def add_service(self, obj):
        self._services[obj.name] = obj

    def remove_service(self, service):
        self.check_service(service)
        del self._services[service]
