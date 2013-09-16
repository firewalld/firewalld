# -*- coding: utf-8 -*-
#
# Copyright (C) 2011-2012 Red Hat, Inc.
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

from firewall.errors import *

class FirewallService:
    def __init__(self, fw):
        self._fw = fw
        self.__init_vars()

    def __init_vars(self):
        self._services = { }

    def cleanup(self):
        self.__init_vars()

    # zones

    def get_services(self):
        return sorted(self._services.keys())

    def check_service(self, service):
        if service not in self._services:
            raise FirewallError(INVALID_SERVICE, service)

    def get_service(self, service):
        self.check_service(service)
        return self._services[service]

    def add_service(self, obj):
        self._services[obj.name] = obj

    def remove_service(self, service):
        self.check_service(service)
        del self._services[service]
