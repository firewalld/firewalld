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

import copy
import os, os.path
from firewall.config import *
from firewall.core.base import *
from firewall.core.logger import log
from firewall.core.io.icmptype import IcmpType, icmptype_reader, icmptype_writer
from firewall.core.io.service import Service, service_reader, service_writer
from firewall.core.io.zone import Zone, zone_reader, zone_writer
from firewall.functions import portStr
from firewall.errors import *

class FirewallConfig:
    def __init__(self, fw):
        self._fw = fw
        self.__init_vars()

    def __init_vars(self):
        self._icmptypes = { }
        self._services = { }
        self._zones = { }
        self._default_icmptypes = { }
        self._default_services = { }
        self._default_zones = { }
        self._firewalld_conf = None
        self._policies = None
        self._direct = None

    def cleanup(self):
        for x in self._default_icmptypes.keys():
            del self._default_icmptypes[x]
        for x in self._icmptypes.keys():
            del self._icmptypes[x]

        for x in self._default_services.keys():
            del self._default_services[x]
        for x in self._services.keys():
            del self._services[x]

        for x in self._default_zones.keys():
            del self._default_zones[x]
        for x in self._zones.keys():
            del self._zones[x]

        self.__init_vars()

    # access check

    def lockdown_enabled(self):
        return self._fw.policies.query_lockdown()

    def access_check(self, key, value):
        return self._fw.policies.access_check(key, value)

    # firewalld_conf

    def set_firewalld_conf(self, conf):
        self._firewalld_conf = conf

    def get_firewalld_conf(self):
        return self._firewalld_conf

    # policies

    def set_policies(self, policies):
        self._policies = policies

    def get_policies(self):
        return self._policies

    def update_lockdown_whitelist(self):
        if not os.path.exists(LOCKDOWN_WHITELIST):
            self._policies.lockdown_whitelist.clear()
        else:
            self._policies.lockdown_whitelist.read()

    # direct

    def set_direct(self, direct):
        self._direct = direct

    def get_direct(self):
        return self._direct

    def update_direct(self):
        if not os.path.exists(FIREWALLD_DIRECT):
            self._direct.clear()
        else:
            self._direct.read()

    # icmptypes

    def get_icmptypes(self):
        return sorted(set(self._icmptypes.keys() + \
                          self._default_icmptypes.keys()))

    def add_icmptype(self, obj):
        if obj.default:
            self._default_icmptypes[obj.name] = obj
        else:
            self._icmptypes[obj.name] = obj

    def get_icmptype(self, name):
        if name in self._icmptypes:
            return self._icmptypes[name]
        elif name in self._default_icmptypes:
            return self._default_icmptypes[name]
        raise FirewallError(INVALID_ICMPTYPE, name)

    def icmptype_has_defaults(self, name):
        return (name in self._icmptypes and name in self._default_icmptypes)

    def icmptype_is_default(self, name):
        return name in self._default_icmptypes

    def load_icmptype_defaults(self, obj):
        if obj.name not in self._icmptypes or self._icmptypes[obj.name] != obj or \
                obj.name not in self._default_icmptypes:
            raise FirewallError(NO_DEFAULTS, obj.name)
        self._remove_icmptype(obj)
        return self._default_icmptypes[obj.name]

    def get_icmptype_config(self, obj):
        return obj.export_config()

    def set_icmptype_config(self, obj, config):
        if obj.default:
            x = copy.copy(obj)
            x.import_config(config)
            x.path = ETC_FIREWALLD_ICMPTYPES
            x.default = False
            self.add_icmptype(x)
            icmptype_writer(x)
            return x
        else:
            obj.import_config(config)
            icmptype_writer(obj)
            return obj

    def new_icmptype(self, name, config):
        try:
            self.get_icmptype(name)
        except:
            pass
        else:
            raise FirewallError(NAME_CONFLICT, name)

        x = IcmpType()
        x.check_name(name)
        x.import_config(config)
        x.name = name
        x.filename = "%s.xml" % name
        x.path = ETC_FIREWALLD_ICMPTYPES
        x.default = False

        icmptype_writer(x)
        self.add_icmptype(x)
        return x

    def update_icmptype_from_path(self, name):
        filename = os.path.basename(name)
        path = os.path.dirname(name)

        if not os.path.exists(name):
            # removed file

            if path == ETC_FIREWALLD_ICMPTYPES:
                # removed custom icmptype
                for x in self._icmptypes.keys():
                    obj = self._icmptypes[x]
                    if obj.filename == filename:
                        del self._icmptypes[x]
                        if obj.name in self._default_icmptypes:
                            return ("update", self._default_icmptypes[obj.name])
                        return ("remove", obj)
            else:
                # removed builtin icmptype
                for x in self._default_icmptypes.keys():
                    obj = self._default_icmptypes[x]
                    if obj.filename == filename:
                        del self._default_icmptypes[x]
                        if obj.name not in self._icmptypes:
                            # update dbus icmptype
                            return ("remove", obj)
                        else:
                            # builtin hidden, no update needed
                            return (None, None)

            # icmptype not known to firewalld, yet (timeout, ..)
            return (None, None)

        # new or updated file

        obj = icmptype_reader(filename, path)

        # new icmptype
        if obj.name not in self._default_icmptypes and obj.name not in self._icmptypes:
            self.add_icmptype(obj)
            return ("new", obj)

        # updated icmptype
        if path == ETC_FIREWALLD_ICMPTYPES:
            # custom icmptype update
            if obj.name in self._icmptypes:
                self._icmptypes[obj.name] = obj
            return ("update", obj)
        else:
            if obj.name in self._default_icmptypes:
                # builtin icmptype update
                del self._default_icmptypes[obj.name]
                self._default_icmptypes[obj.name] = obj

                if obj.name not in self._icmptypes:
                    # update dbus icmptype
                    return ("update", obj)
                else:
                    # builtin hidden, no update needed
                    return (None, None)
            
        # icmptype not known to firewalld, yet (timeout, ..)
        return (None, None)

    def _remove_icmptype(self, obj):
        if obj.name not in self._icmptypes:
            raise FirewallError(INVALID_ICMPTYPE, obj.name)
        if obj.path != ETC_FIREWALLD_ICMPTYPES:
            raise FirewallError(INVALID_DIRECTORY, obj.path)
        os.remove("%s/%s.xml" % (obj.path, obj.name))
        del self._icmptypes[obj.name]

    def is_builtin_icmptype(self, obj):
        if obj.default or obj.name in self._default_icmptypes:
            return True
        return False

    def check_builtin_icmptype(self, obj):
        if self.is_builtin_icmptype(obj):
            raise FirewallError(BUILTIN_ICMPTYPE, obj.name)

    def remove_icmptype(self, obj):
        self.check_builtin_icmptype(obj)
        self._remove_icmptype(obj)

    def rename_icmptype(self, obj, name):
        self.check_builtin_icmptype(obj)
        new_icmptype = self._copy_icmptype(obj, name)
        self._remove_icmptype(obj)
        return new_icmptype

    def _copy_icmptype(self, obj, name):
        return self.new_icmptype(name, obj.export_config())

    # services

    def get_services(self):
        return sorted(set(self._services.keys() + \
                          self._default_services.keys()))

    def add_service(self, obj):
        if obj.default:
            self._default_services[obj.name] = obj
        else:
            self._services[obj.name] = obj

    def get_service(self, name):
        if name in self._services:
            return self._services[name]
        elif name in self._default_services:
            return self._default_services[name]
        raise FirewallError(INVALID_SERVICE, name)

    def service_has_defaults(self, name):
        return (name in self._services and name in self._default_services)

    def service_is_default(self, name):
        return name in self._default_services

    def load_service_defaults(self, obj):
        if obj.name not in self._services or self._services[obj.name] != obj or \
                obj.name not in self._default_services:
            raise FirewallError(NO_DEFAULTS, obj.name)
        self._remove_service(obj)
        return self._default_services[obj.name]

    def get_service_config(self, obj):
        return obj.export_config()

    def set_service_config(self, obj, config):
        if obj.default:
            x = copy.copy(obj)
            x.import_config(config)
            x.path = ETC_FIREWALLD_SERVICES
            x.default = False
            self.add_service(x)
            service_writer(x)
            return x
        else:
            obj.import_config(config)
            service_writer(obj)
            return obj

    def new_service(self, name, config):
        try:
            self.get_service(name)
        except:
            pass
        else:
            raise FirewallError(NAME_CONFLICT, name)

        x = Service()
        x.check_name(name)
        x.import_config(config)
        x.name = name
        x.filename = "%s.xml" % name
        x.path = ETC_FIREWALLD_SERVICES
        x.default = False

        service_writer(x)
        self.add_service(x)
        return x

    def update_service_from_path(self, name):
        filename = os.path.basename(name)
        path = os.path.dirname(name)

        if not os.path.exists(name):
            # removed file

            if path == ETC_FIREWALLD_SERVICES:
                # removed custom service
                for x in self._services.keys():
                    obj = self._services[x]
                    if obj.filename == filename:
                        del self._services[x]
                        if obj.name in self._default_services:
                            return ("update", self._default_services[obj.name])
                        return ("remove", obj)
            else:
                # removed builtin service
                for x in self._default_services.keys():
                    obj = self._default_services[x]
                    if obj.filename == filename:
                        del self._default_services[x]
                        if obj.name not in self._services:
                            # update dbus service
                            return ("remove", obj)
                        else:
                            # builtin hidden, no update needed
                            return (None, None)

            # service not known to firewalld, yet (timeout, ..)
            return (None, None)

        # new or updated file

        obj = service_reader(filename, path)

        # new service
        if obj.name not in self._default_services and obj.name not in self._services:
            self.add_service(obj)
            return ("new", obj)

        # updated service
        if path == ETC_FIREWALLD_SERVICES:
            # custom service update
            if obj.name in self._services:
                self._services[obj.name] = obj
            return ("update", obj)
        else:
            if obj.name in self._default_services:
                # builtin service update
                del self._default_services[obj.name]
                self._default_services[obj.name] = obj

                if obj.name not in self._services:
                    # update dbus service
                    return ("update", obj)
                else:
                    # builtin hidden, no update needed
                    return (None, None)
            
        # service not known to firewalld, yet (timeout, ..)
        return (None, None)

    def _remove_service(self, obj):
        if obj.name not in self._services:
            raise FirewallError(INVALID_SERVICE, obj.name)
        if obj.path != ETC_FIREWALLD_SERVICES:
            raise FirewallError(INVALID_DIRECTORY, obj.path)
        os.remove("%s/%s.xml" % (obj.path, obj.name))
        del self._services[obj.name]

    def is_builtin_service(self, obj):
        if obj.default or obj.name in self._default_services:
            return True
        return False

    def check_builtin_service(self, obj):
        if self.is_builtin_service(obj):
            raise FirewallError(BUILTIN_SERVICE, obj.name)

    def remove_service(self, obj):
        self.check_builtin_service(obj)
        self._remove_service(obj)

    def rename_service(self, obj, name):
        self.check_builtin_service(obj)
        new_service = self._copy_service(obj, name)
        self._remove_service(obj)
        return new_service

    def _copy_service(self, obj, name):
        return self.new_service(name, obj.export_config())

    # zones

    def get_zones(self):
        return sorted(set(self._zones.keys() + \
                          self._default_zones.keys()))

    def add_zone(self, obj):
        if obj.default:
            self._default_zones[obj.name] = obj
        else:
            self._zones[obj.name] = obj

    def forget_zone(self, name):
        if name in self._default_zones:
            del self._default_zones[name]
        if name in self._zones:
            del self._zones[name]

    def get_zone(self, name):
        if name in self._zones:
            return self._zones[name]
        elif name in self._default_zones:
            return self._default_zones[name]
        raise FirewallError(INVALID_ZONE, name)

    def zone_has_defaults(self, name):
        return (name in self._zones and name in self._default_zones)

    def zone_is_default(self, name):
        return name in self._default_zones

    def load_zone_defaults(self, obj):
        if obj.name not in self._zones or self._zones[obj.name] != obj or \
                obj.name not in self._default_zones:
            raise FirewallError(NO_DEFAULTS, obj.name)
        self._remove_zone(obj)
        return self._default_zones[obj.name]

    def get_zone_config(self, obj):
        return obj.export_config()

    def set_zone_config(self, obj, config):
        if obj.default:
            x = copy.copy(obj)
            x.fw_config = self
            x.import_config(config)
            x.path = ETC_FIREWALLD_ZONES
            x.default = False
            self.add_zone(x)
            zone_writer(x)
            return x
        else:
            obj.fw_config = self
            obj.import_config(config)
            zone_writer(obj)
            return obj

    def new_zone(self, name, config):
        try:
            self.get_zone(name)
        except:
            pass
        else:
            raise FirewallError(NAME_CONFLICT, name)

        x = Zone()
        x.check_name(name)
        x.fw_config = self
        x.import_config(config)
        x.name = name
        x.filename = "%s.xml" % name
        x.path = ETC_FIREWALLD_ZONES
        x.default = False

        zone_writer(x)
        self.add_zone(x)
        return x

    def update_zone_from_path(self, name):
        filename = os.path.basename(name)
        path = os.path.dirname(name)

        if not os.path.exists(name):
            # removed file

            if path == ETC_FIREWALLD_ZONES:
                # removed custom zone
                for x in self._zones.keys():
                    obj = self._zones[x]
                    if obj.filename == filename:
                        del self._zones[x]
                        if obj.name in self._default_zones:
                            return ("update", self._default_zones[obj.name])
                        return ("remove", obj)
            else:
                # removed builtin zone
                for x in self._default_zones.keys():
                    obj = self._default_zones[x]
                    if obj.filename == filename:
                        del self._default_zones[x]
                        if obj.name not in self._zones:
                            # update dbus zone
                            return ("remove", obj)
                        else:
                            # builtin hidden, no update needed
                            return (None, None)

            # zone not known to firewalld, yet (timeout, ..)
            return (None, None)

        # new or updated file

        obj = zone_reader(filename, path)
        obj.fw_config = self

        # new zone
        if obj.name not in self._default_zones and obj.name not in self._zones:
            self.add_zone(obj)
            return ("new", obj)

        # updated zone
        if path == ETC_FIREWALLD_ZONES:
            # custom zone update
            if obj.name in self._zones:
                self._zones[obj.name] = obj
            return ("update", obj)
        else:
            if obj.name in self._default_zones:
                # builtin zone update
                del self._default_zones[obj.name]
                self._default_zones[obj.name] = obj

                if obj.name not in self._zones:
                    # update dbus zone
                    return ("update", obj)
                else:
                    # builtin hidden, no update needed
                    return (None, None)
            
        # zone not known to firewalld, yet (timeout, ..)
        return (None, None)

    def _remove_zone(self, obj):
        if obj.name not in self._zones:
            raise FirewallError(INVALID_ZONE, obj.name)
        if obj.path != ETC_FIREWALLD_ZONES:
            raise FirewallError(INVALID_DIRECTORY, obj.path)
        os.remove("%s/%s.xml" % (obj.path, obj.name))
        del self._zones[obj.name]

    def is_builtin_zone(self, obj):
        if obj.default or obj.name in self._default_zones:
            return True
        return False

    def check_builtin_zone(self, obj):
        if self.is_builtin_zone(obj):
            raise FirewallError(BUILTIN_ZONE, obj.name)

    def remove_zone(self, obj):
        self.check_builtin_zone(obj)
        self._remove_zone(obj)

    def rename_zone(self, obj, name):
        self.check_builtin_zone(obj)
        new_zone = self._copy_zone(obj, name)
        self._remove_zone(obj)
        return new_zone

    def _copy_zone(self, obj, name):
        return self.new_zone(name, obj.export_config())
