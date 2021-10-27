# -*- coding: utf-8 -*-
#
# Copyright (C) 2011-2016 Red Hat, Inc.
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

__all__ = [ "FirewallConfig" ]

import copy
import os
import os.path
import shutil
from firewall import config
from firewall.core.logger import log
from firewall.core.io.icmptype import IcmpType, icmptype_reader, icmptype_writer
from firewall.core.io.service import Service, service_reader, service_writer
from firewall.core.io.zone import Zone, zone_reader, zone_writer
from firewall.core.io.ipset import IPSet, ipset_reader, ipset_writer
from firewall.core.io.helper import Helper, helper_reader, helper_writer
from firewall.core.io.policy import Policy, policy_reader, policy_writer
from firewall import errors
from firewall.errors import FirewallError

class FirewallConfig(object):
    def __init__(self, fw):
        self._fw = fw
        self.__init_vars()

    def __repr__(self):
        return '%s(%r, %r, %r, %r, %r, %r, %r, %r, %r, %r, %r, %r, %r, %r, %r)' % \
            (self.__class__,
             self._ipsets, self._icmptypes, self._services, self._zones,
             self._helpers, self.policy_objects,
             self._builtin_ipsets, self._builtin_icmptypes,
             self._builtin_services, self._builtin_zones, self._builtin_helpers,
             self._builtin_policy_objects,
             self._firewalld_conf, self._policies, self._direct)

    def __init_vars(self):
        self._ipsets = { }
        self._icmptypes = { }
        self._services = { }
        self._zones = { }
        self._helpers = { }
        self._policy_objects = { }
        self._builtin_ipsets = { }
        self._builtin_icmptypes = { }
        self._builtin_services = { }
        self._builtin_zones = { }
        self._builtin_helpers = { }
        self._builtin_policy_objects = { }
        self._firewalld_conf = None
        self._policies = None
        self._direct = None

    def cleanup(self):
        for x in list(self._builtin_ipsets.keys()):
            self._builtin_ipsets[x].cleanup()
            del self._builtin_ipsets[x]
        for x in list(self._ipsets.keys()):
            self._ipsets[x].cleanup()
            del self._ipsets[x]

        for x in list(self._builtin_icmptypes.keys()):
            self._builtin_icmptypes[x].cleanup()
            del self._builtin_icmptypes[x]
        for x in list(self._icmptypes.keys()):
            self._icmptypes[x].cleanup()
            del self._icmptypes[x]

        for x in list(self._builtin_services.keys()):
            self._builtin_services[x].cleanup()
            del self._builtin_services[x]
        for x in list(self._services.keys()):
            self._services[x].cleanup()
            del self._services[x]

        for x in list(self._builtin_zones.keys()):
            self._builtin_zones[x].cleanup()
            del self._builtin_zones[x]
        for x in list(self._zones.keys()):
            self._zones[x].cleanup()
            del self._zones[x]

        for x in list(self._builtin_helpers.keys()):
            self._builtin_helpers[x].cleanup()
            del self._builtin_helpers[x]
        for x in list(self._helpers.keys()):
            self._helpers[x].cleanup()
            del self._helpers[x]

        if self._firewalld_conf:
            self._firewalld_conf.cleanup()
            del self._firewalld_conf
            self._firewalld_conf = None

        if self._policies:
            self._policies.cleanup()
            del self._policies
            self._policies = None

        if self._direct:
            self._direct.cleanup()
            del self._direct
            self._direct = None

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

    def update_firewalld_conf(self):
        if not os.path.exists(config.FIREWALLD_CONF):
            self._firewalld_conf.clear()
        else:
            self._firewalld_conf.read()

    # policies

    def set_policies(self, policies):
        self._policies = policies

    def get_policies(self):
        return self._policies

    def update_lockdown_whitelist(self):
        if not os.path.exists(config.LOCKDOWN_WHITELIST):
            self._policies.lockdown_whitelist.cleanup()
        else:
            self._policies.lockdown_whitelist.read()

    # direct

    def set_direct(self, direct):
        self._direct = direct

    def get_direct(self):
        return self._direct

    def update_direct(self):
        if not os.path.exists(config.FIREWALLD_DIRECT):
            self._direct.cleanup()
        else:
            self._direct.read()

    # ipset

    def get_ipsets(self):
        return sorted(set(list(self._ipsets.keys()) + \
                          list(self._builtin_ipsets.keys())))

    def add_ipset(self, obj):
        if obj.builtin:
            self._builtin_ipsets[obj.name] = obj
        else:
            self._ipsets[obj.name] = obj

    def get_ipset(self, name):
        if name in self._ipsets:
            return self._ipsets[name]
        elif name in self._builtin_ipsets:
            return self._builtin_ipsets[name]
        raise FirewallError(errors.INVALID_IPSET, name)

    def load_ipset_defaults(self, obj):
        if obj.name not in self._ipsets:
            raise FirewallError(errors.NO_DEFAULTS, obj.name)
        elif self._ipsets[obj.name] != obj:
            raise FirewallError(errors.NO_DEFAULTS,
                                "self._ipsets[%s] != obj" % obj.name)
        elif obj.name not in self._builtin_ipsets:
            raise FirewallError(errors.NO_DEFAULTS,
                            "'%s' not a built-in ipset" % obj.name)
        self._remove_ipset(obj)
        return self._builtin_ipsets[obj.name]

    def get_ipset_config(self, obj):
        return obj.export_config()

    def set_ipset_config(self, obj, conf):
        if obj.builtin:
            x = copy.copy(obj)
            x.import_config(conf)
            x.path = config.ETC_FIREWALLD_IPSETS
            x.builtin = False
            if obj.path != x.path:
                x.default = False
            self.add_ipset(x)
            ipset_writer(x)
            return x
        else:
            obj.import_config(conf)
            ipset_writer(obj)
            return obj

    def new_ipset(self, name, conf):
        if name in self._ipsets or name in self._builtin_ipsets:
            raise FirewallError(errors.NAME_CONFLICT,
                                "new_ipset(): '%s'" % name)

        x = IPSet()
        x.check_name(name)
        x.import_config(conf)
        x.name = name
        x.filename = "%s.xml" % name
        x.path = config.ETC_FIREWALLD_IPSETS
        # It is not possible to add a new one with a name of a buitin
        x.builtin = False
        x.default = True

        ipset_writer(x)
        self.add_ipset(x)
        return x

    def update_ipset_from_path(self, name):
        filename = os.path.basename(name)
        path = os.path.dirname(name)

        if not os.path.exists(name):
            # removed file

            if path == config.ETC_FIREWALLD_IPSETS:
                # removed custom ipset
                for x in self._ipsets.keys():
                    obj = self._ipsets[x]
                    if obj.filename == filename:
                        del self._ipsets[x]
                        if obj.name in self._builtin_ipsets:
                            return ("update", self._builtin_ipsets[obj.name])
                        return ("remove", obj)
            else:
                # removed builtin ipset
                for x in self._builtin_ipsets.keys():
                    obj = self._builtin_ipsets[x]
                    if obj.filename == filename:
                        del self._builtin_ipsets[x]
                        if obj.name not in self._ipsets:
                            # update dbus ipset
                            return ("remove", obj)
                        else:
                            # builtin hidden, no update needed
                            return (None, None)

            # ipset not known to firewalld, yet (timeout, ..)
            return (None, None)

        # new or updated file

        log.debug1("Loading ipset file '%s'", name)
        try:
            obj = ipset_reader(filename, path)
        except Exception as msg:
            log.error("Failed to load ipset file '%s': %s", filename, msg)
            return (None, None)

        # new ipset
        if obj.name not in self._builtin_ipsets and obj.name not in self._ipsets:
            self.add_ipset(obj)
            return ("new", obj)

        # updated ipset
        if path == config.ETC_FIREWALLD_IPSETS:
            # custom ipset update
            if obj.name in self._ipsets:
                obj.default = self._ipsets[obj.name].default
                self._ipsets[obj.name] = obj
            return ("update", obj)
        else:
            if obj.name in self._builtin_ipsets:
                # builtin ipset update
                del self._builtin_ipsets[obj.name]
                self._builtin_ipsets[obj.name] = obj

                if obj.name not in self._ipsets:
                    # update dbus ipset
                    return ("update", obj)
                else:
                    # builtin hidden, no update needed
                    return (None, None)

        # ipset not known to firewalld, yet (timeout, ..)
        return (None, None)

    def _remove_ipset(self, obj):
        if obj.name not in self._ipsets:
            raise FirewallError(errors.INVALID_IPSET, obj.name)
        if obj.path != config.ETC_FIREWALLD_IPSETS:
            raise FirewallError(errors.INVALID_DIRECTORY,
                                "'%s' != '%s'" % (obj.path,
                                                  config.ETC_FIREWALLD_IPSETS))

        name = "%s/%s.xml" % (obj.path, obj.name)
        try:
            shutil.move(name, "%s.old" % name)
        except Exception as msg:
            log.error("Backup of file '%s' failed: %s", name, msg)
            os.remove(name)

        del self._ipsets[obj.name]

    def check_builtin_ipset(self, obj):
        if obj.builtin or not obj.default:
            raise FirewallError(errors.BUILTIN_IPSET,
                                "'%s' is built-in ipset" % obj.name)

    def remove_ipset(self, obj):
        self.check_builtin_ipset(obj)
        self._remove_ipset(obj)

    def rename_ipset(self, obj, name):
        self.check_builtin_ipset(obj)
        new_ipset = self._copy_ipset(obj, name)
        self._remove_ipset(obj)
        return new_ipset

    def _copy_ipset(self, obj, name):
        return self.new_ipset(name, obj.export_config())

    # icmptypes

    def get_icmptypes(self):
        return sorted(set(list(self._icmptypes.keys()) + \
                          list(self._builtin_icmptypes.keys())))

    def add_icmptype(self, obj):
        if obj.builtin:
            self._builtin_icmptypes[obj.name] = obj
        else:
            self._icmptypes[obj.name] = obj

    def get_icmptype(self, name):
        if name in self._icmptypes:
            return self._icmptypes[name]
        elif name in self._builtin_icmptypes:
            return self._builtin_icmptypes[name]
        raise FirewallError(errors.INVALID_ICMPTYPE, name)

    def load_icmptype_defaults(self, obj):
        if obj.name not in self._icmptypes:
            raise FirewallError(errors.NO_DEFAULTS, obj.name)
        elif self._icmptypes[obj.name] != obj:
            raise FirewallError(errors.NO_DEFAULTS,
                                "self._icmptypes[%s] != obj" % obj.name)
        elif obj.name not in self._builtin_icmptypes:
            raise FirewallError(errors.NO_DEFAULTS,
                                "'%s' not a built-in icmptype" % obj.name)
        self._remove_icmptype(obj)
        return self._builtin_icmptypes[obj.name]

    def get_icmptype_config(self, obj):
        return obj.export_config()

    def set_icmptype_config(self, obj, conf):
        if obj.builtin:
            x = copy.copy(obj)
            x.import_config(conf)
            x.path = config.ETC_FIREWALLD_ICMPTYPES
            x.builtin = False
            if obj.path != x.path:
                x.default = False
            self.add_icmptype(x)
            icmptype_writer(x)
            return x
        else:
            obj.import_config(conf)
            icmptype_writer(obj)
            return obj

    def new_icmptype(self, name, conf):
        if name in self._icmptypes or name in self._builtin_icmptypes:
            raise FirewallError(errors.NAME_CONFLICT,
                                "new_icmptype(): '%s'" % name)

        x = IcmpType()
        x.check_name(name)
        x.import_config(conf)
        x.name = name
        x.filename = "%s.xml" % name
        x.path = config.ETC_FIREWALLD_ICMPTYPES
        # It is not possible to add a new one with a name of a buitin
        x.builtin = False
        x.default = True

        icmptype_writer(x)
        self.add_icmptype(x)
        return x

    def update_icmptype_from_path(self, name):
        filename = os.path.basename(name)
        path = os.path.dirname(name)

        if not os.path.exists(name):
            # removed file

            if path == config.ETC_FIREWALLD_ICMPTYPES:
                # removed custom icmptype
                for x in self._icmptypes.keys():
                    obj = self._icmptypes[x]
                    if obj.filename == filename:
                        del self._icmptypes[x]
                        if obj.name in self._builtin_icmptypes:
                            return ("update", self._builtin_icmptypes[obj.name])
                        return ("remove", obj)
            else:
                # removed builtin icmptype
                for x in self._builtin_icmptypes.keys():
                    obj = self._builtin_icmptypes[x]
                    if obj.filename == filename:
                        del self._builtin_icmptypes[x]
                        if obj.name not in self._icmptypes:
                            # update dbus icmptype
                            return ("remove", obj)
                        else:
                            # builtin hidden, no update needed
                            return (None, None)

            # icmptype not known to firewalld, yet (timeout, ..)
            return (None, None)

        # new or updated file

        log.debug1("Loading icmptype file '%s'", name)
        try:
            obj = icmptype_reader(filename, path)
        except Exception as msg:
            log.error("Failed to load icmptype file '%s': %s", filename, msg)
            return (None, None)

        # new icmptype
        if obj.name not in self._builtin_icmptypes and obj.name not in self._icmptypes:
            self.add_icmptype(obj)
            return ("new", obj)

        # updated icmptype
        if path == config.ETC_FIREWALLD_ICMPTYPES:
            # custom icmptype update
            if obj.name in self._icmptypes:
                obj.default = self._icmptypes[obj.name].default
                self._icmptypes[obj.name] = obj
            return ("update", obj)
        else:
            if obj.name in self._builtin_icmptypes:
                # builtin icmptype update
                del self._builtin_icmptypes[obj.name]
                self._builtin_icmptypes[obj.name] = obj

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
            raise FirewallError(errors.INVALID_ICMPTYPE, obj.name)
        if obj.path != config.ETC_FIREWALLD_ICMPTYPES:
            raise FirewallError(errors.INVALID_DIRECTORY,
                                "'%s' != '%s'" % \
                                (obj.path, config.ETC_FIREWALLD_ICMPTYPES))

        name = "%s/%s.xml" % (obj.path, obj.name)
        try:
            shutil.move(name, "%s.old" % name)
        except Exception as msg:
            log.error("Backup of file '%s' failed: %s", name, msg)
            os.remove(name)

        del self._icmptypes[obj.name]

    def check_builtin_icmptype(self, obj):
        if obj.builtin or not obj.default:
            raise FirewallError(errors.BUILTIN_ICMPTYPE,
                                "'%s' is built-in icmp type" % obj.name)

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
        return sorted(set(list(self._services.keys()) + \
                          list(self._builtin_services.keys())))

    def add_service(self, obj):
        if obj.builtin:
            self._builtin_services[obj.name] = obj
        else:
            self._services[obj.name] = obj

    def get_service(self, name):
        if name in self._services:
            return self._services[name]
        elif name in self._builtin_services:
            return self._builtin_services[name]
        raise FirewallError(errors.INVALID_SERVICE, "get_service(): '%s'" % name)

    def load_service_defaults(self, obj):
        if obj.name not in self._services:
            raise FirewallError(errors.NO_DEFAULTS, obj.name)
        elif self._services[obj.name] != obj:
            raise FirewallError(errors.NO_DEFAULTS,
                                "self._services[%s] != obj" % obj.name)
        elif obj.name not in self._builtin_services:
            raise FirewallError(errors.NO_DEFAULTS,
                                "'%s' not a built-in service" % obj.name)
        self._remove_service(obj)
        return self._builtin_services[obj.name]

    def get_service_config(self, obj):
        conf_dict = obj.export_config_dict()
        conf_list = []
        for i in range(8): # tuple based dbus API has 8 elements
            if obj.IMPORT_EXPORT_STRUCTURE[i][0] not in conf_dict:
                # old API needs the empty elements as well. Grab it from the
                # object otherwise we don't know the type.
                conf_list.append(copy.deepcopy(getattr(obj, obj.IMPORT_EXPORT_STRUCTURE[i][0])))
            else:
                conf_list.append(conf_dict[obj.IMPORT_EXPORT_STRUCTURE[i][0]])
        return tuple(conf_list)

    def get_service_config_dict(self, obj):
        return obj.export_config_dict()

    def set_service_config(self, obj, conf):
        conf_dict = {}
        for i,value in enumerate(conf):
            conf_dict[obj.IMPORT_EXPORT_STRUCTURE[i][0]] = value

        if obj.builtin:
            x = copy.copy(obj)
            x.import_config_dict(conf_dict)
            x.path = config.ETC_FIREWALLD_SERVICES
            x.builtin = False
            if obj.path != x.path:
                x.default = False
            self.add_service(x)
            service_writer(x)
            return x
        else:
            obj.import_config_dict(conf_dict)
            service_writer(obj)
            return obj

    def set_service_config_dict(self, obj, conf):
        if obj.builtin:
            x = copy.copy(obj)
            x.import_config_dict(conf)
            x.path = config.ETC_FIREWALLD_SERVICES
            x.builtin = False
            if obj.path != x.path:
                x.default = False
            self.add_service(x)
            service_writer(x)
            return x
        else:
            obj.import_config_dict(conf)
            service_writer(obj)
            return obj

    def new_service(self, name, conf):
        if name in self._services or name in self._builtin_services:
            raise FirewallError(errors.NAME_CONFLICT,
                                "new_service(): '%s'" % name)

        conf_dict = {}
        for i,value in enumerate(conf):
            conf_dict[Service.IMPORT_EXPORT_STRUCTURE[i][0]] = value

        x = Service()
        x.check_name(name)
        x.import_config_dict(conf_dict)
        x.name = name
        x.filename = "%s.xml" % name
        x.path = config.ETC_FIREWALLD_SERVICES
        # It is not possible to add a new one with a name of a buitin
        x.builtin = False
        x.default = True

        service_writer(x)
        self.add_service(x)
        return x

    def new_service_dict(self, name, conf):
        if name in self._services or name in self._builtin_services:
            raise FirewallError(errors.NAME_CONFLICT,
                                "new_service(): '%s'" % name)

        x = Service()
        x.check_name(name)
        x.import_config_dict(conf)
        x.name = name
        x.filename = "%s.xml" % name
        x.path = config.ETC_FIREWALLD_SERVICES
        # It is not possible to add a new one with a name of a buitin
        x.builtin = False
        x.default = True

        service_writer(x)
        self.add_service(x)
        return x

    def update_service_from_path(self, name):
        filename = os.path.basename(name)
        path = os.path.dirname(name)

        if not os.path.exists(name):
            # removed file

            if path == config.ETC_FIREWALLD_SERVICES:
                # removed custom service
                for x in self._services.keys():
                    obj = self._services[x]
                    if obj.filename == filename:
                        del self._services[x]
                        if obj.name in self._builtin_services:
                            return ("update", self._builtin_services[obj.name])
                        return ("remove", obj)
            else:
                # removed builtin service
                for x in self._builtin_services.keys():
                    obj = self._builtin_services[x]
                    if obj.filename == filename:
                        del self._builtin_services[x]
                        if obj.name not in self._services:
                            # update dbus service
                            return ("remove", obj)
                        else:
                            # builtin hidden, no update needed
                            return (None, None)

            # service not known to firewalld, yet (timeout, ..)
            return (None, None)

        # new or updated file

        log.debug1("Loading service file '%s'", name)
        try:
            obj = service_reader(filename, path)
        except Exception as msg:
            log.error("Failed to load service file '%s': %s", filename, msg)
            return (None, None)

        # new service
        if obj.name not in self._builtin_services and obj.name not in self._services:
            self.add_service(obj)
            return ("new", obj)

        # updated service
        if path == config.ETC_FIREWALLD_SERVICES:
            # custom service update
            if obj.name in self._services:
                obj.default = self._services[obj.name].default
                self._services[obj.name] = obj
            return ("update", obj)
        else:
            if obj.name in self._builtin_services:
                # builtin service update
                del self._builtin_services[obj.name]
                self._builtin_services[obj.name] = obj

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
            raise FirewallError(errors.INVALID_SERVICE, obj.name)
        if obj.path != config.ETC_FIREWALLD_SERVICES:
            raise FirewallError(errors.INVALID_DIRECTORY,
                                "'%s' != '%s'" % \
                                (obj.path, config.ETC_FIREWALLD_SERVICES))

        name = "%s/%s.xml" % (obj.path, obj.name)
        try:
            shutil.move(name, "%s.old" % name)
        except Exception as msg:
            log.error("Backup of file '%s' failed: %s", name, msg)
            os.remove(name)

        del self._services[obj.name]

    def check_builtin_service(self, obj):
        if obj.builtin or not obj.default:
            raise FirewallError(errors.BUILTIN_SERVICE,
                                "'%s' is built-in service" % obj.name)

    def remove_service(self, obj):
        self.check_builtin_service(obj)
        self._remove_service(obj)

    def rename_service(self, obj, name):
        self.check_builtin_service(obj)
        new_service = self._copy_service(obj, name)
        self._remove_service(obj)
        return new_service

    def _copy_service(self, obj, name):
        return self.new_service_dict(name, obj.export_config_dict())

    # zones

    def get_zones(self):
        return sorted(set(list(self._zones.keys()) + \
                          list(self._builtin_zones.keys())))

    def add_zone(self, obj):
        if obj.builtin:
            self._builtin_zones[obj.name] = obj
        else:
            self._zones[obj.name] = obj

    def forget_zone(self, name):
        if name in self._builtin_zones:
            del self._builtin_zones[name]
        if name in self._zones:
            del self._zones[name]

    def get_zone(self, name):
        if name in self._zones:
            return self._zones[name]
        elif name in self._builtin_zones:
            return self._builtin_zones[name]
        raise FirewallError(errors.INVALID_ZONE, "get_zone(): %s" % name)

    def load_zone_defaults(self, obj):
        if obj.name not in self._zones:
            raise FirewallError(errors.NO_DEFAULTS, obj.name)
        elif self._zones[obj.name] != obj:
            raise FirewallError(errors.NO_DEFAULTS,
                                "self._zones[%s] != obj" % obj.name)
        elif obj.name not in self._builtin_zones:
            raise FirewallError(errors.NO_DEFAULTS,
                                "'%s' not a built-in zone" % obj.name)
        self._remove_zone(obj)
        return self._builtin_zones[obj.name]

    def get_zone_config(self, obj):
        conf_dict = obj.export_config_dict()
        conf_list = []
        for i in range(16): # tuple based dbus API has 16 elements
            if obj.IMPORT_EXPORT_STRUCTURE[i][0] not in conf_dict:
                # old API needs the empty elements as well. Grab it from the
                # object otherwise we don't know the type.
                conf_list.append(copy.deepcopy(getattr(obj, obj.IMPORT_EXPORT_STRUCTURE[i][0])))
            else:
                conf_list.append(conf_dict[obj.IMPORT_EXPORT_STRUCTURE[i][0]])
        return tuple(conf_list)

    def get_zone_config_dict(self, obj):
        return obj.export_config_dict()

    def set_zone_config(self, obj, conf):
        conf_dict = {}
        for i,value in enumerate(conf):
            conf_dict[obj.IMPORT_EXPORT_STRUCTURE[i][0]] = value

        if obj.builtin:
            x = copy.copy(obj)
            x.fw_config = self
            x.import_config_dict(conf_dict)
            x.path = config.ETC_FIREWALLD_ZONES
            x.builtin = False
            if obj.path != x.path:
                x.default = False
            self.add_zone(x)
            zone_writer(x)
            return x
        else:
            obj.fw_config = self
            obj.import_config_dict(conf_dict)
            zone_writer(obj)
            return obj

    def set_zone_config_dict(self, obj, conf):
        if obj.builtin:
            x = copy.copy(obj)
            x.fw_config = self
            x.import_config_dict(conf)
            x.path = config.ETC_FIREWALLD_ZONES
            x.builtin = False
            if obj.path != x.path:
                x.default = False
            self.add_zone(x)
            zone_writer(x)
            return x
        else:
            obj.fw_config = self
            obj.import_config_dict(conf)
            zone_writer(obj)
            return obj

    def new_zone(self, name, conf):
        if name in self._zones or name in self._builtin_zones:
            raise FirewallError(errors.NAME_CONFLICT, "new_zone(): '%s'" % name)

        conf_dict = {}
        for i,value in enumerate(conf):
            conf_dict[Zone.IMPORT_EXPORT_STRUCTURE[i][0]] = value

        x = Zone()
        x.fw_config = self
        x.check_name(name)
        x.import_config_dict(conf_dict)
        x.name = name
        x.filename = "%s.xml" % name
        x.path = config.ETC_FIREWALLD_ZONES
        # It is not possible to add a new one with a name of a buitin
        x.builtin = False
        x.default = True

        zone_writer(x)
        self.add_zone(x)
        return x

    def new_zone_dict(self, name, conf):
        if name in self._zones or name in self._builtin_zones:
            raise FirewallError(errors.NAME_CONFLICT, "new_zone(): '%s'" % name)

        x = Zone()
        x.fw_config = self
        x.check_name(name)
        x.import_config_dict(conf)
        x.name = name
        x.filename = "%s.xml" % name
        x.path = config.ETC_FIREWALLD_ZONES
        # It is not possible to add a new one with a name of a buitin
        x.builtin = False
        x.default = True

        zone_writer(x)
        self.add_zone(x)
        return x

    def update_zone_from_path(self, name):
        filename = os.path.basename(name)
        path = os.path.dirname(name)

        if not os.path.exists(name):
            # removed file

            if path.startswith(config.ETC_FIREWALLD_ZONES):
                # removed custom zone
                for x in self._zones.keys():
                    obj = self._zones[x]
                    if obj.filename == filename:
                        del self._zones[x]
                        if obj.name in self._builtin_zones:
                            return ("update", self._builtin_zones[obj.name])
                        return ("remove", obj)
            else:
                # removed builtin zone
                for x in self._builtin_zones.keys():
                    obj = self._builtin_zones[x]
                    if obj.filename == filename:
                        del self._builtin_zones[x]
                        if obj.name not in self._zones:
                            # update dbus zone
                            return ("remove", obj)
                        else:
                            # builtin hidden, no update needed
                            return (None, None)

            # zone not known to firewalld, yet (timeout, ..)
            return (None, None)

        # new or updated file

        log.debug1("Loading zone file '%s'", name)
        try:
            obj = zone_reader(filename, path)
        except Exception as msg:
            log.error("Failed to load zone file '%s': %s", filename, msg)
            return (None, None)

        obj.fw_config = self

        if path.startswith(config.ETC_FIREWALLD_ZONES) and \
           len(path) > len(config.ETC_FIREWALLD_ZONES):
            # custom combined zone part
            obj.name = "%s/%s" % (os.path.basename(path),
                                  os.path.basename(filename)[0:-4])

        # new zone
        if obj.name not in self._builtin_zones and obj.name not in self._zones:
            self.add_zone(obj)
            return ("new", obj)

        # updated zone
        if path.startswith(config.ETC_FIREWALLD_ZONES):
            # custom zone update
            if obj.name in self._zones:
                obj.default = self._zones[obj.name].default
                self._zones[obj.name] = obj
            return ("update", obj)
        else:
            if obj.name in self._builtin_zones:
                # builtin zone update
                del self._builtin_zones[obj.name]
                self._builtin_zones[obj.name] = obj

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
            raise FirewallError(errors.INVALID_ZONE, obj.name)
        if not obj.path.startswith(config.ETC_FIREWALLD_ZONES):
            raise FirewallError(errors.INVALID_DIRECTORY,
                                "'%s' doesn't start with '%s'" % \
                                (obj.path, config.ETC_FIREWALLD_ZONES))

        name = "%s/%s.xml" % (obj.path, obj.name)
        try:
            shutil.move(name, "%s.old" % name)
        except Exception as msg:
            log.error("Backup of file '%s' failed: %s", name, msg)
            os.remove(name)

        del self._zones[obj.name]

    def check_builtin_zone(self, obj):
        if obj.builtin or not obj.default:
            raise FirewallError(errors.BUILTIN_ZONE,
                                "'%s' is built-in zone" % obj.name)

    def remove_zone(self, obj):
        self.check_builtin_zone(obj)
        self._remove_zone(obj)

    def rename_zone(self, obj, name):
        self.check_builtin_zone(obj)
        obj_conf = obj.export_config_dict()
        self._remove_zone(obj)
        try:
            new_zone = self.new_zone_dict(name, obj_conf)
        except:
            # re-add original if rename failed
            self.new_zone_dict(obj.name, obj_conf)
            raise
        return new_zone

    # policy objects

    def get_policy_objects(self):
        return sorted(set(list(self._policy_objects.keys()) + \
                          list(self._builtin_policy_objects.keys())))

    def add_policy_object(self, obj):
        if obj.builtin:
            self._builtin_policy_objects[obj.name] = obj
        else:
            self._policy_objects[obj.name] = obj

    def get_policy_object(self, name):
        if name in self._policy_objects:
            return self._policy_objects[name]
        elif name in self._builtin_policy_objects:
            return self._builtin_policy_objects[name]
        raise FirewallError(errors.INVALID_POLICY, "get_policy_object(): %s" % name)

    def load_policy_object_defaults(self, obj):
        if obj.name not in self._policy_objects:
            raise FirewallError(errors.NO_DEFAULTS, obj.name)
        elif self._policy_objects[obj.name] != obj:
            raise FirewallError(errors.NO_DEFAULTS,
                                "self._policy_objects[%s] != obj" % obj.name)
        elif obj.name not in self._builtin_policy_objects:
            raise FirewallError(errors.NO_DEFAULTS,
                                "'%s' not a built-in policy" % obj.name)
        self._remove_policy_object(obj)
        return self._builtin_policy_objects[obj.name]

    def get_policy_object_config_dict(self, obj):
        return obj.export_config_dict()

    def set_policy_object_config_dict(self, obj, conf):
        if obj.builtin:
            x = copy.copy(obj)
            x.fw_config = self
            x.import_config_dict(conf)
            x.path = config.ETC_FIREWALLD_POLICIES
            x.builtin = False
            if obj.path != x.path:
                x.default = False
            self.add_policy_object(x)
            policy_writer(x)
            return x
        else:
            obj.fw_config = self
            obj.import_config_dict(conf)
            policy_writer(obj)
            return obj

    def new_policy_object_dict(self, name, conf):
        if name in self._policy_objects or name in self._builtin_policy_objects:
            raise FirewallError(errors.NAME_CONFLICT, "new_policy_object(): '%s'" % name)

        x = Policy()
        x.fw_config = self
        x.check_name(name)
        x.import_config_dict(conf)
        x.name = name
        x.filename = "%s.xml" % name
        x.path = config.ETC_FIREWALLD_POLICIES
        # It is not possible to add a new one with a name of a buitin
        x.builtin = False
        x.default = True

        policy_writer(x)
        self.add_policy_object(x)
        return x

    def update_policy_object_from_path(self, name):
        filename = os.path.basename(name)
        path = os.path.dirname(name)

        if not os.path.exists(name):
            # removed file

            if path.startswith(config.ETC_FIREWALLD_POLICIES):
                # removed custom policy_object
                for x in self._policy_objects.keys():
                    obj = self._policy_objects[x]
                    if obj.filename == filename:
                        del self._policy_objects[x]
                        if obj.name in self._builtin_policy_objects:
                            return ("update", self._builtin_policy_objects[obj.name])
                        return ("remove", obj)
            else:
                # removed builtin policy_object
                for x in self._builtin_policy_objects.keys():
                    obj = self._builtin_policy_objects[x]
                    if obj.filename == filename:
                        del self._builtin_policy_objects[x]
                        if obj.name not in self._policy_objects:
                            # update dbus policy_object
                            return ("remove", obj)
                        else:
                            # builtin hidden, no update needed
                            return (None, None)

            # policy_object not known to firewalld, yet (timeout, ..)
            return (None, None)

        # new or updated file

        log.debug1("Loading policy file '%s'", name)
        try:
            obj = policy_reader(filename, path)
        except Exception as msg:
            log.error("Failed to load policy file '%s': %s", filename, msg)
            return (None, None)

        obj.fw_config = self

        if path.startswith(config.ETC_FIREWALLD_POLICIES) and \
           len(path) > len(config.ETC_FIREWALLD_POLICIES):
            # custom combined policy_object part
            obj.name = "%s/%s" % (os.path.basename(path),
                                  os.path.basename(filename)[0:-4])

        # new policy_object
        if obj.name not in self._builtin_policy_objects and obj.name not in self._policy_objects:
            self.add_policy_object(obj)
            return ("new", obj)

        # updated policy_object
        if path.startswith(config.ETC_FIREWALLD_POLICIES):
            # custom policy_object update
            if obj.name in self._policy_objects:
                obj.default = self._policy_objects[obj.name].default
                self._policy_objects[obj.name] = obj
            return ("update", obj)
        else:
            if obj.name in self._builtin_policy_objects:
                # builtin policy_object update
                del self._builtin_policy_objects[obj.name]
                self._builtin_policy_objects[obj.name] = obj

                if obj.name not in self._policy_objects:
                    # update dbus policy_object
                    return ("update", obj)
                else:
                    # builtin hidden, no update needed
                    return (None, None)

        # policy_object not known to firewalld, yet (timeout, ..)
        return (None, None)

    def _remove_policy_object(self, obj):
        if obj.name not in self._policy_objects:
            raise FirewallError(errors.INVALID_POLICY, obj.name)
        if not obj.path.startswith(config.ETC_FIREWALLD_POLICIES):
            raise FirewallError(errors.INVALID_DIRECTORY,
                                "'%s' doesn't start with '%s'" % \
                                (obj.path, config.ETC_FIREWALLD_POLICIES))

        name = "%s/%s.xml" % (obj.path, obj.name)
        try:
            shutil.move(name, "%s.old" % name)
        except Exception as msg:
            log.error("Backup of file '%s' failed: %s", name, msg)
            os.remove(name)

        del self._policy_objects[obj.name]

    def check_builtin_policy_object(self, obj):
        if obj.builtin or not obj.default:
            raise FirewallError(errors.BUILTIN_POLICY,
                                "'%s' is built-in policy" % obj.name)

    def remove_policy_object(self, obj):
        self.check_builtin_policy_object(obj)
        self._remove_policy_object(obj)

    def rename_policy_object(self, obj, name):
        self.check_builtin_policy_object(obj)
        new_policy_object = self._copy_policy_object(obj, name)
        self._remove_policy_object(obj)
        return new_policy_object

    def _copy_policy_object(self, obj, name):
        return self.new_policy_object_dict(name, obj.export_config_dict())

    # helper

    def get_helpers(self):
        return sorted(set(list(self._helpers.keys()) + \
                          list(self._builtin_helpers.keys())))

    def add_helper(self, obj):
        if obj.builtin:
            self._builtin_helpers[obj.name] = obj
        else:
            self._helpers[obj.name] = obj

    def get_helper(self, name):
        if name in self._helpers:
            return self._helpers[name]
        elif name in self._builtin_helpers:
            return self._builtin_helpers[name]
        raise FirewallError(errors.INVALID_HELPER, name)

    def load_helper_defaults(self, obj):
        if obj.name not in self._helpers:
            raise FirewallError(errors.NO_DEFAULTS, obj.name)
        elif self._helpers[obj.name] != obj:
            raise FirewallError(errors.NO_DEFAULTS,
                                "self._helpers[%s] != obj" % obj.name)
        elif obj.name not in self._builtin_helpers:
            raise FirewallError(errors.NO_DEFAULTS,
                            "'%s' not a built-in helper" % obj.name)
        self._remove_helper(obj)
        return self._builtin_helpers[obj.name]

    def get_helper_config(self, obj):
        return obj.export_config()

    def set_helper_config(self, obj, conf):
        if obj.builtin:
            x = copy.copy(obj)
            x.import_config(conf)
            x.path = config.ETC_FIREWALLD_HELPERS
            x.builtin = False
            if obj.path != x.path:
                x.default = False
            self.add_helper(x)
            helper_writer(x)
            return x
        else:
            obj.import_config(conf)
            helper_writer(obj)
            return obj

    def new_helper(self, name, conf):
        if name in self._helpers or name in self._builtin_helpers:
            raise FirewallError(errors.NAME_CONFLICT,
                                "new_helper(): '%s'" % name)

        x = Helper()
        x.check_name(name)
        x.import_config(conf)
        x.name = name
        x.filename = "%s.xml" % name
        x.path = config.ETC_FIREWALLD_HELPERS
        # It is not possible to add a new one with a name of a buitin
        x.builtin = False
        x.default = True

        helper_writer(x)
        self.add_helper(x)
        return x

    def update_helper_from_path(self, name):
        filename = os.path.basename(name)
        path = os.path.dirname(name)

        if not os.path.exists(name):
            # removed file

            if path == config.ETC_FIREWALLD_HELPERS:
                # removed custom helper
                for x in self._helpers.keys():
                    obj = self._helpers[x]
                    if obj.filename == filename:
                        del self._helpers[x]
                        if obj.name in self._builtin_helpers:
                            return ("update", self._builtin_helpers[obj.name])
                        return ("remove", obj)
            else:
                # removed builtin helper
                for x in self._builtin_helpers.keys():
                    obj = self._builtin_helpers[x]
                    if obj.filename == filename:
                        del self._builtin_helpers[x]
                        if obj.name not in self._helpers:
                            # update dbus helper
                            return ("remove", obj)
                        else:
                            # builtin hidden, no update needed
                            return (None, None)

            # helper not known to firewalld, yet (timeout, ..)
            return (None, None)

        # new or updated file

        log.debug1("Loading helper file '%s'", name)
        try:
            obj = helper_reader(filename, path)
        except Exception as msg:
            log.error("Failed to load helper file '%s': %s", filename, msg)
            return (None, None)

        # new helper
        if obj.name not in self._builtin_helpers and obj.name not in self._helpers:
            self.add_helper(obj)
            return ("new", obj)

        # updated helper
        if path == config.ETC_FIREWALLD_HELPERS:
            # custom helper update
            if obj.name in self._helpers:
                obj.default = self._helpers[obj.name].default
                self._helpers[obj.name] = obj
            return ("update", obj)
        else:
            if obj.name in self._builtin_helpers:
                # builtin helper update
                del self._builtin_helpers[obj.name]
                self._builtin_helpers[obj.name] = obj

                if obj.name not in self._helpers:
                    # update dbus helper
                    return ("update", obj)
                else:
                    # builtin hidden, no update needed
                    return (None, None)

        # helper not known to firewalld, yet (timeout, ..)
        return (None, None)

    def _remove_helper(self, obj):
        if obj.name not in self._helpers:
            raise FirewallError(errors.INVALID_HELPER, obj.name)
        if obj.path != config.ETC_FIREWALLD_HELPERS:
            raise FirewallError(errors.INVALID_DIRECTORY,
                                "'%s' != '%s'" % (obj.path,
                                                  config.ETC_FIREWALLD_HELPERS))

        name = "%s/%s.xml" % (obj.path, obj.name)
        try:
            shutil.move(name, "%s.old" % name)
        except Exception as msg:
            log.error("Backup of file '%s' failed: %s", name, msg)
            os.remove(name)

        del self._helpers[obj.name]

    def check_builtin_helper(self, obj):
        if obj.builtin or not obj.default:
            raise FirewallError(errors.BUILTIN_HELPER,
                                "'%s' is built-in helper" % obj.name)

    def remove_helper(self, obj):
        self.check_builtin_helper(obj)
        self._remove_helper(obj)

    def rename_helper(self, obj, name):
        self.check_builtin_helper(obj)
        new_helper = self._copy_helper(obj, name)
        self._remove_helper(obj)
        return new_helper

    def _copy_helper(self, obj, name):
        return self.new_helper(name, obj.export_config())
