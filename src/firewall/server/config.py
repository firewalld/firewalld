# -*- coding: utf-8 -*-
#
# Copyright (C) 2010-2016 Red Hat, Inc.
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

import os

import dbus
import dbus.service

from firewall import config
from firewall.core.base import DEFAULT_ZONE_TARGET
from firewall.core.watcher import Watcher
from firewall.core.logger import log
from firewall.server.dbus import DbusServiceObject
from firewall.server.decorators import handle_exceptions, \
    dbus_handle_exceptions, dbus_service_method, \
    dbus_service_method_deprecated, dbus_service_signal_deprecated, \
    dbus_polkit_require_auth
from firewall.server.config_icmptype import FirewallDConfigIcmpType
from firewall.server.config_service import FirewallDConfigService
from firewall.server.config_zone import FirewallDConfigZone
from firewall.server.config_policy import FirewallDConfigPolicy
from firewall.server.config_ipset import FirewallDConfigIPSet
from firewall.server.config_helper import FirewallDConfigHelper
from firewall.core.io.icmptype import IcmpType
from firewall.core.io.ipset import IPSet
from firewall.core.io.helper import Helper
from firewall.core.io.lockdown_whitelist import LockdownWhitelist
from firewall.core.io.direct import Direct
from firewall.dbus_utils import dbus_to_python, \
    command_of_sender, context_of_sender, uid_of_sender, user_of_uid, \
    dbus_introspection_prepare_properties, \
    dbus_introspection_add_properties, \
    dbus_introspection_add_deprecated
from firewall import errors
from firewall.errors import FirewallError

############################################################################
#
# class FirewallDConfig
#
############################################################################

class FirewallDConfig(DbusServiceObject):
    """FirewallD main class"""

    persistent = True
    """ Make FirewallD persistent. """
    default_polkit_auth_required = config.dbus.PK_ACTION_CONFIG
    """ Use config.dbus.PK_ACTION_INFO as a default """

    @handle_exceptions
    def __init__(self, conf, *args, **kwargs):
        super(FirewallDConfig, self).__init__(*args, **kwargs)
        self.config = conf
        self.busname = args[0]
        self.path = args[1]
        self._init_vars()
        self.watcher = Watcher(self.watch_updater, 5)
        self.watcher.add_watch_dir(config.FIREWALLD_IPSETS)
        self.watcher.add_watch_dir(config.ETC_FIREWALLD_IPSETS)
        self.watcher.add_watch_dir(config.FIREWALLD_ICMPTYPES)
        self.watcher.add_watch_dir(config.ETC_FIREWALLD_ICMPTYPES)
        self.watcher.add_watch_dir(config.FIREWALLD_HELPERS)
        self.watcher.add_watch_dir(config.ETC_FIREWALLD_HELPERS)
        self.watcher.add_watch_dir(config.FIREWALLD_SERVICES)
        self.watcher.add_watch_dir(config.ETC_FIREWALLD_SERVICES)
        self.watcher.add_watch_dir(config.FIREWALLD_ZONES)
        self.watcher.add_watch_dir(config.ETC_FIREWALLD_ZONES)
        self.watcher.add_watch_dir(config.FIREWALLD_POLICIES)
        self.watcher.add_watch_dir(config.ETC_FIREWALLD_POLICIES)
        # Add watches for combined zone directories
        if os.path.exists(config.ETC_FIREWALLD_ZONES):
            for filename in sorted(os.listdir(config.ETC_FIREWALLD_ZONES)):
                path = "%s/%s" % (config.ETC_FIREWALLD_ZONES, filename)
                if os.path.isdir(path):
                    self.watcher.add_watch_dir(path)
        self.watcher.add_watch_file(config.LOCKDOWN_WHITELIST)
        self.watcher.add_watch_file(config.FIREWALLD_DIRECT)
        self.watcher.add_watch_file(config.FIREWALLD_CONF)

        dbus_introspection_prepare_properties(self,
                                              config.dbus.DBUS_INTERFACE_CONFIG,
                                              { "CleanupOnExit": "readwrite",
                                                "CleanupModulesOnExit": "readwrite",
                                                "IPv6_rpfilter": "readwrite",
                                                "Lockdown": "readwrite",
                                                "MinimalMark": "readwrite",
                                                "IndividualCalls": "readwrite",
                                                "LogDenied": "readwrite",
                                                "AutomaticHelpers": "readwrite",
                                                "FirewallBackend": "readwrite",
                                                "FlushAllOnReload": "readwrite",
                                                "RFC3964_IPv4": "readwrite",
                                                "AllowZoneDrifting": "readwrite",
                                              })

    @handle_exceptions
    def _init_vars(self):
        self.ipsets = [ ]
        self.ipset_idx = 0
        self.icmptypes = [ ]
        self.icmptype_idx = 0
        self.services = [ ]
        self.service_idx = 0
        self.zones = [ ]
        self.zone_idx = 0
        self.helpers = [ ]
        self.helper_idx = 0
        self.policy_objects = [ ]
        self.policy_object_idx = 0

        for ipset in self.config.get_ipsets():
            self._addIPSet(self.config.get_ipset(ipset))
        for icmptype in self.config.get_icmptypes():
            self._addIcmpType(self.config.get_icmptype(icmptype))
        for service in self.config.get_services():
            self._addService(self.config.get_service(service))
        for zone in self.config.get_zones():
            self._addZone(self.config.get_zone(zone))
        for helper in self.config.get_helpers():
            self._addHelper(self.config.get_helper(helper))
        for policy in self.config.get_policy_objects():
            self._addPolicy(self.config.get_policy_object(policy))

    @handle_exceptions
    def __del__(self):
        pass

    @handle_exceptions
    def reload(self):
        while len(self.ipsets) > 0:
            item = self.ipsets.pop()
            item.unregister()
            del item
        while len(self.icmptypes) > 0:
            item = self.icmptypes.pop()
            item.unregister()
            del item
        while len(self.services) > 0:
            item = self.services.pop()
            item.unregister()
            del item
        while len(self.zones) > 0:
            item = self.zones.pop()
            item.unregister()
            del item
        while len(self.helpers) > 0:
            item = self.helpers.pop()
            item.unregister()
            del item
        while len(self.policy_objects) > 0:
            item = self.policy_objects.pop()
            item.unregister()
            del item
        self._init_vars()

    @handle_exceptions
    def watch_updater(self, name):
        if name == config.FIREWALLD_CONF:
            old_props = self.GetAll(config.dbus.DBUS_INTERFACE_CONFIG)
            log.debug1("config: Reloading firewalld config file '%s'",
                       config.FIREWALLD_CONF)
            try:
                self.config.update_firewalld_conf()
            except Exception as msg:
                log.error("Failed to load firewalld.conf file '%s': %s" % \
                          (name, msg))
                return
            props = self.GetAll(config.dbus.DBUS_INTERFACE_CONFIG).copy()
            for key in list(props.keys()):
                if key in old_props and old_props[key] == props[key]:
                    del props[key]
            if len(props) > 0:
                self.PropertiesChanged(config.dbus.DBUS_INTERFACE_CONFIG,
                                       props, [])
            return

        if (name.startswith(config.FIREWALLD_ICMPTYPES) or \
            name.startswith(config.ETC_FIREWALLD_ICMPTYPES)) and \
           name.endswith(".xml"):
            try:
                (what, obj) = self.config.update_icmptype_from_path(name)
            except Exception as msg:
                log.error("Failed to load icmptype file '%s': %s" % (name, msg))
                return
            if what == "new":
                self._addIcmpType(obj)
            elif what == "remove":
                self.removeIcmpType(obj)
            elif what == "update":
                self._updateIcmpType(obj)

        elif (name.startswith(config.FIREWALLD_SERVICES) or \
              name.startswith(config.ETC_FIREWALLD_SERVICES)) and \
             name.endswith(".xml"):
            try:
                (what, obj) = self.config.update_service_from_path(name)
            except Exception as msg:
                log.error("Failed to load service file '%s': %s" % (name, msg))
                return
            if what == "new":
                self._addService(obj)
            elif what == "remove":
                self.removeService(obj)
            elif what == "update":
                self._updateService(obj)

        elif name.startswith(config.FIREWALLD_ZONES) or \
             name.startswith(config.ETC_FIREWALLD_ZONES):
            if name.endswith(".xml"):
                try:
                    (what, obj) = self.config.update_zone_from_path(name)
                except Exception as msg:
                    log.error("Failed to load zone file '%s': %s" % (name, msg))
                    return
                if what == "new":
                    self._addZone(obj)
                elif what == "remove":
                    self.removeZone(obj)
                elif what == "update":
                    self._updateZone(obj)
            elif name.startswith(config.ETC_FIREWALLD_ZONES):
                # possible combined zone base directory
                _name = name.replace(config.ETC_FIREWALLD_ZONES, "").strip("/")
                if len(_name) < 1 or "/" in _name:
                    # if there is a / in x, then it is a sub sub directory
                    # ignore it
                    return
                if os.path.isdir(name):
                    if not self.watcher.has_watch(name):
                        self.watcher.add_watch_dir(name)
                elif self.watcher.has_watch(name):
                    self.watcher.remove_watch(name)

        elif (name.startswith(config.FIREWALLD_IPSETS) or \
              name.startswith(config.ETC_FIREWALLD_IPSETS)) and \
             name.endswith(".xml"):
            try:
                (what, obj) = self.config.update_ipset_from_path(name)
            except Exception as msg:
                log.error("Failed to load ipset file '%s': %s" % (name,
                                                                  msg))

                return
            if what == "new":
                self._addIPSet(obj)
            elif what == "remove":
                self.removeIPSet(obj)
            elif what == "update":
                self._updateIPSet(obj)

        elif (name.startswith(config.FIREWALLD_HELPERS) or \
              name.startswith(config.ETC_FIREWALLD_HELPERS)) and \
             name.endswith(".xml"):
            try:
                (what, obj) = self.config.update_helper_from_path(name)
            except Exception as msg:
                log.error("Failed to load helper file '%s': %s" % (name,
                                                                  msg))

                return
            if what == "new":
                self._addHelper(obj)
            elif what == "remove":
                self.removeHelper(obj)
            elif what == "update":
                self._updateHelper(obj)

        elif name == config.LOCKDOWN_WHITELIST:
            try:
                self.config.update_lockdown_whitelist()
            except Exception as msg:
                log.error("Failed to load lockdown whitelist file '%s': %s" % \
                          (name, msg))
                return
            self.LockdownWhitelistUpdated()

        elif name == config.FIREWALLD_DIRECT:
            try:
                self.config.update_direct()
            except Exception as msg:
                log.error("Failed to load direct rules file '%s': %s" % (name,
                                                                         msg))
                return
            self.Updated()

        elif (name.startswith(config.FIREWALLD_POLICIES) or \
              name.startswith(config.ETC_FIREWALLD_POLICIES)) and \
             name.endswith(".xml"):
            try:
                (what, obj) = self.config.update_policy_object_from_path(name)
            except Exception as msg:
                log.error("Failed to load policy file '%s': %s" % (name, msg))
                return
            if what == "new":
                self._addPolicy(obj)
            elif what == "remove":
                self.removePolicy(obj)
            elif what == "update":
                self._updatePolicy(obj)

    @handle_exceptions
    def _addIcmpType(self, obj):
        # TODO: check for idx overflow
        config_icmptype = FirewallDConfigIcmpType(
            self, self.config, obj, self.icmptype_idx, self.busname,
            "%s/%d" % (config.dbus.DBUS_PATH_CONFIG_ICMPTYPE,
                       self.icmptype_idx))
        self.icmptypes.append(config_icmptype)
        self.icmptype_idx += 1
        self.IcmpTypeAdded(obj.name)
        return config_icmptype

    @handle_exceptions
    def _updateIcmpType(self, obj):
        for icmptype in self.icmptypes:
            if icmptype.obj.name == obj.name and \
                    icmptype.obj.path == obj.path and \
                    icmptype.obj.filename == obj.filename:
                icmptype.obj = obj
                icmptype.Updated(obj.name)

    @handle_exceptions
    def removeIcmpType(self, obj):
        index = 7 # see IMPORT_EXPORT_STRUCTURE in class Zone(IO_Object)
        for zone in self.zones:
            settings = zone.getSettings()
            # if this IcmpType is used in a zone remove it from that zone first
            if obj.name in settings[index]:
                settings[index].remove(obj.name)
                zone.obj = self.config.set_zone_config(zone.obj, settings)
                zone.Updated(zone.obj.name)

        for policy in self.policy_objects:
            settings = policy.getSettings()
            # if this IcmpType is used in a policy remove it from that policy first
            if "icmp_blocks" in settings and obj.name in settings["icmp_blocks"]:
                settings["icmp_blocks"].remove(obj.name)
                policy.obj = self.config.set_policy_object_config_dict(policy.obj, settings)
                policy.Updated(policy.obj.name)

        for icmptype in self.icmptypes:
            if icmptype.obj == obj:
                icmptype.Removed(obj.name)
                icmptype.unregister()
                self.icmptypes.remove(icmptype)
                del icmptype

    @handle_exceptions
    def _addService(self, obj):
        # TODO: check for idx overflow
        config_service = FirewallDConfigService(
            self, self.config, obj, self.service_idx, self.busname,
            "%s/%d" % (config.dbus.DBUS_PATH_CONFIG_SERVICE, self.service_idx))
        self.services.append(config_service)
        self.service_idx += 1
        self.ServiceAdded(obj.name)
        return config_service

    @handle_exceptions
    def _updateService(self, obj):
        for service in self.services:
            if service.obj.name == obj.name and \
                    service.obj.path == obj.path and \
                    service.obj.filename == obj.filename:
                service.obj = obj
                service.Updated(obj.name)

    @handle_exceptions
    def removeService(self, obj):
        index = 5 # see IMPORT_EXPORT_STRUCTURE in class Zone(IO_Object)
        for zone in self.zones:
            settings = zone.getSettings()
            # if this Service is used in a zone remove it from that zone first
            if obj.name in settings[index]:
                settings[index].remove(obj.name)
                zone.obj = self.config.set_zone_config(zone.obj, settings)
                zone.Updated(zone.obj.name)

        for policy in self.policy_objects:
            settings = policy.getSettings()
            # if this Service is used in a policy remove it from that policy first
            if "services" in settings and obj.name in settings["services"]:
                settings["services"].remove(obj.name)
                policy.obj = self.config.set_policy_object_config_dict(policy.obj, settings)
                policy.Updated(policy.obj.name)

        for service in self.services:
            if service.obj == obj:
                service.Removed(obj.name)
                service.unregister()
                self.services.remove(service)
                del service

    @handle_exceptions
    def _addZone(self, obj):
        # TODO: check for idx overflow
        config_zone = FirewallDConfigZone(
            self, self.config, obj, self.zone_idx, self.busname,
            "%s/%d" % (config.dbus.DBUS_PATH_CONFIG_ZONE, self.zone_idx))
        self.zones.append(config_zone)
        self.zone_idx += 1
        self.ZoneAdded(obj.name)
        return config_zone

    @handle_exceptions
    def _updateZone(self, obj):
        for zone in self.zones:
            if zone.obj.name == obj.name and zone.obj.path == obj.path and \
                    zone.obj.filename == obj.filename:
                zone.obj = obj
                zone.Updated(obj.name)

    @handle_exceptions
    def removeZone(self, obj):
        for zone in self.zones:
            if zone.obj == obj:
                zone.Removed(obj.name)
                zone.unregister()
                self.zones.remove(zone)
                del zone

    @handle_exceptions
    def _addPolicy(self, obj):
        # TODO: check for idx overflow
        config_policy = FirewallDConfigPolicy(
            self, self.config, obj, self.policy_object_idx, self.busname,
            "%s/%d" % (config.dbus.DBUS_PATH_CONFIG_POLICY, self.policy_object_idx))
        self.policy_objects.append(config_policy)
        self.policy_object_idx += 1
        self.PolicyAdded(obj.name)
        return config_policy

    @handle_exceptions
    def _updatePolicy(self, obj):
        for policy in self.policy_objects:
            if policy.obj.name == obj.name and policy.obj.path == obj.path and \
                    policy.obj.filename == obj.filename:
                policy.obj = obj
                policy.Updated(obj.name)

    @handle_exceptions
    def removePolicy(self, obj):
        for policy in self.policy_objects:
            if policy.obj == obj:
                policy.Removed(obj.name)
                policy.unregister()
                self.policy_objects.remove(policy)
                del policy

    @handle_exceptions
    def _addIPSet(self, obj):
        # TODO: check for idx overflow
        config_ipset = FirewallDConfigIPSet(
            self, self.config, obj, self.ipset_idx, self.busname,
            "%s/%d" % (config.dbus.DBUS_PATH_CONFIG_IPSET, self.ipset_idx))
        self.ipsets.append(config_ipset)
        self.ipset_idx += 1
        self.IPSetAdded(obj.name)
        return config_ipset

    @handle_exceptions
    def _updateIPSet(self, obj):
        for ipset in self.ipsets:
            if ipset.obj.name == obj.name and ipset.obj.path == obj.path and \
                    ipset.obj.filename == obj.filename:
                ipset.obj = obj
                ipset.Updated(obj.name)

    @handle_exceptions
    def removeIPSet(self, obj):
        for ipset in self.ipsets:
            if ipset.obj == obj:
                ipset.Removed(obj.name)
                ipset.unregister()
                self.ipsets.remove(ipset)
                del ipset

    # access check

    @handle_exceptions
    def _addHelper(self, obj):
        # TODO: check for idx overflow
        config_helper = FirewallDConfigHelper(
            self, self.config, obj, self.helper_idx, self.busname,
            "%s/%d" % (config.dbus.DBUS_PATH_CONFIG_HELPER, self.helper_idx))
        self.helpers.append(config_helper)
        self.helper_idx += 1
        self.HelperAdded(obj.name)
        return config_helper

    @handle_exceptions
    def _updateHelper(self, obj):
        for helper in self.helpers:
            if helper.obj.name == obj.name and helper.obj.path == obj.path and \
                    helper.obj.filename == obj.filename:
                helper.obj = obj
                helper.Updated(obj.name)

    @handle_exceptions
    def removeHelper(self, obj):
        for helper in self.helpers:
            if helper.obj == obj:
                helper.Removed(obj.name)
                helper.unregister()
                self.helpers.remove(helper)
                del helper

    # access check

    @dbus_handle_exceptions
    def accessCheck(self, sender):
        if self.config.lockdown_enabled():
            if sender is None:
                log.error("Lockdown not possible, sender not set.")
                return
            bus = dbus.SystemBus()
            context = context_of_sender(bus, sender)
            if self.config.access_check("context", context):
                return
            uid = uid_of_sender(bus, sender)
            if self.config.access_check("uid", uid):
                return
            user = user_of_uid(uid)
            if self.config.access_check("user", user):
                return
            command = command_of_sender(bus, sender)
            if self.config.access_check("command", command):
                return
            raise FirewallError(errors.ACCESS_DENIED, "lockdown is enabled")

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # P R O P E R T I E S

    @dbus_handle_exceptions
    def _get_property(self, prop):
        if prop not in [ "DefaultZone", "MinimalMark", "CleanupOnExit",
                         "CleanupModulesOnExit", "Lockdown", "IPv6_rpfilter",
                         "IndividualCalls", "LogDenied", "AutomaticHelpers",
                         "FirewallBackend", "FlushAllOnReload", "RFC3964_IPv4",
                         "AllowZoneDrifting" ]:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.InvalidArgs: "
                "Property '%s' does not exist" % prop)

        value = self.config.get_firewalld_conf().get(prop)

        if prop == "DefaultZone":
            if value is None:
                value = config.FALLBACK_ZONE
            return dbus.String(value)
        elif prop == "MinimalMark":
            if value is None:
                value = config.FALLBACK_MINIMAL_MARK
            else:
                value = int(value)
            return dbus.Int32(value)
        elif prop == "CleanupOnExit":
            if value is None:
                value = "yes" if config.FALLBACK_CLEANUP_ON_EXIT else "no"
            return dbus.String(value)
        elif prop == "CleanupModulesOnExit":
            if value is None:
                value = "yes" if config.FALLBACK_CLEANUP_MODULES_ON_EXIT else "no"
            return dbus.String(value)
        elif prop == "Lockdown":
            if value is None:
                value = "yes" if config.FALLBACK_LOCKDOWN else "no"
            return dbus.String(value)
        elif prop == "IPv6_rpfilter":
            if value is None:
                value = "yes" if config.FALLBACK_IPV6_RPFILTER else "no"
            return dbus.String(value)
        elif prop == "IndividualCalls":
            if value is None:
                value = "yes" if config.FALLBACK_INDIVIDUAL_CALLS else "no"
            return dbus.String(value)
        elif prop == "LogDenied":
            if value is None:
                value = config.FALLBACK_LOG_DENIED
            return dbus.String(value)
        elif prop == "AutomaticHelpers":
            if value is None:
                value = config.FALLBACK_AUTOMATIC_HELPERS
            return dbus.String(value)
        elif prop == "FirewallBackend":
            if value is None:
                value = config.FALLBACK_FIREWALL_BACKEND
            return dbus.String(value)
        elif prop == "FlushAllOnReload":
            if value is None:
                value = "yes" if config.FALLBACK_FLUSH_ALL_ON_RELOAD else "no"
            return dbus.String(value)
        elif prop == "RFC3964_IPv4":
            if value is None:
                value = "yes" if config.FALLBACK_RFC3964_IPV4 else "no"
            return dbus.String(value)
        elif prop == "AllowZoneDrifting":
            if value is None:
                value = "yes" if config.FALLBACK_ALLOW_ZONE_DRIFTING else "no"
            return dbus.String(value)

    @dbus_handle_exceptions
    def _get_dbus_property(self, prop):
        if prop == "DefaultZone":
            return dbus.String(self._get_property(prop))
        elif prop == "MinimalMark":
            return dbus.Int32(self._get_property(prop))
        elif prop == "CleanupOnExit":
            return dbus.String(self._get_property(prop))
        elif prop == "CleanupModulesOnExit":
            return dbus.String(self._get_property(prop))
        elif prop == "Lockdown":
            return dbus.String(self._get_property(prop))
        elif prop == "IPv6_rpfilter":
            return dbus.String(self._get_property(prop))
        elif prop == "IndividualCalls":
            return dbus.String(self._get_property(prop))
        elif prop == "LogDenied":
            return dbus.String(self._get_property(prop))
        elif prop == "AutomaticHelpers":
            return dbus.String(self._get_property(prop))
        elif prop == "FirewallBackend":
            return dbus.String(self._get_property(prop))
        elif prop == "FlushAllOnReload":
            return dbus.String(self._get_property(prop))
        elif prop == "RFC3964_IPv4":
            return dbus.String(self._get_property(prop))
        elif prop == "AllowZoneDrifting":
            return dbus.String(self._get_property(prop))
        else:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.InvalidArgs: "
                "Property '%s' does not exist" % prop)

    @dbus_service_method(dbus.PROPERTIES_IFACE, in_signature='ss',
                         out_signature='v')
    @dbus_handle_exceptions
    def Get(self, interface_name, property_name, sender=None): # pylint: disable=W0613
        # get a property
        interface_name = dbus_to_python(interface_name, str)
        property_name = dbus_to_python(property_name, str)
        log.debug1("config.Get('%s', '%s')", interface_name, property_name)

        if interface_name == config.dbus.DBUS_INTERFACE_CONFIG:
            return self._get_dbus_property(property_name)
        elif interface_name in [ config.dbus.DBUS_INTERFACE_CONFIG_DIRECT,
                                 config.dbus.DBUS_INTERFACE_CONFIG_POLICIES ]:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.InvalidArgs: "
                "Property '%s' does not exist" % property_name)
        else:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.UnknownInterface: "
                "Interface '%s' does not exist" % interface_name)

    @dbus_service_method(dbus.PROPERTIES_IFACE, in_signature='s',
                         out_signature='a{sv}')
    @dbus_handle_exceptions
    def GetAll(self, interface_name, sender=None): # pylint: disable=W0613
        interface_name = dbus_to_python(interface_name, str)
        log.debug1("config.GetAll('%s')", interface_name)

        ret = { }
        if interface_name == config.dbus.DBUS_INTERFACE_CONFIG:
            for x in [ "DefaultZone", "MinimalMark", "CleanupOnExit",
                       "CleanupModulesOnExit", "Lockdown", "IPv6_rpfilter",
                       "IndividualCalls", "LogDenied", "AutomaticHelpers",
                       "FirewallBackend", "FlushAllOnReload", "RFC3964_IPv4",
                       "AllowZoneDrifting" ]:
                ret[x] = self._get_property(x)
        elif interface_name in [ config.dbus.DBUS_INTERFACE_CONFIG_DIRECT,
                                 config.dbus.DBUS_INTERFACE_CONFIG_POLICIES ]:
            pass
        else:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.UnknownInterface: "
                "Interface '%s' does not exist" % interface_name)

        return dbus.Dictionary(ret, signature="sv")

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(dbus.PROPERTIES_IFACE, in_signature='ssv')
    @dbus_handle_exceptions
    def Set(self, interface_name, property_name, new_value, sender=None):
        interface_name = dbus_to_python(interface_name, str)
        property_name = dbus_to_python(property_name, str)
        new_value = dbus_to_python(new_value)
        log.debug1("config.Set('%s', '%s', '%s')", interface_name,
                   property_name, new_value)
        self.accessCheck(sender)

        if interface_name == config.dbus.DBUS_INTERFACE_CONFIG:
            if property_name in [ "CleanupOnExit",
                                  "CleanupModulesOnExit", "Lockdown",
                                  "IPv6_rpfilter", "IndividualCalls",
                                  "LogDenied",
                                  "FirewallBackend", "FlushAllOnReload",
                                  "RFC3964_IPv4"]:
                if property_name in [ "CleanupOnExit", "CleanupModulesOnExit",
                                      "Lockdown", "IPv6_rpfilter",
                                      "IndividualCalls", "FlushAllOnReload",
                                      "RFC3964_IPv4"]:
                    if new_value.lower() not in [ "yes", "no",
                                                  "true", "false" ]:
                        raise FirewallError(errors.INVALID_VALUE,
                                            "'%s' for %s" % \
                                            (new_value, property_name))
                elif property_name == "LogDenied":
                    if new_value not in config.LOG_DENIED_VALUES:
                        raise FirewallError(errors.INVALID_VALUE,
                                            "'%s' for %s" % \
                                            (new_value, property_name))
                elif property_name == "FirewallBackend":
                    if new_value not in config.FIREWALL_BACKEND_VALUES:
                        raise FirewallError(errors.INVALID_VALUE,
                                            "'%s' for %s" % \
                                            (new_value, property_name))
                else:
                    raise dbus.exceptions.DBusException(
                        "org.freedesktop.DBus.Error.InvalidArgs: "
                        "Property '%s' does not exist" % property_name)

                self.config.get_firewalld_conf().set(property_name, new_value)
                self.config.get_firewalld_conf().write()
                self.PropertiesChanged(interface_name,
                                       { property_name: new_value }, [ ])
            elif property_name in ["MinimalMark", "AutomaticHelpers", "AllowZoneDrifting"]:
                # deprecated fields. Ignore setting them.
                pass
            else:
                raise dbus.exceptions.DBusException(
                    "org.freedesktop.DBus.Error.InvalidArgs: "
                    "Property '%s' does not exist" % property_name)
        elif interface_name in [ config.dbus.DBUS_INTERFACE_CONFIG_DIRECT,
                                 config.dbus.DBUS_INTERFACE_CONFIG_POLICIES ]:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.InvalidArgs: "
                "Property '%s' does not exist" % property_name)
        else:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.UnknownInterface: "
                "Interface '%s' does not exist" % interface_name)

    @dbus.service.signal(dbus.PROPERTIES_IFACE, signature='sa{sv}as')
    def PropertiesChanged(self, interface_name, changed_properties,
                          invalidated_properties):
        interface_name = dbus_to_python(interface_name, str)
        changed_properties = dbus_to_python(changed_properties)
        invalidated_properties = dbus_to_python(invalidated_properties)
        log.debug1("config.PropertiesChanged('%s', '%s', '%s')",
                   interface_name, changed_properties, invalidated_properties)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_INFO)
    @dbus_service_method(dbus.INTROSPECTABLE_IFACE, out_signature='s')
    @dbus_handle_exceptions
    def Introspect(self, sender=None): # pylint: disable=W0613
        log.debug2("config.Introspect()")

        data = super(FirewallDConfig, self).Introspect(self.path,
                                                       self.busname.get_bus())
        data = dbus_introspection_add_properties(
                    self, data, config.dbus.DBUS_INTERFACE_CONFIG)

        for interface in [config.dbus.DBUS_INTERFACE_CONFIG_DIRECT]:
            data = dbus_introspection_add_deprecated(
                        self, data, interface,
                        dbus_service_method_deprecated().deprecated,
                        dbus_service_signal_deprecated().deprecated)

        return data

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # policies

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_POLICIES,
                         out_signature=LockdownWhitelist.DBUS_SIGNATURE)
    @dbus_handle_exceptions
    def getLockdownWhitelist(self, sender=None): # pylint: disable=W0613
        log.debug1("config.policies.getLockdownWhitelist()")
        return self.config.get_policies().lockdown_whitelist.export_config()

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_POLICIES,
                         in_signature=LockdownWhitelist.DBUS_SIGNATURE)
    @dbus_handle_exceptions
    def setLockdownWhitelist(self, settings, sender=None): # pylint: disable=W0613
        log.debug1("config.policies.setLockdownWhitelist(...)")
        settings = dbus_to_python(settings)
        self.config.get_policies().lockdown_whitelist.import_config(settings)
        self.config.get_policies().lockdown_whitelist.write()
        self.LockdownWhitelistUpdated()

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_CONFIG_POLICIES)
    @dbus_handle_exceptions
    def LockdownWhitelistUpdated(self):
        log.debug1("config.policies.LockdownWhitelistUpdated()")

    # command

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_POLICIES,
                         in_signature='s')
    @dbus_handle_exceptions
    def addLockdownWhitelistCommand(self, command, sender=None):
        command = dbus_to_python(command)
        log.debug1("config.policies.addLockdownWhitelistCommand('%s')", command)
        self.accessCheck(sender)
        settings = list(self.getLockdownWhitelist())
        if command in settings[0]:
            raise FirewallError(errors.ALREADY_ENABLED, command)
        settings[0].append(command)
        self.setLockdownWhitelist(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_POLICIES,
                         in_signature='s')
    @dbus_handle_exceptions
    def removeLockdownWhitelistCommand(self, command, sender=None):
        command = dbus_to_python(command)
        log.debug1("config.policies.removeLockdownWhitelistCommand('%s')",
                   command)
        self.accessCheck(sender)
        settings = list(self.getLockdownWhitelist())
        if command not in settings[0]:
            raise FirewallError(errors.NOT_ENABLED, command)
        settings[0].remove(command)
        self.setLockdownWhitelist(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_POLICIES,
                         in_signature='s', out_signature='b')
    @dbus_handle_exceptions
    def queryLockdownWhitelistCommand(self, command, sender=None): # pylint: disable=W0613
        command = dbus_to_python(command)
        log.debug1("config.policies.queryLockdownWhitelistCommand('%s')",
                   command)
        return command in self.getLockdownWhitelist()[0]

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_POLICIES,
                         out_signature='as')
    @dbus_handle_exceptions
    def getLockdownWhitelistCommands(self, sender=None): # pylint: disable=W0613
        log.debug1("config.policies.getLockdownWhitelistCommands()")
        return self.getLockdownWhitelist()[0]

    # context

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_POLICIES,
                         in_signature='s')
    @dbus_handle_exceptions
    def addLockdownWhitelistContext(self, context, sender=None):
        context = dbus_to_python(context)
        log.debug1("config.policies.addLockdownWhitelistContext('%s')", context)
        self.accessCheck(sender)
        settings = list(self.getLockdownWhitelist())
        if context in settings[1]:
            raise FirewallError(errors.ALREADY_ENABLED, context)
        settings[1].append(context)
        self.setLockdownWhitelist(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_POLICIES,
                         in_signature='s')
    @dbus_handle_exceptions
    def removeLockdownWhitelistContext(self, context, sender=None):
        context = dbus_to_python(context)
        log.debug1("config.policies.removeLockdownWhitelistContext('%s')",
                   context)
        self.accessCheck(sender)
        settings = list(self.getLockdownWhitelist())
        if context not in settings[1]:
            raise FirewallError(errors.NOT_ENABLED, context)
        settings[1].remove(context)
        self.setLockdownWhitelist(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_POLICIES,
                         in_signature='s', out_signature='b')
    @dbus_handle_exceptions
    def queryLockdownWhitelistContext(self, context, sender=None): # pylint: disable=W0613
        context = dbus_to_python(context)
        log.debug1("config.policies.queryLockdownWhitelistContext('%s')",
                   context)
        return context in self.getLockdownWhitelist()[1]

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_POLICIES,
                         out_signature='as')
    @dbus_handle_exceptions
    def getLockdownWhitelistContexts(self, sender=None): # pylint: disable=W0613
        log.debug1("config.policies.getLockdownWhitelistContexts()")
        return self.getLockdownWhitelist()[1]

    # user

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_POLICIES,
                         in_signature='s')
    @dbus_handle_exceptions
    def addLockdownWhitelistUser(self, user, sender=None):
        user = dbus_to_python(user)
        log.debug1("config.policies.addLockdownWhitelistUser('%s')", user)
        self.accessCheck(sender)
        settings = list(self.getLockdownWhitelist())
        if user in settings[2]:
            raise FirewallError(errors.ALREADY_ENABLED, user)
        settings[2].append(user)
        self.setLockdownWhitelist(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_POLICIES,
                         in_signature='s')
    @dbus_handle_exceptions
    def removeLockdownWhitelistUser(self, user, sender=None):
        user = dbus_to_python(user)
        log.debug1("config.policies.removeLockdownWhitelistUser('%s')", user)
        self.accessCheck(sender)
        settings = list(self.getLockdownWhitelist())
        if user not in settings[2]:
            raise FirewallError(errors.NOT_ENABLED, user)
        settings[2].remove(user)
        self.setLockdownWhitelist(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_POLICIES,
                         in_signature='s', out_signature='b')
    @dbus_handle_exceptions
    def queryLockdownWhitelistUser(self, user, sender=None): # pylint: disable=W0613
        user = dbus_to_python(user)
        log.debug1("config.policies.queryLockdownWhitelistUser('%s')", user)
        return user in self.getLockdownWhitelist()[2]

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_POLICIES,
                         out_signature='as')
    @dbus_handle_exceptions
    def getLockdownWhitelistUsers(self, sender=None): # pylint: disable=W0613
        log.debug1("config.policies.getLockdownWhitelistUsers()")
        return self.getLockdownWhitelist()[2]

    # uid

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_POLICIES,
                         in_signature='i')
    @dbus_handle_exceptions
    def addLockdownWhitelistUid(self, uid, sender=None):
        uid = dbus_to_python(uid)
        log.debug1("config.policies.addLockdownWhitelistUid(%d)", uid)
        self.accessCheck(sender)
        settings = list(self.getLockdownWhitelist())
        if uid in settings[3]:
            raise FirewallError(errors.ALREADY_ENABLED, uid)
        settings[3].append(uid)
        self.setLockdownWhitelist(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_POLICIES,
                         in_signature='i')
    @dbus_handle_exceptions
    def removeLockdownWhitelistUid(self, uid, sender=None):
        uid = dbus_to_python(uid)
        log.debug1("config.policies.removeLockdownWhitelistUid(%d)", uid)
        self.accessCheck(sender)
        settings = list(self.getLockdownWhitelist())
        if uid not in settings[3]:
            raise FirewallError(errors.NOT_ENABLED, uid)
        settings[3].remove(uid)
        self.setLockdownWhitelist(settings)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_POLICIES,
                         in_signature='i', out_signature='b')
    @dbus_handle_exceptions
    def queryLockdownWhitelistUid(self, uid, sender=None): # pylint: disable=W0613
        uid = dbus_to_python(uid)
        log.debug1("config.policies.queryLockdownWhitelistUid(%d)", uid)
        return uid in self.getLockdownWhitelist()[3]

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_POLICIES,
                         out_signature='ai')
    @dbus_handle_exceptions
    def getLockdownWhitelistUids(self, sender=None): # pylint: disable=W0613
        log.debug1("config.policies.getLockdownWhitelistUids()")
        return self.getLockdownWhitelist()[3]

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # I P S E T S

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG, out_signature='ao')
    @dbus_handle_exceptions
    def listIPSets(self, sender=None): # pylint: disable=W0613
        """list ipsets objects paths
        """
        log.debug1("config.listIPSets()")
        return self.ipsets

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG, out_signature='as')
    @dbus_handle_exceptions
    def getIPSetNames(self, sender=None): # pylint: disable=W0613
        """get ipset names
        """
        log.debug1("config.getIPSetNames()")
        ipsets = [ ]
        for obj in self.ipsets:
            ipsets.append(obj.obj.name)
        return sorted(ipsets)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG, in_signature='s',
                         out_signature='o')
    @dbus_handle_exceptions
    def getIPSetByName(self, ipset, sender=None): # pylint: disable=W0613
        """object path of ipset with given name
        """
        ipset = dbus_to_python(ipset, str)
        log.debug1("config.getIPSetByName('%s')", ipset)
        for obj in self.ipsets:
            if obj.obj.name == ipset:
                return obj
        raise FirewallError(errors.INVALID_IPSET, ipset)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG,
                         in_signature='s'+IPSet.DBUS_SIGNATURE,
                         out_signature='o')
    @dbus_handle_exceptions
    def addIPSet(self, ipset, settings, sender=None):
        """add ipset with given name and settings
        """
        ipset = dbus_to_python(ipset, str)
        settings = dbus_to_python(settings)
        log.debug1("config.addIPSet('%s')", ipset)
        self.accessCheck(sender)
        obj = self.config.new_ipset(ipset, settings)
        config_ipset = self._addIPSet(obj)
        return config_ipset

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_CONFIG, signature='s')
    @dbus_handle_exceptions
    def IPSetAdded(self, ipset):
        ipset = dbus_to_python(ipset, str)
        log.debug1("config.IPSetAdded('%s')" % (ipset))

    # I C M P T Y P E S

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG, out_signature='ao')
    @dbus_handle_exceptions
    def listIcmpTypes(self, sender=None): # pylint: disable=W0613
        """list icmptypes objects paths
        """
        log.debug1("config.listIcmpTypes()")
        return self.icmptypes

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG, out_signature='as')
    @dbus_handle_exceptions
    def getIcmpTypeNames(self, sender=None): # pylint: disable=W0613
        """get icmptype names
        """
        log.debug1("config.getIcmpTypeNames()")
        icmptypes = [ ]
        for obj in self.icmptypes:
            icmptypes.append(obj.obj.name)
        return sorted(icmptypes)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG, in_signature='s',
                         out_signature='o')
    @dbus_handle_exceptions
    def getIcmpTypeByName(self, icmptype, sender=None): # pylint: disable=W0613
        """object path of icmptype with given name
        """
        icmptype = dbus_to_python(icmptype, str)
        log.debug1("config.getIcmpTypeByName('%s')", icmptype)
        for obj in self.icmptypes:
            if obj.obj.name == icmptype:
                return obj
        raise FirewallError(errors.INVALID_ICMPTYPE, icmptype)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG,
                         in_signature='s'+IcmpType.DBUS_SIGNATURE,
                         out_signature='o')
    @dbus_handle_exceptions
    def addIcmpType(self, icmptype, settings, sender=None):
        """add icmptype with given name and settings
        """
        icmptype = dbus_to_python(icmptype, str)
        settings = dbus_to_python(settings)
        log.debug1("config.addIcmpType('%s')", icmptype)
        self.accessCheck(sender)
        obj = self.config.new_icmptype(icmptype, settings)
        config_icmptype = self._addIcmpType(obj)
        return config_icmptype

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_CONFIG, signature='s')
    @dbus_handle_exceptions
    def IcmpTypeAdded(self, icmptype):
        log.debug1("config.IcmpTypeAdded('%s')" % (icmptype))

    # S E R V I C E S

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG, out_signature='ao')
    @dbus_handle_exceptions
    def listServices(self, sender=None): # pylint: disable=W0613
        """list services objects paths
        """
        log.debug1("config.listServices()")
        return self.services

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG, out_signature='as')
    @dbus_handle_exceptions
    def getServiceNames(self, sender=None): # pylint: disable=W0613
        """get service names
        """
        log.debug1("config.getServiceNames()")
        services = [ ]
        for obj in self.services:
            services.append(obj.obj.name)
        return sorted(services)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG, in_signature='s',
                         out_signature='o')
    @dbus_handle_exceptions
    def getServiceByName(self, service, sender=None): # pylint: disable=W0613
        """object path of service with given name
        """
        service = dbus_to_python(service, str)
        log.debug1("config.getServiceByName('%s')", service)
        for obj in self.services:
            if obj.obj.name == service:
                return obj
        raise FirewallError(errors.INVALID_SERVICE, service)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG,
                         in_signature='s(sssa(ss)asa{ss}asa(ss))',
                         out_signature='o')
    @dbus_handle_exceptions
    def addService(self, service, settings, sender=None):
        """add service with given name and settings
        """
        service = dbus_to_python(service, str)
        settings = dbus_to_python(settings)
        log.debug1("config.addService('%s')", service)
        self.accessCheck(sender)
        obj = self.config.new_service(service, settings)
        config_service = self._addService(obj)
        return config_service

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG,
                         in_signature='sa{sv}',
                         out_signature='o')
    @dbus_handle_exceptions
    def addService2(self, service, settings, sender=None):
        """add service with given name and settings
        """
        service = dbus_to_python(service, str)
        settings = dbus_to_python(settings)
        log.debug1("config.addService2('%s')", service)
        self.accessCheck(sender)
        obj = self.config.new_service_dict(service, settings)
        config_service = self._addService(obj)
        return config_service

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_CONFIG, signature='s')
    @dbus_handle_exceptions
    def ServiceAdded(self, service):
        log.debug1("config.ServiceAdded('%s')" % (service))

    # Z O N E S

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG, out_signature='ao')
    @dbus_handle_exceptions
    def listZones(self, sender=None): # pylint: disable=W0613
        """list zones objects paths
        """
        log.debug1("config.listZones()")
        return self.zones

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG, out_signature='as')
    @dbus_handle_exceptions
    def getZoneNames(self, sender=None): # pylint: disable=W0613
        """get zone names
        """
        log.debug1("config.getZoneNames()")
        zones = [ ]
        for obj in self.zones:
            zones.append(obj.obj.name)
        return sorted(zones)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG, in_signature='s',
                         out_signature='o')
    @dbus_handle_exceptions
    def getZoneByName(self, zone, sender=None): # pylint: disable=W0613
        """object path of zone with given name
        """
        zone = dbus_to_python(zone, str)
        log.debug1("config.getZoneByName('%s')", zone)
        for obj in self.zones:
            if obj.obj.name == zone:
                return obj
        raise FirewallError(errors.INVALID_ZONE, zone)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG, in_signature='s',
                         out_signature='s')
    @dbus_handle_exceptions
    def getZoneOfInterface(self, iface, sender=None): # pylint: disable=W0613
        """name of zone the given interface belongs to
        """
        iface = dbus_to_python(iface, str)
        log.debug1("config.getZoneOfInterface('%s')", iface)
        ret = []
        for obj in self.zones:
            if iface in obj.obj.interfaces:
                ret.append(obj.obj.name)
        if len(ret) > 1:
            # Even it shouldn't happen, it's actually possible that
            # the same interface is in several zone XML files
            return " ".join(ret) + \
                "  (ERROR: interface '%s' is in %s zone XML files, can be only in one)" % \
                (iface, len(ret))
        return ret[0] if ret else ""

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG, in_signature='s',
                         out_signature='s')
    @dbus_handle_exceptions
    def getZoneOfSource(self, source, sender=None): # pylint: disable=W0613
        """name of zone the given source belongs to
        """
        source = dbus_to_python(source, str)
        log.debug1("config.getZoneOfSource('%s')", source)
        ret = []
        for obj in self.zones:
            if source in obj.obj.sources:
                ret.append(obj.obj.name)
        if len(ret) > 1:
            # Even it shouldn't happen, it's actually possible that
            # the same source is in several zone XML files
            return " ".join(ret) + \
                "  (ERROR: source '%s' is in %s zone XML files, can be only in one)" % \
                (source, len(ret))
        return ret[0] if ret else ""

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG,
                         in_signature="s(sssbsasa(ss)asba(ssss)asasasasa(ss)b)",
                         out_signature='o')
    @dbus_handle_exceptions
    def addZone(self, zone, settings, sender=None):
        """add zone with given name and settings
        """
        zone = dbus_to_python(zone, str)
        settings = dbus_to_python(settings)
        log.debug1("config.addZone('%s')", zone)
        self.accessCheck(sender)
        if settings[4] == "default":
            # convert to list, fix target, convert back to tuple
            _settings = list(settings)
            _settings[4] = DEFAULT_ZONE_TARGET
            settings = tuple(_settings)
        obj = self.config.new_zone(zone, settings)
        config_zone = self._addZone(obj)
        return config_zone

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG,
                         in_signature="sa{sv}",
                         out_signature='o')
    @dbus_handle_exceptions
    def addZone2(self, zone, settings, sender=None):
        """add zone with given name and settings
        """
        zone = dbus_to_python(zone, str)
        settings = dbus_to_python(settings)
        log.debug1("config.addZone('%s')", zone)
        self.accessCheck(sender)
        if "target" in settings and settings["target"] == "default":
            settings["target"] = DEFAULT_ZONE_TARGET
        obj = self.config.new_zone_dict(zone, settings)
        config_zone = self._addZone(obj)
        return config_zone

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_CONFIG, signature='s')
    @dbus_handle_exceptions
    def ZoneAdded(self, zone):
        log.debug1("config.ZoneAdded('%s')" % (zone))

    # policies

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG, out_signature='ao')
    @dbus_handle_exceptions
    def listPolicies(self, sender=None):
        """list policies objects paths
        """
        log.debug1("config.listPolicies()")
        return self.policy_objects

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG, out_signature='as')
    @dbus_handle_exceptions
    def getPolicyNames(self, sender=None):
        """get policy names
        """
        log.debug1("config.getPolicyNames()")
        policies = [ ]
        for obj in self.policy_objects:
            policies.append(obj.obj.name)
        return sorted(policies)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG, in_signature='s',
                         out_signature='o')
    @dbus_handle_exceptions
    def getPolicyByName(self, policy, sender=None):
        """object path of policy with given name
        """
        policy = dbus_to_python(policy, str)
        log.debug1("config.getPolicyByName('%s')", policy)
        for obj in self.policy_objects:
            if obj.obj.name == policy:
                return obj
        raise FirewallError(errors.INVALID_POLICY, policy)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG,
                         in_signature="sa{sv}",
                         out_signature='o')
    @dbus_handle_exceptions
    def addPolicy(self, policy, settings, sender=None):
        """add policy with given name and settings
        """
        policy = dbus_to_python(policy, str)
        settings = dbus_to_python(settings)
        log.debug1("config.addPolicy('%s')", policy)
        self.accessCheck(sender)
        obj = self.config.new_policy_object_dict(policy, settings)
        config_policy = self._addPolicy(obj)
        return config_policy

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_CONFIG, signature='s')
    @dbus_handle_exceptions
    def PolicyAdded(self, policy):
        log.debug1("config.PolicyAdded('%s')" % (policy))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # H E L P E R S

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG, out_signature='ao')
    @dbus_handle_exceptions
    def listHelpers(self, sender=None): # pylint: disable=W0613
        """list helpers objects paths
        """
        log.debug1("config.listHelpers()")
        return self.helpers

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG, out_signature='as')
    @dbus_handle_exceptions
    def getHelperNames(self, sender=None): # pylint: disable=W0613
        """get helper names
        """
        log.debug1("config.getHelperNames()")
        helpers = [ ]
        for obj in self.helpers:
            helpers.append(obj.obj.name)
        return sorted(helpers)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG, in_signature='s',
                         out_signature='o')
    @dbus_handle_exceptions
    def getHelperByName(self, helper, sender=None): # pylint: disable=W0613
        """object path of helper with given name
        """
        helper = dbus_to_python(helper, str)
        log.debug1("config.getHelperByName('%s')", helper)
        for obj in self.helpers:
            if obj.obj.name == helper:
                return obj
        raise FirewallError(errors.INVALID_HELPER, helper)

    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG,
                         in_signature='s'+Helper.DBUS_SIGNATURE,
                         out_signature='o')
    @dbus_handle_exceptions
    def addHelper(self, helper, settings, sender=None):
        """add helper with given name and settings
        """
        helper = dbus_to_python(helper, str)
        settings = dbus_to_python(settings)
        log.debug1("config.addHelper('%s')", helper)
        self.accessCheck(sender)
        obj = self.config.new_helper(helper, settings)
        config_helper = self._addHelper(obj)
        return config_helper

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_CONFIG, signature='s')
    @dbus_handle_exceptions
    def HelperAdded(self, helper):
        helper = dbus_to_python(helper, str)
        log.debug1("config.HelperAdded('%s')" % (helper))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # DIRECT

    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT,
                         out_signature=Direct.DBUS_SIGNATURE)
    @dbus_handle_exceptions
    def getSettings(self, sender=None): # pylint: disable=W0613
        # returns list ipv, table, list of chains
        log.debug1("config.direct.getSettings()")
        return self.config.get_direct().export_config()

    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT,
                         in_signature=Direct.DBUS_SIGNATURE)
    @dbus_handle_exceptions
    def update(self, settings, sender=None): # pylint: disable=W0613
        # returns list ipv, table, list of chains
        log.debug1("config.direct.update()")
        settings = dbus_to_python(settings)
        self.config.get_direct().import_config(settings)
        self.config.get_direct().write()
        self.Updated()

    @dbus_service_signal_deprecated(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT)
    @dbus.service.signal(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT)
    @dbus_handle_exceptions
    def Updated(self):
        log.debug1("config.direct.Updated()")

    # chain

    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT,
                         in_signature='sss')
    @dbus_handle_exceptions
    def addChain(self, ipv, table, chain, sender=None):
        ipv = dbus_to_python(ipv)
        table = dbus_to_python(table)
        chain = dbus_to_python(chain)
        log.debug1("config.direct.addChain('%s', '%s', '%s')" % \
                   (ipv, table, chain))
        self.accessCheck(sender)
        idx = tuple((ipv, table, chain))
        settings = list(self.getSettings())
        if idx in settings[0]:
            raise FirewallError(errors.ALREADY_ENABLED,
                                "chain '%s' already is in '%s:%s'" % \
                                (chain, ipv, table))
        settings[0].append(idx)
        self.update(settings)

    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT,
                         in_signature='sss')
    @dbus_handle_exceptions
    def removeChain(self, ipv, table, chain, sender=None):
        ipv = dbus_to_python(ipv)
        table = dbus_to_python(table)
        chain = dbus_to_python(chain)
        log.debug1("config.direct.removeChain('%s', '%s', '%s')" % \
                   (ipv, table, chain))
        self.accessCheck(sender)
        idx = tuple((ipv, table, chain))
        settings = list(self.getSettings())
        if idx not in settings[0]:
            raise FirewallError(errors.NOT_ENABLED,
                                "chain '%s' is not in '%s:%s'" % (chain, ipv,
                                                                  table))
        settings[0].remove(idx)
        self.update(settings)

    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT,
                         in_signature='sss', out_signature='b')
    @dbus_handle_exceptions
    def queryChain(self, ipv, table, chain, sender=None): # pylint: disable=W0613
        ipv = dbus_to_python(ipv)
        table = dbus_to_python(table)
        chain = dbus_to_python(chain)
        log.debug1("config.direct.queryChain('%s', '%s', '%s')" % \
                   (ipv, table, chain))
        idx = tuple((ipv, table, chain))
        return idx in self.getSettings()[0]

    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT,
                         in_signature='ss', out_signature='as')
    @dbus_handle_exceptions
    def getChains(self, ipv, table, sender=None): # pylint: disable=W0613
        ipv = dbus_to_python(ipv)
        table = dbus_to_python(table)
        log.debug1("config.direct.getChains('%s', '%s')" % (ipv, table))
        ret = [ ]
        for idx in self.getSettings()[0]:
            if idx[0] == ipv and idx[1] == table:
                ret.append(idx[2])
        return ret

    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT,
                         in_signature='', out_signature='a(sss)')
    @dbus_handle_exceptions
    def getAllChains(self, sender=None): # pylint: disable=W0613
        log.debug1("config.direct.getAllChains()")
        return self.getSettings()[0]

    # rule

    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT,
                         in_signature='sssias')
    @dbus_handle_exceptions
    def addRule(self, ipv, table, chain, priority, args, sender=None): # pylint: disable=R0913
        ipv = dbus_to_python(ipv)
        table = dbus_to_python(table)
        chain = dbus_to_python(chain)
        priority = dbus_to_python(priority)
        args = dbus_to_python(args)
        log.debug1("config.direct.addRule('%s', '%s', '%s', %d, '%s')" % \
                   (ipv, table, chain, priority, "','".join(args)))
        self.accessCheck(sender)
        idx = (ipv, table, chain, priority, args)
        settings = list(self.getSettings())
        if idx in settings[1]:
            raise FirewallError(errors.ALREADY_ENABLED,
                                "rule '%s' already is in '%s:%s:%s'" % \
                                (args, ipv, table, chain))
        settings[1].append(idx)
        self.update(tuple(settings))

    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT,
                         in_signature='sssias')
    @dbus_handle_exceptions
    def removeRule(self, ipv, table, chain, priority, args, sender=None): # pylint: disable=R0913
        ipv = dbus_to_python(ipv)
        table = dbus_to_python(table)
        chain = dbus_to_python(chain)
        priority = dbus_to_python(priority)
        args = dbus_to_python(args)
        log.debug1("config.direct.removeRule('%s', '%s', '%s', %d, '%s')" % \
                   (ipv, table, chain, priority, "','".join(args)))
        self.accessCheck(sender)
        idx = (ipv, table, chain, priority, args)
        settings = list(self.getSettings())
        if idx not in settings[1]:
            raise FirewallError(errors.NOT_ENABLED,
                                "rule '%s' is not in '%s:%s:%s'" % \
                                (args, ipv, table, chain))
        settings[1].remove(idx)
        self.update(tuple(settings))

    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT,
                         in_signature='sssias', out_signature='b')
    @dbus_handle_exceptions
    def queryRule(self, ipv, table, chain, priority, args, sender=None): # pylint: disable=W0613,R0913
        ipv = dbus_to_python(ipv)
        table = dbus_to_python(table)
        chain = dbus_to_python(chain)
        priority = dbus_to_python(priority)
        args = dbus_to_python(args)
        log.debug1("config.direct.queryRule('%s', '%s', '%s', %d, '%s')" % \
                   (ipv, table, chain, priority, "','".join(args)))
        idx = (ipv, table, chain, priority, args)
        return idx in self.getSettings()[1]

    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT,
                         in_signature='sss')
    @dbus_handle_exceptions
    def removeRules(self, ipv, table, chain, sender=None):
        ipv = dbus_to_python(ipv)
        table = dbus_to_python(table)
        chain = dbus_to_python(chain)
        log.debug1("config.direct.removeRules('%s', '%s', '%s')" % \
                   (ipv, table, chain, ))
        self.accessCheck(sender)
        settings = list(self.getSettings())
        for rule in settings[1][:]:
            if (ipv, table, chain) == (rule[0], rule[1], rule[2]):
                settings[1].remove(rule)
        self.update(tuple(settings))

    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT,
                         in_signature='sss', out_signature='a(ias)')
    @dbus_handle_exceptions
    def getRules(self, ipv, table, chain, sender=None): # pylint: disable=W0613
        ipv = dbus_to_python(ipv)
        table = dbus_to_python(table)
        chain = dbus_to_python(chain)
        log.debug1("config.direct.getRules('%s', '%s', '%s')" % \
                   (ipv, table, chain))
        ret = [ ]
        for idx in self.getSettings()[1]:
            if idx[0] == ipv and idx[1] == table and idx[2] == chain:
                ret.append((idx[3], idx[4]))
        return ret

    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT,
                         in_signature='', out_signature='a(sssias)')
    @dbus_handle_exceptions
    def getAllRules(self, sender=None): # pylint: disable=W0613
        log.debug1("config.direct.getAllRules()")
        return self.getSettings()[1]

    # passthrough

    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT,
                         in_signature='sas')
    @dbus_handle_exceptions
    def addPassthrough(self, ipv, args, sender=None):
        ipv = dbus_to_python(ipv)
        args = dbus_to_python(args)
        log.debug1("config.direct.addPassthrough('%s', '%s')" % \
                   (ipv, "','".join(args)))
        self.accessCheck(sender)
        idx = (ipv, args)
        settings = list(self.getSettings())
        if idx in settings[2]:
            raise FirewallError(errors.ALREADY_ENABLED,
                                "passthrough '%s', '%s'" % (ipv, args))
        settings[2].append(idx)
        self.update(settings)


    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT,
                         in_signature='sas')
    @dbus_handle_exceptions
    def removePassthrough(self, ipv, args, sender=None):
        ipv = dbus_to_python(ipv)
        args = dbus_to_python(args)
        log.debug1("config.direct.removePassthrough('%s', '%s')" % \
                   (ipv, "','".join(args)))
        self.accessCheck(sender)
        idx = (ipv, args)
        settings = list(self.getSettings())
        if idx not in settings[2]:
            raise FirewallError(errors.NOT_ENABLED,
                                "passthrough '%s', '%s'" % (ipv, args))
        settings[2].remove(idx)
        self.update(settings)

    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT,
                         in_signature='sas', out_signature='b')
    @dbus_handle_exceptions
    def queryPassthrough(self, ipv, args, sender=None): # pylint: disable=W0613
        ipv = dbus_to_python(ipv)
        args = dbus_to_python(args)
        log.debug1("config.direct.queryPassthrough('%s', '%s')" % \
                   (ipv, "','".join(args)))
        idx = (ipv, args)
        return idx in self.getSettings()[2]

    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT,
                         in_signature='s', out_signature='aas')
    @dbus_handle_exceptions
    def getPassthroughs(self, ipv, sender=None): # pylint: disable=W0613
        ipv = dbus_to_python(ipv)
        log.debug1("config.direct.getPassthroughs('%s')" % (ipv))
        ret = [ ]
        for idx in self.getSettings()[2]:
            if idx[0] == ipv:
                ret.append(idx[1])
        return ret

    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_CONFIG_DIRECT,
                         out_signature='a(sas)')
    @dbus_handle_exceptions
    def getAllPassthroughs(self, sender=None): # pylint: disable=W0613
        log.debug1("config.direct.getAllPassthroughs()")
        return self.getSettings()[2]
