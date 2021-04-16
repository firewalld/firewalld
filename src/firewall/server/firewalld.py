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

__all__ = [ "FirewallD" ]

from gi.repository import GLib

import copy
import dbus
import dbus.service

from firewall import config
from firewall.core.fw import Firewall
from firewall.core.rich import Rich_Rule
from firewall.core.logger import log
from firewall.client import FirewallClientZoneSettings
from firewall.server.dbus import FirewallDBusException, DbusServiceObject
from firewall.server.decorators import dbus_handle_exceptions, \
                                       dbus_service_method, \
                                       handle_exceptions, \
                                       dbus_service_method_deprecated, \
                                       dbus_service_signal_deprecated, \
                                       dbus_polkit_require_auth
from firewall.server.config import FirewallDConfig
from firewall.dbus_utils import dbus_to_python, \
    command_of_sender, context_of_sender, uid_of_sender, user_of_uid, \
    dbus_introspection_prepare_properties, \
    dbus_introspection_add_properties, \
    dbus_introspection_add_deprecated
from firewall.core.io.functions import check_config
from firewall.core.io.ipset import IPSet
from firewall.core.io.icmptype import IcmpType
from firewall.core.io.helper import Helper
from firewall.core.fw_nm import nm_get_bus_name, nm_get_connection_of_interface, \
                                nm_set_zone_of_connection
from firewall.core.fw_ifcfg import ifcfg_set_zone_of_interface
from firewall import errors
from firewall.errors import FirewallError

############################################################################
#
# class FirewallD
#
############################################################################

class FirewallD(DbusServiceObject):
    """FirewallD main class"""

    persistent = True
    """ Make FirewallD persistent. """
    default_polkit_auth_required = config.dbus.PK_ACTION_CONFIG
    """ Use config.dbus.PK_ACTION_CONFIG as a default """

    @handle_exceptions
    def __init__(self, *args, **kwargs):
        super(FirewallD, self).__init__(*args, **kwargs)
        self.fw = Firewall()
        self.busname = args[0]
        self.path = args[1]
        self.start()
        dbus_introspection_prepare_properties(self, config.dbus.DBUS_INTERFACE)
        self.config = FirewallDConfig(self.fw.config, self.busname,
                                      config.dbus.DBUS_PATH_CONFIG)

    def __del__(self):
        self.stop()

    @handle_exceptions
    def start(self):
        # tests if iptables and ip6tables are usable using test functions
        # loads default firewall rules for iptables and ip6tables
        log.debug1("start()")
        self._timeouts = { }
        return self.fw.start()

    @handle_exceptions
    def stop(self):
        # stops firewall: unloads firewall modules, flushes chains and tables,
        #   resets policies
        log.debug1("stop()")
        return self.fw.stop()

    # lockdown functions

    @dbus_handle_exceptions
    def accessCheck(self, sender):
        if self.fw.policies.query_lockdown():
            if sender is None:
                log.error("Lockdown not possible, sender not set.")
                return
            bus = dbus.SystemBus()
            context = context_of_sender(bus, sender)
            if self.fw.policies.access_check("context", context):
                return
            uid = uid_of_sender(bus, sender)
            if self.fw.policies.access_check("uid", uid):
                return
            user = user_of_uid(uid)
            if self.fw.policies.access_check("user", user):
                return
            command = command_of_sender(bus, sender)
            if self.fw.policies.access_check("command", command):
                return
            raise FirewallError(errors.ACCESS_DENIED, "lockdown is enabled")

    # timeout functions

    @dbus_handle_exceptions
    def addTimeout(self, zone, x, tag):
        if zone not in self._timeouts:
            self._timeouts[zone] = { }
        self._timeouts[zone][x] = tag

    @dbus_handle_exceptions
    def removeTimeout(self, zone, x):
        if zone in self._timeouts and x in self._timeouts[zone]:
            GLib.source_remove(self._timeouts[zone][x])
            del self._timeouts[zone][x]

    @dbus_handle_exceptions
    def cleanup_timeouts(self):
        # cleanup timeouts
        for zone in self._timeouts:
            for x in self._timeouts[zone]:
                GLib.source_remove(self._timeouts[zone][x])
            self._timeouts[zone].clear()
        self._timeouts.clear()

    # property handling

    @dbus_handle_exceptions
    def _get_property(self, prop):
        if prop == "version":
            return dbus.String(config.VERSION)
        elif prop == "interface_version":
            return dbus.String("%d.%d" % (config.dbus.DBUS_INTERFACE_VERSION,
                                          config.dbus.DBUS_INTERFACE_REVISION))
        elif prop == "state":
            return dbus.String(self.fw.get_state())

        elif prop == "IPv4":
            return dbus.Boolean(self.fw.is_ipv_enabled("ipv4"))

        elif prop == "IPv4ICMPTypes":
            return dbus.Array(self.fw.ipv4_supported_icmp_types, "s")

        elif prop == "IPv6":
            return dbus.Boolean(self.fw.is_ipv_enabled("ipv6"))

        elif prop == "IPv6_rpfilter":
            return dbus.Boolean(self.fw.ipv6_rpfilter_enabled)

        elif prop == "IPv6ICMPTypes":
            return dbus.Array(self.fw.ipv6_supported_icmp_types, "s")

        elif prop == "BRIDGE":
            return dbus.Boolean(self.fw.ebtables_enabled)

        elif prop == "IPSet":
            return dbus.Boolean(self.fw.ipset_enabled)

        elif prop == "IPSetTypes":
            return dbus.Array(self.fw.ipset_supported_types, "s")

        elif prop == "nf_conntrack_helper_setting":
            return dbus.Boolean(False)

        elif prop == "nf_conntrack_helpers":
            return dbus.Dictionary({}, "sas")

        elif prop == "nf_nat_helpers":
            return dbus.Dictionary({}, "sas")

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
        log.debug1("Get('%s', '%s')", interface_name, property_name)

        if interface_name == config.dbus.DBUS_INTERFACE:
            return self._get_property(property_name)
        elif interface_name in [ config.dbus.DBUS_INTERFACE_ZONE,
                                 config.dbus.DBUS_INTERFACE_DIRECT,
                                 config.dbus.DBUS_INTERFACE_POLICIES,
                                 config.dbus.DBUS_INTERFACE_IPSET ]:
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
        log.debug1("GetAll('%s')", interface_name)

        ret = { }
        if interface_name == config.dbus.DBUS_INTERFACE:
            for x in [ "version", "interface_version", "state",
                       "IPv4", "IPv6", "IPv6_rpfilter", "BRIDGE",
                       "IPSet", "IPSetTypes", "nf_conntrack_helper_setting",
                       "nf_conntrack_helpers", "nf_nat_helpers",
                       "IPv4ICMPTypes", "IPv6ICMPTypes" ]:
                ret[x] = self._get_property(x)
        elif interface_name in [ config.dbus.DBUS_INTERFACE_ZONE,
                                 config.dbus.DBUS_INTERFACE_DIRECT,
                                 config.dbus.DBUS_INTERFACE_POLICIES,
                                 config.dbus.DBUS_INTERFACE_IPSET ]:
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
        log.debug1("Set('%s', '%s', '%s')", interface_name, property_name,
                   new_value)
        self.accessCheck(sender)

        if interface_name == config.dbus.DBUS_INTERFACE:
            if property_name in [ "version", "interface_version", "state",
                                  "IPv4", "IPv6", "IPv6_rpfilter", "BRIDGE",
                                  "IPSet", "IPSetTypes",
                                  "nf_conntrack_helper_setting",
                                  "nf_conntrack_helpers", "nf_nat_helpers",
                                  "IPv4ICMPTypes", "IPv6ICMPTypes" ]:
                raise dbus.exceptions.DBusException(
                    "org.freedesktop.DBus.Error.PropertyReadOnly: "
                    "Property '%s' is read-only" % property_name)
            else:
                raise dbus.exceptions.DBusException(
                    "org.freedesktop.DBus.Error.InvalidArgs: "
                    "Property '%s' does not exist" % property_name)
        elif interface_name in [ config.dbus.DBUS_INTERFACE_ZONE,
                                 config.dbus.DBUS_INTERFACE_DIRECT,
                                 config.dbus.DBUS_INTERFACE_POLICIES,
                                 config.dbus.DBUS_INTERFACE_IPSET ]:
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
        log.debug1("PropertiesChanged('%s', '%s', '%s')",
                   interface_name, changed_properties, invalidated_properties)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_INFO)
    @dbus_service_method(dbus.INTROSPECTABLE_IFACE, out_signature='s')
    @dbus_handle_exceptions
    def Introspect(self, sender=None): # pylint: disable=W0613
        log.debug2("Introspect()")

        data = super(FirewallD, self).Introspect(self.path,
                                                 self.busname.get_bus())

        data = dbus_introspection_add_properties(self, data,
                                                 config.dbus.DBUS_INTERFACE)

        for interface in [config.dbus.DBUS_INTERFACE_DIRECT]:
            data = dbus_introspection_add_deprecated(self, data,
                                                     interface,
                                                     dbus_service_method_deprecated().deprecated,
                                                     dbus_service_signal_deprecated().deprecated)

        return data

    # reload

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE, in_signature='',
                         out_signature='')
    @dbus_handle_exceptions
    def reload(self, sender=None): # pylint: disable=W0613
        """Reload the firewall rules.
        """
        log.debug1("reload()")

        self.fw.reload()
        self.config.reload()
        self.Reloaded()

    # complete_reload

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE, in_signature='',
                         out_signature='')
    @dbus_handle_exceptions
    def completeReload(self, sender=None): # pylint: disable=W0613
        """Completely reload the firewall.

        Completely reload the firewall: Stops firewall, unloads modules and 
        starts the firewall again.
        """
        log.debug1("completeReload()")

        self.fw.reload(True)
        self.config.reload()
        self.Reloaded()

    @dbus.service.signal(config.dbus.DBUS_INTERFACE)
    @dbus_handle_exceptions
    def Reloaded(self):
        log.debug1("Reloaded()")

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE, in_signature='',
                         out_signature='')
    @dbus_handle_exceptions
    def checkPermanentConfig(self, sender=None): # pylint: disable=W0613
        """Check permanent configuration
        """
        log.debug1("checkPermanentConfig()")
        check_config(self.fw)

    # runtime to permanent

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE, in_signature='',
                         out_signature='')
    @dbus_handle_exceptions
    def runtimeToPermanent(self, sender=None): # pylint: disable=W0613
        """Make runtime configuration permanent
        """
        log.debug1("copyRuntimeToPermanent()")

        error = False

        # Services or icmptypes can not be modified in runtime, but they can
        # be removed or modified in permanent environment. Therefore copying
        # of services and icmptypes to permanent is also needed.

        # services

        config_names = self.config.getServiceNames()
        for name in self.fw.service.get_services():
            conf = self.getServiceSettings(name)
            try:
                if name in config_names:
                    conf_obj = self.config.getServiceByName(name)
                    if conf_obj.getSettings() != conf:
                        log.debug1("Copying service '%s' settings" % name)
                        conf_obj.update(conf)
                    else:
                        log.debug1("Service '%s' is identical, ignoring." % name)
                else:
                    log.debug1("Creating service '%s'" % name)
                    self.config.addService(name, conf)
            except Exception as e:
                log.warning(
                    "Runtime To Permanent failed on service '%s': %s" % \
                    (name, e))
                error = True

        # icmptypes

        config_names = self.config.getIcmpTypeNames()
        for name in self.fw.icmptype.get_icmptypes():
            conf = self.getIcmpTypeSettings(name)
            try:
                if name in config_names:
                    conf_obj = self.config.getIcmpTypeByName(name)
                    if conf_obj.getSettings() != conf:
                        log.debug1("Copying icmptype '%s' settings" % name)
                        conf_obj.update(conf)
                    else:
                        log.debug1("IcmpType '%s' is identical, ignoring." % name)
                else:
                    log.debug1("Creating icmptype '%s'" % name)
                    self.config.addIcmpType(name, conf)
            except Exception as e:
                log.warning(
                    "Runtime To Permanent failed on icmptype '%s': %s" % \
                    (name, e))
                error = True

        # ipsets

        config_names = self.config.getIPSetNames()
        for name in self.fw.ipset.get_ipsets():
            try:
                conf = self.getIPSetSettings(name)
                if name in config_names:
                    conf_obj = self.config.getIPSetByName(name)
                    if conf_obj.getSettings() != conf:
                        log.debug1("Copying ipset '%s' settings" % name)
                        conf_obj.update(conf)
                    else:
                        log.debug1("IPSet '%s' is identical, ignoring." % name)
                else:
                    log.debug1("Creating ipset '%s'" % name)
                    self.config.addIPSet(name, conf)
            except Exception as e:
                log.warning(
                    "Runtime To Permanent failed on ipset '%s': %s" % \
                    (name, e))
                error = True

        # zones

        config_names = self.config.getZoneNames()
        nm_bus_name = nm_get_bus_name()
        for name in self.fw.zone.get_zones():
            conf = self.getZoneSettings2(name)
            settings = FirewallClientZoneSettings(conf)
            if nm_bus_name is not None:
                changed = False
                for interface in settings.getInterfaces():
                    if self.fw.zone.interface_get_sender(name, interface) == nm_bus_name:
                        log.debug1("Zone '%s': interface binding for '%s' has been added by NM, ignoring." % (name, interface))
                        settings.removeInterface(interface)
                        changed = True
                # For the remaining interfaces, attempt to let NM manage them
                for interface in settings.getInterfaces():
                    try:
                        connection = nm_get_connection_of_interface(interface)
                        if connection and nm_set_zone_of_connection(name, connection):
                            settings.removeInterface(interface)
                            changed = True
                    except Exception:
                        pass

                if changed:
                    del conf
                    conf = settings.getSettingsDict()
            # For the remaining try to update the ifcfg files
            for interface in settings.getInterfaces():
                ifcfg_set_zone_of_interface(name, interface)
            try:
                if name in config_names:
                    conf_obj = self.config.getZoneByName(name)
                    log.debug1("Copying zone '%s' settings" % name)
                    conf_obj.update2(conf)
                else:
                    log.debug1("Creating zone '%s'" % name)
                    self.config.addZone2(name, conf)
            except Exception as e:
                log.warning(
                    "Runtime To Permanent failed on zone '%s': %s" % \
                    (name, e))
                error = True

        # policies

        config_names = self.config.getPolicyNames()
        for name in self.fw.policy.get_policies_not_derived_from_zone():
            conf = self.getPolicySettings(name)
            try:
                if name in config_names:
                    conf_obj = self.config.getPolicyByName(name)
                    conf_obj.update(conf)
                else:
                    log.debug1("Creating policy '%s'" % name)
                    self.config.addPolicy(name, conf)
            except Exception as e:
                log.warning(
                    "Runtime To Permanent failed on policy '%s': %s" % \
                    (name, e))
                error = True

        # helpers

        config_names = self.config.getHelperNames()
        for name in self.fw.helper.get_helpers():
            conf = self.getHelperSettings(name)
            try:
                if name in config_names:
                    conf_obj = self.config.getHelperByName(name)
                    if conf_obj.getSettings() != conf:
                        log.debug1("Copying helper '%s' settings" % name)
                        conf_obj.update(conf)
                    else:
                        log.debug1("Helper '%s' is identical, ignoring." % name)
                else:
                    log.debug1("Creating helper '%s'" % name)
                    self.config.addHelper(name, conf)
            except Exception as e:
                log.warning(
                    "Runtime To Permanent failed on helper '%s': %s" % \
                    (name, e))
                error = True

        # direct

        # rt_config = self.fw.direct.get_config()
        conf = ( self.fw.direct.get_all_chains(),
                 self.fw.direct.get_all_rules(),
                 self.fw.direct.get_all_passthroughs() )
        try:
            if self.config.getSettings() != conf:
                log.debug1("Copying direct configuration")
                self.config.update(conf)
            else:
                log.debug1("Direct configuration is identical, ignoring.")
        except Exception as e:
            log.warning(
                "Runtime To Permanent failed on direct configuration: %s" % e)
            error = True

        # policies

        conf = self.fw.policies.lockdown_whitelist.export_config()
        try:
            if self.config.getSettings() != conf:
                log.debug1("Copying policies configuration")
                self.config.setLockdownWhitelist(conf)
            else:
                log.debug1("Policies configuration is identical, ignoring.")
        except Exception as e:
            log.warning(
                "Runtime To Permanent failed on policies configuration: %s" % \
                e)
            error = True

        if error:
            raise FirewallError(errors.RT_TO_PERM_FAILED)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # POLICIES
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # lockdown

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_POLICIES)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_POLICIES, in_signature='',
                         out_signature='')
    @dbus_handle_exceptions
    def enableLockdown(self, sender=None):
        """Enable lockdown policies
        """
        log.debug1("policies.enableLockdown()")
        self.accessCheck(sender)
        self.fw.policies.enable_lockdown()
        self.LockdownEnabled()

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_POLICIES)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_POLICIES, in_signature='',
                         out_signature='')
    @dbus_handle_exceptions
    def disableLockdown(self, sender=None):
        """Disable lockdown policies
        """
        log.debug1("policies.disableLockdown()")
        self.accessCheck(sender)
        self.fw.policies.disable_lockdown()
        self.LockdownDisabled()

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_POLICIES_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_POLICIES, in_signature='',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryLockdown(self, sender=None): # pylint: disable=W0613
        """Retuns True if lockdown is enabled
        """
        log.debug1("policies.queryLockdown()")
        # no access check here
        return self.fw.policies.query_lockdown()

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_POLICIES, signature='')
    @dbus_handle_exceptions
    def LockdownEnabled(self):
        log.debug1("LockdownEnabled()")

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_POLICIES, signature='')
    @dbus_handle_exceptions
    def LockdownDisabled(self):
        log.debug1("LockdownDisabled()")

    # lockdown whitelist

    # command

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_POLICIES)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_POLICIES, in_signature='s',
                         out_signature='')
    @dbus_handle_exceptions
    def addLockdownWhitelistCommand(self, command, sender=None):
        """Add lockdown command
        """
        command = dbus_to_python(command, str)
        log.debug1("policies.addLockdownWhitelistCommand('%s')" % command)
        self.accessCheck(sender)
        self.fw.policies.lockdown_whitelist.add_command(command)
        self.LockdownWhitelistCommandAdded(command)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_POLICIES)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_POLICIES, in_signature='s',
                         out_signature='')
    @dbus_handle_exceptions
    def removeLockdownWhitelistCommand(self, command, sender=None):
        """Remove lockdown command
        """
        command = dbus_to_python(command, str)
        log.debug1("policies.removeLockdownWhitelistCommand('%s')" % command)
        self.accessCheck(sender)
        self.fw.policies.lockdown_whitelist.remove_command(command)
        self.LockdownWhitelistCommandRemoved(command)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_POLICIES_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_POLICIES, in_signature='s',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryLockdownWhitelistCommand(self, command, sender=None): # pylint: disable=W0613
        """Query lockdown command
        """
        command = dbus_to_python(command, str)
        log.debug1("policies.queryLockdownWhitelistCommand('%s')" % command)
        # no access check here
        return self.fw.policies.lockdown_whitelist.has_command(command)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_POLICIES_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_POLICIES, in_signature='',
                         out_signature='as')
    @dbus_handle_exceptions
    def getLockdownWhitelistCommands(self, sender=None): # pylint: disable=W0613
        """Add lockdown command
        """
        log.debug1("policies.getLockdownWhitelistCommands()")
        # no access check here
        return self.fw.policies.lockdown_whitelist.get_commands()

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_POLICIES, signature='s')
    @dbus_handle_exceptions
    def LockdownWhitelistCommandAdded(self, command):
        log.debug1("LockdownWhitelistCommandAdded('%s')" % command)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_POLICIES, signature='s')
    @dbus_handle_exceptions
    def LockdownWhitelistCommandRemoved(self, command):
        log.debug1("LockdownWhitelistCommandRemoved('%s')" % command)

    # uid

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_POLICIES)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_POLICIES, in_signature='i',
                         out_signature='')
    @dbus_handle_exceptions
    def addLockdownWhitelistUid(self, uid, sender=None):
        """Add lockdown uid
        """
        uid = dbus_to_python(uid, int)
        log.debug1("policies.addLockdownWhitelistUid('%s')" % uid)
        self.accessCheck(sender)
        self.fw.policies.lockdown_whitelist.add_uid(uid)
        self.LockdownWhitelistUidAdded(uid)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_POLICIES)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_POLICIES, in_signature='i',
                         out_signature='')
    @dbus_handle_exceptions
    def removeLockdownWhitelistUid(self, uid, sender=None):
        """Remove lockdown uid
        """
        uid = dbus_to_python(uid, int)
        log.debug1("policies.removeLockdownWhitelistUid('%s')" % uid)
        self.accessCheck(sender)
        self.fw.policies.lockdown_whitelist.remove_uid(uid)
        self.LockdownWhitelistUidRemoved(uid)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_POLICIES_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_POLICIES, in_signature='i',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryLockdownWhitelistUid(self, uid, sender=None): # pylint: disable=W0613
        """Query lockdown uid
        """
        uid = dbus_to_python(uid, int)
        log.debug1("policies.queryLockdownWhitelistUid('%s')" % uid)
        # no access check here
        return self.fw.policies.lockdown_whitelist.has_uid(uid)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_POLICIES_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_POLICIES, in_signature='',
                         out_signature='ai')
    @dbus_handle_exceptions
    def getLockdownWhitelistUids(self, sender=None): # pylint: disable=W0613
        """Add lockdown uid
        """
        log.debug1("policies.getLockdownWhitelistUids()")
        # no access check here
        return self.fw.policies.lockdown_whitelist.get_uids()

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_POLICIES, signature='i')
    @dbus_handle_exceptions
    def LockdownWhitelistUidAdded(self, uid):
        log.debug1("LockdownWhitelistUidAdded(%d)" % uid)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_POLICIES, signature='i')
    @dbus_handle_exceptions
    def LockdownWhitelistUidRemoved(self, uid):
        log.debug1("LockdownWhitelistUidRemoved(%d)" % uid)

    # user

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_POLICIES)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_POLICIES, in_signature='s',
                         out_signature='')
    @dbus_handle_exceptions
    def addLockdownWhitelistUser(self, user, sender=None):
        """Add lockdown user
        """
        user = dbus_to_python(user, str)
        log.debug1("policies.addLockdownWhitelistUser('%s')" % user)
        self.accessCheck(sender)
        self.fw.policies.lockdown_whitelist.add_user(user)
        self.LockdownWhitelistUserAdded(user)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_POLICIES)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_POLICIES, in_signature='s',
                         out_signature='')
    @dbus_handle_exceptions
    def removeLockdownWhitelistUser(self, user, sender=None):
        """Remove lockdown user
        """
        user = dbus_to_python(user, str)
        log.debug1("policies.removeLockdownWhitelistUser('%s')" % user)
        self.accessCheck(sender)
        self.fw.policies.lockdown_whitelist.remove_user(user)
        self.LockdownWhitelistUserRemoved(user)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_POLICIES_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_POLICIES, in_signature='s',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryLockdownWhitelistUser(self, user, sender=None): # pylint: disable=W0613
        """Query lockdown user
        """
        user = dbus_to_python(user, str)
        log.debug1("policies.queryLockdownWhitelistUser('%s')" % user)
        # no access check here
        return self.fw.policies.lockdown_whitelist.has_user(user)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_POLICIES_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_POLICIES, in_signature='',
                         out_signature='as')
    @dbus_handle_exceptions
    def getLockdownWhitelistUsers(self, sender=None): # pylint: disable=W0613
        """Add lockdown user
        """
        log.debug1("policies.getLockdownWhitelistUsers()")
        # no access check here
        return self.fw.policies.lockdown_whitelist.get_users()

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_POLICIES, signature='s')
    @dbus_handle_exceptions
    def LockdownWhitelistUserAdded(self, user):
        log.debug1("LockdownWhitelistUserAdded('%s')" % user)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_POLICIES, signature='s')
    @dbus_handle_exceptions
    def LockdownWhitelistUserRemoved(self, user):
        log.debug1("LockdownWhitelistUserRemoved('%s')" % user)

    # context

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_POLICIES)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_POLICIES, in_signature='s',
                         out_signature='')
    @dbus_handle_exceptions
    def addLockdownWhitelistContext(self, context, sender=None):
        """Add lockdown context
        """
        context = dbus_to_python(context, str)
        log.debug1("policies.addLockdownWhitelistContext('%s')" % context)
        self.accessCheck(sender)
        self.fw.policies.lockdown_whitelist.add_context(context)
        self.LockdownWhitelistContextAdded(context)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_POLICIES)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_POLICIES, in_signature='s',
                         out_signature='')
    @dbus_handle_exceptions
    def removeLockdownWhitelistContext(self, context, sender=None):
        """Remove lockdown context
        """
        context = dbus_to_python(context, str)
        log.debug1("policies.removeLockdownWhitelistContext('%s')" % context)
        self.accessCheck(sender)
        self.fw.policies.lockdown_whitelist.remove_context(context)
        self.LockdownWhitelistContextRemoved(context)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_POLICIES_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_POLICIES, in_signature='s',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryLockdownWhitelistContext(self, context, sender=None): # pylint: disable=W0613
        """Query lockdown context
        """
        context = dbus_to_python(context, str)
        log.debug1("policies.queryLockdownWhitelistContext('%s')" % context)
        # no access check here
        return self.fw.policies.lockdown_whitelist.has_context(context)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_POLICIES_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_POLICIES, in_signature='',
                         out_signature='as')
    @dbus_handle_exceptions
    def getLockdownWhitelistContexts(self, sender=None): # pylint: disable=W0613
        """Add lockdown context
        """
        log.debug1("policies.getLockdownWhitelistContexts()")
        # no access check here
        return self.fw.policies.lockdown_whitelist.get_contexts()

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_POLICIES, signature='s')
    @dbus_handle_exceptions
    def LockdownWhitelistContextAdded(self, context):
        log.debug1("LockdownWhitelistContextAdded('%s')" % context)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_POLICIES, signature='s')
    @dbus_handle_exceptions
    def LockdownWhitelistContextRemoved(self, context):
        log.debug1("LockdownWhitelistContextRemoved('%s')" % context)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # PANIC

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE, in_signature='',
                         out_signature='')
    @dbus_handle_exceptions
    def enablePanicMode(self, sender=None):
        """Enable panic mode.
        
        All ingoing and outgoing connections and packets will be blocked.
        """
        log.debug1("enablePanicMode()")
        self.accessCheck(sender)
        self.fw.enable_panic_mode()
        self.PanicModeEnabled()

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE, in_signature='',
                         out_signature='')
    @dbus_handle_exceptions
    def disablePanicMode(self, sender=None):
        """Disable panic mode.

        Enables normal mode: Allowed ingoing and outgoing connections 
        will not be blocked anymore
        """
        log.debug1("disablePanicMode()")
        self.accessCheck(sender)
        self.fw.disable_panic_mode()
        self.PanicModeDisabled()

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE, in_signature='',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryPanicMode(self, sender=None): # pylint: disable=W0613
        # returns True if in panic mode
        log.debug1("queryPanicMode()")
        return self.fw.query_panic_mode()

    @dbus.service.signal(config.dbus.DBUS_INTERFACE, signature='')
    @dbus_handle_exceptions
    def PanicModeEnabled(self):
        log.debug1("PanicModeEnabled()")

    @dbus.service.signal(config.dbus.DBUS_INTERFACE, signature='')
    @dbus_handle_exceptions
    def PanicModeDisabled(self):
        log.debug1("PanicModeDisabled()")

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # list functions

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE, in_signature='s',
                         out_signature="(sssbsasa(ss)asba(ssss)asasasasa(ss)b)")
    @dbus_handle_exceptions
    def getZoneSettings(self, zone, sender=None): # pylint: disable=W0613
        # returns zone settings for zone
        zone = dbus_to_python(zone, str)
        log.debug1("getZoneSettings(%s)", zone)
        return self.fw.zone.get_config_with_settings(zone)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature="a{sv}")
    @dbus_handle_exceptions
    def getZoneSettings2(self, zone, sender=None):
        zone = dbus_to_python(zone, str)
        log.debug1("getZoneSettings2(%s)", zone)
        return self.fw.zone.get_config_with_settings_dict(zone)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='sa{sv}')
    @dbus_handle_exceptions
    def setZoneSettings2(self, zone, settings, sender=None):
        zone = dbus_to_python(zone, str)
        log.debug1("setZoneSettings2(%s)", zone)
        self.accessCheck(sender)
        self.fw.zone.set_config_with_settings_dict(zone, settings, sender)
        self.ZoneUpdated(zone, settings)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_ZONE, signature='sa{sv}')
    @dbus_handle_exceptions
    def ZoneUpdated(self, zone, settings):
        log.debug1("zone.ZoneUpdated('%s', '%s')" % (zone, settings))

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_POLICY, in_signature='s',
                         out_signature="a{sv}")
    @dbus_handle_exceptions
    def getPolicySettings(self, policy, sender=None):
        policy = dbus_to_python(policy, str)
        log.debug1("policy.getPolicySettings(%s)", policy)
        return self.fw.policy.get_config_with_settings_dict(policy)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_POLICY, in_signature='sa{sv}')
    @dbus_handle_exceptions
    def setPolicySettings(self, policy, settings, sender=None):
        policy = dbus_to_python(policy, str)
        log.debug1("policy.setPolicySettings(%s)", policy)
        self.accessCheck(sender)
        self.fw.policy.set_config_with_settings_dict(policy, settings, sender)
        self.PolicyUpdated(policy, settings)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_POLICY, signature='sa{sv}')
    @dbus_handle_exceptions
    def PolicyUpdated(self, policy, settings):
        log.debug1("policy.PolicyUpdated('%s', '%s')" % (policy, settings))

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE, in_signature='',
                         out_signature='as')
    @dbus_handle_exceptions
    def listServices(self, sender=None): # pylint: disable=W0613
        # returns the list of services
        # TODO: should be renamed to getServices()
        # because is called by firewall-cmd --get-services
        log.debug1("listServices()")
        return self.fw.service.get_services()

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE, in_signature='s',
                         out_signature='(sssa(ss)asa{ss}asa(ss))')
    @dbus_handle_exceptions
    def getServiceSettings(self, service, sender=None): # pylint: disable=W0613
        # returns service settings for service
        service = dbus_to_python(service, str)
        log.debug1("getServiceSettings(%s)", service)
        obj = self.fw.service.get_service(service)
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

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE, in_signature='s',
                         out_signature='a{sv}')
    @dbus_handle_exceptions
    def getServiceSettings2(self, service, sender=None): # pylint: disable=W0613
        service = dbus_to_python(service, str)
        log.debug1("getServiceSettings2(%s)", service)
        obj = self.fw.service.get_service(service)
        return obj.export_config_dict()

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE, in_signature='',
                         out_signature='as')
    @dbus_handle_exceptions
    def listIcmpTypes(self, sender=None): # pylint: disable=W0613
        # returns the list of services
        # TODO: should be renamed to getIcmptypes()
        # because is called by firewall-cmd --get-icmptypes
        log.debug1("listIcmpTypes()")
        return self.fw.icmptype.get_icmptypes()

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE, in_signature='s',
                         out_signature=IcmpType.DBUS_SIGNATURE)
    @dbus_handle_exceptions
    def getIcmpTypeSettings(self, icmptype, sender=None): # pylint: disable=W0613
        # returns icmptype settings for icmptype
        icmptype = dbus_to_python(icmptype, str)
        log.debug1("getIcmpTypeSettings(%s)", icmptype)
        return self.fw.icmptype.get_icmptype(icmptype).export_config()

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # LOG DENIED

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE, in_signature='',
                         out_signature='s')
    @dbus_handle_exceptions
    def getLogDenied(self, sender=None): # pylint: disable=W0613
        # returns the log denied value
        log.debug1("getLogDenied()")
        return self.fw.get_log_denied()

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE, in_signature='s',
                         out_signature='')
    @dbus_handle_exceptions
    def setLogDenied(self, value, sender=None):
        # set the log denied value
        value = dbus_to_python(value, str)
        log.debug1("setLogDenied('%s')" % value)
        self.accessCheck(sender)
        self.fw.set_log_denied(value)
        self.LogDeniedChanged(value)
        # must reload the firewall as well
        self.fw.reload()
        self.config.reload()
        self.Reloaded()

    @dbus.service.signal(config.dbus.DBUS_INTERFACE, signature='s')
    @dbus_handle_exceptions
    def LogDeniedChanged(self, value):
        log.debug1("LogDeniedChanged('%s')" % (value))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # AUTOMATIC HELPER ASSIGNMENT

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE, in_signature='',
                         out_signature='s')
    @dbus_handle_exceptions
    def getAutomaticHelpers(self, sender=None): # pylint: disable=W0613
        # returns the automatic helpers value
        log.debug1("getAutomaticHelpers()")
        # NOTE: This feature was removed and is now a noop. We retain the dbus
        # call to keep API.
        return "no"

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE, in_signature='s',
                         out_signature='')
    @dbus_handle_exceptions
    def setAutomaticHelpers(self, value, sender=None):
        # set the automatic helpers value
        value = dbus_to_python(value, str)
        log.debug1("setAutomaticHelpers('%s')" % value)
        self.accessCheck(sender)
        # NOTE: This feature was removed and is now a noop. We retain the dbus
        # call to keep API.

    @dbus.service.signal(config.dbus.DBUS_INTERFACE, signature='s')
    @dbus_handle_exceptions
    def AutomaticHelpersChanged(self, value):
        log.debug1("AutomaticHelpersChanged('%s')" % (value))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # DEFAULT ZONE

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE, in_signature='',
                         out_signature='s')
    @dbus_handle_exceptions
    def getDefaultZone(self, sender=None): # pylint: disable=W0613
        # returns the system default zone
        log.debug1("getDefaultZone()")
        return self.fw.get_default_zone()

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE, in_signature='s',
                         out_signature='')
    @dbus_handle_exceptions
    def setDefaultZone(self, zone, sender=None):
        # set the system default zone
        zone = dbus_to_python(zone, str)
        log.debug1("setDefaultZone('%s')" % zone)
        self.accessCheck(sender)
        self.fw.set_default_zone(zone)
        self.DefaultZoneChanged(zone)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE, signature='s')
    @dbus_handle_exceptions
    def DefaultZoneChanged(self, zone):
        log.debug1("DefaultZoneChanged('%s')" % (zone))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # POLICY INTERFACE
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # POLICIES

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_POLICY, in_signature='',
                         out_signature='as')
    @dbus_handle_exceptions
    def getPolicies(self, sender=None):
        log.debug1("policy.getPolicies()")
        return self.fw.policy.get_policies_not_derived_from_zone()

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_POLICY, in_signature='',
                         out_signature='a{sa{sas}}')
    @dbus_handle_exceptions
    def getActivePolicies(self, sender=None):
        log.debug1("policy.getActivePolicies()")
        policies = { }
        for policy in self.fw.policy.get_active_policies_not_derived_from_zone():
            policies[policy] = { }
            policies[policy]["ingress_zones"] = self.fw.policy.list_ingress_zones(policy)
            policies[policy]["egress_zones"] = self.fw.policy.list_egress_zones(policy)
        return policies

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # ZONE INTERFACE
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # ZONES

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_INFO)
    # TODO: shouldn't this be in DBUS_INTERFACE instead of DBUS_INTERFACE_ZONE ?
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='',
                         out_signature='as')
    @dbus_handle_exceptions
    def getZones(self, sender=None): # pylint: disable=W0613
        # returns the list of zones
        log.debug1("zone.getZones()")
        return self.fw.zone.get_zones()

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='',
                         out_signature='a{sa{sas}}')
    @dbus_handle_exceptions
    def getActiveZones(self, sender=None): # pylint: disable=W0613
        # returns the list of active zones
        log.debug1("zone.getActiveZones()")
        zones = { }
        for zone in self.fw.zone.get_zones():
            interfaces = self.fw.zone.list_interfaces(zone)
            sources = self.fw.zone.list_sources(zone)
            if len(interfaces) + len(sources) > 0:
                zones[zone] = { }
                if len(interfaces) > 0:
                    zones[zone]["interfaces"] = interfaces
                if len(sources) > 0:
                    zones[zone]["sources"] = sources
        return zones

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='s')
    @dbus_handle_exceptions
    def getZoneOfInterface(self, interface, sender=None): # pylint: disable=W0613
        """Return the zone an interface belongs to.

        :Parameters:
            `interface` : str
                Name of the interface
        :Returns: str. The name of the zone.
        """
        interface = dbus_to_python(interface, str)
        log.debug1("zone.getZoneOfInterface('%s')" % interface)
        zone = self.fw.zone.get_zone_of_interface(interface)
        if zone:
            return zone
        return ""

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='s')
    @dbus_handle_exceptions
    def getZoneOfSource(self, source, sender=None): # pylint: disable=W0613
        #Return the zone an source belongs to.
        source = dbus_to_python(source, str)
        log.debug1("zone.getZoneOfSource('%s')" % source)
        zone = self.fw.zone.get_zone_of_source(source)
        if zone:
            return zone
        return ""

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='b')
    @dbus_handle_exceptions
    def isImmutable(self, zone, sender=None): # pylint: disable=W0613
        # no immutable zones anymore
        return False

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # INTERFACES

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='ss',
                         out_signature='s')
    @dbus_handle_exceptions
    def addInterface(self, zone, interface, sender=None):
        """Add an interface to a zone.
        If zone is empty, use default zone.
        """
        zone = dbus_to_python(zone, str)
        interface = dbus_to_python(interface, str)
        log.debug1("zone.addInterface('%s', '%s')" % (zone, interface))
        self.accessCheck(sender)
        _zone = self.fw.zone.add_interface(zone, interface, sender)

        self.InterfaceAdded(_zone, interface)
        return _zone

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='ss',
                         out_signature='s')
    @dbus_handle_exceptions
    def changeZone(self, zone, interface, sender=None):
        """Change a zone an interface is part of.
        If zone is empty, use default zone.

        This function is deprecated, use changeZoneOfInterface instead
        """
        zone = dbus_to_python(zone, str)
        interface = dbus_to_python(interface, str)
        return self.changeZoneOfInterface(zone, interface, sender)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='ss',
                         out_signature='s')
    @dbus_handle_exceptions
    def changeZoneOfInterface(self, zone, interface, sender=None):
        """Change a zone an interface is part of.
        If zone is empty, use default zone.
        """
        zone = dbus_to_python(zone, str)
        interface = dbus_to_python(interface, str)
        log.debug1("zone.changeZoneOfInterface('%s', '%s')" % (zone, interface))
        self.accessCheck(sender)
        _zone = self.fw.zone.change_zone_of_interface(zone, interface, sender)

        self.ZoneOfInterfaceChanged(_zone, interface)
        return _zone

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='ss',
                         out_signature='s')
    @dbus_handle_exceptions
    def removeInterface(self, zone, interface, sender=None):
        """Remove interface from a zone.
        If zone is empty, remove from zone the interface belongs to.
        """
        zone = dbus_to_python(zone, str)
        interface = dbus_to_python(interface, str)
        log.debug1("zone.removeInterface('%s', '%s')" % (zone, interface))
        self.accessCheck(sender)
        _zone = self.fw.zone.remove_interface(zone, interface)

        self.InterfaceRemoved(_zone, interface)
        return _zone

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='ss',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryInterface(self, zone, interface, sender=None): # pylint: disable=W0613
        """Return true if an interface is in a zone.
        If zone is empty, use default zone.
        """
        zone = dbus_to_python(zone, str)
        interface = dbus_to_python(interface, str)
        log.debug1("zone.queryInterface('%s', '%s')" % (zone, interface))
        return self.fw.zone.query_interface(zone, interface)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='as')
    @dbus_handle_exceptions
    def getInterfaces(self, zone, sender=None): # pylint: disable=W0613
        """Return the list of interfaces of a zone.
        If zone is empty, use default zone.
        """
        # TODO: should be renamed to listInterfaces()
        # because is called by firewall-cmd --zone --list-interfaces
        zone = dbus_to_python(zone, str)
        log.debug1("zone.getInterfaces('%s')" % (zone))
        return self.fw.zone.list_interfaces(zone)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_ZONE, signature='ss')
    @dbus_handle_exceptions
    def InterfaceAdded(self, zone, interface):
        log.debug1("zone.InterfaceAdded('%s', '%s')" % (zone, interface))

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_ZONE, signature='ss')
    @dbus_handle_exceptions
    def ZoneChanged(self, zone, interface):
        """
        This signal is deprecated.
        """
        log.debug1("zone.ZoneChanged('%s', '%s')" % (zone, interface))

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_ZONE, signature='ss')
    @dbus_handle_exceptions
    def ZoneOfInterfaceChanged(self, zone, interface):
        log.debug1("zone.ZoneOfInterfaceChanged('%s', '%s')" % (zone,
                                                                interface))
        self.ZoneChanged(zone, interface)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_ZONE, signature='ss')
    @dbus_handle_exceptions
    def InterfaceRemoved(self, zone, interface):
        log.debug1("zone.InterfaceRemoved('%s', '%s')" % (zone, interface))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # SOURCES

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='ss',
                         out_signature='s')
    @dbus_handle_exceptions
    def addSource(self, zone, source, sender=None):
        """Add a source to a zone.
        If zone is empty, use default zone.
        """
        zone = dbus_to_python(zone, str)
        source = dbus_to_python(source, str)
        log.debug1("zone.addSource('%s', '%s')" % (zone, source))
        self.accessCheck(sender)
        _zone = self.fw.zone.add_source(zone, source, sender)

        self.SourceAdded(_zone, source)
        return _zone

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='ss',
                         out_signature='s')
    @dbus_handle_exceptions
    def changeZoneOfSource(self, zone, source, sender=None):
        """Change a zone an source is part of.
        If zone is empty, use default zone.
        """
        zone = dbus_to_python(zone, str)
        source = dbus_to_python(source, str)
        log.debug1("zone.changeZoneOfSource('%s', '%s')" % (zone, source))
        self.accessCheck(sender)
        _zone = self.fw.zone.change_zone_of_source(zone, source, sender)

        self.ZoneOfSourceChanged(_zone, source)
        return _zone

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='ss',
                         out_signature='s')
    @dbus_handle_exceptions
    def removeSource(self, zone, source, sender=None):
        """Remove source from a zone.
        If zone is empty, remove from zone the source belongs to.
        """
        zone = dbus_to_python(zone, str)
        source = dbus_to_python(source, str)
        log.debug1("zone.removeSource('%s', '%s')" % (zone, source))
        self.accessCheck(sender)
        _zone = self.fw.zone.remove_source(zone, source)

        self.SourceRemoved(_zone, source)
        return _zone

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='ss',
                         out_signature='b')
    @dbus_handle_exceptions
    def querySource(self, zone, source, sender=None): # pylint: disable=W0613
        """Return true if an source is in a zone.
        If zone is empty, use default zone.
        """
        zone = dbus_to_python(zone, str)
        source = dbus_to_python(source, str)
        log.debug1("zone.querySource('%s', '%s')" % (zone, source))
        return self.fw.zone.query_source(zone, source)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='as')
    @dbus_handle_exceptions
    def getSources(self, zone, sender=None): # pylint: disable=W0613
        """Return the list of sources of a zone.
        If zone is empty, use default zone.
        """
        # TODO: should be renamed to listSources()
        # because is called by firewall-cmd --zone --list-sources
        zone = dbus_to_python(zone, str)
        log.debug1("zone.getSources('%s')" % (zone))
        return self.fw.zone.list_sources(zone)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_ZONE, signature='ss')
    @dbus_handle_exceptions
    def SourceAdded(self, zone, source):
        log.debug1("zone.SourceAdded('%s', '%s')" % (zone, source))

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_ZONE, signature='ss')
    @dbus_handle_exceptions
    def ZoneOfSourceChanged(self, zone, source):
        log.debug1("zone.ZoneOfSourceChanged('%s', '%s')" % (zone, source))

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_ZONE, signature='ss')
    @dbus_handle_exceptions
    def SourceRemoved(self, zone, source):
        log.debug1("zone.SourceRemoved('%s', '%s')" % (zone, source))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # RICH RULES

    @dbus_handle_exceptions
    def disableTimedRichRule(self, zone, rule):
        log.debug1("zone.disableTimedRichRule('%s', '%s')" % (zone, rule))
        del self._timeouts[zone][rule]
        obj = Rich_Rule(rule_str=rule)
        self.fw.zone.remove_rule(zone, obj)
        self.RichRuleRemoved(zone, rule)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='ssi',
                         out_signature='s')
    @dbus_handle_exceptions
    def addRichRule(self, zone, rule, timeout, sender=None): # pylint: disable=W0613
        zone = dbus_to_python(zone, str)
        rule = dbus_to_python(rule, str)
        timeout = dbus_to_python(timeout, int)
        log.debug1("zone.addRichRule('%s', '%s')" % (zone, rule))
        obj = Rich_Rule(rule_str=rule)
        _zone = self.fw.zone.add_rule(zone, obj, timeout)

        if timeout > 0:
            tag = GLib.timeout_add_seconds(timeout, self.disableTimedRichRule,
                                           _zone, rule)
            self.addTimeout(_zone, rule, tag)

        self.RichRuleAdded(_zone, rule, timeout)
        return _zone

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='ss',
                         out_signature='s')
    @dbus_handle_exceptions
    def removeRichRule(self, zone, rule, sender=None): # pylint: disable=W0613
        zone = dbus_to_python(zone, str)
        rule = dbus_to_python(rule, str)
        log.debug1("zone.removeRichRule('%s', '%s')" % (zone, rule))
        obj = Rich_Rule(rule_str=rule)
        _zone = self.fw.zone.remove_rule(zone, obj)
        self.removeTimeout(_zone, rule)
        self.RichRuleRemoved(_zone, rule)
        return _zone

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='ss',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryRichRule(self, zone, rule, sender=None): # pylint: disable=W0613
        zone = dbus_to_python(zone, str)
        rule = dbus_to_python(rule, str)
        log.debug1("zone.queryRichRule('%s', '%s')" % (zone, rule))
        obj = Rich_Rule(rule_str=rule)
        return self.fw.zone.query_rule(zone, obj)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='as')
    @dbus_handle_exceptions
    def getRichRules(self, zone, sender=None): # pylint: disable=W0613
        # returns the list of enabled rich rules for zone
        # TODO: should be renamed to listRichRules()
        # because is called by firewall-cmd --zone --list-rich-rules
        zone = dbus_to_python(zone, str)
        log.debug1("zone.getRichRules('%s')" % (zone))
        return self.fw.zone.list_rules(zone)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_ZONE, signature='ssi')
    @dbus_handle_exceptions
    def RichRuleAdded(self, zone, rule, timeout):
        log.debug1("zone.RichRuleAdded('%s', '%s', %d)" % (zone, rule, timeout))

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_ZONE, signature='ss')
    @dbus_handle_exceptions
    def RichRuleRemoved(self, zone, rule):
        log.debug1("zone.RichRuleRemoved('%s', '%s')" % (zone, rule))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # SERVICES

    @dbus_handle_exceptions
    def disableTimedService(self, zone, service):
        log.debug1("zone.disableTimedService('%s', '%s')" % (zone, service))
        del self._timeouts[zone][service]
        self.fw.zone.remove_service(zone, service)
        self.ServiceRemoved(zone, service)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='ssi',
                         out_signature='s')
    @dbus_handle_exceptions
    def addService(self, zone, service, timeout, sender=None):
        # enables service <service> if not enabled already for zone
        zone = dbus_to_python(zone, str)
        service = dbus_to_python(service, str)
        timeout = dbus_to_python(timeout, int)
        log.debug1("zone.addService('%s', '%s', %d)" % (zone, service, timeout))
        self.accessCheck(sender)

        _zone = self.fw.zone.add_service(zone, service, timeout, sender)

        if timeout > 0:
            tag = GLib.timeout_add_seconds(timeout, self.disableTimedService,
                                           _zone, service)
            self.addTimeout(_zone, service, tag)

        self.ServiceAdded(_zone, service, timeout)
        return _zone

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='ss',
                         out_signature='s')
    @dbus_handle_exceptions
    def removeService(self, zone, service, sender=None):
        # disables service for zone
        zone = dbus_to_python(zone, str)
        service = dbus_to_python(service, str)
        log.debug1("zone.removeService('%s', '%s')" % (zone, service))
        self.accessCheck(sender)

        _zone = self.fw.zone.remove_service(zone, service)

        self.removeTimeout(_zone, service)
        self.ServiceRemoved(_zone, service)
        return _zone

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='ss',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryService(self, zone, service, sender=None): # pylint: disable=W0613
        # returns true if a service is enabled for zone
        zone = dbus_to_python(zone, str)
        service = dbus_to_python(service, str)
        log.debug1("zone.queryService('%s', '%s')" % (zone, service))
        return self.fw.zone.query_service(zone, service)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='as')
    @dbus_handle_exceptions
    def getServices(self, zone, sender=None): # pylint: disable=W0613
        # returns the list of enabled services for zone
        # TODO: should be renamed to listServices()
        # because is called by firewall-cmd --zone --list-services
        zone = dbus_to_python(zone, str)
        log.debug1("zone.getServices('%s')" % (zone))
        return self.fw.zone.list_services(zone)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_ZONE, signature='ssi')
    @dbus_handle_exceptions
    def ServiceAdded(self, zone, service, timeout):
        log.debug1("zone.ServiceAdded('%s', '%s', %d)" % \
                       (zone, service, timeout))

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_ZONE, signature='ss')
    @dbus_handle_exceptions
    def ServiceRemoved(self, zone, service):
        log.debug1("zone.ServiceRemoved('%s', '%s')" % (zone, service))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # PORTS

    @dbus_handle_exceptions
    def disableTimedPort(self, zone, port, protocol):
        log.debug1("zone.disableTimedPort('%s', '%s', '%s')" % \
                       (zone, port, protocol))
        del self._timeouts[zone][(port, protocol)]
        self.fw.zone.remove_port(zone, port, protocol)
        self.PortRemoved(zone, port, protocol)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='sssi',
                         out_signature='s')
    @dbus_handle_exceptions
    def addPort(self, zone, port, protocol, timeout, sender=None): # pylint: disable=R0913
        # adds port <port> <protocol> if not enabled already to zone
        zone = dbus_to_python(zone, str)
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        timeout = dbus_to_python(timeout, int)
        log.debug1("zone.addPort('%s', '%s', '%s')" % \
                       (zone, port, protocol))
        self.accessCheck(sender)
        _zone = self.fw.zone.add_port(zone, port, protocol, timeout, sender)

        if timeout > 0:
            tag = GLib.timeout_add_seconds(timeout, self.disableTimedPort,
                                           _zone, port, protocol)
            self.addTimeout(_zone, (port, protocol), tag)

        self.PortAdded(_zone, port, protocol, timeout)
        return _zone

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='sss',
                         out_signature='s')
    @dbus_handle_exceptions
    def removePort(self, zone, port, protocol, sender=None): # pylint: disable=R0913
        # removes port<port> <protocol> if enabled from zone
        zone = dbus_to_python(zone, str)
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        log.debug1("zone.removePort('%s', '%s', '%s')" % \
                       (zone, port, protocol))
        self.accessCheck(sender)
        _zone= self.fw.zone.remove_port(zone, port, protocol)

        self.removeTimeout(_zone, (port, protocol))
        self.PortRemoved(_zone, port, protocol)
        return _zone

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='sss',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryPort(self, zone, port, protocol, sender=None): # pylint: disable=W0613, R0913
        # returns true if a port is enabled for zone
        zone = dbus_to_python(zone, str)
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        log.debug1("zone.queryPort('%s', '%s', '%s')" % (zone, port, protocol))
        return self.fw.zone.query_port(zone, port, protocol)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='aas')
    @dbus_handle_exceptions
    def getPorts(self, zone, sender=None): # pylint: disable=W0613
        # returns the list of enabled ports
        # TODO: should be renamed to listPorts()
        # because is called by firewall-cmd --zone --list-ports
        zone = dbus_to_python(zone, str)
        log.debug1("zone.getPorts('%s')" % (zone))
        return self.fw.zone.list_ports(zone)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_ZONE, signature='sssi')
    @dbus_handle_exceptions
    def PortAdded(self, zone, port, protocol, timeout=0):
        log.debug1("zone.PortAdded('%s', '%s', '%s', %d)" % \
                       (zone, port, protocol, timeout))

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_ZONE, signature='sss')
    @dbus_handle_exceptions
    def PortRemoved(self, zone, port, protocol):
        log.debug1("zone.PortRemoved('%s', '%s', '%s')" % \
                       (zone, port, protocol))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # PROTOCOLS

    @dbus_handle_exceptions
    def disableTimedProtocol(self, zone, protocol):
        log.debug1("zone.disableTimedProtocol('%s', '%s')" % (zone, protocol))
        del self._timeouts[zone][(protocol)]
        self.fw.zone.remove_protocol(zone, protocol)
        self.ProtocolRemoved(zone, protocol)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='ssi',
                         out_signature='s')
    @dbus_handle_exceptions
    def addProtocol(self, zone, protocol, timeout, sender=None):
        # adds protocol <protocol> if not enabled already to zone
        zone = dbus_to_python(zone, str)
        protocol = dbus_to_python(protocol, str)
        timeout = dbus_to_python(timeout, int)
        log.debug1("zone.enableProtocol('%s', '%s')" % (zone, protocol))
        self.accessCheck(sender)
        _zone = self.fw.zone.add_protocol(zone, protocol, timeout, sender)

        if timeout > 0:
            tag = GLib.timeout_add_seconds(timeout, self.disableTimedProtocol,
                                           _zone, protocol)
            self.addTimeout(_zone, protocol, tag)

        self.ProtocolAdded(_zone, protocol, timeout)
        return _zone

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='ss',
                         out_signature='s')
    @dbus_handle_exceptions
    def removeProtocol(self, zone, protocol, sender=None):
        # removes protocol<protocol> if enabled from zone
        zone = dbus_to_python(zone, str)
        protocol = dbus_to_python(protocol, str)
        log.debug1("zone.removeProtocol('%s', '%s')" % (zone, protocol))
        self.accessCheck(sender)
        _zone= self.fw.zone.remove_protocol(zone, protocol)

        self.removeTimeout(_zone, protocol)
        self.ProtocolRemoved(_zone, protocol)
        return _zone

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='ss',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryProtocol(self, zone, protocol, sender=None): # pylint: disable=W0613
        # returns true if a protocol is enabled for zone
        zone = dbus_to_python(zone, str)
        protocol = dbus_to_python(protocol, str)
        log.debug1("zone.queryProtocol('%s', '%s')" % (zone, protocol))
        return self.fw.zone.query_protocol(zone, protocol)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='as')
    @dbus_handle_exceptions
    def getProtocols(self, zone, sender=None): # pylint: disable=W0613
        # returns the list of enabled protocols
        # TODO: should be renamed to listProtocols()
        # because is called by firewall-cmd --zone --list-protocols
        zone = dbus_to_python(zone, str)
        log.debug1("zone.getProtocols('%s')" % (zone))
        return self.fw.zone.list_protocols(zone)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_ZONE, signature='ssi')
    @dbus_handle_exceptions
    def ProtocolAdded(self, zone, protocol, timeout=0):
        log.debug1("zone.ProtocolAdded('%s', '%s', %d)" % \
                       (zone, protocol, timeout))

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_ZONE, signature='ss')
    @dbus_handle_exceptions
    def ProtocolRemoved(self, zone, protocol):
        log.debug1("zone.ProtocolRemoved('%s', '%s')" % (zone, protocol))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # SOURCE PORTS

    @dbus_handle_exceptions
    def disableTimedSourcePort(self, zone, port, protocol):
        log.debug1("zone.disableTimedSourcePort('%s', '%s', '%s')" % \
                   (zone, port, protocol))
        del self._timeouts[zone][("sport", port, protocol)]
        self.fw.zone.remove_source_port(zone, port, protocol)
        self.SourcePortRemoved(zone, port, protocol)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='sssi',
                         out_signature='s')
    @dbus_handle_exceptions
    def addSourcePort(self, zone, port, protocol, timeout, sender=None): # pylint: disable=R0913
        # adds source port <port> <protocol> if not enabled already to zone
        zone = dbus_to_python(zone, str)
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        timeout = dbus_to_python(timeout, int)
        log.debug1("zone.addSourcePort('%s', '%s', '%s')" % (zone, port,
                                                             protocol))
        self.accessCheck(sender)
        _zone = self.fw.zone.add_source_port(zone, port, protocol, timeout,
                                             sender)

        if timeout > 0:
            tag = GLib.timeout_add_seconds(timeout, self.disableTimedSourcePort,
                                           _zone, port, protocol)
            self.addTimeout(_zone, ("sport", port, protocol), tag)

        self.SourcePortAdded(_zone, port, protocol, timeout)
        return _zone

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='sss',
                         out_signature='s')
    @dbus_handle_exceptions
    def removeSourcePort(self, zone, port, protocol, sender=None): # pylint: disable=R0913
        # removes source port<port> <protocol> if enabled from zone
        zone = dbus_to_python(zone, str)
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        log.debug1("zone.removeSourcePort('%s', '%s', '%s')" % (zone, port,
                                                                protocol))
        self.accessCheck(sender)
        _zone= self.fw.zone.remove_source_port(zone, port, protocol)

        self.removeTimeout(_zone, ("sport", port, protocol))
        self.SourcePortRemoved(_zone, port, protocol)
        return _zone

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='sss',
                         out_signature='b')
    @dbus_handle_exceptions
    def querySourcePort(self, zone, port, protocol, sender=None): # pylint: disable=W0613, R0913
        # returns true if a source port is enabled for zone
        zone = dbus_to_python(zone, str)
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        log.debug1("zone.querySourcePort('%s', '%s', '%s')" % (zone, port,
                                                               protocol))
        return self.fw.zone.query_source_port(zone, port, protocol)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='aas')
    @dbus_handle_exceptions
    def getSourcePorts(self, zone, sender=None): # pylint: disable=W0613
        # returns the list of enabled source ports
        # TODO: should be renamed to listSourcePorts()
        # because is called by firewall-cmd --zone --list-source-ports
        zone = dbus_to_python(zone, str)
        log.debug1("zone.getSourcePorts('%s')" % (zone))
        return self.fw.zone.list_source_ports(zone)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_ZONE, signature='sssi')
    @dbus_handle_exceptions
    def SourcePortAdded(self, zone, port, protocol, timeout=0):
        log.debug1("zone.SourcePortAdded('%s', '%s', '%s', %d)" % \
                   (zone, port, protocol, timeout))

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_ZONE, signature='sss')
    @dbus_handle_exceptions
    def SourcePortRemoved(self, zone, port, protocol):
        log.debug1("zone.SourcePortRemoved('%s', '%s', '%s')" % (zone, port,
                                                                 protocol))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # MASQUERADE

    @dbus_handle_exceptions
    def disableTimedMasquerade(self, zone):
        del self._timeouts[zone]["masquerade"]
        self.fw.zone.remove_masquerade(zone)
        self.MasqueradeRemoved(zone)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='si',
                         out_signature='s')
    @dbus_handle_exceptions
    def addMasquerade(self, zone, timeout, sender=None):
        # adds masquerade if not added already
        zone = dbus_to_python(zone, str)
        timeout = dbus_to_python(timeout, int)
        log.debug1("zone.addMasquerade('%s')" % (zone))
        self.accessCheck(sender)
        _zone = self.fw.zone.add_masquerade(zone, timeout, sender)
        
        if timeout > 0:
            tag = GLib.timeout_add_seconds(timeout, self.disableTimedMasquerade,
                                           _zone)
            self.addTimeout(_zone, "masquerade", tag)

        self.MasqueradeAdded(_zone, timeout)
        return _zone

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='s')
    @dbus_handle_exceptions
    def removeMasquerade(self, zone, sender=None):
        # removes masquerade
        zone = dbus_to_python(zone, str)
        log.debug1("zone.removeMasquerade('%s')" % (zone))
        self.accessCheck(sender)
        _zone = self.fw.zone.remove_masquerade(zone)

        self.removeTimeout(_zone, "masquerade")
        self.MasqueradeRemoved(_zone)
        return _zone

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryMasquerade(self, zone, sender=None): # pylint: disable=W0613
        # returns true if a masquerade is added
        zone = dbus_to_python(zone, str)
        log.debug1("zone.queryMasquerade('%s')" % (zone))
        return self.fw.zone.query_masquerade(zone)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_ZONE, signature='si')
    @dbus_handle_exceptions
    def MasqueradeAdded(self, zone, timeout=0):
        log.debug1("zone.MasqueradeAdded('%s', %d)" % (zone, timeout))

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_ZONE, signature='s')
    @dbus_handle_exceptions
    def MasqueradeRemoved(self, zone):
        log.debug1("zone.MasqueradeRemoved('%s')" % (zone))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # FORWARD PORT

    @dbus_handle_exceptions
    def disable_forward_port(self, zone, port, protocol, toport, toaddr): # pylint: disable=R0913
        del self._timeouts[zone][(port, protocol, toport, toaddr)]
        self.fw.zone.remove_forward_port(zone, port, protocol, toport, toaddr)
        self.ForwardPortRemoved(zone, port, protocol, toport, toaddr)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='sssssi',
                         out_signature='s')
    @dbus_handle_exceptions
    def addForwardPort(self, zone, port, protocol, toport, toaddr, timeout,
                       sender=None): # pylint: disable=R0913
        # add forward port if not enabled already for zone
        zone = dbus_to_python(zone, str)
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        toport = dbus_to_python(toport, str)
        toaddr = dbus_to_python(toaddr, str)
        timeout = dbus_to_python(timeout, int)
        log.debug1("zone.addForwardPort('%s', '%s', '%s', '%s', '%s')" % \
                       (zone, port, protocol, toport, toaddr))
        self.accessCheck(sender)
        _zone = self.fw.zone.add_forward_port(zone, port, protocol, toport,
                                              toaddr, timeout, sender)

        if timeout > 0:
            tag = GLib.timeout_add_seconds(timeout,
                                           self.disable_forward_port,
                                           _zone, port, protocol, toport,
                                           toaddr)
            self.addTimeout(_zone, (port, protocol, toport, toaddr), tag)

        self.ForwardPortAdded(_zone, port, protocol, toport, toaddr, timeout)
        return _zone

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='sssss',
                         out_signature='s')
    @dbus_handle_exceptions
    def removeForwardPort(self, zone, port, protocol, toport, toaddr,
                          sender=None): # pylint: disable=R0913
        # remove forward port from zone
        zone = dbus_to_python(zone, str)
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        toport = dbus_to_python(toport, str)
        toaddr = dbus_to_python(toaddr, str)
        log.debug1("zone.removeForwardPort('%s', '%s', '%s', '%s', '%s')" % \
                       (zone, port, protocol, toport, toaddr))
        self.accessCheck(sender)
        _zone = self.fw.zone.remove_forward_port(zone, port, protocol, toport,
                                                 toaddr)

        self.removeTimeout(_zone, (port, protocol, toport, toaddr))
        self.ForwardPortRemoved(_zone, port, protocol, toport, toaddr)
        return _zone

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='sssss',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryForwardPort(self, zone, port, protocol, toport, toaddr,
                         sender=None): # pylint: disable=W0613, R0913
        # returns true if a forward port is enabled for zone
        zone = dbus_to_python(zone, str)
        port = dbus_to_python(port, str)
        protocol = dbus_to_python(protocol, str)
        toport = dbus_to_python(toport, str)
        toaddr = dbus_to_python(toaddr, str)
        log.debug1("zone.queryForwardPort('%s', '%s', '%s', '%s', '%s')" % \
                       (zone, port, protocol, toport, toaddr))
        return self.fw.zone.query_forward_port(zone, port, protocol, toport,
                                               toaddr)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='aas')
    @dbus_handle_exceptions
    def getForwardPorts(self, zone, sender=None): # pylint: disable=W0613
        # returns the list of enabled ports for zone
        # TODO: should be renamed to listForwardPorts()
        # because is called by firewall-cmd --zone --list-forward-ports
        zone = dbus_to_python(zone, str)
        log.debug1("zone.getForwardPorts('%s')" % (zone))
        return self.fw.zone.list_forward_ports(zone)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_ZONE, signature='sssssi')
    @dbus_handle_exceptions
    def ForwardPortAdded(self, zone, port, protocol, toport, toaddr,
                         timeout=0): # pylint: disable=R0913
        log.debug1("zone.ForwardPortAdded('%s', '%s', '%s', '%s', '%s', %d)" % \
                       (zone, port, protocol, toport, toaddr, timeout))

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_ZONE, signature='sssss')
    @dbus_handle_exceptions
    def ForwardPortRemoved(self, zone, port, protocol, toport, toaddr): # pylint: disable=R0913
        log.debug1("zone.ForwardPortRemoved('%s', '%s', '%s', '%s', '%s')" % \
                       (zone, port, protocol, toport, toaddr))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # ICMP BLOCK

    @dbus_handle_exceptions
    def disableTimedIcmpBlock(self, zone, icmp, sender): # pylint: disable=W0613
        log.debug1("zone.disableTimedIcmpBlock('%s', '%s')" % (zone, icmp))
        del self._timeouts[zone][icmp]
        self.fw.zone.remove_icmp_block(zone, icmp)
        self.IcmpBlockRemoved(zone, icmp)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='ssi',
                         out_signature='s')
    @dbus_handle_exceptions
    def addIcmpBlock(self, zone, icmp, timeout, sender=None):
        # add icmpblock <icmp> if not enabled already for zone
        zone = dbus_to_python(zone, str)
        icmp = dbus_to_python(icmp, str)
        timeout = dbus_to_python(timeout, int)
        log.debug1("zone.enableIcmpBlock('%s', '%s')" % (zone, icmp))
        self.accessCheck(sender)
        _zone = self.fw.zone.add_icmp_block(zone, icmp, timeout, sender)

        if timeout > 0:
            tag = GLib.timeout_add_seconds(timeout, self.disableTimedIcmpBlock,
                                           _zone, icmp, sender)
            self.addTimeout(_zone, icmp, tag)

        self.IcmpBlockAdded(_zone, icmp, timeout)
        return _zone

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='ss',
                         out_signature='s')
    @dbus_handle_exceptions
    def removeIcmpBlock(self, zone, icmp, sender=None):
        # removes icmpBlock from zone
        zone = dbus_to_python(zone, str)
        icmp = dbus_to_python(icmp, str)
        log.debug1("zone.removeIcmpBlock('%s', '%s')" % (zone, icmp))
        self.accessCheck(sender)
        _zone = self.fw.zone.remove_icmp_block(zone, icmp)

        self.removeTimeout(_zone, icmp)
        self.IcmpBlockRemoved(_zone, icmp)
        return _zone

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='ss',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryIcmpBlock(self, zone, icmp, sender=None): # pylint: disable=W0613
        # returns true if a icmp is enabled for zone
        zone = dbus_to_python(zone, str)
        icmp = dbus_to_python(icmp, str)
        log.debug1("zone.queryIcmpBlock('%s', '%s')" % (zone, icmp))
        return self.fw.zone.query_icmp_block(zone, icmp)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='as')
    @dbus_handle_exceptions
    def getIcmpBlocks(self, zone, sender=None): # pylint: disable=W0613
        # returns the list of enabled icmpblocks
        # TODO: should be renamed to listIcmpBlocks()
        # because is called by firewall-cmd --zone --list-icmp-blocks
        zone = dbus_to_python(zone, str)
        log.debug1("zone.getIcmpBlocks('%s')" % (zone))
        return self.fw.zone.list_icmp_blocks(zone)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_ZONE, signature='ssi')
    @dbus_handle_exceptions
    def IcmpBlockAdded(self, zone, icmp, timeout=0):
        log.debug1("zone.IcmpBlockAdded('%s', '%s', %d)" % \
                       (zone, icmp, timeout))

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_ZONE, signature='ss')
    @dbus_handle_exceptions
    def IcmpBlockRemoved(self, zone, icmp):
        log.debug1("zone.IcmpBlockRemoved('%s', '%s')" % (zone, icmp))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # ICMP BLOCK INVERSION

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='s')
    @dbus_handle_exceptions
    def addIcmpBlockInversion(self, zone, sender=None):
        # adds icmpBlockInversion if not added already
        zone = dbus_to_python(zone, str)
        log.debug1("zone.addIcmpBlockInversion('%s')" % (zone))
        self.accessCheck(sender)
        _zone = self.fw.zone.add_icmp_block_inversion(zone, sender)
        
        self.IcmpBlockInversionAdded(_zone)
        return _zone

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='s')
    @dbus_handle_exceptions
    def removeIcmpBlockInversion(self, zone, sender=None):
        # removes icmpBlockInversion
        zone = dbus_to_python(zone, str)
        log.debug1("zone.removeIcmpBlockInversion('%s')" % (zone))
        self.accessCheck(sender)
        _zone = self.fw.zone.remove_icmp_block_inversion(zone)

        self.IcmpBlockInversionRemoved(_zone)
        return _zone

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_ZONE, in_signature='s',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryIcmpBlockInversion(self, zone, sender=None): # pylint: disable=W0613
        # returns true if a icmpBlockInversion is added
        zone = dbus_to_python(zone, str)
        log.debug1("zone.queryIcmpBlockInversion('%s')" % (zone))
        return self.fw.zone.query_icmp_block_inversion(zone)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_ZONE, signature='s')
    @dbus_handle_exceptions
    def IcmpBlockInversionAdded(self, zone):
        log.debug1("zone.IcmpBlockInversionAdded('%s')" % (zone))

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_ZONE, signature='s')
    @dbus_handle_exceptions
    def IcmpBlockInversionRemoved(self, zone):
        log.debug1("zone.IcmpBlockInversionRemoved('%s')" % (zone))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # DIRECT INTERFACE
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # DIRECT CHAIN

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_DIRECT)
    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_DIRECT, in_signature='sss',
                         out_signature='')
    @dbus_handle_exceptions
    def addChain(self, ipv, table, chain, sender=None):
        # inserts direct chain
        ipv = dbus_to_python(ipv, str)
        table = dbus_to_python(table, str)
        chain = dbus_to_python(chain, str)
        log.debug1("direct.addChain('%s', '%s', '%s')" % (ipv, table, chain))
        self.accessCheck(sender)
        self.fw.direct.add_chain(ipv, table, chain)
        self.ChainAdded(ipv, table, chain)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_DIRECT)
    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_DIRECT, in_signature='sss',
                         out_signature='')
    @dbus_handle_exceptions
    def removeChain(self, ipv, table, chain, sender=None):
        # removes direct chain
        ipv = dbus_to_python(ipv, str)
        table = dbus_to_python(table, str)
        chain = dbus_to_python(chain, str)
        log.debug1("direct.removeChain('%s', '%s', '%s')" % (ipv, table, chain))
        self.accessCheck(sender)
        self.fw.direct.remove_chain(ipv, table, chain)
        self.ChainRemoved(ipv, table, chain)
    
    @dbus_polkit_require_auth(config.dbus.PK_ACTION_DIRECT_INFO)
    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_DIRECT, in_signature='sss',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryChain(self, ipv, table, chain, sender=None): # pylint: disable=W0613
        # returns true if a chain is enabled
        ipv = dbus_to_python(ipv, str)
        table = dbus_to_python(table, str)
        chain = dbus_to_python(chain, str)
        log.debug1("direct.queryChain('%s', '%s', '%s')" % (ipv, table, chain))
        return self.fw.direct.query_chain(ipv, table, chain)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_DIRECT_INFO)
    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_DIRECT, in_signature='ss',
                         out_signature='as')
    @dbus_handle_exceptions
    def getChains(self, ipv, table, sender=None): # pylint: disable=W0613
        # returns list of added chains
        ipv = dbus_to_python(ipv, str)
        table = dbus_to_python(table, str)
        log.debug1("direct.getChains('%s', '%s')" % (ipv, table))
        return self.fw.direct.get_chains(ipv, table)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_DIRECT_INFO)
    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_DIRECT, in_signature='',
                         out_signature='a(sss)')
    @dbus_handle_exceptions
    def getAllChains(self, sender=None): # pylint: disable=W0613
        # returns list of added chains
        log.debug1("direct.getAllChains()")
        return self.fw.direct.get_all_chains()

    @dbus_service_signal_deprecated(config.dbus.DBUS_INTERFACE_DIRECT)
    @dbus.service.signal(config.dbus.DBUS_INTERFACE_DIRECT, signature='sss')
    @dbus_handle_exceptions
    def ChainAdded(self, ipv, table, chain):
        log.debug1("direct.ChainAdded('%s', '%s', '%s')" % (ipv, table, chain))

    @dbus_service_signal_deprecated(config.dbus.DBUS_INTERFACE_DIRECT)
    @dbus.service.signal(config.dbus.DBUS_INTERFACE_DIRECT, signature='sss')
    @dbus_handle_exceptions
    def ChainRemoved(self, ipv, table, chain):
        log.debug1("direct.ChainRemoved('%s', '%s', '%s')" % (ipv, table,
                                                              chain))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # DIRECT RULE

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_DIRECT)
    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_DIRECT,
                         in_signature='sssias', out_signature='')
    @dbus_handle_exceptions
    def addRule(self, ipv, table, chain, priority, args, sender=None): # pylint: disable=R0913
        # inserts direct rule
        ipv = dbus_to_python(ipv, str)
        table = dbus_to_python(table, str)
        chain = dbus_to_python(chain, str)
        priority = dbus_to_python(priority, int)
        args = tuple( dbus_to_python(i, str) for i in args )
        log.debug1("direct.addRule('%s', '%s', '%s', %d, '%s')" % \
                       (ipv, table, chain, priority, "','".join(args)))
        self.accessCheck(sender)
        self.fw.direct.add_rule(ipv, table, chain, priority, args)
        self.RuleAdded(ipv, table, chain, priority, args)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_DIRECT)
    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_DIRECT,
                         in_signature='sssias', out_signature='')
    @dbus_handle_exceptions
    def removeRule(self, ipv, table, chain, priority, args, sender=None): # pylint: disable=R0913
        # removes direct rule
        ipv = dbus_to_python(ipv, str)
        table = dbus_to_python(table, str)
        chain = dbus_to_python(chain, str)
        priority = dbus_to_python(priority, int)
        args = tuple( dbus_to_python(i, str) for i in args )
        log.debug1("direct.removeRule('%s', '%s', '%s', %d, '%s')" % \
                       (ipv, table, chain, priority, "','".join(args)))
        self.accessCheck(sender)
        self.fw.direct.remove_rule(ipv, table, chain, priority, args)
        self.RuleRemoved(ipv, table, chain, priority, args)
    
    @dbus_polkit_require_auth(config.dbus.PK_ACTION_DIRECT)
    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_DIRECT, in_signature='sss',
                         out_signature='')
    @dbus_handle_exceptions
    def removeRules(self, ipv, table, chain, sender=None):
        # removes direct rule
        ipv = dbus_to_python(ipv, str)
        table = dbus_to_python(table, str)
        chain = dbus_to_python(chain, str)
        log.debug1("direct.removeRules('%s', '%s', '%s')" % (ipv, table, chain))
        self.accessCheck(sender)
        for (priority, args) in self.fw.direct.get_rules(ipv, table, chain):
            self.fw.direct.remove_rule(ipv, table, chain, priority, args)
            self.RuleRemoved(ipv, table, chain, priority, args)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_DIRECT_INFO)
    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_DIRECT,
                         in_signature='sssias', out_signature='b')
    @dbus_handle_exceptions
    def queryRule(self, ipv, table, chain, priority, args, sender=None): # pylint: disable=W0613, R0913
        # returns true if a rule is enabled
        ipv = dbus_to_python(ipv, str)
        table = dbus_to_python(table, str)
        chain = dbus_to_python(chain, str)
        priority = dbus_to_python(priority, int)
        args = tuple( dbus_to_python(i, str) for i in args )
        log.debug1("direct.queryRule('%s', '%s', '%s', %d, '%s')" % \
                       (ipv, table, chain, priority, "','".join(args)))
        return self.fw.direct.query_rule(ipv, table, chain, priority, args)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_DIRECT_INFO)
    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_DIRECT, in_signature='sss',
                         out_signature='a(ias)')
    @dbus_handle_exceptions
    def getRules(self, ipv, table, chain, sender=None): # pylint: disable=W0613
        # returns list of added rules
        ipv = dbus_to_python(ipv, str)
        table = dbus_to_python(table, str)
        chain = dbus_to_python(chain, str)
        log.debug1("direct.getRules('%s', '%s', '%s')" % (ipv, table, chain))
        return self.fw.direct.get_rules(ipv, table, chain)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_DIRECT_INFO)
    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_DIRECT, in_signature='',
                         out_signature='a(sssias)')
    @dbus_handle_exceptions
    def getAllRules(self, sender=None): # pylint: disable=W0613
        # returns list of added rules
        log.debug1("direct.getAllRules()")
        return self.fw.direct.get_all_rules()

    @dbus_service_signal_deprecated(config.dbus.DBUS_INTERFACE_DIRECT)
    @dbus.service.signal(config.dbus.DBUS_INTERFACE_DIRECT, signature='sssias')
    @dbus_handle_exceptions
    def RuleAdded(self, ipv, table, chain, priority, args): # pylint: disable=R0913
        log.debug1("direct.RuleAdded('%s', '%s', '%s', %d, '%s')" % \
                       (ipv, table, chain, priority, "','".join(args)))

    @dbus_service_signal_deprecated(config.dbus.DBUS_INTERFACE_DIRECT)
    @dbus.service.signal(config.dbus.DBUS_INTERFACE_DIRECT, signature='sssias')
    @dbus_handle_exceptions
    def RuleRemoved(self, ipv, table, chain, priority, args): # pylint: disable=R0913
        log.debug1("direct.RuleRemoved('%s', '%s', '%s', %d, '%s')" % \
                       (ipv, table, chain, priority, "','".join(args)))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # DIRECT PASSTHROUGH (untracked)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_DIRECT)
    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_DIRECT, in_signature='sas',
                         out_signature='s')
    @dbus_handle_exceptions
    def passthrough(self, ipv, args, sender=None):
        # inserts direct rule
        ipv = dbus_to_python(ipv, str)
        args = tuple( dbus_to_python(i, str) for i in args )
        log.debug1("direct.passthrough('%s', '%s')" % (ipv, "','".join(args)))
        self.accessCheck(sender)
        try:
            return self.fw.direct.passthrough(ipv, args)
        except FirewallError as error:
            if ipv in ["ipv4", "ipv6"]:
                query_args = set(["-C", "--check",
                                  "-L", "--list"])
            else:
                query_args = set(["-L", "--list"])
            msg = str(error)
            if error.code == errors.COMMAND_FAILED:
                if len(set(args) & query_args) <= 0:
                    log.warning(msg)
                raise FirewallDBusException(msg)
            raise

    # DIRECT PASSTHROUGH (tracked)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_DIRECT)
    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_DIRECT, in_signature='sas',
                         out_signature='')
    @dbus_handle_exceptions
    def addPassthrough(self, ipv, args, sender=None):
        # inserts direct passthrough
        ipv = dbus_to_python(ipv)
        args = tuple( dbus_to_python(i) for i in args )
        log.debug1("direct.addPassthrough('%s', '%s')" % \
                   (ipv, "','".join(args)))
        self.accessCheck(sender)
        self.fw.direct.add_passthrough(ipv, args)
        self.PassthroughAdded(ipv, args)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_DIRECT)
    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_DIRECT, in_signature='sas',
                         out_signature='')
    @dbus_handle_exceptions
    def removePassthrough(self, ipv, args, sender=None):
        # removes direct passthrough
        ipv = dbus_to_python(ipv)
        args = tuple( dbus_to_python(i) for i in args )
        log.debug1("direct.removePassthrough('%s', '%s')" % \
                       (ipv, "','".join(args)))
        self.accessCheck(sender)
        self.fw.direct.remove_passthrough(ipv, args)
        self.PassthroughRemoved(ipv, args)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_DIRECT_INFO)
    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_DIRECT, in_signature='sas',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryPassthrough(self, ipv, args, sender=None): # pylint: disable=W0613
        # returns true if a passthrough is enabled
        ipv = dbus_to_python(ipv)
        args = tuple( dbus_to_python(i) for i in args )
        log.debug1("direct.queryPassthrough('%s', '%s')" % \
                       (ipv, "','".join(args)))
        return self.fw.direct.query_passthrough(ipv, args)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_DIRECT_INFO)
    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_DIRECT, in_signature='',
                         out_signature='a(sas)')
    @dbus_handle_exceptions
    def getAllPassthroughs(self, sender=None): # pylint: disable=W0613
        # returns list of all added passthroughs
        log.debug1("direct.getAllPassthroughs()")
        return self.fw.direct.get_all_passthroughs()

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_DIRECT)
    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_DIRECT, in_signature='',
                         out_signature='')
    @dbus_handle_exceptions
    def removeAllPassthroughs(self, sender=None): # pylint: disable=W0613
        # remove all passhroughs
        log.debug1("direct.removeAllPassthroughs()")
        # remove in reverse order to avoid removing non-empty chains
        for passthrough in reversed(self.getAllPassthroughs()):
            self.removePassthrough(*passthrough)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_DIRECT_INFO)
    @dbus_service_method_deprecated(config.dbus.DBUS_INTERFACE_DIRECT)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_DIRECT, in_signature='s',
                         out_signature='aas')
    @dbus_handle_exceptions
    def getPassthroughs(self, ipv, sender=None): # pylint: disable=W0613
        # returns list of all added passthroughs with ipv
        ipv = dbus_to_python(ipv)
        log.debug1("direct.getPassthroughs('%s')", ipv)
        return self.fw.direct.get_passthroughs(ipv)

    @dbus_service_signal_deprecated(config.dbus.DBUS_INTERFACE_DIRECT)
    @dbus.service.signal(config.dbus.DBUS_INTERFACE_DIRECT, signature='sas')
    @dbus_handle_exceptions
    def PassthroughAdded(self, ipv, args):
        log.debug1("direct.PassthroughAdded('%s', '%s')" % \
                       (ipv, "','".join(args)))

    @dbus_service_signal_deprecated(config.dbus.DBUS_INTERFACE_DIRECT)
    @dbus.service.signal(config.dbus.DBUS_INTERFACE_DIRECT, signature='sas')
    @dbus_handle_exceptions
    def PassthroughRemoved(self, ipv, args):
        log.debug1("direct.PassthroughRemoved('%s', '%s')" % \
                       (ipv, "','".join(args)))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_ALL)
    @dbus_service_method(config.dbus.DBUS_INTERFACE, in_signature='',
                         out_signature='')
    @dbus_handle_exceptions
    def authorizeAll(self, sender=None): # pylint: disable=W0613
        """ PK_ACTION_ALL implies all other actions, i.e. once a subject is
            authorized for PK_ACTION_ALL it's also authorized for any other action.
            Use-case is GUI (RHBZ#994729).
        """
        pass

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # IPSETS
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_IPSET, in_signature='s',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryIPSet(self, ipset, sender=None): # pylint: disable=W0613
        # returns true if a set with the name exists
        ipset = dbus_to_python(ipset)
        log.debug1("ipset.queryIPSet('%s')" % (ipset))
        return self.fw.ipset.query_ipset(ipset)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_IPSET, in_signature='',
                         out_signature='as')
    @dbus_handle_exceptions
    def getIPSets(self, sender=None): # pylint: disable=W0613
        # returns list of added sets
        log.debug1("ipsets.getIPSets()")
        return self.fw.ipset.get_ipsets()

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_IPSET, in_signature='s',
                         out_signature=IPSet.DBUS_SIGNATURE)
    @dbus_handle_exceptions
    def getIPSetSettings(self, ipset, sender=None): # pylint: disable=W0613
        # returns ipset settings for ipset
        ipset = dbus_to_python(ipset, str)
        log.debug1("getIPSetSettings(%s)", ipset)
        return self.fw.ipset.get_ipset(ipset).export_config()

    # set entries # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_IPSET, in_signature='ss',
                         out_signature='')
    @dbus_handle_exceptions
    def addEntry(self, ipset, entry, sender=None):
        # adds ipset entry
        ipset = dbus_to_python(ipset)
        entry = dbus_to_python(entry)
        log.debug1("ipset.addEntry('%s', '%s')" % (ipset, entry))
        self.accessCheck(sender)
        self.fw.ipset.add_entry(ipset, entry)
        self.EntryAdded(ipset, entry)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_IPSET, in_signature='ss',
                         out_signature='')
    @dbus_handle_exceptions
    def removeEntry(self, ipset, entry, sender=None):
        # removes ipset entry
        ipset = dbus_to_python(ipset)
        entry = dbus_to_python(entry)
        log.debug1("ipset.removeEntry('%s', '%s')" % (ipset, entry))
        self.accessCheck(sender)
        self.fw.ipset.remove_entry(ipset, entry)
        self.EntryRemoved(ipset, entry)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_IPSET, in_signature='ss',
                         out_signature='b')
    @dbus_handle_exceptions
    def queryEntry(self, ipset, entry, sender=None): # pylint: disable=W0613
        # returns true if the entry exists in the ipset
        ipset = dbus_to_python(ipset)
        entry = dbus_to_python(entry)
        log.debug1("ipset.queryEntry('%s', '%s')" % (ipset, entry))
        return self.fw.ipset.query_entry(ipset, entry)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_IPSET, in_signature='s',
                         out_signature='as')
    @dbus_handle_exceptions
    def getEntries(self, ipset, sender=None): # pylint: disable=W0613
        # returns list of added entries for the ipset
        ipset = dbus_to_python(ipset)
        log.debug1("ipset.getEntries('%s')" % ipset)
        return self.fw.ipset.get_entries(ipset)

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG)
    @dbus_service_method(config.dbus.DBUS_INTERFACE_IPSET, in_signature='sas')
    @dbus_handle_exceptions
    def setEntries(self, ipset, entries, sender=None): # pylint: disable=W0613
        # returns list of added entries for the ipset
        ipset = dbus_to_python(ipset)
        entries = dbus_to_python(entries, list)
        log.debug1("ipset.setEntries('%s', '[%s]')", ipset, ",".join(entries))
        old_entries = self.fw.ipset.get_entries(ipset)
        self.fw.ipset.set_entries(ipset, entries)
        old_entries_set = set(old_entries)
        entries_set = set(entries)
        for entry in entries_set - old_entries_set:
            self.EntryAdded(ipset, entry)
        for entry in old_entries_set - entries_set:
            self.EntryRemoved(ipset, entry)

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_IPSET, signature='ss')
    @dbus_handle_exceptions
    def EntryAdded(self, ipset, entry):
        ipset = dbus_to_python(ipset)
        entry = dbus_to_python(entry)
        log.debug1("ipset.EntryAdded('%s', '%s')" % (ipset, entry))

    @dbus.service.signal(config.dbus.DBUS_INTERFACE_IPSET, signature='ss')
    @dbus_handle_exceptions
    def EntryRemoved(self, ipset, entry):
        ipset = dbus_to_python(ipset)
        entry = dbus_to_python(entry)
        log.debug1("ipset.EntryRemoved('%s', '%s')" % (ipset, entry))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # HELPERS
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE, in_signature='',
                         out_signature='as')
    @dbus_handle_exceptions
    def getHelpers(self, sender=None): # pylint: disable=W0613
        # returns list of added sets
        log.debug1("helpers.getHelpers()")
        return self.fw.helper.get_helpers()

    @dbus_polkit_require_auth(config.dbus.PK_ACTION_CONFIG_INFO)
    @dbus_service_method(config.dbus.DBUS_INTERFACE, in_signature='s',
                         out_signature=Helper.DBUS_SIGNATURE)
    @dbus_handle_exceptions
    def getHelperSettings(self, helper, sender=None): # pylint: disable=W0613
        # returns helper settings for helper
        helper = dbus_to_python(helper, str)
        log.debug1("getHelperSettings(%s)", helper)
        return self.fw.helper.get_helper(helper).export_config()

