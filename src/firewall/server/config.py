#
# Copyright (C) 2010-2012 Red Hat, Inc.
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

import dbus
import dbus.service
import slip.dbus
import slip.dbus.service

from firewall.config import *
from firewall.config.dbus import *
from firewall.core.watcher import Watcher
from firewall.core.logger import log
from firewall.server.decorators import *
from firewall.server.config_icmptype import FirewallDConfigIcmpType
from firewall.server.config_service import FirewallDConfigService
from firewall.server.config_zone import FirewallDConfigZone
from firewall.core.io.zone import Zone
from firewall.core.io.service import Service
from firewall.core.io.icmptype import IcmpType
from firewall.dbus_utils import dbus_to_python
from firewall.errors import *
from firewall.dbus_utils import dbus_to_python

############################################################################
#
# class FirewallDConfig
#
############################################################################

class FirewallDConfig(slip.dbus.service.Object):
    """FirewallD main class"""

    persistent = True
    """ Make FirewallD persistent. """
    default_polkit_auth_required = PK_ACTION_CONFIG
    """ Use PK_ACTION_INFO as a default """

    @handle_exceptions
    def __init__(self, config, *args, **kwargs):
        super(FirewallDConfig, self).__init__(*args, **kwargs)
        self.config = config
        self.path = args[0]
        self._init_vars()
        self.watcher = Watcher(self.watch_updater, 5)
        self.watcher.add_watch_dir(FIREWALLD_ICMPTYPES)
        self.watcher.add_watch_dir(ETC_FIREWALLD_ICMPTYPES)
        self.watcher.add_watch_dir(FIREWALLD_SERVICES)
        self.watcher.add_watch_dir(ETC_FIREWALLD_SERVICES)
        self.watcher.add_watch_dir(FIREWALLD_ZONES)
        self.watcher.add_watch_dir(ETC_FIREWALLD_ZONES)

    @handle_exceptions
    def _init_vars(self):
        self.icmptypes = [ ]
        self.icmptype_idx = 0
        self.services = [ ]
        self.service_idx = 0
        self.zones = [ ]
        self.zone_idx = 0

        for icmptype in self.config.get_icmptypes():
            self._addIcmpType(self.config.get_icmptype(icmptype))
        for service in self.config.get_services():
            self._addService(self.config.get_service(service))
        for zone in self.config.get_zones():
            self._addZone(self.config.get_zone(zone))

    @handle_exceptions
    def __del__(self):
        pass

    @handle_exceptions
    def reload(self):
        while len(self.icmptypes) > 0:
            x = self.icmptypes.pop()
            x.unregister()
            del x
        while len(self.services) > 0:
            x = self.services.pop()
            x.unregister()
            del x
        while len(self.zones) > 0:
            x = self.zones.pop()
            x.unregister()
            del x
        self._init_vars()

    @handle_exceptions
    def watch_updater(self, name):
        if not name.endswith(".xml"):
            raise FirewallError(INVALID_FILENAME, name)

        if name.startswith(FIREWALLD_ICMPTYPES) or \
                name.startswith(ETC_FIREWALLD_ICMPTYPES):
            (what, obj) = self.config.update_icmptype_from_path(name)
            if what == "new":
                self._addIcmpType(obj)
                self.IcmpTypeAdded(obj.name)
            elif what == "remove":
                self.removeIcmpType(obj)
            elif what == "update":
                self._updateIcmpType(obj)

        if name.startswith(FIREWALLD_SERVICES) or \
                name.startswith(ETC_FIREWALLD_SERVICES):
            (what, obj) = self.config.update_service_from_path(name)
            if what == "new":
                self._addService(obj)
                self.ServiceAdded(obj.name)
            elif what == "remove":
                self.removeService(obj)
            elif what == "update":
                self._updateService(obj)

        if name.startswith(FIREWALLD_ZONES) or \
                name.startswith(ETC_FIREWALLD_ZONES):
            (what, obj) = self.config.update_zone_from_path(name)
            if what == "new":
                self._addZone(obj)
                self.ZoneAdded(obj.name)
            elif what == "remove":
                self.removeZone(obj)
            elif what == "update":
                self._updateZone(obj)

    @handle_exceptions
    def _addIcmpType(self, obj):
        # TODO: check for idx overflow
        config_icmptype = FirewallDConfigIcmpType(\
            self.config, obj, self.icmptype_idx, self.path,
            "%s/%d" % (DBUS_PATH_CONFIG_ICMPTYPE, self.icmptype_idx))
        self.icmptypes.append(config_icmptype)
        self.icmptype_idx += 1
        return config_icmptype

    @handle_exceptions
    def _updateIcmpType(self, obj):
        for icmptype in self.icmptypes:
            if icmptype.obj.name == obj.name and \
                    icmptype.obj.path == obj.path and \
                    icmptype.obj.filename == obj.filename:
                icmptype.obj = obj
                icmptype.Updated()

    @handle_exceptions
    def removeIcmpType(self, obj):
        for icmptype in self.icmptypes:
            if icmptype.obj == obj:
                icmptype.Removed()
                icmptype.unregister()
                self.icmptypes.remove(icmptype)
                del icmptype

    @handle_exceptions
    def _addService(self, obj):
        # TODO: check for idx overflow
        config_service = FirewallDConfigService(\
            self.config, obj, self.service_idx, self.path,
            "%s/%d" % (DBUS_PATH_CONFIG_SERVICE, self.service_idx))
        self.services.append(config_service)
        self.service_idx += 1
        return config_service

    @handle_exceptions
    def _updateService(self, obj):
        for service in self.services:
            if service.obj.name == obj.name and \
                    service.obj.path == obj.path and \
                    service.obj.filename == obj.filename:
                service.obj = obj
                service.Updated()

    @handle_exceptions
    def removeService(self, obj):
        for service in self.services:
            if service.obj == obj:
                service.Removed()
                service.unregister()
                self.services.remove(service)
                del service

    @handle_exceptions
    def _addZone(self, obj):
        # TODO: check for idx overflow
        config_zone = FirewallDConfigZone(\
            self.config, obj, self.zone_idx, self.path,
            "%s/%d" % (DBUS_PATH_CONFIG_ZONE, self.zone_idx))
        self.zones.append(config_zone)
        self.zone_idx += 1
        return config_zone

    @handle_exceptions
    def _updateZone(self, obj):
        for zone in self.zones:
            if zone.obj.name == obj.name and zone.obj.path == obj.path and \
                    zone.obj.filename == obj.filename:
                zone.obj = obj
                zone.Updated()

    @handle_exceptions
    def removeZone(self, obj):
        for zone in self.zones:
            if zone.obj == obj:
                zone.Removed()
                zone.unregister()
                self.zones.remove(zone)
                del zone

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    # I C M P T Y P E S

    @dbus_service_method(DBUS_INTERFACE_CONFIG, out_signature='ao')
    @dbus_handle_exceptions
    def listIcmpTypes(self, sender=None):
        """list icmptypes objects paths
        """
        log.debug1("config.listIcmpTypes()")
        return self.icmptypes

    @dbus_service_method(DBUS_INTERFACE_CONFIG, in_signature='s',
                         out_signature='o')
    @dbus_handle_exceptions
    def getIcmpTypeByName(self, icmptype, sender=None):
        """list icmptypes objects paths
        """
        log.debug1("config.getIcmpTypeByName('%s')", icmptype)
        for obj in self.icmptypes:
            if obj.obj.name == icmptype:
                return obj
        raise FirewallError(INVALID_ICMPTYPE, icmptype)

    @dbus_service_method(DBUS_INTERFACE_CONFIG,
                         in_signature='s'+IcmpType.DBUS_SIGNATURE,
                         out_signature='o')
    @dbus_handle_exceptions
    def addIcmpType(self, icmptype, settings, sender=None):
        """list icmptypes objects paths
        """
        icmptype = str(icmptype)
        log.debug1("config.addIcmpType('%s')", icmptype)
        obj = self.config.new_icmptype(icmptype, dbus_to_python(settings))
        config_icmptype = self._addIcmpType(obj)
        self.IcmpTypeAdded(icmptype)
        return config_icmptype

    @dbus.service.signal(DBUS_INTERFACE_CONFIG, signature='s')
    @dbus_handle_exceptions
    def IcmpTypeAdded(self, icmptype):
        log.debug1("config.IcmpTypeAdded('%s')" % (icmptype))

    # S E R V I C E S

    @dbus_service_method(DBUS_INTERFACE_CONFIG, out_signature='ao')
    @dbus_handle_exceptions
    def listServices(self, sender=None):
        """list services objects paths
        """
        log.debug1("config.listServices()")
        return self.services

    @dbus_service_method(DBUS_INTERFACE_CONFIG, in_signature='s',
                         out_signature='o')
    @dbus_handle_exceptions
    def getServiceByName(self, service, sender=None):
        """list services objects paths
        """
        log.debug1("config.getServiceByName('%s')", service)
        for obj in self.services:
            if obj.obj.name == service:
                return obj
        raise FirewallError(INVALID_SERVICE, service)

    @dbus_service_method(DBUS_INTERFACE_CONFIG,
                         in_signature='s'+Service.DBUS_SIGNATURE,
                         out_signature='o')
    @dbus_handle_exceptions
    def addService(self, service, settings, sender=None):
        """list services objects paths
        """
        service = str(service)
        log.debug1("config.addService('%s')", service)
        obj = self.config.new_service(service, dbus_to_python(settings))
        config_service = self._addService(obj)
        self.ServiceAdded(service)
        return config_service

    @dbus.service.signal(DBUS_INTERFACE_CONFIG, signature='s')
    @dbus_handle_exceptions
    def ServiceAdded(self, service):
        log.debug1("config.ServiceAdded('%s')" % (service))

    # Z O N E S

    @dbus_service_method(DBUS_INTERFACE_CONFIG, out_signature='ao')
    @dbus_handle_exceptions
    def listZones(self, sender=None):
        """list zones objects paths
        """
        log.debug1("config.listZones()")
        return self.zones

    @dbus_service_method(DBUS_INTERFACE_CONFIG, in_signature='s',
                         out_signature='o')
    @dbus_handle_exceptions
    def getZoneByName(self, zone, sender=None):
        """list zones objects paths
        """
        log.debug1("config.getZoneByName('%s')", zone)
        for obj in self.zones:
            if obj.obj.name == zone:
                return obj
        raise FirewallError(INVALID_ZONE, zone)

    @dbus_service_method(DBUS_INTERFACE_CONFIG,
                         in_signature='s'+Zone.DBUS_SIGNATURE,
                         out_signature='o')
    @dbus_handle_exceptions
    def addZone(self, zone, settings, sender=None):
        """list zones objects paths
        """
        zone = str(zone)
        log.debug1("config.addZone('%s')", zone)
        obj = self.config.new_zone(zone, dbus_to_python(settings))
        config_zone = self._addZone(obj)
        self.ZoneAdded(zone)
        return config_zone

    @dbus.service.signal(DBUS_INTERFACE_CONFIG, signature='s')
    @dbus_handle_exceptions
    def ZoneAdded(self, zone):
        log.debug1("config.ZoneAdded('%s')" % (zone))
