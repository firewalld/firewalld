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

import time
from firewall.core.base import SHORTCUTS, DEFAULT_ZONE_TARGET, \
    ZONE_SOURCE_IPSET_TYPES
from firewall.core.logger import log
from firewall.functions import portStr, checkIPnMask, checkIP6nMask, \
    checkProtocol, enable_ip_forwarding, check_single_address, check_mac
from firewall.core.rich import Rich_Rule, Rich_Accept, Rich_Reject, \
    Rich_Drop, Rich_Mark, Rich_Service, Rich_Port, Rich_Protocol, \
    Rich_Masquerade, Rich_ForwardPort, Rich_SourcePort, Rich_IcmpBlock, \
    Rich_IcmpType
from firewall.core.ipXtables import OUR_CHAINS
from firewall.core.fw_transaction import FirewallTransaction, \
    FirewallZoneTransaction
from firewall.core.fw_ifcfg import ifcfg_set_zone_of_interface
from firewall import errors
from firewall.errors import FirewallError
from firewall.fw_types import LastUpdatedOrderedDict

class FirewallZone(object):
    def __init__(self, fw):
        self._fw = fw
        self._chains = { }
        self._zones = { }

        ip4tables_tables = self._fw.get_available_tables("ipv4")
        ip6tables_tables = self._fw.get_available_tables("ipv6")

        mangle = []
        if "mangle" in ip4tables_tables:
            mangle.append("ipv4")
        if "mangle" in ip6tables_tables:
            mangle.append("ipv6")

        raw = []
        if "raw" in ip4tables_tables:
            raw.append("ipv4")
        if "raw" in ip6tables_tables:
            raw.append("ipv6")

        nat = []
        if "nat" in ip4tables_tables:
            nat.append("ipv4")
        else:
            if "ipv4" in mangle:
                mangle.remove("ipv4")

        if "nat" in ip6tables_tables:
            nat.append("ipv6")
        else:
            if "ipv6" in mangle:
                mangle.remove("ipv6")

        self.zone_chains = {
            "filter": {
                "INPUT": [ "ipv4", "ipv6" ],
                "FORWARD_IN": [ "ipv4", "ipv6" ],
                "FORWARD_OUT": [ "ipv4", "ipv6" ],
            },
            "nat": {
                "PREROUTING": nat,
                "POSTROUTING": nat,
            },
            "mangle": {
                "PREROUTING": mangle,
            },
            "raw": {
                "PREROUTING": raw,
            },
        }

        self.interface_zone_opts = {
            "PREROUTING": "-i",
            "POSTROUTING": "-o",
            "INPUT": "-i",
            "FORWARD_IN": "-i",
            "FORWARD_OUT": "-o",
            "OUTPUT": "-o",
        }

        ## transform self.interface_zone_opts for source address
        tbl = { "-i": "-s",
                "-o": "-d" }
        self.source_zone_opts = {
            key: tbl[val] for key,val in self.interface_zone_opts.items()
        }

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__, self._chains, self._zones)

    def cleanup(self):
        self._chains.clear()
        self._zones.clear()

    # transaction

    def new_transaction(self):
        return FirewallTransaction(self._fw)

    def new_zone_transaction(self, zone):
        return FirewallZoneTransaction(self._fw, zone)

    # zones

    def get_zones(self):
        return sorted(self._zones.keys())

    def get_zone_of_interface(self, interface):
        interface_id = self.__interface_id(interface)
        for zone in self._zones:
            if interface_id in self._zones[zone].settings["interfaces"]:
                # an interface can only be part of one zone
                return zone
        return None

    def get_zone_of_source(self, source):
        source_id = self.__source_id(source)
        for zone in self._zones:
            if source_id in self._zones[zone].settings["sources"]:
                # a source_id can only be part of one zone
                return zone
        return None

    def get_zone(self, zone):
        z = self._fw.check_zone(zone)
        return self._zones[z]

    def _error2warning(self, f, name, *args, **kwargs):
        # transform errors into warnings
        try:
            f(name, *args, **kwargs)
        except FirewallError as error:
            msg = str(error)
            log.warning("%s: %s" % (name, msg))

    def add_zone(self, obj):
        obj.settings = { x : LastUpdatedOrderedDict()
                         for x in [ "interfaces", "sources",
                                    "services", "ports",
                                    "masquerade", "forward_ports",
                                    "source_ports",
                                    "icmp_blocks", "rules",
                                    "protocols", "icmp_block_inversion" ] }

        self._zones[obj.name] = obj

    def remove_zone(self, zone):
        obj = self._zones[zone]
        if obj.applied:
            self.unapply_zone_settings(zone)
        obj.settings.clear()
        del self._zones[zone]

    def apply_zones(self, use_transaction=None):
        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        for zone in self.get_zones():
            obj = self._zones[zone]

            zone_transaction = transaction.zone_transaction(zone)

            # register icmp block inversion setting but don't apply
            if obj.icmp_block_inversion:
                self._error2warning(self.add_icmp_block_inversion, obj.name,
                                    use_zone_transaction=zone_transaction)

            if len(obj.interfaces) > 0 or len(obj.sources) > 0:
                obj.applied = True

            log.debug1("Applying zone '%s'", obj.name)

            # load zone in case of missing services, icmptypes etc.
            for args in obj.icmp_blocks:
                self._error2warning(self.add_icmp_block, obj.name, args,
                                    use_zone_transaction=zone_transaction)
            for args in obj.forward_ports:
                self._error2warning(self.add_forward_port, obj.name, *args,
                                    use_zone_transaction=zone_transaction)
            for args in obj.services:
                self._error2warning(self.add_service, obj.name, args,
                                    use_zone_transaction=zone_transaction)
            for args in obj.ports:
                self._error2warning(self.add_port, obj.name, *args,
                                    use_zone_transaction=zone_transaction)
            for args in obj.protocols:
                self._error2warning(self.add_protocol, obj.name, args,
                                    use_zone_transaction=zone_transaction)
            for args in obj.source_ports:
                self._error2warning(self.add_source_port, obj.name, *args,
                                    use_zone_transaction=zone_transaction)
            if obj.masquerade:
                self._error2warning(self.add_masquerade, obj.name,
                                    use_zone_transaction=zone_transaction)
            for args in obj.rules:
                self._error2warning(self.add_rule, obj.name, args,
                                    use_zone_transaction=zone_transaction)
            for args in obj.interfaces:
                self._error2warning(self.add_interface, obj.name, args,
                                    use_zone_transaction=zone_transaction)
            for args in obj.sources:
                self._error2warning(self.add_source, obj.name, args,
                                    use_zone_transaction=zone_transaction)
            # apply icmp accept/reject rule always
            if obj.applied:
                self._error2warning(self.__icmp_block_inversion, True,
                                    obj.name,
                                    use_zone_transaction=zone_transaction)

        if use_transaction is None:
            transaction.execute(True)

    def set_zone_applied(self, zone, applied):
        obj = self._zones[zone]
        obj.applied = applied

    # zone from chain

    def zone_from_chain(self, chain):
        if "_" not in chain:
            # no zone chain
            return None
        splits = chain.split("_")
        if len(splits) < 2:
            return None
        _chain = None
        for x in SHORTCUTS:
            if splits[0] == SHORTCUTS[x]:
                _chain = x
        if _chain is not None:
            # next part needs to be zone name
            if splits[1] not in self.get_zones():
                return None
            if len(splits) == 2 or \
               (len(splits) == 3 and splits[2] in [ "log", "deny", "allow" ]):
                return (splits[1], _chain)
        return None

    def create_zone_base_by_chain(self, ipv, table, chain,
                                  use_transaction=None):

        # Create zone base chains if the chain is reserved for a zone
        if ipv in [ "ipv4", "ipv6" ]:
            x = self.zone_from_chain(chain)
            if x is not None:
                (_zone, _chain) = x

                if use_transaction is None:
                    transaction = self.new_transaction()
                else:
                    transaction = use_transaction

                self.gen_chain_rules(_zone, True, [(table, _chain)],
                                     transaction)

                if use_transaction is None:
                    transaction.execute(True)

    # dynamic chain handling

    def gen_chain_rules(self, zone, create, chains, transaction):
        for (table, chain) in chains:
            if create:
                if zone in self._chains and  \
                   table in self._chains[zone] and \
                   chain in self._chains[zone][table]:
                    continue
            else:
                if zone not in self._chains or \
                   table not in self._chains[zone] or \
                   chain not in self._chains[zone][table]:
                    continue

            _zone = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS[chain],
                                               zone=zone)

            ipvs = [ ]
            if table in self._fw.get_available_tables("ipv4"):
                ipvs.append("ipv4")
            if table in self._fw.get_available_tables("ipv6"):
                ipvs.append("ipv6")

            for ipv in ipvs:
                OUR_CHAINS[table].update(set([_zone,
                                              "%s_log" % _zone,
                                              "%s_deny" % _zone,
                                              "%s_allow" % _zone]))
                transaction.add_rule(ipv, [ "-N", _zone, "-t", table ])
                transaction.add_rule(ipv, [ "-N", "%s_log" % (_zone), "-t", table ])
                transaction.add_rule(ipv, [ "-N", "%s_deny" % (_zone), "-t", table ])
                transaction.add_rule(ipv, [ "-N", "%s_allow" % (_zone), "-t", table ])
                transaction.add_rule(ipv, [ "-I", _zone, "1", "-t", table,
                                            "-j", "%s_log" % (_zone) ])
                transaction.add_rule(ipv, [ "-I", _zone, "2", "-t", table,
                                            "-j", "%s_deny" % (_zone) ])
                transaction.add_rule(ipv, [ "-I", _zone, "3", "-t", table,
                                            "-j", "%s_allow" % (_zone) ])

                # Handle trust, block and drop zones:
                # Add an additional rule with the zone target (accept, reject
                # or drop) to the base _zone only in the filter table.
                # Otherwise it is not be possible to have a zone with drop
                # target, that is allowing traffic that is locally initiated
                # or that adds additional rules. (RHBZ#1055190)
                target = self._zones[zone].target
                if table == "filter" and \
                   target in [ "ACCEPT", "REJECT", "%%REJECT%%", "DROP" ] and \
                   chain in [ "INPUT", "FORWARD_IN", "FORWARD_OUT", "OUTPUT" ]:
                    transaction.add_rule(ipv, [ "-I", _zone, "4",
                                                "-t", table, "-j", target ])

                if self._fw.get_log_denied() != "off":
                    if table == "filter" and \
                       chain in [ "INPUT", "FORWARD_IN", "FORWARD_OUT", "OUTPUT" ]:
                        if target in [ "REJECT", "%%REJECT%%" ]:
                            transaction.add_rule(
                                ipv, [ "-I", _zone, "4", "-t", table,
                                       "%%LOGTYPE%%",
                                       "-j", "LOG", "--log-prefix",
                                       "\"%s_REJECT: \"" % _zone ])
                        if target == "DROP":
                            transaction.add_rule(
                                ipv, [ "-I", _zone, "4", "-t", table,
                                       "%%LOGTYPE%%",
                                       "-j", "LOG", "--log-prefix",
                                       "\"%s_DROP: \"" % _zone ])

            self.__register_chains(zone, create, chains)
            transaction.add_fail(self.__register_chains, zone, create, chains)

    def __register_chains(self, zone, create, chains):
        # this method is used by FirewallZoneTransaction
        for (table, chain) in chains:
            if create:
                self._chains.setdefault(zone, { }).setdefault(table, [ ]).append(chain)
            else:
                self._chains[zone][table].remove(chain)
                if len(self._chains[zone][table]) == 0:
                    del self._chains[zone][table]
                if len(self._chains[zone]) == 0:
                    del self._chains[zone]

    # settings

    # generate settings record with sender, timeout, mark
    def __gen_settings(self, timeout, sender, mark=None):
        ret = {
            "date": time.time(),
            "sender": sender,
            "timeout": timeout,
        }
        if mark:
            ret["mark"] = mark
        return ret

    def get_settings(self, zone):
        return self.get_zone(zone).settings

    def set_settings(self, zone, settings):
        _obj = self.get_zone(zone)

        try:
            for key in settings:
                for args in settings[key]:
                    if args in _obj.settings[key]:
                        # do not add things, that are already active in the
                        # zone configuration, also do not restore date,
                        # sender and timeout
                        continue
                    if key == "icmp_blocks":
                        self.add_icmp_block(zone, args)
                    elif key == "forward_ports":
                        self.add_forward_port(zone, *args)
                    elif key == "services":
                        self.add_service(zone, args)
                    elif key == "ports":
                        self.add_port(zone, *args)
                    elif key == "protocols":
                        self.add_protocol(zone, *args)
                    elif key == "source_ports":
                        self.add_source_port(zone, *args)
                    elif key == "masquerade":
                        self.add_masquerade(zone)
                    elif key == "rules":
                        self.add_rule(zone, Rich_Rule(rule_str=args))
                    elif key == "interfaces":
                        self.change_zone_of_interface(zone, args)
                    elif key == "sources":
                        self.change_zone_of_source(zone, args)
                    else:
                        log.warning("Zone '%s': Unknown setting '%s:%s', "
                                    "unable to restore.", zone, key, args)
                    # restore old date, sender and timeout
                    if args in _obj.settings[key]:
                        _obj.settings[key][args] = settings[key][args]

        except FirewallError as msg:
            log.warning(str(msg))

    def __zone_settings(self, enable, zone, use_zone_transaction=None):
        _zone = self._fw.check_zone(zone)
        obj = self._zones[_zone]
        if (enable and obj.applied) or (not enable and not obj.applied):
            return
        if enable:
            obj.applied = True

        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(zone)
        else:
            zone_transaction = use_zone_transaction

        settings = self.get_settings(zone)
        for key in settings:
            for args in settings[key]:
                try:
                    if key == "icmp_blocks":
                        self.__icmp_block(enable, _zone, args,
                                          use_zone_transaction=zone_transaction)
                    elif key == "icmp_block_inversion":
                        continue
                    elif key == "forward_ports":
                        mark = obj.settings["forward_ports"][args]["mark"]
                        self.__forward_port(enable, _zone, *args, mark_id=mark,
                                            use_zone_transaction=zone_transaction)
                    elif key == "services":
                        self.__service(enable, _zone, args,
                                       use_zone_transaction=zone_transaction)
                    elif key == "ports":
                        self.__port(enable, _zone, *args,
                                    use_zone_transaction=zone_transaction)
                    elif key == "protocols":
                        self.__protocol(enable, _zone, args,
                                        use_zone_transaction=zone_transaction)
                    elif key == "source_ports":
                        self.__source_port(enable, _zone, *args,
                                           use_zone_transaction=zone_transaction)
                    elif key == "masquerade":
                        self.__masquerade(enable, _zone,
                                          use_zone_transaction=zone_transaction)
                    elif key == "rules":
                        self.__rule(enable, _zone,
                                    Rich_Rule(rule_str=args), None,
                                    use_zone_transaction=zone_transaction)
                    elif key == "interfaces":
                        self.__interface(enable, _zone, args,
                                         use_zone_transaction=zone_transaction)
                    elif key == "sources":
                        self.__source(enable, _zone, *args,
                                      use_zone_transaction=zone_transaction)
                    else:
                        log.warning("Zone '%s': Unknown setting '%s:%s', "
                                    "unable to apply", zone, key, args)
                except FirewallError as msg:
                    log.warning(str(msg))

        if enable:
            # add icmp rule(s) always
            self.__icmp_block_inversion(True, obj.name,
                                        use_zone_transaction=zone_transaction)

        if use_zone_transaction is None:
            zone_transaction.execute(enable)

    def apply_zone_settings(self, zone, use_zone_transaction=None):
        self.__zone_settings(True, zone, use_zone_transaction)

    def unapply_zone_settings(self, zone, use_zone_transaction=None):
        self.__zone_settings(False, zone, use_zone_transaction)

    def unapply_zone_settings_if_unused(self, zone):
        obj = self._zones[zone]
        if len(obj.interfaces) == 0 and len(obj.sources) == 0:
            self.unapply_zone_settings(zone)

    def get_config_with_settings(self, zone):
        """
        :return: exported config updated with runtime settings
        """
        conf = list(self.get_zone(zone).export_config())
        if conf[4] == DEFAULT_ZONE_TARGET:
            conf[4] = "default"
        conf[5] = self.list_services(zone)
        conf[6] = self.list_ports(zone)
        conf[7] = self.list_icmp_blocks(zone)
        conf[8] = self.query_masquerade(zone)
        conf[9] = self.list_forward_ports(zone)
        conf[10] = self.list_interfaces(zone)
        conf[11] = self.list_sources(zone)
        conf[12] = self.list_rules(zone)
        conf[13] = self.list_protocols(zone)
        conf[14] = self.list_source_ports(zone)
        conf[15] = self.query_icmp_block_inversion(zone)
        return tuple(conf)

    # INTERFACES

    def check_interface(self, interface):
        self._fw.check_interface(interface)

    def interface_get_sender(self, zone, interface):
        _zone = self._fw.check_zone(zone)
        _obj = self._zones[_zone]
        interface_id = self.__interface_id(interface)

        if interface_id in _obj.settings["interfaces"]:
            settings = _obj.settings["interfaces"][interface_id]
            if "sender" in settings and settings["sender"] is not None:
                return settings["sender"]

        return None

    def __interface_id(self, interface):
        self.check_interface(interface)
        return interface

    def __interface(self, enable, zone, interface, append=False,
                    use_zone_transaction=None):
        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(zone)
        else:
            zone_transaction = use_zone_transaction

        for table in self.zone_chains:
            for chain in self.zone_chains[table]:
                # create needed chains if not done already
                if enable:
                    zone_transaction.add_chain(table, chain)

                for ipv in self.zone_chains[table][chain]:
                    # handle all zones in the same way here, now
                    # trust and block zone targets are handled now in __chain
                    opt = self.interface_zone_opts[chain]
                    target = DEFAULT_ZONE_TARGET.format(
                        chain=SHORTCUTS[chain], zone=zone)
                    if self._zones[zone].target == DEFAULT_ZONE_TARGET:
                        action = "-g"
                    else:
                        action = "-j"
                    if enable and not append:
                        rule = [ "-I", "%s_ZONES" % chain, "1" ]
                    elif enable:
                        rule = [ "-A", "%s_ZONES" % chain ]
                    else:
                        rule = [ "-D", "%s_ZONES" % chain ]
                    rule += [ "-t", table, opt, interface, action, target ]
                    zone_transaction.add_rule(ipv, rule)

        if use_zone_transaction is None:
            zone_transaction.execute(enable)

    def add_interface(self, zone, interface, sender=None,
                      use_zone_transaction=None):
        self._fw.check_panic()
        _zone = self._fw.check_zone(zone)
        _obj = self._zones[_zone]

        interface_id = self.__interface_id(interface)

        if interface_id in _obj.settings["interfaces"]:
            raise FirewallError(errors.ZONE_ALREADY_SET,
                                "'%s' already bound to '%s'" % (interface,
                                                                zone))
        if self.get_zone_of_interface(interface) is not None:
            raise FirewallError(errors.ZONE_CONFLICT,
                                "'%s' already bound to a zone" % interface)

        log.debug1("Setting zone of interface '%s' to '%s'" % (interface,
                                                               _zone))

        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(_zone)
        else:
            zone_transaction = use_zone_transaction

        if not _obj.applied:
            self.apply_zone_settings(zone,
                                     use_zone_transaction=zone_transaction)
            zone_transaction.add_fail(self.set_zone_applied, _zone, False)

        self.__interface(True, _zone, interface,
                         use_zone_transaction=zone_transaction)

        self.__register_interface(_obj, interface_id, zone, sender)
        zone_transaction.add_fail(self.__unregister_interface, _obj,
                                  interface_id)

        zone_transaction.add_post(ifcfg_set_zone_of_interface, zone, interface)

        if use_zone_transaction is None:
            zone_transaction.execute(True)

        return _zone

    def __register_interface(self, _obj, interface_id, zone, sender):
        _obj.settings["interfaces"][interface_id] = \
            self.__gen_settings(0, sender)
        # add information whether we add to default or specific zone
        _obj.settings["interfaces"][interface_id]["__default__"] = \
            (not zone or zone == "")

    def change_zone_of_interface(self, zone, interface, sender=None):
        self._fw.check_panic()
        _old_zone = self.get_zone_of_interface(interface)
        _new_zone = self._fw.check_zone(zone)

        if _new_zone == _old_zone:
            return _old_zone

        if _old_zone is not None:
            self.remove_interface(_old_zone, interface)

        _zone = self.add_interface(zone, interface, sender)

        return _zone

    def change_default_zone(self, old_zone, new_zone, use_transaction=None):
        self._fw.check_panic()

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        zone_transaction = transaction.zone_transaction(new_zone)
        self.apply_zone_settings(new_zone, zone_transaction)
        self.__interface(True, new_zone, "+", append=True,
                         use_zone_transaction=zone_transaction)
        if old_zone is not None and old_zone != "":
            zone_transaction = transaction.zone_transaction(old_zone)
            self.__interface(False, old_zone, "+", append=True,
                             use_zone_transaction=zone_transaction)

        if use_transaction is None:
            transaction.execute(True)

    def remove_interface(self, zone, interface,
                         use_zone_transaction=None):
        self._fw.check_panic()
        zoi = self.get_zone_of_interface(interface)
        if zoi is None:
            raise FirewallError(errors.UNKNOWN_INTERFACE,
                                "'%s' is not in any zone" % interface)
        _zone = zoi if zone == "" else self._fw.check_zone(zone)
        if zoi != _zone:
            raise FirewallError(errors.ZONE_CONFLICT,
                                "remove_interface(%s, %s): zoi='%s'" % \
                                (zone, interface, zoi))

        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(_zone)
        else:
            zone_transaction = use_zone_transaction

        _obj = self._zones[_zone]
        interface_id = self.__interface_id(interface)
        self.__interface(False, _zone, interface,
                         use_zone_transaction=zone_transaction)

        zone_transaction.add_post(self.__unregister_interface, _obj,
                                  interface_id)

        # Do not reset ZONE with ifdown
        # On reboot or shutdown the zone has been reset to default
        # if the network service is enabled and controlling the
        # interface (RHBZ#1381314)
        #zone_transaction.add_post(ifcfg_set_zone_of_interface, "", interface)

        if use_zone_transaction is None:
            zone_transaction.execute(True)

#        self.unapply_zone_settings_if_unused(_zone)
        return _zone

    def __unregister_interface(self, _obj, interface_id):
        if interface_id in _obj.settings["interfaces"]:
            del _obj.settings["interfaces"][interface_id]

    def query_interface(self, zone, interface):
        return self.__interface_id(interface) in self.get_settings(zone)["interfaces"]

    def list_interfaces(self, zone):
        return self.get_settings(zone)["interfaces"].keys()

    # IPSETS

    def ipset_family(self, name):
        if self._fw.ipset.get_type(name) == "hash:mac":
            return None
        return self._fw.ipset.get_family(name)

    def ipset_type(self, name):
        return self._fw.ipset.get_type(name)

    def ipset_dimension(self, name):
        return self._fw.ipset.get_dimension(name)

    def ipset_match_flags(self, name, flag):
        return ",".join([flag] * self._fw.ipset.get_dimension(name))

    def check_ipset_applied(self, name):
        return self._fw.ipset.check_applied(name)

    def check_ipset_type_for_source(self, name):
        _type = self.ipset_type(name)
        if _type not in ZONE_SOURCE_IPSET_TYPES:
            raise FirewallError(
                errors.INVALID_IPSET,
                "ipset '%s' with type '%s' not usable as source" % \
                (name, _type))

    # SOURCES

    def check_source(self, source):
        if checkIPnMask(source):
            return "ipv4"
        elif checkIP6nMask(source):
            return "ipv6"
        elif check_mac(source):
            return ""
        elif source.startswith("ipset:"):
            self.check_ipset_type_for_source(source[6:])
            self.check_ipset_applied(source[6:])
            return self.ipset_family(source[6:])
        else:
            raise FirewallError(errors.INVALID_ADDR, source)

    def __source_id(self, source):
        ipv = self.check_source(source)
        return (ipv, source)

    def __source(self, enable, zone, ipv, source, use_zone_transaction=None):
        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(zone)
        else:
            zone_transaction = use_zone_transaction

        # make sure mac addresses are unique
        if check_mac(source):
            source = source.upper()

        add_del = { True: "-A", False: "-D" }[enable]

        # For mac source bindings ipv is an empty string, the mac source will
        # be added for ipv4 and ipv6
        if ipv == "" or ipv is None:
            for ipv in [ "ipv4", "ipv6" ]:
                for table in self.zone_chains:
                    for chain in self.zone_chains[table]:
                        # create needed chains if not done already
                        if enable:
                            zone_transaction.add_chain(table, chain)

                        # for zone mac source bindings the features are limited

                        if self._zones[zone].target == DEFAULT_ZONE_TARGET:
                            action = "-g"
                        else:
                            action = "-j"
                        target = DEFAULT_ZONE_TARGET.format(
                            chain=SHORTCUTS[chain], zone=zone)
                        opt = self.source_zone_opts[chain]

                        if source.startswith("ipset:"):
                            _name = source[6:]
                            if opt == "-d":
                                opt = "dst"
                            else:
                                opt = "src"
                            flags = self.ipset_match_flags(_name, opt)
                            rule = [ add_del,
                                     "%s_ZONES_SOURCE" % chain, "-t", table,
                                     "-m", "set", "--match-set", _name,
                                     flags, action, target ]
                        else:
                            # outgoing can not be set
                            if opt == "-d":
                                continue
                            rule = [ add_del,
                                     "%s_ZONES_SOURCE" % chain, "-t", table,
                                     "-m", "mac", "--mac-source", source,
                                     action, target ]
                        zone_transaction.add_rule(ipv, rule)

        else:
            for table in self.zone_chains:
                for chain in self.zone_chains[table]:
                    # create needed chains if not done already
                    if enable:
                        zone_transaction.add_chain(table, chain)

                    # handle all zone bindings in the same way
                    # trust, block and drop zone targets are handled in __chain

                    if self._zones[zone].target == DEFAULT_ZONE_TARGET:
                        action = "-g"
                    else:
                        action = "-j"

                    target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS[chain],
                                                        zone=zone)
                    opt = self.source_zone_opts[chain]

                    rule = [ add_del, "%s_ZONES_SOURCE" % chain, "-t", table ]
                    if source.startswith("ipset:"):
                        _name = source[6:]
                        if opt == "-d":
                            opt = "dst"
                        else:
                            opt = "src"
                        flags = self.ipset_match_flags(_name, opt)
                        rule = [ add_del,
                                 "%s_ZONES_SOURCE" % chain, "-t", table,
                                 "-m", "set", "--match-set", _name, flags,
                                 action, target ]
                    else:
                        rule = [ add_del,
                                 "%s_ZONES_SOURCE" % chain, "-t", table,
                                 opt, source, action, target ]
                    zone_transaction.add_rule(ipv, rule)

        if use_zone_transaction is None:
            zone_transaction.execute(enable)

    def add_source(self, zone, source, sender=None, use_zone_transaction=None):
        self._fw.check_panic()
        _zone = self._fw.check_zone(zone)
        _obj = self._zones[_zone]

        if check_mac(source):
            source = source.upper()

        source_id = self.__source_id(source)

        if source_id in _obj.settings["sources"]:
            raise FirewallError(errors.ZONE_ALREADY_SET,
                            "'%s' already bound to '%s'" % (source, _zone))
        if self.get_zone_of_source(source) is not None:
            raise FirewallError(errors.ZONE_CONFLICT,
                                "'%s' already bound to a zone" % source)

        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(_zone)
        else:
            zone_transaction = use_zone_transaction

        if not _obj.applied:
            self.apply_zone_settings(zone,
                                     use_zone_transaction=zone_transaction)
            zone_transaction.add_fail(self.set_zone_applied, _zone, False)

        self.__source(True, _zone, source_id[0], source_id[1],
                      use_zone_transaction=zone_transaction)

        self.__register_source(_obj, source_id, zone, sender)
        zone_transaction.add_fail(self.__unregister_source, _obj,
                                  source_id)

        if use_zone_transaction is None:
            zone_transaction.execute(True)

        return _zone

    def __register_source(self, _obj, source_id, zone, sender):
        _obj.settings["sources"][source_id] = \
            self.__gen_settings(0, sender)
        # add information whether we add to default or specific zone
        _obj.settings["sources"][source_id]["__default__"] = (not zone or zone == "")

    def change_zone_of_source(self, zone, source, sender=None):
        self._fw.check_panic()
        _old_zone = self.get_zone_of_source(source)
        _new_zone = self._fw.check_zone(zone)

        if _new_zone == _old_zone:
            return _old_zone

        if check_mac(source):
            source = source.upper()

        if _old_zone is not None:
            self.remove_source(_old_zone, source)

        _zone = self.add_source(zone, source, sender)

        return _zone

    def remove_source(self, zone, source,
                      use_zone_transaction=None):
        self._fw.check_panic()
        if check_mac(source):
            source = source.upper()
        zos = self.get_zone_of_source(source)
        if zos is None:
            raise FirewallError(errors.UNKNOWN_SOURCE,
                                "'%s' is not in any zone" % source)
        _zone = zos if zone == "" else self._fw.check_zone(zone)
        if zos != _zone:
            raise FirewallError(errors.ZONE_CONFLICT,
                                "remove_source(%s, %s): zos='%s'" % \
                                (zone, source, zos))

        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(_zone)
        else:
            zone_transaction = use_zone_transaction

        _obj = self._zones[_zone]
        source_id = self.__source_id(source)
        self.__source(False, _zone, source_id[0], source_id[1],
                      use_zone_transaction=zone_transaction)

        zone_transaction.add_post(self.__unregister_source, _obj,
                                  source_id)

        if use_zone_transaction is None:
            zone_transaction.execute(True)

#        self.unapply_zone_settings_if_unused(_zone)
        return _zone

    def __unregister_source(self, _obj, source_id):
        if source_id in _obj.settings["sources"]:
            del _obj.settings["sources"][source_id]

    def query_source(self, zone, source):
        if check_mac(source):
            source = source.upper()
        return self.__source_id(source) in self.get_settings(zone)["sources"]

    def list_sources(self, zone):
        return [ k[1] for k in self.get_settings(zone)["sources"].keys() ]

    # RICH LANGUAGE

    def check_rule(self, rule):
        rule.check()

    def __rule_id(self, rule):
        self.check_rule(rule)
        return str(rule)

    def __rule_source_ipv(self, source):
        if not source:
            return None

        if source.addr:
            if checkIPnMask(source.addr):
                return "ipv4"
            elif checkIP6nMask(source.addr):
                return "ipv6"
        elif hasattr(source, "mac") and source.mac:
            return ""
        elif hasattr(source, "ipset") and source.ipset:
            self.check_ipset_type_for_source(source.ipset)
            self.check_ipset_applied(source.ipset)
            return self.ipset_family(source.ipset)

        return None

    def __rule_source(self, source, command):
        if source:
            if source.addr:
                if source.invert:
                    command.append("!")
                command += [ "-s", source.addr ]

            elif hasattr(source, "mac") and source.mac:
                command += [ "-m", "mac" ]
                if source.invert:
                    command.append("!")
                command += [ "--mac-source", source.mac ]

            elif hasattr(source, "ipset") and source.ipset:
                command += [ "-m", "set" ]
                if source.invert:
                    command.append("!")
                flags = self.ipset_match_flags(source.ipset, "src")
                command += [ "--match-set", source.ipset, flags ]

    def __rule_destination(self, destination, command):
        if destination:
            if destination.invert:
                command.append("!")
            command += [ "-d", destination.addr ]

    def __rule_limit(self, limit):
        if limit:
            return [ "-m", "limit", "--limit", limit.value ]
        return [ ]

    def __rule_log(self, enable, ipv, table, target, rule, command,
                   zone_transaction):
        if not rule.log:
            return
        chain = "%s_log" % target
        _command = command[:]
        _command += [ "-j", "LOG" ]
        if rule.log.prefix:
            _command += [ "--log-prefix", '"%s"' % rule.log.prefix ]
        if rule.log.level:
            _command += [ "--log-level", '"%s"' % rule.log.level ]
        _command += self.__rule_limit(rule.log.limit)

        add_del = { True: "-A", False: "-D" }[enable]
        _rule = [ add_del, chain, "-t", table ]
        _rule += _command
        zone_transaction.add_rule(ipv, _rule)

    def __rule_audit(self, enable, ipv, table, target, rule, command,
                     zone_transaction):
        if not rule.audit:
            return
        chain = "%s_log" % target
        _command = command[:]
        if type(rule.action) == Rich_Accept:
            _type = "accept"
        elif type(rule.action) == Rich_Reject:
            _type = "reject"
        elif type(rule.action) ==  Rich_Drop:
            _type = "drop"
        else:
            _type = "unknown"
        _command += [ "-j", "AUDIT", "--type", _type ]
        _command += self.__rule_limit(rule.audit.limit)

        add_del = { True: "-A", False: "-D" }[enable]
        _rule = [ add_del, chain, "-t", table ]
        _rule += _command
        zone_transaction.add_rule(ipv, _rule)

    def __rule_action(self, enable, zone, ipv, table, target, rule, command,
                      zone_transaction):
        if not rule.action:
            return
        _command = command[:]
        if type(rule.action) == Rich_Accept:
            chain = "%s_allow" % target
            _command += [ "-j", "ACCEPT" ]
        elif type(rule.action) == Rich_Reject:
            chain = "%s_deny" % target
            _command += [ "-j", "REJECT" ]
            if rule.action.type:
                _command += [ "--reject-with", rule.action.type ]
        elif type(rule.action) ==  Rich_Drop:
            chain = "%s_deny" % target
            _command += [ "-j", "DROP" ]
        elif type(rule.action) == Rich_Mark:
            if enable:
                zone_transaction.add_chain("mangle", "PREROUTING")
            table = "mangle"
            target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["PREROUTING"],
                                                zone=zone)
            chain = "%s_allow" % target
            _command += [ "-j", "MARK", "--set-xmark", rule.action.set ]
        else:
            raise FirewallError(errors.INVALID_RULE,
                                "Unknown action %s" % type(rule.action))
        _command += self.__rule_limit(rule.action.limit)

        add_del = { True: "-A", False: "-D" }[enable]
        _rule = [ add_del, chain, "-t", table ]
        _rule += _command
        zone_transaction.add_rule(ipv, _rule)

    def __rule_prepare(self, enable, zone, rule, mark_id, zone_transaction):
        if rule.family is not None:
            ipvs = [ rule.family ]
        else:
            ipvs = [ "ipv4", "ipv6" ]

        add_del = { True: "-A", False: "-D" }[enable]
        source_ipv = self.__rule_source_ipv(rule.source)
        if source_ipv is not None and source_ipv != "":
            if rule.family is not None:
                # rule family is defined by user, no way to change it
                if rule.family != source_ipv:
                    raise FirewallError(errors.INVALID_RULE,
                                        "Source address family '%s' conflicts with rule family '%s'." % (source_ipv, rule.family))
            else:
                # use the source family as rule family
                ipvs = [ source_ipv ]

        for ipv in ipvs:
            # SERVICE
            if type(rule.element) == Rich_Service:
                svc = self._fw.service.get_service(rule.element.name)

                if len(svc.destination) > 0:
                    if ipv not in svc.destination:
                        # destination is set, only use if it contains ipv
                        raise FirewallError(errors.INVALID_RULE,
                                            "Service %s is not usable with %s" %
                                            (rule.element.name, ipv))
                    if svc.destination[ipv] != "" and rule.destination:
                        # we can not use two destinations at the same time
                        raise FirewallError(errors.INVALID_RULE,
                                            "Destination conflict with service.")

                table = "filter"
                if enable:
                    zone_transaction.add_chain(table, "INPUT")
                    if self._fw.nf_conntrack_helper_setting == 0:
                        zone_transaction.add_chain("raw", "PREROUTING")

                if type(rule.action) == Rich_Accept:
                    # only load modules for accept action
                    helpers = self.get_helpers_for_service_modules(svc.modules,
                                                                   enable)

                    modules = [ ]
                    for helper in helpers:
                        module = helper.module
                        if self._fw.nf_conntrack_helper_setting == 0:
                            if helper.name not in \
                               self._fw.nf_conntrack_helpers[module]:
                                raise FirewallError(
                                    errors.INVALID_HELPER,
                                    "'%s' not available in kernel" % module)
                            if helper.family != "" and helper.family != ipv:
                                # no support for family ipv, continue
                                continue
                            for (port,proto) in helper.ports:
                                target = DEFAULT_ZONE_TARGET.format(
                                    chain=SHORTCUTS["PREROUTING"], zone=zone)
                                _rule = [ add_del, "%s_allow" % (target),
                                          "-t", "raw", "-p", proto ]
                                if port:
                                    _rule += [ "--dport", "%s" % portStr(port) ]
                                if ipv in svc.destination and \
                                   svc.destination[ipv] != "":
                                    _rule += [ "-d",  svc.destination[ipv] ]
                                _rule += [ "-j", "CT", "--helper", helper.name ]
                                self.__rule_source(rule.source, _rule)
                                zone_transaction.add_rule(ipv, _rule)
                        else:
                            if helper.module not in modules:
                                modules.append(helper.module)
                    zone_transaction.add_modules(modules)

                target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["INPUT"],
                                                    zone=zone)

                # create rules
                for (port,proto) in svc.ports:
                    command = [ ]
                    self.__rule_source(rule.source, command)
                    self.__rule_destination(rule.destination, command)

                    command += [ "-p", proto ]
                    if port:
                        command += [ "--dport", "%s" % portStr(port) ]
                    if ipv in svc.destination and svc.destination[ipv] != "":
                        command += [ "-d",  svc.destination[ipv] ]
                    if type(rule.action) != Rich_Mark:
                        command += [ "-m", "conntrack", "--ctstate", "NEW" ]

                    self.__rule_log(enable, ipv, table, target, rule, command,
                                    zone_transaction)
                    self.__rule_audit(enable, ipv, table, target, rule, command,
                                      zone_transaction)
                    self.__rule_action(enable, zone, ipv, table, target, rule,
                                       command, zone_transaction)

                for proto in svc.protocols:
                    command = [ ]
                    self.__rule_source(rule.source, command)
                    self.__rule_destination(rule.destination, command)

                    command += [ "-p", proto ]
                    if ipv in svc.destination and svc.destination[ipv] != "":
                        command += [ "-d",  svc.destination[ipv] ]
                    if type(rule.action) != Rich_Mark:
                        command += [ "-m", "conntrack", "--ctstate", "NEW" ]

                    self.__rule_log(enable, ipv, table, target, rule, command,
                                    zone_transaction)
                    self.__rule_audit(enable, ipv, table, target, rule, command,
                                      zone_transaction)
                    self.__rule_action(enable, zone, ipv, table, target, rule,
                                       command, zone_transaction)

                # create rules
                for (port,proto) in svc.source_ports:
                    command = [ ]
                    self.__rule_source(rule.source, command)
                    self.__rule_destination(rule.destination, command)

                    command += [ "-p", proto ]
                    if port:
                        command += [ "--sport", "%s" % portStr(port) ]
                    if ipv in svc.destination and svc.destination[ipv] != "":
                        command += [ "-d",  svc.destination[ipv] ]
                    if type(rule.action) != Rich_Mark:
                        command += [ "-m", "conntrack", "--ctstate", "NEW" ]

                    self.__rule_log(enable, ipv, table, target, rule, command,
                                    zone_transaction)
                    self.__rule_audit(enable, ipv, table, target, rule, command,
                                      zone_transaction)
                    self.__rule_action(enable, zone, ipv, table, target, rule,
                                       command, zone_transaction)

            # PORT
            elif type(rule.element) == Rich_Port:
                port = rule.element.port
                protocol = rule.element.protocol
                self.check_port(port, protocol)

                table = "filter"
                if enable:
                    zone_transaction.add_chain(table, "INPUT")
                target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["INPUT"],
                                                    zone=zone)

                command = [ ]
                self.__rule_source(rule.source, command)
                self.__rule_destination(rule.destination, command)
                command += [ "-m", protocol, "-p", protocol,
                           "--dport", portStr(port) ]
                if type(rule.action) != Rich_Mark:
                    command += [ "-m", "conntrack", "--ctstate", "NEW" ]

                self.__rule_log(enable, ipv, table, target, rule, command,
                                zone_transaction)
                self.__rule_audit(enable, ipv, table, target, rule, command,
                                  zone_transaction)
                self.__rule_action(enable, zone, ipv, table, target, rule,
                                   command, zone_transaction)

            # PROTOCOL
            elif type(rule.element) == Rich_Protocol:
                protocol = rule.element.value
                self.check_protocol(protocol)

                table = "filter"
                if enable:
                    zone_transaction.add_chain(table, "INPUT")
                target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["INPUT"],
                                                    zone=zone)

                command = [ ]
                self.__rule_source(rule.source, command)
                self.__rule_destination(rule.destination, command)
                command += [ "-p", protocol ]
                if type(rule.action) != Rich_Mark:
                    command += ["-m", "conntrack", "--ctstate", "NEW" ]

                self.__rule_log(enable, ipv, table, target, rule, command,
                                zone_transaction)
                self.__rule_audit(enable, ipv, table, target, rule, command,
                                  zone_transaction)
                self.__rule_action(enable, zone, ipv, table, target, rule,
                                   command, zone_transaction)

            # MASQUERADE
            elif type(rule.element) == Rich_Masquerade:
                if enable:
                    enable_ip_forwarding(ipv)

                if enable:
                    zone_transaction.add_chain("nat", "POSTROUTING")
                    zone_transaction.add_chain("filter", "FORWARD_OUT")

                # POSTROUTING
                target = DEFAULT_ZONE_TARGET.format(
                    chain=SHORTCUTS["POSTROUTING"], zone=zone)
                command = [ ]
                self.__rule_source(rule.source, command)
                self.__rule_destination(rule.destination, command)
                command += [ "!", "-o", "lo", "-j", "MASQUERADE" ]

                _rule = [ add_del, "%s_allow" % target, "-t", "nat" ]
                _rule += command
                zone_transaction.add_rule(ipv, _rule)

                # FORWARD_OUT
                target = DEFAULT_ZONE_TARGET.format(
                    chain=SHORTCUTS["FORWARD_OUT"], zone=zone)
                command = [ ]
                # reverse source/destination !
                self.__rule_source(rule.destination, command)
                self.__rule_destination(rule.source, command)
                command += [ "-m", "conntrack", "--ctstate", "NEW",
                             "-j", "ACCEPT" ]

                _rule = [ add_del, "%s_allow" % target, "-t", "filter" ]
                _rule += command
                zone_transaction.add_rule(ipv, _rule)

            # FORWARD PORT
            elif type(rule.element) == Rich_ForwardPort:
                port = rule.element.port
                protocol = rule.element.protocol
                toport = rule.element.to_port
                toaddr = rule.element.to_address
                self.check_forward_port(ipv, port, protocol, toport, toaddr)

                if enable:
                    enable_ip_forwarding(ipv)
                    mark_id = self._fw.new_mark()

                filter_chain = "INPUT" if not toaddr else "FORWARD_IN"

                if enable:
                    zone_transaction.add_chain("mangle", "PREROUTING")
                    zone_transaction.add_chain("nat", "PREROUTING")
                    zone_transaction.add_chain("filter", filter_chain)

                mark_str = "0x%x" % mark_id
                port_str = portStr(port)

                to = ""
                if toaddr:
                    to += toaddr

                if toport and toport != "":
                    to += ":%s" % portStr(toport, "-")

                mark = [ "-m", "mark", "--mark", mark_str ]

                target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["PREROUTING"],
                                                    zone=zone)
                command = [ ]
                self.__rule_source(rule.source, command)
                self.__rule_destination(rule.destination, command)
                command += [ "-p", protocol, "--dport", port_str ]

                # log
                self.__rule_log(enable, ipv, "mangle", target, rule, command,
                                zone_transaction)

                # mark for later dnat using mark
                command += [ "-j", "MARK", "--set-mark", mark_str ]

                _rule = [ add_del, "%s_allow" % target, "-t", "mangle" ]
                _rule += command
                zone_transaction.add_rule(ipv, _rule)

                # local and remote
                command = [ "-p", protocol ] + mark + \
                    [ "-j", "DNAT", "--to-destination", to ]

                _rule = [ add_del, "%s_allow" % target, "-t", "nat" ]
                _rule += command
                zone_transaction.add_rule(ipv, _rule)

                target = DEFAULT_ZONE_TARGET.format(
                    chain=SHORTCUTS[filter_chain], zone=zone)
                command = [ "-m", "conntrack", "--ctstate", "NEW" ] + \
                    mark + [ "-j", "ACCEPT" ]

                _rule = [ add_del, "%s_allow" % target, "-t", "filter" ]
                _rule += command
                zone_transaction.add_rule(ipv, _rule)

                if not enable:
                    zone_transaction.add_post(self._fw.del_mark, mark_id)
                    mark_id = None

            # SOURCE PORT
            elif type(rule.element) == Rich_SourcePort:
                port = rule.element.port
                protocol = rule.element.protocol
                self.check_port(port, protocol)

                table = "filter"
                if enable:
                    zone_transaction.add_chain(table, "INPUT")
                target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["INPUT"],
                                                    zone=zone)

                command = [ ]
                self.__rule_source(rule.source, command)
                self.__rule_destination(rule.destination, command)
                command += [ "-m", protocol, "-p", protocol,
                             "--sport", portStr(port) ]
                if type(rule.action) != Rich_Mark:
                    command += [ "-m", "conntrack", "--ctstate", "NEW" ]

                self.__rule_log(enable, ipv, table, target, rule, command,
                                zone_transaction)
                self.__rule_audit(enable, ipv, table, target, rule, command,
                                  zone_transaction)
                self.__rule_action(enable, zone, ipv, table, target, rule,
                                   command, zone_transaction)

            # ICMP BLOCK and ICMP TYPE
            elif type(rule.element) == Rich_IcmpBlock or \
                 type(rule.element) == Rich_IcmpType:
                ict = self._fw.icmptype.get_icmptype(rule.element.name)

                if type(rule.element) == Rich_IcmpBlock and \
                   rule.action and type(rule.action) == Rich_Accept:
                    # icmp block might have reject or drop action, but not accept
                    raise FirewallError(errors.INVALID_RULE,
                                        "IcmpBlock not usable with accept action")
                if ict.destination and ipv not in ict.destination:
                    raise FirewallError(
                        errors.INVALID_RULE,
                        "Icmp%s %s not usable with %s" % \
                        ("Block" if type(rule.element) == \
                         Rich_IcmpBlock else "Type",
                         rule.element.name, ipv))

                table = "filter"
                if enable:
                    zone_transaction.add_chain(table, "INPUT")
                    zone_transaction.add_chain(table, "FORWARD_IN")

                if ipv == "ipv4":
                    proto = [ "-p", "icmp" ]
                    match = [ "-m", "icmp", "--icmp-type", rule.element.name ]
                else:
                    proto = [ "-p", "ipv6-icmp" ]
                    match = [ "-m", "icmp6", "--icmpv6-type", rule.element.name ]


                # INPUT
                target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["INPUT"],
                                                    zone=zone)
                command = [ ]
                self.__rule_source(rule.source, command)
                self.__rule_destination(rule.destination, command)
                command += proto + match
                self.__rule_log(enable, ipv, table, target, rule, command,
                                zone_transaction)
                self.__rule_audit(enable, ipv, table, target, rule, command,
                                  zone_transaction)
                if rule.action:
                    self.__rule_action(enable, zone, ipv, table, target, rule,
                                       command, zone_transaction)
                else:
                    command += [ "-j", "%%REJECT%%" ]
                    _rule = [ add_del, "%s_deny" % target, "-t", table ]
                    _rule += command
                    zone_transaction.add_rule(ipv, _rule)

                # FORWARD_IN
                target = DEFAULT_ZONE_TARGET.format(
                    chain=SHORTCUTS["FORWARD_IN"], zone=zone)
                command = [ ]
                self.__rule_source(rule.source, command)
                self.__rule_destination(rule.destination, command)
                command += proto + match
                self.__rule_log(enable, ipv, table, target, rule, command,
                                zone_transaction)
                self.__rule_audit(enable, ipv, table, target, rule, command,
                                  zone_transaction)
                if rule.action:
                    self.__rule_action(enable, zone, ipv, table, target, rule,
                                       command, zone_transaction)
                else:
                    command += [ "-j", "%%REJECT%%" ]
                    _rule = [ add_del, "%s_deny" % target, "-t", table ]
                    _rule += command
                    zone_transaction.add_rule(ipv, _rule)

            elif rule.element is None:
                # source/destination action
                table = "filter"
                if enable:
                    zone_transaction.add_chain(table, "INPUT")

                target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["INPUT"],
                                                    zone=zone)
                command = [ ]
                self.__rule_source(rule.source, command)
                self.__rule_destination(rule.destination, command)
                self.__rule_log(enable, ipv, table, target, rule, command,
                                zone_transaction)
                self.__rule_audit(enable, ipv, table, target, rule, command,
                                  zone_transaction)
                self.__rule_action(enable, zone, ipv, table, target, rule,
                                   command, zone_transaction)

            # EVERYTHING ELSE
            else:
                raise FirewallError(errors.INVALID_RULE, "Unknown element %s" %
                                    type(rule.element))
        return mark_id

    def __rule(self, enable, zone, rule, mark_id, use_zone_transaction=None):
        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(zone)
        else:
            zone_transaction = use_zone_transaction

        try:
            mark = self.__rule_prepare(enable, zone, rule, mark_id,
                                       zone_transaction)
        except FirewallError as msg:
            log.warning(str(msg))
            mark = None

        if use_zone_transaction is None:
            zone_transaction.execute(enable)

        return mark

    def add_rule(self, zone, rule, timeout=0, sender=None,
                 use_zone_transaction=None):
        _zone = self._fw.check_zone(zone)
        self._fw.check_timeout(timeout)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        rule_id = self.__rule_id(rule)
        if rule_id in _obj.settings["rules"]:
            raise FirewallError(errors.ALREADY_ENABLED,
                                "'%s' already in '%s'" % (rule, _zone))

        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(_zone)
        else:
            zone_transaction = use_zone_transaction

        if _obj.applied:
            mark = self.__rule(True, _zone, rule, None,
                               use_zone_transaction=zone_transaction)
        else:
            mark = None

        self.__register_rule(_obj, rule_id, mark, timeout, sender)
        zone_transaction.add_fail(self.__unregister_rule, _obj, rule_id)

        if use_zone_transaction is None:
            zone_transaction.execute(True)

        return _zone

    def __register_rule(self, _obj, rule_id, mark, timeout, sender):
        _obj.settings["rules"][rule_id] = self.__gen_settings(
            timeout, sender, mark=mark)

    def remove_rule(self, zone, rule,
                    use_zone_transaction=None):
        _zone = self._fw.check_zone(zone)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        rule_id = self.__rule_id(rule)
        if rule_id not in _obj.settings["rules"]:
            raise FirewallError(errors.NOT_ENABLED,
                                "'%s' not in '%s'" % (rule, _zone))

        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(_zone)
        else:
            zone_transaction = use_zone_transaction

        if "mark" in _obj.settings["rules"][rule_id]:
            mark = _obj.settings["rules"][rule_id]["mark"]
        else:
            mark = None
        if _obj.applied:
            self.__rule(False, _zone, rule, mark,
                        use_zone_transaction=zone_transaction)

        zone_transaction.add_post(self.__unregister_rule, _obj, rule_id)

        if use_zone_transaction is None:
            zone_transaction.execute(True)

        return _zone

    def __unregister_rule(self, _obj, rule_id):
        if rule_id in _obj.settings["rules"]:
            del _obj.settings["rules"][rule_id]

    def query_rule(self, zone, rule):
        return self.__rule_id(rule) in self.get_settings(zone)["rules"]

    def list_rules(self, zone):
        return list(self.get_settings(zone)["rules"].keys())

    # SERVICES

    def check_service(self, service):
        self._fw.check_service(service)

    def __service_id(self, service):
        self.check_service(service)
        return service

    def __service(self, enable, zone, service, use_zone_transaction=None):
        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(zone)
        else:
            zone_transaction = use_zone_transaction

        svc = self._fw.service.get_service(service)
        helpers = self.get_helpers_for_service_modules(svc.modules, enable)

        if enable:
            if self._fw.nf_conntrack_helper_setting == 0:
                zone_transaction.add_chain("raw", "PREROUTING")
            else:
                modules = [ ]
                for helper in helpers:
                    modules.append(helper.module)
                zone_transaction.add_modules(modules)
            zone_transaction.add_chain("filter", "INPUT")

        add_del = { True: "-A", False: "-D" }[enable]
        for ipv in [ "ipv4", "ipv6" ]:
            if len(svc.destination) > 0 and ipv not in svc.destination:
                # destination is set, only use if it contains ipv
                continue

            if self._fw.nf_conntrack_helper_setting == 0:
                for helper in helpers:
                    module = helper.module
                    if helper.name not in \
                       self._fw.nf_conntrack_helpers[module]:
                        raise FirewallError(
                            errors.INVALID_HELPER,
                            "'%s' is not available in kernel" % module)
                    if helper.family != "" and helper.family != ipv:
                        # no support for family ipv, continue
                        continue
                    for (port,proto) in helper.ports:
                        target = DEFAULT_ZONE_TARGET.format(
                            chain=SHORTCUTS["PREROUTING"], zone=zone)
                        rule = [ add_del, "%s_allow" % (target), "-t", "raw",
                                 "-p", proto ]
                        if port:
                            rule += [ "--dport", "%s" % portStr(port) ]
                        if ipv in svc.destination and \
                           svc.destination[ipv] != "":
                            rule += [ "-d",  svc.destination[ipv] ]
                        rule += [ "-j", "CT", "--helper", helper.name ]
                        zone_transaction.add_rule(ipv, rule)

            # handle rules
            for (port,proto) in svc.ports:
                target = DEFAULT_ZONE_TARGET.format(
                    chain=SHORTCUTS["INPUT"], zone=zone)
                rule = [ add_del, "%s_allow" % (target), "-t", "filter",
                         "-p", proto ]
                if port:
                    rule += [ "--dport", "%s" % portStr(port) ]
                if ipv in svc.destination and svc.destination[ipv] != "":
                    rule += [ "-d",  svc.destination[ipv] ]
                rule += [ "-m", "conntrack", "--ctstate", "NEW" ]
                rule += [ "-j", "ACCEPT" ]
                zone_transaction.add_rule(ipv, rule)

            for protocol in svc.protocols:
                target = DEFAULT_ZONE_TARGET.format(
                    chain=SHORTCUTS["INPUT"], zone=zone)
                rule = [ add_del, "%s_allow" % (target),
                         "-t", "filter", "-p", protocol,
                         "-m", "conntrack", "--ctstate", "NEW",
                         "-j", "ACCEPT" ]
                zone_transaction.add_rule(ipv, rule)

            for (port,proto) in svc.source_ports:
                target = DEFAULT_ZONE_TARGET.format(
                    chain=SHORTCUTS["INPUT"], zone=zone)
                rule = [ add_del, "%s_allow" % (target), "-t", "filter",
                         "-p", proto ]
                if port:
                    rule += [ "--sport", "%s" % portStr(port) ]
                if ipv in svc.destination and svc.destination[ipv] != "":
                    rule += [ "-d",  svc.destination[ipv] ]
                rule += [ "-m", "conntrack", "--ctstate", "NEW" ]
                rule += [ "-j", "ACCEPT" ]
                zone_transaction.add_rule(ipv, rule)

        if use_zone_transaction is None:
            zone_transaction.execute(enable)

    def add_service(self, zone, service, timeout=0, sender=None,
                    use_zone_transaction=None):
        _zone = self._fw.check_zone(zone)
        self._fw.check_timeout(timeout)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        service_id = self.__service_id(service)
        if service_id in _obj.settings["services"]:
            raise FirewallError(errors.ALREADY_ENABLED,
                                "'%s' already in '%s'" % (service, _zone))

        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(_zone)
        else:
            zone_transaction = use_zone_transaction

        if _obj.applied:
            self.__service(True, _zone, service,
                           use_zone_transaction=zone_transaction)

        self.__register_service(_obj, service_id, timeout, sender)
        zone_transaction.add_fail(self.__unregister_service, _obj, service_id)

        if use_zone_transaction is None:
            zone_transaction.execute(True)

        return _zone

    def __register_service(self, _obj, service_id, timeout, sender):
        _obj.settings["services"][service_id] = \
            self.__gen_settings(timeout, sender)

    def remove_service(self, zone, service,
                       use_zone_transaction=None):
        _zone = self._fw.check_zone(zone)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        service_id = self.__service_id(service)
        if service_id not in _obj.settings["services"]:
            raise FirewallError(errors.NOT_ENABLED,
                                "'%s' not in '%s'" % (service, _zone))

        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(_zone)
        else:
            zone_transaction = use_zone_transaction

        if _obj.applied:
            self.__service(False, _zone, service,
                           use_zone_transaction=zone_transaction)

        zone_transaction.add_post(self.__unregister_service, _obj,
                                  service_id)

        if use_zone_transaction is None:
            zone_transaction.execute(True)

        return _zone

    def __unregister_service(self, _obj, service_id):
        if service_id in _obj.settings["services"]:
            del _obj.settings["services"][service_id]

    def query_service(self, zone, service):
        return self.__service_id(service) in self.get_settings(zone)["services"]

    def list_services(self, zone):
        return self.get_settings(zone)["services"].keys()

    def get_helpers_for_service_modules(self, modules, enable):
        # If automatic helper assignment is turned off, helpers that
        # do not have ports defined will be replaced by the helpers
        # that the helper.module defines.
        _helpers = [ ]
        for module in modules:
            try:
                helper = self._fw.helper.get_helper(module)
            except FirewallError:
                raise FirewallError(errors.INVALID_HELPER, module)
            if helper.module not in self._fw.nf_conntrack_helpers:
                raise FirewallError(
                    errors.INVALID_HELPER,
                    "'%s' is not available" % helper.module)
            if self._fw.nf_conntrack_helper_setting == 0 and \
               len(helper.ports) < 1:
                for mod in self._fw.nf_conntrack_helpers[helper.module]:
                    try:
                        _helper = self._fw.helper.get_helper(mod)
                    except FirewallError:
                        if enable:
                            log.warning("Helper '%s' is not available" % mod)
                        continue
                    _helpers.append(_helper)
            else:
                _helpers.append(helper)
        return _helpers

    # PORTS

    def check_port(self, port, protocol):
        self._fw.check_port(port)
        self._fw.check_tcpudp(protocol)

    def __port_id(self, port, protocol):
        self.check_port(port, protocol)
        return (portStr(port, "-"), protocol)

    def __port(self, enable, zone, port, protocol, use_zone_transaction=None):
        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(zone)
        else:
            zone_transaction = use_zone_transaction

        if enable:
            zone_transaction.add_chain("filter", "INPUT")

        add_del = { True: "-A", False: "-D" }[enable]
        for ipv in [ "ipv4", "ipv6" ]:
            target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["INPUT"],
                                                     zone=zone)
            zone_transaction.add_rule(ipv,
                                      [ add_del, "%s_allow" % (target),
                                        "-t", "filter",
                                        "-m", protocol, "-p", protocol,
                                        "--dport", portStr(port),
                                        "-m", "conntrack", "--ctstate", "NEW",
                                        "-j", "ACCEPT" ])

        if use_zone_transaction is None:
            zone_transaction.execute(enable)

    def add_port(self, zone, port, protocol, timeout=0, sender=None,
                 use_zone_transaction=None):
        _zone = self._fw.check_zone(zone)
        self._fw.check_timeout(timeout)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        port_id = self.__port_id(port, protocol)
        if port_id in _obj.settings["ports"]:
            raise FirewallError(errors.ALREADY_ENABLED,
                                "'%s:%s' already in '%s'" % (port, protocol,
                                                             _zone))

        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(_zone)
        else:
            zone_transaction = use_zone_transaction

        if _obj.applied:
            self.__port(True, _zone, port, protocol,
                        use_zone_transaction=zone_transaction)

        self.__register_port(_obj, port_id, timeout, sender)
        zone_transaction.add_fail(self.__unregister_port, _obj, port_id)

        if use_zone_transaction is None:
            zone_transaction.execute(True)

        return _zone

    def __register_port(self, _obj, port_id, timeout, sender):
        _obj.settings["ports"][port_id] = \
            self.__gen_settings(timeout, sender)

    def remove_port(self, zone, port, protocol,
                    use_zone_transaction=None):
        _zone = self._fw.check_zone(zone)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        port_id = self.__port_id(port, protocol)
        if port_id not in _obj.settings["ports"]:
            raise FirewallError(errors.NOT_ENABLED,
                                "'%s:%s' not in '%s'" % (port, protocol, _zone))

        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(_zone)
        else:
            zone_transaction = use_zone_transaction

        if _obj.applied:
            self.__port(False, _zone, port, protocol,
                        use_zone_transaction=zone_transaction)

        zone_transaction.add_post(self.__unregister_port, _obj,
                                  port_id)

        if use_zone_transaction is None:
            zone_transaction.execute(True)

        return _zone

    def __unregister_port(self, _obj, port_id):
        if port_id in _obj.settings["ports"]:
            del _obj.settings["ports"][port_id]

    def query_port(self, zone, port, protocol):
        return self.__port_id(port, protocol) in self.get_settings(zone)["ports"]

    def list_ports(self, zone):
        return list(self.get_settings(zone)["ports"].keys())

    # PROTOCOLS

    def check_protocol(self, protocol):
        if not checkProtocol(protocol):
            raise FirewallError(errors.INVALID_PROTOCOL, protocol)

    def __protocol_id(self, protocol):
        self.check_protocol(protocol)
        return protocol

    def __protocol(self, enable, zone, protocol, use_zone_transaction=None):
        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(zone)
        else:
            zone_transaction = use_zone_transaction

        if enable:
            zone_transaction.add_chain("filter", "INPUT")

        add_del = { True: "-A", False: "-D" }[enable]
        for ipv in [ "ipv4", "ipv6" ]:
            target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["INPUT"],
                                                zone=zone)
            zone_transaction.add_rule(ipv,
                                      [ add_del, "%s_allow" % (target),
                                        "-t", "filter", "-p", protocol,
                                        "-m", "conntrack", "--ctstate", "NEW",
                                        "-j", "ACCEPT" ])

        if use_zone_transaction is None:
            zone_transaction.execute(enable)

    def add_protocol(self, zone, protocol, timeout=0, sender=None,
                     use_zone_transaction=None):
        _zone = self._fw.check_zone(zone)
        self._fw.check_timeout(timeout)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        protocol_id = self.__protocol_id(protocol)
        if protocol_id in _obj.settings["protocols"]:
            raise FirewallError(errors.ALREADY_ENABLED,
                                "'%s' already in '%s'" % (protocol, _zone))

        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(_zone)
        else:
            zone_transaction = use_zone_transaction

        if _obj.applied:
            self.__protocol(True, _zone, protocol,
                            use_zone_transaction=zone_transaction)

        self.__register_protocol(_obj, protocol_id, timeout, sender)
        zone_transaction.add_fail(self.__unregister_protocol, _obj, protocol_id)

        if use_zone_transaction is None:
            zone_transaction.execute(True)

        return _zone

    def __register_protocol(self, _obj, protocol_id, timeout, sender):
        _obj.settings["protocols"][protocol_id] = \
            self.__gen_settings(timeout, sender)

    def remove_protocol(self, zone, protocol,
                        use_zone_transaction=None):
        _zone = self._fw.check_zone(zone)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        protocol_id = self.__protocol_id(protocol)
        if protocol_id not in _obj.settings["protocols"]:
            raise FirewallError(errors.NOT_ENABLED,
                                "'%s' not in '%s'" % (protocol, _zone))

        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(_zone)
        else:
            zone_transaction = use_zone_transaction

        if _obj.applied:
            self.__protocol(False, _zone, protocol,
                            use_zone_transaction=zone_transaction)

        zone_transaction.add_post(self.__unregister_protocol, _obj,
                                  protocol_id)

        if use_zone_transaction is None:
            zone_transaction.execute(True)

        return _zone

    def __unregister_protocol(self, _obj, protocol_id):
        if protocol_id in _obj.settings["protocols"]:
            del _obj.settings["protocols"][protocol_id]

    def query_protocol(self, zone, protocol):
        return self.__protocol_id(protocol) in self.get_settings(zone)["protocols"]

    def list_protocols(self, zone):
        return list(self.get_settings(zone)["protocols"].keys())

    # SOURCE PORTS

    def __source_port_id(self, port, protocol):
        self.check_port(port, protocol)
        return (portStr(port, "-"), protocol)

    def __source_port(self, enable, zone, port, protocol,
                      use_zone_transaction=None):
        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(zone)
        else:
            zone_transaction = use_zone_transaction

        if enable:
            zone_transaction.add_chain("filter", "INPUT")

        add_del = { True: "-A", False: "-D" }[enable]
        for ipv in [ "ipv4", "ipv6" ]:
            target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["INPUT"],
                                                zone=zone)
            zone_transaction.add_rule(ipv,
                                      [ add_del, "%s_allow" % (target),
                                        "-t", "filter",
                                        "-m", protocol, "-p", protocol,
                                        "--sport", portStr(port),
                                        "-m", "conntrack", "--ctstate", "NEW",
                                        "-j", "ACCEPT" ])

        if use_zone_transaction is None:
            zone_transaction.execute(enable)

    def add_source_port(self, zone, port, protocol, timeout=0, sender=None,
                        use_zone_transaction=None):
        _zone = self._fw.check_zone(zone)
        self._fw.check_timeout(timeout)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        port_id = self.__source_port_id(port, protocol)
        if port_id in _obj.settings["source_ports"]:
            raise FirewallError(errors.ALREADY_ENABLED,
                                "'%s:%s' already in '%s'" % (port, protocol,
                                                             _zone))

        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(_zone)
        else:
            zone_transaction = use_zone_transaction

        if _obj.applied:
            self.__source_port(True, _zone, port, protocol,
                               use_zone_transaction=zone_transaction)

        self.__register_source_port(_obj, port_id, timeout, sender)
        zone_transaction.add_fail(self.__unregister_source_port, _obj, port_id)

        if use_zone_transaction is None:
            zone_transaction.execute(True)

        return _zone

    def __register_source_port(self, _obj, port_id, timeout, sender):
        _obj.settings["source_ports"][port_id] = \
            self.__gen_settings(timeout, sender)

    def remove_source_port(self, zone, port, protocol,
                           use_zone_transaction=None):
        _zone = self._fw.check_zone(zone)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        port_id = self.__source_port_id(port, protocol)
        if port_id not in _obj.settings["source_ports"]:
            raise FirewallError(errors.NOT_ENABLED,
                                "'%s:%s' not in '%s'" % (port, protocol, _zone))

        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(_zone)
        else:
            zone_transaction = use_zone_transaction

        if _obj.applied:
            self.__source_port(False, _zone, port, protocol,
                               use_zone_transaction=zone_transaction)

        zone_transaction.add_post(self.__unregister_source_port, _obj,
                                  port_id)

        if use_zone_transaction is None:
            zone_transaction.execute(True)

        return _zone

    def __unregister_source_port(self, _obj, port_id):
        if port_id in _obj.settings["source_ports"]:
            del _obj.settings["source_ports"][port_id]

    def query_source_port(self, zone, port, protocol):
        return self.__source_port_id(port, protocol) in \
            self.get_settings(zone)["source_ports"]

    def list_source_ports(self, zone):
        return list(self.get_settings(zone)["source_ports"].keys())

    # MASQUERADE

    def __masquerade_id(self):
        return True

    def __masquerade(self, enable, zone, use_zone_transaction=None):
        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(zone)
        else:
            zone_transaction = use_zone_transaction

        if enable:
            zone_transaction.add_chain("nat", "POSTROUTING")
            zone_transaction.add_chain("filter", "FORWARD_OUT")
            zone_transaction.add_post(enable_ip_forwarding, "ipv4")

        add_del = { True: "-A", False: "-D" }[enable]
        for ipv in [ "ipv4" ]: # IPv4 only!
            target = DEFAULT_ZONE_TARGET.format(
                chain=SHORTCUTS["POSTROUTING"], zone=zone)
            zone_transaction.add_rule(ipv, [ add_del, "%s_allow" % (target),
                                             "!", "-o", "lo",
                                             "-t", "nat", "-j", "MASQUERADE" ])
            # FORWARD_OUT
            target = DEFAULT_ZONE_TARGET.format(
                chain=SHORTCUTS["FORWARD_OUT"], zone=zone)
            zone_transaction.add_rule(ipv, [ add_del, "%s_allow" % (target),
                                             "-t", "filter",
                                             "-m", "conntrack",
                                             "--ctstate", "NEW",
                                             "-j", "ACCEPT" ])

        if use_zone_transaction is None:
            zone_transaction.execute(enable)

    def add_masquerade(self, zone, timeout=0, sender=None,
                       use_zone_transaction=None):
        _zone = self._fw.check_zone(zone)
        self._fw.check_timeout(timeout)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        masquerade_id = self.__masquerade_id()
        if masquerade_id in _obj.settings["masquerade"]:
            raise FirewallError(errors.ALREADY_ENABLED,
                                "masquerade already enabled in '%s'" % _zone)

        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(_zone)
        else:
            zone_transaction = use_zone_transaction

        if _obj.applied:
            self.__masquerade(True, _zone,
                              use_zone_transaction=zone_transaction)

        self.__register_masquerade(_obj, masquerade_id, timeout, sender)
        zone_transaction.add_fail(self.__unregister_masquerade, _obj,
                                  masquerade_id)

        if use_zone_transaction is None:
            zone_transaction.execute(True)

        return _zone

    def __register_masquerade(self, _obj, masquerade_id, timeout, sender):
        _obj.settings["masquerade"][masquerade_id] = \
            self.__gen_settings(timeout, sender)

    def remove_masquerade(self, zone, use_zone_transaction=None):
        _zone = self._fw.check_zone(zone)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        masquerade_id = self.__masquerade_id()
        if masquerade_id not in _obj.settings["masquerade"]:
            raise FirewallError(errors.NOT_ENABLED,
                                "masquerade not enabled in '%s'" % _zone)

        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(_zone)
        else:
            zone_transaction = use_zone_transaction

        if _obj.applied:
            self.__masquerade(False, _zone,
                              use_zone_transaction=zone_transaction)

        zone_transaction.add_post(self.__unregister_masquerade, _obj,
                                  masquerade_id)

        if use_zone_transaction is None:
            zone_transaction.execute(True)

        return _zone

    def __unregister_masquerade(self, _obj, masquerade_id):
        if masquerade_id in _obj.settings["masquerade"]:
            del _obj.settings["masquerade"][masquerade_id]

    def query_masquerade(self, zone):
        return self.__masquerade_id() in self.get_settings(zone)["masquerade"]

    # PORT FORWARDING

    def check_forward_port(self, ipv, port, protocol, toport=None, toaddr=None):
        self._fw.check_port(port)
        self._fw.check_tcpudp(protocol)
        if toport:
            self._fw.check_port(toport)
        if toaddr:
            if not check_single_address(ipv, toaddr):
                raise FirewallError(errors.INVALID_ADDR, toaddr)
        if not toport and not toaddr:
            raise FirewallError(
                errors.INVALID_FORWARD,
                "port-forwarding is missing to-port AND to-addr")

    def __forward_port_id(self, port, protocol, toport=None, toaddr=None):
        self.check_forward_port("ipv4", port, protocol, toport, toaddr)
        return (portStr(port, "-"), protocol,
                portStr(toport, "-"), str(toaddr))

    def __forward_port(self, enable, zone, port, protocol, toport=None,
                       toaddr=None, mark_id=None, use_zone_transaction=None):
        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(zone)
        else:
            zone_transaction = use_zone_transaction

        mark_str = "0x%x" % mark_id
        port_str = portStr(port)

        to = ""
        if toaddr:
            to += toaddr

        filter_chain = "INPUT" if not toaddr else "FORWARD_IN"

        if toport and toport != "":
            to += ":%s" % portStr(toport, "-")

        mark = [ "-m", "mark", "--mark", mark_str ]

        if enable:
            zone_transaction.add_chain("mangle", "PREROUTING")
            zone_transaction.add_chain("nat", "PREROUTING")
            zone_transaction.add_chain("filter", filter_chain)
            zone_transaction.add_post(enable_ip_forwarding, "ipv4")

        add_del = { True: "-A", False: "-D" }[enable]
        for ipv in [ "ipv4" ]: # IPv4 only!
            target = DEFAULT_ZONE_TARGET.format(
                chain=SHORTCUTS["PREROUTING"], zone=zone)
            zone_transaction.add_rule(ipv,
                                      [ add_del, "%s_allow" % (target),
                                        "-t", "mangle",
                                        "-p", protocol, "--dport", port_str,
                                        "-j", "MARK", "--set-mark", mark_str ])
            # local and remote
            zone_transaction.add_rule(ipv,
                                      [ add_del, "%s_allow" % (target),
                                        "-t", "nat",
                                        "-p", protocol ] + mark +
                                      [ "-j", "DNAT", "--to-destination", to ])

            target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS[filter_chain],
                                                zone=zone)
            zone_transaction.add_rule(ipv,
                                      [ add_del, "%s_allow" % (target),
                                        "-t", "filter", "-m", "conntrack",
                                        "--ctstate", "NEW" ] +
                                      mark + [ "-j", "ACCEPT" ])

        zone_transaction.add_fail(self._fw.del_mark, mark_id)

        if use_zone_transaction is None:
            zone_transaction.execute(enable)

    def add_forward_port(self, zone, port, protocol, toport=None,
                         toaddr=None, timeout=0, sender=None,
                         use_zone_transaction=None):
        _zone = self._fw.check_zone(zone)
        self._fw.check_timeout(timeout)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        forward_id = self.__forward_port_id(port, protocol, toport, toaddr)
        if forward_id in _obj.settings["forward_ports"]:
            raise FirewallError(errors.ALREADY_ENABLED,
                                "'%s:%s:%s:%s' already in '%s'" % \
                                (port, protocol, toport, toaddr, _zone))

        mark = self._fw.new_mark()

        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(_zone)
        else:
            zone_transaction = use_zone_transaction

        if _obj.applied:
            self.__forward_port(True, _zone, port, protocol, toport, toaddr,
                                mark_id=mark,
                                use_zone_transaction=zone_transaction)

        self.__register_forward_port(_obj, forward_id, timeout, sender, mark)
        zone_transaction.add_fail(self.__unregister_forward_port, _obj,
                                  forward_id, mark)

        if use_zone_transaction is None:
            zone_transaction.execute(True)

        return _zone

    def __register_forward_port(self, _obj, forward_id, timeout, sender, mark):
        _obj.settings["forward_ports"][forward_id] = \
            self.__gen_settings(timeout, sender, mark=mark)

    def remove_forward_port(self, zone, port, protocol, toport=None,
                            toaddr=None, use_zone_transaction=None):
        _zone = self._fw.check_zone(zone)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        forward_id = self.__forward_port_id(port, protocol, toport, toaddr)
        if not forward_id in _obj.settings["forward_ports"]:
            raise FirewallError(errors.NOT_ENABLED,
                                "'%s:%s:%s:%s' not in '%s'" % \
                                (port, protocol, toport, toaddr, _zone))

        mark = _obj.settings["forward_ports"][forward_id]["mark"]

        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(_zone)
        else:
            zone_transaction = use_zone_transaction

        if _obj.applied:
            self.__forward_port(False, _zone, port, protocol, toport, toaddr,
                                mark_id=mark,
                                use_zone_transaction=zone_transaction)

        zone_transaction.add_post(self.__unregister_forward_port, _obj,
                                  forward_id, mark)

        if use_zone_transaction is None:
            zone_transaction.execute(True)

        return _zone

    def __unregister_forward_port(self, _obj, forward_id, mark):
        if forward_id in _obj.settings["forward_ports"]:
            del _obj.settings["forward_ports"][forward_id]
        self._fw.del_mark(mark)

    def query_forward_port(self, zone, port, protocol, toport=None,
                           toaddr=None):
        forward_id = self.__forward_port_id(port, protocol, toport, toaddr)
        return forward_id in self.get_settings(zone)["forward_ports"]

    def list_forward_ports(self, zone):
        return list(self.get_settings(zone)["forward_ports"].keys())

    # ICMP BLOCK

    def check_icmp_block(self, icmp):
        self._fw.check_icmptype(icmp)

    def __icmp_block_id(self, icmp):
        self.check_icmp_block(icmp)
        return icmp

    def __icmp_block(self, enable, zone, icmp, use_zone_transaction=None):
        ict = self._fw.icmptype.get_icmptype(icmp)

        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(zone)
        else:
            zone_transaction = use_zone_transaction

        if enable:
            zone_transaction.add_chain("filter", "INPUT")
            zone_transaction.add_chain("filter", "FORWARD_IN")

        add_del = { True: "-A", False: "-D" }[enable]
        for ipv in [ "ipv4", "ipv6" ]:
            if ict.destination and ipv not in ict.destination:
                continue

            if ipv == "ipv4":
                proto = [ "-p", "icmp" ]
                match = [ "-m", "icmp", "--icmp-type", icmp ]
            else:
                proto = [ "-p", "ipv6-icmp" ]
                match = [ "-m", "icmp6", "--icmpv6-type", icmp ]

            target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["INPUT"],
                                                zone=zone)
            if self.query_icmp_block_inversion(zone):
                final_chain = "%s_allow" % target
                final_target = "ACCEPT"
            else:
                final_chain = "%s_deny" % target
                final_target = "%%REJECT%%"
            if self._fw.get_log_denied() != "off" and final_target != "ACCEPT":
                zone_transaction.add_rule(
                    ipv,
                    [ add_del, final_chain, "-t", "filter" ] + proto + match +
                    [ "%%LOGTYPE%%", "-j", "LOG",
                      "--log-prefix", "\"%s_ICMP_BLOCK: \"" % zone ])
            zone_transaction.add_rule(ipv, [ add_del, final_chain,
                                             "-t", "filter", ] + proto +
                                      match + [ "-j", final_target ])
            target = DEFAULT_ZONE_TARGET.format(
                chain=SHORTCUTS["FORWARD_IN"], zone=zone)
            if self._fw.get_log_denied() != "off" and final_target != "ACCEPT":
                zone_transaction.add_rule(
                    ipv,
                    [ add_del, final_chain, "-t", "filter" ] + proto + match +
                    [ "%%LOGTYPE%%", "-j", "LOG",
                      "--log-prefix", "\"%s_ICMP_BLOCK: \"" % zone ])
            zone_transaction.add_rule(ipv, [ add_del, final_chain,
                                             "-t", "filter", ] + proto + \
                                      match + [ "-j", final_target ])

        if use_zone_transaction is None:
            zone_transaction.execute(enable)

    def add_icmp_block(self, zone, icmp, timeout=0, sender=None,
                       use_zone_transaction=None):
        _zone = self._fw.check_zone(zone)
        self._fw.check_timeout(timeout)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        icmp_id = self.__icmp_block_id(icmp)
        if icmp_id in _obj.settings["icmp_blocks"]:
            raise FirewallError(errors.ALREADY_ENABLED,
                                "'%s' already in '%s'" % (icmp, _zone))

        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(_zone)
        else:
            zone_transaction = use_zone_transaction

        if _obj.applied:
            self.__icmp_block(True, _zone, icmp,
                              use_zone_transaction=zone_transaction)

        self.__register_icmp_block(_obj, icmp_id, timeout, sender)
        zone_transaction.add_fail(self.__unregister_icmp_block, _obj, icmp_id)

        if use_zone_transaction is None:
            zone_transaction.execute(True)

        return _zone

    def __register_icmp_block(self, _obj, icmp_id, timeout, sender):
        _obj.settings["icmp_blocks"][icmp_id] = \
            self.__gen_settings(timeout, sender)

    def remove_icmp_block(self, zone, icmp, use_zone_transaction=None):
        _zone = self._fw.check_zone(zone)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        icmp_id = self.__icmp_block_id(icmp)
        if icmp_id not in _obj.settings["icmp_blocks"]:
            raise FirewallError(errors.NOT_ENABLED,
                                "'%s' not in '%s'" % (icmp, _zone))

        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(_zone)
        else:
            zone_transaction = use_zone_transaction

        if _obj.applied:
            self.__icmp_block(False, _zone, icmp,
                              use_zone_transaction=zone_transaction)

        zone_transaction.add_post(self.__unregister_icmp_block, _obj,
                                  icmp_id)

        if use_zone_transaction is None:
            zone_transaction.execute(True)

        return _zone

    def __unregister_icmp_block(self, _obj, icmp_id):
        if icmp_id in _obj.settings["icmp_blocks"]:
            del _obj.settings["icmp_blocks"][icmp_id]

    def query_icmp_block(self, zone, icmp):
        return self.__icmp_block_id(icmp) in self.get_settings(zone)["icmp_blocks"]

    def list_icmp_blocks(self, zone):
        return self.get_settings(zone)["icmp_blocks"].keys()

    # ICMP BLOCK INVERSION

    def __icmp_block_inversion_id(self):
        return True

    def __icmp_block_inversion(self, enable, zone, use_zone_transaction=None):
        target = self._zones[zone].target

        # Do not add general icmp accept rules into a trusted, block or drop
        # zone.
        if target in [ "DROP", "%%REJECT%%", "REJECT" ]:
            return
        if not self.query_icmp_block_inversion(zone) and target == "ACCEPT":
            # ibi target and zone target are ACCEPT, no need to add an extra
            # rule
            return

        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(zone)
        else:
            zone_transaction = use_zone_transaction

        zone_transaction.add_chain("filter", "INPUT")
        zone_transaction.add_chain("filter", "FORWARD_IN")

        for ipv in [ "ipv4", "ipv6" ]:
            rule_idx = 4
            table = "filter"
            for chain in [ "INPUT", "FORWARD_IN" ]:
                _zone = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS[chain],
                                                   zone=zone)

                if self.query_icmp_block_inversion(zone):
                    ibi_target = "%%REJECT%%"

                    if self._fw.get_log_denied() != "off":
                        if enable:
                            rule = [ "-I", _zone, str(rule_idx) ]
                        else:
                            rule = [ "-D", _zone ]

                        zone_transaction.add_rule(
                            ipv,
                            rule + [ "-t", table, "-p", "%%ICMP%%",
                                     "%%LOGTYPE%%",
                                     "-j", "LOG", "--log-prefix",
                                     "\"%s_ICMP_BLOCK: \"" % _zone ])
                        rule_idx += 1
                else:
                    ibi_target = "ACCEPT"

                if enable:
                    rule = [ "-I", _zone, str(rule_idx) ]
                else:
                    rule = [ "-D", _zone ]
                zone_transaction.add_rule(ipv,
                                          rule +
                                          [ "-t", table, "-p", "%%ICMP%%",
                                            "-j", ibi_target ])

        if use_zone_transaction is None:
            zone_transaction.execute(enable)

    def add_icmp_block_inversion(self, zone, sender=None,
                                 use_zone_transaction=None):
        _zone = self._fw.check_zone(zone)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        icmp_block_inversion_id = self.__icmp_block_inversion_id()
        if icmp_block_inversion_id in _obj.settings["icmp_block_inversion"]:
            raise FirewallError(
                errors.ALREADY_ENABLED,
                "icmp-block-inversion already enabled in '%s'" % _zone)

        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(_zone)
        else:
            zone_transaction = use_zone_transaction

        if _obj.applied:
            # undo icmp blocks
            for args in self.get_settings(_zone)["icmp_blocks"]:
                self.__icmp_block(False, _zone, args,
                                  use_zone_transaction=zone_transaction)

            self.__icmp_block_inversion(False, _zone,
                                        use_zone_transaction=zone_transaction)

        self.__register_icmp_block_inversion(_obj, icmp_block_inversion_id,
                                             sender)
        zone_transaction.add_fail(self.__undo_icmp_block_inversion, _zone, _obj,
                                  icmp_block_inversion_id)

        # redo icmp blocks
        if _obj.applied:
            for args in self.get_settings(_zone)["icmp_blocks"]:
                self.__icmp_block(True, _zone, args,
                                  use_zone_transaction=zone_transaction)

            self.__icmp_block_inversion(True, _zone,
                                        use_zone_transaction=zone_transaction)

        if use_zone_transaction is None:
            zone_transaction.execute(True)

        return _zone

    def __register_icmp_block_inversion(self, _obj, icmp_block_inversion_id,
                                        sender):
        _obj.settings["icmp_block_inversion"][icmp_block_inversion_id] = \
            self.__gen_settings(0, sender)

    def __undo_icmp_block_inversion(self, _zone, _obj, icmp_block_inversion_id):
        zone_transaction = self.new_zone_transaction(_zone)

        # undo icmp blocks
        if _obj.applied:
            for args in self.get_settings(_zone)["icmp_blocks"]:
                self.__icmp_block(False, _zone, args,
                                  use_zone_transaction=zone_transaction)

        if icmp_block_inversion_id in _obj.settings["icmp_block_inversion"]:
            del _obj.settings["icmp_block_inversion"][icmp_block_inversion_id]

        # redo icmp blocks
        if _obj.applied:
            for args in self.get_settings(_zone)["icmp_blocks"]:
                self.__icmp_block(True, _zone, args,
                                  use_zone_transaction=zone_transaction)

        zone_transaction.execute(True)

    def remove_icmp_block_inversion(self, zone, use_zone_transaction=None):
        _zone = self._fw.check_zone(zone)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        icmp_block_inversion_id = self.__icmp_block_inversion_id()
        if icmp_block_inversion_id not in _obj.settings["icmp_block_inversion"]:
            raise FirewallError(
                errors.NOT_ENABLED,
                "icmp-block-inversion not enabled in '%s'" % _zone)

        if use_zone_transaction is None:
            zone_transaction = self.new_zone_transaction(_zone)
        else:
            zone_transaction = use_zone_transaction

        if _obj.applied:
            # undo icmp blocks
            for args in self.get_settings(_zone)["icmp_blocks"]:
                self.__icmp_block(False, _zone, args,
                                  use_zone_transaction=zone_transaction)

            self.__icmp_block_inversion(False, _zone,
                                        use_zone_transaction=zone_transaction)

        self.__unregister_icmp_block_inversion(_obj,
                                               icmp_block_inversion_id)
        zone_transaction.add_fail(self.__register_icmp_block_inversion, _obj,
                                  icmp_block_inversion_id, None)

        # redo icmp blocks
        if _obj.applied:
            for args in self.get_settings(_zone)["icmp_blocks"]:
                self.__icmp_block(True, _zone, args,
                                  use_zone_transaction=zone_transaction)

            self.__icmp_block_inversion(True, _zone,
                                        use_zone_transaction=zone_transaction)

        if use_zone_transaction is None:
            zone_transaction.execute(True)

        return _zone

    def __unregister_icmp_block_inversion(self, _obj, icmp_block_inversion_id):
        if icmp_block_inversion_id in _obj.settings["icmp_block_inversion"]:
            del _obj.settings["icmp_block_inversion"][icmp_block_inversion_id]

    def query_icmp_block_inversion(self, zone):
        return self.__icmp_block_inversion_id() in \
            self.get_settings(zone)["icmp_block_inversion"]

