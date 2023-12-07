# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2011-2016 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>

import copy
from firewall.core.base import SHORTCUTS, DEFAULT_ZONE_TARGET, SOURCE_IPSET_TYPES
from firewall.core.fw_transaction import FirewallTransaction
from firewall.core.io.policy import Policy
from firewall.core.logger import log
from firewall.core.rich import (
    Rich_ForwardPort,
    Rich_IcmpBlock,
    Rich_IcmpType,
    Rich_Mark,
    Rich_Masquerade,
    Rich_Port,
    Rich_Protocol,
    Rich_Rule,
    Rich_Service,
    Rich_SourcePort,
    Rich_Tcp_Mss_Clamp,
)
from firewall.core.fw_nm import nm_get_bus_name
from firewall.functions import checkIPnMask, checkIP6nMask, check_mac
from firewall import errors
from firewall.errors import FirewallError


class FirewallZone:
    ZONE_POLICY_PRIORITY = 0

    def __init__(self, fw):
        self._fw = fw
        self._zones = {}
        self._zone_policies = {}

    def __repr__(self):
        return "%s(%r)" % (self.__class__, self._zones)

    def cleanup(self):
        self._zones.clear()
        self._zone_policies.clear()

    def new_transaction(self):
        t = FirewallTransaction(self._fw)
        t.add_pre(self._fw.full_check_config)
        return t

    def policy_name_from_zones(self, fromZone, toZone):
        return "zone_{fromZone}_{toZone}".format(fromZone=fromZone, toZone=toZone)

    # zones

    def get_zones(self):
        return sorted(self._zones.keys())

    def get_active_zones(self, append_default=True):
        active_zones = []
        for zone in self.get_zones():
            if self.list_interfaces(zone) or self.list_sources(zone):
                active_zones.append(zone)
        if append_default and self._fw._default_zone not in active_zones:
            active_zones.append(self._fw._default_zone)
        return active_zones

    def get_zone_of_interface(self, interface):
        interface_id = self.__interface_id(interface)
        for zone in self._zones:
            if interface_id in self._zones[zone].interfaces:
                # an interface can only be part of one zone
                return zone
        return None

    def get_zone_of_source(self, source):
        source_id = self.__source_id(source)
        for zone in self._zones:
            if source_id in self._zones[zone].sources:
                # a source_id can only be part of one zone
                return zone
        return None

    def get_zone(self, zone):
        z = self._fw.check_zone(zone)
        return self._zones[z]

    def policy_obj_from_zone_obj(self, z_obj, fromZone, toZone):
        p_obj = Policy()
        p_obj.derived_from_zone = z_obj.name
        p_obj.name = self.policy_name_from_zones(fromZone, toZone)
        p_obj.priority = self.ZONE_POLICY_PRIORITY
        p_obj.target = z_obj.target
        p_obj.ingress_zones = [fromZone]
        p_obj.egress_zones = [toZone]

        # copy zone permanent config to policy permanent config
        # WARN: This assumes the same attribute names.
        #
        for setting in [
            "services",
            "ports",
            "masquerade",
            "forward_ports",
            "source_ports",
            "icmp_blocks",
            "icmp_block_inversion",
            "rules_str",
            "protocols",
        ]:
            if (
                fromZone == z_obj.name
                and toZone == "HOST"
                and setting
                in [
                    "services",
                    "ports",
                    "source_ports",
                    "icmp_blocks",
                    "icmp_block_inversion",
                    "protocols",
                ]
            ):
                # zone --> HOST
                setattr(p_obj, setting, copy.deepcopy(getattr(z_obj, setting)))
            elif (
                fromZone == "ANY" and toZone == z_obj.name and setting in ["masquerade"]
            ):
                # any zone --> zone
                setattr(p_obj, setting, copy.deepcopy(getattr(z_obj, setting)))
            elif (
                fromZone == z_obj.name
                and toZone == "ANY"
                and setting in ["forward_ports"]
            ):
                # zone --> any zone
                setattr(p_obj, setting, copy.deepcopy(getattr(z_obj, setting)))
            elif setting in ["rules_str"]:
                p_obj.rules_str = []
                p_obj.rules = []
                for rule_str in z_obj.rules_str:
                    current_policy = self.policy_name_from_zones(fromZone, toZone)

                    rule = Rich_Rule(rule_str=rule_str)
                    if current_policy in self._rich_rule_to_policies(z_obj.name, rule):
                        p_obj.rules_str.append(rule_str)
                        p_obj.rules.append(rule)

        return p_obj

    def add_zone(self, obj):
        self._zones[obj.name] = obj
        self._zone_policies[obj.name] = []

        # Create policy objects, will need many:
        #   - (zone --> HOST) - ports, service, etc
        #   - (HOST --> zone) - tracking only, no zone features
        #   - (any zone --> zone) - masquerade
        #   - (zone --> any zone)
        #       - also includes forward-ports because it works on (nat,
        #       PREROUTING) and therefore applies to redirects to the local
        #       host or dnat to a different host.
        #       - also includes rich rule "mark" action for the same reason
        #
        for fromZone, toZone in [
            (obj.name, "HOST"),
            ("HOST", obj.name),
            ("ANY", obj.name),
            (obj.name, "ANY"),
        ]:
            p_obj = self.policy_obj_from_zone_obj(obj, fromZone, toZone)
            self._fw.policy.add_policy(p_obj)
            self._zone_policies[obj.name].append(p_obj.name)

    def remove_zone(self, zone):
        obj = self._zones[zone]
        if obj.applied:
            self.unapply_zone_settings(zone)
        del self._zones[zone]
        del self._zone_policies[zone]

    def apply_zones(self, use_transaction=None):
        for zone in self.get_zones():
            z_obj = self._zones[zone]
            if len(z_obj.interfaces) > 0 or len(z_obj.sources) > 0:
                log.debug1("Applying zone '%s'", zone)
                self.apply_zone_settings(zone, use_transaction=use_transaction)

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
            if len(splits) == 2 or (
                len(splits) == 3
                and splits[2] in ["pre", "log", "deny", "allow", "post"]
            ):
                return (splits[1], _chain)
        return None

    def policy_from_chain(self, chain):
        x = self.zone_from_chain(chain)
        if x is None:
            return None

        (zone, _chain) = x
        # derived from _get_table_chains_for_zone_dispatch()
        if _chain in ["PREROUTING", "FORWARD"]:
            fromZone = zone
            toZone = "ANY"
        elif _chain in ["INPUT"]:
            fromZone = zone
            toZone = "HOST"
        elif _chain in ["POSTROUTING"]:
            fromZone = "ANY"
            toZone = zone
        else:
            raise FirewallError(
                errors.INVALID_CHAIN, "chain '%s' can't be mapped to a policy" % (chain)
            )

        return (self.policy_name_from_zones(fromZone, toZone), _chain)

    def create_zone_base_by_chain(self, ipv, table, chain, use_transaction=None):
        # Create zone base chains if the chain is reserved for a zone
        if ipv in ["ipv4", "ipv6"]:
            x = self.policy_from_chain(chain)
            if x is not None:
                (policy, _chain) = self.policy_from_chain(chain)
                if use_transaction is None:
                    transaction = self.new_transaction()
                else:
                    transaction = use_transaction

                self._fw.policy.gen_chain_rules(
                    policy, True, table, _chain, transaction
                )

                if use_transaction is None:
                    transaction.execute(True)

    def _zone_settings(self, enable, zone, transaction):
        for key in ["interfaces", "sources", "forward", "icmp_block_inversion"]:
            args_list = getattr(self.get_zone(zone), key)
            if isinstance(args_list, bool):
                args_list = [args_list]
            for args in args_list:
                if key == "interfaces":
                    self._interface(enable, zone, args, transaction)
                elif key == "sources":
                    ipv = self.check_source(args)
                    self._source(enable, zone, ipv, args, transaction)
                elif key == "icmp_block_inversion":
                    continue
                elif key in ["forward", "ingress_priority", "egress_priority"]:
                    # no need to call this when applying the zone as the rules
                    # will be generated when adding the interfaces/sources
                    pass
                else:
                    log.warning(
                        "Zone '%s': Unknown setting '%s:%s', " "unable to apply",
                        zone,
                        key,
                        args,
                    )
        # ICMP-block-inversion is always applied
        if enable:
            self._icmp_block_inversion(enable, zone, transaction)

    def apply_zone_settings(self, zone, use_transaction=None):
        _zone = self._fw.check_zone(zone)
        obj = self._zones[_zone]
        if obj.applied:
            return
        obj.applied = True

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        for policy in self._zone_policies[_zone]:
            log.debug1("Applying policy (%s) derived from zone '%s'", policy, zone)
            self._fw.policy.apply_policy_settings(policy, use_transaction=transaction)

        self._zone_settings(True, _zone, transaction)

        if use_transaction is None:
            transaction.execute(True)

    def unapply_zone_settings(self, zone, use_transaction=None):
        _zone = self._fw.check_zone(zone)
        obj = self._zones[_zone]
        if not obj.applied:
            return

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        for policy in self._zone_policies[_zone]:
            self._fw.policy.unapply_policy_settings(policy, use_transaction=transaction)

        self._zone_settings(False, _zone, transaction)

        if use_transaction is None:
            transaction.execute(True)

    def get_config_with_settings(self, zone):
        """
        :return: exported config updated with runtime settings
        """
        obj = self.get_zone(zone)
        conf_dict = self.get_config_with_settings_dict(zone)
        conf_list = []
        for i in range(16):  # tuple based API has 16 elements
            if obj.IMPORT_EXPORT_STRUCTURE[i][0] not in conf_dict:
                # old API needs the empty elements as well. Grab it from the
                # class otherwise we don't know the type.
                conf_list.append(
                    copy.deepcopy(getattr(obj, obj.IMPORT_EXPORT_STRUCTURE[i][0]))
                )
            else:
                conf_list.append(conf_dict[obj.IMPORT_EXPORT_STRUCTURE[i][0]])
        return tuple(conf_list)

    def get_config_with_settings_dict(self, zone):
        """
        :return: exported config updated with runtime settings
        """
        permanent = self.get_zone(zone).export_config_dict()
        if permanent["target"] == DEFAULT_ZONE_TARGET:
            permanent["target"] = "default"
        runtime = {
            "services": self.list_services(zone),
            "ports": self.list_ports(zone),
            "icmp_blocks": self.list_icmp_blocks(zone),
            "masquerade": self.query_masquerade(zone),
            "forward_ports": self.list_forward_ports(zone),
            "interfaces": self.list_interfaces(zone),
            "sources": self.list_sources(zone),
            "rules_str": self.list_rules(zone),
            "protocols": self.list_protocols(zone),
            "source_ports": self.list_source_ports(zone),
            "icmp_block_inversion": self.query_icmp_block_inversion(zone),
            "forward": self.query_forward(zone),
        }
        return self._fw.combine_runtime_with_permanent_settings(permanent, runtime)

    def set_config_with_settings_dict(self, zone, settings, sender):
        # stupid wrappers to convert rich rule string to rich rule object
        def add_rule_wrapper(zone, rule_str, timeout=0, sender=None):
            self.add_rule(zone, Rich_Rule(rule_str=rule_str), timeout=0, sender=sender)

        def remove_rule_wrapper(zone, rule_str):
            self.remove_rule(zone, Rich_Rule(rule_str=rule_str))

        setting_to_fn = {
            "services": (self.add_service, self.remove_service),
            "ports": (self.add_port, self.remove_port),
            "icmp_blocks": (self.add_icmp_block, self.remove_icmp_block),
            "masquerade": (self.add_masquerade, self.remove_masquerade),
            "forward_ports": (self.add_forward_port, self.remove_forward_port),
            "interfaces": (self.add_interface, self.remove_interface),
            "sources": (self.add_source, self.remove_source),
            "rules_str": (add_rule_wrapper, remove_rule_wrapper),
            "protocols": (self.add_protocol, self.remove_protocol),
            "source_ports": (self.add_source_port, self.remove_source_port),
            "icmp_block_inversion": (
                self.add_icmp_block_inversion,
                self.remove_icmp_block_inversion,
            ),
            "forward": (self.add_forward, self.remove_forward),
        }

        # do a full config check on a temporary object before trying to make
        # the runtime changes
        old_obj = self.get_zone(zone)
        check_obj = copy.copy(old_obj)
        check_obj.import_config_dict(settings, self._fw.get_all_io_objects_dict())
        self._fw.full_check_config({"zones": [check_obj]})

        old_settings = self.get_config_with_settings_dict(zone)
        (add_settings, remove_settings) = self._fw.get_added_and_removed_settings(
            old_settings, settings
        )

        for key in remove_settings:
            if isinstance(remove_settings[key], list):
                for args in remove_settings[key]:
                    if isinstance(args, tuple):
                        setting_to_fn[key][1](zone, *args)
                    else:
                        setting_to_fn[key][1](zone, args)
            else:  # bool
                setting_to_fn[key][1](zone)

        for key in add_settings:
            if isinstance(add_settings[key], list):
                for args in add_settings[key]:
                    if key in ["interfaces", "sources"]:
                        # no timeout arg
                        setting_to_fn[key][0](zone, args, sender=sender)
                    else:
                        if isinstance(args, tuple):
                            setting_to_fn[key][0](zone, *args, timeout=0, sender=sender)
                        else:
                            setting_to_fn[key][0](zone, args, timeout=0, sender=sender)
            else:  # bool
                if key in ["icmp_block_inversion"]:
                    # no timeout arg
                    setting_to_fn[key][0](zone, sender=sender)
                else:
                    setting_to_fn[key][0](zone, timeout=0, sender=sender)

    # INTERFACES

    def check_interface(self, interface):
        self._fw.check_interface(interface)

    def __interface_id(self, interface):
        self.check_interface(interface)
        return interface

    def add_interface(
        self, zone, interface, sender=None, use_transaction=None, allow_apply=True
    ):
        self._fw.check_panic()
        _zone = self._fw.check_zone(zone)
        _obj = self._zones[_zone]

        interface_id = self.__interface_id(interface)

        if interface_id in _obj.interfaces:
            raise FirewallError(
                errors.ZONE_ALREADY_SET,
                "'%s' already bound to '%s'" % (interface, zone),
            )
        zoi = self.get_zone_of_interface(interface)
        if zoi is not None:
            raise FirewallError(
                errors.ZONE_CONFLICT, "'%s' already bound to '%s'" % (interface, zoi)
            )

        log.debug1("Setting zone of interface '%s' to '%s'" % (interface, _zone))

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if not _obj.applied and allow_apply:
            self.apply_zone_settings(zone, use_transaction=transaction)
            transaction.add_fail(self.set_zone_applied, _zone, False)

        if allow_apply:
            self._interface(True, _zone, interface, transaction)

        self.__register_interface(_obj, interface_id, zone, sender)
        transaction.add_fail(self.__unregister_interface, _obj, interface_id)

        if use_transaction is None:
            transaction.execute(True)

        return _zone

    def __register_interface(self, _obj, interface_id, zone, sender):
        _obj.interfaces.append(interface_id)
        if not zone or zone == "":
            self._fw._default_zone_interfaces.append(interface_id)
        if sender == nm_get_bus_name():
            self._fw._nm_assigned_interfaces.append(interface_id)

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

    def remove_interface(self, zone, interface, use_transaction=None):
        self._fw.check_panic()
        zoi = self.get_zone_of_interface(interface)
        if zoi is None:
            raise FirewallError(
                errors.UNKNOWN_INTERFACE, "'%s' is not in any zone" % interface
            )
        _zone = zoi if zone == "" else self._fw.check_zone(zone)
        if zoi != _zone:
            raise FirewallError(
                errors.ZONE_CONFLICT,
                "remove_interface(%s, %s): zoi='%s'" % (zone, interface, zoi),
            )

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        _obj = self._zones[_zone]
        interface_id = self.__interface_id(interface)
        transaction.add_post(self.__unregister_interface, _obj, interface_id)
        self._interface(False, _zone, interface, transaction)

        if use_transaction is None:
            transaction.execute(True)

        return _zone

    def __unregister_interface(self, _obj, interface_id):
        if interface_id in _obj.interfaces:
            _obj.interfaces.remove(interface_id)
        if interface_id in self._fw._default_zone_interfaces:
            self._fw._default_zone_interfaces.remove(interface_id)
        if interface_id in self._fw._nm_assigned_interfaces:
            self._fw._nm_assigned_interfaces.remove(interface_id)

    def query_interface(self, zone, interface):
        return self.__interface_id(interface) in self.get_zone(zone).interfaces

    def list_interfaces(self, zone):
        return self.get_zone(zone).interfaces

    # SOURCES

    def check_source(self, source, applied=False):
        if checkIPnMask(source):
            return "ipv4"
        elif checkIP6nMask(source):
            return "ipv6"
        elif check_mac(source):
            return ""
        elif source.startswith("ipset:"):
            self._check_ipset_type_for_source(source[6:])
            if applied:
                self._check_ipset_applied(source[6:])
            return self._ipset_family(source[6:])
        else:
            raise FirewallError(errors.INVALID_ADDR, source)

    def __source_id(self, source, applied=False):
        self.check_source(source, applied=applied)
        return source

    def add_source(
        self, zone, source, sender=None, use_transaction=None, allow_apply=True
    ):
        self._fw.check_panic()
        _zone = self._fw.check_zone(zone)
        _obj = self._zones[_zone]

        if check_mac(source):
            source = source.upper()

        ipv = self.check_source(source, applied=allow_apply)
        source_id = self.__source_id(source, applied=allow_apply)

        if source_id in _obj.sources:
            raise FirewallError(
                errors.ZONE_ALREADY_SET, "'%s' already bound to '%s'" % (source, _zone)
            )
        if self.get_zone_of_source(source) is not None:
            raise FirewallError(
                errors.ZONE_CONFLICT, "'%s' already bound to a zone" % source
            )

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if not _obj.applied and allow_apply:
            self.apply_zone_settings(zone, use_transaction=transaction)
            transaction.add_fail(self.set_zone_applied, _zone, False)

        if allow_apply:
            self._source(True, _zone, ipv, source_id, transaction)

        self.__register_source(_obj, source_id, zone, sender)
        transaction.add_fail(self.__unregister_source, _obj, source_id)

        if use_transaction is None:
            transaction.execute(True)

        return _zone

    def __register_source(self, _obj, source_id, zone, sender):
        _obj.sources.append(source_id)

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

    def remove_source(self, zone, source, use_transaction=None):
        self._fw.check_panic()
        if check_mac(source):
            source = source.upper()
        zos = self.get_zone_of_source(source)
        if zos is None:
            raise FirewallError(
                errors.UNKNOWN_SOURCE, "'%s' is not in any zone" % source
            )
        _zone = zos if zone == "" else self._fw.check_zone(zone)
        if zos != _zone:
            raise FirewallError(
                errors.ZONE_CONFLICT,
                "remove_source(%s, %s): zos='%s'" % (zone, source, zos),
            )

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        _obj = self._zones[_zone]
        ipv = self.check_source(source)
        source_id = self.__source_id(source)
        transaction.add_post(self.__unregister_source, _obj, source_id)
        self._source(False, _zone, ipv, source_id, transaction)

        if use_transaction is None:
            transaction.execute(True)

        return _zone

    def __unregister_source(self, _obj, source_id):
        if source_id in _obj.sources:
            _obj.sources.remove(source_id)

    def query_source(self, zone, source):
        if check_mac(source):
            source = source.upper()
        return self.__source_id(source) in self.get_zone(zone).sources

    def list_sources(self, zone):
        return self.get_zone(zone).sources

    def _interface_or_source_update_zone_termination(
        self, enable, zone, interface, source, transaction
    ):
        self._interface_or_source_update_policies_derived_from_zone(
            enable, zone, interface, source, transaction, last=True
        )

    def _interface_or_source_update_policies_derived_from_zone(
        self, enable, zone, interface, source, transaction, last=False
    ):
        # host <--> zone
        policy = self.policy_name_from_zones(zone, "HOST")
        self._fw.policy._ingress_egress_pair(
            enable,
            policy,
            zone,
            "HOST",
            interface,
            source,
            "",
            "",
            transaction,
            last=last,
        )
        policy = self.policy_name_from_zones("HOST", zone)
        self._fw.policy._ingress_egress_pair(
            enable,
            policy,
            "HOST",
            zone,
            "",
            "",
            interface,
            source,
            transaction,
            last=last,
        )
        # zone <--> zone
        _zoneB_list = (
            set(self.get_active_zones() + [zone])
            if interface != "+"
            else [self._fw._default_zone]
        )
        for _zoneB in _zoneB_list:
            if _zoneB != zone and not self.get_zone(_zoneB).applied:
                continue

            _zoneB_interfaces = list(self.list_interfaces(_zoneB))
            _zoneB_sources = list(self.list_sources(_zoneB))
            if zone == _zoneB and interface and interface not in _zoneB_interfaces:
                # include the interface that's currently being activated
                _zoneB_interfaces.append(interface)
            if zone == _zoneB and source and source not in _zoneB_sources:
                _zoneB_sources.append(source)
            # Need to consider dispatch to the default zone as well.
            if interface == "+":
                _zoneB_interfaces = ["+"]
                _zoneB_sources = []
            elif _zoneB == self._fw._default_zone and "+" not in _zoneB_interfaces:
                _zoneB_interfaces.append("+")

            for _zoneB_interface in _zoneB_interfaces:
                policy = self.policy_name_from_zones(zone, "ANY")
                self._fw.policy._ingress_egress_pair(
                    enable,
                    policy,
                    zone,
                    _zoneB,
                    interface,
                    source,
                    _zoneB_interface,
                    "",
                    transaction,
                    last=last,
                )
                policy = self.policy_name_from_zones("ANY", zone)
                self._fw.policy._ingress_egress_pair(
                    enable,
                    policy,
                    _zoneB,
                    zone,
                    _zoneB_interface,
                    "",
                    interface,
                    source,
                    transaction,
                    last=last,
                )
                if interface != _zoneB_interface:
                    policy = self.policy_name_from_zones(_zoneB, "ANY")
                    self._fw.policy._ingress_egress_pair(
                        enable,
                        policy,
                        _zoneB,
                        zone,
                        _zoneB_interface,
                        "",
                        interface,
                        source,
                        transaction,
                        last=last,
                    )
                    policy = self.policy_name_from_zones("ANY", _zoneB)
                    self._fw.policy._ingress_egress_pair(
                        enable,
                        policy,
                        zone,
                        _zoneB,
                        interface,
                        source,
                        _zoneB_interface,
                        "",
                        transaction,
                        last=last,
                    )
            for _zoneB_source in _zoneB_sources:
                # must be same IPv4/IPv6 family!
                if source and self.check_source(source) != self.check_source(
                    _zoneB_source
                ):
                    continue
                policy = self.policy_name_from_zones(zone, "ANY")
                self._fw.policy._ingress_egress_pair(
                    enable,
                    policy,
                    zone,
                    _zoneB,
                    interface,
                    source,
                    "",
                    _zoneB_source,
                    transaction,
                    last=last,
                )
                policy = self.policy_name_from_zones("ANY", zone)
                self._fw.policy._ingress_egress_pair(
                    enable,
                    policy,
                    _zoneB,
                    zone,
                    "",
                    _zoneB_source,
                    interface,
                    source,
                    transaction,
                    last=last,
                )
                if source != _zoneB_source:
                    policy = self.policy_name_from_zones(_zoneB, "ANY")
                    self._fw.policy._ingress_egress_pair(
                        enable,
                        policy,
                        _zoneB,
                        zone,
                        "",
                        _zoneB_source,
                        interface,
                        source,
                        transaction,
                        last=last,
                    )
                    policy = self.policy_name_from_zones("ANY", _zoneB)
                    self._fw.policy._ingress_egress_pair(
                        enable,
                        policy,
                        zone,
                        _zoneB,
                        interface,
                        source,
                        "",
                        _zoneB_source,
                        transaction,
                        last=last,
                    )

    def _interface_or_source_update_policies(
        self, enable, zone, interface, source, transaction
    ):
        # update policy dispatch for any policy using this zone as an
        # ingress-zone or egress-zone
        for policy in self._fw.policy.get_policies_not_derived_from_zone():
            if enable and not self._fw.policy.get_policy(policy).applied:
                transaction.add_post(self._fw.policy.try_apply_policy_settings, policy)
            elif self._fw.policy.get_policy(policy).applied:
                if not enable:
                    transaction.add_post(
                        self._fw.policy.try_unapply_policy_settings, policy
                    )

                ingress_zone_list = self._fw.policy.list_ingress_zones(policy)
                egress_zone_list = self._fw.policy.list_egress_zones(policy)

                if "ANY" in ingress_zone_list and "ANY" in egress_zone_list:
                    self._fw.policy._ingress_zone(
                        enable,
                        policy,
                        zone,
                        transaction,
                        ingressInterface=interface,
                        ingressSource=source,
                    )
                    self._fw.policy._egress_zone(
                        enable,
                        policy,
                        zone,
                        transaction,
                        egressInterface=interface,
                        egressSource=source,
                    )
                elif "ANY" in ingress_zone_list and "HOST" in egress_zone_list:
                    self._fw.policy._ingress_zone(
                        enable,
                        policy,
                        zone,
                        transaction,
                        ingressInterface=interface,
                        ingressSource=source,
                    )
                elif "HOST" in ingress_zone_list and "ANY" in egress_zone_list:
                    self._fw.policy._egress_zone(
                        enable,
                        policy,
                        zone,
                        transaction,
                        egressInterface=interface,
                        egressSource=source,
                    )
                elif zone in ingress_zone_list and "ANY" in egress_zone_list:
                    self._fw.policy._ingress_zone(
                        enable,
                        policy,
                        zone,
                        transaction,
                        ingressInterface=interface,
                        ingressSource=source,
                    )
                    self._fw.policy._egress_zone(
                        enable,
                        policy,
                        zone,
                        transaction,
                        egressInterface=interface,
                        egressSource=source,
                    )
                elif zone in ingress_zone_list and "HOST" in egress_zone_list:
                    self._fw.policy._ingress_zone(
                        enable,
                        policy,
                        zone,
                        transaction,
                        ingressInterface=interface,
                        ingressSource=source,
                    )
                elif "ANY" in ingress_zone_list and zone in egress_zone_list:
                    self._fw.policy._ingress_zone(
                        enable,
                        policy,
                        zone,
                        transaction,
                        ingressInterface=interface,
                        ingressSource=source,
                    )
                    self._fw.policy._egress_zone(
                        enable,
                        policy,
                        zone,
                        transaction,
                        egressInterface=interface,
                        egressSource=source,
                    )
                elif "HOST" in ingress_zone_list and zone in egress_zone_list:
                    self._fw.policy._egress_zone(
                        enable,
                        policy,
                        zone,
                        transaction,
                        egressInterface=interface,
                        egressSource=source,
                    )
                elif zone in ingress_zone_list and zone in egress_zone_list:
                    self._fw.policy._ingress_zone(
                        enable,
                        policy,
                        zone,
                        transaction,
                        ingressInterface=interface,
                        ingressSource=source,
                    )
                    self._fw.policy._egress_zone(
                        enable,
                        policy,
                        zone,
                        transaction,
                        egressInterface=interface,
                        egressSource=source,
                    )
                elif zone in ingress_zone_list or "ANY" in ingress_zone_list:
                    self._fw.policy._ingress_zone(
                        enable,
                        policy,
                        zone,
                        transaction,
                        ingressInterface=interface,
                        ingressSource=source,
                    )
                elif zone in egress_zone_list or "ANY" in egress_zone_list:
                    self._fw.policy._egress_zone(
                        enable,
                        policy,
                        zone,
                        transaction,
                        egressInterface=interface,
                        egressSource=source,
                    )

    def _interface(self, enable, zone, interface, transaction):
        for backend in self._fw.enabled_backends():
            if not backend.policies_supported:
                continue
            if interface == "+":
                continue

            # intra zone forward
            policy = self.policy_name_from_zones(zone, "ANY")
            if self.get_zone(zone).forward:
                rules = backend.build_zone_forward_rules(
                    enable, zone, policy, "filter", interface=interface
                )
                transaction.add_rules(backend, rules)

        self._interface_or_source_update_zone_termination(
            enable, zone, interface, "", transaction
        )
        self._interface_or_source_update_policies_derived_from_zone(
            enable, zone, interface, "", transaction
        )
        self._interface_or_source_update_policies(
            enable, zone, interface, "", transaction
        )

    # IPSETS

    def _ipset_family(self, name):
        if self._ipset_type(name) == "hash:mac":
            return None
        return self._fw.ipset.get_family(name, applied=False)

    def _ipset_type(self, name):
        return self._fw.ipset.get_type(name, applied=False)

    def _ipset_match_flags(self, name, flag):
        return ",".join([flag] * self._fw.ipset.get_dimension(name))

    def _check_ipset_applied(self, name):
        return self._fw.ipset.check_applied(name)

    def _check_ipset_type_for_source(self, name):
        _type = self._ipset_type(name)
        if _type not in SOURCE_IPSET_TYPES:
            raise FirewallError(
                errors.INVALID_IPSET,
                "ipset '%s' with type '%s' not usable as source" % (name, _type),
            )

    def _source(self, enable, zone, ipv, source, transaction):
        # For mac source bindings ipv is an empty string, the mac source will
        # be added for ipv4 and ipv6
        for backend in (
            [self._fw.get_backend_by_ipv(ipv)] if ipv else self._fw.enabled_backends()
        ):
            if not backend.policies_supported:
                continue

            # intra zone forward
            policy = self.policy_name_from_zones(zone, "ANY")
            if self.get_zone(zone).forward:
                rules = backend.build_zone_forward_rules(
                    enable, zone, policy, "filter", source=source
                )
                transaction.add_rules(backend, rules)

        self._interface_or_source_update_zone_termination(
            enable, zone, "", source, transaction
        )
        self._interface_or_source_update_policies_derived_from_zone(
            enable, zone, "", source, transaction
        )
        self._interface_or_source_update_policies(enable, zone, "", source, transaction)

    def add_service(self, zone, service, timeout=0, sender=None):
        zone = self._fw.check_zone(zone)
        p_name = self.policy_name_from_zones(zone, "HOST")
        self._fw.policy.add_service(p_name, service, timeout, sender)
        return zone

    def remove_service(self, zone, service):
        zone = self._fw.check_zone(zone)
        p_name = self.policy_name_from_zones(zone, "HOST")
        self._fw.policy.remove_service(p_name, service)
        return zone

    def query_service(self, zone, service):
        zone = self._fw.check_zone(zone)
        p_name = self.policy_name_from_zones(zone, "HOST")
        return self._fw.policy.query_service(p_name, service)

    def list_services(self, zone):
        zone = self._fw.check_zone(zone)
        p_name = self.policy_name_from_zones(zone, "HOST")
        return self._fw.policy.list_services(p_name)

    def add_port(self, zone, port, protocol, timeout=0, sender=None):
        zone = self._fw.check_zone(zone)
        p_name = self.policy_name_from_zones(zone, "HOST")
        self._fw.policy.add_port(p_name, port, protocol, timeout, sender)
        return zone

    def remove_port(self, zone, port, protocol):
        zone = self._fw.check_zone(zone)
        p_name = self.policy_name_from_zones(zone, "HOST")
        self._fw.policy.remove_port(p_name, port, protocol)
        return zone

    def query_port(self, zone, port, protocol):
        zone = self._fw.check_zone(zone)
        p_name = self.policy_name_from_zones(zone, "HOST")
        return self._fw.policy.query_port(p_name, port, protocol)

    def list_ports(self, zone):
        zone = self._fw.check_zone(zone)
        p_name = self.policy_name_from_zones(zone, "HOST")
        return self._fw.policy.list_ports(p_name)

    def add_source_port(self, zone, source_port, protocol, timeout=0, sender=None):
        zone = self._fw.check_zone(zone)
        p_name = self.policy_name_from_zones(zone, "HOST")
        self._fw.policy.add_source_port(p_name, source_port, protocol, timeout, sender)
        return zone

    def remove_source_port(self, zone, source_port, protocol):
        zone = self._fw.check_zone(zone)
        p_name = self.policy_name_from_zones(zone, "HOST")
        self._fw.policy.remove_source_port(p_name, source_port, protocol)
        return zone

    def query_source_port(self, zone, source_port, protocol):
        zone = self._fw.check_zone(zone)
        p_name = self.policy_name_from_zones(zone, "HOST")
        return self._fw.policy.query_source_port(p_name, source_port, protocol)

    def list_source_ports(self, zone):
        zone = self._fw.check_zone(zone)
        p_name = self.policy_name_from_zones(zone, "HOST")
        return self._fw.policy.list_source_ports(p_name)

    def _rich_rule_to_policies(self, zone, rule):
        zone = self._fw.check_zone(zone)
        if isinstance(rule.action, Rich_Mark):
            return [self.policy_name_from_zones(zone, "ANY")]
        elif isinstance(
            rule.element,
            (
                Rich_Service,
                Rich_Port,
                Rich_Protocol,
                Rich_SourcePort,
                Rich_IcmpBlock,
                Rich_IcmpType,
            ),
        ):
            return [self.policy_name_from_zones(zone, "HOST")]
        elif isinstance(rule.element, Rich_ForwardPort):
            return [self.policy_name_from_zones(zone, "ANY")]
        elif isinstance(rule.element, Rich_Masquerade):
            return [self.policy_name_from_zones("ANY", zone)]
        elif isinstance(rule.element, Rich_Tcp_Mss_Clamp):
            return [self.policy_name_from_zones(zone, "ANY")]
        elif rule.element is None:
            return [self.policy_name_from_zones(zone, "HOST")]
        else:
            raise FirewallError(
                errors.INVALID_RULE,
                "Rich rule type (%s) not handled." % (type(rule.element)),
            )

    def add_rule(self, zone, rule, timeout=0, sender=None):
        for p_name in self._rich_rule_to_policies(zone, rule):
            self._fw.policy.add_rule(p_name, rule, timeout, sender)
        return zone

    def remove_rule(self, zone, rule):
        for p_name in self._rich_rule_to_policies(zone, rule):
            self._fw.policy.remove_rule(p_name, rule)
        return zone

    def query_rule(self, zone, rule):
        ret = True
        for p_name in self._rich_rule_to_policies(zone, rule):
            ret = ret and self._fw.policy.query_rule(p_name, rule)
        return ret

    def list_rules(self, zone):
        zone = self._fw.check_zone(zone)
        ret = set()
        for p_name in [
            self.policy_name_from_zones(zone, "ANY"),
            self.policy_name_from_zones(zone, "HOST"),
            self.policy_name_from_zones("ANY", zone),
        ]:
            ret.update(set(self._fw.policy.list_rules(p_name)))
        return list(ret)

    def add_protocol(self, zone, protocol, timeout=0, sender=None):
        zone = self._fw.check_zone(zone)
        p_name = self.policy_name_from_zones(zone, "HOST")
        self._fw.policy.add_protocol(p_name, protocol, timeout, sender)
        return zone

    def remove_protocol(self, zone, protocol):
        zone = self._fw.check_zone(zone)
        p_name = self.policy_name_from_zones(zone, "HOST")
        self._fw.policy.remove_protocol(p_name, protocol)
        return zone

    def query_protocol(self, zone, protocol):
        zone = self._fw.check_zone(zone)
        p_name = self.policy_name_from_zones(zone, "HOST")
        return self._fw.policy.query_protocol(p_name, protocol)

    def list_protocols(self, zone):
        zone = self._fw.check_zone(zone)
        p_name = self.policy_name_from_zones(zone, "HOST")
        return self._fw.policy.list_protocols(p_name)

    def add_masquerade(self, zone, timeout=0, sender=None):
        zone = self._fw.check_zone(zone)
        p_name = self.policy_name_from_zones("ANY", zone)
        self._fw.policy.add_masquerade(p_name, timeout, sender)
        return zone

    def remove_masquerade(self, zone):
        zone = self._fw.check_zone(zone)
        p_name = self.policy_name_from_zones("ANY", zone)
        self._fw.policy.remove_masquerade(p_name)
        return zone

    def query_masquerade(self, zone):
        zone = self._fw.check_zone(zone)
        p_name = self.policy_name_from_zones("ANY", zone)
        return self._fw.policy.query_masquerade(p_name)

    def add_forward_port(
        self, zone, port, protocol, toport=None, toaddr=None, timeout=0, sender=None
    ):
        zone = self._fw.check_zone(zone)
        p_name = self.policy_name_from_zones(zone, "ANY")
        self._fw.policy.add_forward_port(
            p_name, port, protocol, toport, toaddr, timeout, sender
        )
        return zone

    def remove_forward_port(self, zone, port, protocol, toport=None, toaddr=None):
        zone = self._fw.check_zone(zone)
        p_name = self.policy_name_from_zones(zone, "ANY")
        self._fw.policy.remove_forward_port(p_name, port, protocol, toport, toaddr)
        return zone

    def query_forward_port(self, zone, port, protocol, toport=None, toaddr=None):
        zone = self._fw.check_zone(zone)
        p_name = self.policy_name_from_zones(zone, "ANY")
        return self._fw.policy.query_forward_port(
            p_name, port, protocol, toport, toaddr
        )

    def list_forward_ports(self, zone):
        zone = self._fw.check_zone(zone)
        p_name = self.policy_name_from_zones(zone, "ANY")
        return self._fw.policy.list_forward_ports(p_name)

    def add_icmp_block(self, zone, icmp, timeout=0, sender=None):
        zone = self._fw.check_zone(zone)
        p_name = self.policy_name_from_zones(zone, "HOST")
        self._fw.policy.add_icmp_block(p_name, icmp, timeout, sender)

        return zone

    def remove_icmp_block(self, zone, icmp):
        zone = self._fw.check_zone(zone)
        p_name = self.policy_name_from_zones(zone, "HOST")
        self._fw.policy.remove_icmp_block(p_name, icmp)

        return zone

    def query_icmp_block(self, zone, icmp):
        zone = self._fw.check_zone(zone)
        p_name_host = self.policy_name_from_zones(zone, "HOST")
        return self._fw.policy.query_icmp_block(p_name_host, icmp)

    def list_icmp_blocks(self, zone):
        zone = self._fw.check_zone(zone)
        p_name_host = self.policy_name_from_zones(zone, "HOST")
        return sorted(set(self._fw.policy.list_icmp_blocks(p_name_host)))

    def add_icmp_block_inversion(self, zone, sender=None):
        zone = self._fw.check_zone(zone)
        p_name = self.policy_name_from_zones(zone, "HOST")
        self._fw.policy.add_icmp_block_inversion(p_name, sender)

        return zone

    def _icmp_block_inversion(self, enable, zone, transaction):
        zone = self._fw.check_zone(zone)
        p_name = self.policy_name_from_zones(zone, "HOST")
        self._fw.policy._icmp_block_inversion(enable, p_name, transaction)

    def remove_icmp_block_inversion(self, zone):
        zone = self._fw.check_zone(zone)
        p_name = self.policy_name_from_zones(zone, "HOST")
        self._fw.policy.remove_icmp_block_inversion(p_name)

        return zone

    def query_icmp_block_inversion(self, zone):
        zone = self._fw.check_zone(zone)
        p_name_host = self.policy_name_from_zones(zone, "HOST")
        return self._fw.policy.query_icmp_block_inversion(p_name_host)

    def _forward(self, enable, zone, transaction):
        p_name = self.policy_name_from_zones(zone, "ANY")

        for interface in self._zones[zone].interfaces:
            for backend in self._fw.enabled_backends():
                if not backend.policies_supported:
                    continue
                rules = backend.build_zone_forward_rules(
                    enable, zone, p_name, "filter", interface=interface
                )
                transaction.add_rules(backend, rules)

        for source in self._zones[zone].sources:
            ipv = self.check_source(source)
            for backend in (
                [self._fw.get_backend_by_ipv(ipv)]
                if ipv
                else self._fw.enabled_backends()
            ):
                if not backend.policies_supported:
                    continue
                rules = backend.build_zone_forward_rules(
                    enable, zone, p_name, "filter", source=source
                )
                transaction.add_rules(backend, rules)

    def add_forward(self, zone, timeout=0, sender=None, use_transaction=None):
        _zone = self._fw.check_zone(zone)
        self._fw.check_timeout(timeout)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        if _obj.forward:
            raise FirewallError(
                errors.ALREADY_ENABLED, "forward already enabled in '%s'" % _zone
            )

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            self._forward(True, _zone, transaction)

        self.__register_forward(_obj, timeout, sender)
        transaction.add_fail(self.__unregister_forward, _obj)

        if use_transaction is None:
            transaction.execute(True)

        return _zone

    def __register_forward(self, _obj, timeout, sender):
        _obj.forward = True

    def remove_forward(self, zone, use_transaction=None):
        _zone = self._fw.check_zone(zone)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        if not _obj.forward:
            raise FirewallError(
                errors.NOT_ENABLED, "forward not enabled in '%s'" % _zone
            )

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            self._forward(False, _zone, transaction)

        transaction.add_post(self.__unregister_forward, _obj)

        if use_transaction is None:
            transaction.execute(True)

        return _zone

    def __unregister_forward(self, _obj):
        _obj.forward = False

    def query_forward(self, zone):
        return self.get_zone(zone).forward
