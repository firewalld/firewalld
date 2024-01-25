#
# SPDX-License-Identifier: GPL-2.0-or-later

import copy

from firewall.core.logger import log
from firewall.functions import (
    portStr,
    checkIPnMask,
    checkIP6nMask,
    checkProtocol,
    enable_ip_forwarding,
    check_single_address,
    portInPortRange,
    get_nf_conntrack_short_name,
    coalescePortRange,
    breakPortRange,
    checkTcpMssClamp,
)
from firewall.core.rich import (
    Rich_Rule,
    Rich_Accept,
    Rich_Service,
    Rich_Port,
    Rich_Protocol,
    Rich_Masquerade,
    Rich_ForwardPort,
    Rich_SourcePort,
    Rich_IcmpBlock,
    Rich_IcmpType,
    Rich_Tcp_Mss_Clamp,
)
from firewall.core.fw_transaction import FirewallTransaction
from firewall import errors
from firewall.errors import FirewallError
from firewall.core.base import SOURCE_IPSET_TYPES


class FirewallPolicy:
    def __init__(self, fw):
        self._fw = fw
        self._chains = {}
        self._policies = {}

    def __repr__(self):
        return "%s(%r, %r)" % (self.__class__, self._chains, self._policies)

    def cleanup(self):
        self._chains.clear()
        self._policies.clear()

    # transaction

    def new_transaction(self):
        t = FirewallTransaction(self._fw)
        t.add_pre(self._fw.full_check_config)
        return t

    # policies

    def get_policies(self):
        return sorted(self._policies.keys())

    def get_policies_not_derived_from_zone(self):
        policies = []
        for p in self.get_policies():
            p_obj = self.get_policy(p)
            if not p_obj.derived_from_zone:
                policies.append(p)
        return sorted(policies)

    def get_active_policies_not_derived_from_zone(self):
        active_policies = []
        for policy in self.get_policies_not_derived_from_zone():
            p_obj = self.get_policy(policy)
            if (
                set(p_obj.ingress_zones)
                & set(self._fw.zone.get_active_zones() + ["HOST", "ANY"])
            ) and (
                set(p_obj.egress_zones)
                & set(self._fw.zone.get_active_zones() + ["HOST", "ANY"])
            ):
                active_policies.append(policy)

        return active_policies

    def get_policy(self, policy):
        p = self._fw.check_policy(policy)
        return self._policies[p]

    def add_policy(self, obj):
        self._policies[obj.name] = obj

    def remove_policy(self, policy):
        obj = self._policies[policy]
        if obj.applied:
            self.unapply_policy_settings(policy)
        del self._policies[policy]

    def apply_policies(self, use_transaction=None):
        for policy in self.get_policies():
            p_obj = self._policies[policy]
            if p_obj.derived_from_zone:
                continue
            if policy in self.get_active_policies_not_derived_from_zone():
                log.debug1("Applying policy '%s'", policy)
                self.apply_policy_settings(policy, use_transaction=use_transaction)

    def set_policy_applied(self, policy, applied):
        obj = self._policies[policy]
        obj.applied = applied

    def _policy_settings(self, enable, policy, use_transaction=None):
        _policy = self._fw.check_policy(policy)
        obj = self._policies[_policy]
        if (enable and obj.applied) or (not enable and not obj.applied):
            return
        if enable:
            obj.applied = True

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if enable:
            # build the base chain layout of the policy
            for table, chain in (
                self._get_table_chains_for_policy_dispatch(policy)
                if not obj.derived_from_zone
                else self._get_table_chains_for_zone_dispatch(policy)
            ):
                self.gen_chain_rules(policy, True, table, chain, transaction)

        for key in [
            "services",
            "ports",
            "masquerade",
            "forward_ports",
            "source_ports",
            "icmp_blocks",
            "rules_str",
            "protocols",
            "icmp_block_inversion",
            "ingress_zones",
            "egress_zones",
        ]:
            args_list = getattr(self.get_policy(policy), key)
            if isinstance(args_list, bool):
                if not ((enable and args_list) or (not enable and args_list)):
                    continue
                args_list = [args_list]
            for args in args_list:
                if key == "icmp_blocks":
                    self._icmp_block(enable, _policy, args, transaction)
                elif key == "icmp_block_inversion":
                    continue
                elif key == "forward_ports":
                    self._forward_port(enable, _policy, transaction, *args)
                elif key == "services":
                    self._service(enable, _policy, args, transaction)
                elif key == "ports":
                    self._port(enable, _policy, args[0], args[1], transaction)
                elif key == "protocols":
                    self._protocol(enable, _policy, args, transaction)
                elif key == "source_ports":
                    self._source_port(enable, _policy, args[0], args[1], transaction)
                elif key == "masquerade":
                    self._masquerade(enable, _policy, transaction)
                elif key == "rules_str":
                    self.__rule(enable, _policy, Rich_Rule(rule_str=args), transaction)
                elif key == "ingress_zones":
                    if not obj.derived_from_zone:
                        self._ingress_zone(enable, _policy, args, transaction)
                elif key == "egress_zones":
                    # key off ingress zones, which also considers egress zones
                    continue
                else:
                    log.warning(
                        "Policy '%s': Unknown setting '%s:%s', " "unable to apply",
                        policy,
                        key,
                        args,
                    )

        if not enable:
            for table, chain in (
                self._get_table_chains_for_policy_dispatch(policy)
                if not obj.derived_from_zone
                else self._get_table_chains_for_zone_dispatch(policy)
            ):
                self.gen_chain_rules(policy, False, table, chain, transaction)
            obj.applied = False

        if use_transaction is None:
            transaction.execute(enable)

    def apply_policy_settings(self, policy, use_transaction=None):
        self._policy_settings(True, policy, use_transaction=use_transaction)

    def try_apply_policy_settings(self, policy, use_transaction=None):
        if policy in self.get_active_policies_not_derived_from_zone():
            self.apply_policy_settings(policy, use_transaction=use_transaction)

    def unapply_policy_settings(self, policy, use_transaction=None):
        self._policy_settings(False, policy, use_transaction=use_transaction)

    def try_unapply_policy_settings(self, policy, use_transaction=None):
        if policy not in self.get_active_policies_not_derived_from_zone():
            self.unapply_policy_settings(policy, use_transaction=use_transaction)

    def get_config_with_settings_dict(self, policy):
        return self.get_policy(policy).export_config_dict()

    def set_config_with_settings_dict(self, policy, settings, sender):
        # stupid wrappers to convert rich rule string to rich rule object
        from firewall.core.rich import Rich_Rule

        def add_rule_wrapper(policy, rule_str, timeout=0, sender=None):
            self.add_rule(
                policy, Rich_Rule(rule_str=rule_str), timeout=0, sender=sender
            )

        def remove_rule_wrapper(policy, rule_str):
            self.remove_rule(policy, Rich_Rule(rule_str=rule_str))

        setting_to_fn = {
            "services": (self.add_service, self.remove_service),
            "ports": (self.add_port, self.remove_port),
            "icmp_blocks": (self.add_icmp_block, self.remove_icmp_block),
            "masquerade": (self.add_masquerade, self.remove_masquerade),
            "forward_ports": (self.add_forward_port, self.remove_forward_port),
            "rich_rules": (add_rule_wrapper, remove_rule_wrapper),
            "protocols": (self.add_protocol, self.remove_protocol),
            "source_ports": (self.add_source_port, self.remove_source_port),
            "ingress_zones": (self.add_ingress_zone, self.remove_ingress_zone),
            "egress_zones": (self.add_egress_zone, self.remove_egress_zone),
        }

        # do a full config check on a temporary object before trying to make
        # the runtime changes
        old_obj = self.get_policy(policy)
        check_obj = copy.copy(old_obj)
        check_obj.import_config_dict(settings, self._fw.get_all_io_objects_dict())
        self._fw.full_check_config({"policies": [check_obj]})

        old_settings = self.get_config_with_settings_dict(policy)
        (add_settings, remove_settings) = self._fw.get_added_and_removed_settings(
            old_settings, settings
        )

        for key in remove_settings:
            if isinstance(remove_settings[key], list):
                for args in remove_settings[key]:
                    if isinstance(args, tuple):
                        setting_to_fn[key][1](policy, *args)
                    else:
                        setting_to_fn[key][1](policy, args)
            else:  # bool
                setting_to_fn[key][1](policy)

        for key in add_settings:
            if isinstance(add_settings[key], list):
                for args in add_settings[key]:
                    if isinstance(args, tuple):
                        setting_to_fn[key][0](policy, *args, timeout=0, sender=sender)
                    else:
                        setting_to_fn[key][0](policy, args, timeout=0, sender=sender)
            else:  # bool
                setting_to_fn[key][0](policy, timeout=0, sender=sender)

    # ingress zones

    def check_ingress_zone(self, zone):
        if not zone:
            raise FirewallError(errors.INVALID_ZONE)
        if zone not in ["HOST", "ANY"]:
            self._fw.check_zone(zone)

    def __ingress_zone_id(self, zone):
        self.check_ingress_zone(zone)
        return zone

    def add_ingress_zone(
        self, policy, zone, timeout=0, sender=None, use_transaction=None
    ):
        _policy = self._fw.check_policy(policy)
        self._fw.check_timeout(timeout)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        zone_id = self.__ingress_zone_id(zone)
        if zone_id in _obj.ingress_zones:
            raise FirewallError(
                errors.ALREADY_ENABLED, "'%s' already in '%s'" % (zone, _policy)
            )

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            self._ingress_zone(True, _policy, zone, transaction)

        self.__register_ingress_zone(_obj, zone_id, timeout, sender)
        transaction.add_fail(self.__unregister_ingress_zone, _obj, zone_id)

        if not _obj.applied:
            self.try_apply_policy_settings(policy, use_transaction=transaction)

        if use_transaction is None:
            transaction.execute(True)

    def __register_ingress_zone(self, _obj, zone_id, timeout, sender):
        _obj.ingress_zones.append(zone_id)

    def remove_ingress_zone(self, policy, zone, use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        zone_id = self.__ingress_zone_id(zone)
        if zone_id not in _obj.ingress_zones:
            raise FirewallError(
                errors.NOT_ENABLED, "'%s' not in '%s'" % (zone, _policy)
            )

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            if len(_obj.ingress_zones) <= 1:
                self.unapply_policy_settings(policy, use_transaction=transaction)
            else:
                self._ingress_zone(False, _policy, zone, transaction)

        transaction.add_post(self.__unregister_ingress_zone, _obj, zone_id)

        if use_transaction is None:
            transaction.execute(True)

        return _policy

    def __unregister_ingress_zone(self, _obj, zone_id):
        if zone_id in _obj.ingress_zones:
            _obj.ingress_zones.remove(zone_id)

    def query_ingress_zone(self, policy, zone):
        return self.__ingress_zone_id(zone) in self.get_policy(policy).ingress_zones

    def list_ingress_zones(self, policy):
        return self.get_policy(policy).ingress_zones

    # egress zones

    def check_egress_zone(self, zone):
        if not zone:
            raise FirewallError(errors.INVALID_ZONE)
        if zone not in ["HOST", "ANY"]:
            self._fw.check_zone(zone)

    def __egress_zone_id(self, zone):
        self.check_egress_zone(zone)
        return zone

    def add_egress_zone(
        self, policy, zone, timeout=0, sender=None, use_transaction=None
    ):
        _policy = self._fw.check_policy(policy)
        self._fw.check_timeout(timeout)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        zone_id = self.__egress_zone_id(zone)
        if zone_id in _obj.egress_zones:
            raise FirewallError(
                errors.ALREADY_ENABLED, "'%s' already in '%s'" % (zone, _policy)
            )

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            self._egress_zone(True, _policy, zone, transaction)

        self.__register_egress_zone(_obj, zone_id, timeout, sender)
        transaction.add_fail(self.__unregister_egress_zone, _obj, zone_id)

        if not _obj.applied:
            self.try_apply_policy_settings(policy, use_transaction=transaction)

        if use_transaction is None:
            transaction.execute(True)

    def __register_egress_zone(self, _obj, zone_id, timeout, sender):
        _obj.egress_zones.append(zone_id)

    def remove_egress_zone(self, policy, zone, use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        zone_id = self.__egress_zone_id(zone)
        if zone_id not in _obj.egress_zones:
            raise FirewallError(
                errors.NOT_ENABLED, "'%s' not in '%s'" % (zone, _policy)
            )

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            if len(_obj.egress_zones) <= 1:
                self.unapply_policy_settings(policy, use_transaction=transaction)
            else:
                self._egress_zone(False, _policy, zone, transaction)

        transaction.add_post(self.__unregister_egress_zone, _obj, zone_id)

        if use_transaction is None:
            transaction.execute(True)

        return _policy

    def __unregister_egress_zone(self, _obj, zone_id):
        if zone_id in _obj.egress_zones:
            _obj.egress_zones.remove(zone_id)

    def query_egress_zone(self, policy, zone):
        return self.__egress_zone_id(zone) in self.get_policy(policy).egress_zones

    def list_egress_zones(self, policy):
        return self.get_policy(policy).egress_zones

    # RICH LANGUAGE

    def check_rule(self, rule):
        rule.check()

    def __rule_id(self, rule):
        self.check_rule(rule)
        return str(rule)

    def _rule_source_ipv(self, source):
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
            self._check_ipset_type_for_source(source.ipset)
            self._check_ipset_applied(source.ipset)
            return self._ipset_family(source.ipset)

        return None

    def __rule(self, enable, policy, rule, transaction):
        self._rule_prepare(enable, policy, rule, transaction)

    def add_rule(self, policy, rule, timeout=0, sender=None, use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_timeout(timeout)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        rule_id = self.__rule_id(rule)
        if rule_id in _obj.rules_str:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(
                errors.ALREADY_ENABLED, "'%s' already in '%s'" % (rule, _name)
            )

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            self.__rule(True, _policy, rule, transaction)

        self.__register_rule(_obj, rule_id, timeout, sender)
        transaction.add_fail(self.__unregister_rule, _obj, rule_id)

        if use_transaction is None:
            transaction.execute(True)

        return _policy

    def __register_rule(self, _obj, rule_id, timeout, sender):
        _obj.rules_str.append(rule_id)

    def remove_rule(self, policy, rule, use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        rule_id = self.__rule_id(rule)
        if rule_id not in _obj.rules_str:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(errors.NOT_ENABLED, "'%s' not in '%s'" % (rule, _name))

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            self.__rule(False, _policy, rule, transaction)

        transaction.add_post(self.__unregister_rule, _obj, rule_id)

        if use_transaction is None:
            transaction.execute(True)

        return _policy

    def __unregister_rule(self, _obj, rule_id):
        if rule_id in _obj.rules_str:
            _obj.rules_str.remove(rule_id)

    def query_rule(self, policy, rule):
        return self.__rule_id(rule) in self.get_policy(policy).rules_str

    def list_rules(self, policy):
        return self.get_policy(policy).rules_str

    # SERVICES

    def check_service(self, service):
        self._fw.check_service(service)

    def __service_id(self, service):
        self.check_service(service)
        return service

    def add_service(
        self, policy, service, timeout=0, sender=None, use_transaction=None
    ):
        _policy = self._fw.check_policy(policy)
        self._fw.check_timeout(timeout)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        service_id = self.__service_id(service)
        if service_id in _obj.services:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(
                errors.ALREADY_ENABLED, "'%s' already in '%s'" % (service, _name)
            )

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            self._service(True, _policy, service, transaction)

        self.__register_service(_obj, service_id, timeout, sender)
        transaction.add_fail(self.__unregister_service, _obj, service_id)

        if use_transaction is None:
            transaction.execute(True)

        return _policy

    def __register_service(self, _obj, service_id, timeout, sender):
        _obj.services.append(service_id)

    def remove_service(self, policy, service, use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        service_id = self.__service_id(service)
        if service_id not in _obj.services:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(
                errors.NOT_ENABLED, "'%s' not in '%s'" % (service, _name)
            )

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            self._service(False, _policy, service, transaction)

        transaction.add_post(self.__unregister_service, _obj, service_id)

        if use_transaction is None:
            transaction.execute(True)

        return _policy

    def __unregister_service(self, _obj, service_id):
        if service_id in _obj.services:
            _obj.services.remove(service_id)

    def query_service(self, policy, service):
        return self.__service_id(service) in self.get_policy(policy).services

    def list_services(self, policy):
        return self.get_policy(policy).services

    def get_helpers_for_service_helpers(self, helpers):
        _helpers = []
        for helper in helpers:
            try:
                _helper = self._fw.helper.get_helper(helper)
            except FirewallError:
                raise FirewallError(errors.INVALID_HELPER, helper)
            _helpers.append(_helper)
        return _helpers

    def get_helpers_for_service_modules(self, modules, enable):
        # If automatic helper assignment is turned off, helpers that
        # do not have ports defined will be replaced by the helpers
        # that the helper.module defines.
        _helpers = []
        for module in modules:
            try:
                helper = self._fw.helper.get_helper(module)
            except FirewallError:
                raise FirewallError(errors.INVALID_HELPER, module)
            if len(helper.ports) < 1:
                _module_short_name = get_nf_conntrack_short_name(helper.module)
                try:
                    _helper = self._fw.helper.get_helper(_module_short_name)
                    _helpers.append(_helper)
                except FirewallError:
                    if enable:
                        log.warning("Helper '%s' is not available" % _module_short_name)
                    continue
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

    def add_port(
        self, policy, port, protocol, timeout=0, sender=None, use_transaction=None
    ):
        _policy = self._fw.check_policy(policy)
        self._fw.check_timeout(timeout)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        existing_port_ids = list(filter(lambda x: x[1] == protocol, _obj.ports))
        for port_id in existing_port_ids:
            if portInPortRange(port, port_id[0]):
                _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
                raise FirewallError(
                    errors.ALREADY_ENABLED,
                    "'%s:%s' already in '%s'" % (port, protocol, _name),
                )

        added_ranges, removed_ranges = coalescePortRange(
            port, [_port for (_port, _protocol) in existing_port_ids]
        )

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            for range in added_ranges:
                self._port(True, _policy, portStr(range, "-"), protocol, transaction)
            for range in removed_ranges:
                self._port(False, _policy, portStr(range, "-"), protocol, transaction)

        for range in added_ranges:
            port_id = self.__port_id(range, protocol)
            self.__register_port(_obj, port_id, timeout, sender)
            transaction.add_fail(self.__unregister_port, _obj, port_id)
        for range in removed_ranges:
            port_id = self.__port_id(range, protocol)
            transaction.add_post(self.__unregister_port, _obj, port_id)

        if use_transaction is None:
            transaction.execute(True)

        return _policy

    def __register_port(self, _obj, port_id, timeout, sender):
        _obj.ports.append(port_id)

    def remove_port(self, policy, port, protocol, use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        existing_port_ids = list(filter(lambda x: x[1] == protocol, _obj.ports))
        for port_id in existing_port_ids:
            if portInPortRange(port, port_id[0]):
                break
        else:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(
                errors.NOT_ENABLED, "'%s:%s' not in '%s'" % (port, protocol, _name)
            )

        added_ranges, removed_ranges = breakPortRange(
            port, [_port for (_port, _protocol) in existing_port_ids]
        )

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            for range in added_ranges:
                self._port(True, _policy, portStr(range, "-"), protocol, transaction)
            for range in removed_ranges:
                self._port(False, _policy, portStr(range, "-"), protocol, transaction)

        for range in added_ranges:
            port_id = self.__port_id(range, protocol)
            self.__register_port(_obj, port_id, 0, None)
            transaction.add_fail(self.__unregister_port, _obj, port_id)
        for range in removed_ranges:
            port_id = self.__port_id(range, protocol)
            transaction.add_post(self.__unregister_port, _obj, port_id)

        if use_transaction is None:
            transaction.execute(True)

        return _policy

    def __unregister_port(self, _obj, port_id):
        if port_id in _obj.ports:
            _obj.ports.remove(port_id)

    def query_port(self, policy, port, protocol):
        for _port, _protocol in self.get_policy(policy).ports:
            if portInPortRange(port, _port) and protocol == _protocol:
                return True

        return False

    def list_ports(self, policy):
        return self.get_policy(policy).ports

    # PROTOCOLS

    def check_protocol(self, protocol):
        if not checkProtocol(protocol):
            raise FirewallError(errors.INVALID_PROTOCOL, protocol)

    def check_tcp_mss_clamp(self, tcp_mss_clamp_value):
        if not checkTcpMssClamp(tcp_mss_clamp_value):
            raise FirewallError(
                errors.INVALID_RULE,
                "tcp-mss-clamp value must be greater than or equal to 536, or the value 'pmtu'. Invalid value '%s'"
                % (tcp_mss_clamp_value),
            )

    def __protocol_id(self, protocol):
        self.check_protocol(protocol)
        return protocol

    def add_protocol(
        self, policy, protocol, timeout=0, sender=None, use_transaction=None
    ):
        _policy = self._fw.check_policy(policy)
        self._fw.check_timeout(timeout)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        protocol_id = self.__protocol_id(protocol)
        if protocol_id in _obj.protocols:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(
                errors.ALREADY_ENABLED, "'%s' already in '%s'" % (protocol, _name)
            )

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            self._protocol(True, _policy, protocol, transaction)

        self.__register_protocol(_obj, protocol_id, timeout, sender)
        transaction.add_fail(self.__unregister_protocol, _obj, protocol_id)

        if use_transaction is None:
            transaction.execute(True)

        return _policy

    def __register_protocol(self, _obj, protocol_id, timeout, sender):
        _obj.protocols.append(protocol_id)

    def remove_protocol(self, policy, protocol, use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        protocol_id = self.__protocol_id(protocol)
        if protocol_id not in _obj.protocols:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(
                errors.NOT_ENABLED, "'%s' not in '%s'" % (protocol, _name)
            )

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            self._protocol(False, _policy, protocol, transaction)

        transaction.add_post(self.__unregister_protocol, _obj, protocol_id)

        if use_transaction is None:
            transaction.execute(True)

        return _policy

    def __unregister_protocol(self, _obj, protocol_id):
        if protocol_id in _obj.protocols:
            _obj.protocols.remove(protocol_id)

    def query_protocol(self, policy, protocol):
        return self.__protocol_id(protocol) in self.get_policy(policy).protocols

    def list_protocols(self, policy):
        return self.get_policy(policy).protocols

    # SOURCE PORTS

    def __source_port_id(self, port, protocol):
        self.check_port(port, protocol)
        return (portStr(port, "-"), protocol)

    def add_source_port(
        self, policy, port, protocol, timeout=0, sender=None, use_transaction=None
    ):
        _policy = self._fw.check_policy(policy)
        self._fw.check_timeout(timeout)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        existing_port_ids = list(filter(lambda x: x[1] == protocol, _obj.source_ports))
        for port_id in existing_port_ids:
            if portInPortRange(port, port_id[0]):
                _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
                raise FirewallError(
                    errors.ALREADY_ENABLED,
                    "'%s:%s' already in '%s'" % (port, protocol, _name),
                )

        added_ranges, removed_ranges = coalescePortRange(
            port, [_port for (_port, _protocol) in existing_port_ids]
        )

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            for range in added_ranges:
                self._source_port(
                    True, _policy, portStr(range, "-"), protocol, transaction
                )
            for range in removed_ranges:
                self._source_port(
                    False, _policy, portStr(range, "-"), protocol, transaction
                )

        for range in added_ranges:
            port_id = self.__source_port_id(range, protocol)
            self.__register_source_port(_obj, port_id, timeout, sender)
            transaction.add_fail(self.__unregister_source_port, _obj, port_id)
        for range in removed_ranges:
            port_id = self.__source_port_id(range, protocol)
            transaction.add_post(self.__unregister_source_port, _obj, port_id)

        if use_transaction is None:
            transaction.execute(True)

        return _policy

    def __register_source_port(self, _obj, port_id, timeout, sender):
        _obj.source_ports.append(port_id)

    def remove_source_port(self, policy, port, protocol, use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        existing_port_ids = list(filter(lambda x: x[1] == protocol, _obj.source_ports))
        for port_id in existing_port_ids:
            if portInPortRange(port, port_id[0]):
                break
        else:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(
                errors.NOT_ENABLED, "'%s:%s' not in '%s'" % (port, protocol, _name)
            )

        added_ranges, removed_ranges = breakPortRange(
            port, [_port for (_port, _protocol) in existing_port_ids]
        )

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            for range in added_ranges:
                self._source_port(
                    True, _policy, portStr(range, "-"), protocol, transaction
                )
            for range in removed_ranges:
                self._source_port(
                    False, _policy, portStr(range, "-"), protocol, transaction
                )

        for range in added_ranges:
            port_id = self.__source_port_id(range, protocol)
            self.__register_source_port(_obj, port_id, 0, None)
            transaction.add_fail(self.__unregister_source_port, _obj, port_id)
        for range in removed_ranges:
            port_id = self.__source_port_id(range, protocol)
            transaction.add_post(self.__unregister_source_port, _obj, port_id)

        if use_transaction is None:
            transaction.execute(True)

        return _policy

    def __unregister_source_port(self, _obj, port_id):
        if port_id in _obj.source_ports:
            _obj.source_ports.remove(port_id)

    def query_source_port(self, policy, port, protocol):
        for _port, _protocol in self.get_policy(policy).source_ports:
            if portInPortRange(port, _port) and protocol == _protocol:
                return True

        return False

    def list_source_ports(self, policy):
        return self.get_policy(policy).source_ports

    # MASQUERADE

    def add_masquerade(self, policy, timeout=0, sender=None, use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_timeout(timeout)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        if _obj.masquerade:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(
                errors.ALREADY_ENABLED, "masquerade already enabled in '%s'" % _name
            )

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            self._masquerade(True, _policy, transaction)

        self.__register_masquerade(_obj, timeout, sender)
        transaction.add_fail(self.__unregister_masquerade, _obj)

        if use_transaction is None:
            transaction.execute(True)

        return _policy

    def __register_masquerade(self, _obj, timeout, sender):
        _obj.masquerade = True

    def remove_masquerade(self, policy, use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        if not _obj.masquerade:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(
                errors.NOT_ENABLED, "masquerade not enabled in '%s'" % _name
            )

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            self._masquerade(False, _policy, transaction)

        transaction.add_post(self.__unregister_masquerade, _obj)

        if use_transaction is None:
            transaction.execute(True)

        return _policy

    def __unregister_masquerade(self, _obj):
        _obj.masquerade = False

    def query_masquerade(self, policy):
        return self.get_policy(policy).masquerade

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
                errors.INVALID_FORWARD, "port-forwarding is missing to-port AND to-addr"
            )

    def __forward_port_id(self, port, protocol, toport=None, toaddr=None):
        if check_single_address("ipv6", toaddr):
            self.check_forward_port("ipv6", port, protocol, toport, toaddr)
        else:
            self.check_forward_port("ipv4", port, protocol, toport, toaddr)
        return (portStr(port, "-"), protocol, portStr(toport, "-"), str(toaddr))

    def add_forward_port(
        self,
        policy,
        port,
        protocol,
        toport=None,
        toaddr=None,
        timeout=0,
        sender=None,
        use_transaction=None,
    ):
        _policy = self._fw.check_policy(policy)
        self._fw.check_timeout(timeout)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        forward_id = self.__forward_port_id(port, protocol, toport, toaddr)
        if forward_id in _obj.forward_ports:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(
                errors.ALREADY_ENABLED,
                "'%s:%s:%s:%s' already in '%s'"
                % (port, protocol, toport, toaddr, _name),
            )

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            self._forward_port(
                True, _policy, transaction, port, protocol, toport, toaddr
            )

        self.__register_forward_port(_obj, forward_id, timeout, sender)
        transaction.add_fail(self.__unregister_forward_port, _obj, forward_id)

        if use_transaction is None:
            transaction.execute(True)

        return _policy

    def __register_forward_port(self, _obj, forward_id, timeout, sender):
        _obj.forward_ports.append(forward_id)

    def remove_forward_port(
        self, policy, port, protocol, toport=None, toaddr=None, use_transaction=None
    ):
        _policy = self._fw.check_policy(policy)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        forward_id = self.__forward_port_id(port, protocol, toport, toaddr)
        if forward_id not in _obj.forward_ports:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(
                errors.NOT_ENABLED,
                "'%s:%s:%s:%s' not in '%s'" % (port, protocol, toport, toaddr, _name),
            )

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            self._forward_port(
                False, _policy, transaction, port, protocol, toport, toaddr
            )

        transaction.add_post(self.__unregister_forward_port, _obj, forward_id)

        if use_transaction is None:
            transaction.execute(True)

        return _policy

    def __unregister_forward_port(self, _obj, forward_id):
        if forward_id in _obj.forward_ports:
            _obj.forward_ports.remove(forward_id)

    def query_forward_port(self, policy, port, protocol, toport=None, toaddr=None):
        forward_id = self.__forward_port_id(port, protocol, toport, toaddr)
        return forward_id in self.get_policy(policy).forward_ports

    def list_forward_ports(self, policy):
        return self.get_policy(policy).forward_ports

    # ICMP BLOCK

    def check_icmp_block(self, icmp):
        self._fw.check_icmptype(icmp)

    def __icmp_block_id(self, icmp):
        self.check_icmp_block(icmp)
        return icmp

    def add_icmp_block(
        self, policy, icmp, timeout=0, sender=None, use_transaction=None
    ):
        _policy = self._fw.check_policy(policy)
        self._fw.check_timeout(timeout)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        icmp_id = self.__icmp_block_id(icmp)
        if icmp_id in _obj.icmp_blocks:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(
                errors.ALREADY_ENABLED, "'%s' already in '%s'" % (icmp, _name)
            )

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            self._icmp_block(True, _policy, icmp, transaction)

        self.__register_icmp_block(_obj, icmp_id, timeout, sender)
        transaction.add_fail(self.__unregister_icmp_block, _obj, icmp_id)

        if use_transaction is None:
            transaction.execute(True)

        return _policy

    def __register_icmp_block(self, _obj, icmp_id, timeout, sender):
        _obj.icmp_blocks.append(icmp_id)

    def remove_icmp_block(self, policy, icmp, use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        icmp_id = self.__icmp_block_id(icmp)
        if icmp_id not in _obj.icmp_blocks:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(errors.NOT_ENABLED, "'%s' not in '%s'" % (icmp, _name))

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            self._icmp_block(False, _policy, icmp, transaction)

        transaction.add_post(self.__unregister_icmp_block, _obj, icmp_id)

        if use_transaction is None:
            transaction.execute(True)

        return _policy

    def __unregister_icmp_block(self, _obj, icmp_id):
        if icmp_id in _obj.icmp_blocks:
            _obj.icmp_blocks.remove(icmp_id)

    def query_icmp_block(self, policy, icmp):
        return self.__icmp_block_id(icmp) in self.get_policy(policy).icmp_blocks

    def list_icmp_blocks(self, policy):
        return self.get_policy(policy).icmp_blocks

    # ICMP BLOCK INVERSION

    def add_icmp_block_inversion(self, policy, sender=None, use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        if _obj.icmp_block_inversion:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(
                errors.ALREADY_ENABLED,
                "icmp-block-inversion already enabled in '%s'" % _name,
            )

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            # undo icmp blocks
            for args in _obj.icmp_blocks:
                self._icmp_block(False, _policy, args, transaction)

            self._icmp_block_inversion(False, _policy, transaction)

        self.__register_icmp_block_inversion(_obj, sender)
        transaction.add_fail(self.__undo_icmp_block_inversion, _policy, _obj)

        # redo icmp blocks
        if _obj.applied:
            for args in _obj.icmp_blocks:
                self._icmp_block(True, _policy, args, transaction)

            self._icmp_block_inversion(True, _policy, transaction)

        if use_transaction is None:
            transaction.execute(True)

        return _policy

    def __register_icmp_block_inversion(self, _obj, sender):
        _obj.icmp_block_inversion = True

    def __undo_icmp_block_inversion(self, _policy, _obj):
        transaction = self.new_transaction()

        # undo icmp blocks
        if _obj.applied:
            for args in _obj.icmp_blocks:
                self._icmp_block(False, _policy, args, transaction)

        _obj.icmp_block_inversion = False

        # redo icmp blocks
        if _obj.applied:
            for args in _obj.icmp_blocks:
                self._icmp_block(True, _policy, args, transaction)

        transaction.execute(True)

    def remove_icmp_block_inversion(self, policy, use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        if not _obj.icmp_block_inversion:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(
                errors.NOT_ENABLED, "icmp-block-inversion not enabled in '%s'" % _name
            )

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            # undo icmp blocks
            for args in _obj.icmp_blocks:
                self._icmp_block(False, _policy, args, transaction)

            self._icmp_block_inversion(False, _policy, transaction)

        self.__unregister_icmp_block_inversion(_obj)
        transaction.add_fail(self.__register_icmp_block_inversion, _obj, None)

        # redo icmp blocks
        if _obj.applied:
            for args in _obj.icmp_blocks:
                self._icmp_block(True, _policy, args, transaction)

            self._icmp_block_inversion(True, _policy, transaction)

        if use_transaction is None:
            transaction.execute(True)

        return _policy

    def __unregister_icmp_block_inversion(self, _obj):
        _obj.icmp_block_inversion = False

    def query_icmp_block_inversion(self, policy):
        return self.get_policy(policy).icmp_block_inversion

    def gen_chain_rules(self, policy, create, table, chain, transaction):
        obj = self._fw.policy.get_policy(policy)
        if obj.derived_from_zone:
            # For policies derived from zones, use only the first policy in the
            # list to track chain creation. The chain names are converted to
            # zone-based names as such they're "global" for all zone derived
            # policies.
            tracking_policy = self._fw.zone._zone_policies[obj.derived_from_zone][0]
        else:
            tracking_policy = policy

        if create:
            if (
                tracking_policy in self._chains
                and (table, chain) in self._chains[tracking_policy]
            ):
                return
        else:
            if (
                tracking_policy not in self._chains
                or (table, chain) not in self._chains[tracking_policy]
            ):
                return

        for backend in self._fw.enabled_backends():
            if backend.policies_supported and table in backend.get_available_tables():
                rules = backend.build_policy_chain_rules(create, policy, table, chain)
                transaction.add_rules(backend, rules)

        self._register_chains(tracking_policy, create, [(table, chain)])
        transaction.add_fail(
            self._register_chains, tracking_policy, not create, [(table, chain)]
        )

    def _register_chains(self, policy, create, tables):
        for table, chain in tables:
            if create:
                self._chains.setdefault(policy, []).append((table, chain))
            else:
                self._chains[policy].remove((table, chain))
                if len(self._chains[policy]) == 0:
                    del self._chains[policy]

    # IPSETS

    def _ipset_family(self, name):
        if self._fw.ipset.get_type(name) == "hash:mac":
            return None
        return self._fw.ipset.get_family(name)

    def __ipset_type(self, name):
        return self._fw.ipset.get_type(name)

    def _ipset_match_flags(self, name, flag):
        return ",".join([flag] * self._fw.ipset.get_dimension(name))

    def _check_ipset_applied(self, name):
        return self._fw.ipset.check_applied(name)

    def _check_ipset_type_for_source(self, name):
        _type = self.__ipset_type(name)
        if _type not in SOURCE_IPSET_TYPES:
            raise FirewallError(
                errors.INVALID_IPSET,
                "ipset '%s' with type '%s' not usable as source" % (name, _type),
            )

    def _rule_prepare(self, enable, policy, rule, transaction, included_services=None):
        # First apply any services this service may include
        if isinstance(rule.element, Rich_Service):
            svc = self._fw.service.get_service(rule.element.name)
            if included_services is None:
                included_services = [rule.element.name]
            for include in svc.includes:
                if include in included_services:
                    continue
                self.check_service(include)
                included_services.append(include)
                _rule = copy.deepcopy(rule)
                _rule.element.name = include
                self._rule_prepare(
                    enable,
                    policy,
                    _rule,
                    transaction,
                    included_services=included_services,
                )

        ipvs = []
        if rule.family:
            ipvs = [rule.family]
        elif rule.element and (
            isinstance(rule.element, Rich_IcmpBlock)
            or isinstance(rule.element, Rich_IcmpType)
        ):
            ict = self._fw.config.get_icmptype(rule.element.name)
            if ict.destination:
                ipvs = [ipv for ipv in ["ipv4", "ipv6"] if ipv in ict.destination]

        source_ipv = self._rule_source_ipv(rule.source)
        if source_ipv:
            if rule.family:
                # rule family is defined by user, no way to change it
                if rule.family != source_ipv:
                    raise FirewallError(
                        errors.INVALID_RULE,
                        "Source address family '%s' conflicts with rule family '%s'."
                        % (source_ipv, rule.family),
                    )
            else:
                # use the source family as rule family
                ipvs = [source_ipv]

        if not ipvs:
            ipvs = ["ipv4", "ipv6"]

        # clamp ipvs to those that are actually enabled.
        ipvs = [ipv for ipv in ipvs if self._fw.is_ipv_enabled(ipv)]

        # add an element to object to allow backends to know what ipvs this applies to
        rule.ipvs = ipvs

        for backend in set([self._fw.get_backend_by_ipv(x) for x in ipvs]):
            # SERVICE
            if isinstance(rule.element, Rich_Service):
                svc = self._fw.service.get_service(rule.element.name)

                destinations = []
                if len(svc.destination) > 0:
                    if rule.destination:
                        # we can not use two destinations at the same time
                        raise FirewallError(
                            errors.INVALID_RULE, "Destination conflict with service."
                        )
                    for ipv in ipvs:
                        if ipv in svc.destination and backend.is_ipv_supported(ipv):
                            destinations.append(svc.destination[ipv])
                else:
                    # dummy for the following for loop
                    destinations.append(None)

                for destination in destinations:
                    if isinstance(rule.action, Rich_Accept):
                        # only load modules for accept action
                        helpers = self.get_helpers_for_service_modules(
                            svc.modules, enable
                        )
                        helpers += self.get_helpers_for_service_helpers(svc.helpers)
                        helpers = sorted(set(helpers), key=lambda x: x.name)

                        modules = []
                        for helper in helpers:
                            module = helper.module
                            _module_short_name = get_nf_conntrack_short_name(module)
                            nat_module = module.replace("conntrack", "nat")
                            modules.append(nat_module)
                            if helper.family != "" and not backend.is_ipv_supported(
                                helper.family
                            ):
                                # no support for family ipv, continue
                                continue
                            if len(helper.ports) < 1:
                                modules.append(module)
                            else:
                                for port, proto in helper.ports:
                                    rules = backend.build_policy_helper_ports_rules(
                                        enable,
                                        policy,
                                        proto,
                                        port,
                                        destination,
                                        helper.name,
                                        _module_short_name,
                                    )
                                    transaction.add_rules(backend, rules)
                        transaction.add_modules(modules)

                    # create rules
                    for port, proto in svc.ports:
                        rules = backend.build_policy_ports_rules(
                            enable, policy, proto, port, destination, rule
                        )
                        transaction.add_rules(backend, rules)

                    for proto in svc.protocols:
                        rules = backend.build_policy_protocol_rules(
                            enable, policy, proto, destination, rule
                        )
                        transaction.add_rules(backend, rules)

                    # create rules
                    for port, proto in svc.source_ports:
                        rules = backend.build_policy_source_ports_rules(
                            enable, policy, proto, port, destination, rule
                        )
                        transaction.add_rules(backend, rules)

            # PORT
            elif isinstance(rule.element, Rich_Port):
                port = rule.element.port
                protocol = rule.element.protocol
                self.check_port(port, protocol)

                rules = backend.build_policy_ports_rules(
                    enable, policy, protocol, port, None, rule
                )
                transaction.add_rules(backend, rules)

            # PROTOCOL
            elif isinstance(rule.element, Rich_Protocol):
                protocol = rule.element.value
                self.check_protocol(protocol)

                rules = backend.build_policy_protocol_rules(
                    enable, policy, protocol, None, rule
                )
                transaction.add_rules(backend, rules)

            # TCP/MSS CLAMP
            elif isinstance(rule.element, Rich_Tcp_Mss_Clamp):
                tcp_mss_clamp_value = rule.element.value
                self.check_tcp_mss_clamp(tcp_mss_clamp_value)

                rules = backend.build_policy_tcp_mss_clamp_rules(
                    enable, policy, tcp_mss_clamp_value, None, rule
                )
                transaction.add_rules(backend, rules)

            # MASQUERADE
            elif isinstance(rule.element, Rich_Masquerade):
                if enable:
                    for ipv in ipvs:
                        if backend.is_ipv_supported(ipv):
                            transaction.add_post(enable_ip_forwarding, ipv)

                rules = backend.build_policy_masquerade_rules(enable, policy, rule)
                transaction.add_rules(backend, rules)

            # FORWARD PORT
            elif isinstance(rule.element, Rich_ForwardPort):
                port = rule.element.port
                protocol = rule.element.protocol
                toport = rule.element.to_port
                toaddr = rule.element.to_address
                for ipv in ipvs:
                    if backend.is_ipv_supported(ipv):
                        self.check_forward_port(ipv, port, protocol, toport, toaddr)
                    if toaddr and enable:
                        transaction.add_post(enable_ip_forwarding, ipv)

                rules = backend.build_policy_forward_port_rules(
                    enable, policy, port, protocol, toport, toaddr, rule
                )
                transaction.add_rules(backend, rules)

            # SOURCE PORT
            elif isinstance(rule.element, Rich_SourcePort):
                port = rule.element.port
                protocol = rule.element.protocol
                self.check_port(port, protocol)

                rules = backend.build_policy_source_ports_rules(
                    enable, policy, protocol, port, None, rule
                )
                transaction.add_rules(backend, rules)

            # ICMP BLOCK and ICMP TYPE
            elif isinstance(rule.element, Rich_IcmpBlock) or isinstance(
                rule.element, Rich_IcmpType
            ):
                ict = self._fw.config.get_icmptype(rule.element.name)

                if (
                    rule.family
                    and ict.destination
                    and rule.family not in ict.destination
                ):
                    raise FirewallError(
                        errors.INVALID_ICMPTYPE,
                        "rich rule family '%s' conflicts with icmp type '%s'"
                        % (rule.family, rule.element.name),
                    )

                if (
                    isinstance(rule.element, Rich_IcmpBlock)
                    and rule.action
                    and isinstance(rule.action, Rich_Accept)
                ):
                    # icmp block might have reject or drop action, but not accept
                    raise FirewallError(
                        errors.INVALID_RULE, "IcmpBlock not usable with accept action"
                    )

                rules = backend.build_policy_icmp_block_rules(enable, policy, ict, rule)
                transaction.add_rules(backend, rules)

            elif rule.element is None:
                rules = backend.build_policy_rich_source_destination_rules(
                    enable, policy, rule
                )
                transaction.add_rules(backend, rules)

            # EVERYTHING ELSE
            else:
                raise FirewallError(
                    errors.INVALID_RULE, "Unknown element %s" % type(rule.element)
                )

    def _service(self, enable, policy, service, transaction, included_services=None):
        svc = self._fw.service.get_service(service)
        helpers = self.get_helpers_for_service_modules(svc.modules, enable)
        helpers += self.get_helpers_for_service_helpers(svc.helpers)
        helpers = sorted(set(helpers), key=lambda x: x.name)

        # First apply any services this service may include
        if included_services is None:
            included_services = [service]
        for include in svc.includes:
            if include in included_services:
                continue
            self.check_service(include)
            included_services.append(include)
            self._service(
                enable,
                policy,
                include,
                transaction,
                included_services=included_services,
            )

        # build a list of (backend, destination). The destination may be ipv4,
        # ipv6 or None
        #
        backends_ipv = []
        for ipv in ["ipv4", "ipv6"]:
            if not self._fw.is_ipv_enabled(ipv):
                continue
            backend = self._fw.get_backend_by_ipv(ipv)
            if len(svc.destination) > 0:
                if ipv in svc.destination:
                    backends_ipv.append((backend, svc.destination[ipv]))
            else:
                if (backend, None) not in backends_ipv:
                    backends_ipv.append((backend, None))

        for backend, destination in backends_ipv:
            for helper in helpers:
                module = helper.module
                _module_short_name = get_nf_conntrack_short_name(module)
                nat_module = helper.module.replace("conntrack", "nat")
                transaction.add_module(nat_module)
                if helper.family != "" and not backend.is_ipv_supported(helper.family):
                    # no support for family ipv, continue
                    continue
                if len(helper.ports) < 1:
                    transaction.add_module(module)
                else:
                    for port, proto in helper.ports:
                        rules = backend.build_policy_helper_ports_rules(
                            enable,
                            policy,
                            proto,
                            port,
                            destination,
                            helper.name,
                            _module_short_name,
                        )
                        transaction.add_rules(backend, rules)

            for port, proto in svc.ports:
                rules = backend.build_policy_ports_rules(
                    enable, policy, proto, port, destination
                )
                transaction.add_rules(backend, rules)

            for protocol in svc.protocols:
                rules = backend.build_policy_protocol_rules(
                    enable, policy, protocol, destination
                )
                transaction.add_rules(backend, rules)

            for port, proto in svc.source_ports:
                rules = backend.build_policy_source_ports_rules(
                    enable, policy, proto, port, destination
                )
                transaction.add_rules(backend, rules)

    def _port(self, enable, policy, port, protocol, transaction):
        for backend in self._fw.enabled_backends():
            if not backend.policies_supported:
                continue

            rules = backend.build_policy_ports_rules(enable, policy, protocol, port)
            transaction.add_rules(backend, rules)

    def _protocol(self, enable, policy, protocol, transaction):
        for backend in self._fw.enabled_backends():
            if not backend.policies_supported:
                continue

            rules = backend.build_policy_protocol_rules(enable, policy, protocol)
            transaction.add_rules(backend, rules)

    def _source_port(self, enable, policy, port, protocol, transaction):
        for backend in self._fw.enabled_backends():
            if not backend.policies_supported:
                continue

            rules = backend.build_policy_source_ports_rules(
                enable, policy, protocol, port
            )
            transaction.add_rules(backend, rules)

    def _masquerade(self, enable, policy, transaction):
        ipv = "ipv4"
        transaction.add_post(enable_ip_forwarding, ipv)

        backend = self._fw.get_backend_by_ipv(ipv)
        rules = backend.build_policy_masquerade_rules(enable, policy)
        transaction.add_rules(backend, rules)

    def _forward_port(
        self, enable, policy, transaction, port, protocol, toport=None, toaddr=None
    ):
        if check_single_address("ipv6", toaddr):
            ipv = "ipv6"
        else:
            ipv = "ipv4"

        if toaddr and enable:
            transaction.add_post(enable_ip_forwarding, ipv)
        backend = self._fw.get_backend_by_ipv(ipv)
        rules = backend.build_policy_forward_port_rules(
            enable, policy, port, protocol, toport, toaddr
        )
        transaction.add_rules(backend, rules)

    def _icmp_block(self, enable, policy, icmp, transaction):
        ict = self._fw.config.get_icmptype(icmp)

        for backend in self._fw.enabled_backends():
            if not backend.policies_supported:
                continue
            skip_backend = False

            if ict.destination:
                for ipv in ["ipv4", "ipv6"]:
                    if ipv in ict.destination:
                        if not backend.is_ipv_supported(ipv):
                            skip_backend = True
                            break

            if skip_backend:
                continue

            rules = backend.build_policy_icmp_block_rules(enable, policy, ict)
            transaction.add_rules(backend, rules)

    def _icmp_block_inversion(self, enable, policy, transaction):
        target = self._policies[policy].target

        # Do not add general icmp accept rules into a trusted, block or drop
        # policy.
        if target in ["DROP", "%%REJECT%%", "REJECT"]:
            return
        if not self.query_icmp_block_inversion(policy) and target == "ACCEPT":
            # ibi target and policy target are ACCEPT, no need to add an extra
            # rule
            return

        for backend in self._fw.enabled_backends():
            if not backend.policies_supported:
                continue

            rules = backend.build_policy_icmp_block_inversion_rules(enable, policy)
            transaction.add_rules(backend, rules)

    def _ingress_egress_pair(
        self,
        enable,
        policy,
        ingress_zone,
        egress_zone,
        ingress_interface,
        ingress_source,
        egress_interface,
        egress_source,
        transaction,
        last=False,
    ):
        p_obj = self.get_policy(policy)
        ipv = None
        if ingress_source:
            ipv = self._fw.zone.check_source(ingress_source)
        elif egress_source:
            ipv = self._fw.zone.check_source(egress_source)

        for backend in (
            [self._fw.get_backend_by_ipv(ipv)] if ipv else self._fw.enabled_backends()
        ):
            if not backend.policies_supported:
                continue

            for table, chain in (
                self._get_table_chains_for_policy_dispatch(policy)
                if not p_obj.derived_from_zone
                else self._get_table_chains_for_zone_dispatch(policy)
            ):
                rules = backend.build_policy_ingress_egress_pair_rules(
                    enable,
                    policy,
                    table,
                    chain,
                    ingress_zone,
                    egress_zone,
                    ingress_interface,
                    ingress_source,
                    egress_interface,
                    egress_source,
                    last=last,
                )
                transaction.add_rules(backend, rules)

    def _ingress_egress_zone(
        self,
        enable,
        policy,
        ingress_zone,
        egress_zone,
        transaction,
        ingressInterface=None,
        ingressSource=None,
        egressInterface=None,
        egressSource=None,
    ):
        if ingress_zone == "ANY":
            _ingress_zones = self._fw.zone.get_active_zones()

            # include the zone currently being activated
            if egress_zone not in ["HOST", "ANY"] and egress_zone not in _ingress_zones:
                _ingress_zones.append(egress_zone)
        else:
            _ingress_zones = [ingress_zone]
        if egress_zone == "ANY":
            _egress_zones = self._fw.zone.get_active_zones()

            # include the zone currently being activated
            if (
                ingress_zone not in ["HOST", "ANY"]
                and ingress_zone not in _egress_zones
            ):
                _egress_zones.append(ingress_zone)
        else:
            _egress_zones = [egress_zone]

        for _ingress_zone in _ingress_zones:
            if _ingress_zone == "HOST":
                _ingress_interfaces = [""]
                _ingress_sources = []
            else:
                if ingressInterface:
                    _ingress_interfaces = [ingressInterface]
                    _ingress_sources = []
                elif ingressSource:
                    _ingress_interfaces = []
                    _ingress_sources = [ingressSource]
                else:
                    _ingress_interfaces = list(
                        self._fw.zone.list_interfaces(_ingress_zone)
                    )
                    if (
                        _ingress_zone == self._fw._default_zone
                        and "+" not in _ingress_interfaces
                    ):
                        _ingress_interfaces.append("+")
                    _ingress_sources = list(self._fw.zone.list_sources(_ingress_zone))
                    try:
                        # In some cases, e.g. (ANY --> zone) the ingress
                        # interfaces and egress interface may the same, because
                        # the zone appears in both ingress and egress. So avoid
                        # adding it twice by skipping it when updating the
                        # egress side.
                        _ingress_interfaces.remove(egressInterface)
                    except:
                        pass
                    try:
                        _ingress_sources.remove(egressSource)
                    except:
                        pass

            for _egress_zone in _egress_zones:
                if _egress_zone == "HOST":
                    _egress_interfaces = [""]
                    _egress_sources = []
                else:
                    if egressInterface:
                        _egress_interfaces = [egressInterface]
                        _egress_sources = []
                    elif egressSource:
                        _egress_interfaces = []
                        _egress_sources = [egressSource]
                    else:
                        _egress_interfaces = list(
                            self._fw.zone.list_interfaces(_egress_zone)
                        )
                        if (
                            _egress_zone == self._fw._default_zone
                            and "+" not in _egress_interfaces
                        ):
                            _egress_interfaces.append("+")
                        _egress_sources = list(self._fw.zone.list_sources(_egress_zone))

                        # If the currently activating zone is in both ingress
                        # and egress, then we must include the activating
                        # interface now as it will not be present in
                        # zone.list_interfaces().
                        if _ingress_zone == _egress_zone:
                            if (
                                ingressInterface
                                and ingressInterface not in _egress_interfaces
                            ):
                                _egress_interfaces.append(ingressInterface)
                            if ingressSource and ingressSource not in _egress_sources:
                                _egress_sources.append(ingressSource)

                for _ingress_interface in _ingress_interfaces:
                    for _egress_interface in _egress_interfaces:
                        if _ingress_interface == "+" and _egress_interface == "+":
                            continue
                        self._ingress_egress_pair(
                            enable,
                            policy,
                            _ingress_zone,
                            _egress_zone,
                            _ingress_interface,
                            "",
                            _egress_interface,
                            "",
                            transaction,
                        )
                    for _egress_source in _egress_sources:
                        self._ingress_egress_pair(
                            enable,
                            policy,
                            _ingress_zone,
                            _egress_zone,
                            _ingress_interface,
                            "",
                            "",
                            _egress_source,
                            transaction,
                        )
                for _ingress_source in _ingress_sources:
                    for _egress_interface in _egress_interfaces:
                        self._ingress_egress_pair(
                            enable,
                            policy,
                            _ingress_zone,
                            _egress_zone,
                            "",
                            _ingress_source,
                            _egress_interface,
                            "",
                            transaction,
                        )
                    for _egress_source in _egress_sources:
                        # must be same IPv4/IPv6 family!
                        if self._fw.zone.check_source(
                            _ingress_source
                        ) != self._fw.zone.check_source(_egress_source):
                            continue
                        self._ingress_egress_pair(
                            enable,
                            policy,
                            _ingress_zone,
                            _egress_zone,
                            "",
                            _ingress_source,
                            "",
                            _egress_source,
                            transaction,
                        )

    def _ingress_zone(
        self,
        enable,
        policy,
        ingress_zone,
        transaction,
        ingressInterface=None,
        ingressSource=None,
    ):
        for egress_zone in self.list_egress_zones(policy):
            if (
                egress_zone not in ["HOST", "ANY"]
                and not self._fw.zone.get_zone(egress_zone).applied
            ):
                continue
            self._ingress_egress_zone(
                enable,
                policy,
                ingress_zone,
                egress_zone,
                transaction,
                ingressInterface=ingressInterface,
                ingressSource=ingressSource,
            )

    def _egress_zone(
        self,
        enable,
        policy,
        egress_zone,
        transaction,
        egressInterface=None,
        egressSource=None,
    ):
        for ingress_zone in self.list_ingress_zones(policy):
            if (
                ingress_zone not in ["HOST", "ANY"]
                and not self._fw.zone.get_zone(ingress_zone).applied
            ):
                continue
            self._ingress_egress_zone(
                enable,
                policy,
                ingress_zone,
                egress_zone,
                transaction,
                egressInterface=egressInterface,
                egressSource=egressSource,
            )

    def _get_table_chains_for_policy_dispatch(self, policy):
        """Create a list of (table, chain) needed for policy dispatch"""
        obj = self._policies[policy]
        if "ANY" in obj.ingress_zones and "HOST" in obj.egress_zones:
            # any --> HOST
            tc = [("filter", "INPUT"), ("nat", "PREROUTING"), ("mangle", "PREROUTING")]
            # iptables backend needs to put conntrack helper rules in raw
            # prerouting.
            if not self._fw.nftables_enabled:
                tc.append(("raw", "PREROUTING"))
            return tc
        elif "HOST" in obj.egress_zones:
            # zone --> HOST
            tc = [("filter", "INPUT")]
            # iptables backend needs to put conntrack helper rules in raw
            # prerouting.
            if not self._fw.nftables_enabled:
                tc.append(("raw", "PREROUTING"))
            return tc
        elif "HOST" in obj.ingress_zones:
            # HOST --> zone/any
            return [("filter", "OUTPUT"), ("nat", "OUTPUT")]
        elif "ANY" in obj.ingress_zones and "ANY" in obj.egress_zones:
            # any --> any
            tc = [
                ("filter", "FORWARD"),
                ("nat", "PREROUTING"),
                ("nat", "POSTROUTING"),
                ("mangle", "PREROUTING"),
            ]
            # iptables backend needs to put conntrack helper rules in raw
            # prerouting.
            if not self._fw.nftables_enabled:
                tc.append(("raw", "PREROUTING"))
            return tc
        elif "ANY" in obj.egress_zones:
            # zone --> any
            tc = [
                ("filter", "FORWARD"),
                ("nat", "PREROUTING"),
                ("mangle", "PREROUTING"),
            ]
            # iptables backend needs to put conntrack helper rules in raw
            # prerouting.
            if not self._fw.nftables_enabled:
                tc.append(("raw", "PREROUTING"))
            if self._fw._firewall_backend == "nftables":
                tc.append(("nat", "POSTROUTING"))
            else:
                for zone in obj.ingress_zones:
                    if self._fw.zone.get_zone(zone).interfaces:
                        break
                else:
                    tc.append(("nat", "POSTROUTING"))
            return tc
        elif "ANY" in obj.ingress_zones:
            # any --> zone
            tc = [("filter", "FORWARD"), ("nat", "POSTROUTING")]
            # iptables backend needs to put conntrack helper rules in raw
            # prerouting.
            if not self._fw.nftables_enabled:
                tc.append(("raw", "PREROUTING"))
            for zone in obj.egress_zones:
                if self._fw.zone.get_zone(zone).interfaces:
                    break
            else:
                tc.append(("nat", "PREROUTING"))
                tc.append(("mangle", "PREROUTING"))
            return tc
        else:
            # zone -> zone
            tc = [("filter", "FORWARD")]
            # iptables backend needs to put conntrack helper rules in raw
            # prerouting.
            if not self._fw.nftables_enabled:
                tc.append(("raw", "PREROUTING"))
            if self._fw._firewall_backend == "nftables":
                tc.append(("nat", "POSTROUTING"))
            else:
                for zone in obj.ingress_zones:
                    if self._fw.zone.get_zone(zone).interfaces:
                        break
                else:
                    tc.append(("nat", "POSTROUTING"))
            for zone in obj.egress_zones:
                if self._fw.zone.get_zone(zone).interfaces:
                    break
            else:
                tc.append(("nat", "PREROUTING"))
                tc.append(("mangle", "PREROUTING"))
            return tc

    def _get_table_chains_for_zone_dispatch(self, policy):
        """Create a list of (table, chain) needed for zone dispatch"""
        obj = self._policies[policy]
        if "HOST" in obj.egress_zones:
            # zone --> Host
            tc = [("filter", "INPUT")]
            # iptables backend needs to put conntrack helper rules in raw
            # prerouting.
            if not self._fw.nftables_enabled:
                tc.append(("raw", "PREROUTING"))
            return tc
        elif "HOST" in obj.ingress_zones:
            # zone derived policies of this type are for tracking only, no zone
            # features use it
            return [("filter", "OUTPUT"), ("nat", "OUTPUT")]
        elif "ANY" in obj.egress_zones:
            # zone --> any
            return [
                ("filter", "FORWARD"),
                ("nat", "PREROUTING"),
                ("mangle", "PREROUTING"),
            ]
        elif "ANY" in obj.ingress_zones:
            # any --> zone
            return [("nat", "POSTROUTING")]
        raise FirewallError(errors.INVALID_POLICY, "Invalid policy: %s" % (policy))

    def policy_base_chain_name(self, policy, table, policy_prefix, isSNAT=False):
        obj = self._fw.policy.get_policy(policy)
        if obj.derived_from_zone:
            suffix = obj.derived_from_zone
        else:
            suffix = policy_prefix + policy

        if "HOST" in obj.egress_zones:
            # zone/any --> Host
            if table == "filter":
                return "IN_" + suffix
            elif table == "raw":
                # NOTE: nftables doesn't actually use this. Only iptables
                return "PRE_" + suffix
            elif table in ["mangle", "nat"]:
                return "PRE_" + suffix
        elif "HOST" in obj.ingress_zones:
            # HOST --> zone/any
            if table in ["filter", "nat"]:
                return "OUT_" + suffix
        elif "ANY" in obj.egress_zones:
            # zone/any --> any
            if table == "filter":
                return "FWD_" + suffix
            elif table == "nat":
                if isSNAT:
                    return "POST_" + suffix
                else:
                    return "PRE_" + suffix
            elif table in ["mangle", "raw"]:
                return "PRE_" + suffix
        elif "ANY" in obj.ingress_zones:
            # any --> zone
            if table == "filter":
                return "FWD_" + suffix
            elif table == "nat":
                if isSNAT:
                    return "POST_" + suffix
                else:
                    return "PRE_" + suffix
            elif table in ["mangle", "raw"]:
                return "PRE_" + suffix
        elif not obj.derived_from_zone:
            # zone --> zone
            if table == "filter":
                return "FWD_" + suffix
            elif table == "nat":
                if isSNAT:
                    return "POST_" + suffix
                else:
                    return "PRE_" + suffix
            elif table in ["mangle", "raw"]:
                return "PRE_" + suffix
        raise FirewallError(
            errors.INVALID_POLICY,
            "Can't convert policy to chain name: %s, %s, %s" % (policy, table, isSNAT),
        )
