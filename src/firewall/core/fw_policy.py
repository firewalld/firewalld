# -*- coding: utf-8 -*-
#
# SPDX-License-Identifier: GPL-2.0-or-later

import time
from firewall.core.logger import log
from firewall.functions import portStr, checkIPnMask, checkIP6nMask, \
    checkProtocol, enable_ip_forwarding, check_single_address, \
    portInPortRange, get_nf_conntrack_short_name, coalescePortRange, breakPortRange
from firewall.core.rich import Rich_Rule, Rich_Accept, \
    Rich_Service, Rich_Port, Rich_Protocol, \
    Rich_Masquerade, Rich_ForwardPort, Rich_SourcePort, Rich_IcmpBlock, \
    Rich_IcmpType
from firewall.core.fw_transaction import FirewallTransaction
from firewall import errors
from firewall.errors import FirewallError
from firewall.fw_types import LastUpdatedOrderedDict
from firewall.core.base import SOURCE_IPSET_TYPES

class FirewallPolicy(object):
    def __init__(self, fw):
        self._fw = fw
        self._chains = { }
        self._policies = { }

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__, self._chains, self._policies)

    def cleanup(self):
        self._chains.clear()
        self._policies.clear()

    # transaction

    def new_transaction(self):
        return FirewallTransaction(self._fw)

    # policies

    def get_policies(self):
        return sorted(self._policies.keys())

    def get_policy(self, policy):
        p = self._fw.check_policy(policy)
        return self._policies[p]

    def _first_except(self, e, f, name, *args, **kwargs):
        try:
            f(name, *args, **kwargs)
        except FirewallError as error:
            if not e:
                return error
        return e

    def add_policy(self, obj):
        obj.settings = { x : LastUpdatedOrderedDict()
                         for x in [ "services", "ports",
                                    "masquerade", "forward_ports",
                                    "source_ports",
                                    "icmp_blocks", "rules",
                                    "protocols", "icmp_block_inversion" ] }

        self._policies[obj.name] = obj
        self.copy_permanent_to_runtime(obj.name)

    def remove_policy(self, policy):
        obj = self._policies[policy]
        if obj.applied:
            self.unapply_policy_settings(policy)
        obj.settings.clear()
        del self._policies[policy]

    def copy_permanent_to_runtime(self, policy):
        obj = self._policies[policy]

        if obj.applied:
            return

        for args in obj.icmp_blocks:
            self.add_icmp_block(policy, args)
        for args in obj.forward_ports:
            self.add_forward_port(policy, *args)
        for args in obj.services:
            self.add_service(policy, args)
        for args in obj.ports:
            self.add_port(policy, *args)
        for args in obj.protocols:
            self.add_protocol(policy, args)
        for args in obj.source_ports:
            self.add_source_port(policy, *args)
        for args in obj.rules:
            self.add_rule(policy, args)
        if obj.masquerade:
            self.add_masquerade(policy)

    def set_policy_applied(self, policy, applied):
        obj = self._policies[policy]
        obj.applied = applied

    # settings

    # generate settings record with sender, timeout
    def __gen_settings(self, timeout, sender):
        ret = {
            "date": time.time(),
            "sender": sender,
            "timeout": timeout,
        }
        return ret

    def get_settings(self, policy):
        return self.get_policy(policy).settings

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
            for (table, chain) in self._get_table_chains_for_policy_dispatch(policy) if not obj.derived_from_zone \
                             else self._get_table_chains_for_zone_dispatch(policy):
                self.gen_chain_rules(policy, True, table, chain, transaction)

        settings = self.get_settings(policy)
        for key in settings:
            for args in settings[key]:
                if key == "icmp_blocks":
                    self._icmp_block(enable, _policy, args, transaction)
                elif key == "icmp_block_inversion":
                    continue
                elif key == "forward_ports":
                    self._forward_port(enable, _policy, transaction,
                                       *args)
                elif key == "services":
                    self._service(enable, _policy, args, transaction)
                elif key == "ports":
                    self._port(enable, _policy, args[0], args[1],
                                transaction)
                elif key == "protocols":
                    self._protocol(enable, _policy, args, transaction)
                elif key == "source_ports":
                    self._source_port(enable, _policy, args[0], args[1],
                                       transaction)
                elif key == "masquerade":
                    self._masquerade(enable, _policy, transaction)
                elif key == "rules":
                    self.__rule(enable, _policy, Rich_Rule(rule_str=args),
                                transaction)
                else:
                    log.warning("Policy '%s': Unknown setting '%s:%s', "
                                "unable to apply", policy, key, args)

        if not enable:
            for (table, chain) in self._get_table_chains_for_policy_dispatch(policy) if not obj.derived_from_zone \
                             else self._get_table_chains_for_zone_dispatch(policy):
                self.gen_chain_rules(policy, False, table, chain, transaction)
            obj.applied = False

        if use_transaction is None:
            transaction.execute(enable)

    def apply_policy_settings(self, policy, use_transaction=None):
        self._policy_settings(True, policy, use_transaction=use_transaction)

    def unapply_policy_settings(self, policy, use_transaction=None):
        self._policy_settings(False, policy, use_transaction=use_transaction)

    def get_config_with_settings(self, policy):
        """
        :return: exported config updated with runtime settings
        """
        conf = list(self.get_policy(policy).export_config())
        conf[5] = self.list_services(policy)
        conf[6] = self.list_ports(policy)
        conf[7] = self.list_icmp_blocks(policy)
        conf[8] = self.query_masquerade(policy)
        conf[9] = self.list_forward_ports(policy)
        conf[12] = self.list_rules(policy)
        conf[13] = self.list_protocols(policy)
        conf[14] = self.list_source_ports(policy)
        conf[15] = self.query_icmp_block_inversion(policy)
        return tuple(conf)

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

    def add_rule(self, policy, rule, timeout=0, sender=None,
                 use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_timeout(timeout)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        rule_id = self.__rule_id(rule)
        if rule_id in _obj.settings["rules"]:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(errors.ALREADY_ENABLED,
                                "'%s' already in '%s'" % (rule, _name))

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
        _obj.settings["rules"][rule_id] = self.__gen_settings(
            timeout, sender)

    def remove_rule(self, policy, rule,
                    use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        rule_id = self.__rule_id(rule)
        if rule_id not in _obj.settings["rules"]:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(errors.NOT_ENABLED,
                                "'%s' not in '%s'" % (rule, _name))

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
        if rule_id in _obj.settings["rules"]:
            del _obj.settings["rules"][rule_id]

    def query_rule(self, policy, rule):
        return self.__rule_id(rule) in self.get_settings(policy)["rules"]

    def list_rules(self, policy):
        return list(self.get_settings(policy)["rules"].keys())

    # SERVICES

    def check_service(self, service):
        self._fw.check_service(service)

    def __service_id(self, service):
        self.check_service(service)
        return service

    def add_service(self, policy, service, timeout=0, sender=None,
                    use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_timeout(timeout)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        service_id = self.__service_id(service)
        if service_id in _obj.settings["services"]:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(errors.ALREADY_ENABLED,
                                "'%s' already in '%s'" % (service, _name))

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
        _obj.settings["services"][service_id] = \
            self.__gen_settings(timeout, sender)

    def remove_service(self, policy, service,
                       use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        service_id = self.__service_id(service)
        if service_id not in _obj.settings["services"]:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(errors.NOT_ENABLED,
                                "'%s' not in '%s'" % (service, _name))

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
        if service_id in _obj.settings["services"]:
            del _obj.settings["services"][service_id]

    def query_service(self, policy, service):
        return self.__service_id(service) in self.get_settings(policy)["services"]

    def list_services(self, policy):
        return self.get_settings(policy)["services"].keys()

    def get_helpers_for_service_helpers(self, helpers):
        _helpers = [ ]
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
        _helpers = [ ]
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

    def add_port(self, policy, port, protocol, timeout=0, sender=None,
                 use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_timeout(timeout)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        existing_port_ids = list(filter(lambda x: x[1] == protocol, _obj.settings["ports"]))
        for port_id in existing_port_ids:
            if portInPortRange(port, port_id[0]):
                _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
                raise FirewallError(errors.ALREADY_ENABLED,
                                    "'%s:%s' already in '%s'" % (port, protocol, _name))

        added_ranges, removed_ranges = coalescePortRange(port, [_port for (_port, _protocol) in existing_port_ids])

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
        _obj.settings["ports"][port_id] = \
            self.__gen_settings(timeout, sender)

    def remove_port(self, policy, port, protocol,
                    use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        existing_port_ids = list(filter(lambda x: x[1] == protocol, _obj.settings["ports"]))
        for port_id in existing_port_ids:
            if portInPortRange(port, port_id[0]):
                break
        else:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(errors.NOT_ENABLED,
                                "'%s:%s' not in '%s'" % (port, protocol, _name))

        added_ranges, removed_ranges = breakPortRange(port, [_port for (_port, _protocol) in existing_port_ids])

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
        if port_id in _obj.settings["ports"]:
            del _obj.settings["ports"][port_id]

    def query_port(self, policy, port, protocol):
        for (_port, _protocol) in self.get_settings(policy)["ports"]:
            if portInPortRange(port, _port) and protocol == _protocol:
                return True

        return False

    def list_ports(self, policy):
        return list(self.get_settings(policy)["ports"].keys())

    # PROTOCOLS

    def check_protocol(self, protocol):
        if not checkProtocol(protocol):
            raise FirewallError(errors.INVALID_PROTOCOL, protocol)

    def __protocol_id(self, protocol):
        self.check_protocol(protocol)
        return protocol

    def add_protocol(self, policy, protocol, timeout=0, sender=None,
                     use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_timeout(timeout)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        protocol_id = self.__protocol_id(protocol)
        if protocol_id in _obj.settings["protocols"]:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(errors.ALREADY_ENABLED,
                                "'%s' already in '%s'" % (protocol, _name))

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
        _obj.settings["protocols"][protocol_id] = \
            self.__gen_settings(timeout, sender)

    def remove_protocol(self, policy, protocol,
                        use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        protocol_id = self.__protocol_id(protocol)
        if protocol_id not in _obj.settings["protocols"]:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(errors.NOT_ENABLED,
                                "'%s' not in '%s'" % (protocol, _name))

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            self._protocol(False, _policy, protocol, transaction)

        transaction.add_post(self.__unregister_protocol, _obj,
                                  protocol_id)

        if use_transaction is None:
            transaction.execute(True)

        return _policy

    def __unregister_protocol(self, _obj, protocol_id):
        if protocol_id in _obj.settings["protocols"]:
            del _obj.settings["protocols"][protocol_id]

    def query_protocol(self, policy, protocol):
        return self.__protocol_id(protocol) in self.get_settings(policy)["protocols"]

    def list_protocols(self, policy):
        return list(self.get_settings(policy)["protocols"].keys())

    # SOURCE PORTS

    def __source_port_id(self, port, protocol):
        self.check_port(port, protocol)
        return (portStr(port, "-"), protocol)

    def add_source_port(self, policy, port, protocol, timeout=0, sender=None,
                        use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_timeout(timeout)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        existing_port_ids = list(filter(lambda x: x[1] == protocol, _obj.settings["source_ports"]))
        for port_id in existing_port_ids:
            if portInPortRange(port, port_id[0]):
                _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
                raise FirewallError(errors.ALREADY_ENABLED,
                                    "'%s:%s' already in '%s'" % (port, protocol, _name))

        added_ranges, removed_ranges = coalescePortRange(port, [_port for (_port, _protocol) in existing_port_ids])

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            for range in added_ranges:
                self._source_port(True, _policy, portStr(range, "-"), protocol, transaction)
            for range in removed_ranges:
                self._source_port(False, _policy, portStr(range, "-"), protocol, transaction)

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
        _obj.settings["source_ports"][port_id] = \
            self.__gen_settings(timeout, sender)

    def remove_source_port(self, policy, port, protocol,
                           use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        existing_port_ids = list(filter(lambda x: x[1] == protocol, _obj.settings["source_ports"]))
        for port_id in existing_port_ids:
            if portInPortRange(port, port_id[0]):
                break
        else:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(errors.NOT_ENABLED,
                                "'%s:%s' not in '%s'" % (port, protocol, _name))

        added_ranges, removed_ranges = breakPortRange(port, [_port for (_port, _protocol) in existing_port_ids])

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            for range in added_ranges:
                self._source_port(True, _policy, portStr(range, "-"), protocol, transaction)
            for range in removed_ranges:
                self._source_port(False, _policy, portStr(range, "-"), protocol, transaction)

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
        if port_id in _obj.settings["source_ports"]:
            del _obj.settings["source_ports"][port_id]

    def query_source_port(self, policy, port, protocol):
        for (_port, _protocol) in self.get_settings(policy)["source_ports"]:
            if portInPortRange(port, _port) and protocol == _protocol:
                return True

        return False

    def list_source_ports(self, policy):
        return list(self.get_settings(policy)["source_ports"].keys())

    # MASQUERADE

    def __masquerade_id(self):
        return True

    def add_masquerade(self, policy, timeout=0, sender=None,
                       use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_timeout(timeout)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        masquerade_id = self.__masquerade_id()
        if masquerade_id in _obj.settings["masquerade"]:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(errors.ALREADY_ENABLED,
                                "masquerade already enabled in '%s'" % _name)

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            self._masquerade(True, _policy, transaction)

        self.__register_masquerade(_obj, masquerade_id, timeout, sender)
        transaction.add_fail(self.__unregister_masquerade, _obj, masquerade_id)

        if use_transaction is None:
            transaction.execute(True)

        return _policy

    def __register_masquerade(self, _obj, masquerade_id, timeout, sender):
        _obj.settings["masquerade"][masquerade_id] = \
            self.__gen_settings(timeout, sender)

    def remove_masquerade(self, policy, use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        masquerade_id = self.__masquerade_id()
        if masquerade_id not in _obj.settings["masquerade"]:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(errors.NOT_ENABLED,
                                "masquerade not enabled in '%s'" % _name)

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            self._masquerade(False, _policy, transaction)

        transaction.add_post(self.__unregister_masquerade, _obj, masquerade_id)

        if use_transaction is None:
            transaction.execute(True)

        return _policy

    def __unregister_masquerade(self, _obj, masquerade_id):
        if masquerade_id in _obj.settings["masquerade"]:
            del _obj.settings["masquerade"][masquerade_id]

    def query_masquerade(self, policy):
        return self.__masquerade_id() in self.get_settings(policy)["masquerade"]

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
        if check_single_address("ipv6", toaddr):
            self.check_forward_port("ipv6", port, protocol, toport, toaddr)
        else:
            self.check_forward_port("ipv4", port, protocol, toport, toaddr)
        return (portStr(port, "-"), protocol,
                portStr(toport, "-"), str(toaddr))

    def add_forward_port(self, policy, port, protocol, toport=None,
                         toaddr=None, timeout=0, sender=None,
                         use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_timeout(timeout)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        forward_id = self.__forward_port_id(port, protocol, toport, toaddr)
        if forward_id in _obj.settings["forward_ports"]:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(errors.ALREADY_ENABLED,
                                "'%s:%s:%s:%s' already in '%s'" % \
                                (port, protocol, toport, toaddr, _name))

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            self._forward_port(True, _policy, transaction, port, protocol,
                               toport, toaddr)

        self.__register_forward_port(_obj, forward_id, timeout, sender)
        transaction.add_fail(self.__unregister_forward_port, _obj, forward_id)

        if use_transaction is None:
            transaction.execute(True)

        return _policy

    def __register_forward_port(self, _obj, forward_id, timeout, sender):
        _obj.settings["forward_ports"][forward_id] = \
            self.__gen_settings(timeout, sender)

    def remove_forward_port(self, policy, port, protocol, toport=None,
                            toaddr=None, use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        forward_id = self.__forward_port_id(port, protocol, toport, toaddr)
        if forward_id not in _obj.settings["forward_ports"]:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(errors.NOT_ENABLED,
                                "'%s:%s:%s:%s' not in '%s'" % \
                                (port, protocol, toport, toaddr, _name))

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            self._forward_port(False, _policy, transaction, port, protocol,
                               toport, toaddr)

        transaction.add_post(self.__unregister_forward_port, _obj, forward_id)

        if use_transaction is None:
            transaction.execute(True)

        return _policy

    def __unregister_forward_port(self, _obj, forward_id):
        if forward_id in _obj.settings["forward_ports"]:
            del _obj.settings["forward_ports"][forward_id]

    def query_forward_port(self, policy, port, protocol, toport=None,
                           toaddr=None):
        forward_id = self.__forward_port_id(port, protocol, toport, toaddr)
        return forward_id in self.get_settings(policy)["forward_ports"]

    def list_forward_ports(self, policy):
        return list(self.get_settings(policy)["forward_ports"].keys())

    # ICMP BLOCK

    def check_icmp_block(self, icmp):
        self._fw.check_icmptype(icmp)

    def __icmp_block_id(self, icmp):
        self.check_icmp_block(icmp)
        return icmp

    def add_icmp_block(self, policy, icmp, timeout=0, sender=None,
                       use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_timeout(timeout)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        icmp_id = self.__icmp_block_id(icmp)
        if icmp_id in _obj.settings["icmp_blocks"]:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(errors.ALREADY_ENABLED,
                                "'%s' already in '%s'" % (icmp, _name))

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
        _obj.settings["icmp_blocks"][icmp_id] = \
            self.__gen_settings(timeout, sender)

    def remove_icmp_block(self, policy, icmp, use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        icmp_id = self.__icmp_block_id(icmp)
        if icmp_id not in _obj.settings["icmp_blocks"]:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(errors.NOT_ENABLED,
                                "'%s' not in '%s'" % (icmp, _name))

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
        if icmp_id in _obj.settings["icmp_blocks"]:
            del _obj.settings["icmp_blocks"][icmp_id]

    def query_icmp_block(self, policy, icmp):
        return self.__icmp_block_id(icmp) in self.get_settings(policy)["icmp_blocks"]

    def list_icmp_blocks(self, policy):
        return self.get_settings(policy)["icmp_blocks"].keys()

    # ICMP BLOCK INVERSION

    def __icmp_block_inversion_id(self):
        return True

    def add_icmp_block_inversion(self, policy, sender=None,
                                 use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        icmp_block_inversion_id = self.__icmp_block_inversion_id()
        if icmp_block_inversion_id in _obj.settings["icmp_block_inversion"]:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(
                errors.ALREADY_ENABLED,
                "icmp-block-inversion already enabled in '%s'" % _name)

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            # undo icmp blocks
            for args in self.get_settings(_policy)["icmp_blocks"]:
                self._icmp_block(False, _policy, args, transaction)

            self._icmp_block_inversion(False, _policy, transaction)

        self.__register_icmp_block_inversion(_obj, icmp_block_inversion_id,
                                             sender)
        transaction.add_fail(self.__undo_icmp_block_inversion, _policy, _obj,
                             icmp_block_inversion_id)

        # redo icmp blocks
        if _obj.applied:
            for args in self.get_settings(_policy)["icmp_blocks"]:
                self._icmp_block(True, _policy, args, transaction)

            self._icmp_block_inversion(True, _policy, transaction)

        if use_transaction is None:
            transaction.execute(True)

        return _policy

    def __register_icmp_block_inversion(self, _obj, icmp_block_inversion_id,
                                        sender):
        _obj.settings["icmp_block_inversion"][icmp_block_inversion_id] = \
            self.__gen_settings(0, sender)

    def __undo_icmp_block_inversion(self, _policy, _obj, icmp_block_inversion_id):
        transaction = self.new_transaction()

        # undo icmp blocks
        if _obj.applied:
            for args in self.get_settings(_policy)["icmp_blocks"]:
                self._icmp_block(False, _policy, args, transaction)

        if icmp_block_inversion_id in _obj.settings["icmp_block_inversion"]:
            del _obj.settings["icmp_block_inversion"][icmp_block_inversion_id]

        # redo icmp blocks
        if _obj.applied:
            for args in self.get_settings(_policy)["icmp_blocks"]:
                self._icmp_block(True, _policy, args, transaction)

        transaction.execute(True)

    def remove_icmp_block_inversion(self, policy, use_transaction=None):
        _policy = self._fw.check_policy(policy)
        self._fw.check_panic()
        _obj = self._policies[_policy]

        icmp_block_inversion_id = self.__icmp_block_inversion_id()
        if icmp_block_inversion_id not in _obj.settings["icmp_block_inversion"]:
            _name = _obj.derived_from_zone if _obj.derived_from_zone else _policy
            raise FirewallError(
                errors.NOT_ENABLED,
                "icmp-block-inversion not enabled in '%s'" % _name)

        if use_transaction is None:
            transaction = self.new_transaction()
        else:
            transaction = use_transaction

        if _obj.applied:
            # undo icmp blocks
            for args in self.get_settings(_policy)["icmp_blocks"]:
                self._icmp_block(False, _policy, args, transaction)

            self._icmp_block_inversion(False, _policy, transaction)

        self.__unregister_icmp_block_inversion(_obj,
                                               icmp_block_inversion_id)
        transaction.add_fail(self.__register_icmp_block_inversion, _obj,
                             icmp_block_inversion_id, None)

        # redo icmp blocks
        if _obj.applied:
            for args in self.get_settings(_policy)["icmp_blocks"]:
                self._icmp_block(True, _policy, args, transaction)

            self._icmp_block_inversion(True, _policy, transaction)

        if use_transaction is None:
            transaction.execute(True)

        return _policy

    def __unregister_icmp_block_inversion(self, _obj, icmp_block_inversion_id):
        if icmp_block_inversion_id in _obj.settings["icmp_block_inversion"]:
            del _obj.settings["icmp_block_inversion"][icmp_block_inversion_id]

    def query_icmp_block_inversion(self, policy):
        return self.__icmp_block_inversion_id() in \
            self.get_settings(policy)["icmp_block_inversion"]

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
            if tracking_policy in self._chains and  \
               (table, chain) in self._chains[tracking_policy]:
                return
        else:
            if tracking_policy not in self._chains or \
               (table, chain) not in self._chains[tracking_policy]:
                return

        for backend in self._fw.enabled_backends():
            if backend.policies_supported and \
               table in backend.get_available_tables():
                rules = backend.build_policy_chain_rules(create, policy, table)
                transaction.add_rules(backend, rules)

        self._register_chains(tracking_policy, create, [(table, chain)])
        transaction.add_fail(self._register_chains, tracking_policy, not create, [(table, chain)])

    def _register_chains(self, policy, create, tables):
        for (table, chain) in tables:
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
                "ipset '%s' with type '%s' not usable as source" % \
                (name, _type))

    def _rule_prepare(self, enable, policy, rule, transaction):
        ipvs = []
        if rule.family:
            ipvs = [ rule.family ]
        elif rule.element and (isinstance(rule.element, Rich_IcmpBlock) or isinstance(rule.element, Rich_IcmpType)):
            ict = self._fw.config.get_icmptype(rule.element.name)
            if ict.destination:
                ipvs = [ipv for ipv in ["ipv4", "ipv6"] if ipv in ict.destination]

        source_ipv = self._rule_source_ipv(rule.source)
        if source_ipv:
            if rule.family:
                # rule family is defined by user, no way to change it
                if rule.family != source_ipv:
                    raise FirewallError(errors.INVALID_RULE,
                                        "Source address family '%s' conflicts with rule family '%s'." % (source_ipv, rule.family))
            else:
                # use the source family as rule family
                ipvs = [ source_ipv ]

        if not ipvs:
            ipvs = ["ipv4", "ipv6"]

        # clamp ipvs to those that are actually enabled.
        ipvs = [ipv for ipv in ipvs if self._fw.is_ipv_enabled(ipv)]

        # add an element to object to allow backends to know what ipvs this applies to
        rule.ipvs = ipvs

        for backend in set([self._fw.get_backend_by_ipv(x) for x in ipvs]):
            # SERVICE
            if type(rule.element) == Rich_Service:
                svc = self._fw.service.get_service(rule.element.name)

                destinations = []
                if len(svc.destination) > 0:
                    if rule.destination:
                        # we can not use two destinations at the same time
                        raise FirewallError(errors.INVALID_RULE,
                                            "Destination conflict with service.")
                    for ipv in ipvs:
                        if ipv in svc.destination and backend.is_ipv_supported(ipv):
                            destinations.append(svc.destination[ipv])
                else:
                    # dummy for the following for loop
                    destinations.append(None)

                for destination in destinations:
                    if type(rule.action) == Rich_Accept:
                        # only load modules for accept action
                        helpers = self.get_helpers_for_service_modules(svc.modules,
                                                                       enable)
                        helpers += self.get_helpers_for_service_helpers(svc.helpers)
                        helpers = sorted(set(helpers), key=lambda x: x.name)

                        modules = [ ]
                        for helper in helpers:
                            module = helper.module
                            _module_short_name = get_nf_conntrack_short_name(module)
                            nat_module = module.replace("conntrack", "nat")
                            modules.append(nat_module)
                            if helper.family != "" and not backend.is_ipv_supported(helper.family):
                                # no support for family ipv, continue
                                continue
                            if len(helper.ports) < 1:
                                modules.append(module)
                            else:
                                for (port,proto) in helper.ports:
                                    rules = backend.build_policy_helper_ports_rules(
                                                    enable, policy, proto, port,
                                                    destination, helper.name, _module_short_name)
                                    transaction.add_rules(backend, rules)
                        transaction.add_modules(modules)

                    # create rules
                    for (port,proto) in svc.ports:
                        rules = backend.build_policy_ports_rules(
                                    enable, policy, proto, port, destination, rule)
                        transaction.add_rules(backend, rules)

                    for proto in svc.protocols:
                        rules = backend.build_policy_protocol_rules(
                                    enable, policy, proto, destination, rule)
                        transaction.add_rules(backend, rules)

                    # create rules
                    for (port,proto) in svc.source_ports:
                        rules = backend.build_policy_source_ports_rules(
                                    enable, policy, proto, port, destination, rule)
                        transaction.add_rules(backend, rules)

            # PORT
            elif type(rule.element) == Rich_Port:
                port = rule.element.port
                protocol = rule.element.protocol
                self.check_port(port, protocol)

                rules = backend.build_policy_ports_rules(
                            enable, policy, protocol, port, None, rule)
                transaction.add_rules(backend, rules)

            # PROTOCOL
            elif type(rule.element) == Rich_Protocol:
                protocol = rule.element.value
                self.check_protocol(protocol)

                rules = backend.build_policy_protocol_rules(
                            enable, policy, protocol, None, rule)
                transaction.add_rules(backend, rules)

            # MASQUERADE
            elif type(rule.element) == Rich_Masquerade:
                if enable:
                    for ipv in ipvs:
                        if backend.is_ipv_supported(ipv):
                            transaction.add_post(enable_ip_forwarding, ipv)

                rules = backend.build_policy_masquerade_rules(enable, policy, rule)
                transaction.add_rules(backend, rules)

            # FORWARD PORT
            elif type(rule.element) == Rich_ForwardPort:
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
                                    enable, policy, port, protocol, toport,
                                    toaddr, rule)
                transaction.add_rules(backend, rules)

            # SOURCE PORT
            elif type(rule.element) == Rich_SourcePort:
                port = rule.element.port
                protocol = rule.element.protocol
                self.check_port(port, protocol)

                rules = backend.build_policy_source_ports_rules(
                            enable, policy, protocol, port, None, rule)
                transaction.add_rules(backend, rules)

            # ICMP BLOCK and ICMP TYPE
            elif type(rule.element) == Rich_IcmpBlock or \
                 type(rule.element) == Rich_IcmpType:
                ict = self._fw.config.get_icmptype(rule.element.name)

                if type(rule.element) == Rich_IcmpBlock and \
                   rule.action and type(rule.action) == Rich_Accept:
                    # icmp block might have reject or drop action, but not accept
                    raise FirewallError(errors.INVALID_RULE,
                                        "IcmpBlock not usable with accept action")

                rules = backend.build_policy_icmp_block_rules(enable, policy, ict, rule)
                transaction.add_rules(backend, rules)

            elif rule.element is None:
                rules = backend.build_policy_rich_source_destination_rules(
                            enable, policy, rule)
                transaction.add_rules(backend, rules)

            # EVERYTHING ELSE
            else:
                raise FirewallError(errors.INVALID_RULE, "Unknown element %s" %
                                    type(rule.element))

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
            self._service(enable, policy, include, transaction, included_services=included_services)

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

        for (backend,destination) in backends_ipv:
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
                    for (port,proto) in helper.ports:
                        rules = backend.build_policy_helper_ports_rules(
                                        enable, policy, proto, port,
                                        destination, helper.name, _module_short_name)
                        transaction.add_rules(backend, rules)

            for (port,proto) in svc.ports:
                rules = backend.build_policy_ports_rules(enable, policy, proto,
                                                       port, destination)
                transaction.add_rules(backend, rules)

            for protocol in svc.protocols:
                rules = backend.build_policy_protocol_rules(
                                    enable, policy, protocol, destination)
                transaction.add_rules(backend, rules)

            for (port,proto) in svc.source_ports:
                rules = backend.build_policy_source_ports_rules(
                                    enable, policy, proto, port, destination)
                transaction.add_rules(backend, rules)

    def _port(self, enable, policy, port, protocol, transaction):
        for backend in self._fw.enabled_backends():
            if not backend.policies_supported:
                continue

            rules = backend.build_policy_ports_rules(enable, policy, protocol,
                                                   port)
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

            rules = backend.build_policy_source_ports_rules(enable, policy, protocol, port)
            transaction.add_rules(backend, rules)

    def _masquerade(self, enable, policy, transaction):
        ipv = "ipv4"
        transaction.add_post(enable_ip_forwarding, ipv)

        backend = self._fw.get_backend_by_ipv(ipv)
        rules = backend.build_policy_masquerade_rules(enable, policy)
        transaction.add_rules(backend, rules)

    def _forward_port(self, enable, policy, transaction, port, protocol,
                       toport=None, toaddr=None):
        if check_single_address("ipv6", toaddr):
            ipv = "ipv6"
        else:
            ipv = "ipv4"

        if toaddr and enable:
            transaction.add_post(enable_ip_forwarding, ipv)
        backend = self._fw.get_backend_by_ipv(ipv)
        rules = backend.build_policy_forward_port_rules(
                            enable, policy, port, protocol, toport,
                            toaddr)
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
        if target in [ "DROP", "%%REJECT%%", "REJECT" ]:
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

    def _get_table_chains_for_zone_dispatch(self, policy):
        """Create a list of (table, chain) needed for zone dispatch"""
        obj = self._policies[policy]
        if obj.egress_zones[0] == "HOST":
            # zone --> Host
            return [("filter", "INPUT"), ("raw", "PREROUTING")]
        elif obj.egress_zones[0] == "ANY":
            # zone --> any
            return [("filter", "FORWARD_IN"), ("nat", "PREROUTING"),
                    ("mangle", "PREROUTING")]
        elif obj.ingress_zones[0] == "ANY":
            # any --> zone
            return [("filter", "FORWARD_OUT"), ("nat", "POSTROUTING")]
        else:
            return FirewallError("Invalid policy: %s" % (policy))

    def policy_base_chain_name(self, policy, table, policy_prefix):
        obj = self._fw.policy.get_policy(policy)
        if obj.derived_from_zone:
            if obj.egress_zones[0] == "HOST":
                # zone --> Host
                if table == "filter":
                    return "IN_" + obj.derived_from_zone
                if table == "raw":
                    # FIXME: nftables doesn't actually use this. Only iptables
                    return "PRE_" + obj.derived_from_zone
            elif obj.egress_zones[0] == "ANY":
                # zone --> any
                if table == "filter":
                    return "FWDI_" + obj.derived_from_zone
                elif table in ["nat", "mangle", "raw"]:
                    return "PRE_" + obj.derived_from_zone
            elif obj.ingress_zones[0] == "ANY":
                # any --> zone
                if table == "filter":
                    return "FWDO_" + obj.derived_from_zone
                elif table == "nat":
                    return "POST_" + obj.derived_from_zone
            return FirewallError("Can't convert policy to chain name: %s" % (policy))
        else:
            return policy_prefix + policy
