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

import time
from firewall.core.base import *
from firewall.core.logger import log
from firewall.functions import portStr, checkIPnMask, checkIP6nMask, \
    checkProtocol, enable_ip_forwarding, check_single_address
from firewall.core.rich import *
from firewall.errors import *
from ipXtables import ip4tables_available_tables, ip6tables_available_tables

mangle = []
if "mangle" in ip4tables_available_tables:
    mangle.append("ipv4")
if "mangle" in ip6tables_available_tables:
    mangle.append("ipv6")

nat = []
if "nat" in ip4tables_available_tables:
    nat.append("ipv4")
else:
    if "ipv4" in mangle:
        mangle.remove("ipv4")
if "nat" in ip6tables_available_tables:
    nat.append("ipv6")
else:
    if "ipv6" in mangle:
        mangle.remove("ipv6")

ZONE_CHAINS = {
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
}

INTERFACE_ZONE_OPTS = {
    "PREROUTING": "-i",
    "POSTROUTING": "-o",
    "INPUT": "-i",
    "FORWARD_IN": "-i",
    "FORWARD_OUT": "-o",
    "OUTPUT": "-o",
}

class FirewallZone:
    def __init__(self, fw):
        self._fw = fw
        self.__init_vars()

    def __init_vars(self):
        self._chains = { }
        self._zones = { }

    def cleanup(self):
        self.__init_vars()

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

    def _error2warning(self, f, name, *args):
        # transform errors into warnings
        try:
            f(name, *args)
        except FirewallError as error:
            msg = str(error)
            code = FirewallError.get_code(msg)
            log.warning("%s: %s" % (name, msg))

    def add_zone(self, obj):
        obj.settings = { x : {} for x in [ "interfaces", "sources",
                                           "services", "ports",
                                           "masquerade", "forward_ports",
                                           "icmp_blocks", "rules" ] }

        self._zones[obj.name] = obj

        # load zone in case of missing services, icmptypes etc.
        for args in obj.interfaces:
            self._error2warning(self.add_interface, obj.name, args)
        for args in obj.sources:
            self._error2warning(self.add_source, obj.name, args)
        for args in obj.icmp_blocks:
            self._error2warning(self.add_icmp_block, obj.name, args)
        for args in obj.forward_ports:
            self._error2warning(self.add_forward_port, obj.name, *args)
        for args in obj.services:
            self._error2warning(self.add_service, obj.name, args)
        for args in obj.ports:
            self._error2warning(self.add_port, obj.name, *args)
        if obj.masquerade:
            self._error2warning(self.add_masquerade, obj.name)
        for args in obj.rules:
            self._error2warning(self.add_rule, obj.name, args)

    def remove_zone(self, zone):
        obj = self._zones[zone]
        for args in obj.interfaces:
            self._error2warning(self.remove_interface, obj.name, args)
        for args in obj.sources:
            self._error2warning(self.remove_source, obj.name, args)
        for args in obj.icmp_blocks:
            self._error2warning(self.remove_icmp_block, obj.name, args)
        for args in obj.forward_ports:
            self._error2warning(self.remove_forward_port, obj.name, *args)
        for args in obj.services:
            self._error2warning(self.remove_service, obj.name, args)
        for args in obj.ports:
            self._error2warning(self.remove_port, obj.name, *args)
        if obj.masquerade:
            self._error2warning(self.remove_masquerade, obj.name)
        for args in obj.rules:
            self._error2warning(self.remove_rule, obj.name, args)

        obj.settings.clear()
        del self._zones[zone]

    # dynamic chain handling

    def __chain(self, zone, create, table, chain):
        if zone in self._chains and table in self._chains[zone] and \
                chain in self._chains[zone][table]:
            return

        chains = [ ]
        rules = [ ]
        zones = [ DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS[chain],
                                                  zone=zone) ]

        # TODO: simplify for one zone only
        for _zone in zones:
            ipvs = []
            if self._fw.is_table_available("ipv4", table):
                ipvs.append("ipv4")
            if self._fw.is_table_available("ipv6", table):
                ipvs.append("ipv6")

            for ipv in ipvs:
                chains.append((ipv, [ _zone, "-t", table ]))
                chains.append((ipv, [ "%s_log" % (_zone), "-t", table ]))
                chains.append((ipv, [ "%s_deny" % (_zone), "-t", table ]))
                chains.append((ipv, [ "%s_allow" % (_zone), "-t", table ]))
                rules.append((ipv, [ _zone, 1, "-t", table,
                                     "-j", "%s_log" % (_zone) ]))
                rules.append((ipv, [ _zone, 2, "-t", table,
                                     "-j", "%s_deny" % (_zone) ]))
                rules.append((ipv, [ _zone, 3, "-t", table,
                                     "-j", "%s_allow" % (_zone) ]))

        if create:
            # handle chains first
            ret = self._fw.handle_chains(chains, create)
            if ret:
                (cleanup_chains, msg) = ret
                log.debug2(msg)
                self._fw.handle_chains(cleanup_chains, not create)
                raise FirewallError(COMMAND_FAILED, msg)

            # handle rules
            ret = self._fw.handle_rules(rules, create, insert=True)
            if ret:
                # also cleanup chains
                self._fw.handle_chains(chains, not create)

                (cleanup_rules, msg) = ret
                self._fw.handle_rules(cleanup_rules, not create)
                raise FirewallError(COMMAND_FAILED, msg)
        else:
            # cleanup rules first
            ret = self._fw.handle_rules(rules, create, insert=True)
            if ret:
                (cleanup_rules, msg) = ret
                self._fw.handle_rules(cleanup_rules, not create)
                raise FirewallError(COMMAND_FAILED, msg)
            
            # cleanup chains
            ret = self._fw.handle_chains(chains, create)
            if ret:
                # also create rules
                self._fw.handle_rules(cleanup_rules, not create)

                (cleanup_chains, msg) = ret
                self._fw.handle_chains(cleanup_chains, not create)
                raise FirewallError(COMMAND_FAILED, msg)

        if create:
            self._chains.setdefault(zone, { }).setdefault(table, [ ]).append(chain)
        else:
            self._chains[zone][table].remove(chain)
            if len(self._chains[zone][table]) == 0:
                del self._chains[zone][table]
            if len(self._chains[zone]) == 0:
                del self._chains[zone]

    def add_chain(self, zone, table, chain):
        self.__chain(zone, True, table, chain)

    def remove_chain(self, zone, table, chain):
        # TODO: add config setting to remove chains optionally if 
        #       table,chain is not used for zone anymore
#        self.__chain(zone, False, table, chain)
        pass

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
                    if key == "interfaces":
                        self.change_zone_of_interface(zone, args)
                    elif key == "sources":
                        self.change_zone_of_source(zone, args)
                    elif key == "icmp_blocks":
                        self.add_icmp_block(zone, args)
                    elif key == "forward_ports":
                        self.add_forward_port(zone, *args)
                    elif key == "services":
                        self.add_service(zone, args)
                    elif key == "ports":
                        self.add_port(zone, *args)
                    elif key == "masquerade":
                        self.add_masquerade(zone)
                    else:
                        log.error("Zone '%s': Unknown setting '%s:%s', "
                                  "unable to restore.", zone, key, args)
                    # restore old date, sender and timeout
                    if args in _obj.settings[key]:
                        _obj.settings[key][args] = settings[key][args]

        except FirewallError as msg:
            log.error(msg)

    # handle chains, modules and rules for a zone
    def handle_cmr(self, zone, chains, modules, rules, enable):
        cleanup_chains = None
        cleanup_modules = None
        cleanup_rules = None
        
        # handle chains
        if enable:
            for (table, chain) in chains:
                self.add_chain(zone, table, chain)

        # handle modules
        module_return = self._fw.handle_modules(modules, enable)
        if module_return == None:
            # handle rules
            rules_return = self._fw.handle_rules2(rules, enable)
            if rules_return != None:
                (cleanup_rules, msg) = rules_return
                cleanup_chains = chains
                cleanup_modules = modules
        else:
            # error loading modules
            (cleanup_modules, msg) = module_return

        # error case:
        if cleanup_chains != None or cleanup_modules != None or \
                cleanup_rules != None:
            # cleanup chains
            for (table, chain) in cleanup_chains:
                if enable:
                    self.remove_chain(zone, table, chain)
                else:
                    self.add_chain(zone, table, chain)
            # cleanup modules
            if cleanup_modules != None:
                self._fw.handle_modules(cleanup_modules, not enable)
            # cleanup rules
            if cleanup_rules != None:
                self._fw.handle_rules2(cleanup_rules, not enable)

        # cleanup chains last
        if not enable:
            for (table, chain) in chains:
                self.remove_chain(zone, table, chain)

        # report error case
        if cleanup_chains != None or cleanup_modules != None or \
                cleanup_rules != None:
            log.error(msg)
            return msg

        return None

    # INTERFACES

    def check_interface(self, interface):
        self._fw.check_interface(interface)

    def __interface_id(self, interface):
        self.check_interface(interface)
        return interface

    def __interface(self, enable, zone, interface, append=False):
        rules = [ ]
        for table in ZONE_CHAINS:
            for chain in ZONE_CHAINS[table]:
                for ipv in ZONE_CHAINS[table][chain]:
                    # create needed chains if not done already
                    if enable:
                        self.add_chain(zone, table, chain)

                    # handle trust and block zone directly, accept or reject
                    # others will be placed into the proper zone chains
                    opt = INTERFACE_ZONE_OPTS[chain]
                    target = self._zones[zone].target.format(
                        chain=SHORTCUTS[chain], zone=zone)
                    if target in [ "REJECT", "%%REJECT%%" ] and \
                            chain not in [ "INPUT", "FORWARD_IN", "FORWARD_OUT", "OUTPUT" ]:
                        # REJECT is only valid in the INPUT, FORWARD and
                        # OUTPUT chains, and user-defined chains which are 
                        # only called from those chains
                        continue
                    if target == "DROP" and table == "nat":
                        # DROP is not supported in nat table
                        continue
                    action = "-g" if "_ZONE_" in target else "-j"
                    rule = [ "%s_ZONES" % chain, "-t", table,
                             opt, interface, action, target ]
                    if enable and not append:
                        rule.insert(1, "1")
                    rules.append((ipv, rule))

        # handle rules
        ret = self._fw.handle_rules(rules, enable, not append)
        if ret:
            (cleanup_rules, msg) = ret
            self._fw.handle_rules(cleanup_rules, not enable)
            log.debug2(msg)
            raise FirewallError(COMMAND_FAILED, msg)

        if not enable:
            self.remove_chain(zone, table, chain)

    def add_interface(self, zone, interface, sender=None):
        self._fw.check_panic()
        _zone = self._fw.check_zone(zone)
        _obj = self._zones[_zone]

        interface_id = self.__interface_id(interface)

        if interface_id in _obj.settings["interfaces"]:
            raise FirewallError(ZONE_ALREADY_SET)
        if self.get_zone_of_interface(interface) != None:
            raise FirewallError(ZONE_CONFLICT)

        self.__interface(True, _zone, interface)

        _obj.settings["interfaces"][interface_id] = \
            self.__gen_settings(0, sender)
        # add information whether we add to default or specific zone
        _obj.settings["interfaces"][interface_id]["__default__"] = (not zone or zone == "")

        return _zone

    def change_zone_of_interface(self, zone, interface, sender=None):
        self._fw.check_panic()
        _old_zone = self.get_zone_of_interface(interface)
        _new_zone = self._fw.check_zone(zone)

        if _new_zone == _old_zone:
            return _old_zone

        if _old_zone != None:
            self.remove_interface(_old_zone, interface)

        return self.add_interface(zone, interface, sender)

    def change_default_zone(self, old_zone, new_zone):
        self._fw.check_panic()

        self.__interface(True, new_zone, "+", True)
        if old_zone != None and old_zone != "":
            self.__interface(False, old_zone, "+", True)

    def remove_interface(self, zone, interface):
        self._fw.check_panic()
        zoi = self.get_zone_of_interface(interface)
        if zoi == None:
            raise FirewallError(UNKNOWN_INTERFACE, interface)
        _zone = zoi if zone == "" else self._fw.check_zone(zone)
        if zoi != _zone:
            raise FirewallError(ZONE_CONFLICT)

        _obj = self._zones[_zone]
        interface_id = self.__interface_id(interface)
        self.__interface(False, _zone, interface)

        if interface_id in _obj.settings["interfaces"]:
            del _obj.settings["interfaces"][interface_id]

        return _zone

    def query_interface(self, zone, interface):
        return self.__interface_id(interface) in self.get_settings(zone)["interfaces"]

    def list_interfaces(self, zone):
        return sorted(self.get_settings(zone)["interfaces"].keys())

    # SOURCES

    def check_source(self, source):
        if checkIPnMask(source):
            return "ipv4"
        elif checkIP6nMask(source):
            return "ipv6"
        else:
            raise FirewallError(INVALID_ADDR, source)

    def __source_id(self, source):
        ipv = self.check_source(source)
        return (ipv, source)

    def __source(self, enable, zone, ipv, source):
        rules = [ ]

        for table in ZONE_CHAINS:
            for chain in ZONE_CHAINS[table]:
                # create needed chains if not done already
                if enable:
                    self.add_chain(zone, table, chain)

                # handle trust and block zone directly, accept or reject
                # others will be placed into the proper zone chains
                opt = INTERFACE_ZONE_OPTS[chain]

                # transform INTERFACE_ZONE_OPTS for source address
                if opt == "-i":
                    opt = "-s"
                if opt == "-o":
                    opt = "-d"

                target = self._zones[zone].target.format(
                    chain=SHORTCUTS[chain], zone=zone)
                if target in [ "REJECT", "%%REJECT%%" ] and \
                        chain not in [ "INPUT", "FORWARD", "OUTPUT" ]:
                    # REJECT is only valid in the INPUT, FORWARD and
                    # OUTPUT chains, and user-defined chains which are 
                    # only called from those chains
                    continue
                if target == "DROP" and table == "nat":
                    # DROP is not supported in nat table
                    continue
                # append rule
                action = "-g" if "_ZONE_" in target else "-j"
                rule = [ "%s_ZONES_SOURCE" % chain, "-t", table,
                         opt, source, action, target ]
                rules.append((ipv, rule))

        # handle rules
        ret = self._fw.handle_rules(rules, enable)
        if ret:
            (cleanup_rules, msg) = ret
            self._fw.handle_rules(cleanup_rules, not enable)
            log.debug2(msg)
            raise FirewallError(COMMAND_FAILED, msg)

        if not enable:
            self.remove_chain(zone, table, chain)

    def add_source(self, zone, source, sender=None):
        self._fw.check_panic()
        _zone = self._fw.check_zone(zone)
        _obj = self._zones[_zone]
        source_id = self.__source_id(source)

        if source_id in _obj.settings["sources"]:
            raise FirewallError(ZONE_ALREADY_SET)
        if self.get_zone_of_source(source) != None:
            raise FirewallError(ZONE_CONFLICT)

        self.__source(True, _zone, source_id[0], source_id[1])

        _obj.settings["sources"][source_id] = \
            self.__gen_settings(0, sender)
        # add information whether we add to default or specific zone
        _obj.settings["sources"][source_id]["__default__"] = (not zone or zone == "")

        return _zone

    def change_zone_of_source(self, zone, source, sender=None):
        self._fw.check_panic()
        _old_zone = self.get_zone_of_source(source)
        _new_zone = self._fw.check_zone(zone)

        if _new_zone == _old_zone:
            return _old_zone

        if _old_zone != None:
            self.remove_source(_old_zone, source)

        return self.add_source(zone, source, sender)

    def remove_source(self, zone, source):
        self._fw.check_panic()
        zos = self.get_zone_of_source(source)
        if zos == None:
            raise FirewallError(UNKNOWN_SOURCE, source)
        _zone = zos if zone == "" else self._fw.check_zone(zone)
        if zos != _zone:
            raise FirewallError(ZONE_CONFLICT)

        _obj = self._zones[_zone]
        source_id = self.__source_id(source)
        self.__source(False, _zone, source_id[0], source_id[1])

        if source_id in _obj.settings["sources"]:
            del _obj.settings["sources"][source_id]

        return _zone

    def query_source(self, zone, source):
        return self.__source_id(source) in self.get_settings(zone)["sources"]

    def list_sources(self, zone):
        return [ k[1] for k in self.get_settings(zone)["sources"].keys() ]

    # RICH LANGUAGE

    def check_rule(self, rule):
        rule.check()

    def __rule_id(self, rule):
        self.check_rule(rule)
        return (str(rule))

    def __rule_source(self, source, command):
        if source:
            if source.invert:
                command.append("!")
            command += [ "-s", source.addr ]

    def __rule_destination(self, destination, command):
        if destination:
            if destination.invert:
                command.append("!")
            command += [ "-d", destination.addr ]

    def __rule_limit(self, limit):
        if limit:
            return [ "-m", "limit", "--limit", limit.value ]
        return [ ]

    def __rule_log(self, ipv, table, target, rule, command, rules):
        if not rule.log:
            return
        chain = "%s_log" % target
        _command = command[:]
        _command += [ "-j", "LOG" ]
        if rule.log.prefix:
            _command += [ "--log-prefix", '%s' % rule.log.prefix ]
        if rule.log.level:
            _command += [ "--log-level", '%s' % rule.log.level ]
        _command += self.__rule_limit(rule.log.limit)
        rules.append((ipv, table, chain, _command))

    def __rule_audit(self, ipv, table, target, rule, command, rules):
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
        rules.append((ipv, table, chain, _command))

    def __rule_action(self, ipv, table, target, rule, command, rules):
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
        else:
            raise FirewallError(INVALID_RULE,
                                "Unknown action %s" % type(rule.action))
        _command += self.__rule_limit(rule.action.limit)
        rules.append((ipv, table, chain, _command))

    def __rule(self, enable, zone, rule, mark_id):
                       
        chains = [ ]
        modules = [ ]
        rules = [ ]

        if rule.family != None:
            ipvs = [ rule.family ]
        else:
            ipvs = [ "ipv4", "ipv6" ]

        for ipv in ipvs:

            # SERVICE
            if type(rule.element) == Rich_Service:
                svc = self._fw.service.get_service(rule.element.name)

                if len(svc.destination) > 0:
                    if ipv not in svc.destination:
                        # destination is set, only use if it contains ipv
                        raise FirewallError(INVALID_RULE,
                                            "Service %s is not usable with %s" % 
                                            (rule.element.name, ipv))
                    if svc.destination[ipv] != "" and rule.destination:
                        # we can not use two destinations at the same time
                        raise FirewallError(INVALID_RULE,
                                            "Destination conflict with service.")

                table = "filter"
                chains.append([table, "INPUT" ])
                if type(rule.action) == Rich_Accept:
                    # only load modules for accept action
                    modules += svc.modules
                target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["INPUT"],
                                                    zone=zone)

                # create rules
                for (port,proto) in svc.ports:
                    table = "filter"
                    command = [ ]
                    self.__rule_source(rule.source, command)
                    self.__rule_destination(rule.destination, command)

                    if proto in [ "tcp", "udp" ]:
                        command += [ "-m", proto, "-p", proto ]
                    else:
                        if ipv == "ipv4":
                            command += [ "-p", proto ]
                        else:
                            command += [ "-m", "ipv6header", "--header", proto ]
                    if port:
                        command += [ "--dport", "%s" % portStr(port) ]
                    if ipv in svc.destination and svc.destination[ipv] != "":
                        command += [ "-d",  svc.destination[ipv] ]
                    command += [ "-m", "conntrack", "--ctstate", "NEW" ]

                    self.__rule_log(ipv, table, target, rule, command, rules)
                    self.__rule_audit(ipv, table, target, rule, command, rules)
                    self.__rule_action(ipv, table, target, rule, command, rules)

            # PORT
            elif type(rule.element) == Rich_Port:
                port = rule.element.port
                protocol = rule.element.protocol
                self.check_port(port, protocol)

                table = "filter"
                chains.append([ table, "INPUT" ])
                target = self._zones[zone].target.format(chain=SHORTCUTS["INPUT"],
                                                         zone=zone)

                command = [ ]
                self.__rule_source(rule.source, command)
                self.__rule_destination(rule.destination, command)
                command += [ "-m", protocol, "-p", protocol,
                           "--dport", portStr(port),
                           "-m", "conntrack", "--ctstate", "NEW" ]

                self.__rule_log(ipv, table, target, rule, command, rules)
                self.__rule_audit(ipv, table, target, rule, command, rules)
                self.__rule_action(ipv, table, target, rule, command, rules)

            # PROTOCOL
            elif type(rule.element) == Rich_Protocol:
                protocol = rule.element.value
                self.check_protocol(protocol)

                table = "filter"
                chains.append([ table, "INPUT" ])
                target = self._zones[zone].target.format(chain=SHORTCUTS["INPUT"],
                                                         zone=zone)

                command = [ ]
                self.__rule_source(rule.source, command)
                self.__rule_destination(rule.destination, command)
                command += [ "-p", protocol, 
                             "-m", "conntrack", "--ctstate", "NEW" ]

                self.__rule_log(ipv, table, target, rule, command, rules)
                self.__rule_audit(ipv, table, target, rule, command, rules)
                self.__rule_action(ipv, table, target, rule, command, rules)

            # MASQUERADE
            elif type(rule.element) == Rich_Masquerade:
                if enable:
                    enable_ip_forwarding(ipv)

                chains.append([ "nat", "POSTROUTING" ])
                chains.append([ "filter", "FORWARD_OUT" ])

                # POSTROUTING
                target = DEFAULT_ZONE_TARGET.format(
                    chain=SHORTCUTS["POSTROUTING"], zone=zone)
                command = [ ]
                self.__rule_source(rule.source, command)
                self.__rule_destination(rule.destination, command)
                command += [ "-j", "MASQUERADE" ]
                rules.append((ipv, "nat", "%s_allow" % target, command))

                # FORWARD_OUT
                target = DEFAULT_ZONE_TARGET.format(
                    chain=SHORTCUTS["FORWARD_OUT"], zone=zone)
                command = [ ]
                # reverse source/destination !
                self.__rule_source(rule.destination, command)
                self.__rule_destination(rule.source, command)
                command += [ "-j", "ACCEPT" ]
                rules.append((ipv, "filter", "%s_allow" % target, command))

            # FORWARD PORT
            elif type(rule.element) == Rich_ForwardPort:
                if enable:
                    enable_ip_forwarding(ipv)

                port = rule.element.port
                protocol = rule.element.protocol
                toport = rule.element.to_port
                toaddr = rule.element.to_address
                self.check_forward_port(ipv, port, protocol, toport, toaddr)

                if enable:
                    mark_id = self._fw.new_mark()

                filter_chain = "INPUT" if not toaddr else "FORWARD_IN"

                chains.append([ "mangle", "PREROUTING" ])
                chains.append([ "nat", "PREROUTING" ])
                chains.append([ "filter", filter_chain ])

                mark_str = "0x%x" % mark_id
                port_str = portStr(port)

                dest = [ ]
                to = ""
                if toaddr:
                    to += toaddr

                if toport and toport != "":
                    toport_str = portStr(toport)
                    dest = [ "--dport", toport_str ]
                    to += ":%s" % portStr(toport, "-")

                mark = [ "-m", "mark", "--mark", mark_str ]

                target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["PREROUTING"],
                                                    zone=zone)
                command = [ ]
                self.__rule_source(rule.source, command)
                command += [ "-p", protocol, "--dport", port_str,
                             "-j", "MARK", "--set-mark", mark_str ]
                rules.append((ipv, "mangle", "%s_allow" % target, command))

                # local and remote
                command = [ "-p", protocol ] + mark + \
                    [ "-j", "DNAT", "--to-destination", to ]
                rules.append((ipv, "nat", "%s_allow" % target, command))

                target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS[filter_chain],
                                                    zone=zone)
                command = [ "-m", "conntrack", "--ctstate", "NEW" ] + \
                    mark + [ "-j", "ACCEPT" ]
                rules.append((ipv, "filter", "%s_allow" % target, command))

                if not enable:
                    self._fw.del_mark(mark_id)

            # ICMP BLOCK
            elif type(rule.element) == Rich_IcmpBlock:
                ict = self._fw.icmptype.get_icmptype(rule.element.name)

                if rule.action and type(rule.action) == Rich_Accept:
                    # icmp block might have reject or drop action, but not accept
                    raise FirewallError(INVALID_RULE,
                                        "IcmpBlock not usable with accept action")
                if ict.destination and ipv not in ict.destination:
                    raise FirewallError(INVALID_RULE,
                                        "IcmpBlock %s not usable with %s" % 
                                        (rule.element.name, ipv))

                table = "filter"
                chains.append([ table, "INPUT" ])
                chains.append([ table, "FORWARD_IN" ])

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
                self.__rule_log(ipv, table, target, rule, command, rules)
                self.__rule_audit(ipv, table, target, rule, command, rules)
                if rule.action:
                    self.__rule_action(ipv, table, target, rule, command, rules)
                else:
                    command += [ "-j", "%%REJECT%%" ]
                    rules.append((ipv, table, "%s_deny" % target, command))

                # FORWARD_IN
                target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["FORWARD_IN"],
                                                    zone=zone)
                command = [ ]
                self.__rule_source(rule.source, command)
                self.__rule_destination(rule.destination, command)
                command += proto + match
                self.__rule_log(ipv, table, target, rule, command, rules)
                self.__rule_audit(ipv, table, target, rule, command, rules)
                if rule.action:
                    self.__rule_action(ipv, table, target, rule, command, rules)
                else:
                    command += [ "-j", "%%REJECT%%" ]
                    rules.append((ipv, table, "%s_deny" % target, command))

            elif rule.element == None:
                # source action
                table = "filter"
                chains.append([ table, "INPUT" ])
                target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["INPUT"],
                                                    zone=zone)
                command = [ ]
                self.__rule_source(rule.source, command)
                self.__rule_log(ipv, table, target, rule, command, rules)
                self.__rule_audit(ipv, table, target, rule, command, rules)
                self.__rule_action(ipv, table, target, rule, command, rules)

            # EVERYTHING ELSE
            else:
                raise FirewallError(INVALID_RULE, "Unknown element %s" % 
                                    type(rule.element))

        msg = self.handle_cmr(zone, chains, modules, rules, enable)
        if msg != None:
            raise FirewallError(COMMAND_FAILED, msg)

        return mark_id

    def add_rule(self, zone, rule, timeout=0, sender=None):
        _zone = self._fw.check_zone(zone)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        rule_id = self.__rule_id(rule)
        if rule_id in _obj.settings["rules"]:
            raise FirewallError(ALREADY_ENABLED)

        mark = self.__rule(True, _zone, rule, None)

        _obj.settings["rules"][rule_id] = \
            self.__gen_settings(timeout, sender, mark=mark)

        return _zone

    def remove_rule(self, zone, rule):
        _zone = self._fw.check_zone(zone)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        rule_id = self.__rule_id(rule)
        if not rule_id in _obj.settings["rules"]:
            raise FirewallError(NOT_ENABLED)

        if "mark" in _obj.settings["rules"][rule_id]:
            mark = _obj.settings["rules"][rule_id]["mark"]
        else:
            mark = None
        self.__rule(False, _zone, rule, mark)

        if rule_id in _obj.settings["rules"]:
            del _obj.settings["rules"][rule_id]

        return _zone

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

    def __service(self, enable, zone, service):
        svc = self._fw.service.get_service(service)

        if enable:
            self.add_chain(zone, "filter", "INPUT")

        rules = [ ]
        for ipv in [ "ipv4", "ipv6" ]:
            if len(svc.destination) > 0 and ipv not in svc.destination:
                # destination is set, only use if it contains ipv
                continue

            # handle rules
            for (port,proto) in svc.ports:
                target = DEFAULT_ZONE_TARGET.format(
                    chain=SHORTCUTS["INPUT"], zone=zone)
                rule = [ "%s_allow" % (target), "-t", "filter" ]
                if proto in [ "tcp", "udp" ]:
                    rule += [ "-m", proto, "-p", proto ]
                else:
                    if ipv == "ipv4":
                        rule += [ "-p", proto ]
                    else:
                        rule += [ "-m", "ipv6header", "--header", proto ]
                if port:
                    rule += [ "--dport", "%s" % portStr(port) ]
                if ipv in svc.destination and svc.destination[ipv] != "":
                    rule += [ "-d",  svc.destination[ipv] ]
                rule += [ "-m", "conntrack", "--ctstate", "NEW" ]
                rule += [ "-j", "ACCEPT" ]
                rules.append((ipv, rule))

        cleanup_rules = None
        cleanup_modules = None
        msg = None

        # handle rules
        ret = self._fw.handle_rules(rules, enable)
        if ret == None: # no error, handle modules
            mod_ret = self._fw.handle_modules(svc.modules, enable)
            if mod_ret != None: # error loading modules
                (cleanup_modules, msg) = mod_ret
                cleanup_rules = rules
        else: # ret != None
            (cleanup_rules, msg) = ret

        if cleanup_rules!= None or cleanup_modules != None:
            if cleanup_rules:
                self._fw.handle_rules(cleanup_rules, not enable)
            if cleanup_modules:
                self._fw.handle_modules(cleanup_modules, not enable)
            raise FirewallError(COMMAND_FAILED, msg)

        if not enable:
            self.remove_chain(zone, "filter", "INPUT")

    def add_service(self, zone, service, timeout=0, sender=None):
        _zone = self._fw.check_zone(zone)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        service_id = self.__service_id(service)
        if service_id in _obj.settings["services"]:
            raise FirewallError(ALREADY_ENABLED)

        self.__service(True, _zone, service)

        _obj.settings["services"][service_id] = \
            self.__gen_settings(timeout, sender)

        return _zone

    def remove_service(self, zone, service):
        _zone = self._fw.check_zone(zone)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        service_id = self.__service_id(service)
        if not service_id in _obj.settings["services"]:
            raise FirewallError(NOT_ENABLED)

        self.__service(False, _zone, service)

        if service_id in _obj.settings["services"]:
            del _obj.settings["services"][service_id]

        return _zone

    def query_service(self, zone, service):
        return (self.__service_id(service) in self.get_settings(zone)["services"])

    def list_services(self, zone):
        return sorted(self.get_settings(zone)["services"].keys())

    # PORTS

    def check_port(self, port, protocol):
        self._fw.check_port(port)
        self._fw.check_protocol(protocol)

    def __port_id(self, port, protocol):
        self.check_port(port, protocol)
        return (portStr(port, "-"), protocol)

    def __port(self, enable, zone, port, protocol):
        if enable:
            self.add_chain(zone, "filter", "INPUT")

        rules = [ ]
        for ipv in [ "ipv4", "ipv6" ]:
            target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS["INPUT"],
                                                     zone=zone)
            rules.append((ipv, [ "%s_allow" % (target),
                                 "-t", "filter",
                                 "-m", protocol, "-p", protocol,
                                 "--dport", portStr(port),
                                 "-m", "conntrack", "--ctstate", "NEW",
                                 "-j", "ACCEPT" ]))

        # handle rules
        ret = self._fw.handle_rules(rules, enable)
        if ret:
            (cleanup_rules, msg) = ret
            self._fw.handle_rules(cleanup_rules, not enable)
            raise FirewallError(COMMAND_FAILED, msg)
        
        if not enable:
            self.remove_chain(zone, "filter", "INPUT")

    def add_port(self, zone, port, protocol, timeout=0, sender=None):
        _zone = self._fw.check_zone(zone)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        port_id = self.__port_id(port, protocol)
        if port_id in _obj.settings["ports"]:
            raise FirewallError(ALREADY_ENABLED)

        self.__port(True, _zone, port, protocol)

        _obj.settings["ports"][port_id] = \
            self.__gen_settings(timeout, sender)

        return _zone

    def remove_port(self, zone, port, protocol):
        _zone = self._fw.check_zone(zone)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        port_id = self.__port_id(port, protocol)
        if not port_id in _obj.settings["ports"]:
            raise FirewallError(NOT_ENABLED)

        self.__port(False, _zone, port, protocol)

        if port_id in _obj.settings["ports"]:
            del _obj.settings["ports"][port_id]

        return _zone

    def query_port(self, zone, port, protocol):
        return self.__port_id(port, protocol) in self.get_settings(zone)["ports"]

    def list_ports(self, zone):
        return list(self.get_settings(zone)["ports"].keys())

    # PROTOCOLS

    def check_protocol(self, protocol):
        if not checkProtocol(protocol):
            raise FirewallError(INVALID_PROTOCOL, protocol)

    # MASQUERADE

    def __masquerade_id(self):
        return True

    def __masquerade(self, enable, zone):
        if enable:
            self.add_chain(zone, "nat", "POSTROUTING")
            self.add_chain(zone, "filter", "FORWARD_OUT")
            enable_ip_forwarding("ipv4")

        rules = [ ]
        for ipv in [ "ipv4" ]: # IPv4 only!
            target = DEFAULT_ZONE_TARGET.format(
                chain=SHORTCUTS["POSTROUTING"], zone=zone)
            rules.append((ipv, [ "%s_allow" % (target), "!", "-i", "lo",
                                 "-t", "nat", "-j", "MASQUERADE" ]))
            # FORWARD_OUT
            target = DEFAULT_ZONE_TARGET.format(
                chain=SHORTCUTS["FORWARD_OUT"], zone=zone)
            rules.append((ipv, [ "%s_allow" % (target),
                                 "-t", "filter", "-j", "ACCEPT" ]))

        # handle rules
        ret = self._fw.handle_rules(rules, enable)
        if ret:
            (cleanup_rules, msg) = ret
            self._fw.handle_rules(cleanup_rules, not enable)
            raise FirewallError(COMMAND_FAILED, msg)

        if not enable:
            self.remove_chain(zone, "nat", "POSTROUTING")
            self.remove_chain(zone, "filter", "FORWARD_OUT")

    def add_masquerade(self, zone, timeout=0, sender=None):
        _zone = self._fw.check_zone(zone)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        masquerade_id = self.__masquerade_id()
        if masquerade_id in _obj.settings["masquerade"]:
            raise FirewallError(ALREADY_ENABLED)

        self.__masquerade(True, _zone)

        _obj.settings["masquerade"][masquerade_id] = \
            self.__gen_settings(timeout, sender)

        return _zone

    def remove_masquerade(self, zone):
        _zone = self._fw.check_zone(zone)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        masquerade_id = self.__masquerade_id()
        if masquerade_id not in _obj.settings["masquerade"]:
            raise FirewallError(NOT_ENABLED)

        self.__masquerade(False, _zone)

        if masquerade_id in _obj.settings["masquerade"]:
            del _obj.settings["masquerade"][masquerade_id]

        return _zone

    def query_masquerade(self, zone):
        return self.__masquerade_id() in self.get_settings(zone)["masquerade"]

    # PORT FORWARDING

    def check_forward_port(self, ipv, port, protocol, toport=None, toaddr=None):
        self._fw.check_port(port)
        self._fw.check_protocol(protocol)
        if toport:
            self._fw.check_port(toport)
        if toaddr:
            check_single_address(ipv, toaddr)
        if not toport and not toaddr:
            raise FirewallError(INVALID_FORWARD)

    def __forward_port_id(self, port, protocol, toport=None, toaddr=None):
        self.check_forward_port("ipv4", port, protocol, toport, toaddr)
        return (portStr(port, "-"), protocol,
                portStr(toport, "-"), str(toaddr))

    def __forward_port(self, enable, zone, port, protocol, toport=None,
                       toaddr=None, mark_id=None):
        mark_str = "0x%x" % mark_id
        port_str = portStr(port)

        dest = [ ]
        to = ""
        if toaddr:
            to += toaddr

        filter_chain = "INPUT" if not toaddr else "FORWARD_IN"

        if toport and toport != "":
            toport_str = portStr(toport)
            dest = [ "--dport", toport_str ]
            to += ":%s" % portStr(toport, "-")

        mark = [ "-m", "mark", "--mark", mark_str ]

        if enable:
            self.add_chain(zone, "mangle", "PREROUTING")
            self.add_chain(zone, "nat", "PREROUTING")
            self.add_chain(zone, "filter", filter_chain)
            enable_ip_forwarding("ipv4")

        rules = [ ]
        for ipv in [ "ipv4" ]: # IPv4 only!
            target = DEFAULT_ZONE_TARGET.format(
                chain=SHORTCUTS["PREROUTING"], zone=zone)
            rules.append((ipv, [ "%s_allow" % (target),
                                 "-t", "mangle",
                                 "-p", protocol, "--dport", port_str,
                                 "-j", "MARK", "--set-mark", mark_str ]))
            # local and remote
            rules.append((ipv, [ "%s_allow" % (target),
                                 "-t", "nat",
                                 "-p", protocol ] + mark + \
                              [ "-j", "DNAT", "--to-destination", to ]))

            target = DEFAULT_ZONE_TARGET.format(chain=SHORTCUTS[filter_chain],
                                                zone=zone)
            rules.append((ipv, [ "%s_allow" % (target),
                                 "-t", "filter",
                                 "-m", "conntrack", "--ctstate", "NEW" ] + \
                               mark + [ "-j", "ACCEPT" ]))

        # handle rules
        ret = self._fw.handle_rules(rules, enable)
        if ret:
            (cleanup_rules, msg) = ret
            self._fw.handle_rules(cleanup_rules, not enable)
            if enable:
                self._fw.del_mark(mark_id)
            raise FirewallError(COMMAND_FAILED, msg)

        if not enable:
            self.remove_chain(zone, "mangle", "PREROUTING")
            self.remove_chain(zone, "nat", "PREROUTING")
            self.remove_chain(zone, "filter", filter_chain)

    def add_forward_port(self, zone, port, protocol, toport=None,
                         toaddr=None, timeout=0, sender=None):
        _zone = self._fw.check_zone(zone)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        forward_id = self.__forward_port_id(port, protocol, toport, toaddr)
        if forward_id in _obj.settings["forward_ports"]:
            raise FirewallError(ALREADY_ENABLED)

        mark = self._fw.new_mark()
        self.__forward_port(True, _zone, port, protocol, toport, toaddr,
                            mark_id=mark)
        
        _obj.settings["forward_ports"][forward_id] = \
            self.__gen_settings(timeout, sender, mark=mark)

        return _zone

    def remove_forward_port(self, zone, port, protocol, toport=None,
                            toaddr=None):
        _zone = self._fw.check_zone(zone)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        forward_id = self.__forward_port_id(port, protocol, toport, toaddr)
        if not forward_id in _obj.settings["forward_ports"]:
            raise FirewallError(NOT_ENABLED)

        mark = _obj.settings["forward_ports"][forward_id]["mark"]

        self.__forward_port(False, _zone, port, protocol, toport, toaddr,
                            mark_id=mark)

        if forward_id in _obj.settings["forward_ports"]:
            del _obj.settings["forward_ports"][forward_id]
        self._fw.del_mark(mark)

        return _zone

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

    def __icmp_block(self, enable, zone, icmp):
        ict = self._fw.icmptype.get_icmptype(icmp)

        if enable:
            self.add_chain(zone, "filter", "INPUT")
            self.add_chain(zone, "filter", "FORWARD_IN")

        rules = [ ]
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
            rules.append((ipv, [ "%s_deny" % (target),
                                 "-t", "filter", ] + proto + \
                              match + [ "-j", "%%REJECT%%" ]))
            target = DEFAULT_ZONE_TARGET.format(
                chain=SHORTCUTS["FORWARD_IN"], zone=zone)
            rules.append((ipv, [ "%s_deny" % (target),
                                 "-t", "filter", ] + proto + \
                              match + [ "-j", "%%REJECT%%" ]))

        # handle rules
        ret = self._fw.handle_rules(rules, enable)
        if ret:
            (cleanup_rules, msg) = ret
            self._fw.handle_rules(cleanup_rules, not enable)
            raise FirewallError(COMMAND_FAILED, msg)

        if not enable:
            self.remove_chain(zone, "filter", "INPUT")
            self.remove_chain(zone, "filter", "FORWARD_IN")

    def add_icmp_block(self, zone, icmp, timeout=0, sender=None):
        _zone = self._fw.check_zone(zone)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        icmp_id = self.__icmp_block_id(icmp)
        if icmp_id in _obj.settings["icmp_blocks"]:
            raise FirewallError(ALREADY_ENABLED)

        self.__icmp_block(True, _zone, icmp)

        _obj.settings["icmp_blocks"][icmp_id] = \
            self.__gen_settings(timeout, sender)

        return _zone

    def remove_icmp_block(self, zone, icmp):
        _zone = self._fw.check_zone(zone)
        self._fw.check_panic()
        _obj = self._zones[_zone]

        icmp_id = self.__icmp_block_id(icmp)
        if not icmp_id in _obj.settings["icmp_blocks"]:
            raise FirewallError(NOT_ENABLED)

        self.__icmp_block(False, _zone, icmp)

        if icmp_id in _obj.settings["icmp_blocks"]:
            del _obj.settings["icmp_blocks"][icmp_id]

        return _zone

    def query_icmp_block(self, zone, icmp):
        return self.__icmp_block_id(icmp) in self.get_settings(zone)["icmp_blocks"]

    def list_icmp_blocks(self, zone):
        return sorted(self.get_settings(zone)["icmp_blocks"].keys())
