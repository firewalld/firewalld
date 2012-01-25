#
# Copyright (C) 2010-2012 Red Hat, Inc.
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

import os.path, sys, time

import fw_services
import fw_icmp
import fw_functions
import ipXtables
import ebtables
import modules
from firewall.errors import *

CHAINS = {
    "raw": [ "PREROUTING", "OUTPUT" ],
    "mangle": [ "PREROUTING", "POSTROUTING", "INPUT", "OUTPUT", "FORWARD" ],
    "nat": [ "PREROUTING", "POSTROUTING", "OUTPUT" ],
    "filter": [ "INPUT", "OUTPUT", "FORWARD" ],
}

REJECT_TYPE = {
    "ipv4": "icmp-host-prohibited",
    "ipv6": "icmp6-adm-prohibited",
}

MANGLE_RULES = [
    [ "-N", "PREROUTING_virt" ],
    [ "-N", "PREROUTING_forward" ],
    [ "-N", "PREROUTING_custom" ],
    [ "-N", "INPUT_virt" ],
    [ "-N", "INPUT_custom" ],
    [ "-N", "FORWARD_virt" ],
    [ "-N", "FORWARD_custom" ],
    [ "-N", "OUTPUT_virt" ],
    [ "-N", "OUTPUT_custom" ],
    [ "-N", "POSTROUTING_virt" ],
    [ "-N", "POSTROUTING_custom" ],
    
    [ "-I", "PREROUTING", "1", "-j", "PREROUTING_virt" ],
    [ "-I", "PREROUTING", "2", "-j", "PREROUTING_forward" ],
    [ "-I", "PREROUTING", "3", "-j", "PREROUTING_custom" ],
    [ "-I", "INPUT", "1", "-j", "INPUT_virt" ],
    [ "-I", "INPUT", "2", "-j", "INPUT_custom" ],
    [ "-I", "FORWARD", "1", "-j", "FORWARD_virt" ],
    [ "-I", "FORWARD", "2", "-j", "FORWARD_custom" ],
    [ "-I", "OUTPUT", "1", "-j", "OUTPUT_virt" ],
    [ "-I", "OUTPUT", "2", "-j", "OUTPUT_custom" ],
    [ "-I", "POSTROUTING", "1", "-j", "POSTROUTING_virt" ],
    [ "-I", "POSTROUTING", "2", "-j", "POSTROUTING_custom" ],
]

NAT_RULES = [
    [ "-N", "PREROUTING_virt" ],
    [ "-N", "PREROUTING_forward" ],
    [ "-N", "PREROUTING_custom" ],
    [ "-N", "OUTPUT_virt" ],
    [ "-N", "OUTPUT_custom" ],
    [ "-N", "POSTROUTING_virt" ],
    [ "-N", "POSTROUTING_masq" ],
    [ "-N", "POSTROUTING_custom" ],

    [ "-I", "PREROUTING", "1", "-j", "PREROUTING_virt" ],
    [ "-I", "PREROUTING", "2", "-j", "PREROUTING_forward" ],
    [ "-I", "PREROUTING", "3", "-j", "PREROUTING_custom" ],
    [ "-I", "OUTPUT", "1", "-j", "OUTPUT_virt" ],
    [ "-I", "OUTPUT", "2", "-j", "OUTPUT_custom" ],
    [ "-I", "POSTROUTING", "1", "-j", "POSTROUTING_virt" ],
    [ "-I", "POSTROUTING", "2", "-j", "POSTROUTING_masq" ],
    [ "-I", "POSTROUTING", "3", "-j", "POSTROUTING_custom" ],
]

FILTER_RULES = [
    [ "-N", "INPUT_virt" ],
    [ "-N", "INPUT_forward" ],
    [ "-N", "INPUT_icmp" ],
    [ "-N", "INPUT_ports" ],
    [ "-N", "INPUT_services" ],
    [ "-N", "INPUT_trusted" ],
    [ "-N", "INPUT_custom" ],

    [ "-N", "FORWARD_virt" ],
    [ "-N", "FORWARD_forward" ],
    [ "-N", "FORWARD_icmp" ],
    [ "-N", "FORWARD_trusted" ],
    [ "-N", "FORWARD_masq" ],
    [ "-N", "FORWARD_custom" ],

    [ "-N", "OUTPUT_virt" ],
    [ "-N", "OUTPUT_custom" ],

    [ "-I", "INPUT", "1", "-j", "INPUT_virt" ],
    [ "-I", "INPUT", "2", "-m", "state", "--state", "INVALID",
      "-j", "REJECT", "--reject-with", "%%REJECT_TYPE%%" ],
    [ "-I", "INPUT", "3", "-m", "state", "--state", "RELATED,ESTABLISHED",
      "-j", "ACCEPT" ],
    [ "-I", "INPUT", "4", "-i", "lo", "-j", "ACCEPT" ],
    [ "-I", "INPUT", "5", "-p", "icmp", "-j", "INPUT_icmp" ],
    [ "-I", "INPUT", "6", "-p", "icmp", "-j", "ACCEPT" ],
    [ "-I", "INPUT", "7", "-j", "INPUT_trusted" ],
    [ "-I", "INPUT", "8", "-j", "INPUT_forward" ],
    [ "-I", "INPUT", "9", "-j", "INPUT_services" ],
    [ "-I", "INPUT", "10", "-j", "INPUT_ports" ],
    [ "-I", "INPUT", "11", "-j", "INPUT_custom" ],
    [ "-I", "INPUT", "12", "-j", "REJECT", "--reject-with", "%%REJECT_TYPE%%" ],

    [ "-I", "FORWARD", "1", "-j", "FORWARD_virt" ],
    [ "-I", "FORWARD", "2", "-m", "state", "--state", "INVALID",
      "-j", "REJECT", "--reject-with", "%%REJECT_TYPE%%" ],
    [ "-I", "FORWARD", "3", "-m", "state", "--state", "RELATED,ESTABLISHED",
      "-j", "ACCEPT" ],
    [ "-I", "FORWARD", "4", "-i", "lo", "-j", "ACCEPT" ],
    [ "-I", "FORWARD", "5", "-p", "icmp", "-j", "FORWARD_icmp" ],
    [ "-I", "FORWARD", "6", "-p", "icmp", "-j", "ACCEPT" ],
    [ "-I", "FORWARD", "7", "-j", "FORWARD_trusted" ],
    [ "-I", "FORWARD", "8", "-j", "FORWARD_forward" ],
    [ "-I", "FORWARD", "9", "-j", "FORWARD_masq" ],
    [ "-I", "FORWARD", "10", "-j", "FORWARD_custom" ],
    [ "-I", "FORWARD", "11",
      "-j", "REJECT", "--reject-with", "%%REJECT_TYPE%%" ],

    [ "-I", "OUTPUT", "1", "-j", "OUTPUT_virt" ],
    [ "-I", "OUTPUT", "2", "-j", "OUTPUT_custom" ],
]

class Firewall:
    def __init__(self):
        self.__init_vars()
        self.start()

    def __init_vars(self):
        self._initialized = False
        self._panic = False
        self._icmp_block = [ ]
        self._trusted = [ ]
        self._forward = { } # forward entry: mark
        self._services = [ ]
        self._ports = [ ]
        self._masquerade = [ ]
        self._custom = [ ]
        self._virt_rules = [ ]
        self._virt_chains = [ ]
        self._module_refcount = { }
        self._marks = [ ]
        self._min_mark = 100

        self._rules = { }
        self._rules_by_id = { }

        # TODO: check if ipv4 is enabled:
        self._ip4tables = ipXtables.ip4tables()
        # TODO: check if ipv6 is enabled:
        self._ip6tables = ipXtables.ip6tables()

        self._ebtables = ebtables.ebtables()

        self._modules = modules.modules()

    def start(self):
        # initialize firewall
        self._flush()
        self._set_policy("ACCEPT")
        self._apply_default_rules()
        self._initialized = True

    def __new_mark(self):
        # return first unused mark
        i = self._min_mark
        while i in self._marks:
            i += 1
        self._marks.append(i)
        return i

    def __del_mark(self, mark):
        self._marks.remove(mark)

    def __handle_rules(self, rules, enable):
        append_delete = { True: "-A", False: "-D", }

        # appends rules
        # returns None if all worked, else (cleanup rules, error message)
        i = 0
        for i in xrange(len(rules)):
            (ipv, rule) = rules[i]
            try:
                self.__rule(ipv, [ append_delete[enable], ] + rule)
            except Exception, msg:
                if enable:
                    return (rules[:i], msg) # cleanup rules and error message
                # else: ignore cleanup
        return None

    def __handle_modules(self, modules, enable):
        for i in xrange(len(modules)):
            module = modules[i]
            if enable:
                (status, msg) = self._modules.load_module(module)
            else:
                if self._module_refcount[module] > 1:
                    status = 0 # module referenced more then one, do not unload
                else:
                    (status, msg) = self._modules.unload_module(module)
            if status != 0:
                if enable:
                    return (modules[:i], msg) # cleanup modules and error msg
                # else: ignore cleanup

            if enable:
                self._module_refcount.setdefault(module, 0)
                self._module_refcount[module] += 1
            else:
                if module in self._module_refcount:
                     self._module_refcount[module] -= 1
                     if self._module_refcount[module] == 0:
                         del self._module_refcount[module]
        return None

    def __apply_default_rules(self, ipv):
        for (prefix, rules) in [ ([ "-t", "mangle" ], MANGLE_RULES),
                                 ([ "-t", "nat" ], NAT_RULES),
                                 ([ "-t", "filter" ], FILTER_RULES) ]:
            if ipv == "ipv6" and rules == NAT_RULES:
                # no nat for IPv6
                continue
            for rule in rules:
                _rule = prefix+rule[:]
                try:
                    i = _rule.index("%%REJECT_TYPE%%")
                except:
                    pass
                else:
                    _rule[i] = REJECT_TYPE[ipv]

                if ipv == "ipv4":
                    self._ip4tables.set_rule(_rule)
                else:
                    self._ip6tables.set_rule(_rule)

#                try:
#                except Exception, msg:
# TODO: better handling of init error
#                    if "Chain already exists." in msg:
#                        continue
#                    # TODO: log msg
#                    raise FirewallError, <code>

    def _apply_default_rules(self):
        for ipv in [ "ipv4", "ipv6" ]:
            self.__apply_default_rules(ipv)

    def __get_firewall_modules(self):
        modules = [ ]
        (mods, deps) = self._modules.loaded_modules()

        for mod in [ "ip_tables", "ip6_tables", "nf_conntrack" ]:
            self._modules.get_deps(mod, deps, modules)

        for mod in mods:
            if mod.startswith("iptable_") or mod.startswith("ip6table_") or \
                    mod.startswith("nf_") or mod.startswith("xt_") or \
                    mod.startswith("ipt_") or mod.startswith("ip6t_") :
                self._modules.get_deps(mod, deps, modules)
        return modules

    def _unload_firewall_modules(self):
        modules = self.__get_firewall_modules()
        for mod in modules:
            self._modules.unload_module(mod)

    def _flush(self):
        self._ip4tables.flush()
        self._ip6tables.flush()

    def _set_policy(self, policy, which="used"):
        self._ip4tables.set_policy(policy, which)
        self._ip6tables.set_policy(policy, which)

    def _panic(self):
        self._flush()
        self._set_policy("DROP", "all")

    def __rule(self, ipv, rule):
        if ipv == "ipv4":
            self._ip4tables.set_rule(rule)
        elif ipv == "ipv6":
            self._ip6tables.set_rule(rule)
        elif ipv == "eb":
            self._ebtables.set_rule(rule)
        else:
            raise FirewallError(INVALID_IPV)

    ### RESTART ###

    def reload(self):
        _panic = self._panic
        _icmp_block = self._icmp_block
        _trusted = self._trusted
        _forward = self._forward
        _services = self._services
        _ports = self._ports
        _masq = self._masquerade
        _custom = self._custom
        _virt_rules = self._virt_rules
        _virt_chains = self._virt_chains

        self.__init_vars()
        self.start()

        # start
        if _panic:
            self.enable_panic_mode()
        for icmp in _icmp_block:
            self.__icmp_block(True, icmp)
        for trusted in _trusted:
            self.__trusted(True, trusted)
        for args in _forward.keys():
            self.__forward_port(True, *args)
        for service in _services:
            self.__service(True, service)
        for args in _ports:
            self.__port(True, *args)
        for masq in _masq:
            self.__masquerade(True, masq)
        for args in _custom:
            self.__custom(True, *args)
        for args in _virt_chains:
            self.__virt_chain(True, *args)
        for args in _virt_rules:
            self.__virt_rule(True, *args)

    def restart(self):
        self._unload_firewall_modules()
        self.reload()

    ### STATUS ###

    def status(self):
#        mods = self.__get_firewall_modules()
#        print "\n".join(mods)
        return (self._initialized == True)

    ### PANIC MODE ###

    def enable_panic_mode(self):
        if self._panic:
            raise FirewallError(ALREADY_ENABLED)
        try:
            self._set_policy("DROP", "all")
        except Exception, msg:
            # TODO: log msg
            raise FirewallError(ENABLE_FAILED)
        self._panic = True

    def disable_panic_mode(self):
        if not self._panic:
            raise FirewallError(NOT_ENABLED)
        try:
            self._set_policy("ACCEPT", "all")
        except Exception, msg:
            # TODO: log msg
            raise FirewallError(DISABLE_FAILED)
        self._panic = False

    def query_panic_mode(self):
        return (self._panic == True)

    ### SERVICES ###

    def __service(self, enable, service):
        svc = fw_services.getByKey(service)
        if not svc:
            raise FirewallError(INVALID_SERVICE)

        service_id = service

        if enable:
            if service_id in self._services:
                raise FirewallError(ALREADY_ENABLED)
        else:
            if not service_id in self._services:
                raise FirewallError(NOT_ENABLED)

        rules = [ ]
        for ipv in [ "ipv4", "ipv6" ]:
            # handle rules
            for (port,proto) in svc.ports:
                rule = [ "INPUT_services", "-t", "filter" ]
                if proto in [ "tcp", "udp" ]:
                    rule += [ "-m", proto, "-p", proto ]
                else:
                    if ipv == "ipv4":
                         rule += [ "-p", proto ]
                    else:
                         rule += [ "-m", "ipv6header", "--header", proto ]
                if port:
                     rule += [ "--dport", "%s" % self.__portStr(port) ]
                if ipv in svc.destination:
                     rule += [ "-d",  svc.destination[ipv] ]
                rule += [ "-j", "ACCEPT" ]
                rules.append((ipv, rule))

        cleanup_rules = None
        cleanup_modules = None
        msg = None

        # handle rules
        ret = self.__handle_rules(rules, enable)
        if ret == None: # no error, handle modules
            mod_ret = self.__handle_modules(svc.modules, enable)
            if mod_ret != None: # error loading modules
                (cleanup_modules, msg) = mod_ret
                cleanup_rules = rules
        else: # ret != None
            (cleanup_rules, msg) = ret

        if cleanup_rules or cleanup_modules:
            if cleanup_rules:
                self.__handle_rules(cleanup_rules, not enable)
            if cleanup_modules:
                self.__handle_modules(cleanup_modules, not enable)
            # TODO: log msg
            if enable:
                raise FirewallError(ENABLE_FAILED)
            else:
                raise FirewallError(DISABLE_FAILED)

        if enable:
            self._services.append(service_id)
        else:
            self._services.remove(service_id)

    def enable_service(self, service):
        self.__service(True, service)

    def disable_service(self, service):
        self.__service(False, service)

    def query_service(self, service):
        return (service in self._services)

    def get_services(self):
        return self._services[:]

    ### PORTS ###

    def __portStr(self, port, delimiter=":"):
        range = functions.getPortRange(port)
        if len(range) == 1:
            return "%s" % range
        else:
            return "%s%s%s" % (range[0], delimiter, range[1])

    def __check_port(self, port):
        range = functions.getPortRange(port)

        if range == -2 or range == -1 or range == None or \
                (len(range) == 2 and range[0] >= range[1]):
#            if range == -2:
#                log("port > 65535")
#            elif len(range) == 2 and range[0] >= range[1]:
#                log("range start >= end")
            raise FirewallError(INVALID_PORT)

    def __check_protocol(self, protocol):
        if not protocol:
            raise FirewallError(MISSING_PROTOCOL)
        if not protocol in [ "tcp", "udp" ]:
            # TODO: log protocol
            raise FirewallError(INVALID_PROTOCOL)

    def __port(self, enable, port, protocol):
        self.__check_port(port)
        self.__check_protocol(protocol)

        port_id = (str(port), protocol)
        port_str = "port=%s:proto=%s" % (port, protocol)

        if enable:
            if port_id in self._ports:
                raise FirewallError(ALREADY_ENABLED)
        else:
            if not port_id in self._ports:
                raise FirewallError(NOT_ENABLED)

        rules = [ ]
        for ipv in [ "ipv4", "ipv6" ]:
            rules.append((ipv, [ "INPUT_ports", "-t", "filter",
                                 "-m", protocol, "-p", protocol,
                                 "--dport", self.__portStr(port),
                                 "-j", "ACCEPT" ]))

        # handle rules
        ret = self.__handle_rules(rules, enable)
        if ret:
            (cleanup_rules, msg) = ret
            self.__handle_rules(cleanup_rules, not enable)
            # TODO: log , port_str, str(msg))
            if enable:
                raise FirewallError(ENABLE_FAILED)
            else:
                raise FirewallError(DISABLE_FAILED)
        
        if enable:
            self._ports.append(port_id)
        else:
            self._ports.remove(port_id)

    def enable_port(self, port, protocol):
        self.__port(True, port, protocol)

    def disable_port(self, port, protocol):
        self.__port(False, port, protocol)

    def query_port(self, port, protocol):
        port_id = (str(port), protocol)
        return port_id in self._ports

    def get_ports(self):
        return self._ports[:]

    ### TRUSTED ###

    def __check_interface(self, interface):
        if not functions.checkInterface(interface):
            raise FirewallError(INVALID_INTERFACE)

    def __trusted(self, enable, trusted):
        self.__check_interface(trusted)

        trusted_id = trusted

        if enable:
            if trusted_id in self._trusted:
                raise FirewallError(ALREADY_ENABLED)
        else:
            if not trusted_id in self._trusted:
                raise FirewallError(NOT_ENABLED)

        rules = [ ]
        for ipv in [ "ipv4", "ipv6" ]:
            rules.append((ipv, [ "INPUT_trusted", "-t", "filter", "-i", trusted,
                                 "-j", "ACCEPT" ]))
            rules.append((ipv, [ "FORWARD_trusted", "-t", "filter",
                                 "-i", trusted, "-j", "ACCEPT" ]))

        # handle rules
        ret = self.__handle_rules(rules, enable)
        if ret:
            (cleanup_rules, msg) = ret
            self.__handle_rules(cleanup_rules, not enable)
            # TODO: log msg
            if enable:
                raise FirewallError(ENABLE_FAILED)
            else:
                raise FirewallError(DISABLE_FAILED)

        if enable:
            self._trusted.append(trusted_id)
        else:
            self._trusted.remove(trusted_id)

    def enable_trusted(self, trusted):
        self.__trusted(True, trusted)

    def disable_trusted(self, trusted):
        self.__trusted(False, trusted)

    def query_trusted(self, trusted):
        return trusted in self._trusted

    def get_trusted(self):
        return self._trusted[:]

    ### MASQUERADE ###

    def __masquerade(self, enable, masq):
        self.__check_interface(masq)

        masq_id = masq

        if enable:
            if masq_id in self._masquerade:
                raise FirewallError(ALREADY_ENABLED)
        else:
            if not masq_id in self._masquerade:
                raise FirewallError(NOT_ENABLED)

        rules = [ ]
        for ipv in [ "ipv4" ]: # IPv4 only!
            rules.append((ipv, [ "POSTROUTING_masq", "-t", "nat", "-o", masq,
                                 "-j", "MASQUERADE" ]))
            rules.append((ipv, [ "FORWARD_masq", "-t", "filter", "-o", masq,
                                 "-j", "ACCEPT" ]))

        # handle rules
        ret = self.__handle_rules(rules, enable)
        if ret:
            (cleanup_rules, msg) = ret
            self.__handle_rules(cleanup_rules, not enable)
            # TODO: log msg
            if enable:
                raise FirewallError(ENABLE_FAILED)
            else:
                raise FirewallError(DISABLE_FAILED)

        if enable:
            self._masquerade.append(masq_id)
        else:
            self._masquerade.remove(masq_id)

    def enable_masquerade(self, masq):
        self.__masquerade(True, masq)

    def disable_masquerade(self, masq):
        self.__masquerade(False, masq)

    def query_masquerade(self, masq):
        return masq in self._masquerade

    def get_masquerades(self):
        return self._masquerade[:]

    ### PORT FORWARDING ###

    def __check_ip(self, ip):
        if not functions.checkIP(ip):
            raise FirewallError(INVALID_ADDR)

    def __forward_port(self, enable, interface, port, protocol, toport=None,
                       toaddr=None):
        self.__check_interface(interface)
        self.__check_port(port)
        self.__check_protocol(protocol)
        if toport:
            self.__check_port(toport)
        if toaddr:
            self.__check_ip(toaddr)

        forward_id = (interface, str(port), protocol, str(toport), str(toaddr))
        forward_str = "if=%s:port=%s:proto=%s:toport=%s:toaddr=%s" % \
            (interface, port, protocol, toport, toaddr)

        if not toport and not toaddr:
            # TODO: log forward_str
            raise FirewallError(INVALID_FORWARD)

        if enable:
            if forward_id in self._forward:
                raise FirewallError(ALREADY_ENABLED)
            mark_id = self.__new_mark()
        else:
            if not forward_id in self._forward:
                raise FirewallError(NOT_ENABLED)
            mark_id = self._forward[forward_id]

        mark_str = "0x%x" % mark_id

        port_str = self.__portStr(port)
        if toport:
            toport_str = self.__portStr(toport)
        dest = [ ]
        if toport:
            dest = [ "--dport", toport_str ]
#        mark = [ ]
#        if not toaddr:
#            mark = [ "-m", "mark", "--mark", mark_str ]
        mark = [ "-m", "mark", "--mark", mark_str ]
        to = ""
        if toaddr:
            to += toaddr
        if toport:
            to += ":%s" % self.__portStr(toport, "-")

        rules = [ ]
        for ipv in [ "ipv4" ]: # IPv4 only!
            rules.append((ipv, [ "PREROUTING_forward", "-t", "mangle",
                                 "-i", interface,
                                 "-p", protocol, "--dport", port_str,
                                 "-j", "MARK", "--set-mark", mark_str ]))
            if not toaddr:
                # local only
#                rules.append((ipv, [ "PREROUTING_forward", "-t", "mangle",
#                                     "-i", interface,
#                                     "-p", protocol, "--dport", port_str,
#                                     "-j", "MARK", "--set-mark", mark_str ]))

                rules.append((ipv, [ "INPUT_forward", "-t", "filter",
                                     "-i", interface,
                                     "-m", protocol, "-p", protocol ] + \
                                  dest + mark + [ "-j", "ACCEPT" ]))
            else:
                # remote only
                if toport:
                    toport2_str = toport_str
                else:
                    toport2_str = port_str

                rules.append((ipv, [ "FORWARD_forward", "-t", "filter",
                                     "-i", interface,
                                     "-m", protocol, "-p", protocol,
                                     "--destination", toaddr,
                                     "--dport", toport2_str] + mark + \
                                  [ "-j", "ACCEPT" ]))

            # local and remote
            rules.append((ipv, [ "PREROUTING_forward", "-t", "nat",
                                 "-i", interface,
                                 "-p", protocol, "--dport", port_str ] + \
                              mark + [ "-j", "DNAT", "--to-destination", to ]))

        # handle rules
        ret = self.__handle_rules(rules, enable)
        if ret:
            (cleanup_rules, msg) = ret
            self.__handle_rules(cleanup_rules, not enable)
            # TODO: log msg
            if enable:
                raise FirewallError(ENABLE_FAILED)
            else:
                raise FirewallError(DISABLE_FAILED)

        if enable:
            self._forward[forward_id] = mark_id
        else:
            del self._forward[forward_id]
            if not toaddr:
                self.__del_mark(mark_id)

    def enable_forward_port(self, interface, port, protocol, toport=None,
                            toaddr=None):
        self.__forward_port(True, interface, port, protocol, toport, toaddr)

    def disable_forward_port(self, interface, port, protocol, toport=None,
                             toaddr=None):
        self.__forward_port(False, interface, port, protocol, toport, toaddr)

    def query_forward_port(self,interface, port, protocol, toport=None,
                           toaddr=None):
        forward_id = (interface, str(port), protocol, str(toport), str(toaddr))
        return forward_id in self._forward

    def get_forward_ports(self):
        ret = [ ]
        for key in self._forward:
            ret.append(key[:])
        return ret

    ### ICMP ###

    def __icmp_block(self, enable, icmp):
        ic = fw_icmp.getByKey(icmp)
        if not ic:
            raise FirewallError(INVALID_ICMP_TYPE)

        icmp_id = icmp

        if enable:
            if icmp_id in self._icmp_block:
                raise FirewallError(ALREADY_ENABLED)
        else:
            if not icmp_id in self._icmp_block:
                raise FirewallError(NOT_ENABLED)

        rules = [ ]
        for ipv in [ "ipv4", "ipv6" ]:
            if ic.type and ipv not in ic.type:
                continue

            if ipv == "ipv4":
                proto = [ "-p", "icmp" ]
                match = [ "-m", "icmp", "--icmp-type", icmp ]
            else:
                proto = [ "-p", "ipv6-icmp" ]
                match = [ "-m", "icmp6", "--icmpv6-type", icmp ]

            rules.append((ipv, [ "INPUT_icmp", "-t", "filter", ] + proto + \
                              match + [ "-j", "REJECT",
                                        "--reject-with", REJECT_TYPE[ipv] ]))
            rules.append((ipv, [ "FORWARD_icmp", "-t", "filter", ] + proto + \
                              match + [ "-j", "REJECT",
                                        "--reject-with", REJECT_TYPE[ipv] ]))

        # handle rules
        ret = self.__handle_rules(rules, enable)
        if ret:
            (cleanup_rules, msg) = ret
            self.__handle_rules(cleanup_rules, not enable)
            # TODO: log msg
            if enable:
                raise FirewallError(ENABLE_FAILED)
            else:
                raise FirewallError(DISABLE_FAILED)

        if enable:
            self._icmp_block.append(icmp_id)
        else:
            self._icmp_block.remove(icmp_id)

    def enable_icmp_block(self, icmp):
        self.__icmp_block(True, icmp)

    def disable_icmp_block(self, icmp):
        self.__icmp_block(False, icmp)

    def query_icmp_block(self, icmp):
        return icmp in self._icmp_block

    def get_icmp_blocks(self):
        return self._icmp_block[:]

    ### CUSTOM ###

    def __custom(self, enable, table="filter", chain="INPUT",
                 src=None, src_port=None, dst=None, dst_port=None,
                 protocol=None, iface_in=None, iface_out=None,
                 physdev_in=None, physdev_out=None, target="ACCEPT"):
        if src:
            self.__check_ip(src)
        if src_port:
            self.__check_port(src_port)
        if dst:
            self.__check_ip(dst)
        if dst_port:
            self.__check_port(dst_port)
        self.__check_protocol(protocol)
        if iface_in:
            self.__check_interface(iface_in)
        if iface_out:
            self.__check_interface(iface_out)
        if physdev_in:
            self.__check_interface(physdev_in)
        if physdev_out:
            self.__check_interface(physdev_out)

        if not table:
            raise FirewallError(MISSING_TABLE)
        elif table not in CHAINS:
            raise FirewallError(INVALID_TABLE)

        if not chain:
            raise FirewallError(MISSING_CHAIN)

        if not src_port and not dst_port:
            raise FirewallError(MISSING_PORT)

        if not target in [ "ACCEPT", "DROP", "REJECT" ]:
            raise FirewallError(INVALID_TARGET)

        custom_id = (table, chain, src, src_port, dst, dst_port, protocol,
                     iface_in, iface_out, physdev_in, physdev_out, target)
        custom_str = "table=%s:chain=%s:src=%s:src_port=%s:dst=%s:dst_port=%s:proto=%s:iface_in=%s:iface_out=%s:physdev_in=%s:physdev_out=%s:target=%s" % \
            (table, chain, src, src_port, dst, dst_port, protocol, iface_in,
             iface_out, physdev_in, physdev_out, target)

        if enable:
            if custom_id in self._custom:
                raise FirewallError(ALREADY_ENABLED)
            opt = "-A"
        else:
            if not custom_id in self._custom:
                raise FirewallError(NOT_ENABLED)
            opt = "-D"

        _chain = None
        if table != "raw" and table in CHAINS and chain in CHAINS[table]:
            _chain = "%s_custom" % (chain)
        if not _chain:
            # TODO: log table and chain
            raise FirewallError(INVALID_CHAIN)

        rules = [ ]
        for ipv in [ "ipv4", "ipv6" ]:
            if table == "nat" and ipv == "ipv6":
                raise FirewallError(NO_IPV6_NAT)

            rule = [ _chain, "-t", table, "-m", protocol, "-p", protocol ]
            if src:
                rule += [ "-s", src ]
            if src_port:
                rule += [ "--sport", self.__portStr(src_port) ]
            if dst:
                rule += [ "-d", dst ]
            if dst_port:
                rule += [ "--dport", self.__portStr(dst_port) ]
            if iface_in:
                rule += [ "-i", iface_in ]
            if iface_out:
                rule += [ "-o", iface_out ]
            if physdev_in or physdev_out:
                rule += [ "-m", "physdev" ]
                if physdev_in:
                    rule += [ "--physdev-in", physdev_in ]
                else:
                    rule += [ "--physdev-out", physdev_out ]
            rule += [ "-j", target ]
            if target == "REJECT":
                rule += [ "--reject-with", REJECT_TYPE[ipv] ]
            rules.append((ipv, rule))

        # handle rules
        ret = self.__handle_rules(rules, enable)
        if ret:
            (cleanup_rules, msg) = ret
            self.__handle_rules(cleanup_rules, not enable)
            # TODO: log msg
            if enable:
                raise FirewallError(ENABLE_FAILED)
            else:
                raise FirewallError(DISABLE_FAILED)

        if enable:
            self._custom.append(custom_id)
        else:
            self._custom.remove(custom_id)

    def enable_custom(self, table="filter", chain="INPUT",
                      src=None, src_port=None, dst=None, dst_port=None,
                      protocol=None, iface_in=None, iface_out=None,
                      physdev_in=None, physdev_out=None, target="ACCEPT"):
        self.__custom(True, table, chain, src, src_port, dst, dst_port,
                      protocol, iface_in, iface_out, physdev_in, physdev_out,
                      target)

    def disable_custom(self, table="filter", chain="INPUT",
                       src=None, src_port=None, dst=None, dst_port=None,
                       protocol=None, iface_in=None, iface_out=None,
                       physdev_in=None, physdev_out=None, target="ACCEPT"):
        self.__custom(False, table, chain, src, src_port, dst, dst_port,
                      protocol, iface_in, iface_out, physdev_in, physdev_out,
                      target)

    def query_custom(self,table="filter", chain="INPUT",
                     src=None, src_port=None, dst=None, dst_port=None,
                     protocol=None, iface_in=None, iface_out=None,
                     physdev_in=None, physdev_out=None, target="ACCEPT"):
        custom_id = (table, chain, src, src_port, dst, dst_port, protocol,
                     iface_in, iface_out, physdev_in, physdev_out, target)
        return custom_id in self._custom

    def get_customs(self):
        return self._custom[:]

    ### VIRT RULES ###

    def __virt_rule(self, insert, ipv, table, chain, args):
        _chain = "%s_virt" % (chain)
        rule_id = (ipv, table, _chain) + args

        if insert:
            if rule_id in self._virt_rules:
                raise FirewallError(AREADY_ENABLED)
        else:
            if not rule_id in self._virt_rules:
                raise FirewallError(NOT_ENABLED)

        rule = [ "-t", table ]
        if insert:
            rule.append("-I")
        else:
            rule.append("-D")
        rule.append(_chain)
        rule += args

        try:
            self.__rule(ipv, rule)
        except Exception, msg:
            log(msg)
            if insert:
                FirewallError(ENABLE_FAILED)
            else:
                FirewallError(DISABLE_FAILED)

        if insert:
            self._virt_rules.append(rule_id)
        else:
            self._virt_rules.remove(rule_id)

    def __virt_chain(self, add, ipv, table, chain):
        _chain = "%s_virt" % (chain)
        chain_id = (ipv, table, _chain)

        if add:
            if chain_id in self._virt_chains:
                raise FirewallError(ALREADY_ENABLED)
        else:
            if not chain_id in self._virt_chains:
                raise FirewallError(NOT_ENABLED)

        rule = [ "-t", table ]
        if add:
            rule.append("-N")
        else:
            rule.append("-X")
        rule.append(_chain)

        try:
            self.__rule(ipv, rule)
        except Exception, msg:
            log(msg)
            if add:
                FirewallError(ENABLE_FAILED)
            else:
                FirewallError(DISABLE_FAILED)

        if add:
            self._virt_chains.append(chain_id)
        else:
            self._virt_chains.remove(chain_id)

    def virt_insert_rule(self, ipv, table, chain, args):
        self.__virt_rule(True, ipv, table, chain, args)

    def virt_delete_rule(self, ipv, table, chain, args):
        self.__virt_rule(False, ipv, table, chain, args)

    def virt_query_rule(self, ipv, table, chain, args):
        rule_id = (ipv, table, "%s_virt" % (chain)) + args
        return (rule_id in self._virt_rules)

    def virt_new_chain(self, ipv, table, chain, policy="ACCEPT"):
        self.__virt_chain(True, ipv, table, chain)

    def virt_remove_chain(self, ipv, table, chain):
        self.__virt_chain(False, ipv, table, chain)

    def virt_query_chain(self, ipv, table, chain):
         chain_id = (ipv, table, "%s_virt" % (chain))
         return (chain_id in self._virt_chains)

    ### STOP ###

    def stop(self):
#        print "modules:", self.__get_firewall_modules()
        self.__init_vars()
        self._flush()
        self._unload_firewall_modules()
#        print "modules:", self.__get_firewall_modules()
