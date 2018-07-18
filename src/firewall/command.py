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

"""FirewallCommand class for command line client simplification"""

__all__ = [ "FirewallCommand" ]

import sys

from firewall import errors
from firewall.errors import FirewallError
from dbus.exceptions import DBusException
from firewall.functions import checkIPnMask, checkIP6nMask, check_mac, \
    check_port, check_single_address

class FirewallCommand(object):
    def __init__(self, quiet=False, verbose=False):
        self.quiet = quiet
        self.verbose = verbose
        self.__use_exception_handler = True
        self.fw = None

    def set_fw(self, fw):
        self.fw = fw

    def set_quiet(self, flag):
        self.quiet = flag

    def get_quiet(self):
        return self.quiet

    def set_verbose(self, flag):
        self.verbose = flag

    def get_verbose(self):
        return self.verbose

    def print_msg(self, msg=None):
        if msg is not None and not self.quiet:
            sys.stdout.write(msg + "\n")

    def print_error_msg(self, msg=None):
        if msg is not None and not self.quiet:
            sys.stderr.write(msg + "\n")

    def print_warning(self, msg=None):
        FAIL = '\033[91m'
        END = '\033[00m'
        if sys.stderr.isatty():
            msg = FAIL + msg + END
        self.print_error_msg(msg)

    def print_and_exit(self, msg=None, exit_code=0):
        #OK = '\033[92m'
        #END = '\033[00m'
        if exit_code > 1:
            self.print_warning(msg)
        else:
            #if sys.stdout.isatty():
            #   msg = OK + msg + END
            self.print_msg(msg)
        sys.exit(exit_code)

    def fail(self, msg=None):
        self.print_and_exit(msg, 2)

    def print_if_verbose(self, msg=None):
        if msg is not None and self.verbose:
            sys.stdout.write(msg + "\n")

    def __cmd_sequence(self, cmd_type, option, action_method, query_method, # pylint: disable=W0613, R0913, R0914
                       parse_method, message, start_args=None, end_args=None, # pylint: disable=W0613
                       no_exit=False):
        if self.fw is not None:
            self.fw.authorizeAll()
        items = [ ]
        _errors = 0
        _error_codes = [ ]
        for item in option:
            if parse_method is not None:
                try:
                    item = parse_method(item)
                except Exception as msg:
                    code = FirewallError.get_code(str(msg))
                    if len(option) > 1:
                        self.print_warning("Warning: %s" % msg)
                    else:
                        self.print_and_exit("Error: %s" % msg, code)
                    if code not in _error_codes:
                        _error_codes.append(code)
                    _errors += 1
                    continue

            items.append(item)

        for item in items:
            call_item = [ ]
            if start_args is not None:
                call_item += start_args
            if not isinstance(item, list) and not isinstance(item, tuple):
                call_item.append(item)
            else:
                call_item += item
            if end_args is not None:
                call_item += end_args
            self.deactivate_exception_handler()
            try:
                action_method(*call_item)
            except (DBusException, Exception) as msg:
                if isinstance(msg, DBusException):
                    self.fail_if_not_authorized(msg.get_dbus_name())
                    msg = msg.get_dbus_message()
                else:
                    msg = str(msg)
                code = FirewallError.get_code(msg)
                if code in [ errors.ALREADY_ENABLED, errors.NOT_ENABLED,
                             errors.ZONE_ALREADY_SET, errors.ALREADY_SET ]:
                    code = 0
                if len(option) > 1:
                    self.print_warning("Warning: %s" % msg)
                elif code == 0:
                    self.print_warning("Warning: %s" % msg)
                    return
                else:
                    self.print_and_exit("Error: %s" % msg, code)
                if code not in _error_codes:
                    _error_codes.append(code)
                _errors += 1
            self.activate_exception_handler()

        if not no_exit:
            if len(option) > _errors or 0 in _error_codes:
                # There have been more options than errors or there
                # was at least one error code 0, return.
                return
            elif len(_error_codes) == 1:
                # Exactly one error code, use it.
                sys.exit(_error_codes[0])
            elif len(_error_codes) > 1:
                # There is more than error, exit using
                # UNKNOWN_ERROR. This could happen within sequences
                # where parsing failed with different errors like
                # INVALID_PORT and INVALID_PROTOCOL.
                sys.exit(errors.UNKNOWN_ERROR)

    def add_sequence(self, option, action_method, query_method, parse_method, # pylint: disable=R0913
                     message, no_exit=False):
        self.__cmd_sequence("add", option, action_method, query_method,
                            parse_method, message, no_exit=no_exit)

    def x_add_sequence(self, x, option, action_method, query_method, # pylint: disable=R0913
                       parse_method, message, no_exit=False):
        self.__cmd_sequence("add", option, action_method, query_method,
                            parse_method, message, start_args=[x],
                            no_exit=no_exit)

    def zone_add_timeout_sequence(self, zone, option, action_method, # pylint: disable=R0913
                                  query_method, parse_method, message,
                                  timeout, no_exit=False):
        self.__cmd_sequence("add", option, action_method, query_method,
                            parse_method, message, start_args=[zone],
                            end_args=[timeout], no_exit=no_exit)

    def remove_sequence(self, option, action_method, query_method, # pylint: disable=R0913
                        parse_method, message, no_exit=False):
        self.__cmd_sequence("remove", option, action_method, query_method,
                            parse_method, message, no_exit=no_exit)

    def x_remove_sequence(self, x, option, action_method, query_method, # pylint: disable=R0913
                          parse_method, message, no_exit=False):
        self.__cmd_sequence("remove", option, action_method, query_method,
                            parse_method, message, start_args=[x],
                            no_exit=no_exit)


    def __query_sequence(self, option, query_method, parse_method, message, # pylint: disable=R0913
                         start_args=None, no_exit=False):
        items = [ ]
        for item in option:
            if parse_method is not None:
                try:
                    item = parse_method(item)
                except Exception as msg:
                    if len(option) > 1:
                        self.print_warning("Warning: %s" % msg)
                        continue
                    else:
                        code = FirewallError.get_code(str(msg))
                        self.print_and_exit("Error: %s" % msg, code)
            items.append(item)

        for item in items:
            call_item = [ ]
            if start_args is not None:
                call_item += start_args
            if not isinstance(item, list) and not isinstance(item, tuple):
                call_item.append(item)
            else:
                call_item += item
            self.deactivate_exception_handler()
            try:
                res = query_method(*call_item)
            except DBusException as msg:
                self.fail_if_not_authorized(msg.get_dbus_name())
                code = FirewallError.get_code(msg.get_dbus_message())
                if len(option) > 1:
                    self.print_warning("Warning: %s" % msg.get_dbus_message())
                    continue
                else:
                    self.print_and_exit("Error: %s" % msg.get_dbus_message(),
                                        code)
            except Exception as msg:
                code = FirewallError.get_code(str(msg))
                if len(option) > 1:
                    self.print_warning("Warning: %s" % msg)
                else:
                    self.print_and_exit("Error: %s" % msg, code)
            self.activate_exception_handler()
            if len(option) > 1:
                self.print_msg("%s: %s" % (message % item, ("no", "yes")[res]))
            else:
                self.print_query_result(res)
        if not no_exit:
            sys.exit(0)

    def query_sequence(self, option, query_method, parse_method, message, # pylint: disable=R0913
                       no_exit=False):
        self.__query_sequence(option, query_method, parse_method,
                              message, no_exit=no_exit)

    def x_query_sequence(self, x, option, query_method, parse_method, # pylint: disable=R0913
                         message, no_exit=False):
        self.__query_sequence(option, query_method, parse_method,
                              message, start_args=[x], no_exit=no_exit)


    def parse_source(self, value):
        if not checkIPnMask(value) and not checkIP6nMask(value) \
           and not check_mac(value) and not \
           (value.startswith("ipset:") and len(value) > 6):
            raise FirewallError(errors.INVALID_ADDR,
                                "'%s' is no valid IPv4, IPv6 or MAC address, nor an ipset" % value)
        return value

    def parse_port(self, value, separator="/"):
        try:
            (port, proto) = value.split(separator)
        except ValueError:
            raise FirewallError(errors.INVALID_PORT, "bad port (most likely "
                                "missing protocol), correct syntax is "
                                "portid[-portid]%sprotocol" % separator)
        if not check_port(port):
            raise FirewallError(errors.INVALID_PORT, port)
        if proto not in [ "tcp", "udp", "sctp", "dccp" ]:
            raise FirewallError(errors.INVALID_PROTOCOL,
                                "'%s' not in {'tcp'|'udp'|'sctp'|'dccp'}" % \
                                proto)
        return (port, proto)

    def parse_forward_port(self, value, compat=False):
        port = None
        protocol = None
        toport = None
        toaddr = None
        i = 0
        while ("=" in value[i:]):
            opt = value[i:].split("=", 1)[0]
            i += len(opt) + 1
            if "=" in value[i:]:
                val = value[i:].split(":", 1)[0]
            else:
                val = value[i:]
            i += len(val) + 1

            if opt == "port":
                port = val
            elif opt == "proto":
                protocol = val
            elif opt == "toport":
                toport = val
            elif opt == "toaddr":
                toaddr = val
            elif opt == "if" and compat:
                # ignore if option in compat mode
                pass
            else:
                raise FirewallError(errors.INVALID_FORWARD,
                                    "invalid forward port arg '%s'" % (opt))
        if not port:
            raise FirewallError(errors.INVALID_FORWARD, "missing port")
        if not protocol:
            raise FirewallError(errors.INVALID_FORWARD, "missing protocol")
        if not (toport or toaddr):
            raise FirewallError(errors.INVALID_FORWARD, "missing destination")

        if not check_port(port):
            raise FirewallError(errors.INVALID_PORT, port)
        if protocol not in [ "tcp", "udp", "sctp", "dccp" ]:
            raise FirewallError(errors.INVALID_PROTOCOL,
                                "'%s' not in {'tcp'|'udp'|'sctp'|'dccp'}" % \
                                protocol)
        if toport and not check_port(toport):
            raise FirewallError(errors.INVALID_PORT, toport)
        if toaddr and not check_single_address("ipv4", toaddr):
            if compat or not check_single_address("ipv6", toaddr):
                raise FirewallError(errors.INVALID_ADDR, toaddr)

        return (port, protocol, toport, toaddr)

    def parse_ipset_option(self, value):
        args = value.split("=")
        if len(args) == 1:
            return (args[0], "")
        elif len(args) == 2:
            return args
        else:
            raise FirewallError(errors.INVALID_OPTION,
                                "invalid ipset option '%s'" % (value))

    def check_destination_ipv(self, value):
        ipvs = [ "ipv4", "ipv6", ]
        if value not in ipvs:
            raise FirewallError(errors.INVALID_IPV,
                                "invalid argument: %s (choose from '%s')" % \
                                (value, "', '".join(ipvs)))
        return value

    def parse_service_destination(self, value):
        try:
            (ipv, destination) = value.split(":", 1)
        except ValueError:
            raise FirewallError(errors.INVALID_DESTINATION,
                                "destination syntax is ipv:address[/mask]")
        return (self.check_destination_ipv(ipv), destination)

    def check_ipv(self, value):
        ipvs = [ "ipv4", "ipv6", "eb" ]
        if value not in ipvs:
            raise FirewallError(errors.INVALID_IPV,
                                "invalid argument: %s (choose from '%s')" % \
                                (value, "', '".join(ipvs)))
        return value

    def check_helper_family(self, value):
        ipvs = [ "", "ipv4", "ipv6" ]
        if value not in ipvs:
            raise FirewallError(errors.INVALID_IPV,
                                "invalid argument: %s (choose from '%s')" % \
                                (value, "', '".join(ipvs)))
        return value

    def check_module(self, value):
        if not value.startswith("nf_conntrack_"):
            raise FirewallError(
                errors.INVALID_MODULE,
                "'%s' does not start with 'nf_conntrack_'" % value)
        if len(value.replace("nf_conntrack_", "")) < 1:
            raise FirewallError(errors.INVALID_MODULE,
                                "Module name '%s' too short" % value)
        return value

    def print_zone_info(self, zone, settings, default_zone=None, extra_interfaces=[]): # pylint: disable=R0914
        target = settings.getTarget()
        icmp_block_inversion = settings.getIcmpBlockInversion()
        interfaces = sorted(set(settings.getInterfaces() + extra_interfaces))
        sources = settings.getSources()
        services = settings.getServices()
        ports = settings.getPorts()
        protocols = settings.getProtocols()
        masquerade = settings.getMasquerade()
        forward_ports = settings.getForwardPorts()
        source_ports = settings.getSourcePorts()
        icmp_blocks = settings.getIcmpBlocks()
        rules = settings.getRichRules()
        description = settings.getDescription()
        short_description = settings.getShort()

        attributes = []
        if default_zone is not None:
            if zone == default_zone:
                attributes.append("default")
        if interfaces or sources:
            attributes.append("active")
        if attributes:
            zone = zone + " (%s)" % ", ".join(attributes)
        self.print_msg(zone)
        if self.verbose:
            self.print_msg("  summary: " + short_description)
            self.print_msg("  description: " + description)
        self.print_msg("  target: " + target)
        self.print_msg("  icmp-block-inversion: %s" % \
                       ("yes" if icmp_block_inversion else "no"))
        self.print_msg("  interfaces: " + " ".join(interfaces))
        self.print_msg("  sources: " + " ".join(sources))
        self.print_msg("  services: " + " ".join(services))
        self.print_msg("  ports: " + " ".join(["%s/%s" % (port[0], port[1])
                                               for port in ports]))
        self.print_msg("  protocols: " + " ".join(protocols))
        self.print_msg("  masquerade: %s" % ("yes" if masquerade else "no"))
        self.print_msg("  forward-ports: " +
                       "\n\t".join(["port=%s:proto=%s:toport=%s:toaddr=%s" % \
                                    (port, proto, toport, toaddr)
                                    for (port, proto, toport, toaddr) in \
                                    forward_ports]))
        self.print_msg("  source-ports: " +
                       " ".join(["%s/%s" % (port[0], port[1])
                                 for port in source_ports]))
        self.print_msg("  icmp-blocks: " + " ".join(icmp_blocks))
        self.print_msg("  rich rules: \n\t" + "\n\t".join(rules))

    def print_service_info(self, service, settings):
        ports = settings.getPorts()
        protocols = settings.getProtocols()
        source_ports = settings.getSourcePorts()
        modules = settings.getModules()
        description = settings.getDescription()
        destinations = settings.getDestinations()
        short_description = settings.getShort()
        self.print_msg(service)
        if self.verbose:
            self.print_msg("  summary: " + short_description)
            self.print_msg("  description: " + description)
        self.print_msg("  ports: " + " ".join(["%s/%s" % (port[0], port[1])
                                               for port in ports]))
        self.print_msg("  protocols: " + " ".join(protocols))
        self.print_msg("  source-ports: " +
                       " ".join(["%s/%s" % (port[0], port[1])
                                 for port in source_ports]))
        self.print_msg("  modules: " + " ".join(modules))
        self.print_msg("  destination: " +
                       " ".join(["%s:%s" % (k, v)
                                 for k, v in destinations.items()]))

    def print_icmptype_info(self, icmptype, settings):
        destinations = settings.getDestinations()
        description = settings.getDescription()
        short_description = settings.getShort()
        if len(destinations) == 0:
            destinations = [ "ipv4", "ipv6" ]
        self.print_msg(icmptype)
        if self.verbose:
            self.print_msg("  summary: " + short_description)
            self.print_msg("  description: " + description)
        self.print_msg("  destination: " + " ".join(destinations))

    def print_ipset_info(self, ipset, settings):
        ipset_type = settings.getType()
        options = settings.getOptions()
        entries = settings.getEntries()
        description = settings.getDescription()
        short_description = settings.getShort()
        self.print_msg(ipset)
        if self.verbose:
            self.print_msg("  summary: " + short_description)
            self.print_msg("  description: " + description)
        self.print_msg("  type: " + ipset_type)
        self.print_msg("  options: " + " ".join(["%s=%s" % (k, v) if v else k
                                                 for k, v in options.items()]))
        self.print_msg("  entries: " + " ".join(entries))

    def print_helper_info(self, helper, settings):
        ports = settings.getPorts()
        module = settings.getModule()
        family = settings.getFamily()
        description = settings.getDescription()
        short_description = settings.getShort()
        self.print_msg(helper)
        if self.verbose:
            self.print_msg("  summary: " + short_description)
            self.print_msg("  description: " + description)
        self.print_msg("  family: " + family)
        self.print_msg("  module: " + module)
        self.print_msg("  ports: " + " ".join(["%s/%s" % (port[0], port[1])
                                               for port in ports]))

    def print_query_result(self, value):
        if value:
            self.print_and_exit("yes")
        else:
            self.print_and_exit("no", 1)

    def exception_handler(self, exception_message):
        if not self.__use_exception_handler:
            raise
        self.fail_if_not_authorized(exception_message)
        code = FirewallError.get_code(str(exception_message))
        if code in [ errors.ALREADY_ENABLED, errors.NOT_ENABLED,
                     errors.ZONE_ALREADY_SET, errors.ALREADY_SET ]:
            self.print_warning("Warning: %s" % exception_message)
        else:
            self.print_and_exit("Error: %s" % exception_message, code)

    def fail_if_not_authorized(self, exception_message):
        if "NotAuthorizedException" in exception_message:
            msg = """Authorization failed.
    Make sure polkit agent is running or run the application as superuser."""
            self.print_and_exit(msg, errors.NOT_AUTHORIZED)

    def deactivate_exception_handler(self):
        self.__use_exception_handler = False

    def activate_exception_handler(self):
        self.__use_exception_handler = True

    def get_ipset_entries_from_file(self, filename):
        entries = [ ]
        entries_set = set()
        f = open(filename)
        for line in f:
            if not line:
                break
            line = line.strip()
            if len(line) < 1 or line[0] in ['#', ';']:
                continue
            if line not in entries_set:
                entries.append(line)
                entries_set.add(line)
        f.close()
        return entries
