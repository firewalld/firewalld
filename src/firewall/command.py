# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2011-2016 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>

"""FirewallCommand class for command line client simplification"""

import sys
import dbus

import firewall.config
from firewall import errors
from firewall.errors import FirewallError
from dbus.exceptions import DBusException
from firewall.functions import (
    checkIPnMask,
    checkIP6nMask,
    check_mac,
    check_port,
    check_single_address,
)


class FirewallCommand:
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

    def exit(self, exit_code=0):
        sys.exit(exit_code)

    def get_file(self, *, is_err=False, file=None):
        if file is None:
            return sys.stderr if is_err else sys.stdout
        return file

    def isatty(self, *, is_err=False, file=None):
        return self.get_file(is_err=is_err, file=file).isatty()

    def print(
        self,
        msg,
        *,
        file=None,
        is_err=False,
        force=False,
        only_with_verbose=False,
        not_with_quiet=True,
        eol="\n",
        exit_code=None,
    ):
        if msg is not None:
            if not force:
                if not_with_quiet and self.quiet:
                    msg = None
                elif only_with_verbose and not self.verbose:
                    msg = None

            if msg is not None:
                msg = str(msg)

                if eol is not None and eol != "":
                    msg = msg + eol

                file = self.get_file(is_err=is_err, file=file)
                file.write(msg)

        if exit_code is not None:
            self.exit(exit_code)

    def print_msg(self, msg=None, *, force=False, file=None, exit_code=None):
        self.print(
            msg=msg,
            file=file,
            is_err=False,
            force=force,
            only_with_verbose=False,
            not_with_quiet=True,
            exit_code=exit_code,
        )

    def print_error_msg(self, msg=None, *, force=False, file=None, exit_code=None):
        self.print(
            msg=msg,
            file=file,
            is_err=True,
            force=force,
            only_with_verbose=False,
            not_with_quiet=True,
            exit_code=exit_code,
        )

    def print_warning(self, msg=None, *, exit_code=None):
        file = sys.stderr
        if msg is not None:
            if self.isatty(file=file):
                FAIL = "\033[91m"
                END = "\033[00m"
                msg = FAIL + str(msg) + END
        self.print_error_msg(msg, file=file, exit_code=exit_code)

    def print_and_exit(self, msg=None, exit_code=0):
        if exit_code is not None and exit_code > 1:
            self.print_warning(msg, exit_code=exit_code)
        else:
            self.print_msg(msg, exit_code=exit_code)

    def fail(self, msg=None):
        self.print_and_exit(msg, 2)

    def print_if_verbose(self, msg=None):
        self.print(
            msg=msg,
            is_err=False,
            only_with_verbose=True,
            not_with_quiet=True,
        )

    def __cmd_sequence(
        self,
        cmd_type,
        option,
        action_method,
        query_method,  # pylint: disable=W0613, R0913, R0914
        parse_method,
        message,
        start_args=None,
        end_args=None,  # pylint: disable=W0613
        no_exit=False,
    ):
        if self.fw is not None:
            self.fw.authorizeAll()
        items = []
        _errors = 0
        _error_codes = []
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
            call_item = []
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
                if code in [
                    errors.ALREADY_ENABLED,
                    errors.NOT_ENABLED,
                    errors.ZONE_ALREADY_SET,
                    errors.ALREADY_SET,
                ]:
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
                self.exit(_error_codes[0])
            elif len(_error_codes) > 1:
                # There is more than error, exit using
                # UNKNOWN_ERROR. This could happen within sequences
                # where parsing failed with different errors like
                # INVALID_PORT and INVALID_PROTOCOL.
                self.exit(errors.UNKNOWN_ERROR)

    def add_sequence(
        self,
        option,
        action_method,
        query_method,
        parse_method,  # pylint: disable=R0913
        message,
        no_exit=False,
    ):
        self.__cmd_sequence(
            "add",
            option,
            action_method,
            query_method,
            parse_method,
            message,
            no_exit=no_exit,
        )

    def x_add_sequence(
        self,
        x,
        option,
        action_method,
        query_method,  # pylint: disable=R0913
        parse_method,
        message,
        no_exit=False,
    ):
        self.__cmd_sequence(
            "add",
            option,
            action_method,
            query_method,
            parse_method,
            message,
            start_args=[x],
            no_exit=no_exit,
        )

    def zone_add_timeout_sequence(
        self,
        zone,
        option,
        action_method,  # pylint: disable=R0913
        query_method,
        parse_method,
        message,
        timeout,
        no_exit=False,
    ):
        self.__cmd_sequence(
            "add",
            option,
            action_method,
            query_method,
            parse_method,
            message,
            start_args=[zone],
            end_args=[timeout],
            no_exit=no_exit,
        )

    def remove_sequence(
        self,
        option,
        action_method,
        query_method,  # pylint: disable=R0913
        parse_method,
        message,
        no_exit=False,
    ):
        self.__cmd_sequence(
            "remove",
            option,
            action_method,
            query_method,
            parse_method,
            message,
            no_exit=no_exit,
        )

    def x_remove_sequence(
        self,
        x,
        option,
        action_method,
        query_method,  # pylint: disable=R0913
        parse_method,
        message,
        no_exit=False,
    ):
        self.__cmd_sequence(
            "remove",
            option,
            action_method,
            query_method,
            parse_method,
            message,
            start_args=[x],
            no_exit=no_exit,
        )

    def __query_sequence(
        self,
        option,
        query_method,
        parse_method,
        message,  # pylint: disable=R0913
        start_args=None,
        no_exit=False,
    ):
        items = []
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
            call_item = []
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
                    self.print_and_exit("Error: %s" % msg.get_dbus_message(), code)
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
            self.exit()

    def query_sequence(
        self,
        option,
        query_method,
        parse_method,
        message,  # pylint: disable=R0913
        no_exit=False,
    ):
        self.__query_sequence(
            option, query_method, parse_method, message, no_exit=no_exit
        )

    def x_query_sequence(
        self,
        x,
        option,
        query_method,
        parse_method,  # pylint: disable=R0913
        message,
        no_exit=False,
    ):
        self.__query_sequence(
            option, query_method, parse_method, message, start_args=[x], no_exit=no_exit
        )

    def parse_source(self, value):
        if (
            not checkIPnMask(value)
            and not checkIP6nMask(value)
            and not check_mac(value)
            and not (value.startswith("ipset:") and len(value) > 6)
        ):
            raise FirewallError(
                errors.INVALID_ADDR,
                "'%s' is no valid IPv4, IPv6 or MAC address, nor an ipset" % value,
            )
        return value

    def parse_port(self, value, separator="/"):
        try:
            (port, proto) = value.split(separator)
        except ValueError:
            raise FirewallError(
                errors.INVALID_PORT,
                "bad port (most likely "
                "missing protocol), correct syntax is "
                "portid[-portid]%sprotocol" % separator,
            )
        if not check_port(port):
            raise FirewallError(errors.INVALID_PORT, port)
        if proto not in ["tcp", "udp", "sctp", "dccp"]:
            raise FirewallError(
                errors.INVALID_PROTOCOL,
                "'%s' not in {'tcp'|'udp'|'sctp'|'dccp'}" % proto,
            )
        return (port, proto)

    def parse_forward_port(self, value, compat=False):
        port = None
        protocol = None
        toport = None
        toaddr = None
        i = 0
        while "=" in value[i:]:
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
                raise FirewallError(
                    errors.INVALID_FORWARD, "invalid forward port arg '%s'" % (opt)
                )
        if not port:
            raise FirewallError(errors.INVALID_FORWARD, "missing port")
        if not protocol:
            raise FirewallError(errors.INVALID_FORWARD, "missing protocol")
        if not (toport or toaddr):
            raise FirewallError(errors.INVALID_FORWARD, "missing destination")

        if not check_port(port):
            raise FirewallError(errors.INVALID_PORT, port)
        if protocol not in ["tcp", "udp", "sctp", "dccp"]:
            raise FirewallError(
                errors.INVALID_PROTOCOL,
                "'%s' not in {'tcp'|'udp'|'sctp'|'dccp'}" % protocol,
            )
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
            raise FirewallError(
                errors.INVALID_OPTION, "invalid ipset option '%s'" % (value)
            )

    def check_destination_ipv(self, value):
        ipvs = [
            "ipv4",
            "ipv6",
        ]
        if value not in ipvs:
            raise FirewallError(
                errors.INVALID_IPV,
                "invalid argument: %s (choose from '%s')" % (value, "', '".join(ipvs)),
            )
        return value

    def parse_service_destination(self, value):
        try:
            (ipv, destination) = value.split(":", 1)
        except ValueError:
            raise FirewallError(
                errors.INVALID_DESTINATION, "destination syntax is ipv:address[/mask]"
            )
        return (self.check_destination_ipv(ipv), destination)

    def check_ipv(self, value):
        ipvs = ["ipv4", "ipv6", "eb"]
        if value not in ipvs:
            raise FirewallError(
                errors.INVALID_IPV,
                "invalid argument: %s (choose from '%s')" % (value, "', '".join(ipvs)),
            )
        return value

    def check_helper_family(self, value):
        ipvs = ["", "ipv4", "ipv6"]
        if value not in ipvs:
            raise FirewallError(
                errors.INVALID_IPV,
                "invalid argument: %s (choose from '%s')" % (value, "', '".join(ipvs)),
            )
        return value

    def check_module(self, value):
        if not value.startswith("nf_conntrack_"):
            raise FirewallError(
                errors.INVALID_MODULE,
                "'%s' does not start with 'nf_conntrack_'" % value,
            )
        if len(value.replace("nf_conntrack_", "")) < 1:
            raise FirewallError(
                errors.INVALID_MODULE, "Module name '%s' too short" % value
            )
        return value

    def print_zone_policy_info(
        self,
        zone,
        settings,
        default_zone=None,
        extra_interfaces=[],
        active_zones=[],
        active_policies=[],
        isPolicy=True,
    ):  # pylint: disable=R0914
        target = settings.getTarget()
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
        if isPolicy:
            ingress_zones = settings.getIngressZones()
            egress_zones = settings.getEgressZones()
            priority = settings.getPriority()
        else:
            icmp_block_inversion = settings.getIcmpBlockInversion()
            interfaces = sorted(set(settings.getInterfaces() + extra_interfaces))
            sources = settings.getSources()
            forward = settings.getForward()
            ingress_priority = settings.getIngressPriority()
            egress_priority = settings.getEgressPriority()

        def rich_rule_sorted_key(rule):
            priority = 0
            search_str = "priority="
            try:
                i = rule.index(search_str)
            except ValueError:
                pass
            else:
                i += len(search_str)
                priority = int(rule[i : i + (rule[i:].index(" "))].replace('"', ""))

            return priority

        attributes = []
        if default_zone is not None:
            if zone == default_zone:
                attributes.append("default")
        if not isPolicy and zone in active_zones:
            attributes.append("active")
        if isPolicy and zone in active_policies:
            attributes.append("active")
        if attributes:
            zone = zone + " (%s)" % ", ".join(attributes)
        self.print_msg(zone)
        if self.verbose:
            self.print_msg("  summary: " + short_description)
            self.print_msg("  description: " + description)
        if isPolicy:
            self.print_msg("  priority: " + str(priority))
        self.print_msg("  target: " + target)
        if not isPolicy:
            self.print_msg("  ingress-priority: " + str(ingress_priority))
            self.print_msg("  egress-priority: " + str(egress_priority))
            self.print_msg(
                "  icmp-block-inversion: %s" % ("yes" if icmp_block_inversion else "no")
            )
        if isPolicy:
            self.print_msg("  ingress-zones: " + " ".join(ingress_zones))
            self.print_msg("  egress-zones: " + " ".join(egress_zones))
        else:
            self.print_msg("  interfaces: " + " ".join(interfaces))
            self.print_msg("  sources: " + " ".join(sources))
        self.print_msg("  services: " + " ".join(sorted(services)))
        self.print_msg(
            "  ports: " + " ".join(["%s/%s" % (port[0], port[1]) for port in ports])
        )
        self.print_msg("  protocols: " + " ".join(sorted(protocols)))
        if not isPolicy:
            self.print_msg("  forward: %s" % ("yes" if forward else "no"))
        self.print_msg("  masquerade: %s" % ("yes" if masquerade else "no"))
        self.print_msg(
            "  forward-ports: "
            + ("\n\t" if forward_ports else "")
            + "\n\t".join(
                [
                    "port=%s:proto=%s:toport=%s:toaddr=%s"
                    % (port, proto, toport, toaddr)
                    for (port, proto, toport, toaddr) in forward_ports
                ]
            )
        )
        self.print_msg(
            "  source-ports: "
            + " ".join(["%s/%s" % (port[0], port[1]) for port in source_ports])
        )
        self.print_msg("  icmp-blocks: " + " ".join(icmp_blocks))
        self.print_msg(
            "  rich rules: "
            + ("\n\t" if rules else "")
            + "\n\t".join(sorted(rules, key=rich_rule_sorted_key))
        )

    def print_zone_info(
        self, zone, settings, default_zone=None, extra_interfaces=[], active_zones=[]
    ):
        self.print_zone_policy_info(
            zone,
            settings,
            default_zone=default_zone,
            extra_interfaces=extra_interfaces,
            active_zones=active_zones,
            isPolicy=False,
        )

    def print_policy_info(
        self,
        policy,
        settings,
        default_zone=None,
        extra_interfaces=[],
        active_policies=[],
    ):
        self.print_zone_policy_info(
            policy,
            settings,
            default_zone=default_zone,
            extra_interfaces=extra_interfaces,
            active_policies=active_policies,
            isPolicy=True,
        )

    def print_service_info(self, service, settings):
        ports = settings.getPorts()
        protocols = settings.getProtocols()
        source_ports = settings.getSourcePorts()
        modules = settings.getModules()
        description = settings.getDescription()
        destinations = settings.getDestinations()
        short_description = settings.getShort()
        includes = settings.getIncludes()
        helpers = settings.getHelpers()
        self.print_msg(service)
        if self.verbose:
            self.print_msg("  summary: " + short_description)
            self.print_msg("  description: " + description)
        self.print_msg(
            "  ports: " + " ".join(["%s/%s" % (port[0], port[1]) for port in ports])
        )
        self.print_msg("  protocols: " + " ".join(protocols))
        self.print_msg(
            "  source-ports: "
            + " ".join(["%s/%s" % (port[0], port[1]) for port in source_ports])
        )
        self.print_msg("  modules: " + " ".join(modules))
        self.print_msg(
            "  destination: "
            + " ".join(["%s:%s" % (k, v) for k, v in destinations.items()])
        )
        self.print_msg("  includes: " + " ".join(sorted(includes)))
        self.print_msg("  helpers: " + " ".join(sorted(helpers)))

    def print_icmptype_info(self, icmptype, settings):
        destinations = settings.getDestinations()
        description = settings.getDescription()
        short_description = settings.getShort()
        if len(destinations) == 0:
            destinations = ["ipv4", "ipv6"]
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
        self.print_msg(
            "  options: "
            + " ".join(["%s=%s" % (k, v) if v else k for k, v in options.items()])
        )
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
        self.print_msg(
            "  ports: " + " ".join(["%s/%s" % (port[0], port[1]) for port in ports])
        )

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
        if code in [
            errors.ALREADY_ENABLED,
            errors.NOT_ENABLED,
            errors.ZONE_ALREADY_SET,
            errors.ALREADY_SET,
        ]:
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
        entries = []
        entries_set = set()
        f = open(filename)
        for line in f:
            if not line:
                break
            line = line.strip()
            if len(line) < 1 or line[0] in ["#", ";"]:
                continue
            if line not in entries_set:
                entries.append(line)
                entries_set.add(line)
        f.close()
        return entries

    def show_state_and_exit(self, fw, usage_text=None, verbose=False):
        config = fw.config()

        exit_code = 0
        msg = ""
        state = fw.get_state()
        if state == "RUNNING":
            s = "running"
        elif state == "FAILED":
            s = "failed"
        elif state == "NOT_AUTHORIZED":
            s = "not authorized"
            exit_code = errors.NOT_AUTHORIZED
        else:
            state = "NOT_RUNNING"
            s = "not running"
            exit_code = errors.NOT_RUNNING
        if verbose or state != "RUNNING":
            msg += f"State: {s}\n"

        try:
            v = fw.raw_get_property("version", dbus.String)
        except (TypeError, dbus.exceptions.DBusException):
            v = None
        if v is None:
            v = "unknown"
            show_client_version = True
        elif v != firewall.config.VERSION:
            show_client_version = True
        else:
            show_client_version = False
        if verbose or show_client_version:
            msg += f"Version: {v}"
            if show_client_version:
                msg += f" (client: {firewall.config.VERSION})"
            msg += "\n"

        panic_mode = None
        try:
            v = fw.raw_queryPanicMode()
        except (TypeError, dbus.exceptions.DBusException):
            if state not in ("NOT_RUNNING", "NOT_AUTHORIZED"):
                panic_mode = "unknown"
        else:
            if v:
                panic_mode = "enabled"
        if panic_mode is not None:
            msg += f"PanicMode: {panic_mode}\n"

        try:
            default_zone = fw.raw_getDefaultZone()
        except (TypeError, dbus.exceptions.DBusException):
            default_zone = None

        zones = {}
        try:
            lst = fw.raw_getActiveZones()
        except (TypeError, dbus.exceptions.DBusException):
            pass
        else:
            for name, args in lst.items():
                d = zones.setdefault(name, {})
                d["active"] = args
        try:
            lst = fw.raw_getZones()
        except (TypeError, dbus.exceptions.DBusException):
            pass
        else:
            for name in lst:
                d = zones.setdefault(name, {})
                d["runtime"] = True
        if config is not None:
            try:
                lst = config.raw_getZoneNames()
            except (TypeError, dbus.exceptions.DBusException):
                pass
            else:
                for name in lst:
                    d = zones.setdefault(name, {})
                    d["permanent"] = True
        zones_lst = list(zones.items())
        zones_lst.sort(key=lambda z: (z[0] != default_zone, "active" in z[1], z[0]))

        if default_zone is not None and default_zone not in zones:
            msg += f"DefaultZone: {default_zone}\n"

        lst_active = [z for z in zones_lst if z[0] == default_zone or "active" in z[1]]
        lst_other = [
            z for z in zones_lst if not (z[0] == default_zone or "active" in z[1])
        ]
        for i in (0, 1):
            if i == 0:
                lst = lst_active
            else:
                if not verbose:
                    continue
                lst = lst_other
            if not lst:
                continue
            if i == 0:
                msg += "ActiveZones:\n"
            else:
                msg += "Zones:\n"
            for name, args in lst:
                msg += f"  {name}"
                extra = []
                if name == default_zone:
                    extra.append("default")
                if ("permanent" in args) != (
                    "runtime" in args
                ) or "permanent" not in args:
                    if "permanent" in args:
                        extra.append("permanent")
                    if "runtime" in args:
                        extra.append("runtime")
                if extra:
                    msg += f" ({' '.join(extra)})"
                msg += "\n"
                active_args = args.get("active")
                if active_args:
                    v = active_args.get("interfaces")
                    if v:
                        v = " ".join(v)
                        msg += f"    interfaces: {v}\n"
                    v = active_args.get("sources")
                    if v:
                        v = " ".join(v)
                        msg += f"    sources:    {v}\n"

        policies = {}
        try:
            lst = fw.raw_getActivePolicies()
        except (TypeError, dbus.exceptions.DBusException):
            pass
        else:
            for name, args in lst.items():
                d = policies.setdefault(name, {})
                d["active"] = args
        try:
            lst = fw.raw_getPolicies()
        except (TypeError, dbus.exceptions.DBusException):
            pass
        else:
            for name in lst:
                d = policies.setdefault(name, {})
                d["runtime"] = True
        if config is not None:
            try:
                lst = config.raw_getPolicyNames()
            except (TypeError, dbus.exceptions.DBusException):
                pass
            else:
                for name in lst:
                    d = policies.setdefault(name, {})
                d["permanent"] = True
        policies_lst = list(policies.items())
        policies_lst.sort(key=lambda p: ("active" in p[1], p[0]))

        lst_active = [
            z for z in policies_lst if z[0] == default_zone or "active" in z[1]
        ]
        lst_other = [
            z for z in policies_lst if not (z[0] == default_zone or "active" in z[1])
        ]
        for i in (0, 1):
            if i == 0:
                lst = lst_active
            else:
                if not verbose:
                    continue
                lst = lst_other
            if not lst:
                continue
            if i == 0:
                msg += "ActivePolicies:\n"
            else:
                msg += "Policies:\n"
            for name, args in lst:
                msg += f"  {name}"
                extra = []
                if ("permanent" in args) != (
                    "runtime" in args
                ) or "permanent" not in args:
                    if "permanent" in args:
                        extra.append("permanent")
                    if "runtime" in args:
                        extra.append("runtime")
                if extra:
                    msg += f" ({' '.join(extra)})"
                msg += "\n"
                active_args = args.get("active")
                if active_args:
                    v = active_args.get("ingress_zones")
                    if v:
                        v = " ".join(v)
                        msg += f"    ingress-zones: {v}\n"
                    v = active_args.get("egress_zones")
                    if v:
                        v = " ".join(v)
                        msg += f"    egress-zones:  {v}\n"

        if usage_text:
            msg += f"\n{usage_text}\n"

        self.print(msg, not_with_quiet=False, eol=None)
        self.exit(exit_code)
