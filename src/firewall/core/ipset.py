# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2015-2016 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>

"""The ipset command wrapper"""

import os.path
import ipaddress
import socket

from firewall import errors
from firewall.errors import FirewallError
from firewall.core.prog import runProg
from firewall.core.logger import log
from firewall.functions import tempFile, readfile
from firewall.config import COMMANDS
import firewall.functions

IPSET_MAXNAMELEN = 32
IPSET_TYPES = [
    # bitmap and set types are currently not supported
    # "bitmap:ip",
    # "bitmap:ip,mac",
    # "bitmap:port",
    # "list:set",
    "hash:ip",
    "hash:ip,port",
    "hash:ip,port,ip",
    "hash:ip,port,net",
    "hash:ip,mark",
    "hash:net",
    "hash:net,net",
    "hash:net,port",
    "hash:net,port,net",
    "hash:net,iface",
    "hash:mac",
]
IPSET_CREATE_OPTIONS = {
    "family": "inet|inet6",
    "hashsize": "value",
    "maxelem": "value",
    "timeout": "value in secs",
    # "counters": None,
    # "comment": None,
}
IPSET_DEFAULT_CREATE_OPTIONS = {
    "family": "inet",
    "hashsize": "1024",
    "maxelem": "65536",
}


class ipset:
    """ipset command wrapper class"""

    def __init__(self):
        self._command = COMMANDS["ipset"]
        self.name = "ipset"

    def __run(self, args):
        """Call ipset with args"""
        # convert to string list
        _args = ["%s" % item for item in args]
        log.debug2("%s: %s %s", self.__class__, self._command, " ".join(_args))
        (status, ret) = runProg(self._command, _args)
        if status != 0:
            raise ValueError(
                "'%s %s' failed: %s" % (self._command, " ".join(_args), ret)
            )
        return ret

    def check_name(self, name):
        """Check ipset name"""
        if len(name) > IPSET_MAXNAMELEN:
            raise FirewallError(
                errors.INVALID_NAME, "ipset name '%s' is not valid" % name
            )

    def set_supported_types(self):
        """Return types that are supported by the ipset command and kernel"""
        ret = []
        output = ""
        try:
            output = self.__run(["--help"])
        except ValueError as ex:
            log.debug1("ipset error: %s" % ex)
        lines = output.splitlines()

        in_types = False
        for line in lines:
            # print(line)
            if in_types:
                splits = line.strip().split(None, 2)
                if splits[0] not in ret and splits[0] in IPSET_TYPES:
                    ret.append(splits[0])
            if line.startswith("Supported set types:"):
                in_types = True
        return ret

    def check_type(self, type_name):
        """Check ipset type"""
        if len(type_name) > IPSET_MAXNAMELEN or type_name not in IPSET_TYPES:
            raise FirewallError(
                errors.INVALID_TYPE, "ipset type name '%s' is not valid" % type_name
            )

    def set_create(self, set_name, type_name, options=None):
        """Create an ipset with name, type and options"""
        self.check_name(set_name)
        self.check_type(type_name)

        args = ["create", set_name, type_name]
        if isinstance(options, dict):
            for key, val in options.items():
                args.append(key)
                if val != "":
                    args.append(val)
        return self.__run(args)

    def set_destroy(self, set_name):
        self.check_name(set_name)
        return self.__run(["destroy", set_name])

    def set_add(self, set_name, entry):
        args = ["add", set_name, entry]
        return self.__run(args)

    def set_delete(self, set_name, entry):
        args = ["del", set_name, entry]
        return self.__run(args)

    def test(self, set_name, entry, options=None):
        args = ["test", set_name, entry]
        if options:
            args.append("%s" % " ".join(options))
        return self.__run(args)

    def set_list(self, set_name=None, options=None):
        args = ["list"]
        if set_name:
            args.append(set_name)
        if options:
            args.extend(options)
        return self.__run(args).split("\n")

    def set_get_active_terse(self):
        """Get active ipsets (only headers)"""
        lines = self.set_list(options=["-terse"])

        ret = {}
        _name = _type = None
        _options = {}
        for line in lines:
            if len(line) < 1:
                continue
            pair = [x.strip() for x in line.split(":", 1)]
            if len(pair) != 2:
                continue
            elif pair[0] == "Name":
                _name = pair[1]
            elif pair[0] == "Type":
                _type = pair[1]
            elif pair[0] == "Header":
                splits = pair[1].split()
                i = 0
                while i < len(splits):
                    opt = splits[i]
                    if opt in ["family", "hashsize", "maxelem", "timeout", "netmask"]:
                        if len(splits) > i:
                            i += 1
                            _options[opt] = splits[i]
                        else:
                            log.error("Malformed ipset list -terse output: %s", line)
                            return {}
                    i += 1
                if _name and _type:
                    ret[_name] = (_type, remove_default_create_options(_options))
                _name = _type = None
                _options.clear()
        return ret

    def save(self, set_name=None):
        args = ["save"]
        if set_name:
            args.append(set_name)
        return self.__run(args)

    def set_restore(
        self, set_name, type_name, entries, create_options=None, entry_options=None
    ):
        self.check_name(set_name)
        self.check_type(type_name)

        temp_file = tempFile()

        if " " in set_name:
            set_name = "'%s'" % set_name
        args = ["create", set_name, type_name, "-exist"]
        if create_options:
            for key, val in create_options.items():
                args.append(key)
                if val != "":
                    args.append(val)
        temp_file.write("%s\n" % " ".join(args))
        temp_file.write("flush %s\n" % set_name)

        for entry in entries:
            if " " in entry:
                entry = "'%s'" % entry
            if entry_options:
                temp_file.write(
                    "add %s %s %s\n" % (set_name, entry, " ".join(entry_options))
                )
            else:
                temp_file.write("add %s %s\n" % (set_name, entry))
        temp_file.close()

        stat = os.stat(temp_file.name)
        log.debug2(
            "%s: %s restore %s",
            self.__class__,
            self._command,
            "%s: %d" % (temp_file.name, stat.st_size),
        )

        args = ["restore"]
        (status, ret) = runProg(self._command, args, stdin=temp_file.name)

        if log.getDebugLogLevel() > 2:
            try:
                readfile(temp_file.name)
            except Exception:
                pass
            else:
                i = 1
                for line in readfile(temp_file.name):
                    log.debug3("%8d: %s" % (i, line), nofmt=1, nl=0)
                    if not line.endswith("\n"):
                        log.debug3("", nofmt=1)
                    i += 1

        os.unlink(temp_file.name)

        if status != 0:
            raise ValueError(
                "'%s %s' failed: %s" % (self._command, " ".join(args), ret)
            )
        return ret

    def set_flush(self, set_name):
        args = ["flush"]
        if set_name:
            args.append(set_name)
        return self.__run(args)

    def rename(self, old_set_name, new_set_name):
        return self.__run(["rename", old_set_name, new_set_name])

    def swap(self, set_name_1, set_name_2):
        return self.__run(["swap", set_name_1, set_name_2])

    def version(self):
        return self.__run(["version"])


def check_ipset_name(name):
    """Return true if ipset name is valid"""
    if len(name) > IPSET_MAXNAMELEN:
        return False
    return True


def remove_default_create_options(options):
    """Return only non default create options"""
    _options = options.copy()
    for opt in IPSET_DEFAULT_CREATE_OPTIONS:
        if opt in _options and IPSET_DEFAULT_CREATE_OPTIONS[opt] == _options[opt]:
            del _options[opt]
    return _options


###############################################################################


def options_to_addr_family(options):
    # Note that with "hash:mac" there isn't really an IP address family. In
    # some cases, you may want to treat that as "ether".  In any case, this
    # function determines the address-family based on the "options", while the
    # type is a separate field.
    if options and options.get("family") == "inet6":
        return "ipv6"
    return "ipv4"


def ipset_type_parse(ipset_type):
    if isinstance(ipset_type, str) and ipset_type.startswith("hash:"):
        s = ipset_type[5:]
        if s:
            return s.split(",")
    raise FirewallError(
        errors.INVALID_IPSET, "ipset type '%s' not usable" % (ipset_type,)
    )


def ipset_entry_split(entry):
    if isinstance(entry, str) and entry:
        return entry.split(",")
    raise FirewallError(errors.INVALID_IPSET, "ipset entry '%s' not usable" % (entry,))


def ipset_entry_split_with_type(entry, ipset_type):
    flags = ipset_type_parse(ipset_type)
    items = ipset_entry_split(entry)

    if len(flags) != len(items):
        raise FirewallError(
            errors.INVALID_ENTRY,
            "entry '%s' does not match ipset type '%s'" % (entry, ipset_type),
        )

    return items, flags


###############################################################################


def _raise_firewallerror_ipset_inval_addr(entry_item, entry, ipset_type, family):
    raise FirewallError(
        errors.INVALID_ENTRY,
        "invalid address '%s' in '%s' for %s (%s)"
        % (entry_item, entry, ipset_type, family),
    )


def _raise_firewallerror_ipset_inval_mac(entry_item, entry):
    raise FirewallError(
        errors.INVALID_ENTRY,
        "invalid mac address '%s' in '%s'" % (entry_item, entry),
    )


def ipset_entry_parse(entry, ipset_type, lst_entry, lst_ipset_type, idx, family):
    entry_item = lst_entry[idx]
    ipset_type_item = lst_ipset_type[idx]

    orig_family = family
    family = firewall.functions.addr_family(family, allow_unspec=False)

    entrytype = None
    detail = None

    if ipset_type_item in ("ip", "net"):
        try:
            entrytype, detail = firewall.functions.EntryType.parse(
                entry_item,
                family=family,
                types=(
                    firewall.functions.EntryTypeAddr,
                    firewall.functions.EntryTypeAddrMask,
                    firewall.functions.EntryTypeAddrRange,
                ),
            )
        except ValueError:
            if (
                ipset_type_item == "ip"
                and entry_item.count("-") >= 2
                and family == socket.AF_INET
            ):
                raise FirewallError(
                    errors.INVALID_ENTRY,
                    "invalid address range '%s' in '%s' for %s (%s)"
                    % (entry_item, entry, ipset_type, orig_family),
                )
            _raise_firewallerror_ipset_inval_addr(
                entry_item, entry, ipset_type, orig_family
            )

        if entrytype is firewall.functions.EntryTypeAddr:
            addrbin, family = detail
            if ipset_type_item == "ip":
                if (
                    family == socket.AF_INET
                    and addrbin == firewall.functions.IPAddrZero4
                ):
                    _raise_firewallerror_ipset_inval_addr(
                        entry_item, entry, ipset_type, orig_family
                    )
            elif ipset_type_item == "net":
                pass
            else:
                raise errors.BugError()
        elif entrytype is firewall.functions.EntryTypeAddrMask:
            addrbin, plen, family = detail
            if ipset_type_item == "ip":
                if idx > 0:
                    # IPs with mask only allowed in the first
                    # position of the type
                    _raise_firewallerror_ipset_inval_addr(
                        entry_item, entry, ipset_type, orig_family
                    )
            elif ipset_type_item == "net":
                if plen == 0:
                    if (
                        family == socket.AF_INET6
                        and idx == 0
                        and tuple(lst_ipset_type) == ("net", "iface")
                    ):
                        pass
                    else:
                        _raise_firewallerror_ipset_inval_addr(
                            entry_item, entry, ipset_type, orig_family
                        )
            else:
                raise errors.BugError()
        elif entrytype is firewall.functions.EntryTypeAddrRange:
            addrbin1, addrbin2, plen, family = detail
            if ipset_type_item == "ip":
                if idx > 1:
                    # IP ranges only with plain IPs, no masks
                    raise FirewallError(
                        errors.INVALID_ENTRY,
                        "invalid address '%s' in '%s'[%s]" % (entry_item, entry, idx),
                    )
                if plen != -1:
                    # Subnet mask not allowed with this type
                    _raise_firewallerror_ipset_inval_addr(
                        f"{firewall.functions.ipaddr_unparse(addrbin2, family)}/{plen}",
                        entry,
                        ipset_type,
                        orig_family,
                    )
                if family != socket.AF_INET:
                    # A range is only supported with the first "ip" for IPv4.
                    _raise_firewallerror_ipset_inval_addr(
                        entry_item, entry, ipset_type, orig_family
                    )
            elif ipset_type_item == "net":
                pass
            else:
                raise errors.BugError()
        else:
            raise errors.BugError()

    elif ipset_type_item == "mac":
        try:
            entrytype, detail = firewall.functions.EntryType.parse(
                entry_item,
                family=family,
                types=(firewall.functions.EntryTypeMac,),
            )
        except ValueError:
            _raise_firewallerror_ipset_inval_mac(entry_item, entry)
        (mac,) = detail
        if mac == "00:00:00:00:00:00":
            # ipset does not allow to add 00:00:00:00:00:00
            _raise_firewallerror_ipset_inval_mac(entry_item, entry)
    elif ipset_type_item == "port":
        try:
            entrytype, detail = firewall.functions.EntryType.parse(
                entry_item,
                family=family,
                types=(firewall.functions.EntryTypePort,),
            )
        except ValueError:
            raise FirewallError(
                errors.INVALID_ENTRY, "invalid port '%s' in '%s'" % (entry_item, entry)
            )
    elif ipset_type_item == "mark":
        try:
            entrytype, detail = firewall.functions.EntryType.parse(
                entry_item,
                family=family,
                types=(firewall.functions.EntryTypeMark,),
            )
        except ValueError:
            raise FirewallError(
                errors.INVALID_ENTRY, "invalid mark '%s' in '%s'" % (entry_item, entry)
            )
    elif ipset_type_item == "iface":
        try:
            entrytype, detail = firewall.functions.EntryType.parse(
                entry_item,
                family=family,
                types=(firewall.functions.EntryTypeIface,),
            )
        except ValueError:
            raise FirewallError(
                errors.INVALID_ENTRY,
                "invalid interface '%s' in '%s'" % (entry_item, entry),
            )
    else:
        raise FirewallError(
            errors.INVALID_IPSET, "ipset type '%s' not usable" % (ipset_type_item,)
        )

    return entrytype, detail


###############################################################################


def normalize_ipset_entry(entry):
    """Normalize IP addresses in entry"""
    _entry = []
    for _part in ipset_entry_split(entry):
        try:
            _part.index("/")
            _entry.append(str(ipaddress.ip_network(_part, strict=False)))
        except ValueError:
            _entry.append(_part)

    return ",".join(_entry)


def check_entry_overlaps_existing(entry, entries):
    """Check if entry overlaps any entry in the list of entries"""
    # Only check simple types
    if len(ipset_entry_split(entry)) > 1:
        return

    try:
        entry_network = ipaddress.ip_network(entry, strict=False)
    except ValueError:
        # could not parse the new IP address, maybe a MAC
        return

    for itr in entries:
        if entry_network.overlaps(ipaddress.ip_network(itr, strict=False)):
            raise FirewallError(
                errors.INVALID_ENTRY,
                "Entry '{}' overlaps with existing entry '{}'".format(entry, itr),
            )


def check_for_overlapping_entries(entries):
    """Check if any entry overlaps any entry in the list of entries"""
    try:
        entries = [ipaddress.ip_network(x, strict=False) for x in entries]
    except ValueError:
        # at least one entry can not be parsed
        return

    if len(entries) == 0:
        return

    # We can take advantage of some facts of IPv4Network/IPv6Network and
    # how Python sorts the networks to quickly detect overlaps.
    #
    # Facts:
    #
    #   1. IPv{4,6}Network are normalized to remove host bits, e.g.
    #     10.1.1.0/16 will become 10.1.0.0/16.
    #
    #   2. IPv{4,6}Network objects are sorted by:
    #     a. IP address (network bits)
    #   then
    #     b. netmask (significant bits count)
    #
    # Because of the above we have these properties:
    #
    #   1. big networks (netA) are sorted before smaller networks (netB)
    #      that overlap the big network (netA)
    #     - e.g. 10.1.128.0/17 (netA) sorts before 10.1.129.0/24 (netB)
    #   2. same value addresses (network bits) are grouped together even
    #      if the number of network bits vary. e.g. /16 vs /24
    #     - recall that address are normalized to remove host bits
    #     - e.g. 10.1.128.0/17 (netA) sorts before 10.1.128.0/24 (netC)
    #   3. non-overlapping networks (netD, netE) are always sorted before or
    #      after networks that overlap (netB, netC) the current one (netA)
    #     - e.g. 10.1.128.0/17 (netA) sorts before 10.2.128.0/16 (netD)
    #     - e.g. 10.1.128.0/17 (netA) sorts after 9.1.128.0/17 (netE)
    #     - e.g. 9.1.128.0/17 (netE) sorts before 10.1.129.0/24 (netB)
    #
    # With this we know the sorted list looks like:
    #
    #   list: [ netE, netA, netB, netC, netD ]
    #
    #   netE = non-overlapping network
    #   netA = big network
    #   netB = smaller network that overlaps netA (subnet)
    #   netC = smaller network that overlaps netA (subnet)
    #   netD = non-overlapping network
    #
    #   If networks netB and netC exist in the list, they overlap and are
    #   adjacent to netA.
    #
    # Checking for overlaps on a sorted list is thus:
    #
    #   1. compare adjacent elements in the list for overlaps
    #
    # Recall that we only need to detect a single overlap. We do not need to
    # detect them all.
    #
    entries.sort()
    prev_network = entries.pop(0)
    for current_network in entries:
        if prev_network.overlaps(current_network):
            raise FirewallError(
                errors.INVALID_ENTRY,
                "Entry '{}' overlaps entry '{}'".format(prev_network, current_network),
            )
        prev_network = current_network
