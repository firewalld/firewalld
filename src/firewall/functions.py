# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2007,2008,2011,2012 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>

import enum
import socket
import os
import os.path
import shlex
import string
import tempfile

import firewall.errors
from firewall.core.logger import log
from firewall.config import FIREWALLD_TEMPDIR, FIREWALLD_PIDFILE
import firewall.core.icmp

NOPRINT_TRANS_TABLE = {
    # Limit to C0 and C1 code points. Building entries for all unicode code
    # points requires too much memory.
    # C0 = [0, 31]
    # C1 = [127, 159]
    #
    i: None
    for i in range(0, 160)
    if not (i > 31 and i < 127)
}


###############################################################################


def addr_family(family, allow_unspec=False):
    """Normalizes (and verifies) the address family. It returns the corresponding
    socket.AF_INET, socket.AF_INET6, or socket.AF_UNSPEC

    @family: the family to normalize/verify.
    @allow_unspec: whether socket.AF_UNSPEC and None is accepted as socket.AF_UNSPEC
    """
    if family == socket.AF_INET or family == socket.AF_INET6:
        return family
    if family is None or family == socket.AF_UNSPEC:
        if allow_unspec:
            return socket.AF_UNSPEC
    elif isinstance(family, str):
        family = family.lower()
        if family in ("ipv4", "4", "ip4", "inet4", "inet"):
            return socket.AF_INET
        if family in ("ipv6", "6", "ip6", "inet6"):
            return socket.AF_INET6
        if allow_unspec and family == "ip":
            return socket.AF_UNSPEC

    # Family is not untrusted user-input, it's provided by the calling code.
    # It's a bug to come up with an invalid address family.
    raise firewall.errors.BugError("not a valid IP address family")


def addr_family_str(family):
    """Returns either 'IPv4' or 'IPv6' or 'IP', depending on the address family."""
    family = addr_family(family, allow_unspec=True)
    if family == socket.AF_INET:
        return "IPv4"
    if family == socket.AF_INET6:
        return "IPv6"
    return "IP"


def addr_family_size(family):
    family = addr_family(family)
    if family == socket.AF_INET:
        return 4
    return 16


def addr_family_bitsize(family):
    family = addr_family(family)
    if family == socket.AF_INET:
        return 32
    return 128


###############################################################################


IPAddrZero4 = b"\0\0\0\0"


###############################################################################


def _parse_check_fcn(parse_fcn):
    def f(*a, **kw):
        try:
            parse_fcn(*a, **kw)
        except ValueError:
            return False
        return True

    return f


def _parse_norm_fcn(parse_fcn, unparse_fcn):
    def f(*a, **kw):
        detail = parse_fcn(*a, **kw)
        return unparse_fcn(*detail)

    return f


###############################################################################


def ipaddr_parse(addr, *, family=None, flags=0):
    """Parses and validates the address

    @addr: the IP address as str
    @family: the address to parse. Set to None to autodetect the family
    @flags: EntryType.ParseFlags flags
    @Returns (addrbin, family) on success, the address in binary and
      the detected address family (like socket.AF_INET).
      Otherwise, raises ValueError().
    """

    family = addr_family(family, allow_unspec=True)

    addrbin = None

    if family == socket.AF_INET or family == socket.AF_UNSPEC:
        try:
            addrbin = socket.inet_pton(socket.AF_INET, addr)
        except socket.error:
            pass
        else:
            family = socket.AF_INET

    if addrbin is None and (family == socket.AF_INET6 or family == socket.AF_UNSPEC):
        try:
            addrbin = socket.inet_pton(socket.AF_INET6, addr)
        except socket.error:
            pass
        else:
            family = socket.AF_INET6
        if (
            addrbin is None
            and not (flags & EntryType.ParseFlags.NO_IP6_BRACKETS)
            and isinstance(addr, str)
            and len(addr) > 2
            and addr[0] == "["
            and addr[-1] == "]"
        ):
            try:
                addrbin = socket.inet_pton(socket.AF_INET6, addr[1:][0:-1])
            except socket.error:
                pass
            else:
                family = socket.AF_INET6
    if addrbin is None:
        raise ValueError("not a valid {addr_family_str(family)} address")

    return addrbin, family


def ipaddr_unparse(addrbin, family, *, with_ip6_brackets=False):
    s = socket.inet_ntop(family, addrbin)
    if with_ip6_brackets and family == socket.AF_INET6:
        s = f"[{s}]"
    return s


ipaddr_check = _parse_check_fcn(ipaddr_parse)

ipaddr_norm = _parse_norm_fcn(ipaddr_parse, ipaddr_unparse)


###############################################################################


def ipaddrmask_to_plen(maskbin, family=None):
    family = addr_family(family, allow_unspec=True)

    if isinstance(maskbin, bytes) and family == socket.AF_UNSPEC:
        if len(maskbin) == 4:
            family = socket.AF_INET
        elif len(maskbin) == 16:
            family = socket.AF_INET6

    if isinstance(maskbin, bytes) and len(maskbin) == addr_family_size(family):
        pass
    else:
        raise ValueError("Invalid mask")

    n = len(maskbin)
    plen = n * 8
    for i in range(n):
        c = maskbin[n - i - 1]
        if c == 0:
            plen -= 8
            continue
        if c < 255:
            b = 1
            for i in range(8):
                if (c & b) != 0:
                    break
                plen -= 1
                b <<= 1
        break

    return plen


###############################################################################


def ipaddrmask_parse(
    addrmask,
    *,
    family=None,
    flags=0,
    require_plen=True,
):

    family = addr_family(family, allow_unspec=True)

    if isinstance(addrmask, str):
        index = addrmask.find("/")
        if index != -1:
            addr = addrmask[:index]
            mask = addrmask[index + 1 :]
        else:
            addr = addrmask
            mask = None
    else:
        addr = None
        mask = None

    if addr is not None:
        try:
            addrbin, family = ipaddr_parse(addr, family=family, flags=flags)
            plen = -1
            if mask is not None:
                try:
                    plen = int(mask)
                    if plen < 0:
                        raise ValueError("fail")
                except ValueError:
                    if family != socket.AF_INET:
                        # only for IPv4, we accept a subnet mask (/255.255.255.0)
                        raise
                    mask, _ = ipaddr_parse(mask, family=family, flags=flags)
                    plen = ipaddrmask_to_plen(mask, family)

            if plen != -1 and plen > addr_family_bitsize(family):
                raise ValueError("invalid plen")

            if plen == -1 and require_plen:
                raise ValueError(
                    "{addr_family_str(family)} address lacks a mask/prefixlength"
                )

            return addrbin, plen, family
        except ValueError:
            pass

    raise ValueError("not a valid {addr_family_str(family)} subnet")


def ipaddrmask_unparse(addrbin, plen, family):
    s = ipaddr_unparse(addrbin, family)
    if plen == -1:
        return s
    return f"{s}/{plen}"


ipaddrmask_check = _parse_check_fcn(ipaddrmask_parse)

ipaddrmask_norm = _parse_norm_fcn(ipaddrmask_parse, ipaddrmask_unparse)


###############################################################################


def ipaddrrange_parse(addrrange, *, family=None, flags=0):
    family = addr_family(family, allow_unspec=True)
    addr1 = None
    addr2 = None
    if isinstance(addrrange, str):
        index = addrrange.find("-")
        if index != -1:
            addr1 = addrrange[:index]
            addr2 = addrrange[index + 1 :]

    if addr1 is None:
        raise ValueError("not a valid address range")

    try:
        addrbin1, family = ipaddr_parse(addr1, family=family, flags=flags)
        # Second part can also have a mask.
        addrbin2, plen, _ = ipaddrmask_parse(
            addr2, family=family, flags=flags, require_plen=False
        )
    except ValueError:
        if family == socket.AF_UNSPEC:
            # Try to detect the family for a better error message...
            try:
                _, _, family = ipaddrmask_parse(addr2, flags=flags, require_plen=False)
            except ValueError:
                pass
        raise ValueError(f"not a valid {addr_family_str(family)} address range")

    # Maybe we should reject negative ranges. I think libnftables
    # does that too, which would make it important for firewalld to
    # agree.
    # if plen == -1:
    #     addrx1 = int.from_bytes(addrbin1, "big")
    #     addrx2 = int.from_bytes(addrbin2, "big")
    #     if addrx1 > addrx2:
    #         raise ValueError("IP address range has negative size")

    return addrbin1, addrbin2, plen, family


def ipaddrrange_unparse(addrbin1, addrbin2, plen, family):
    s1 = ipaddr_unparse(addrbin1, family)
    s2 = ipaddrmask_unparse(addrbin2, plen, family)
    return f"{s1}-{s2}"


ipaddrrange_check = _parse_check_fcn(ipaddrrange_parse)

ipaddrrange_norm = _parse_norm_fcn(ipaddrrange_parse, ipaddrrange_unparse)


###############################################################################


def mac_parse(mac, *, family=None, flags=0):

    # The family argument is ignored. It has no meaning for MAC addresses and
    # only exist so that all parse() function have a compatible API. However,
    # we still validate it here.
    family = addr_family(family, allow_unspec=True)

    if isinstance(mac, str) and len(mac) == 12 + 5:
        good = True
        # 0 1 : 3 4 : 6 7 : 9 10 : 12 13 : 15 16
        for i in (2, 5, 8, 11, 14):
            if mac[i] != ":":
                good = False
                break
        if good:
            for i in (0, 1, 3, 4, 6, 7, 9, 10, 12, 13, 15, 16):
                if mac[i] not in string.hexdigits:
                    good = False
                    break
            if good:
                return (mac.lower(),)

    raise ValueError("not a valid ethernet MAC address")


def mac_unparse(mac):
    return mac


mac_check = _parse_check_fcn(mac_parse)

mac_norm = _parse_norm_fcn(mac_parse, mac_unparse)


###############################################################################


def port_parse(
    port,
    *,
    family=None,
    flags=0,
    allow_proto=True,
    allow_range=True,
):
    def check_range(port_id):
        return port_id >= 0 and port_id <= 65535

    def parse_one(port):
        port_name = None
        port_id = None
        if port:
            port = port.strip()
            try:
                port_id = int(port)
            except ValueError:
                if " " in port:
                    # We don't accept space inside the port name (but we accept
                    # at the beginning/end, i.e. around the delimiter.
                    pass
                else:
                    try:
                        port_id = socket.getservbyname(port)
                        port_name = port
                    except socket.error:
                        pass

        if port_id is None:
            raise ValueError("not a valid port")
        return port_id, port_name

    def port_swap(port_id1, port_name1, port_id2, port_name2):
        if port_id2 is not None:
            # If this is a range that is reversed, fix it up.
            if port_id1 > port_id2:
                # swap
                port_id1, port_id2 = port_id2, port_id1
                port_name1, port_name2 = port_name2, port_name1
            elif port_id1 == port_id2:
                if port_name1 is None and port_name2 is not None:
                    # We preserve the name.
                    port_name1 = port_name2
                port_id2 = None
                port_name2 = None
        return port_id1, port_name1, port_id2, port_name2

    family = addr_family(family, allow_unspec=True)

    parse_one_error = None
    proto = None
    port_name1 = None
    port_name2 = None
    port_id1 = None
    port_id2 = None

    if isinstance(port, str) and allow_proto:
        idx = port.find(":")
        if idx != -1:
            p1 = port[:idx].strip()
            p2 = port[idx + 1 :].strip()

            if p1 == "icmp":
                if family == socket.AF_INET6:
                    raise ValueError("Invalid protocol for address family")
                if not firewall.core.icmp.check_icmp_name(
                    p2
                ) and not firewall.core.icmp.check_icmp_type(p2):
                    raise ValueError("Invalid icmp type")
                proto, port_id1, port_name1 = p1, None, p2
            elif p1 in ("icmpv6", "ipv6-icmp"):
                if family == socket.AF_INET:
                    raise ValueError("Invalid protocol for address family")
                if not firewall.core.icmp.check_icmpv6_name(
                    p2
                ) and not firewall.core.icmp.check_icmpv6_type(p2):
                    raise ValueError("Invalid icmpv6 type")
                proto, port_id1, port_name1 = p1, None, p2
            elif p1 not in (
                "tcp",
                "sctp",
                "udp",
                "udplite",
            ) and not checkProtocol(p1):
                raise ValueError("Invalid protocol")
            else:
                (
                    x_proto,
                    x_port_id1,
                    x_port_name1,
                    x_port_id2,
                    x_port_name2,
                ) = port_parse(
                    p2,
                    family=family,
                    flags=flags,
                    allow_range=allow_range,
                    allow_proto=False,
                )
                proto, port_id1, port_name1, port_id2, port_name2 = (
                    p1,
                    x_port_id1,
                    x_port_name1,
                    x_port_id2,
                    x_port_name2,
                )

    if proto is None:
        if isinstance(port, str):
            try:
                port_id1, port_name1 = parse_one(port)
            except ValueError as ex:
                parse_one_error = ex
            if parse_one_error is None:
                # We succeeded to parse a single name. We accept that, even if it
                # contains a delimiter.
                pass
            else:
                if "-" in port and allow_range:
                    # We want to parse ranges, but port-name can contain dashes.
                    # So we iterate over all dashes, and try to find one which
                    # we can use as a split.
                    for i in range(len(port)):
                        if port[i] != "-":
                            continue
                        try:
                            p1 = parse_one(port[:i])
                            p2 = parse_one(port[i + 1 :])
                        except ValueError:
                            continue
                        if port_id1 is not None:
                            # no unique match. We fail.
                            raise ValueError("port name is ambiguous")
                        port_id1, port_name1 = p1
                        port_id2, port_name2 = p2

        else:
            # Usually, our parse just accepts strings. However, also accept
            # already pre-parsed input.
            if isinstance(port, int):
                port_id1 = port
            elif allow_range and (isinstance(port, tuple) or isinstance(port, list)):
                if len(port) == 1:
                    (port_id1,) = port
                elif len(port) == 2:
                    (port_id1, port_id2) = port

        if port_id1 is None:
            if parse_one_error is not None:
                raise ValueError(str(parse_one_error))
            raise ValueError("not a valid port")

        if not check_range(port_id1) or (
            port_id2 is not None and not check_range(port_id2)
        ):
            raise ValueError("port out of range")

        port_id1, port_name1, port_id2, port_name2 = port_swap(
            port_id1, port_name1, port_id2, port_name2
        )

    return proto, port_id1, port_name1, port_id2, port_name2


def port_unparse(proto, port_id1, port_name1, port_id2, port_name2, *, delimiter=None):

    if proto is not None:
        if port_id1 is None:
            # special case for icmp/icmpv6/ipv6-icmp. There is only a port_name.
            p = port_name1
        else:
            p = port_unparse(
                None, port_id1, port_name1, port_id2, port_name2, delimiter=delimiter
            )
        return f"{proto}:{p}"

    p1 = port_name1 or str(port_id1)
    p2 = None
    if port_id2 is not None:
        p2 = port_name2 or str(port_id2)

    if delimiter is not None:
        if p2 is None:
            return p1
        return f"{p1}{delimiter}{p2}"

    # We want to unparse something, that can be parsed back. Since we use
    # '-' as delimiter, and '-' can be part of the names, it's not entirely
    # clear that we always can.
    #
    # If any of the names contain a '-', join them with a space. Our names
    # cannot contain spaces, but the parser strips spaces around the "-"
    if p2 is None:
        return p1
    if "-" not in p1 and "-" not in p2:
        return f"{p1}-{p2}"
    return f"{p1} - {p2}"


port_check = _parse_check_fcn(port_parse)

port_norm = _parse_norm_fcn(port_parse, port_unparse)


###############################################################################


class EntryType:
    class ParseFlags(enum.IntFlag):
        NO_IP6_BRACKETS = 0x1

    def __init__(self, name, fcn_parse, fcn_unparse):
        self.name = name
        self.parse = fcn_parse
        self.unparse = fcn_unparse
        self.check = self._check

    def __repr__(self):
        return f"EntryType({self.name})"

    def norm(self, *a, **kw):
        detail = self.parse(*a, **kw)
        return self.unparse(*detail)

    def _check(self, *a, **kw):
        try:
            self.parse(*a, **kw)
        except ValueError:
            return False
        return True

    @staticmethod
    def parse(entry, *, family=None, flags=0, types):

        first_ex = None

        for entrytype in types:

            if entrytype is None:
                # We allow passing None entry types. Those never parse successfully.
                continue

            try:
                detail = entrytype.parse(
                    entry,
                    family=family,
                    flags=flags,
                )
            except ValueError as ex:
                if first_ex is None:
                    first_ex = ex
                continue

            return (entrytype, detail)

        if first_ex is not None and len(types) == 1:
            # Preserve the error message if we only have one type to parse.
            raise ValueError(str(first_ex))

        raise ValueError("not a valid entry, like an IP address or a port")

    @staticmethod
    def check(entry, *, family=None, flags=0, types):
        try:
            EntryType.parse(entry, family=family, flags=flags, types=types)
        except ValueError:
            return False
        return True


EntryTypeAddr = EntryType("addr", ipaddr_parse, ipaddr_unparse)

EntryTypeAddrMask = EntryType("addr-mask", ipaddrmask_parse, ipaddrmask_unparse)

EntryTypeAddrRange = EntryType("addr-range", ipaddrrange_parse, ipaddrrange_unparse)

EntryTypeMac = EntryType("mac", mac_parse, mac_unparse)

EntryTypePort = EntryType("port", port_parse, port_unparse)

###############################################################################


def getPortID(port):
    """Check and Get port id from port string or port id using socket.getservbyname

    @param port port string or port id
    @return Port id if valid, -1 if port can not be found and -2 if port is too big
    """
    try:
        proto, port_id1, port_name1, port_id2, port_name2 = port_parse(
            port, allow_range=False, allow_proto=False
        )
    except ValueError as ex:
        if "out of range" in str(ex):
            return -2
        return -1
    return port_id1


def getPortRange(ports):
    """Get port range for port range string or single port id

    @param ports an integer or port string or port range string
    @return Array containing start and end port id for a valid range or -1 if port can not be found and -2 if port is too big for integer input or -1 for invalid ranges or None if the range is ambiguous.
    """
    try:
        proto, port_id1, port_name1, port_id2, port_name2 = port_parse(
            ports, allow_proto=False
        )
    except ValueError as ex:
        if "ambiguous" in str(ex):
            return None
        if "out of range" in str(ex):
            return -2
        return -1

    if port_id2 is None:
        return (port_id1,)

    return port_id1, port_id2


def portStr(port, delimiter=":"):
    """Create port and port range string

    @param port port or port range int or [int, int]
    @param delimiter of the output string for port ranges, default ':'
    @return Port or port range string, empty string if port isn't specified, None if port or port range is not valid
    """
    if port == "":
        return ""

    try:
        proto, port_id1, port_name1, port_id2, port_name2 = port_parse(
            port, allow_proto=False
        )
    except ValueError:
        return None

    if port_id2 is not None:
        return f"{port_id1}{delimiter}{port_id2}"
    if port_id1 is not None:
        return f"{port_id1}"
    return None


def portInPortRange(port, range):
    try:
        proto, a_port_id1, a_port_name1, a_port_id2, a_port_name2 = port_parse(
            port, allow_proto=False
        )
        proto, b_port_id1, b_port_name1, b_port_id2, b_port_name2 = port_parse(
            range, allow_proto=False
        )
    except ValueError:
        return False

    if a_port_id2 is None:
        if b_port_id2 is None:
            return a_port_id1 == b_port_id1
        return a_port_id1 >= b_port_id1 and a_port_id1 <= b_port_id2
    return (
        b_port_id2 is not None
        and a_port_id1 >= b_port_id1
        and a_port_id1 <= b_port_id2
        and a_port_id2 >= b_port_id1
        and a_port_id2 <= b_port_id2
    )


def coalescePortRange(new_range, ranges):
    """Coalesce a port range with existing list of port ranges

    @param new_range tuple/list/string
    @param ranges list of tuple/list/string
    @return tuple of (list of ranges added after coalescing, list of removed original ranges)
    """

    coalesced_range = getPortRange(new_range)
    # normalize singleton ranges, e.g. (x,) --> (x,x)
    if len(coalesced_range) == 1:
        coalesced_range = (coalesced_range[0], coalesced_range[0])
    _ranges = map(getPortRange, ranges)
    _ranges = sorted(
        map(lambda x: (x[0], x[0]) if len(x) == 1 else x, _ranges), key=lambda x: x[0]
    )

    removed_ranges = []
    for range in _ranges:
        if coalesced_range[0] <= range[0] and coalesced_range[1] >= range[1]:
            # new range covers this
            removed_ranges.append(range)
        elif (
            coalesced_range[0] <= range[0]
            and coalesced_range[1] < range[1]
            and coalesced_range[1] >= range[0]
        ):
            # expand beginning of range
            removed_ranges.append(range)
            coalesced_range = (coalesced_range[0], range[1])
        elif (
            coalesced_range[0] > range[0]
            and coalesced_range[1] >= range[1]
            and coalesced_range[0] <= range[1]
        ):
            # expand end of range
            removed_ranges.append(range)
            coalesced_range = (range[0], coalesced_range[1])

    # normalize singleton ranges, e.g. (x,x) --> (x,)
    removed_ranges = list(map(lambda x: (x[0],) if x[0] == x[1] else x, removed_ranges))
    if coalesced_range[0] == coalesced_range[1]:
        coalesced_range = (coalesced_range[0],)

    return ([coalesced_range], removed_ranges)


def breakPortRange(remove_range, ranges):
    """break a port range from existing list of port ranges

    @param remove_range tuple/list/string
    @param ranges list of tuple/list/string
    @return tuple of (list of ranges added after breaking up, list of removed original ranges)
    """

    remove_range = getPortRange(remove_range)
    # normalize singleton ranges, e.g. (x,) --> (x,x)
    if len(remove_range) == 1:
        remove_range = (remove_range[0], remove_range[0])
    _ranges = map(getPortRange, ranges)
    _ranges = sorted(
        map(lambda x: (x[0], x[0]) if len(x) == 1 else x, _ranges), key=lambda x: x[0]
    )

    removed_ranges = []
    added_ranges = []
    for range in _ranges:
        if remove_range[0] <= range[0] and remove_range[1] >= range[1]:
            # remove entire range
            removed_ranges.append(range)
        elif (
            remove_range[0] <= range[0]
            and remove_range[1] < range[1]
            and remove_range[1] >= range[0]
        ):
            # remove from beginning of range
            removed_ranges.append(range)
            added_ranges.append((remove_range[1] + 1, range[1]))
        elif (
            remove_range[0] > range[0]
            and remove_range[1] >= range[1]
            and remove_range[0] <= range[1]
        ):
            # remove from end of range
            removed_ranges.append(range)
            added_ranges.append((range[0], remove_range[0] - 1))
        elif remove_range[0] > range[0] and remove_range[1] < range[1]:
            # remove inside range
            removed_ranges.append(range)
            added_ranges.append((range[0], remove_range[0] - 1))
            added_ranges.append((remove_range[1] + 1, range[1]))

    # normalize singleton ranges, e.g. (x,x) --> (x,)
    removed_ranges = list(map(lambda x: (x[0],) if x[0] == x[1] else x, removed_ranges))
    added_ranges = list(map(lambda x: (x[0],) if x[0] == x[1] else x, added_ranges))

    return (added_ranges, removed_ranges)


def getServiceName(port, proto):
    """Check and Get service name from port and proto string combination using socket.getservbyport

    @param port string or id
    @param protocol string
    @return Service name if port and protocol are valid, else None
    """

    try:
        name = socket.getservbyport(int(port), proto)
    except socket.error:
        return None
    return name


def checkIP(ip):
    """Check IPv4 address.

    @param ip address string
    @return True if address is valid, else False
    """
    return ipaddr_check(ip, family=socket.AF_INET)


def normalizeIP6(ip):
    """Normalize the IPv6 address

    This is mostly about converting URL-like IPv6 address to normal ones.
    e.g. [1234::4321] --> 1234::4321
    """
    return ipaddr_norm(ip, family=socket.AF_INET6)


def checkIP6(ip):
    """Check IPv6 address.

    @param ip address string
    @return True if address is valid, else False
    """
    return ipaddr_check(ip, family=socket.AF_INET6)


def checkIPnMask(ip):
    return ipaddrmask_check(ip, family=socket.AF_INET, require_plen=False)


def stripNonPrintableCharacters(rule_str):
    return rule_str.translate(NOPRINT_TRANS_TABLE)


def checkIP6nMask(ip):
    return ipaddrmask_check(ip, family=socket.AF_INET6, require_plen=False)


def checkProtocol(protocol):
    try:
        i = int(protocol)
    except ValueError:
        # string
        try:
            socket.getprotobyname(protocol)
        except socket.error:
            return False
    else:
        if i < 0 or i > 255:
            return False

    return True


def checkTcpMssClamp(tcp_mss_clamp_value):
    if tcp_mss_clamp_value:
        if tcp_mss_clamp_value.isdigit():
            if int(tcp_mss_clamp_value) < 536:
                return False
        elif tcp_mss_clamp_value == "None":
            return True
        elif tcp_mss_clamp_value != "pmtu":
            return False
    return True


def checkInterface(iface):
    """Check interface string

    @param interface string
    @return True if interface is valid (maximum 16 chars and does not contain ' ', '/', '!', ':', '*'), else False
    """

    if not iface or len(iface) > 16:
        return False
    for ch in [" ", "/", "!", "*"]:
        # !:* are limits for iptables <= 1.4.5
        if ch in iface:
            return False
    # disabled old iptables check
    # if iface == "+":
    #    # limit for iptables <= 1.4.5
    #    return False
    return True


def checkUINT16(val):
    try:
        x = int(val, 0)
    except ValueError:
        return False
    else:
        if x >= 0 and x <= 65535:
            return True
    return False


def checkUINT32(val):
    try:
        x = int(val, 0)
    except ValueError:
        return False
    else:
        if x >= 0 and x <= 4294967295:
            return True
    return False


def firewalld_is_active():
    """Check if firewalld is active

    @return True if there is a firewalld pid file and the pid is used by firewalld
    """

    if not os.path.exists(FIREWALLD_PIDFILE):
        return False

    try:
        with open(FIREWALLD_PIDFILE, "r") as fd:
            pid = fd.readline()
    except Exception:
        return False

    if not os.path.exists("/proc/%s" % pid):
        return False

    try:
        with open("/proc/%s/cmdline" % pid, "r") as fd:
            cmdline = fd.readline()
    except Exception:
        return False

    if "firewalld" in cmdline:
        return True

    return False


def tempFile():
    try:
        if not os.path.exists(FIREWALLD_TEMPDIR):
            os.mkdir(FIREWALLD_TEMPDIR, 0o750)

        return tempfile.NamedTemporaryFile(
            mode="wt", prefix="temp.", dir=FIREWALLD_TEMPDIR, delete=False
        )
    except Exception as msg:
        log.error("Failed to create temporary file: %s" % msg)
        raise


def readfile(filename):
    try:
        with open(filename, "r") as f:
            return f.readlines()
    except Exception as e:
        log.error('Failed to read file "%s": %s' % (filename, e))
    return None


def writefile(filename, line):
    try:
        with open(filename, "w") as f:
            f.write(line)
    except Exception as e:
        log.error('Failed to write to file "%s": %s' % (filename, e))
        return False
    return True


def enable_ip_forwarding(ipv):
    if ipv == "ipv4":
        return writefile("/proc/sys/net/ipv4/ip_forward", "1\n")
    elif ipv == "ipv6":
        return writefile("/proc/sys/net/ipv6/conf/all/forwarding", "1\n")
    return False


def get_nf_conntrack_short_name(module):
    return module.replace("_", "-").replace("nf-conntrack-", "")


def check_port(port):
    _range = getPortRange(port)
    if (
        _range == -2
        or _range == -1
        or _range is None
        or (len(_range) == 2 and _range[0] >= _range[1])
    ):
        if _range == -2:
            log.debug2("'%s': port > 65535" % port)
        elif _range == -1:
            log.debug2("'%s': port is invalid" % port)
        elif _range is None:
            log.debug2("'%s': port is ambiguous" % port)
        elif len(_range) == 2 and _range[0] >= _range[1]:
            log.debug2("'%s': range start >= end" % port)
        return False
    return True


def check_address(ipv, source):
    return ipaddrmask_check(source, family=ipv, require_plen=False)


def check_single_address(ipv, source):
    return ipaddr_check(source, family=ipv)


def check_mac(mac):
    return mac_check(mac)


def uniqify(_list):
    # removes duplicates from list, whilst preserving order
    output = []
    for x in _list:
        if x not in output:
            output.append(x)
    return output


def ppid_of_pid(pid):
    """Get parent for pid"""
    try:
        f = os.popen("ps -o ppid -h -p %d 2>/dev/null" % pid)
        pid = int(f.readlines()[0].strip())
        f.close()
    except Exception:
        return None
    return pid


def max_policy_name_len():
    """
    iptables limits length of chain to (currently) 28 chars.
    The longest chain we create is POST_<policy>_allow,
    which leaves 28 - 11 = 17 chars for <policy>.
    """
    from firewall.core.ipXtables import POLICY_CHAIN_PREFIX
    from firewall.core.base import SHORTCUTS

    longest_shortcut = max(map(len, SHORTCUTS.values()))
    return 28 - (longest_shortcut + len(POLICY_CHAIN_PREFIX) + len("_allow"))


def max_zone_name_len():
    """
    Netfilter limits length of chain to (currently) 28 chars.
    The longest chain we create is POST_<zone>_allow,
    which leaves 28 - 11 = 17 chars for <zone>.
    """
    from firewall.core.base import SHORTCUTS

    longest_shortcut = max(map(len, SHORTCUTS.values()))
    return 28 - (longest_shortcut + len("__allow"))


def checkUser(user):
    if len(user) < 1 or len(user) > os.sysconf("SC_LOGIN_NAME_MAX"):
        return False
    for c in user:
        if (
            c not in string.ascii_letters
            and c not in string.digits
            and c not in [".", "-", "_", "$"]
        ):
            return False
    return True


def checkUid(uid):
    if isinstance(uid, str):
        try:
            uid = int(uid)
        except ValueError:
            return False
    if uid >= 0 and uid <= 2**31 - 1:
        return True
    return False


def checkCommand(command):
    if len(command) < 1 or len(command) > 1024:
        return False
    for ch in ["|", "\n", "\0"]:
        if ch in command:
            return False
    if command[0] != "/":
        return False
    return True


def checkContext(context):
    splits = context.split(":")
    if len(splits) not in [4, 5]:
        return False
    # user ends with _u if not root
    if splits[0] != "root" and splits[0][-2:] != "_u":
        return False
    # role ends with _r
    if splits[1][-2:] != "_r":
        return False
    # type ends with _t
    if splits[2][-2:] != "_t":
        return False
    # level might also contain :
    if len(splits[3]) < 1:
        return False
    return True


def joinArgs(args):
    return " ".join(shlex.quote(a) for a in args)


def splitArgs(_string):
    return shlex.split(_string)


def wrong_args_for_callable(fcn, *a, **kw):
    import inspect

    # Check whether fcn(*a, **kw) will fail due to invalid
    # arguments.

    try:
        inspect.bind(fcn, *a, **kw)
    except TypeError:
        return False
    return True
