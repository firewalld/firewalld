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

###############################################################################


def getPortID(port):
    """Check and Get port id from port string or port id using socket.getservbyname

    @param port port string or port id
    @return Port id if valid, -1 if port can not be found and -2 if port is too big
    """

    if isinstance(port, int):
        _id = port
    else:
        if port:
            port = port.strip()
        try:
            _id = int(port)
        except ValueError:
            try:
                _id = socket.getservbyname(port)
            except socket.error:
                return -1
    if _id > 65535:
        return -2
    return _id


def getPortRange(ports):
    """Get port range for port range string or single port id

    @param ports an integer or port string or port range string
    @return Array containing start and end port id for a valid range or -1 if port can not be found and -2 if port is too big for integer input or -1 for invalid ranges or None if the range is ambiguous.
    """

    # (port, port)  or [port, port] case
    if isinstance(ports, tuple) or isinstance(ports, list):
        return ports

    # "<port-id>" case
    if isinstance(ports, int) or ports.isdigit():
        id1 = getPortID(ports)
        if id1 >= 0:
            return (id1,)
        return id1

    splits = ports.split("-")

    # "<port-id>-<port-id>" case
    if len(splits) == 2 and splits[0].isdigit() and splits[1].isdigit():
        id1 = getPortID(splits[0])
        id2 = getPortID(splits[1])
        if id1 >= 0 and id2 >= 0:
            if id1 < id2:
                return (id1, id2)
            elif id1 > id2:
                return (id2, id1)
            else:  # ids are the same
                return (id1,)

    # everything else "<port-str>[-<port-str>]"
    matched = []
    for i in range(len(splits), 0, -1):
        id1 = getPortID("-".join(splits[:i]))
        port2 = "-".join(splits[i:])
        if len(port2) > 0:
            id2 = getPortID(port2)
            if id1 >= 0 and id2 >= 0:
                if id1 < id2:
                    matched.append((id1, id2))
                elif id1 > id2:
                    matched.append((id2, id1))
                else:
                    matched.append((id1,))
        else:
            if id1 >= 0:
                matched.append((id1,))
                if i == len(splits):
                    # full match, stop here
                    break
    if len(matched) < 1:
        return -1
    elif len(matched) > 1:
        return None
    return matched[0]


def portStr(port, delimiter=":"):
    """Create port and port range string

    @param port port or port range int or [int, int]
    @param delimiter of the output string for port ranges, default ':'
    @return Port or port range string, empty string if port isn't specified, None if port or port range is not valid
    """
    if port == "":
        return ""

    _range = getPortRange(port)
    if isinstance(_range, int) and _range < 0:
        return None
    elif len(_range) == 1:
        return "%s" % _range
    else:
        return "%s%s%s" % (_range[0], delimiter, _range[1])


def portInPortRange(port, range):
    _port = getPortRange(port)
    _range = getPortRange(range)

    if len(_port) == 1:
        if len(_range) == 1:
            return getPortID(_port[0]) == getPortID(_range[0])
        if (
            len(_range) == 2
            and getPortID(_port[0]) >= getPortID(_range[0])
            and getPortID(_port[0]) <= getPortID(_range[1])
        ):
            return True
    elif len(_port) == 2:
        if (
            len(_range) == 2
            and getPortID(_port[0]) >= getPortID(_range[0])
            and getPortID(_port[0]) <= getPortID(_range[1])
            and getPortID(_port[1]) >= getPortID(_range[0])
            and getPortID(_port[1]) <= getPortID(_range[1])
        ):
            return True

    return False


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
    index = ip.find("/")
    if index != -1:
        addr = ip[:index]
        mask = ip[index + 1 :]
        if not addr or not mask:
            return False
    else:
        addr = ip
        mask = None
    if not checkIP(addr):
        return False
    if mask:
        if "." in mask:
            return checkIP(mask)
        else:
            try:
                i = int(mask)
            except ValueError:
                return False
            if i < 0 or i > 32:
                return False
    return True


def stripNonPrintableCharacters(rule_str):
    return rule_str.translate(NOPRINT_TRANS_TABLE)


def checkIP6nMask(ip):
    index = ip.find("/")
    if index != -1:
        addr = ip[:index]
        mask = ip[index + 1 :]
        if not addr or not mask:
            return False
    else:
        addr = ip
        mask = None
    if not checkIP6(addr):
        return False
    if mask:
        try:
            i = int(mask)
        except ValueError:
            return False
        if i < 0 or i > 128:
            return False

    return True


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
    if ipv == "ipv4":
        return checkIPnMask(source)
    elif ipv == "ipv6":
        return checkIP6nMask(source)
    else:
        return False


def check_single_address(ipv, source):
    return ipaddr_check(source, family=ipv)


def check_mac(mac):
    if len(mac) == 12 + 5:
        # 0 1 : 3 4 : 6 7 : 9 10 : 12 13 : 15 16
        for i in (2, 5, 8, 11, 14):
            if mac[i] != ":":
                return False
        for i in (0, 1, 3, 4, 6, 7, 9, 10, 12, 13, 15, 16):
            if mac[i] not in string.hexdigits:
                return False
        return True
    return False


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
