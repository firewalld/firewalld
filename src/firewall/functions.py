#
# Copyright (C) 2007,2008,2011,2012 Red Hat, Inc.
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

import socket
import types
import os.path

def getPortID(port):
    """ Check and Get port id from port string or port id using socket.getservbyname

    @param port port string or port id
    @return Port id if valid, -1 if port can not be found and -2 if port is too big
    """
    
    if isinstance(port, types.IntType):
        id = port
    else:
        if port:
            port = port.strip()
        try:
            id = int(port)
        except:
            try:
                id = socket.getservbyname(port)
            except:
                return -1
    if id > 65535:
        return -2
    return id

def getPortRange(ports):
    """ Get port range for port range string or single port id

    @param ports an integer or port string or port range string
    @return Array containing start and end port id for a valid range or -1 if port can not be found and -2 if port is too big for integer input or -1 for invalid ranges or None if the range is ambiguous.
    """

    if isinstance(ports, types.IntType):
        id = getPortID(ports)
        if id >= 0:
            return (id,)
        return id

    splits = ports.split("-")
    matched = [ ]
    for i in xrange(len(splits), 0, -1):
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
                    matched.append((id1, ))
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
    """ Create port and port range string 
    
    @param port port or port range int or [int, int]
    @param delimiter of the output string for port ranges, default ':'
    @return Port or port range string, empty string if port isn't specified, None if port or port range is not valid
    """
    if port == "":
        return ""

    range = getPortRange(port)
    if isinstance(range, types.IntType) and range < 0:
        return None
    elif len(range) == 1:
        return "%s" % range
    else:
        return "%s%s%s" % (range[0], delimiter, range[1])

def getServiceName(port, proto):
    """ Check and Get service name from port and proto string combination using socket.getservbyport

    @param port string or id
    @param protocol string
    @return Service name if port and protocol are valid, else None
    """

    try:
        name = socket.getservbyport(int(port), proto)
    except:
        return None
    return name

def checkIP(ip):
    """ Check IPv4 address.
    
    @param ip address string
    @return True if address is valid, else False
    """

    if ip != "":
        splits = ip.split(".")
        if len(splits) != 4:
            return False
        for i in xrange(len(splits)):
            try:
                l = int(splits[i])
            except:
                return False
            if l < 0 or l > 255:
                return False
    return True

def checkIP6(ip):
    """ Check IPv6 address.
    
    @param ip address string
    @return True if address is valid, else False
    """

    try:
        socket.inet_pton(socket.AF_INET6, ip)
    except socket.error as err:
        return False
    return True

def checkIPnMask(ip):
    if "/" in ip:
        addr = ip[:ip.index("/")]
        mask = ip[ip.index("/")+1:]
    else:
        addr = ip
        mask = None
    if not checkIP(addr):
        return False
    if mask:
        if "." in mask and checkIP(addr):
            return False
        else:
            try:
                i = int(mask)
            except:
                return False
    return True

def checkIP6nMask(ip):
    if "/" in ip:
        addr = ip[:ip.index("/")]
        mask = ip[ip.index("/")+1:]
    else:
        addr = ip
        mask = None
    if not checkIP6(addr):
        return False
    if mask:
        try:
            i = int(mask)
        except:
            return False
    return True

def checkInterface(iface):
    """ Check interface string

    @param interface string
    @return True if interface is valid (maximum 16 chars and does not contain ' ', '/', '!', ':', '*'), else False
    """

    if not iface or len(iface) > 16:
        return False
    for ch in [ ' ', '/', '!', ':', '*' ]:
        # !:* are limits for iptables <= 1.4.5
        if ch in iface:
            return False
    # disabled old iptables check
    #if iface == "+":
    #    # limit for iptables <= 1.4.5
    #    return False
    return True

def firewalld_is_active():
    """ Check if firewalld is active

    @return True if there is a firewalld pid file and the pid is used by firewalld
    """

    if not os.path.exists("/var/run/firewalld.pid"):
        return False

    try:
        fd = open("/var/run/firewalld.pid", "r")
        pid = fd.readline()
        fd.close()
    except:
        return False

    if not os.path.exists("/proc/%s" % pid):
        return False

    try:
        fd = open("/proc/%s/cmdline" % pid, "r")
        cmdline = fd.readline()
        fd.close()
    except:
        return False

    if "firewalld" in cmdline:
        return True

    return False
