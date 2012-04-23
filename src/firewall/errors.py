#
# Copyright (C) 2010 Red Hat, Inc.
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

ALREADY_ENABLED   =   11
NOT_ENABLED       =   12
COMMAND_FAILED    =   13
NO_IPV6_NAT       =   14
PANIC_MODE        =   15
ZONE_ALREADY_SET  =   16
UNKNOWN_INTERFACE =   17
ZONE_CONFLICT     =   18
IMMUTABLE         =   19
BUILTIN_CHAIN     =   20
EBTABLES_NO_REJECT =  21
NOT_OVERLOADABLE  =   22

INVALID_ACTION    =   30
INVALID_SERVICE   =   31
INVALID_PORT      =   32
INVALID_PROTOCOL  =   33
INVALID_INTERFACE =   34
INVALID_ADDR      =   35
INVALID_FORWARD   =   36
INVALID_ICMPTYPE  =   37
INVALID_TABLE     =   38
INVALID_CHAIN     =   39
INVALID_TARGET    =   40
INVALID_IPV       =   41
INVALID_ZONE      =   42
INVALID_PROPERTY  =   43
INVALID_VALUE     =   44
INVALID_OBJECT    =   45

MISSING_TABLE     =   50
MISSING_CHAIN     =   51
MISSING_PORT      =   52
MISSING_PROTOCOL  =   53
MISSING_ADDR      =   54

NOT_RUNNING       =   98
NOT_AUTHORIZED    =   99
UNKNOWN_ERROR     =  100

import sys

class FirewallError(Exception):
    mod = sys.modules[__module__]
    errors = dict([(getattr(mod,varname),varname)
                   for varname in dir(mod)
                   if not varname.startswith("_")])
    codes = dict([(errors[code],code) for code in errors])

    def __init__(self, code, msg=None):
        self.code = code
        self.msg = msg

    def __str__(self):
        if self.msg:
            return "%s: %s" % (self.errors[self.code], self.msg)
        return self.errors[self.code]

    def get_code(msg):
        if ":" in msg:
            idx = msg.index(":")
            ecode = msg[:idx]
        else:
            ecode = msg
        return FirewallError.codes[ecode]
    get_code = staticmethod(get_code)
