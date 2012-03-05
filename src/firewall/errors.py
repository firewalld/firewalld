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

ALREADY_ENABLED   =   -1
NOT_ENABLED       =   -2
ENABLE_FAILED     =   -3
DISABLE_FAILED    =   -4
NO_IPV6_NAT       =   -5
PANIC_MODE        =   -6
ZONE_ALREADY_SET  =   -7
UNKNOWN_INTERFACE =   -8
ZONE_CONFLICT     =   -9
ADD_FAILED        =  -10
REMOVE_FAILED     =  -11
IMMUTABLE         =  -12
BUILTIN_CHAIN     =  -13
EBTABLES_NO_REJECT =  -14
NOT_OVERLOADABLE  =  -15

INVALID_ACTION    =  -20
INVALID_SERVICE   =  -21
INVALID_PORT      =  -22
INVALID_PROTOCOL  =  -23
INVALID_INTERFACE =  -24
INVALID_ADDR      =  -25
INVALID_FORWARD   =  -26
INVALID_ICMPTYPE  =  -27
INVALID_TABLE     =  -28
INVALID_CHAIN     =  -29
INVALID_TARGET    =  -30
INVALID_IPV       =  -31
INVALID_ZONE      =  -32
INVALID_PROPERTY  =  -33
INVALID_VALUE     =  -34
INVALID_OBJECT    =  -35

MISSING_TABLE     =  -40
MISSING_CHAIN     =  -41
MISSING_PORT      =  -42
MISSING_PROTOCOL  =  -43
MISSING_ADDR      =  -44

UNKNOWN_SENDER    =  -99
UNKNOWN_ERROR     = -100

import sys

class FirewallError(Exception):
    mod = sys.modules[__module__]
    errors = dict([(getattr(mod,varname),varname)
                   for varname in dir(mod)
                   if not varname.startswith("_")])
    codes = dict([(errors[code],code) for code in errors])

    def __init__(self, code, msg=None):
        self.code = code

    def __str__(self):
        return self.errors[self.code]
