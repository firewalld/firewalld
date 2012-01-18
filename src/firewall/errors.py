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

NO_ERROR          =    0
ALREADY_ENABLED   =   -1
NOT_ENABLED       =   -2
ENABLE_FAILED     =   -3
DISABLE_FAILED    =   -4
NO_IPV6_NAT       =   -5

INVALID_ACTION    =  -10
INVALID_SERVICE   =  -11
INVALID_PORT      =  -12
INVALID_PROTOCOL  =  -13
INVALID_INTERFACE =  -14
INVALID_ADDR      =  -15
INVALID_FORWARD   =  -16
INVALID_ICMP_TYPE =  -17
INVALID_TABLE     =  -18
INVALID_CHAIN     =  -19
INVALID_TARGET    =  -20
INVALID_IPV       =  -21

MISSING_TABLE     =  -30
MISSING_CHAIN     =  -31
MISSING_PORT      =  -32
MISSING_PROTOCOL  =  -33
MISSING_ADDR      =  -34

UNKNOWN_ERROR     = -100

class FirewallError(Exception):
    def __init__(self, code, msg=None):
        self.code = code

    def __str__(self):
        return repr(self.code)
