# -*- coding: utf-8 -*-
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

ALREADY_ENABLED     =   11
NOT_ENABLED         =   12
COMMAND_FAILED      =   13
NO_IPV6_NAT         =   14
PANIC_MODE          =   15
ZONE_ALREADY_SET    =   16
UNKNOWN_INTERFACE   =   17
ZONE_CONFLICT       =   18
BUILTIN_CHAIN       =   19
EBTABLES_NO_REJECT  =   20
NOT_OVERLOADABLE    =   21
NO_DEFAULTS         =   22
BUILTIN_ZONE        =   23
BUILTIN_SERVICE     =   24
BUILTIN_ICMPTYPE    =   25
NAME_CONFLICT       =   26
NAME_MISMATCH       =   27
PARSE_ERROR         =   28
ACCESS_DENIED       =   29
UNKNOWN_SOURCE      =   30
RT_TO_PERM_FAILED   =   31
IPSET_WITH_TIMEOUT  =   32
BUILTIN_IPSET       =   33
ALREADY_SET         =   34
MISSING_IMPORT      =   35
DBUS_ERROR          =   36
BUILTIN_HELPER      =   37
NOT_APPLIED         =   38

INVALID_ACTION      =  100
INVALID_SERVICE     =  101
INVALID_PORT        =  102
INVALID_PROTOCOL    =  103
INVALID_INTERFACE   =  104
INVALID_ADDR        =  105
INVALID_FORWARD     =  106
INVALID_ICMPTYPE    =  107
INVALID_TABLE       =  108
INVALID_CHAIN       =  109
INVALID_TARGET      =  110
INVALID_IPV         =  111
INVALID_ZONE        =  112
INVALID_PROPERTY    =  113
INVALID_VALUE       =  114
INVALID_OBJECT      =  115
INVALID_NAME        =  116
INVALID_FILENAME    =  117
INVALID_DIRECTORY   =  118
INVALID_TYPE        =  119
INVALID_SETTING     =  120
INVALID_DESTINATION =  121
INVALID_RULE        =  122
INVALID_LIMIT       =  123
INVALID_FAMILY      =  124
INVALID_LOG_LEVEL   =  125
INVALID_AUDIT_TYPE  =  126
INVALID_MARK        =  127
INVALID_CONTEXT     =  128
INVALID_COMMAND     =  129
INVALID_USER        =  130
INVALID_UID         =  131
INVALID_MODULE      =  132
INVALID_PASSTHROUGH =  133
INVALID_MAC         =  134
INVALID_IPSET       =  135
INVALID_ENTRY       =  136
INVALID_OPTION      =  137
INVALID_HELPER      =  138
INVALID_PRIORITY    =  139
INVALID_POLICY      =  140

MISSING_TABLE       =  200
MISSING_CHAIN       =  201
MISSING_PORT        =  202
MISSING_PROTOCOL    =  203
MISSING_ADDR        =  204
MISSING_NAME        =  205
MISSING_SETTING     =  206
MISSING_FAMILY      =  207

RUNNING_BUT_FAILED  =  251
NOT_RUNNING         =  252
NOT_AUTHORIZED      =  253
UNKNOWN_ERROR       =  254

import sys

class FirewallError(Exception):
    def __init__(self, code, msg=None):
        self.code = code
        if msg is not None:
            # escape msg if needed
            if sys.version < '3':
                try:
                    x = str(msg) # noqa: F841
                except UnicodeEncodeError:
                    msg = unicode(msg).encode("unicode_escape") # noqa: F821
        self.msg = msg

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__, self.code, self.msg)

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

        try:
            code = FirewallError.codes[ecode]
        except KeyError:
            code = UNKNOWN_ERROR

        return code

    get_code = staticmethod(get_code)

mod = sys.modules[FirewallError.__module__]
FirewallError.errors = { getattr(mod,varname) : varname
                         for varname in dir(mod)
                         if not varname.startswith("_") and \
                         type(getattr(mod,varname)) == int }
FirewallError.codes =  { FirewallError.errors[code] : code
                         for code in FirewallError.errors }
