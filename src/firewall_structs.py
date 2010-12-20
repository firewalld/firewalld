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

import dbus

class Struct:
    _args = [ ]
    _values = [ ]

    def __init__(self, *args, **kwargs):
        if len(args) > 0:
#            if len(self._args) != len(args):
#                raise LookupError, "size does not match"
            for i in xrange(len(args)):
                self._values[i] = args[i]
        for key in kwargs:
            setattr(self, key, kwargs[key])


    def __setattr__(self, attr, value):
        if attr not in self._args:
            raise AttributeError, "Attribute %s not allowed" % attr
        i = self._args.index(attr)
        self._values[i] = value

    def __getattr__(self, attr):
        if attr not in self._args:
            raise AttributeError, "Attribute %s not allowed" % attr
        i = self._args.index(attr)
        return self._values[i]

    def __delattr__(self, name):
        raise AttributeError, "Can't delete attributes from %s" % \
            (self.__class__.__name__)

    def toDBUS(self):
        return dbus.Struct(self._values)

    def fromDBUS(self, dbus_struct):
        if len(self._args) != len(dbus_struct):
            raise TypeError, "size mismatch"
        
        for i in xrange(len(dbus_struct)):
            self._values[i] = dbus_struct[i]

    def __str__(self):
        s = [ ]
        for val in self._values:
            s.append(str(val))
        return "%s(%s)" % (self.__class__.__name__, ",".join(s))

class ServiceStruct(Struct):
    _args = [ "service", "timeout" ]
    _values = [ None, 0 ]

class PortStruct(Struct):
    _args = [ "port", "protocol", "timeout" ]
    _values = [ None, None, 0 ]

class PortRangeStruct(Struct):
    _args = [ "start", "end", "protocol", "timeout" ]
    _values = [ None, None, None, 0 ]

a = ServiceStruct("ssh")
print a
a.service = "ipp-client"
print a
a.timeout = 10
print a
dbus_struct = a.toDBUS()
print dbus_struct

b = ServiceStruct()
b.fromDBUS(dbus_struct)
print b

c = PortStruct()
print c
dbus_struct = c.toDBUS()
print dbus_struct
c.fromDBUS(dbus_struct)
print c
