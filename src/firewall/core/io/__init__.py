# -*- coding: utf-8 -*-
#
# Copyright (C) 2012 Red Hat, Inc.
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

# fix xmlplus to be compatible with the python xml sax parser and python 3
# by adding __contains__ to xml.sax.xmlreader.AttributesImpl
import xml
if "_xmlplus" in xml.__file__:
    from xml.sax.xmlreader import AttributesImpl
    if not hasattr(AttributesImpl, "__contains__"):
        # this is missing:
        def __AttributesImpl__contains__(self, name):
            return name in getattr(self, "_attrs")
        # add it using the name __contains__
        setattr(AttributesImpl, "__contains__", __AttributesImpl__contains__)
    from xml.sax.saxutils import XMLGenerator
    if not hasattr(XMLGenerator, "_write"):
        # this is missing:
        def __XMLGenerator_write(self, text):
            getattr(self, "_out").write(text)
        # add it using the name _write
        setattr(XMLGenerator, "_write", __XMLGenerator_write)
