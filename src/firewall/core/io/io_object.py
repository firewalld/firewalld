# -*- coding: utf-8 -*-
#
# Copyright (C) 2011-2016 Red Hat, Inc.
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

"""Generic io_object handler, io specific check methods."""

__all__ = [ "PY2",
            "IO_Object", "IO_Object_ContentHandler", "IO_Object_XMLGenerator",
            "check_port", "check_tcpudp", "check_protocol", "check_address" ]

import xml.sax as sax
import xml.sax.saxutils as saxutils
import copy
import sys

from firewall import functions
from firewall.functions import b2u
from firewall import errors
from firewall.errors import FirewallError

PY2 = sys.version < '3'

class IO_Object(object):
    """ Abstract IO_Object as base for icmptype, service and zone """

    IMPORT_EXPORT_STRUCTURE = ( )
    DBUS_SIGNATURE = '()'
    ADDITIONAL_ALNUM_CHARS = [ ] # additional to alnum
    PARSER_REQUIRED_ELEMENT_ATTRS = { }
    PARSER_OPTIONAL_ELEMENT_ATTRS = { }

    def __init__(self):
        self.filename = ""
        self.path = ""
        self.name = ""
        self.default = False
        self.builtin = False

    def export_config(self):
        ret = [ ]
        for x in self.IMPORT_EXPORT_STRUCTURE:
            ret.append(copy.deepcopy(getattr(self, x[0])))
        return tuple(ret)

    def import_config(self, conf):
        self.check_config(conf)
        for i,(element,dummy) in enumerate(self.IMPORT_EXPORT_STRUCTURE):
            if isinstance(conf[i], list):
                # remove duplicates without changing the order
                _conf = [ ]
                _set = set()
                for x in conf[i]:
                    if x not in _set:
                        _conf.append(x)
                        _set.add(x)
                del _set
                setattr(self, element, copy.deepcopy(_conf))
            else:
                setattr(self, element, copy.deepcopy(conf[i]))

    def check_name(self, name):
        if not isinstance(name, str):
            raise FirewallError(errors.INVALID_TYPE,
                                "'%s' not of type %s, but %s" % (name, type(""),
                                                                 type(name)))
        if len(name) < 1:
            raise FirewallError(errors.INVALID_NAME, "name can't be empty")
        for char in name:
            if not char.isalnum() and char not in self.ADDITIONAL_ALNUM_CHARS:
                raise FirewallError(
                    errors.INVALID_NAME,
                    "'%s' is not allowed in '%s'" % ((char, name)))

    def check_config(self, conf):
        if len(conf) != len(self.IMPORT_EXPORT_STRUCTURE):
            raise FirewallError(
                errors.INVALID_TYPE,
                "structure size mismatch %d != %d" % \
                (len(conf), len(self.IMPORT_EXPORT_STRUCTURE)))
        for i,(element,value) in enumerate(self.IMPORT_EXPORT_STRUCTURE):
            self._check_config_structure(conf[i], value)
            self._check_config(conf[i], element)

    def _check_config(self, dummy1, dummy2):
        # to be overloaded by sub classes
        return

    def _check_config_structure(self, conf, structure):
        if not type(conf) == type(structure):
            raise FirewallError(errors.INVALID_TYPE,
                                "'%s' not of type %s, but %s" % \
                                (conf, type(structure), type(conf)))
        if isinstance(structure, list):
            # same type elements, else struct
            if len(structure) != 1:
                raise FirewallError(errors.INVALID_TYPE,
                                    "len('%s') != 1" % structure)
            for x in conf:
                self._check_config_structure(x, structure[0])
        elif isinstance(structure, tuple):
            if len(structure) != len(conf):
                raise FirewallError(errors.INVALID_TYPE,
                                    "len('%s') != %d" % (conf,
                                                         len(structure)))
            for i,value in enumerate(structure):
                self._check_config_structure(conf[i], value)
        elif isinstance(structure, dict):
            # only one key value pair in structure
            (skey, svalue) = list(structure.items())[0]
            for (key, value) in conf.items():
                if type(key) != type(skey):
                    raise FirewallError(errors.INVALID_TYPE,
                                        "'%s' not of type %s, but %s" % (\
                            key, type(skey), type(key)))
                if type(value) != type(svalue):
                    raise FirewallError(errors.INVALID_TYPE,
                                        "'%s' not of type %s, but %s" % (\
                            value, type(svalue), type(value)))

    # check required elements and attributes and also optional attributes
    def parser_check_element_attrs(self, name, attrs):
        _attrs = attrs.getNames()

        found = False
        if name in self.PARSER_REQUIRED_ELEMENT_ATTRS:
            found = True
            if self.PARSER_REQUIRED_ELEMENT_ATTRS[name] is not None:
                for x in self.PARSER_REQUIRED_ELEMENT_ATTRS[name]:
                    if x in _attrs:
                        _attrs.remove(x)
                    else:
                        raise FirewallError(
                            errors.PARSE_ERROR,
                            "Missing attribute %s for %s" % (x, name))
        if name in self.PARSER_OPTIONAL_ELEMENT_ATTRS:
            found = True
            for x in self.PARSER_OPTIONAL_ELEMENT_ATTRS[name]:
                if x in _attrs:
                    _attrs.remove(x)
        if not found:
            raise FirewallError(errors.PARSE_ERROR,
                                "Unexpected element %s" % name)
        # raise attributes[0]
        for x in _attrs:
            raise FirewallError(errors.PARSE_ERROR,
                                "%s: Unexpected attribute %s" % (name, x))

# PARSER

class UnexpectedElementError(Exception):
    def __init__(self, name):
        super(UnexpectedElementError, self).__init__()
        self.name = name
    def __str__(self):
        return "Unexpected element '%s'" % (self.name)

class MissingAttributeError(Exception):
    def __init__(self, name, attribute):
        super(MissingAttributeError, self).__init__()
        self.name = name
        self.attribute = attribute
    def __str__(self):
        return "Element '%s': missing '%s' attribute" % \
            (self.name, self.attribute)

class UnexpectedAttributeError(Exception):
    def __init__(self, name, attribute):
        super(UnexpectedAttributeError, self).__init__()
        self.name = name
        self.attribute = attribute
    def __str__(self):
        return "Element '%s': unexpected attribute '%s'" % \
            (self.name, self.attribute)

class IO_Object_ContentHandler(sax.handler.ContentHandler):
    def __init__(self, item):
        self.item = item
        self._element = ""

    def startDocument(self):
        self._element = ""

    def startElement(self, name, attrs):
        self._element = ""

    def endElement(self, name):
        if name == "short":
            self.item.short = self._element
        elif name == "description":
            self.item.description = self._element

    def characters(self, content):
        self._element += content.replace('\n', ' ')

class IO_Object_XMLGenerator(saxutils.XMLGenerator):
    def __init__(self, out):
        # fix memory leak in saxutils.XMLGenerator.__init__:
        #   out = _gettextwriter(out, encoding)
        # creates unbound object results in garbage in gc
        #
        # saxutils.XMLGenerator.__init__(self, out, "utf-8")
        #   replaced by modified saxutils.XMLGenerator.__init__ code:
        sax.handler.ContentHandler.__init__(self)
        self._write = out.write
        self._flush = out.flush
        self._ns_contexts = [{}] # contains uri -> prefix dicts
        self._current_context = self._ns_contexts[-1]
        self._undeclared_ns_maps = []
        self._encoding = "utf-8"
        self._pending_start_element = False
        self._short_empty_elements = False

    def startElement(self, name, attrs):
        """ saxutils.XMLGenerator.startElement() expects name and attrs to be
            unicode and bad things happen if any of them is (utf-8) encoded.
            We override the method here to sanitize this case.
            Can be removed once we drop Python2 support.
        """
        if PY2:
            attrs = { b2u(name):b2u(value) for name, value in attrs.items() }
        saxutils.XMLGenerator.startElement(self, name, attrs)

    def simpleElement(self, name, attrs):
        """ slightly modified startElement()
        """
        if PY2:
            self._write(u'<' + b2u(name))
            for (name, value) in attrs.items():
                self._write(u' %s=%s' % (b2u(name),
                                         saxutils.quoteattr(b2u(value))))
            self._write(u'/>')
        else:
            self._write('<' + name)
            for (name, value) in attrs.items():
                self._write(' %s=%s' % (name, saxutils.quoteattr(value)))
            self._write('/>')

    def endElement(self, name):
        """ saxutils.XMLGenerator.endElement() expects name to be
            unicode and bad things happen if it's (utf-8) encoded.
            We override the method here to sanitize this case.
            Can be removed once we drop Python2 support.
        """
        saxutils.XMLGenerator.endElement(self, b2u(name))

    def characters(self, content):
        """ saxutils.XMLGenerator.characters() expects content to be
            unicode and bad things happen if it's (utf-8) encoded.
            We override the method here to sanitize this case.
            Can be removed once we drop Python2 support.
        """
        saxutils.XMLGenerator.characters(self, b2u(content))

    def ignorableWhitespace(self, content):
        """ saxutils.XMLGenerator.ignorableWhitespace() expects content to be
            unicode and bad things happen if it's (utf-8) encoded.
            We override the method here to sanitize this case.
            Can be removed once we drop Python2 support.
        """
        saxutils.XMLGenerator.ignorableWhitespace(self, b2u(content))

def check_port(port):
    port_range = functions.getPortRange(port)
    if port_range == -2:
        raise FirewallError(errors.INVALID_PORT,
                            "port number in '%s' is too big" % port)
    elif port_range == -1:
        raise FirewallError(errors.INVALID_PORT,
                            "'%s' is invalid port range" % port)
    elif port_range is None:
        raise FirewallError(errors.INVALID_PORT,
                            "port range '%s' is ambiguous" % port)
    elif len(port_range) == 2 and port_range[0] >= port_range[1]:
        raise FirewallError(errors.INVALID_PORT,
                            "'%s' is invalid port range" % port)

def check_tcpudp(protocol):
    if protocol not in [ "tcp", "udp", "sctp", "dccp" ]:
        raise FirewallError(errors.INVALID_PROTOCOL,
                            "'%s' not from {'tcp'|'udp'|'sctp'|'dccp'}" % \
                            protocol)

def check_protocol(protocol):
    if not functions.checkProtocol(protocol):
        raise FirewallError(errors.INVALID_PROTOCOL, protocol)

def check_address(ipv, addr):
    if not functions.check_address(ipv, addr):
        raise FirewallError(errors.INVALID_ADDR,
                            "'%s' is not valid %s address" % (addr, ipv))

