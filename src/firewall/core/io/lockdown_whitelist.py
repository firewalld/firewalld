# -*- coding: utf-8 -*-
#
# Copyright (C) 2011-2013 Red Hat, Inc.
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

import xml.sax as sax
import os
import shutil

from firewall.config import _
from firewall.errors import *
from firewall.core.io.io_object import *
from firewall.core.logger import log
from firewall.functions import uniqify

class lockdown_whitelist_ContentHandler(IO_Object_ContentHandler):
    def __init__(self, item):
        IO_Object_ContentHandler.__init__(self, item)
        self.whitelist = False

    def startElement(self, name, attrs):
        self.item.parser_check_element_attrs(name, attrs)

        if name == "whitelist":
            if self.whitelist:
                raise FirewallError(PARSE_ERROR, "More than one whitelist.")
            self.whitelist = True

        elif name == "command":
            if not self.whitelist:
                log.error("Parse Error: command outside of whitelist")
                return
            command = str(attrs["name"])
            self.item.add_command(command)

        elif name == "user":
            if not self.whitelist:
                log.error("Parse Error: user outside of whitelist")
                return
            if "id" in attrs:
                try:
                    uid = int(str(attrs["id"]))
                except:
                    log.error("Parse Error: %s is not a valid uid" % 
                              attrs["id"])
                    return
                self.item.add_uid(uid)
            elif "name" in attrs:
                self.item.add_user(str(attrs["name"]))

        elif name == "selinux":
            if not self.whitelist:
                log.error("Parse Error: selinux outside of whitelist")
                return
            if not "context" in attrs:
                log.error("Parse Error: no context")
                return
            self.item.add_context(str(attrs["context"]))
            

        else:
            log.error('Unknown XML element %s' % name)
            return

class LockdownWhitelist(IO_Object):
    """ LockdownWhitelist class """

    IMPORT_EXPORT_STRUCTURE = (
        )
    DBUS_SIGNATURE = '()'
    ADDITIONAL_ALNUM_CHARS = [ "_" ]
    PARSER_REQUIRED_ELEMENT_ATTRS = {
        "whitelist": None,
        "command": [ "name" ],
        "user": None,
#        "group": None,
        "selinux": [ "context" ],
        }
    PARSER_OPTIONAL_ELEMENT_ATTRS = {
        "user": [ "id", "name" ],
        "group": [ "id", "name" ],
        }

    def __init__(self, filename):
        super(LockdownWhitelist, self).__init__()
        self.filename = filename
        self.clear()

    def _check_config(self, config, item):
        pass

    def clear(self):
        self._commands = [ ]
        self._uids = [ ]
        self._users = [ ]
        self._contexts = [ ]

    # commands

    def add_command(self, command):
        if command not in self._commands:
            self._commands.append(command)

    def remove_command(self, command):
        if command in self._commands:
            self._commands.remove(command)
        else:
            raise ValueError, 'Command "%s" not in whitelist.' % command

    def has_command(self, command):
        return (command in self._commands)

    def match_command(self, command):
        for _command in self._commands:
            if _command.endswith("*"):
                if command.startswith(_command[:-1]):
                    return True
            else:
                if _command == command:
                    return True
        return False

    def get_commands(self):
        return self._commands

    # user ids

    def add_uid(self, uid):
        if uid not in self._uids:
            self._uids.append(uid)

    def remove_uid(self, uid):
        if uid in self._uids:
            self._uids.remove(uid)
        else:
            raise ValueError, 'Uid "%s" not in whitelist.' % uid

    def has_uid(self, uid):
        return (uid in self._uids)

    def match_uid(self, uid):
        return (uid in self._uids)

    def get_uids(self):
        return self._uids

    # users

    def add_user(self, user):
        if user not in self._users:
            self._users.append(user)

    def remove_user(self, user):
        if user in self._users:
            self._users.remove(user)
        else:
            raise ValueError, 'User "%s" not in whitelist.' % user

    def has_user(self, user):
        return (user in self._users)

    def match_user(self, user):
        return (user in self._users)

    def get_users(self):
        return self._users

    # selinux contexts

    def add_context(self, context):
        if context not in self._contexts:
            self._contexts.append(context)

    def remove_context(self, context):
        if context in self._contexts:
            self._contexts.remove(context)
        else:
            raise ValueError, 'Context "%s" not in whitelist.' % context

    def has_context(self, context):
        return (context in self._contexts)

    def match_context(self, context):
        return (context in self._contexts)

    def get_contexts(self):
        return self._contexts

    # read and write

    def read(self):
        self.clear()
        if not self.filename.endswith(".xml"):
            raise FirewallError(INVALID_NAME, self.filename)
        handler = lockdown_whitelist_ContentHandler(self)
        parser = sax.make_parser()
        parser.setContentHandler(handler)
        parser.parse(self.filename)

    def write(self):
        if os.path.exists(self.filename):
            try:
                shutil.copy2(self.filename, "%s.old" % self.filename)
            except Exception, msg:
                raise IOError, "Backup of '%s' failed: %s" % (self.filename,
                                                              msg)

        fd = open(self.filename, "w")
        handler = IO_Object_XMLGenerator(fd)
        handler.startDocument()

        # start whitelist element
        handler.startElement("whitelist", { })
        handler.ignorableWhitespace("\n")

        # commands
        for command in uniqify(self._commands):
            handler.ignorableWhitespace("  ")
            handler.simpleElement("command", { "name": command })
            handler.ignorableWhitespace("\n")

        for uid in uniqify(self._uids):
            handler.ignorableWhitespace("  ")
            handler.simpleElement("user", { "id": str(uid) })
            handler.ignorableWhitespace("\n")

        for user in uniqify(self._users):
            handler.ignorableWhitespace("  ")
            handler.simpleElement("user", { "name": user })
            handler.ignorableWhitespace("\n")

        for context in uniqify(self._contexts):
            handler.ignorableWhitespace("  ")
            handler.simpleElement("selinux", { "context": context })
            handler.ignorableWhitespace("\n")

        # end whitelist element
        handler.endElement("whitelist")
        handler.ignorableWhitespace("\n")
        handler.endDocument()
        fd.close()
