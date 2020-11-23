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

import xml.sax as sax
import os
import io
import shutil

from firewall import config
from firewall.core.io.io_object import IO_Object, \
                    IO_Object_ContentHandler, IO_Object_XMLGenerator
from firewall.core.logger import log
from firewall.functions import uniqify, checkUser, checkUid, checkCommand, \
                               checkContext
from firewall import errors
from firewall.errors import FirewallError

class lockdown_whitelist_ContentHandler(IO_Object_ContentHandler):
    def __init__(self, item):
        IO_Object_ContentHandler.__init__(self, item)
        self.whitelist = False

    def startElement(self, name, attrs):
        IO_Object_ContentHandler.startElement(self, name, attrs)
        self.item.parser_check_element_attrs(name, attrs)

        if name == "whitelist":
            if self.whitelist:
                raise FirewallError(errors.PARSE_ERROR,
                                    "More than one whitelist.")
            self.whitelist = True

        elif name == "command":
            if not self.whitelist:
                log.error("Parse Error: command outside of whitelist")
                return
            command = attrs["name"]
            self.item.add_command(command)

        elif name == "user":
            if not self.whitelist:
                log.error("Parse Error: user outside of whitelist")
                return
            if "id" in attrs:
                try:
                    uid = int(attrs["id"])
                except ValueError:
                    log.error("Parse Error: %s is not a valid uid" % 
                              attrs["id"])
                    return
                self.item.add_uid(uid)
            elif "name" in attrs:
                self.item.add_user(attrs["name"])

        elif name == "selinux":
            if not self.whitelist:
                log.error("Parse Error: selinux outside of whitelist")
                return
            if "context" not in attrs:
                log.error("Parse Error: no context")
                return
            self.item.add_context(attrs["context"])
            

        else:
            log.error('Unknown XML element %s' % name)
            return

class LockdownWhitelist(IO_Object):
    """ LockdownWhitelist class """

    IMPORT_EXPORT_STRUCTURE = (
        ( "commands", [ "" ] ),   # as
        ( "contexts", [ "" ] ),   # as
        ( "users", [ "" ] ),      # as
        ( "uids", [ 0 ] )         # ai
        )
    DBUS_SIGNATURE = '(asasasai)'
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
#        "group": [ "id", "name" ],
        }

    def __init__(self, filename):
        super(LockdownWhitelist, self).__init__()
        self.filename = filename
        self.parser = None
        self.commands = [ ]
        self.contexts = [ ]
        self.users = [ ]
        self.uids = [ ]
#        self.gids = [ ]
#        self.groups = [ ]

    def _check_config(self, config, item, all_config):
        if item in [ "commands", "contexts", "users", "uids" ]:
            for x in config:
                self._check_config(x, item[:-1], all_config)
        elif item == "command":
            if not checkCommand(config):
                raise FirewallError(errors.INVALID_COMMAND, config)
        elif item == "context":
            if not checkContext(config):
                raise FirewallError(errors.INVALID_CONTEXT, config)
        elif item == "user":
            if not checkUser(config):
                raise FirewallError(errors.INVALID_USER, config)
        elif item == "uid":
            if not checkUid(config):
                raise FirewallError(errors.INVALID_UID, config)

    def cleanup(self):
        del self.commands[:]
        del self.contexts[:]
        del self.users[:]
        del self.uids[:]
#        del self.gids[:]
#        del self.groups[:]

    # commands

    def add_command(self, command):
        if not checkCommand(command):
            raise FirewallError(errors.INVALID_COMMAND, command)
        if command not in self.commands:
            self.commands.append(command)
        else:
            raise FirewallError(errors.ALREADY_ENABLED,
                                'Command "%s" already in whitelist' % command)

    def remove_command(self, command):
        if command in self.commands:
            self.commands.remove(command)
        else:
            raise FirewallError(errors.NOT_ENABLED,
                                'Command "%s" not in whitelist.' % command)

    def has_command(self, command):
        return (command in self.commands)

    def match_command(self, command):
        for _command in self.commands:
            if _command.endswith("*"):
                if command.startswith(_command[:-1]):
                    return True
            else:
                if _command == command:
                    return True
        return False

    def get_commands(self):
        return self.commands

    # user ids

    def add_uid(self, uid):
        if not checkUid(uid):
            raise FirewallError(errors.INVALID_UID, str(uid))
        if uid not in self.uids:
            self.uids.append(uid)
        else:
            raise FirewallError(errors.ALREADY_ENABLED,
                                'Uid "%s" already in whitelist' % uid)


    def remove_uid(self, uid):
        if uid in self.uids:
            self.uids.remove(uid)
        else:
            raise FirewallError(errors.NOT_ENABLED,
                                'Uid "%s" not in whitelist.' % uid)

    def has_uid(self, uid):
        return (uid in self.uids)

    def match_uid(self, uid):
        return (uid in self.uids)

    def get_uids(self):
        return self.uids

    # users

    def add_user(self, user):
        if not checkUser(user):
            raise FirewallError(errors.INVALID_USER, user)
        if user not in self.users:
            self.users.append(user)
        else:
            raise FirewallError(errors.ALREADY_ENABLED,
                                'User "%s" already in whitelist' % user)


    def remove_user(self, user):
        if user in self.users:
            self.users.remove(user)
        else:
            raise FirewallError(errors.NOT_ENABLED,
                                'User "%s" not in whitelist.' % user)

    def has_user(self, user):
        return (user in self.users)

    def match_user(self, user):
        return (user in self.users)

    def get_users(self):
        return self.users

#    # group ids
#
#    def add_gid(self, gid):
#        if gid not in self.gids:
#            self.gids.append(gid)
#
#    def remove_gid(self, gid):
#        if gid in self.gids:
#            self.gids.remove(gid)
#        else:
#            raise FirewallError(errors.NOT_ENABLED,
#                                'Gid "%s" not in whitelist.' % gid)
#
#    def has_gid(self, gid):
#        return (gid in self.gids)
#
#    def match_gid(self, gid):
#        return (gid in self.gids)
#
#    def get_gids(self):
#        return self.gids

#    # groups
#
#    def add_group(self, group):
#        if group not in self.groups:
#            self.groups.append(group)
#
#    def remove_group(self, group):
#        if group in self.groups:
#            self.groups.remove(group)
#        else:
#            raise FirewallError(errors.NOT_ENABLED,
#                                'Group "%s" not in whitelist.' % group)
#
#    def has_group(self, group):
#        return (group in self.groups)
#
#    def match_group(self, group):
#        return (group in self.groups)
#
#    def get_groups(self):
#        return self.groups

    # selinux contexts

    def add_context(self, context):
        if not checkContext(context):
            raise FirewallError(errors.INVALID_CONTEXT, context)
        if context not in self.contexts:
            self.contexts.append(context)
        else:
            raise FirewallError(errors.ALREADY_ENABLED,
                                'Context "%s" already in whitelist' % context)


    def remove_context(self, context):
        if context in self.contexts:
            self.contexts.remove(context)
        else:
            raise FirewallError(errors.NOT_ENABLED,
                                'Context "%s" not in whitelist.' % context)

    def has_context(self, context):
        return (context in self.contexts)

    def match_context(self, context):
        return (context in self.contexts)

    def get_contexts(self):
        return self.contexts

    # read and write

    def read(self):
        self.cleanup()
        if not self.filename.endswith(".xml"):
            raise FirewallError(errors.INVALID_NAME,
                                "'%s' is missing .xml suffix" % self.filename)
        handler = lockdown_whitelist_ContentHandler(self)
        parser = sax.make_parser()
        parser.setContentHandler(handler)
        try:
            parser.parse(self.filename)
        except sax.SAXParseException as msg:
            raise FirewallError(errors.INVALID_TYPE,
                                "Not a valid file: %s" % \
                                msg.getException())
        del handler
        del parser

    def write(self):
        if os.path.exists(self.filename):
            try:
                shutil.copy2(self.filename, "%s.old" % self.filename)
            except Exception as msg:
                raise IOError("Backup of '%s' failed: %s" % (self.filename, msg))

        if not os.path.exists(config.ETC_FIREWALLD):
            os.mkdir(config.ETC_FIREWALLD, 0o750)

        f = io.open(self.filename, mode='wt', encoding='UTF-8')
        handler = IO_Object_XMLGenerator(f)
        handler.startDocument()

        # start whitelist element
        handler.startElement("whitelist", { })
        handler.ignorableWhitespace("\n")

        # commands
        for command in uniqify(self.commands):
            handler.ignorableWhitespace("  ")
            handler.simpleElement("command", { "name": command })
            handler.ignorableWhitespace("\n")

        for uid in uniqify(self.uids):
            handler.ignorableWhitespace("  ")
            handler.simpleElement("user", { "id": str(uid) })
            handler.ignorableWhitespace("\n")

        for user in uniqify(self.users):
            handler.ignorableWhitespace("  ")
            handler.simpleElement("user", { "name": user })
            handler.ignorableWhitespace("\n")

#        for gid in uniqify(self.gids):
#            handler.ignorableWhitespace("  ")
#            handler.simpleElement("user", { "id": str(gid) })
#            handler.ignorableWhitespace("\n")

#        for group in uniqify(self.groups):
#            handler.ignorableWhitespace("  ")
#            handler.simpleElement("group", { "name": group })
#            handler.ignorableWhitespace("\n")

        for context in uniqify(self.contexts):
            handler.ignorableWhitespace("  ")
            handler.simpleElement("selinux", { "context": context })
            handler.ignorableWhitespace("\n")

        # end whitelist element
        handler.endElement("whitelist")
        handler.ignorableWhitespace("\n")
        handler.endDocument()
        f.close()
        del handler
