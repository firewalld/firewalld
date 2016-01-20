# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Red Hat, Inc.
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

import os.path

from firewall.core.prog import runProg
from firewall.core.logger import log
from firewall.functions import tempFile, readfile
from firewall.config import COMMANDS

IPSET_MAXNAMELEN = 32
IPSET_TYPES = [
    # bitmap and set types are currently not supported
    # "bitmap:ip",
    # "bitmap:ip,mac",
    # "bitmap:port",
    # "list:set",

    "hash:ip",
    #"hash:ip,port",
    #"hash:ip,port,ip",
    #"hash:ip,port,net",
    #"hash:ip,mark",

    "hash:net",
    #"hash:net,net",
    #"hash:net,port",
    #"hash:net,port,net",
    #"hash:net,iface",

    "hash:mac",
]
IPSET_CREATE_OPTIONS = {
    "family": "inet|inet6",
    "hashsize": "value",
    "maxelem": "value",
    "timeout": "value in secs",
#    "counters": None,
#    "comment": None,
}

class ipset:
    def __init__(self):
        self._command = COMMANDS["ipset"]

    def __run(self, args):
        # convert to string list
        _args = ["%s" % item for item in args]
        log.debug2("%s: %s %s", self.__class__, self._command, " ".join(_args))
        (status, ret) = runProg(self._command, _args)
        if status != 0:
            raise ValueError("'%s %s' failed: %s" % (self._command,
                                                     " ".join(_args), ret))
        return ret

    def check_name(self, name):
        if len(name) > IPSET_MAXNAMELEN:
            raise FirewallError(INVALID_NAME,
                                "ipset name '%s' is not valid" % name)

    def supported_types(self):
        ret = { }
        output = ""
        try:
            output = self.__run(["--help"])
        except ValueError as e:
            log.debug1("ipset error: %s" % e)
        lines = output.splitlines()

        in_types = False
        for line in lines:
            #print(line)
            if in_types:
                splits = line.strip().split(None, 2)
                ret[splits[0]] = splits[2]
            if line.startswith("Supported set types:"):
                in_types = True
        return ret

    def check_type(self, type_name):
        if len(type_name) > IPSET_MAXNAMELEN or type_name not in IPSET_TYPES:
            raise FirewallError(INVALID_TYPE,
                                "ipset type name '%s' is not valid" % type_name)

    def create(self, set_name, type_name, options=None):
        self.check_name(set_name)
        self.check_type(type_name)

        args = [ "create", set_name, type_name ]
        if options:
            for k,v in options.items():
                args.append(k)
                if v != "":
                    args.append(v)
        return self.__run(args)

    def destroy(self, set_name):
        self.check_name(set_name)
        return self.__run([ "destroy", set_name ])

    def add(self, set_name, entry, options=None):
        args = [ "add", set_name, entry ]
        if options:
            args.append("%s" % " ".join(options))
        return self.__run(args)

    def delete(self, set_name, entry, options=None):
        args = [ "del", set_name, entry ]
        if options:
            args.append("%s" % " ".join(options))
        return self.__run(args)

    def test(self, set_name, entry, options=None):
        args = [ "test", set_name, entry ]
        if options:
            args.append("%s" % " ".join(options))
        return self.__run(args)

    def list(self, set_name=None):
        args = [ "list" ]
        if set_name:
            args.append(set_name)
        return self.__run(args).split()

    def save(self, set_name=None):
        args = [ "save" ]
        if set_name:
            args.append(set_name)
        return self.__run(args)

    def restore(self, set_name, type_name, entries,
                create_options=None, entry_options=None):
        self.check_name(set_name)
        self.check_type(type_name)

        temp_file = tempFile()

        if ' ' in set_name:
            set_name = "'%s'" % set_name
        args = [ "create", set_name, type_name, "-exist" ]
        if create_options:
            for k,v in create_options.items():
                args.append(k)
                if v != "":
                    args.append(v)
        temp_file.write("%s\n" % " ".join(args))

        for entry in entries:
            if ' ' in entry:
                entry = "'%s'" % entry
            if entry_options:
                temp_file.write("add %s %s %s\n" % (set_name, entry,
                                                    " ".join(entry_options)))
            else:
                temp_file.write("add %s %s\n" % (set_name, entry))
        temp_file.close()

        stat = os.stat(temp_file.name)
        log.debug2("%s: %s restore %s", self.__class__, self._command,
                   "%s: %d" % (temp_file.name, stat.st_size))

        args = [ "restore" ]
        (status, ret) = runProg(self._command, args,
                                stdin=temp_file.name)

        if log.getDebugLogLevel() > 2:
            try:
                lines = readfile(temp_file.name)
            except:
                pass
            else:
                i = 1
                for line in readfile(temp_file.name):
                    log.debug3("%8d: %s" % (i, line), nofmt=1, nl=0)
                    if not line.endswith("\n"):
                        log.debug3("", nofmt=1)
                    i += 1

        os.unlink(temp_file.name)

        if status != 0:
            raise ValueError("'%s %s' failed: %s" % (self._command,
                                                     " ".join(args), ret))
        return ret

    def flush(self, set_name):
        args = [ "flush" ]
        if set_name:
            args.append(set_name)
        return self.__run(args)

    def rename(self, old_set_name, new_set_name):
        return self.__run([ "rename", old_set_name, new_set_name ])

    def swap(self, set_name_1, set_name_2):
        return self.__run([ "swap", set_name_1, set_name_2 ])

    def version(self):
        return self.__run([ "version" ])


def check_ipset_name(self, ipset):
    if len(ipset) > IPSET_MAXNAMELEN:
        return False
    return True
