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

import os

def runProg(prog, argv=[ ]):
    args = [ prog ] + argv

    (rfd, wfd) = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            fd = os.open("/dev/null", os.O_RDONLY)
            if fd != 0:
                os.dup2(fd, 0)
                os.close(fd)
            if wfd != 1:
                os.dup2(wfd, 1)
                os.close(wfd)
            os.dup2(1, 2)
            e = { "LANG": "C" }
            os.execve(args[0], args, e)
        finally:
            os._exit(255)
    os.close(wfd)

    cret = ""
    cout = os.read(rfd, 8192)
    while cout:
        cret += cout
        cout = os.read(rfd, 8192)
    os.close(rfd)
    (cpid, status) = os.waitpid(pid, 0)

    return (status, cret.rstrip())
