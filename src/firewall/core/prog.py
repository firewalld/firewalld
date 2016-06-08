# -*- coding: utf-8 -*-
#
# Copyright (C) 2010-2016 Red Hat, Inc.
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

__all__ = [ "runProg" ]

import os
import resource # Resource usage information.

maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
if maxfd == resource.RLIM_INFINITY:
    maxfd = 1024

def runProg(prog, argv=None, stdin=None):
    if argv is None:
        argv = [ ]

    args = [ prog ] + argv

    (rfd, wfd) = os.pipe()
    pid = os.fork()
    if pid == 0:

        # Iterate through and close all file descriptors.
        for fd in range(0, maxfd):
            if fd == wfd: # Do not close write end of pipe
                continue
            try:
                os.close(fd)
            except OSError:
                # ERROR, fd wasn't open to begin with (ignored)
                pass

        try:
            if stdin is not None:
                fd = os.open(stdin, os.O_RDONLY)
            else:
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
            # The use of os._exit is needed here, sys.exit is not an option
            os._exit(255) # pylint: disable=W0212
    os.close(wfd)

    cret = b''
    cout = os.read(rfd, 8192)
    while cout:
        cret += cout
        cout = os.read(rfd, 8192)
    os.close(rfd)
    (dummy, status) = os.waitpid(pid, 0)

    cret = cret.rstrip().decode('utf-8', 'replace')
    return (status, cret)
