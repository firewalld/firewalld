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

import subprocess


__all__ = ["runProg"]


def runProg(prog, argv=None, stdin=None):
    if argv is None:
        argv = []

    args = [prog] + argv

    input_string = None
    if stdin:
        with open(stdin, 'r') as handle:
            input_string = handle.read().encode()

    env = {'LANG': 'C'}
    try:
        process = subprocess.Popen(args, stdin=subprocess.PIPE,
                                   stderr=subprocess.STDOUT,
                                   stdout=subprocess.PIPE,
                                   close_fds=True, env=env)
    except OSError:
        return (255, '')

    (output, err_output) = process.communicate(input_string)
    output = output.decode('utf-8', 'replace')
    return (process.returncode, output)
