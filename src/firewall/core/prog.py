# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2010-2016 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>

import subprocess


def runProg(prog, argv=None, stdin=None):
    if argv is None:
        argv = []

    args = [prog] + argv

    input_string = None
    if stdin:
        with open(stdin, "r") as handle:
            input_string = handle.read().encode()

    env = {"LANG": "C"}
    try:
        process = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdout=subprocess.PIPE,
            close_fds=True,
            env=env,
        )
    except OSError:
        return (255, "")

    (output, err_output) = process.communicate(input_string)
    output = output.decode("utf-8", "replace")
    return (process.returncode, output)
