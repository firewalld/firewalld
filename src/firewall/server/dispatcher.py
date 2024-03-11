# SPDX-License-Identifier: GPL-2.0-or-later

import os
import subprocess

from firewall.core.logger import log
from firewall.config import FIREWALLD_DISPATCHER, ETC_FIREWALLD_DISPATCHER, COMMANDS


def run_dispatcher(interface, signal, args):
    def _dispatchers(directories):
        for directory in directories:
            if not os.path.isdir(directory):
                continue
            for file in os.listdir(directory):
                _path = os.path.abspath(directory + os.sep + file)
                if os.path.isfile(_path) and os.access(_path, os.X_OK):
                    yield _path

    env = {"LANG": "C"}
    prog_args1 = [COMMANDS["systemd-run"], "--no-block", "--property", "TimeoutSec=60"]
    prog_args2 = [interface, signal] + [str(a) for a in args]

    for file in _dispatchers([FIREWALLD_DISPATCHER, ETC_FIREWALLD_DISPATCHER]):
        try:
            subprocess.Popen(
                prog_args1 + [file] + prog_args2,
                stdin=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                close_fds=True,
                env=env,
            )
        except OSError:
            log.debug1(f"Failed to call dispatcher: {file}.")
            pass
