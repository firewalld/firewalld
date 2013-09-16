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
# signal handling and run_server derived from setroubleshoot
# Copyright (C) 2006,2007,2008,2009 Red Hat, Inc.
# Authors:
#   John Dennis <jdennis@redhat.com>
#   Thomas Liu  <tliu@redhat.com>
#   Dan Walsh <dwalsh@redhat.com>

import os, sys
import signal

# force use of pygobject3 in python-slip
from gi.repository import GObject, GLib
sys.modules['gobject'] = GObject

import dbus
import dbus.service
import dbus.mainloop.glib
import slip.dbus

from firewall.config.dbus import *
from firewall.core.logger import log
from firewall.server.firewalld import FirewallD

############################################################################
#
# signal handlers
#
############################################################################

def sighup(data):
    os.system("firewall-cmd --reload &")

def sigterm(mainloop):
    mainloop.quit()

############################################################################
#
# run_server function
#
############################################################################

def run_server():
    """ Main function for firewall server. Handles D-BUS and GLib mainloop.
    """
    service = None

    try:
        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        bus = dbus.SystemBus()
        name = dbus.service.BusName(DBUS_INTERFACE, bus=bus)
        service = FirewallD(name, DBUS_PATH)

        mainloop = GLib.MainLoop()
        slip.dbus.service.set_mainloop(mainloop)

        # use unix_signal_add if available, else unix_signal_add_full
        if hasattr(GLib, 'unix_signal_add'):
            unix_signal_add = GLib.unix_signal_add
        else:
            unix_signal_add = GLib.unix_signal_add_full

        unix_signal_add(GLib.PRIORITY_HIGH, signal.SIGHUP,
                        sighup, None)
        unix_signal_add(GLib.PRIORITY_HIGH, signal.SIGTERM,
                        sigterm, mainloop)

        mainloop.run()

    except KeyboardInterrupt as e:
        log.info1("Stopping..")

    except SystemExit as e:
        log.error("Raising SystemExit in run_server")

    except Exception as e:
        log.error("Exception %s: %s", e.__class__.__name__, str(e))

    if service:
        service.stop()
