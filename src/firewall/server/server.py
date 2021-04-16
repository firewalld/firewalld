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
# signal handling and run_server derived from setroubleshoot
# Copyright (C) 2006,2007,2008,2009 Red Hat, Inc.
# Authors:
#   John Dennis <jdennis@redhat.com>
#   Thomas Liu  <tliu@redhat.com>
#   Dan Walsh <dwalsh@redhat.com>

__all__ = [ "run_server" ]

import signal

from gi.repository import GLib

import dbus
import dbus.service
import dbus.mainloop.glib

from firewall import config
from firewall.core.logger import log
from firewall.server.firewalld import FirewallD

############################################################################
#
# signal handlers
#
############################################################################

def sighup(service):
    service.reload()
    return True

def sigterm(mainloop):
    mainloop.quit()

############################################################################
#
# run_server function
#
############################################################################

def run_server(debug_gc=False):
    """ Main function for firewall server. Handles D-Bus and GLib mainloop.
    """
    service = None
    if debug_gc:
        from pprint import pformat
        import gc
        gc.enable()
        gc.set_debug(gc.DEBUG_LEAK)

        gc_timeout = 10
        def gc_collect():
            gc.collect()
            if len(gc.garbage) > 0:
                print("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
                      ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n")
                print("GARBAGE OBJECTS (%d):\n" % len(gc.garbage))
                for x in gc.garbage:
                    print(type(x), "\n  ",)
                    print(pformat(x))
                print("\n<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
                      "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n")
            GLib.timeout_add_seconds(gc_timeout, gc_collect)

    try:
        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        bus = dbus.SystemBus()
        name = dbus.service.BusName(config.dbus.DBUS_INTERFACE, bus=bus)
        service = FirewallD(name, config.dbus.DBUS_PATH)

        mainloop = GLib.MainLoop()
        if debug_gc:
            GLib.timeout_add_seconds(gc_timeout, gc_collect)

        # use unix_signal_add if available, else unix_signal_add_full
        if hasattr(GLib, 'unix_signal_add'):
            unix_signal_add = GLib.unix_signal_add
        else:
            unix_signal_add = GLib.unix_signal_add_full

        unix_signal_add(GLib.PRIORITY_HIGH, signal.SIGHUP,
                        sighup, service)
        unix_signal_add(GLib.PRIORITY_HIGH, signal.SIGTERM,
                        sigterm, mainloop)

        mainloop.run()

    except KeyboardInterrupt:
        log.debug1("Stopping..")

    except SystemExit:
        log.error("Raising SystemExit in run_server")

    except Exception as e:
        log.error("Exception %s: %s", e.__class__.__name__, str(e))

    if service:
        service.stop()
