#
# Copyright (C) 2010-2012 Red Hat, Inc.
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

from gi.repository import GObject
# fix use of gobject in python-slip, crashes in Gio use
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
# signal handler
#
############################################################################

def sighandler(signum, frame):
    """ signal handler
    """
    # reloading over dbus is not working server is not responding anymore
    # therefore using external firewall-cmd 
    if signum == signal.SIGHUP:
        os.system("firewall-cmd --reload &")
        return

    sys.exit()

############################################################################
#
# run_server function
#
############################################################################

def run_server():
    """ Main function for firewall server. Handles D-BUS and GLib mainloop.
    """
    signal.signal(signal.SIGHUP, sighandler)
    signal.signal(signal.SIGQUIT, sighandler)
    signal.signal(signal.SIGTERM, sighandler)
    signal.signal(signal.SIGALRM, sighandler)

    service = None

    try:
        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        bus = dbus.SystemBus()
        name = dbus.service.BusName(DBUS_INTERFACE, bus=bus)
        service = FirewallD(name, DBUS_PATH)

        mainloop = GObject.MainLoop()
        slip.dbus.service.set_mainloop(mainloop)
        mainloop.run()

    except KeyboardInterrupt, e:
        log.warning("KeyboardInterrupt in run_server")

    except SystemExit, e:
        log.error("Raising SystemExit in run_server")

    except Exception, e:
        log.error("Exception %s: %s", e.__class__.__name__, str(e))

    if service:
       service.stop()
