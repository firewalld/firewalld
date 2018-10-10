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

"""Functions to search for and change ifcfg files"""

__all__ = [ "search_ifcfg_of_interface", "ifcfg_set_zone_of_interface" ]

import os
import os.path

from firewall import config
from firewall.core.logger import log
from firewall.core.io.ifcfg import ifcfg

def search_ifcfg_of_interface(interface):
    """search ifcfg file for the interface in config.IFCFGDIR"""

    # Return quickly if config.IFCFGDIR does not exist
    if not os.path.exists(config.IFCFGDIR):
        return None

    for filename in sorted(os.listdir(config.IFCFGDIR)):
        if not filename.startswith("ifcfg-"):
            continue
        for ignored in [ ".bak", ".orig", ".rpmnew", ".rpmorig", ".rpmsave",
                         "-range" ]:
            if filename.endswith(ignored):
                continue
        if "." in filename:
            continue
        ifcfg_file = ifcfg("%s/%s" % (config.IFCFGDIR, filename))
        ifcfg_file.read()
        if ifcfg_file.get("DEVICE") == interface:
            return ifcfg_file

    # Wasn't found above, so assume filename matches the device we want
    filename = "%s/ifcfg-%s" % (config.IFCFGDIR, interface)
    if os.path.exists(filename):
        ifcfg_file = ifcfg(filename)
        ifcfg_file.read()
        return ifcfg_file

    return None

def ifcfg_set_zone_of_interface(zone, interface):
    """Set zone (ZONE=<zone>) in the ifcfg file that uses the interface
    (DEVICE=<interface>)"""

    if zone is None:
        zone = ""

    ifcfg_file = search_ifcfg_of_interface(interface)
    if ifcfg_file is not None and ifcfg_file.get("ZONE") != zone and not \
       (ifcfg_file.get("ZONE") is None and zone == ""):
        log.debug1("Setting ZONE=%s in '%s'" % (zone, ifcfg_file.filename))
        ifcfg_file.set("ZONE", zone)
        ifcfg_file.write()
