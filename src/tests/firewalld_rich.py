#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2013 Red Hat, Inc.
#
# Authors:
# Jiri Popelka <jpopelka@redhat.com>
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

# To use in git tree: PYTHONPATH=.. python firewalld-test.py

import dbus as python_dbus

from firewall.core.base import DEFAULT_ZONE_TARGET
from firewall.config import *
from firewall.config.dbus import *
from firewall.dbus_utils import dbus_to_python

bus = python_dbus.SystemBus()
dbus_obj = bus.get_object(DBUS_INTERFACE, DBUS_PATH_CONFIG)
fw = python_dbus.Interface(dbus_obj, dbus_interface=DBUS_INTERFACE)
fw_config = python_dbus.Interface(dbus_obj, dbus_interface=DBUS_INTERFACE_CONFIG)

rule = ['rule service name=ftp audit limit value="1/m" accept ',
        'rule protocol value=ah accept ',
        'rule protocol value=esp accept ']
settings = ["", "", "", False, DEFAULT_ZONE_TARGET, [], [], [], False, [], [], [], rule]
fw_config.addZone("zone1", settings)

rule = ['rule family=ipv4 source address="192.168.0.0/24" service name=tftp log prefix=tftp level=info limit value=1/m accept']
settings = ["", "", "", False, DEFAULT_ZONE_TARGET, [], [], [], False, [], [], [], rule]
fw_config.addZone("zone2", settings)

rule = ['rule family=ipv4 source not address=192.168.0.0/24 service name=dns log prefix=dns level=info limit value=2/m accept ']
settings = ["", "", "", False, DEFAULT_ZONE_TARGET, [], [], [], False, [], [], [], rule]
fw_config.addZone("zone3", settings)

rule = ['rule family=ipv6 source address=1:2:3:4:6:: service name=radius log prefix=dns level=info limit value=3/m reject limit value=20/m ']
settings = ["", "", "", False, DEFAULT_ZONE_TARGET, [], [], [], False, [], [], [], rule]
fw_config.addZone("zone4", settings)

rule = ['rule family=ipv6 source address=1:2:3:4:5:: port port=4011 protocol=tcp log prefix="port 4011/tcp" level=info limit value=4/m drop ']
settings = ["", "", "", False, DEFAULT_ZONE_TARGET, [], [], [], False, [], [], [], rule]
fw_config.addZone("zone5", settings)

rule = ['rule family=ipv6 source address=1:2:3:4:6:: forward-port port=4011 protocol=tcp to-port=4012 to-addr=1::2:3:4:7 ']
settings = ["", "", "", False, DEFAULT_ZONE_TARGET, [], [], [], False, [], [], [], rule]
fw_config.addZone("zone6", settings)

rule = ['rule family=ipv4 source address=192.168.0.0/24 icmp-block name=source-quench log level=info prefix=source-quench limit value=4/m ']
settings = ["", "", "", False, DEFAULT_ZONE_TARGET, [], [], [], False, [], [], [], rule]
fw_config.addZone("zone7", settings)

rule = ['rule family=ipv6 source address=1:2:3:4:6:: icmp-block name=redirect log prefix=redirect level=info limit value=4/m ']
settings = ["", "", "", False, DEFAULT_ZONE_TARGET, [], [], [], False, [], [], [], rule]
fw_config.addZone("zone8", settings)

rule = ['rule family=ipv4 source address=192.168.1.0/24 masquerade ',
        'rule family=ipv6 masquerade ']
settings = ["", "", "", False, DEFAULT_ZONE_TARGET, [], [], [], False, [], [], [], rule]
fw_config.addZone("zone9", settings)
