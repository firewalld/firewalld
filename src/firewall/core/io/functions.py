# -*- coding: utf-8 -*-
#
# Copyright (C) 2018 Red Hat, Inc.
#
# Authors:
# Eric Garver <egarver@redhat.com>
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

from firewall import config
from firewall.errors import FirewallError

from firewall.core.fw_config import FirewallConfig
from firewall.core.io.zone import zone_reader
from firewall.core.io.service import service_reader
from firewall.core.io.ipset import ipset_reader
from firewall.core.io.icmptype import icmptype_reader
from firewall.core.io.helper import helper_reader
from firewall.core.io.policy import policy_reader
from firewall.core.io.direct import Direct
from firewall.core.io.lockdown_whitelist import LockdownWhitelist
from firewall.core.io.firewalld_conf import firewalld_conf

def check_config(fw):
    fw_config = FirewallConfig(fw)
    readers = {
        "ipset":    {"reader": ipset_reader,
                     "add": fw_config.add_ipset,
                     "dirs": [config.FIREWALLD_IPSETS, config.ETC_FIREWALLD_IPSETS],
                    },
        "helper":   {"reader": helper_reader,
                     "add": fw_config.add_helper,
                     "dirs": [config.FIREWALLD_HELPERS, config.ETC_FIREWALLD_HELPERS],
                    },
        "icmptype": {"reader": icmptype_reader,
                     "add": fw_config.add_icmptype,
                     "dirs": [config.FIREWALLD_ICMPTYPES, config.ETC_FIREWALLD_ICMPTYPES],
                    },
        "service":  {"reader": service_reader,
                     "add": fw_config.add_service,
                     "dirs": [config.FIREWALLD_SERVICES, config.ETC_FIREWALLD_SERVICES],
                    },
        "zone":     {"reader": zone_reader,
                     "add": fw_config.add_zone,
                     "dirs": [config.FIREWALLD_ZONES, config.ETC_FIREWALLD_ZONES],
                    },
        "policy":   {"reader": policy_reader,
                     "add": fw_config.add_policy_object,
                     "dirs": [config.FIREWALLD_POLICIES, config.ETC_FIREWALLD_POLICIES],
                    },
    }
    for reader in readers.keys():
        for _dir in readers[reader]["dirs"]:
            if not os.path.isdir(_dir):
                continue
            for file in sorted(os.listdir(_dir)):
                if file.endswith(".xml"):
                    try:
                        obj = readers[reader]["reader"](file, _dir)
                        if reader in ["zone", "policy"]:
                            obj.fw_config = fw_config
                        obj.check_config_dict(obj.export_config_dict())
                        readers[reader]["add"](obj)
                    except FirewallError as error:
                        raise FirewallError(error.code, "'%s': %s" % (file, error.msg))
                    except Exception as msg:
                        raise Exception("'%s': %s" % (file, msg))
    if os.path.isfile(config.FIREWALLD_DIRECT):
        try:
            obj = Direct(config.FIREWALLD_DIRECT)
            obj.read()
            obj.check_config(obj.export_config())
        except FirewallError as error:
            raise FirewallError(error.code, "'%s': %s" % (config.FIREWALLD_DIRECT, error.msg))
        except Exception as msg:
            raise Exception("'%s': %s" % (config.FIREWALLD_DIRECT, msg))
    if os.path.isfile(config.LOCKDOWN_WHITELIST):
        try:
            obj = LockdownWhitelist(config.LOCKDOWN_WHITELIST)
            obj.read()
            obj.check_config(obj.export_config())
        except FirewallError as error:
            raise FirewallError(error.code, "'%s': %s" % (config.LOCKDOWN_WHITELIST, error.msg))
        except Exception as msg:
            raise Exception("'%s': %s" % (config.LOCKDOWN_WHITELIST, msg))
    if os.path.isfile(config.FIREWALLD_CONF):
        try:
            obj = firewalld_conf(config.FIREWALLD_CONF)
            obj.read()
        except FirewallError as error:
            raise FirewallError(error.code, "'%s': %s" % (config.FIREWALLD_CONF, error.msg))
        except Exception as msg:
            raise Exception("'%s': %s" % (config.FIREWALLD_CONF, msg))
