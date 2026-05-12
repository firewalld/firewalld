# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2018 Red Hat, Inc.
#
# Authors:
# Eric Garver <egarver@redhat.com>

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
from firewall.core.io.firewalld_conf import firewalld_conf


def get_config_files_in_dir(directory, conf_type):
    """
    Returns: list of tuples (directory, file)
    """
    if not os.path.isdir(directory):
        return []
    dir_file_list = []
    for file in sorted(os.listdir(directory)):
        if file.endswith(".xml"):
            dir_file_list.append((directory, file))
        # combined zones: <zone name>/foo.xml
        #                 ...
        #                 <zone name>/bar.xml
        elif conf_type == "zone" and os.path.isdir(os.path.join(directory, file)):
            dir_file_list.extend(
                get_config_files_in_dir(os.path.join(directory, file), conf_type)
            )
    return dir_file_list


def check_on_disk_config(fw):
    fw_config = FirewallConfig(fw)

    try:
        _firewalld_conf = firewalld_conf(config.FIREWALLD_CONF)
        _firewalld_conf.read()
    except FirewallError as error:
        raise FirewallError(error.code, "'%s': %s" % (config.FIREWALLD_CONF, error.msg))
    except IOError:
        # defaults will be filled
        pass
    except Exception as msg:
        raise Exception("'%s': %s" % (config.FIREWALLD_CONF, msg))
    fw_config.set_firewalld_conf(_firewalld_conf)

    readers = {
        "ipset": {
            "reader": ipset_reader,
            "add": fw_config.add_ipset,
            "dirs": [config.FIREWALLD_IPSETS, config.ETC_FIREWALLD_IPSETS],
        },
        "helper": {
            "reader": helper_reader,
            "add": fw_config.add_helper,
            "dirs": [config.FIREWALLD_HELPERS, config.ETC_FIREWALLD_HELPERS],
        },
        "icmptype": {
            "reader": icmptype_reader,
            "add": fw_config.add_icmptype,
            "dirs": [config.FIREWALLD_ICMPTYPES, config.ETC_FIREWALLD_ICMPTYPES],
        },
        "service": {
            "reader": service_reader,
            "add": fw_config.add_service,
            "dirs": [config.FIREWALLD_SERVICES, config.ETC_FIREWALLD_SERVICES],
        },
        "zone": {
            "reader": zone_reader,
            "add": fw_config.add_zone,
            "dirs": [config.FIREWALLD_ZONES, config.ETC_FIREWALLD_ZONES],
        },
        "policy": {
            "reader": policy_reader,
            "add": fw_config.add_policy_object,
            "dirs": [config.FIREWALLD_POLICIES, config.ETC_FIREWALLD_POLICIES],
        },
    }
    for reader in readers.keys():
        for _dir in readers[reader]["dirs"]:
            for directory, file in get_config_files_in_dir(_dir, reader):
                obj = readers[reader]["reader"](file, directory)
                readers[reader]["add"](obj)

    fw_config.full_check_config()

    if os.path.isfile(config.FIREWALLD_DIRECT):
        try:
            obj = Direct(config.FIREWALLD_DIRECT)
            obj.read()
            obj.check_config(obj.export_config())
        except FirewallError as error:
            raise FirewallError(
                error.code, "'%s': %s" % (config.FIREWALLD_DIRECT, error.msg)
            )
        except Exception as msg:
            raise Exception("'%s': %s" % (config.FIREWALLD_DIRECT, msg))
