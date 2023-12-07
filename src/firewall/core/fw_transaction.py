# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2016 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>

"""Transaction classes for firewalld"""

import traceback

from firewall.core.logger import log
from firewall import errors
from firewall.errors import FirewallError


class FirewallTransaction:
    def __init__(self, fw):
        self.fw = fw
        self.rules = {}  # [ ( backend.name, [ rule,.. ] ),.. ]
        self.pre_funcs = []  # [ (func, args),.. ]
        self.post_funcs = []  # [ (func, args),.. ]
        self.fail_funcs = []  # [ (func, args),.. ]
        self.modules = []  # [ module,.. ]

    def clear(self):
        self.rules.clear()
        del self.pre_funcs[:]
        del self.post_funcs[:]
        del self.fail_funcs[:]

    def add_rule(self, backend, rule):
        self.rules.setdefault(backend.name, []).append(rule)

    def add_rules(self, backend, rules):
        for rule in rules:
            self.add_rule(backend, rule)

    def query_rule(self, backend, rule):
        return backend.name in self.rules and rule in self.rules[backend.name]

    def remove_rule(self, backend, rule):
        if backend.name in self.rules and rule in self.rules[backend.name]:
            self.rules[backend.name].remove(rule)

    def add_pre(self, func, *args):
        self.pre_funcs.append((func, args))

    def add_post(self, func, *args):
        self.post_funcs.append((func, args))

    def add_fail(self, func, *args):
        self.fail_funcs.append((func, args))

    def add_module(self, module):
        if module not in self.modules:
            self.modules.append(module)

    def remove_module(self, module):
        if module in self.modules:
            self.modules.remove(module)

    def add_modules(self, modules):
        for module in modules:
            self.add_module(module)

    def remove_modules(self, modules):
        for module in modules:
            self.remove_module(module)

    def execute(self, enable):
        log.debug4("%s.execute(%s)" % (type(self), enable))

        rules = self.rules
        modules = self.modules

        # pre
        self.pre()

        # stage 1: apply rules
        error = False
        errorMsg = ""
        done = []
        for backend_name in rules:
            try:
                self.fw.rules(backend_name, rules[backend_name])
            except Exception as msg:
                error = True
                errorMsg = msg
                log.debug1(traceback.format_exc())
                log.error(msg)
            else:
                done.append(backend_name)

        # stage 2: load modules
        if not error:
            module_return = self.fw.handle_modules(modules, enable)
            if module_return:
                # Debug log about issues loading modules, but don't error. The
                # modules may be builtin or CONFIG_MODULES=n, in which case
                # modprobe will fail. Or we may be running inside a container
                # that doesn't have sufficient privileges. Unfortunately there
                # is no way for us to know.
                (status, msg) = module_return
                if status:
                    log.debug1(msg)

        if error:
            # call failure functions
            for func, args in self.fail_funcs:
                try:
                    func(*args)
                except Exception as msg:
                    log.debug1(traceback.format_exc())
                    log.error("Calling fail func %s(%s) failed: %s" % (func, args, msg))

            raise FirewallError(errors.COMMAND_FAILED, errorMsg)

        # post
        self.post()

    def pre(self):
        log.debug4("%s.pre()" % type(self))

        for func, args in self.pre_funcs:
            func(*args)

    def post(self):
        log.debug4("%s.post()" % type(self))

        for func, args in self.post_funcs:
            func(*args)
