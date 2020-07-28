# -*- coding: utf-8 -*-
#
# Copyright (C) 2016 Red Hat, Inc.
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

"""Transaction classes for firewalld"""

__all__ = [ "FirewallTransaction" ]

import traceback

from firewall.core.logger import log
from firewall import errors
from firewall.errors import FirewallError

class FirewallTransaction(object):
    def __init__(self, fw):
        self.fw = fw
        self.rules = { } # [ ( backend.name, [ rule,.. ] ),.. ]
        self.pre_funcs = [ ] # [ (func, args),.. ]
        self.post_funcs = [ ] # [ (func, args),.. ]
        self.fail_funcs = [ ] # [ (func, args),.. ]
        self.modules = [ ] # [ module,.. ]

    def clear(self):
        self.rules.clear()
        del self.pre_funcs[:]
        del self.post_funcs[:]
        del self.fail_funcs[:]

    def add_rule(self, backend, rule):
        self.rules.setdefault(backend.name, [ ]).append(rule)

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

    def prepare(self, enable):
        log.debug4("%s.prepare(%s, %s)" % (type(self), enable, "..."))

        rules = { }
        if not enable:
            # reverse rule order for cleanup
            for backend_name in self.rules:
                for rule in reversed(self.rules[backend_name]):
                    rules.setdefault(backend_name, [ ]).append(
                        self.fw.get_backend_by_name(backend_name).reverse_rule(rule))
        else:
            for backend_name in self.rules:
                rules.setdefault(backend_name, [ ]).extend(self.rules[backend_name])

        return rules, self.modules

    def execute(self, enable):
        log.debug4("%s.execute(%s)" % (type(self), enable))

        rules, modules = self.prepare(enable)

        # pre
        self.pre()

        # stage 1: apply rules
        error = False
        errorMsg = ""
        done = [ ]
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

        # error case: revert rules
        if error:
            undo_rules = { }
            for backend_name in done:
                undo_rules[backend_name] = [ ]
                for rule in reversed(rules[backend_name]):
                    undo_rules[backend_name].append(
                        self.fw.get_backend_by_name(backend_name).reverse_rule(rule))
            for backend_name in undo_rules:
                try:
                    self.fw.rules(backend_name, undo_rules[backend_name])
                except Exception as msg:
                    log.debug1(traceback.format_exc())
                    log.error(msg)
            # call failure functions
            for (func, args) in self.fail_funcs:
                try:
                    func(*args)
                except Exception as msg:
                    log.debug1(traceback.format_exc())
                    log.error("Calling fail func %s(%s) failed: %s" % \
                              (func, args, msg))

            raise FirewallError(errors.COMMAND_FAILED, errorMsg)

        # post
        self.post()

    def pre(self):
        log.debug4("%s.pre()" % type(self))

        for (func, args) in self.pre_funcs:
            try:
                func(*args)
            except Exception as msg:
                log.debug1(traceback.format_exc())
                log.error("Calling pre func %s(%s) failed: %s" % \
                          (func, args, msg))

    def post(self):
        log.debug4("%s.post()" % type(self))

        for (func, args) in self.post_funcs:
            try:
                func(*args)
            except Exception as msg:
                log.debug1(traceback.format_exc())
                log.error("Calling post func %s(%s) failed: %s" % \
                          (func, args, msg))
