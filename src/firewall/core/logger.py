# -*- coding: utf-8 -*-
#
# Copyright (C) 2005-2007,2012 Red Hat, Inc.
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

__all__ = [ "LogTarget", "FileLog", "Logger", "log" ]

import sys
import types
import time
import inspect
import fnmatch
import syslog
import traceback
import fcntl
import os.path
import os

# ---------------------------------------------------------------------------

# abstract class for logging targets
class LogTarget(object):
    """ Abstract class for logging targets. """
    def __init__(self):
        self.fd = None

    def write(self, data, level, logger, is_debug=0):
        raise NotImplementedError("LogTarget.write is an abstract method")

    def flush(self):
        raise NotImplementedError("LogTarget.flush is an abstract method")

    def close(self):
        raise NotImplementedError("LogTarget.close is an abstract method")

# ---------------------------------------------------------------------------

# private class for stdout
class _StdoutLog(LogTarget):
    def __init__(self):
        LogTarget.__init__(self)
        self.fd = sys.stdout

    def write(self, data, level, logger, is_debug=0):
        # ignore level
        self.fd.write(data)
        self.flush()

    def close(self):
        self.flush()

    def flush(self):
        self.fd.flush()

# ---------------------------------------------------------------------------

# private class for stderr
class _StderrLog(_StdoutLog):
    def __init__(self):
        _StdoutLog.__init__(self)
        self.fd = sys.stderr

# ---------------------------------------------------------------------------

# private class for syslog
class _SyslogLog(LogTarget):
    def __init__(self):
        # Only initialize LogTarget here as fs should be None
        LogTarget.__init__(self)
        #
        # Derived from: https://github.com/canvon/firewalld/commit/af0edfee1cc1891b7b13f302ca5911b24e9b0f13
        #
        # Work around Python issue 27875, "Syslogs /usr/sbin/foo as /foo
        # instead of as foo"
        # (but using openlog explicitly might be better anyway)
        #
        # Set ident to basename, log PID as well, and log to facility "daemon".
        syslog.openlog(os.path.basename(sys.argv[0]),
                       syslog.LOG_PID, syslog.LOG_DAEMON)

    def write(self, data, level, logger, is_debug=0):
        priority = None
        if is_debug:
            priority = syslog.LOG_DEBUG
        else:
            if level >= logger.INFO1:
                priority = syslog.LOG_INFO
            elif level == logger.WARNING:
                priority = syslog.LOG_WARNING
            elif level == logger.ERROR:
                priority = syslog.LOG_ERR
            elif level == logger.FATAL:
                priority = syslog.LOG_CRIT

        if data.endswith("\n"):
            data = data[:len(data)-1]
        if len(data) > 0:
            if priority is None:
                syslog.syslog(data)
            else:
                syslog.syslog(priority, data)

    def close(self):
        syslog.closelog()

    def flush(self):
        pass

# ---------------------------------------------------------------------------

class FileLog(LogTarget):
    """ FileLog class.
    File will be opened on the first write. """
    def __init__(self, filename, mode="w"):
        LogTarget.__init__(self)
        self.filename = filename
        self.mode = mode

    def open(self):
        if self.fd:
            return
        flags = os.O_CREAT | os.O_WRONLY
        if self.mode.startswith('a'):
            flags |= os.O_APPEND
        self.fd = os.open(self.filename, flags, 0o640)
        # Make sure that existing file has correct perms
        os.fchmod(self.fd, 0o640)
        # Make it an object
        self.fd = os.fdopen(self.fd, self.mode)
        fcntl.fcntl(self.fd, fcntl.F_SETFD, fcntl.FD_CLOEXEC)

    def write(self, data, level, logger, is_debug=0):
        if not self.fd:
            self.open()
        self.fd.write(data)
        self.fd.flush()

    def close(self):
        if not self.fd:
            return
        self.fd.close()
        self.fd = None

    def flush(self):
        if not self.fd:
            return
        self.fd.flush()

# ---------------------------------------------------------------------------

class Logger(object):
    r"""
    Format string:

    %(class)s      Calling class the function belongs to, else empty
    %(date)s       Date using Logger.date_format, see time module
    %(domain)s     Full Domain: %(module)s.%(class)s.%(function)s
    %(file)s       Filename of the module
    %(function)s   Function name, empty in __main__
    %(label)s      Label according to log function call from Logger.label
    %(level)d      Internal logging level
    %(line)d       Line number in module
    %(module)s     Module name
    %(message)s    Log message

    Standard levels:

    FATAL                 Fatal error messages
    ERROR                 Error messages
    WARNING               Warning messages
    INFOx, x in [1..5]    Information
    DEBUGy, y in [1..10]  Debug messages
    NO_INFO               No info output
    NO_DEBUG              No debug output
    INFO_MAX              Maximum info level
    DEBUG_MAX             Maximum debug level

    x and y depend on info_max and debug_max from Logger class
    initialization. See __init__ function.

    Default logging targets:

    stdout        Logs to stdout
    stderr        Logs to stderr
    syslog        Logs to syslog

    Additional arguments for logging functions (fatal, error, warning, info
    and debug):

    nl       Disable newline at the end with nl=0, default is nl=1.
    fmt      Format string for this logging entry, overloads global format
             string. Example: fmt="%(file)s:%(line)d %(message)s"
    nofmt    Only output message with nofmt=1. The nofmt argument wins over
             the fmt argument.

    Example:

    from logger import log
    log.setInfoLogLevel(log.INFO1)
    log.setDebugLogLevel(log.DEBUG1)
    for i in range(1, log.INFO_MAX+1):
        log.setInfoLogLabel(i, "INFO%d: " % i)
    log.setFormat("%(date)s %(module)s:%(line)d [%(domain)s] %(label)s: "
                  "%(level)d %(message)s")
    log.setDateFormat("%Y-%m-%d %H:%M:%S")

    fl = FileLog("/tmp/log", "a")
    log.addInfoLogging("*", fl)
    log.addDebugLogging("*", fl)
    log.addInfoLogging("*", log.syslog, fmt="%(label)s%(message)s")

    log.debug3("debug3")
    log.debug2("debug2")
    log.debug1("debug1")
    log.info2("info2")
    log.info1("info1")
    log.warning("warning\n", nl=0)
    log.error("error\n", nl=0)
    log.fatal("fatal")
    log.info(log.INFO1, "nofmt info", nofmt=1)

    """

    ALL       = -5
    NOTHING   = -4
    FATAL     = -3
    TRACEBACK = -2
    ERROR     = -1
    WARNING   =  0

    # Additional levels are generated in class initilization

    stdout = _StdoutLog()
    stderr = _StderrLog()
    syslog = _SyslogLog()

    def __init__(self, info_max=5, debug_max=10):
        """ Logger class initialization """
        self._level = { }
        self._debug_level = { }
        self._format = ""
        self._date_format = ""
        self._label = { }
        self._debug_label = { }
        self._logging = { }
        self._debug_logging = { }
        self._domains = { }
        self._debug_domains = { }

        # INFO1 is required for standard log level
        if info_max < 1:
            raise ValueError("Logger: info_max %d is too low" % info_max)
        if debug_max < 0:
            raise ValueError("Logger: debug_max %d is too low" % debug_max)

        self.NO_INFO   = self.WARNING # = 0
        self.INFO_MAX  = info_max
        self.NO_DEBUG  = 0
        self.DEBUG_MAX = debug_max

        self.setInfoLogLabel(self.FATAL, "FATAL ERROR: ")
        self.setInfoLogLabel(self.TRACEBACK, "")
        self.setInfoLogLabel(self.ERROR, "ERROR: ")
        self.setInfoLogLabel(self.WARNING, "WARNING: ")

        # generate info levels and infox functions
        for _level in range(1, self.INFO_MAX+1):
            setattr(self, "INFO%d" % _level, _level)
            self.setInfoLogLabel(_level, "")
            setattr(self, "info%d" % (_level),
                    (lambda self, x:
                     lambda message, *args, **kwargs:
                     self.info(x, message, *args, **kwargs))(self, _level)) # pylint: disable=E0602

        # generate debug levels and debugx functions
        for _level in range(1, self.DEBUG_MAX+1):
            setattr(self, "DEBUG%d" % _level, _level)
            self.setDebugLogLabel(_level, "DEBUG%d: " % _level)
            setattr(self, "debug%d" % (_level),
                    (lambda self, x:
                     lambda message, *args, **kwargs:
                     self.debug(x, message, *args, **kwargs))(self, _level)) # pylint: disable=E0602

        # set initial log levels, formats and targets
        self.setInfoLogLevel(self.INFO1)
        self.setDebugLogLevel(self.NO_DEBUG)
        self.setFormat("%(label)s%(message)s")
        self.setDateFormat("%d %b %Y %H:%M:%S")
        self.setInfoLogging("*", self.stderr, [ self.FATAL, self.ERROR,
                                                self.WARNING ])
        self.setInfoLogging("*", self.stdout,
                            [ i for i in range(self.INFO1, self.INFO_MAX+1) ])
        self.setDebugLogging("*", self.stdout,
                             [ i for i in range(1, self.DEBUG_MAX+1) ])

    def close(self):
        """ Close all logging targets """
        for level in range(self.FATAL, self.DEBUG_MAX+1):
            if level not in self._logging:
                continue
            for (dummy, target, dummy) in self._logging[level]:
                target.close()

    def getInfoLogLevel(self, domain="*"):
        """ Get info log level. """
        self._checkDomain(domain)
        if domain in self._level:
            return self._level[domain]
        return self.NOTHING

    def setInfoLogLevel(self, level, domain="*"):
        """ Set log level [NOTHING .. INFO_MAX] """
        self._checkDomain(domain)
        if level < self.NOTHING:
            level = self.NOTHING
        if level > self.INFO_MAX:
            level = self.INFO_MAX
        self._level[domain] = level

    def getDebugLogLevel(self, domain="*"):
        """ Get debug log level. """
        self._checkDomain(domain)
        if domain in self._debug_level:
            return self._debug_level[domain] + self.NO_DEBUG
        return self.NO_DEBUG

    def setDebugLogLevel(self, level, domain="*"):
        """ Set debug log level [NO_DEBUG .. DEBUG_MAX] """
        self._checkDomain(domain)
        if level < 0:
            level = 0
        if level > self.DEBUG_MAX:
            level = self.DEBUG_MAX
        self._debug_level[domain] = level - self.NO_DEBUG

    def getFormat(self):
        return self._format

    def setFormat(self, _format):
        self._format = _format

    def getDateFormat(self):
        return self._date_format

    def setDateFormat(self, _format):
        self._date_format = _format

    def setInfoLogLabel(self, level, label):
        """ Set log label for level. Level can be a single level or an array
        of levels. """
        levels = self._getLevels(level)
        for level in levels:
            self._checkLogLevel(level, min_level=self.FATAL,
                                max_level=self.INFO_MAX)
            self._label[level] = label

    def setDebugLogLabel(self, level, label):
        """ Set log label for level. Level can be a single level or an array
        of levels. """
        levels = self._getLevels(level, is_debug=1)
        for level in levels:
            self._checkLogLevel(level, min_level=self.INFO1,
                                max_level=self.DEBUG_MAX)
            self._debug_label[level] = label

    def setInfoLogging(self, domain, target, level=ALL, fmt=None):
        """ Set info log target for domain and level. Level can be a single
        level or an array of levels. Use level ALL to set for all levels.
        If no format is specified, the default format will be used. """
        self._setLogging(domain, target, level, fmt, is_debug=0)

    def setDebugLogging(self, domain, target, level=ALL, fmt=None):
        """ Set debug log target for domain and level. Level can be a single
        level or an array of levels. Use level ALL to set for all levels.
        If no format is specified, the default format will be used. """
        self._setLogging(domain, target, level, fmt, is_debug=1)

    def addInfoLogging(self, domain, target, level=ALL, fmt=None):
        """ Add info log target for domain and level. Level can be a single
        level or an array of levels. Use level ALL to set for all levels.
        If no format is specified, the default format will be used. """
        self._addLogging(domain, target, level, fmt, is_debug=0)

    def addDebugLogging(self, domain, target, level=ALL, fmt=None):
        """ Add debg log target for domain and level. Level can be a single
        level or an array of levels. Use level ALL to set for all levels.
        If no format is specified, the default format will be used. """
        self._addLogging(domain, target, level, fmt, is_debug=1)

    def delInfoLogging(self, domain, target, level=ALL, fmt=None):
        """ Delete info log target for domain and level. Level can be a single
        level or an array of levels. Use level ALL to set for all levels.
        If no format is specified, the default format will be used. """
        self._delLogging(domain, target, level, fmt, is_debug=0)

    def delDebugLogging(self, domain, target, level=ALL, fmt=None):
        """ Delete debug log target for domain and level. Level can be a single
        level or an array of levels. Use level ALL to set for all levels.
        If no format is specified, the default format will be used. """
        self._delLogging(domain, target, level, fmt, is_debug=1)

    def isInfoLoggingHere(self, level):
        """ Is there currently any info logging for this log level (and
        domain)? """
        return self._isLoggingHere(level, is_debug=0)

    def isDebugLoggingHere(self, level):
        """ Is there currently any debug logging for this log level (and
        domain)? """
        return self._isLoggingHere(level, is_debug=1)

    ### log functions

    def fatal(self, _format, *args, **kwargs):
        """ Fatal error log. """
        self._checkKWargs(kwargs)
        kwargs["is_debug"] = 0
        self._log(self.FATAL, _format, *args, **kwargs)

    def error(self, _format, *args, **kwargs):
        """ Error log. """
        self._checkKWargs(kwargs)
        kwargs["is_debug"] = 0
        self._log(self.ERROR, _format, *args, **kwargs)

    def warning(self, _format, *args, **kwargs):
        """ Warning log. """
        self._checkKWargs(kwargs)
        kwargs["is_debug"] = 0
        self._log(self.WARNING, _format, *args, **kwargs)

    def info(self, level, _format, *args, **kwargs):
        """ Information log using info level [1..info_max].
        There are additional infox functions according to info_max from
        __init__"""
        self._checkLogLevel(level, min_level=1, max_level=self.INFO_MAX)
        self._checkKWargs(kwargs)
        kwargs["is_debug"] = 0
        self._log(level+self.NO_INFO, _format, *args, **kwargs)

    def debug(self, level, _format, *args, **kwargs):
        """ Debug log using debug level [1..debug_max].
        There are additional debugx functions according to debug_max
        from __init__"""
        self._checkLogLevel(level, min_level=1, max_level=self.DEBUG_MAX)
        self._checkKWargs(kwargs)
        kwargs["is_debug"] = 1
        self._log(level, _format, *args, **kwargs)

    def exception(self):
        self._log(self.TRACEBACK, traceback.format_exc(), args=[], kwargs={})

    ### internal functions

    def _checkLogLevel(self, level, min_level, max_level):
        if level < min_level or level > max_level:
            raise ValueError("Level %d out of range, should be [%d..%d]." % \
                             (level, min_level, max_level))

    def _checkKWargs(self, kwargs):
        if not kwargs:
            return
        for key in kwargs.keys():
            if key not in [ "nl", "fmt", "nofmt" ]:
                raise ValueError("Key '%s' is not allowed as argument for logging." % key)

    def _checkDomain(self, domain):
        if not domain or domain == "":
            raise ValueError("Domain '%s' is not valid." % domain)

    def _getLevels(self, level, is_debug=0):
        """ Generate log level array. """
        if level != self.ALL:
            if isinstance(level, list) or isinstance(level, tuple):
                levels = level
            else:
                levels = [ level ]
            for level in levels:
                if is_debug:
                    self._checkLogLevel(level, min_level=1,
                                        max_level=self.DEBUG_MAX)
                else:
                    self._checkLogLevel(level, min_level=self.FATAL,
                                        max_level=self.INFO_MAX)
        else:
            if is_debug:
                levels = [ i for i in range(self.DEBUG1, self.DEBUG_MAX) ]
            else:
                levels = [ i for i in range(self.FATAL, self.INFO_MAX) ]
        return levels

    def _getTargets(self, target):
        """ Generate target array. """
        if isinstance(target, list) or isinstance(target, tuple):
            targets = target
        else:
            targets = [ target ]
        for _target in targets:
            if not issubclass(_target.__class__, LogTarget):
                raise ValueError("'%s' is no valid logging target." % \
                      _target.__class__.__name__)
        return targets

    def _genDomains(self, is_debug=0):
        # private method for self._domains array creation, speeds up
        """ Generate dict with domain by level. """
        if is_debug:
            _domains = self._debug_domains
            _logging = self._debug_logging
            _range = ( 1, self.DEBUG_MAX+1 )
        else:
            _domains = self._domains
            _logging = self._logging
            _range = ( self.FATAL, self.INFO_MAX+1 )

        if len(_domains) > 0:
            _domains.clear()

        for level in range(_range[0], _range[1]):
            if level not in _logging:
                continue
            for (domain, dummy, dummy) in _logging[level]:
                if domain not in _domains:
                    _domains.setdefault(level, [ ]).append(domain)

    def _setLogging(self, domain, target, level=ALL, fmt=None, is_debug=0):
        self._checkDomain(domain)
        levels = self._getLevels(level, is_debug)
        targets = self._getTargets(target)

        if is_debug:
            _logging = self._debug_logging
        else:
            _logging = self._logging

        for level in levels:
            for target in targets:
                _logging[level] = [ (domain, target, fmt) ]
        self._genDomains(is_debug)

    def _addLogging(self, domain, target, level=ALL, fmt=None, is_debug=0):
        self._checkDomain(domain)
        levels = self._getLevels(level, is_debug)
        targets = self._getTargets(target)

        if is_debug:
            _logging = self._debug_logging
        else:
            _logging = self._logging

        for level in levels:
            for target in targets:
                _logging.setdefault(level, [ ]).append((domain, target, fmt))
        self._genDomains(is_debug)

    def _delLogging(self, domain, target, level=ALL, fmt=None, is_debug=0):
        self._checkDomain(domain)
        levels = self._getLevels(level, is_debug)
        targets = self._getTargets(target)

        if is_debug:
            _logging = self._debug_logging
        else:
            _logging = self._logging

        for _level in levels:
            for target in targets:
                if _level not in _logging:
                    continue
                if (domain, target, fmt) in _logging[_level]:
                    _logging[_level].remove( (domain, target, fmt) )
                    if len(_logging[_level]) == 0:
                        del _logging[_level]
                        continue
                if level != self.ALL:
                    raise ValueError("No mathing logging for " \
                          "level %d, domain %s, target %s and format %s." % \
                          (_level, domain, target.__class__.__name__, fmt))
        self._genDomains(is_debug)

    def _isLoggingHere(self, level, is_debug=0):
        _dict = self._genDict(level, is_debug)
        if not _dict:
            return False

        point_domain = _dict["domain"] + "."

        if is_debug:
            _logging = self._debug_logging
        else:
            _logging = self._logging

        # do we need to log?
        for (domain, dummy, dummy) in _logging[level]:
            if domain == "*" or \
                   point_domain.startswith(domain) or \
                   fnmatch.fnmatchcase(_dict["domain"], domain):
                return True
        return False

    def _getClass(self, frame):
        """ Function to get calling class. Returns class or None. """
        # get class by first function argument, if there are any
        if frame.f_code.co_argcount > 0:
            selfname = frame.f_code.co_varnames[0]
            if selfname in frame.f_locals:
                _self = frame.f_locals[selfname]
                obj = self._getClass2(_self.__class__, frame.f_code)
                if obj:
                    return obj

        module = inspect.getmodule(frame.f_code)
        code = frame.f_code

        # function in module?
        if code.co_name in module.__dict__:
            if hasattr(module.__dict__[code.co_name], "func_code") and \
                   module.__dict__[code.co_name].__code__  == code:
                return None

        # class in module
        for (dummy, obj) in module.__dict__.items():
            if isinstance(obj, types.ClassType):
                if hasattr(obj, code.co_name):
                    value = getattr(obj, code.co_name)
                    if isinstance(value, types.FunctionType):
                        if value.__code__ == code:
                            return obj

        # nothing found
        return None

    def _getClass2(self, obj, code):
        """ Internal function to get calling class. Returns class or None. """
        for value in obj.__dict__.values():
            if isinstance(value, types.FunctionType):
                if value.__code__ == code:
                    return obj

        for base in obj.__bases__:
            _obj = self._getClass2(base, code)
            if _obj:
                return _obj
        return None

    # internal log class
    def _log(self, level, _format, *args, **kwargs):
        is_debug = 0
        if "is_debug" in kwargs:
            is_debug = kwargs["is_debug"]

        nl = 1
        if "nl" in kwargs:
            nl = kwargs["nl"]

        nofmt = 0
        if "nofmt" in kwargs:
            nofmt = kwargs["nofmt"]

        _dict = self._genDict(level, is_debug)
        if not _dict:
            return

        if len(args) > 1:
            _dict['message'] = _format % args
        elif len(args) == 1:  # needed for _format % _dict
            _dict['message'] = _format % args[0]
        else:
            _dict['message'] = _format

        point_domain = _dict["domain"] + "."

        if is_debug:
            _logging = self._debug_logging
        else:
            _logging = self._logging

        used_targets = [ ]
        # log to target(s)
        for (domain, target, _format) in _logging[level]:
            if target in used_targets:
                continue
            if domain == "*" \
                   or point_domain.startswith(domain+".") \
                   or fnmatch.fnmatchcase(_dict["domain"], domain):
                if not _format:
                    _format = self._format
                if "fmt" in kwargs:
                    _format = kwargs["fmt"]
                if nofmt:
                    target.write(_dict["message"], level, self, is_debug)
                else:
                    target.write(_format % _dict, level, self, is_debug)
                if nl: # newline
                    target.write("\n", level, self, is_debug)
                used_targets.append(target)

    # internal function to generate the dict, needed for logging
    def _genDict(self, level, is_debug=0):
        """ Internal function. """
        check_domains = [ ]
        simple_match = False

        if is_debug:
            _dict = self._debug_level
            _domains = self._debug_domains
            _label = self._debug_label
        else:
            _dict = self._level
            _domains = self._domains
            _label = self._label

        # no debug
        for domain in _dict:
            if domain == "*":
                # '*' matches everything: simple match
                if _dict[domain] >= level:
                    simple_match = True
                    if len(check_domains) > 0:
                        check_domains = [ ]
                    break
            else:
                if _dict[domain] >= level:
                    check_domains.append(domain)

        if not simple_match and len(check_domains) < 1:
            return None

        if level not in _domains:
            return None

        f = inspect.currentframe()

        # go outside of logger module as long as there is a lower frame
        while f and f.f_back and f.f_globals["__name__"] == self.__module__:
            f = f.f_back

        if not f:
            raise ValueError("Frame information not available.")

        # get module name
        module_name = f.f_globals["__name__"]

        # simple module match test for all entries of check_domain
        point_module = module_name + "."
        for domain in check_domains:
            if point_module.startswith(domain):
                # found domain in module name
                check_domains = [ ]
                break

        # get code
        co = f.f_code

        # optimization: bail out early if domain can not match at all
        _len = len(module_name)
        for domain in _domains[level]:
            i = domain.find("*")
            if i == 0:
                continue
            elif i > 0:
                d = domain[:i]
            else:
                d = domain
            if _len >= len(d):
                if not module_name.startswith(d):
                    return None
            else:
                if not d.startswith(module_name):
                    return None

        # generate _dict for format output
        level_str = ""
        if level in _label:
            level_str = _label[level]
        _dict = { 'file': co.co_filename,
                  'line': f.f_lineno,
                  'module': module_name,
                  'class': '',
                  'function': co.co_name,
                  'domain': '',
                  'label' : level_str,
                  'level' : level,
                  'date' : time.strftime(self._date_format, time.localtime()) }
        if _dict["function"] == "?":
            _dict["function"] = ""

        # domain match needed?
        domain_needed = False
        for domain in _domains[level]:
            # standard domain, matches everything
            if domain == "*":
                continue
            # domain is needed
            domain_needed = True
            break

        # do we need to get the class object?
        if self._format.find("%(domain)") >= 0 or \
               self._format.find("%(class)") >= 0 or \
               domain_needed or \
               len(check_domains) > 0:
            obj = self._getClass(f)
            if obj:
                _dict["class"] = obj.__name__

        # build domain string
        _dict["domain"] = "" + _dict["module"]
        if _dict["class"] != "":
            _dict["domain"] += "." + _dict["class"]
        if _dict["function"] != "":
            _dict["domain"] += "." + _dict["function"]

        if len(check_domains) < 1:
            return _dict

        point_domain = _dict["domain"] + "."
        for domain in check_domains:
            if point_domain.startswith(domain) or \
                   fnmatch.fnmatchcase(_dict["domain"], domain):
                return _dict

        return None

# ---------------------------------------------------------------------------

# Global logging object.
log = Logger()

# ---------------------------------------------------------------------------

"""
# Example
if __name__ == '__main__':
    log.setInfoLogLevel(log.INFO2)
    log.setDebugLogLevel(log.DEBUG5)
    for i in range(log.INFO1, log.INFO_MAX+1):
        log.setInfoLogLabel(i, "INFO%d: " % i)
    for i in range(log.DEBUG1, log.DEBUG_MAX+1):
        log.setDebugLogLabel(i, "DEBUG%d: " % i)

    log.setFormat("%(date)s %(module)s:%(line)d %(label)s"
                  "%(message)s")
    log.setDateFormat("%Y-%m-%d %H:%M:%S")

    fl = FileLog("/tmp/log", "a")
    log.addInfoLogging("*", fl)
    log.delDebugLogging("*", log.stdout)
    log.setDebugLogging("*", log.stdout, [ log.DEBUG1, log.DEBUG2 ] )
    log.addDebugLogging("*", fl)
#    log.addInfoLogging("*", log.syslog, fmt="%(label)s%(message)s")
#    log.addDebugLogging("*", log.syslog, fmt="%(label)s%(message)s")

    log.debug10("debug10")
    log.debug9("debug9")
    log.debug8("debug8")
    log.debug7("debug7")
    log.debug6("debug6")
    log.debug5("debug5")
    log.debug4("debug4")
    log.debug3("debug3")
    log.debug2("debug2", fmt="%(file)s:%(line)d %(message)s")
    log.debug1("debug1", nofmt=1)
    log.info5("info5")
    log.info4("info4")
    log.info3("info3")
    log.info2("info2")
    log.info1("info1")
    log.warning("warning\n", nl=0)
    log.error("error ", nl=0)
    log.error("error", nofmt=1)
    log.fatal("fatal")
    log.info(log.INFO1, "nofmt info", nofmt=1)
    log.info(log.INFO2, "info2 fmt", fmt="%(file)s:%(line)d %(message)s")

    try:
        a = b
    except Exception as e:
        log.exception()
"""

# vim:ts=4:sw=4:showmatch:expandtab
