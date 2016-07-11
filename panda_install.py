#!/usr/bin/env python

import sys
import shlex
import platform
import subprocess
import re

try:
    # Prefer the new configparser over the ConfigParser relic.
    import configparser
except ImportError:
    if sys.version_info < (3, 2):
        sys.exit('Please install the configparser backport to your system (%s).' % ('https://pypi.python.org/pypi/configparser'))
    else:
        # this shouldn't ever happen
        raise


class OSStubBase(object):
    ''' Base class for OS stub objects. '''

    # implemented methods
    def __init__(self, dist):
        self.dist = dist
    def get_option(self, confsec, optname):
        ''' Returns the OS-specific option for optname from confsec. '''
        optkey = '%s_%s' % (optname, self.dist[0].upper())
        return confsec[optkey]
    def cmd(self, args):
        ''' Runs the specified command and returns output. '''
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        return p.communicate() + (p.returncode,)
    def sudo(self, args):
        ''' Executes the specified command as root. '''
        args = shlex.split(args) if isinstance(args, basestring) else args
        return self.cmd(['sudo',] + args)
    def are_installed(self, packages):
        ''' Checks if the listed packages are installed. '''
        return False if self.find_missing(packages) else True
    def are_available(self, packages):
        ''' Checkis if the listed packages are available for installation. '''

    # os-specific methods
    def unavailable(self, packages):
        ''' Returns which of the listed packages are not available for installation. '''
    def missing(self, packages):
        ''' Returns which of the listed packages are not installed. '''
    def install(self, packages):
        ''' Installs the listed packages. '''
        raise Exception('Not implemented.')

    @classmethod
    def getStub(cls):
        ''' Returns a stub object for the running OS. '''
        dist = platform.dist()
        if dist[0] in ['Debian', 'Ubuntu']:
            return DebianStub(dist)
        else:
            raise Exception('No stub implementation for %s %s (%s)...' % (dist))


class DebianStub(OSStubBase):
    def missing(self, packages):
        if isinstance(packages, basestring):
            packages = shlex.split(packages)
        out, err, status = self.cmd(['dpkg', '-l'] + packages)

        # package name stops on \s or ':' to handle multi-arch installations
        # e.g. libssl-dev:amd64
        installed_re = re.compile(r'ii\s+(?P<package>[^\s:]+)')
        installed = [ m.group('package')
            for m in map(installed_re.match, out.splitlines())
            if m is not None
        ]
        missing = set(packages) - set(installed)
        return missing
    def unavailable(self, packages):
        if isinstance(packages, basestring):
            packages = shlex.split(packages)
        packages_spec = '^(%s)$' % ('|'.join(packages))
        out, err, status = self.cmd(['apt-cache', 'search', packages_spec])

        # search apt-cache using a regular expression '^(pkg1|pkg2|...)$'
        available_re = re.compile(r'(?P<package>[^\s]+)')
        available = [ m.group('package')
            for m in map(available_re.match, out.splitlines())
            if m is not None
        ]
        unavailable = set(packages) - set(available)
        return unavailable


if __name__ == '__main__':
    # read config
    config = configparser.ConfigParser()
    config.read('panda_install.ini')

    # get package manager stub
    pm = OSStubBase.getStub()

    prereq = pm.get_option(config['panda'], 'PREREQ')
    print(prereq)
    pm.unavailable(prereq)
    print(pm.missing(prereq))
    print(pm.unavailable(prereq))
    print(pm.sudo('ls'))




# vim:sts=4:sw=4:et:
