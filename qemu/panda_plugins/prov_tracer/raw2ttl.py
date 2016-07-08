#!/usr/bin/env python

# Converter from our custom raw provenance output to turtle output.
# See: http://www.w3.org/TeamSubmission/turtle/

import argparse
import sys
import fileinput
import string
import urllib
import mimetypes
import re
from textwrap import dedent
from pprint import pprint
import datetime

#### constants and formats ##########################################
rdf_header = dedent('''
    @prefix prov: <http://www.w3.org/ns/prov#> .
    @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
    @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
    @prefix dt: <http://m000.github.com/ns/v1/desktop#> .
''').strip()

rdf_exec_fmt = dedent('''
    <exe://{program_url}> a prov:Activity .
    <exe://{program_url}> rdf:type dt:{program_type} .
''').strip()

rdf_open_fmt = dedent('''
    <file:{file_url}> a prov:Entity .
    <file:{file_url}> rdfs:label "{label}" .
    <file:{file_url}> rdf:type dt:{file_type} .
''').strip()

rdf_used_fmt = dedent('''
    <exe://{program_url}> prov:used <file:{file_url}> .
''').strip()

rdf_generated_fmt = dedent('''
    <file:{file_url}> prov:wasGeneratedBy <exe://{program_url}> .
''').strip()

rdf_derived_fmt = dedent('''
    <file:{file_url1}> prov:wasDerivedFrom <file:{file_url2}> .
''').strip()

rdf_duration_fmt = dedent('''
    <exe://{program_url}> prov:startedAtTime {started_pts} .
    <exe://{program_url}> prov:endedAtTime {ended_pts} .
''').strip()

#### time formatr - you guessed it, for provToolbox #################
time_fmt = lambda t: t
#time_fmt = lambda t: datetime.datetime.fromtimestamp(float(t)).isoformat() # --doesn't work

#### program types ##################################################
def get_program_type(process):
    prog_types = {
        'vi':           'Editor',
        'vim':          'Editor',
        'nano':         'Editor',
        'pico':         'Editor',
        'sh':           'Shell',
        'bash':         'Shell',
        'zsh':          'Shell',
        'cron':         'Daemon',
        'acpid':        'Daemon',
        'dbus-daemon':  'Daemon',
        'rpcbind':      'Daemon',
        'init':         'Daemon',
        'tar':          'Fileutil',
        'unzip':        'Fileutil',
        'gzip':         'Fileutil',
        'zip':          'Fileutil',
        'ls':           'Shellutil',
    }
    exe, pid = process.rsplit('~', 1)

    # provToolbox doesn't like dots in dt:
    return prog_types[exe] if exe in prog_types else exe.replace('.', '')

#### exceptions #####################################################
class Error(Exception):
    """Base class for exceptions in this module."""
    pass

class UnknownUFDError(Error):
    """Raised when there's no mapping for an ufd."""
    def __init__(self, ufd):
        self.ufd = ufd
    def __str__(self):
        return "No active mapping for %s." % (self.ufd)

class TagFormatError(Error):
    """Raised when tags cannot be parsed."""
    def __init__(self, tagspec):
        self.tagspec = tagspec
    def __str__(self):
        return "Cannot parse '%s' into tags." % (self.tagspec)

#### handlers for entry lines #######################################
def process_d(data):
    filename1, filename2 = data
    print rdf_derived_fmt.format(
        # prov toolbox has problems with url-quoted characters
        # file_url1 = urllib.pathname2url(filename1),
        file_url1 = filename1,
        # prov toolbox has problems with url-quoted characters
        # file_url2 = urllib.pathname2url(filename2),
        file_url2 = filename2,
    )

def process_g(data):
    global s
    # line format: u:<asid>:<process label>:<filename>:<nwritten>
    asid, process, filename, nwritten = data
    process = ':'.join(process.split(';'))

    if filename not in s.files:
        file_type = mimetypes.guess_type(filename)[0]
        file_type = re.sub(r'\W+', '', file_type) if file_type else "Unknown"
        print rdf_open_fmt.format(
            # prov toolbox has problems with url-quoted characters
            # file_url = urllib.pathname2url(filename),
            file_url = filename,
            label = filename,
            file_type = file_type,
        )
        s.files.add(filename)

    print rdf_generated_fmt.format(
        program_url = process,
        # prov toolbox has problems with url-quoted characters
        # file_url = urllib.pathname2url(filename),
        file_url = filename,
    )

def process_q(data):
    # line format: q:<asid>:<process label>:<started_pts>:<ended_pts>
    asid, process, started_pts, ended_pts = data
    print rdf_duration_fmt.format(
        program_url = process,
        started_pts = time_fmt(started_pts),
        ended_pts = time_fmt(ended_pts),
    )

def process_u(data):
    global s
    # line format: u:<asid>:<process label>:<filename>:<nread>
    asid, process, filename, nread = data
    process = ':'.join(process.split(';'))

    if filename not in s.files:
        file_type = mimetypes.guess_type(filename)[0]
        file_type = re.sub(r'\W+', '', file_type) if file_type else "Unknown"
        print rdf_open_fmt.format(
            # prov toolbox has problems with url-quoted characters
            # file_url = urllib.pathname2url(filename),
            file_url = filename,
            label = filename,
            file_type = file_type,
        )
        s.files.add(filename)

    #print triple
    print rdf_used_fmt.format(
        program_url = process,
        # prov toolbox has problems with url-quoted characters
        # file_url = urllib.pathname2url(filename),
        file_url = filename,
    )

def process_x(data):
    global s
    # line format: x:<asid>:<process label>
    asid, process = data
    process = ':'.join(process.split(';'))

    print rdf_exec_fmt.format(
        program_url = process,
        program_type = get_program_type(process),
    )

class Raw2TTLState:
    exe = None
    ufdmap = {}
    derived = {}
    generated = set()

    files = set()

#### main ###########################################################
if __name__ == "__main__":
    s = Raw2TTLState()

    parser = argparse.ArgumentParser(description='Convert DataTracker raw format to PROV/Turtle format.')
    parser.add_argument('files', metavar='file', nargs='*', help='specify input files')
    args = parser.parse_args()

    print rdf_header
    for line in fileinput.input(args.files):
        if line.startswith('#'):
            print line.strip()
            continue

        # split and unquote data
        op, data = line.strip().split(':', 1)
        data = map(urllib.unquote, data.split(':'))

        # provToolbox hack - eliminate ':' which cause problems
        data = map(lambda s: s.replace(':', '+'), data)

        try:
            # call proper handler
            # print '# Debug line: '+line.strip()
            globals()['process_'+op](data)
        except KeyError:
            # Keep bad line as comment.
            print '# Bad line: '+line.strip()
            raise



#### crap ###########################################################
#def process_c(data):
    #global s
    ## line format: c:<filename>
    #ufd, = data
    #filename1 = s.ufdmap[ufd]

    ## print triples
    #if ufd in s.derived:
        #for filename2 in s.derived[ufd]:
            #print rdf_derived_fmt.format(
                #file_url1 = 'file://'+urllib.pathname2url(filename1),
                #file_url2 = 'file://'+urllib.pathname2url(filename2),
            #)
        #del s.derived[ufd]

    # cleanup generated
    #if filename1 in s.generated: s.generated.remove(filename1)

#def process_o(data):
    #global s
    # line format: o:<ufd>:<filename>
    #ufd, filename = data

    # print triple

#def process_w(data):
    #global s
    ## line format: w:<range type>:<output ufd>:<output offset>:<origin ufd>:<origin offset>:<length>
    #rtype, ufd, offset, ufd_origin, offset_origin, length = data

    #if ufd not in s.ufdmap:
        #raise UnknownUFDError(ufd)
    #if ufd_origin not in s.ufdmap:
        #raise UnknownUFDError(ufd_origin)

    #filename = s.ufdmap[ufd]
    #filename_origin = s.ufdmap[ufd_origin]
    #offset = int(offset)
    #offset_origin = int(offset_origin)
    #length = int(length)

    # emit generated triple if needed
    #if filename in s.generated:
        #print rdf_generated_fmt.format(
            ## prov toolbox has problems with url-quoted characters
            ## program_url = urllib.pathname2url(s.exe),
            #program_url = s.exe,
            ## prov toolbox has problems with url-quoted characters
            ## file_url = urllib.pathname2url(filename),
            #file_url = filename,
        #)
        #s.generated.remove(filename)

    ## simple file provenance
    #if ufd in s.derived:
        #s.derived[ufd].add(filename_origin)
    #else:
        #s.derived[ufd] = set([filename_origin])


