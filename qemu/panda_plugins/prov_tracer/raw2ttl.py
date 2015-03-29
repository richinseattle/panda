#!/usr/bin/env python

# Converter from our custom raw provenance output to turtle output.
# See: http://www.w3.org/TeamSubmission/turtle/                

import argparse
import sys
import fileinput
import string
import urllib
from textwrap import dedent
from pprint import pprint


#### constants and formats ##########################################
rdf_header = dedent('''
    @prefix prov: <http://www.w3.org/ns/prov#> .
    @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
''').strip()

rdf_exec_fmt = dedent('''
    <exe://{url_program}> a prov:Activity . 
''').strip()

rdf_open_fmt = dedent('''
    <file:{url_file}> a prov:Entity .
    <file:{url_file}> rdfs:label "{label}" .
''').strip()

rdf_used_fmt = dedent('''
    <exe://{url_program}> prov:used <file:{url_file}> .
''').strip()

rdf_generated_fmt = dedent('''
    <file:{url_file}> prov:wasGeneratedBy <exe://{url_program}> .
''').strip()

rdf_derived_fmt = dedent('''
    <file:{url_file1}> prov:wasDerivedFrom <file:{url_file2}> .
''').strip()

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
    pass

def process_g(data):
    global s
    # line format: u:<asid>:<process label>:<filename>:<nwritten>
    asid, process, filename, nwritten = data
    process = ':'.join(process.split(';'))

    if filename not in s.files:
        print rdf_open_fmt.format(
            # prov toolbox has problems with url-quoted characters
            # url_file = urllib.pathname2url(filename),
            url_file = filename,
            label = filename
        )
        s.files.add(filename)

    print rdf_generated_fmt.format(
        url_program = process,
        # prov toolbox has problems with url-quoted characters
        # url_file = urllib.pathname2url(filename),
        url_file = filename,
    )

def process_q(data):
    pass

def process_u(data):
    global s
    # line format: u:<asid>:<process label>:<filename>:<nread>
    asid, process, filename, nread = data
    process = ':'.join(process.split(';'))

    if filename not in s.files:
        print rdf_open_fmt.format(
            # prov toolbox has problems with url-quoted characters
            # url_file = urllib.pathname2url(filename),
            url_file = filename,
            label = filename
        )
        s.files.add(filename)

    #print triple
    print rdf_used_fmt.format(
        url_program = process,
        # prov toolbox has problems with url-quoted characters
        # url_file = urllib.pathname2url(filename),
        url_file = filename,
    )

def process_w(data):
    global s
    # line format: w:<range type>:<output ufd>:<output offset>:<origin ufd>:<origin offset>:<length>
    rtype, ufd, offset, ufd_origin, offset_origin, length = data

    if ufd not in s.ufdmap:
        raise UnknownUFDError(ufd)
    if ufd_origin not in s.ufdmap:
        raise UnknownUFDError(ufd_origin)

    filename = s.ufdmap[ufd]
    filename_origin = s.ufdmap[ufd_origin]
    offset = int(offset)
    offset_origin = int(offset_origin)
    length = int(length)

    # emit generated triple if needed
    if filename in s.generated:
        print rdf_generated_fmt.format(
            # prov toolbox has problems with url-quoted characters
            # url_program = urllib.pathname2url(s.exe),
            url_program = s.exe,
            # prov toolbox has problems with url-quoted characters
            # url_file = urllib.pathname2url(filename),
            url_file = filename,
        )
        s.generated.remove(filename)

    # simple file provenance
    if ufd in s.derived:
        s.derived[ufd].add(filename_origin)
    else:
        s.derived[ufd] = set([filename_origin])

def process_x(data):
    global s
    # line format: x:<asid>:<process label>
    asid, process = data
    process = ':'.join(process.split(';'))

    print rdf_exec_fmt.format(
        url_program = process,
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

        try:
            # call proper handler 
            print '# Debug line: '+line.strip()
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
                #url_file1 = 'file://'+urllib.pathname2url(filename1),
                #url_file2 = 'file://'+urllib.pathname2url(filename2),
            #)
        #del s.derived[ufd]

    # cleanup generated
    #if filename1 in s.generated: s.generated.remove(filename1)

#def process_o(data):
    #global s
    # line format: o:<ufd>:<filename>
    #ufd, filename = data

    # print triple


