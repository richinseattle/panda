#!/usr/bin/env python

import sys
import os.path
import re
import textwrap


def find_message(buf):
    i = buf.find("message")
    if i == -1:
        return None
    j = buf.find("{", i)
    k = buf.find("}", j)
    before = buf[:i]
    message = buf[i:k+1]
    after = buf[k+1:]
    return (before, message, after)


def get_proto_text(filename):
    buf = ""
    for line in open(filename):
        foo = re.search("^(\s*)\/\/", line)
        if foo:
            continue
        bar = re.search("^(\s*)$", line)
        if bar:
            continue
#        print("line=[%s]" % line)
        buf += line
    return buf


def check_blank(buf):
    foo = re.search("^(\s*)$", buf)
    if foo:
        return True
    return buf.strip()


def parse_proto_part(buf):
    # find the messages
    messages = []
    rests = []
    while True:
        x = find_message(buf)
        if x is None:
            y = check_blank(buf)
            if not (y is True):
                rests.append(y)
            break
        (before, message, after) = x
        messages.append(message)
#        print("message = [%s]" % message)
        y = check_blank(before)
        if not (y is True):
            rests.append(y)
        buf = after
#        print(len(after))
    return (messages, rests)


if __name__ == '__main__':
    # panda.proto template
    pandalog_proto_tpl = textwrap.dedent("""
        syntax = "proto2";
        package panda;

        {messages}
        message LogEntry {{
        required uint64 pc = 1;
        required uint64 instr = 2;
        {logentry_fields}
        }}
    """).lstrip()

    messages = []
    rests = []

    # file locations
    panda_plugins = sys.argv[1] if len(sys.argv) > 1 else 'panda_plugins'
    pandalog_proto = sys.argv[2] if len(sys.argv) > 2 else os.path.join('panda', 'pandalog.proto')
    panda_plugins_config = os.path.join(panda_plugins, 'config.panda')
    proto_part_format = os.path.join(panda_plugins, '{plugin}', '{plugin}.proto')

    # read list of active plugins
    with open(panda_plugins_config, 'r') as pf:
        active_plugins_filter = lambda s: not s.startswith('#')
        active_plugins = filter(active_plugins_filter, map(str.strip, pf.readlines()))

    # process proto files
    for plugin in sorted(active_plugins):
        proto_part_file = proto_part_format.format(plugin=plugin)
        if os.path.isfile(proto_part_file):
            print(proto_part_file)
            proto_part = get_proto_text(proto_part_file)
            (m, r) = parse_proto_part(proto_part)
            messages.extend(m)
            rests.extend(r)

    # write pandalog.proto
    with open(pandalog_proto, 'w') as f:
        f.write(pandalog_proto_tpl.format(
            messages = '\n'.join(messages),
            logentry_fields = '\n'.join(rests),
        ))

