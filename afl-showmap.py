#!/usr/bin/env python

"""
afl-showmap.py - an alternative map display utility for American Fuzzy Lop
--------------------------------------------------------------------------

Written by Jacek Wielemborek <d33tah@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

A very simple tool that runs the targeted binary and displays
the contents of the trace bitmap in a human-readable form. Useful in
scripts to eliminate redundant inputs and perform other checks.
"""

import argparse
import sys
from shm_instrumentation import SHMInstrumentation

class AFLShowmap(SHMInstrumentation):

    def pre_proc_started(self):
        sys.stderr.write('-- Program output begins --\n')

    def post_proc_started(self):
        sys.stderr.write('-- Program output ends --\n')

    def go(self, target, outfile):
        trace_bytes = SHMInstrumentation.go(self, target, outfile, sys.stdin)
        num_tuples = 0
        with open(outfile, "w") as f:
            for i in range(len(trace_bytes)):
                if trace_bytes[i] == '\x00':
                    continue
                f.write("%06u:%u\n" % (i, ord(trace_bytes[i])))
                num_tuples += 1

        if num_tuples:
            sys.stderr.write("\x1b[1;32m[+] \x1b[0mCaptured %d " % num_tuples)
            sys.stderr.write("tuples in '%s'.\x1b[0m\n" % outfile)
        else:
            # bSTOP RESET_G1 CURSOR_SHOW
            sys.stderr.write('\x0f\x1b)B\x1b[?25h\n')
            sys.stderr.write("\x1b[1;31m[-] PROGRAM ABORT : ")
            sys.stderr.write("\x1b[1;37mNo instrumentation ")
            sys.stderr.write("detected\x1b[1;31m\n")


def parse_cmdline(argv):
    epilog = 'This tool displays raw tuple data captured by AFL ' \
             'instrumentation.\nFor additional help, consult docs/README.'
    parser = argparse.ArgumentParser(usage='%(prog)s [options] -- '
                                     '/path/to/target_app [ ... ]',
                                     epilog=epilog)

    # I really wanted this newline.
    old_parser_help = parser.format_help
    parser.format_help = lambda: "\n" + old_parser_help()

    reqgroup = parser.add_argument_group('required arguments')
    reqgroup.add_argument('-o', required=True, metavar='file',
                          help='file to write the trace data to')

    parser.add_argument('path_to_target_app', nargs='+',
                        help=argparse.SUPPRESS)

    return parser.parse_args(argv[1:])


if __name__ == '__main__':

    sys.stderr.write("\x1b[0;36mafl-showmap \x1b[1;37m1.94b")
    sys.stderr.write("\x1b[0m by <d33tah@gmail.com>\n")

    args = parse_cmdline(sys.argv)
    AFLShowmap().go(args.path_to_target_app, args.o)
