#!/usr/bin/env python

import argparse
import ctypes
import subprocess
import atexit
import sys

IPC_PRIVATE, IPC_CREAT, IPC_EXCL, IPC_RMID = 0, 512, 1024, 0
MAP_SIZE = 65536

shmget = ctypes.cdll.LoadLibrary("libc.so.6").shmget
shmat = ctypes.cdll.LoadLibrary("libc.so.6").shmat
shmat.restype = ctypes.POINTER(ctypes.c_char * MAP_SIZE)
shmctl = ctypes.cdll.LoadLibrary("libc.so.6").shmctl


def remove_shm(shm_id):
    shmctl(shm_id, IPC_RMID, 0)


def main(target, outfile):

    shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600)
    atexit.register(remove_shm, shm_id)

    target_cmd = ' '.join(target)
    sys.stderr.write("\x1b[1;34m[*] \x1b[0mExecuting '%s'...\n" % target_cmd)
    sys.stderr.write("\x1b[0\n")

    sys.stderr.write('-- Program output begins --\n')
    p = subprocess.Popen(target, env={'__AFL_SHM_ID': str(shm_id)})
    p.wait()
    sys.stderr.write('-- Program output ends --\n')

    trace_bytes = shmat(shm_id, 0, 0)[0]

    num_tuples = 0
    with open(outfile, "w") as f:
        for i in range(MAP_SIZE):
            if trace_bytes[i] == '\x00':
                continue
            f.write("%06u:%u\n" % (i, ord(trace_bytes[i])))
            num_tuples += 1

    if num_tuples:
        sys.stderr.write("\x1b[1;32m[+] \x1b[0mCaptured %d " % num_tuples)
        sys.stderr.write("tuples in '%s'.\x1b[0m\n" % outfile)
    else:
        sys.stderr.write('\x0f\x1b)B\x1b[?25h\n')  # bSTOP RESET_G1 CURSOR_SHOW
        sys.stderr.write("\x1b[1;31m[-] PROGRAM ABORT : ")
        sys.stderr.write("\x1b[1;37mNo instrumentation detected\x1b[1;31m\n")

def parse_cmdline(argv):
    formattter_class = argparse.RawDescriptionHelpFormatter
    epilog = 'This tool displays raw tuple data captured by AFL ' \
             'instrumentation.\nFor additional help, consult docs/README.'
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=formattter_class,
                                     usage='%(prog)s [options] -- '
                                     '/path/to/target_app [ ... ]',
                                     epilog=epilog)

    reqgroup = parser.add_argument_group('required arguments')
    reqgroup.add_argument('-o', required=True, metavar='file',
                          help='file to write the trace data to')

    parser.add_argument('path_to_target_app', nargs='+',
                        help=argparse.SUPPRESS)

    # I really wanted this newline.
    old_parser_help = parser.format_help()
    parser.format_help = lambda: "\n" + old_parser_help

    return parser.parse_args(argv[1:])


if __name__ == '__main__':

    sys.stderr.write("\x1b[0;36mafl-showmap \x1b[1;37m1.94b")
    sys.stderr.write("\x1b[0m by <d33tah@gmail.com>\n")

    args = parse_cmdline(sys.argv)
    main(args.path_to_target_app, args.o)
