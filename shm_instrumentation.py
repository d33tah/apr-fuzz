#!/usr/bin/env python

import ctypes
import subprocess
import atexit
import sys
import threading
import os

IPC_PRIVATE, IPC_CREAT, IPC_EXCL, IPC_RMID = 0, 512, 1024, 0
MAP_SIZE = 65536
MINUS_ONE = 2**64 - 1

libc = ctypes.cdll.LoadLibrary("libc.so.6")

shmget = libc.shmget
shmat = libc.shmat
shmat.restype = ctypes.c_void_p
shmctl = libc.shmctl
calloc = libc.calloc
calloc.restype = ctypes.c_void_p

libc.__errno_location.restype = ctypes.POINTER(ctypes.c_int)
errno = lambda: libc.__errno_location().contents.value


class SHMInstrumentation(object):

    def __init__(self):
        shm_perms = IPC_CREAT | IPC_EXCL | 0600
        self.shm_id = shmget(IPC_PRIVATE, MAP_SIZE, shm_perms)
        if self.shm_id == MINUS_ONE:
            raise RuntimeError("shmget() failed (%s)" % os.strerror(errno()))
        self.trace_bytes_addr = shmat(self.shm_id, 0, 0)
        if self.trace_bytes_addr == 2**64 - 1:
            raise RuntimeError("shmat() failed (%s)" % os.strerror(errno()))
        self.empty_trace_bytes_addr = calloc(MAP_SIZE, 1)

        atexit.register(self.remove_shm)

    def remove_shm(self):
        if self.shm_id:
            shmctl(self.shm_id, IPC_RMID, 0)
            self.shm_id = None

    def pre_proc_started(self):
        pass

    def post_proc_started(self):
        pass

    def go(self, target, outfile, infile, stderr=sys.stderr, timeout=None):

        ctypes.memmove(self.trace_bytes_addr, self.empty_trace_bytes_addr, MAP_SIZE)

        self.pre_proc_started()
        try:
            infile_fileno = infile.fileno()
        except AttributeError:
            infile_fileno = None
        p_stdin = infile if infile_fileno is not None else subprocess.PIPE

        if timeout is not None:
            p = [None]
            def kill_process(p):
                if p[0]:
                    p[0].kill()
                else:
                    raise RuntimeError("Race condition at p[0].kill")
            timer = threading.Timer(timeout, lambda: kill_process(p))

        p[0] = subprocess.Popen(target, stdin=p_stdin, stderr=stderr,
                                env={'__AFL_SHM_ID': str(self.shm_id)})
        if timeout is not None:
            timer.start()

        try:
            if p_stdin == subprocess.PIPE:
                p[0].stdin.write(infile.read())
                p[0].stdin.close()
        except IOError:  # brobably broken pipe
            raise
        p[0].wait()
        if timeout is not None:
            timer.cancel()
        self.post_proc_started()

        trace_bytes = ctypes.string_at(ctypes.c_void_p(self.trace_bytes_addr),
                                       MAP_SIZE)
        return trace_bytes

if __name__ == '__main__':
    import tempfile
    import StringIO
    import os
    test_c_code = """
        /*
         * A simple program that is not instrumented by American Fuzzy Lop,
         * but behaves as if it was.
         */

        #include <stdlib.h>
        #include <stdio.h>
        #include <sys/types.h>
        #include <sys/shm.h>

        int main() {
            char* shmid_c = getenv("__AFL_SHM_ID");
            if (shmid_c == NULL) {
                printf("__AFL_SHM_ID not set.\\n");
                exit(2);
            }
            int shmid = atoi(shmid_c);
            char* x = shmat(shmid, 0, 0);
            if (x == (char *)-1)
                exit(1);
            x[0] = 1;
            exit(0);
        }
    """
    try:
        with tempfile.NamedTemporaryFile(suffix='.c') as tmp_c_file:
            tmp_c_file.write(test_c_code)
            tmp_c_file.flush()
            compiled = tmp_c_file.name + '.out'
            print("Building the test case...")
            subprocess.call(['gcc', tmp_c_file.name, '-o', compiled])
            print("Testing if sys.stdin is supported...")
            a1 = SHMInstrumentation().go([compiled], sys.stdout, sys.stdin)
            print("Testing if StringIO is supported...")
            a2 = SHMInstrumentation().go([compiled], sys.stdout,
                                         StringIO.StringIO('a'))
            if a1.count('\x00') == MAP_SIZE or a2.count('\x00') == MAP_SIZE:
                print("Instrumentation didn't work - SHM map is empty.")
                sys.exit(1)
            if a1 == a2:
                print("Testing successful.")
                sys.exit()
            else:
                print("Test results don't match.")
                sys.exit(1)
    finally:
            os.unlink(compiled)
