#!/usr/bin/env python

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


class SHMInstrumentation(object):

    def __init__(self):
        self.shm_id = None

    def remove_shm(self):
        if self.shm_id:
            shmctl(self.shm_id, IPC_RMID, 0)
            self.shm_id = None

    def pre_proc_started(self):
        pass

    def post_proc_started(self):
        pass

    def go(self, target, outfile, infile):

        shm_perms = IPC_CREAT | IPC_EXCL | 0600
        self.shm_id = shmget(IPC_PRIVATE, MAP_SIZE, shm_perms)
        atexit.register(self.remove_shm)

        self.pre_proc_started()
        try:
            infile_fileno = infile.fileno()
        except AttributeError:
            infile_fileno = None
        p_stdin = infile if infile_fileno is not None else subprocess.PIPE
        p = subprocess.Popen(target, stdin=p_stdin,
                             env={'__AFL_SHM_ID': str(self.shm_id)})
        if p_stdin == subprocess.PIPE:
            p.stdin.write(infile.read())
        p.wait()
        self.post_proc_started()

        trace_bytes = shmat(self.shm_id, 0, 0)[0]
        shmctl(self.shm_id, IPC_RMID, 0)
        self.shm_id = None
        return trace_bytes.raw

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
            if a1 == a2:
                print("Testing successful.")
                sys.exit()
            else:
                print("Test results don't match.")
                sys.exit(1)
    finally:
            os.unlink(compiled)
