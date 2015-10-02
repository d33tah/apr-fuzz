#!/usr/bin/env python

import ctypes
import subprocess
import atexit
import sys
import threading
import os
import io

IPC_PRIVATE, IPC_CREAT, IPC_EXCL, IPC_RMID = 0, 512, 1024, 0
MAP_SIZE = 65536

libc = ctypes.CDLL(None, use_errno=True)

shmget = libc.shmget
shmat = libc.shmat
shmat.restype = ctypes.c_void_p
shmctl = libc.shmctl
calloc = libc.calloc
calloc.restype = ctypes.c_void_p

do_nothing = lambda *args, **kwargs: None


class SHMInstrumentation(object):

    def __init__(self):

        # set up SHM
        shm_perms = IPC_CREAT | IPC_EXCL | int('0600', 8)
        self.shm_id = shmget(IPC_PRIVATE, MAP_SIZE, shm_perms)
        if self.shm_id == -1:
            error_string = os.strerror(ctypes.get_errno())
            raise RuntimeError("shmget() failed (%s)" % error_string)

        # actually get the buffer SHM points to
        self.trace_bytes_addr = shmat(self.shm_id, 0, 0)
        if self.trace_bytes_addr == ctypes.c_void_p(-1).value:
            error_string = os.strerror(ctypes.get_errno())
            raise RuntimeError("shmat() failed (%s)" % error_string)

        # we might need to clean the buffer between executions - let's
        # create a backup buffer so we can just use memmove()
        self.empty_trace_bytes_addr = calloc(MAP_SIZE, 1)

        # whatever happens, remove the SHM before exiting the application
        atexit.register(self.remove_shm, shmctl)

    def remove_shm(self, shmctl):
        if self.shm_id:
            shmctl(self.shm_id, IPC_RMID, 0)
            self.shm_id = None

    def go(self, target, outfile, infile, stderr=sys.stderr, timeout=None,
           pre_proc_started=do_nothing, post_proc_started=do_nothing):

        crashed = [False]
        hung = [False]

        # clean the SHM buffer in case we reuse the SHMInstrumentation object
        ctypes.memmove(self.trace_bytes_addr, self.empty_trace_bytes_addr,
                       MAP_SIZE)

        pre_proc_started()

        # support cStringIO - if we can't get the file number, we'll use pipes
        # instead of forwarding the fd to the subprocess
        try:
            infile_fileno = infile.fileno()
        except AttributeError:
            infile_fileno = None
        except io.UnsupportedOperation:
            infile_fileno = None
        p_stdin = infile if infile_fileno is not None else subprocess.PIPE

        p = [None]
        if timeout is not None:

            def kill_process(p, hung):
                if p[0]:
                    p[0].kill()
                    hung[0] = True
                else:
                    raise RuntimeError("Race condition at p[0].kill")
            timer = threading.Timer(timeout, lambda: kill_process(p, hung))

        p[0] = subprocess.Popen(target, stdin=p_stdin, stderr=stderr,
                                env={'__AFL_SHM_ID': str(self.shm_id)})
        if timeout is not None:
            timer.start()

        if p_stdin == subprocess.PIPE:
            p[0].stdin.write(infile.read())
            p[0].stdin.close()

        p[0].wait()

        if timeout is not None:
            timer.cancel()
        post_proc_started()

        if p[0].returncode < 0 and p[0].returncode != -9:
            crashed[0] = p[0].returncode

        trace_bytes = ctypes.string_at(ctypes.c_void_p(self.trace_bytes_addr),
                                       MAP_SIZE)

        return trace_bytes, crashed[0], hung[0]

if __name__ == '__main__':
    import tempfile
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
                                         io.StringIO(u'a'))
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
