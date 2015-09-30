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

        target_cmd = ' '.join(target)

        self.pre_proc_started()
        p = subprocess.Popen(target, stdin=infile,
                             env={'__AFL_SHM_ID': str(self.shm_id)})
        p.wait()
        self.post_proc_started()

        trace_bytes = shmat(self.shm_id, 0, 0)[0]
        shmctl(self.shm_id, IPC_RMID, 0)
        self.shm_id = None
        return trace_bytes


