#!/usr/bin/env python

import ctypes
import subprocess
import atexit

IPC_PRIVATE, IPC_CREAT, IPC_EXCL, IPC_RMID = 0, 512, 1024, 0
MAP_SIZE = 65536

shmget = ctypes.cdll.LoadLibrary("libc.so.6").shmget
shmat = ctypes.cdll.LoadLibrary("libc.so.6").shmat
shmat.restype = ctypes.POINTER(ctypes.c_char * MAP_SIZE)
shmctl = ctypes.cdll.LoadLibrary("libc.so.6").shmctl


def atexit_handler(shm_id):
    shmctl(shm_id, IPC_RMID, 0)


def main():

    shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600)
    atexit.register(atexit_handler, shm_id)

    print('-- Program output begins --')
    p = subprocess.Popen('./hello', shell=True,
                         env={'__AFL_SHM_ID': str(shm_id)})
    p.wait()
    print('-- Program output ends --')

    trace_bytes = shmat(shm_id, 0, 0)[0]

    for i in range(MAP_SIZE):
        if trace_bytes[i] == '\x00':
            continue
        print("%06u:%u" % (i, ord(trace_bytes[i])))

if __name__ == '__main__':
    main()
