import os
from pwn import *

r = remote("eofqual.zoolab.org", 10111)
# r = process(["python3", "server.py"])

def print_as_bin(b):
    for i in range(len(b)):
        print("{:>08b}".format(b[i]), end="|" if i + 1 != len(b) else "\n")

def query(s: bytes):
    # Return true if valid
    assert len(s) % 8 == 0
    r.sendlineafter("輸入訊息: ", s.hex())
    res = r.recvline(keepends=False).decode("utf-8")
    if res == "陌生人: 哈哈哈哈":
        return True
    elif res == "(訊息無法傳出...)":
        return False
    else:
        print(f"Error: {res}")
        exit(1)
        
def find_1(iv: bytes, block: bytes, num: int = 8) -> bytes:
    assert len(iv) == 8 and len(block) >= num
    ivarr, blockarr = bytearray(iv), bytearray(block)
    for I in range(1<<num):
        btarr = bytearray(((I>>i)&1)<<7 for i in range(num))
        qrarr = ivarr + blockarr
        for i in range(num):
            qrarr[i] ^= btarr[i]

        res = query(bytes(qrarr))
        if not res: continue

        for i in range(num):
            qrarr[i] ^= (1<<6)

        res = query(bytes(qrarr))
        if res: return bytes(btarr)
    return None

def find_23(iv: bytes, block: bytes, current: bytes, num: int = 8, pad: list = None) -> bytes:
    assert len(iv) == 8 and len(block) >= num and len(current) >= num
    ivarr, blockarr = bytearray(iv), bytearray(block)
    for i in range(num):
        end = (1<<7) if i == 0 else (1<<6)
        flag = False
        for I in range(0, end, (1<<5)):
            for J in range(0, (1<<7), (1<<6)):
                print(i, I, J)
                btarr = bytearray(current)
                if i + 1 < len(block):
                    qrarr = ivarr + blockarr
                else:
                    qrarr = ivarr + blockarr + pad[1]
                btarr[i] ^= I
                if i + 1 < len(block): 
                    btarr[i + 1] ^= J
                for j in range(len(current)):
                    qrarr[j] ^= btarr[j]
                qrarr[i] ^=     0b11000000
                if i + 1 < len(block):
                    qrarr[i + 1] ^= 0b10000000
                res = query(qrarr)
                if not res:
                    qrarr[i] ^= 0b00010000
                    res = query(qrarr)
                if res:
                    current = bytes(btarr)
                    flag = True
                if flag: break
            if flag: break
        assert flag
    return current

def find_4_or_up(idx: int, iv: bytes, block: bytes, current: bytes, pad: list = None) -> bytes:  
    assert idx >= 4 and idx <= 5
    assert len(iv) == 8 and len(block) == 8 and len(current) == 8
    ivarr, blockarr = bytearray(iv), bytearray(block)
    ofs = 8 - idx
    for i in range(8):
        flag = False
        for I in range(0, (1<<(ofs + 1)), (1<<ofs)):
            print(idx, i, I)
            btarr = bytearray(current)
            qrarr = ivarr + blockarr
            btarr[i] ^= I

            for j in range(8):
                qrarr[j] ^= btarr[j]

            qrarr[i] ^= ((1<<(idx - 1)) - 1) << (ofs + 1)

            if i + idx - 2 >= len(current):
                qrarr += pad[i + idx - 1 - len(current)]

            for j in range(i + 1, i + idx - 1):
                if j < len(current):
                    qrarr[j] ^= 0b10000000

            # if idx >= 5:
            #     print_as_bin(btarr)
            #     print_as_bin(iv)
            #     print_as_bin(qrarr)

            res = query(qrarr)
            if not res:
                qrarr[i] ^= 1 << (ofs - 1)
                res = query(qrarr)
                if res:
                    print(f"Flip: {i}")
            if res:
                current = bytes(btarr)
                flag = True
            if flag: break
        assert flag
    return current

# flag = open("flag", "rb").read()

# print_as_bin(flag)

r.recvuntil(": ")
dat = r.recvline(keepends=False)
cipher, md5_digest = dat[:-32], dat[-32:]

cipher = bytes.fromhex(cipher.decode("utf-8"))
cipher = [ cipher[i:i + 8] for i in range(0, len(cipher), 8) ]

# cipher = cipher[:-1]

current = [ cipher[0] ] + [ bytearray(8) for _ in range(1, len(cipher)) ]

pad = [ [ None ] * 4 for _ in range(len(cipher)) ]

print(f"MD5: {md5_digest}") 

for i in range(1, len(cipher)):
    while True:
        candi = os.urandom(8)
        res = find_1(cipher[i], candi, 4)
        if res is None: continue
        for j in range(4):
            if res[j] == 0x00:
                L = j
                break
        else:
            continue

        if L == 0 or pad[i][L] is not None: continue

        qrarr = bytearray(cipher[i]) + bytearray(candi)
        for j in range(L):
            qrarr[j] ^= 0x80
        if not query(bytes(qrarr)): continue

        res = find_23(cipher[i], candi, res, L)
        ok = True
        for j in range(L):
            if res[j] >= 0xc0: ok = False
        if ok:
            pad[i][L] = candi
            print(f"Get: {i} {L}")
            ok = True
            for j in range(1, 4):
                if pad[i][j] is None: ok = False
            if ok:
                break
    print("Finish:", i)

print(cipher)
print(pad)

for i in range(1, len(cipher)):
    print(f"=== 1 {i} ===")
    current[i] = find_1(cipher[i - 1], cipher[i])

for i in range(1, len(cipher)):
    print(f"=== 23 {i} ===")
    current[i] = find_23(cipher[i - 1], cipher[i], current[i], pad=pad[i])
    print_as_bin(current[i])

for j in range(4, 6):
    for i in range(1, len(cipher)):
        print(f"=== {j} {i} ===")
        current[i] = find_4_or_up(j, cipher[i - 1], cipher[i], current[i], pad=pad[i])

# print(flag)
for i in range(1, len(cipher)):
    cur = bytearray(current[i])
    for j in range(8):
        # known = 5 if j <= 4 else 9 - j
        known = 5
        fmtstr = "{:>0" + str(known) + "b}" + "x" * (8 - known)
        # if (i - 1) * 8 + j < len(flag):
        #     print(fmtstr.format(cur[j]>>(8 - known)) + " | " + "{:>08b}".format(flag[(i - 1) * 8 + j]))
        # else:
        print(fmtstr.format(cur[j]>>(8 - known)))
    

