from pwn import *
r = remote("eofqual.zoolab.org", 10110)
r.recvuntil(": ")
cipher = r.recvuntil("\n", drop=True)
cipher = cipher[:-32]
cipher = bytes.fromhex(cipher.decode("utf-8"))
man = b'\xe7\x94\xb7'
after_key = b''
print(cipher.hex())
def valid(res):
	res = res.decode('utf-8')
	return (res == '系統訊息: 對方離開了，請按離開按鈕回到首頁') or (res == '陌生人: 哈哈哈哈')
def xor_bytes(a, b, start = 0):
	return a[:start] + bytes([int(a[i+start])^int(b[i]) for i in range(len(b))])+a[start+len(b):]

for block in range(1,4):
	set_zero = b''
	arr = [0]*3
	for first_bits in range(256):
		set_zero = b''
		for i in range(8):
			if first_bits & 1 << i:
				set_zero = set_zero + b'\x80'
			else:
				set_zero = set_zero + b'\x00'
		guess = set_zero + cipher[block*8:(block+1)*8]
		r.sendlineafter('輸入訊息: ', guess.hex())
		res = r.recvline(keepends=False)
		if valid(res):
			check_flag = True
			for i in range(8):
				tmp = xor_bytes(set_zero, b'\x40', i)
				check = tmp + cipher[block*8:(block+1)*8]
				r.sendlineafter('輸入訊息: ', check.hex())
				res = r.recvline(keepends=False)
				if not valid(res):
					check_flag = False
			if check_flag:
				break
	for arr[0] in range(0, 128, 1<<4):
		arr[0] = arr[0] + (1 - (set_zero[0]>>7))*128
		find = False
		for arr[1] in range(0, 128, 1<<6):
			arr[1] = arr[1] + (1 - (set_zero[1]>>7))*128
			for arr[2] in range(0, 128, 1<<6):
				arr[2] = arr[2] + (1 - (set_zero[2]>>7))*128
				guess = bytes(arr[:3]) + set_zero[3:] + cipher[block*8:(block+1)*8]
				r.sendlineafter('輸入訊息: ', guess.hex())
				res = r.recvline(keepends=False)
				if valid(res):
					offset = [0]*3
					for offset[0] in range(1<<4):
						print("offset[0]: ",offset[0])
						for offset[1] in range(1<<6):
							for offset[2] in range(1<<6):
								tmp = [0]*3
								for i in range(3):
									tmp[i] = arr[i]+offset[i]
								guess = bytes(tmp[:3]) + set_zero[3:] + cipher[block*8:(block+1)*8]
								r.sendlineafter('輸入訊息: ', guess.hex())
								res = r.recvline(keepends=False)
								# print(res.decode("utf-8"))
								if res.decode("utf-8") == '系統訊息: 對方離開了，請按離開按鈕回到首頁':
									print("find block ", block, " first 3 bytes")
									find = True
									after_key = after_key + xor_bytes(bytes(tmp[:3]), man)
									break
							if find:
								break
						if find:
							break
			if find:
				break
		if find:
			break
	print(after_key)
	for i in range(3,8):
		print(i)
		for base in range(0, 128, 1<<6):
			base = base + (1 - (set_zero[i]>>7))*128
			guess = set_zero[:i-2] + xor_bytes(after_key[-2:], man[:2]) \
			+ base.to_bytes(1,byteorder = "little")+ set_zero[i+1:] \
			+ cipher[block*8:(block+1)*8]
			r.sendlineafter('輸入訊息: ', guess.hex())
			res = r.recvline(keepends=False)
			if valid(res):
				for offset in range(1<<6):
					guess = set_zero[:i-2] + xor_bytes(after_key[-2:], man[:2]) \
					+ (base+offset).to_bytes(1,byteorder = "little")+ set_zero[i+1:] \
					+ cipher[block*8:(block+1)*8]
					r.sendlineafter('輸入訊息: ', guess.hex())
					res = r.recvline(keepends=False)
					if res.decode("utf-8") == '系統訊息: 對方離開了，請按離開按鈕回到首頁':
						print(i)
						after_key = after_key + ((base+offset)^man[2]).to_bytes(1,byteorder='little')
						break
				print(after_key)
				break
	print("done block ", block)
	print("after_key: ", after_key)
	
flag = xor_bytes(cipher[:24],after_key)
print(flag.decode("utf-8"))