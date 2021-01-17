import sys
from data import data_bytes

assert len(sys.argv) == 3

src = sys.argv[1]
dest = sys.argv[2]

data = bytes.fromhex(data_bytes)

print(len(data))

with open(src, "rb") as f:
    readme_data = f.read()

TH = 5
cnt = 0

for i in range(len(data)):
    ok = True
    for j in range(TH):
        if readme_data[len(readme_data) - j - 1] != data[(i - j) % len(data)]:
            ok = False
            break
    if ok:
        cnt += 1
        target = bytearray(readme_data)  
        assert target[-1] ^ data[i] == 0
        for j in range(len(readme_data)):
            target[-j - 1] = target[-j - 1] ^ data[(i - j) % len(data)]
        target = bytes(target)
        target = target.rstrip(b"\x00")
        with open(dest, "wb") as f:
            f.write(target)

if cnt != 1:
    print(cnt)
    assert cnt == 1
