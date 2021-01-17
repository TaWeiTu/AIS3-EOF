from hashlib import md5
import string

data = "a88121e46e48322b13328cebf4fb6c1e"
data_a = bytearray.fromhex(data)

orig_targets = [
    "c35f2bca2f79dcf56c4863b89c80a973",
    "62a474546521780f878ac7651dead037",
    "f8380f4c51a73167f1957f164cd1866d",
    "2431aa540b53d462b4455abc7289a49f",
    "34a7fe7abc1b5715a2ece8bedf263669",
    "13431e915e03b55f838a34f725f508e1",
    "0a06bbde480e4e68e30b3c39d0173080",
    "70d1d1a8b500030188d3fd09e03bd8f0",
    "65a345df725e158b52a806d14432979e",
    "5080d06a9fedc6af6b516175c4af22eb",
    "4cf2b11ae72dbf6ee061a17e283ba900",
    "018f38724d89f59c203351a0b2cf061c",
    "a6b9cfa80e24ca8141a67be5a6a10bab",
    "90084de1b0314a4c5319d6803ceda13f",
    "5bcf5f6f2908744f85bf5cfec245ed56",
    "fea2885bc4d7ef1acfb6d70d720f9e1e",
    "435d2529990c5ee0284627a2ca7f0ee8",
    "3cb14c1dfab3ec40ed331ee5bbddff2e",
]

actual_targets = []

for s in orig_targets:
    s_a = bytearray.fromhex(s)
    for i in range(16):
        s_a[i] ^= data_a[i]
    actual_targets.append(bytes(s_a).hex())

print("\n".join(actual_targets))

print("=== Go ===")

sigma = "_" + string.ascii_lowercase + "} "

for a in sigma:
    for b in sigma:
        for c in sigma:
            for d in sigma:
                for e in sigma:
                    s = a + b + c + d + e
                    s = s.strip()
                    dig = md5(s.encode("ascii")).hexdigest()
                    if dig in actual_targets:
                        print(f"{dig}: {s}")
