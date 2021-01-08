from PIL import Image

W = 11
H = 13

img = []
for i in range(W * H):
    img.append(Image.open(f'./data/{i + 1}.jpg'))

img = img[::-1]

print(img[0])

Ws = 152 * W
Hs = 152 * H

I = Image.new('RGB', (Ws, Hs))

for i in range(H):
    for j in range(W):
        I.paste(img[i * W + j], (j * 152, i * 152))

I.show()

# for i in range(H):
#     s = 0
#     for j in range(W):
#         s += img[i * W + j].width
#     print(s)
# 
# for j in range(W):
#     s = 0
#     for i in range(H):
#         s += img[i * W + j].height
#     print(s)
