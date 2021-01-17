import json
import typing
from base64 import b64decode, b64encode

import itsdangerous
from itsdangerous.exc import BadTimeSignature, SignatureExpired

secret_key = "Ludibrium-Secret-133.221.333.123.111_kvYAtbZkwkhyPv5B"
signer = itsdangerous.TimestampSigner(str(secret_key))

data = {"id": 0, "filenames": [], "debug": True}

data = b64encode(json.dumps(data).encode("utf-8"))
data = signer.sign(data).decode("utf-8")

print(data)
