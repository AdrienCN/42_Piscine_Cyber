import os

totp_key = os.urandom(32)

print(totp_key)
print(totp_key.hex())

iv_key = os.urandom(16)

print(iv_key)
print(iv_key.hex())