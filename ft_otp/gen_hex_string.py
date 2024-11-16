import os

totp_key = os.urandom(32)

print(totp_key.hex(), end='')