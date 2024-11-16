import re
import os
import random
import argparse
import hmac
import time
import pyotp
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import subprocess

# QUESTION

# Implement QR code ?
# Implement UX ?
# Doc auto / integrer 

# ---------------------------
# Global variable
# ---------------------------

# ENcryption / DEcrytpion keyS
aes_key = b'[\xfe\x02\x05\x8e\x8fk\xbe\x1e\xa2\xd1\xc5o\xa0\xef\xea\xcb\xca\xa7y`\x87\x1c\xc06\x17\x99U\x0b5\xcd\x9a'
iv = b')9\xa2\x1e\xc2NBc\x11\xa2oC\x17t\xdb?'

# Hash method
sha_mode="sha512"


# ---------------------------
# Key generation
# ---------------------------
def check_key_format(hex_str: str):
        
        if (re.fullmatch(r'^[0-9a-fA-F]{64}$', hex_str)) is None:
            return False
        return True


def aes_256_encrypt(data: bytes):
    # Pad data to make it 16 bytes block
    # Necessary for AES 256 encryption
    padded_data = pad(data, AES.block_size) 
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    encrypted_data = cipher.encrypt(padded_data)
    
    return encrypted_data


def gen_totp_key(hex_file):

    try :
        hex_str = hex_file.read()

        if check_key_format(hex_str) == False:
            return print("Error : key must be 64 hexadecimal characters.")
        
        byte_str = hex_str.encode('utf-8')
        encrypted_data = aes_256_encrypt(byte_str)
        
        with open('ft_otp.key', 'wb') as file:
            file.write(encrypted_data)

    except Exception as e:
        print(f"{e}")
    return




# ---------------------------
# TOTP code generation
# ---------------------------

# Create a pseudo-random Offset value
def get_offset(hash_b: bytes):

    # Get value from the last 4 bits of the HASH last byte
    hash_len = len(hash_b)
    last_byte = hash_b[hash_len - 1]
    offset = last_byte & 0b1111
    return offset


# RFC mandatory, totp is made of the last 31 bits of the selected bytes
def get_last_31_bits(p: bytes):
    s_bits = ((p[0]  & 0b01111111)  << 24   # 0x7f delete the first bit
        | (p[1] & 0b11111111)       << 16   # 0xff
        | (p[2] & 0b11111111)       <<  8   # 0xff
        | (p[3] & 0b11111111))              # 0xff
    return s_bits


# Truncate the (20 or 64) bytes long hash to a 31 BITS long string 
def dynamic_truncation(hash_b: bytes):
    
    offset = get_offset(hash_b)
    p = hash_b[offset:offset + 4] # Select 4 bytes block w/ offset value as start idx
    s_bits = get_last_31_bits(p)  # s_bits = selected bits
    return s_bits

# RFC 4226 : https://www.rfc-editor.org/rfc/rfc4226
# HOTP(K, C) algorithm
# K = Key       // Secret Key shared symmetrically btw client & server
# C = Counter   // Simple count (0,1 ,2 ...) incremented after each authentication attempt 
def hotp_algo(key : bytes, time_value: int):
    
    c = time_value.to_bytes(8, byteorder='big')
    hash_obj = hmac.new(key, c, sha_mode)
    hash_b= hash_obj.digest() # Convert hash object to byte object
    s_bits = dynamic_truncation(hash_b)
    # Current totp is too long
    # This calcultation makes it 6 digit long
    totp_code = s_bits % (10 ** 6)
    
    return f"{totp_code:06}"


# RFC 6238 : https://www.rfc-editor.org/rfc/rfc6238
# TOTP algo, reimplementation of HOTP
# TOTP reimplementat HOTP(K,C) --->  HOTP(K, T) 
# T = current time / 30 sec
def totp_algo(k: bytes):

    unix_cur_time = time.time()
    t = 30
    time_value = int(unix_cur_time / t)
    return hotp_algo(k, time_value)


def aes_256_decrypt(encrypted_key: bytes):
    # Pad data to make it 16bytes block which is necessary for AES 256 encryption
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_key = cipher.decrypt(encrypted_key)
    key = unpad(decrypted_key, AES.block_size) 
    return key

def gen_totp_code(key_file, tester: int):
    
    encrypted_key = key_file.read()
    key = aes_256_decrypt(encrypted_key)
    
    # Loop for option -t
    for j in range(tester):
    
        code = totp_algo(key)
        pycode = pyotp.TOTP(base64.b32encode(key), digest=sha_mode)
        oathtool_output = subprocess.check_output(f"oathtool --totp={sha_mode} {key.hex()}", shell=True).decode().strip()
        print(f'{"Ft_OTP    :":<12} {code} <--')
        print(f'{"Oathtool  :":<12} {oathtool_output}')
        print(f'{"PyOTP     :":<12} {pycode.now()}\n')
        key = os.urandom(32)

    return


# ---------------------------
# Argument parsing
# ---------------------------

def argparsing():
    parser = argparse.ArgumentParser(
                        prog="ft_otp.py",
                        usage="python3 ft_otp.py -g [HexString64]\npython3 ft_otp.py -k [file.key] -t [1-20]",
                        description="Generates Key File or TOTP Authtentication code"
                        )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-g", dest="hex_file", type=argparse.FileType("r"), help="Generate key file from hex string")
    group.add_argument("-k", dest="key_file",type=argparse.FileType("rb"), help="Generate TOTP code from key file")
    parser.add_argument("-t", dest="tester", type=int, default=1, choices=range(1,20), help="Test ft_otp againt PyOTP and Oathtool (must be between 1-20)")
    args = parser.parse_args()
    return args


def main():
    args = argparsing()

    if args.tester and not args.key_file:
        print("Error : Option -t can only be used together with -k")
        return

    if args.hex_file is not None:
        gen_totp_key(args.hex_file)
    elif args.key_file is not None:
        gen_totp_code(args.key_file, args.tester)
    return


if __name__ == "__main__":
    main()