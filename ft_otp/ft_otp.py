import re
import argparse
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import hmac
import time
import sys


# QUESTION
# Python bytes ARRAY ?
# Why AES 256 ? --> (safe; common; secure; NASA approved)
# Why CBC  ? 

# - g "[64HEXSTRING]" --> key.hex
# file.key =  encrypted file  

# Bad practice but required by the project
aes_key = b'[\xfe\x02\x05\x8e\x8fk\xbe\x1e\xa2\xd1\xc5o\xa0\xef\xea\xcb\xca\xa7y`\x87\x1c\xc06\x17\x99U\x0b5\xcd\x9a'
iv = b')9\xa2\x1e\xc2NBc\x11\xa2oC\x17t\xdb?'
password = b"ThisIsAPassword!"

class TOTP:
    def __init__(self, hex_file=None, key_file=None):
        self.hex_file = hex_file
        self.key_file = key_file
        self._aes_key=aes_key
        self._iv=iv
        self._password= password
        return
    
    def __str__(self):
        return f"Class TOTP g = {self.hex_file} k = {self.key_file}"


def check_key_format(hex_str: str):
        
        if (re.fullmatch(r'^[0-9a-fA-F]{64}$', hex_str)) is None:
            return False
        return True

def aes_256_encrypt(totp: TOTP, data: bytes):
    # Pad data to make it 16bytes block
    # Necessary for AES 256 encryption
    padded_data = pad(data, AES.block_size) 
    cipher = AES.new(totp._aes_key, AES.MODE_CBC, iv=totp._iv)
    # cipher = AES.new(totp._password, AES.MODE_CBC, iv=totp._iv)

    encrypted_data = cipher.encrypt(padded_data)
    
    return encrypted_data

def gen_totp_key(totp: TOTP):
    # Check key format
    # Encrypt w/AES256
    # Save it in  key.hex locally
    # Handle Error
        # Read / Open error
        # Str wrong format
        # Encryption fail 
    # --> password ?
    try :
        hex_str = totp.hex_file.read()

        if check_key_format(hex_str) == False:
            return print_error("key must be 64 hexadecimal characters.")
        
        byte_str = hex_str.encode('utf-8')
        encrypted_data = aes_256_encrypt(totp, byte_str)
        
        with open('ft_otp.key', 'wb') as file:
            file.write(encrypted_data)
        print(f"byte_str {byte_str}")
        print(f"encrypted_data {encrypted_data}")

    except Exception as e:
        print(f"{e}")
    return



# Truncate the (20 or 64) bytes long hash to a 31 BITS long string
# Truncation is describred in RFC 4226
def dynamic_truncation(h_bytes: bytes):
    # Create an Offset from the last 4 bits of the specific 20th byte  = h_bytes[19]
    target_byte = h_bytes[19]
    offset = target_byte & 0b00001111  # RFC alternative : offset = target_byte & 0xf
    # Select a 4 bytes block using offset value as a start
    P = h_bytes[offset:offset + 4]
    # Return 31bits of P 
    binary_code = ((P[0]  & 0b01111111) << 24 # 0x7f delete the first bit
        | (P[1] & 0b11111111) << 16 # 0xff
        | (P[2] & 0b11111111) <<  8 # 0xff
        | (P[3] & 0b11111111))      # 0xff
    
    return binary_code



def truncate_hash_to_otp(h_bytes: bytes):
    binary_code = dynamic_truncation(h_bytes)
    #binary_code value is too long, we convert it to get a 6digit code
    digit_code = binary_code % (10 ** 6)
    print(binary_code)
    print(digit_code)
    return 0

def hotp_algo(key : bytes, counter: int):

    hash_obj = hmac.new(key, counter, "sha512")
    hash_bytes = hash_obj.digest()
    code = truncate_hash_to_otp(hash_bytes)

def totp_algo(k: bytes):
    unix_cur_time = time.time()
    timestep = 30
    timevalue = int(unix_cur_time / timestep)
    c = timevalue.to_bytes(8, byteorder='big')

    #HOTP initial is HMAC(k, c), we replace C by the time value
    code = hotp_algo(k, c)

def aes_256_decrypt(totp: TOTP, encrypted_key: bytes):
    # Pad data to make it 16bytes block which is necessary for AES 256 encryption
    cipher = AES.new(totp._aes_key, AES.MODE_CBC, iv=totp._iv)
    decrypted_key = cipher.decrypt(encrypted_key)
    key = unpad(decrypted_key, AES.block_size) 
    return key

def gen_totp_code(totp: TOTP):

    #Decrypt data
    encrypted_key = totp.key_file.read()
    key = aes_256_decrypt(totp, encrypted_key)
    # TOTP = HOTP(K, C) --> HOTP( K, ( Time / timestep ) ) )
    # HOTP = HMAC_SHA1(K, C)
    # HMAC-SHA256/512(K, C)
    # K = Key / secret
    # C = Counter incremented after each OTP attmempt
    code = totp_algo(key)



    return


def print_error(err_msg: str):
    print(f"Error : {err_msg}")
    return

def argparsing():
    parser = argparse.ArgumentParser(
                        prog="ft_otp.py",
                        usage="npython3 ft_otp.py [ -g [HexString64] ] [ -k [file.key] ]",
                        description="Generates Key File or TOTP Authtentication code"
                        #"-g : Generate key file\n-t : Generate TOTP code2FA Authentication"
                        )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-g", type=argparse.FileType("r"), help="Generate key file from hex string")
    group.add_argument("-k", type=argparse.FileType("rb"), help="Generate TOTP code from key file")
    args = parser.parse_args()
    return args

def main():
    args = argparsing()

    totp = TOTP(args.g, args.k)

    if totp.hex_file is not None:
        gen_totp_key(totp)
    elif totp.key_file is not None:
        gen_totp_code(totp)
    return

if __name__ == "__main__":
    main()