
#  TOTP = Truncate( HMAC-SHA256/512( K,( Time / timestep ) ) )
# K = secret
# T = current Unix time
# timestep = 30 sec

# QUESTION
# Python bytes ARRAY ?
# Why AES 256 ? --> (safe; common; secure; NASA approved)
# Why CBC  ? 

# - g "[64HEXSTRING]" --> key.hex
# key.hex =  encrypted file  
import re
import argparse
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad


# Bad practice but required by the project

class TOPT:
    def __init__(self, hex_file=None, secret_file=None):
        self.hex_file = hex_file
        self.secret_file = secret_file
        self._aes_key=b'[\xfe\x02\x05\x8e\x8fk\xbe\x1e\xa2\xd1\xc5o\xa0\xef\xea\xcb\xca\xa7y`\x87\x1c\xc06\x17\x99U\x0b5\xcd\x9a'
        self._iv=b')9\xa2\x1e\xc2NBc\x11\xa2oC\x17t\xdb?'
        self._password=b"ThisIsAPassword!"
        return
    
    def __str__(self):
        return f"Class TOPT g = {self.hex_file} k = {self.secret_file}"


def check_key_format(hex_str):
        
        if (re.fullmatch(r'^[0-9a-fA-F]{64}$', hex_str)) is None:
            return False
        return True

def aes_256_encrypt(totp, data):
    # Pad data to make it 16bytes block which is necessary for AES 256 encryption
    padded_data = pad(data, AES.block_size) 
    cipher = AES.new(totp._aes_key, AES.MODE_CBC, iv=totp._iv)
    encrypted_data = cipher.encrypt(padded_data)
    return encrypted_data

def gen_totp_key(totp):
    # Encrypt w/AES256
    # Save it in  key.hex locally
    # Handle Error
        # Read / Open error
        # Str wrong format
        # Encryption fail 
    # --> password ?
    try :
        hex_str = totp.hex_file.read()
    
        # Check that string is Base64Hex format
        if check_key_format(hex_str) == False:
            return print_error("key must be 64 hexadecimal characters.")
        byte_str = hex_str.encode('utf-8')
        encrypted_data = aes_256_encrypt(totp, byte_str)
        print(encrypted_data)



    except Exception as e:
        print(f"{e}")
    return

def gen_totp_code(totp):
    return


def print_error(err_msg):
    print(f"Error : {err_msg}")
    return

def argparsing():
    parser = argparse.ArgumentParser(
                        prog="ft_otp.py",
                        usage="npython3 ft_otp.py [ -g [HexString64] ] [ -k [file.key] ]",
                        description="Generates Key File or TOPT Authtentication code"
                        #"-g : Generate key file\n-t : Generate TOPT code2FA Authentication"
                        )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-g", type=argparse.FileType("r"), help="Generate key file from hex string")
    group.add_argument("-k", type=argparse.FileType("r"), help="Generate TOTP code from key file")
    args = parser.parse_args()
    return args

def main():
    args = argparsing()

    totp = TOPT(args.g, args.k)

    if totp.hex_file is not None:
        gen_totp_key(totp)
    elif totp.key_file is not None:
        gen_totp_code(totp)
    return

if __name__ == "__main__":
    main()