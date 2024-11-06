
#  TOTP = Truncate( HMAC-SHA256/512( K,( Time / timestep ) ) )
# K = secret
# T = current Unix time
# timestep = 30 sec

# - g "[64HEXSTRING]" --> key.hex
# key.hex =  encrypted file  
import re
import argparse

class TOPT:
    def __init__(self, g_opt=None, k_opt=None):
        self.g_opt = g_opt
        self.k_opt = k_opt
        return
    
    def __str__(self):
        return f"Class TOPT g = {self.g_opt} k = {self.k_opt}"

    def gen_key(self):
        return
    
    def gen_topt(self):
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

    topt = TOPT(args.g, args.k)
    print(topt)

    if topt.g_opt is not None:
        topt.gen_key()
    elif topt.k_opt is not None:
        topt.gen_totp()
   # print(f"attr : {args}")
    return

if __name__ == "__main__":
    main()