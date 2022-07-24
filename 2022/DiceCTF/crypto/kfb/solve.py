
input_plain = 'A' * 16
input_enc = "76bc16a9f5b95995e83aa5d4472d4e41"

flag_enc = "0ec376dc9ec22fe7a759ddab22513a0e15d86fda8ef63deaa759c1b1315b013903f36dd78ade3ada9a1986f16f593c6603943e8a80cd7cb1852db2c3503a5956"

def brute_key(plain, enc):
    '''brute force the key. enc is hex, plain is ascii'''
    enc = bytes.fromhex(enc)
    key = ""
    for i, v in enumerate(enc):
        for j in range(256):
            if chr(v ^ j) == plain[i]:
                key += j.to_bytes(1, "big").hex()
                break
    return key

def xor_enc(enc, key):
    '''xor the enc with the key. enc is hex, key is hex'''
    key = bytes.fromhex(key)
    enc = bytes.fromhex(enc)
    flag = ""
    for i, v in enumerate(enc):
        s = v ^ key[i % len(key)]
        flag += chr(s)
    return flag.encode("ascii").hex()

def get_patern():
    '''make dictionary of patern, and return dictionary of key and value,
    where the key is the hex patern and the value is the ascii patern'''
    patern_hex = "3033323534373639383b3a3d3c3f3e212023222524272629282b1013121514171619181b1a1d1c1f1e010003020504070609080b606362656467666968612a2c0e"
    patern_hex = [patern_hex[i:i+2] for i in range(0, len(patern_hex), 2)]    
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890{}_"
    lst = dict()
    for i, v in enumerate(alphabet):
        lst[patern_hex[i]] = v
    return lst

def translate_patern(enc):
    '''translate the hex patern to ascii, where enc is hex'''
    enc = [enc[i:i+2] for i in range(0, len(enc), 2)]
    patern = get_patern()
    text = ""
    try:
        for i in enc:
            text += patern[i]
    except:
        return text
    return text

key = brute_key(input_plain, input_enc)
ugly_flag = xor_enc(flag_enc, key)

flag = (translate_patern(ugly_flag))

print(flag)