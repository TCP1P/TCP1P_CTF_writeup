from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

private_key = RSA.import_key(open('privatekey.pem').read())
cipher_rsa = PKCS1_OAEP.new(private_key)
with open('encrypted.bin', 'rb') as f:
	enc = f.read()
flag = cipher_rsa.decrypt(enc)
print(flag)