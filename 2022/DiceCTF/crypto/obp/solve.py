import random

with open('obp.output.txt', 'r') as f:
    plaintext = bytearray.fromhex(f.read())

# print(plaintext)

for i in range(256):
    random.seed(i)
    key = random.randrange(256)
    ciphertext = [key ^ byte for byte in plaintext]

    print(bytes(ciphertext))

# hope{not_a_lot_of_keys_mdpxuqlcpmegqu}