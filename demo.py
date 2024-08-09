from Crypto.Cipher import AES as A
from Crypto.Cipher import ARC4 as R
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def e_a(m, k):
    c = A.new(k, A.MODE_CBC)
    t, i = c.encrypt(pad(m.encode(), A.block_size)), c.iv
    return t, i

def d_a(ciphertext, k, iv):
    c = A.new(k, A.MODE_CBC, iv)
    return unpad(c.decrypt(ciphertext), A.block_size).decode()

def e_r(m, k):
    c = R.new(k)
    return c.encrypt(m.encode())

def d_r(ciphertext, k):
    c = R.new(k)
    return c.decrypt(ciphertext).decode()
print("Sender")
m = input("Enter the message to encrypt: ")
k_a = get_random_bytes(16)
k_r = get_random_bytes(16)

e_a_res, iv_a = e_a(m, k_a)
d_a_res = d_a(e_a_res, k_a, iv_a)

print("receiver")
print("\nAES(Advanced Encryption Standard-Block Cipher)Encryption:")
print("Original Message:", m)
print("Keystream:", k_a)
print("Encrypted Message:", e_a_res)
print("Decrypted Message:", d_a_res)

e_r_res = e_r(m, k_r)
d_r_res = d_r(e_r_res, k_r)

print("\nRC4(Rivest Cipher 4-Stream Cipher) Encryption:")
print("Original Message:", m)
print("Keystream:", k_r)
print("Encrypted Message:", e_r_res)
print("Decrypted Message:", d_r_res)