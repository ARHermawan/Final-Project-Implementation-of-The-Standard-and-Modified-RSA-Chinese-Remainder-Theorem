import math, binascii, os
import rsa
from datetime import datetime
import sys
import timeit
import os
import psutil
sys.set_int_max_str_digits(pow(2,31)-1)

def get_process_memory():
    process = psutil.Process(os.getpid())
    return process.memory_info().rss/ 1024 / 1024

"""## Prime"""

def get_primality_testing_rounds(number: int) -> int:
    bitsize = math.ceil(math.log2(number))
    if bitsize >= 1536:
        return 3
    if bitsize >= 1024:
        return 4
    if bitsize >= 512:
        return 7
    return 10

def miller_rabin_primality_testing(n: int, k: int) -> bool:
    if n < 2:
        return False

    d = n - 1
    r = 0

    while not (d & 1):
        r += 1
        d >>= 1

    for _ in range(k):

        a = rsa.randnum.randint(n - 3) + 1

        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == 1:

                return False
            if x == n - 1:

                break
        else:

            return False

    return True

def is_prime(number: int) -> bool:

    if number < 10:
        return number in {2, 3, 5, 7}

    if not (number & 1):
        return False

    k = get_primality_testing_rounds(number)

    return miller_rabin_primality_testing(number, k + 1)

def getprime(nbits: int) -> int:

    assert nbits > 3 

    while True:
        integer = rsa.randnum.read_random_odd_int(nbits)

        if is_prime(integer):
            return integer

"""## Relatively Prime"""

def gcd(p: int, q: int) -> int:
    while q != 0:
        (p, q) = (q, p % q)
    return p

def are_relatively_prime(a: int, b: int) -> bool:
    d = gcd(a, b)
    return d == 1

"""## Encrypt and Decrypt Algorithm

### Standard
"""
def power(a, b, n):
    result = 1  
    a = a % n 
    if a == 0:
        return 0
    while b > 0:
        if b % 2 == 1:
            result = (result * a) % n
        b = b // 2
        a = (a * a) % n
    return result

def simple_rsa_encrypt(m, e, n):
 return power(m, e, n)


def simple_rsa_decrypt(c, d, n):
 return power(c, d, n)

"""### Chinese Remainder Theorem"""
def Extended_Euclidean(a,b):
    a1 = 0
    a2 = 1
    b1 = 1
    b2 = 0
    T1 = a
    T2 = b
    while b != 0:
        q = a // b
        (a, b) = (b, a % b)
        (a1, b1) = ((b1 - (q * a1)), a1)
        (a2, b2) = ((b2 - (q * a2)), a2)
    if b1 < 0:
        b1 += T2
    if b2 < 0:
        b2 += T1
    return b1, b2

def simple_rsa_crt_decrypt(c, p, q, d, n):
  d_p = power(d,1,p-1)
  d_q = power(d,1,q-1)
  M_p, M_q = Extended_Euclidean(q, p)
  P_p = power(c,d_p,p)
  P_q = power(c,d_q,q)
  A = M_p*q*P_p + M_q*p*P_q
  return(power(A,1,n))

"""## Additional Algorithm"""

def int_to_bytes(i):
 i = int(i)
 return i.to_bytes((i.bit_length()+7)//8, byteorder='big')

def dummy(b, dumm=1):
  if dumm > 0 and dumm <=2:
    bytes_new_2 = b.to_bytes((b.bit_length()+(7+(8*(dumm-1))))//8, byteorder='big')
  elif dumm >2 and dumm <= 4:
    bytes_new_2 = b.to_bytes((b.bit_length()+(7+(8*(dumm-2))))//8, byteorder='big')
  elif dumm >4 and dumm <= 6:
    bytes_new_2 = b.to_bytes((b.bit_length()+(7+(8*(dumm-3))))//8, byteorder='big')
  else:
    bytes_new_2 = b.to_bytes((b.bit_length()+(7+(8*(dumm-4))))//8, byteorder='big')
  return bytes_new_2

def bytes_to_int(b):
 return int.from_bytes(b, byteorder='big')

def split_plaintext(plaintext, panjang_n, divisor):
  plaintext_parts = []
  chunk_size = panjang_n // divisor
  for i in range(0, len(plaintext), chunk_size):
    plaintext_parts.append(plaintext[i:i + chunk_size])
  return plaintext_parts

"""## RSA Execute"""

def RSA_Encrypt(plaintext_parts, e, n, bit_p):
  ciphertext_parts = []
  for plain in plaintext_parts:
      plain_text = plain.encode()
      plain_text_as_int = bytes_to_int(plain_text)
      cipher = simple_rsa_encrypt(plain_text_as_int, e,n)
      cipher_int= int_to_bytes(cipher)
      cipher_hex = binascii.hexlify(cipher_int).decode()
      if len(cipher_hex) != bit_p//2:
        dumm = bit_p//2 - len(cipher_hex)
        cipher_int = dummy(cipher,dumm)
        cipher_hex = binascii.hexlify(cipher_int).decode()
      ciphertext_parts.append(cipher_hex)
  ciphertext = [str(cipher) for cipher in ciphertext_parts]
  ciphertext = ''.join(ciphertext)
  return ciphertext

if __name__ == "__main__":
  bit = 1024
  p = getprime(bit)
  q = getprime(bit)
  n = p*q
  e = 65537
  divisor = 50
  phi_n = math.prod([x - 1 for x in [p, q]])
  d = rsa.common.inverse(e, phi_n)
  print(f"Nilai p adalah = {p}\nNilai q adalah = {q}")
  plaintext_path = f'C:/Users/Adita Raffl H/Documents/python/Tugas Akhir/300000 character.txt'
  with open(plaintext_path, 'r', encoding = 'utf-8') as file:
    plaintext = file.read()
  Plaintext_parts = split_plaintext(plaintext, bit, divisor)
  Ciphertext = RSA_Encrypt(Plaintext_parts, e, n, bit)
  
  filename = plaintext_path.split('/')[len(plaintext_path.split('/'))-1]
  
  ciphertext_path = f'cipher {bit} bit {filename}'
  if os.path.exists(ciphertext_path):
      os.remove(ciphertext_path)
  with open(ciphertext_path, 'a', encoding = 'utf-8') as f:
    f.write(Ciphertext)
    f.closed
    
  prime_p = f'bilangan prima p {bit} bit.txt'
  if os.path.exists(prime_p):
      os.remove(prime_p)
  with open(prime_p, 'a', encoding = 'utf-8') as f:
    f.write(str(p))
    f.closed
  prime_q = f'bilangan prima q {bit} bit.txt'
  if os.path.exists(prime_q):
      os.remove(prime_q)
  with open(prime_q, 'a', encoding = 'utf-8') as f:
    f.write(str(q))
    f.closed