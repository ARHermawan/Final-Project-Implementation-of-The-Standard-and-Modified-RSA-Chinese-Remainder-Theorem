import math, binascii, os
import rsa
import sys
import timeit
import os
import psutil
import shutil
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

def split_plaintext(plaintext, panjang_n, divisor = 1):
  plaintext_parts = []
  chunk_size = panjang_n // divisor
  for i in range(0, len(plaintext), chunk_size):
    plaintext_parts.append(plaintext[i:i + chunk_size])
  return plaintext_parts

"""## RSA Execute"""

def RSA_Encrypt(plaintext_parts, e, n, dummy_bit):
  ciphertext_parts = []
  for plain in plaintext_parts:
      plain_text = plain.encode()
      plain_text_as_int = bytes_to_int(plain_text)
      cipher = simple_rsa_encrypt(plain_text_as_int, e,n)
      cipher_int= int_to_bytes(cipher)
      cipher_hex = binascii.hexlify(cipher_int).decode()
      if len(cipher_hex) != dummy_bit//2:
        dumm = dummy_bit//2 - len(cipher_hex)
        cipher_int = dummy(cipher,dumm)
        cipher_hex = binascii.hexlify(cipher_int).decode()
      ciphertext_parts.append(cipher_hex)
  ciphertext = [str(cipher) for cipher in ciphertext_parts]
  ciphertext = ''.join(ciphertext)
  return ciphertext, ciphertext_parts

def RSA_Decrypt(ciphertext_parts, d, n):
  plaintext_new = []
  start = timeit.default_timer()
  for cipher in ciphertext_parts:
      cipher_text = cipher.encode()
      cipher_bytes = binascii.unhexlify(cipher_text)
      cipher_text_as_int = bytes_to_int(cipher_bytes)
      plaintextnew = simple_rsa_decrypt(cipher_text_as_int, d, n)
      plaintextnew = int_to_bytes(plaintextnew)
      plaintextnew= plaintextnew.decode()
      plaintext_new.append(plaintextnew)
  stop = timeit.default_timer()
  time_accumulate = stop - start
  new_plaintext = [str(elemen) for elemen in plaintext_new]
  new_plaintext = ''.join(new_plaintext)
  return new_plaintext, time_accumulate


def RSA_CRT_Decrypt(ciphertext_parts, p, q, d):
  plaintext_new = []
  start = timeit.default_timer()
  for cipher in ciphertext_parts:
      cipher_text = cipher.encode()
      cipher_bytes = binascii.unhexlify(cipher_text)
      cipher_text_as_int = bytes_to_int(cipher_bytes)
      plaintextnew = simple_rsa_crt_decrypt(cipher_text_as_int, p, q, d)
      plaintextnew = int_to_bytes(plaintextnew)
      plaintextnew= plaintextnew.decode()
      plaintext_new.append(plaintextnew)
  stop = timeit.default_timer()
  time_accumulate = stop - start
  new_plaintext = [str(elemen) for elemen in plaintext_new]
  new_plaintext = ''.join(new_plaintext)
  return new_plaintext, time_accumulate

"""## Main Program"""

def getKeyRSA(bit:int, character:str, A:int):
  p = getprime(bit)
  q = getprime(bit)
  n = p*q
  e = 65537
  phi_n = math.prod([x - 1 for x in [p, q]])
  d = rsa.common.inverse(e, phi_n)
  
  plaintext_path = f'{character} character.txt'
  
  with open(plaintext_path, 'r', encoding = 'utf-8') as file:
    plaintext = file.read()

  Plaintext_parts = split_plaintext(plaintext, bit, 5)
  (Ciphertext, ciphertext_parts_1) = RSA_Encrypt(Plaintext_parts, e, n, bit)
  chip_1 = []
  for tes in ciphertext_parts_1:
        sss = len(tes)
        chip_1.append(sss)
  if min(chip_1) == max(chip_1):
     print("chip 1 bener")
  print(f"maksimum panjang Ciphertext_parts adalah {max(chip_1)}")
  prime_p = f'prima p {character} {bit} bit ke-{A}.txt'
  prime_q = f'prima q {character} {bit} bit ke-{A}.txt'

  if os.path.exists(prime_p):
      os.remove(prime_p)
  with open(prime_p, 'a', encoding = 'utf-8') as f:
    f.write(str(p))
    f.closed

  if os.path.exists(prime_q):
      os.remove(prime_q)
  with open(prime_q, 'a', encoding = 'utf-8') as f:
    f.write(str(q))
    f.closed
    
  ciphertext_path = f'cipher {character} {bit} bit ke-{A}.txt'
  if os.path.exists(ciphertext_path):
      os.remove(ciphertext_path)
  with open(ciphertext_path, 'a', encoding = 'utf-8') as f:
    f.write(Ciphertext)
    f.closed

  with open(ciphertext_path, 'r') as file:
    new_ciphertext = file.read()
  bit_split_cipher = (bit//2)
  Ciphertext_parts = split_plaintext(new_ciphertext, bit_split_cipher)
  chip = []
  for tes in Ciphertext_parts:
        sss = len(tes)
        chip.append(sss)
  if min(chip) == max(chip):
     print("chip bener")
  print(f"maksimum panjang Ciphertext_parts adalah {max(chip)}")
  if max(chip) == bit//2:
        print(True)
        (new_plaintext_standard, time_accumulate) = RSA_Decrypt(Ciphertext_parts, d, n)
        memory_accumulate = get_process_memory()
        if memory_accumulate <0:
           sys.exit()
        (new_plaintext_CRT, time_accumulate_CRT) = RSA_CRT_Decrypt(Ciphertext_parts, p, q, d)
        memory_accumulate_CRT = get_process_memory()
        if memory_accumulate_CRT <0:
           sys.exit()
        print(f"time std {time_accumulate}")
        print(f"time crt {time_accumulate_CRT}")
        print(f"memory std {memory_accumulate}")
        print(f"memory crt {memory_accumulate_CRT}")
  print("==============================================================================")
  print(f"Nilai p adalah = {p}\nNilai q adalah = {q}")
  additional = f"Hasil {character} dengan {bit} bit"
  print(f"{additional} ke-{A}")

  if plaintext == new_plaintext_standard and plaintext == new_plaintext_CRT:
    print("Teks ini menunjukkan Plaintext Hasil Dekripsi RSA Standart dan RSA Chinese Remainder Theorem = Plaintext Awal")
    return  time_accumulate, time_accumulate_CRT, memory_accumulate, memory_accumulate_CRT

def iterasi5kali(bit:int, character:str):
  global new_dir
  t_STD_acc_1 = []
  t_CRT_acc_1 = []
  m_STD_acc_1 = []
  m_CRT_acc_1 = []

  for letsgoo in range (1,6):
    time_accumulate, time_accumulate_CRT, memory_accumulate, memory_accumulate_CRT = getKeyRSA(bit, character, letsgoo)
    t_STD_acc_1.append(time_accumulate)
    t_CRT_acc_1.append(time_accumulate_CRT)
    m_STD_acc_1.append(memory_accumulate)
    m_CRT_acc_1.append(memory_accumulate_CRT)

  dir = f'Hasil {character} {bit}.txt'
  if os.path.exists(dir):
      os.remove(dir)
  with open(dir, 'a', encoding = 'utf-8') as f:
    f.write(f"{t_STD_acc_1} \n") #0
    f.write(f"{t_CRT_acc_1} \n") #1
    f.write(f"{m_STD_acc_1} \n") #2
    f.write(f"{m_CRT_acc_1} \n") #3
    f.closed
  new_dir = os.path.join(base_dir,f'{bit}')
  os.replace(f'{base_dir}/{dir}', f'{new_dir}/{dir}')
  
def iterasi5kalidandirectory(bit:int, character_1:str, character_2:str, character_3:str, character_4:str):
  if os.path.exists(f'{character_1}'):
    shutil.rmtree(f'{character_1}')
  else:
    os.mkdir(f'{character_1}')

  if os.path.exists(f'{character_2}'):
    shutil.rmtree(f'{character_2}')
  else:
    os.mkdir(f'{character_2}')

  if os.path.exists(f'{character_3}'):
    shutil.rmtree(f'{character_3}')
  else:
    os.mkdir(f'{character_3}')

  if os.path.exists(f'{character_4}'):
    shutil.rmtree(f'{character_4}')
  else:
    os.mkdir(f'{character_4}')

  iterasi5kali(bit,character_1)
  iterasi5kali(bit,character_2)
  iterasi5kali(bit,character_3)
  iterasi5kali(bit,character_4)
  os.replace(f'{base_dir}/{character_1}', f'{new_dir}/{character_1}')
  os.replace(f'{base_dir}/{character_2}', f'{new_dir}/{character_2}')
  os.replace(f'{base_dir}/{character_3}', f'{new_dir}/{character_3}')
  os.replace(f'{base_dir}/{character_4}', f'{new_dir}/{character_4}')
  new_dir1 = f'{new_dir}/{character_1}'
  new_dir2 = f'{new_dir}/{character_2}'
  new_dir3 = f'{new_dir}/{character_3}'
  new_dir4 = f'{new_dir}/{character_4}'
  for A in range (1,6):
    os.replace(f'{base_dir}/cipher {character_1} {bit} bit ke-{A}.txt', f'{new_dir1}/cipher {character_1} {bit} bit ke-{A}.txt')
    os.replace(f'{base_dir}/cipher {character_2} {bit} bit ke-{A}.txt', f'{new_dir2}/cipher {character_2} {bit} bit ke-{A}.txt')
    os.replace(f'{base_dir}/cipher {character_3} {bit} bit ke-{A}.txt', f'{new_dir3}/cipher {character_3} {bit} bit ke-{A}.txt')
    os.replace(f'{base_dir}/cipher {character_4} {bit} bit ke-{A}.txt', f'{new_dir4}/cipher {character_4} {bit} bit ke-{A}.txt')

    os.replace(f'{base_dir}/prima p {character_1} {bit} bit ke-{A}.txt', f'{new_dir1}/prima p {character_1} {bit} bit ke-{A}.txt')
    os.replace(f'{base_dir}/prima p {character_2} {bit} bit ke-{A}.txt', f'{new_dir2}/prima p {character_2} {bit} bit ke-{A}.txt')
    os.replace(f'{base_dir}/prima p {character_3} {bit} bit ke-{A}.txt', f'{new_dir3}/prima p {character_3} {bit} bit ke-{A}.txt')
    os.replace(f'{base_dir}/prima p {character_4} {bit} bit ke-{A}.txt', f'{new_dir4}/prima p {character_4} {bit} bit ke-{A}.txt')

    os.replace(f'{base_dir}/prima q {character_1} {bit} bit ke-{A}.txt', f'{new_dir1}/prima q {character_1} {bit} bit ke-{A}.txt')
    os.replace(f'{base_dir}/prima q {character_2} {bit} bit ke-{A}.txt', f'{new_dir2}/prima q {character_2} {bit} bit ke-{A}.txt')
    os.replace(f'{base_dir}/prima q {character_3} {bit} bit ke-{A}.txt', f'{new_dir3}/prima q {character_3} {bit} bit ke-{A}.txt')
    os.replace(f'{base_dir}/prima q {character_4} {bit} bit ke-{A}.txt', f'{new_dir4}/prima q {character_4} {bit} bit ke-{A}.txt')
    
if __name__ == '__main__':
  bit_128 = 128
  bit_256 = 256
  bit_512 = 512
  bit_1024 = 1024
  bit_2048 = 2048
  character_50000 = "50000"
  character_100000 = "100000"
  character_200000 = "200000"
  character_300000 = "300000"
  base_dir = '' #Input Folder

  os.mkdir(f'{bit_128}')  
  os.mkdir(f'{bit_256}')
  os.mkdir(f'{bit_512}')    
  os.mkdir(f'{bit_1024}')    
  os.mkdir(f'{bit_2048}')
  
  iterasi5kalidandirectory(bit_128, character_50000, character_100000, character_200000, character_300000)
  iterasi5kalidandirectory(bit_256, character_50000, character_100000, character_200000, character_300000)
  iterasi5kalidandirectory(bit_512, character_50000, character_100000, character_200000, character_300000)
  iterasi5kalidandirectory(bit_1024, character_50000, character_100000, character_200000, character_300000)
  iterasi5kalidandirectory(bit_2048, character_50000, character_100000, character_200000, character_300000)