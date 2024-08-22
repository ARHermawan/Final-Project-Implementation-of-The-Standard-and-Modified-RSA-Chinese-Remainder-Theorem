import math, binascii, os
import rsa
from datetime import datetime
import sys
import timeit
import os
import psutil
sys.set_int_max_str_digits(pow(2,31)-1)

# inner psutil function
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
    # prevent potential infinite loop when d = 0
    if n < 2:
        return False

    # Decompose (n - 1) to write it as (2 ** r) * d
    # While d is even, divide it by 2 and increase the exponent.
    d = n - 1
    r = 0

    while not (d & 1):
        r += 1
        d >>= 1

    for _ in range(k):
        # Generate random integer a, where 2 <= a <= (n - 2)
        a = rsa.randnum.randint(n - 3) + 1

        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == 1:
                # n is composite.
                return False
            if x == n - 1:
                # Exit inner loop and continue with next witness.
                break
        else:
            # If loop doesn't break, n is composite.
            return False

    return True

def is_prime(number: int) -> bool:
    # Check for small numbers.
    if number < 10:
        return number in {2, 3, 5, 7}

    # Check for even numbers.
    if not (number & 1):
        return False

    # Calculate minimum number of rounds.
    k = get_primality_testing_rounds(number)

    # Run primality testing with (minimum + 1) rounds.
    return miller_rabin_primality_testing(number, k + 1)

def getprime(nbits: int) -> int:

    assert nbits > 3  # the loop will hang on too small numbers

    while True:
        integer = rsa.randnum.read_random_odd_int(nbits)

        # Test for primeness
        if is_prime(integer):
            return integer

            # Retry if not prime

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
 # i might be a gmpy2 big integer; convert back to a Python int
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

if __name__ == '__main__':
    base_dir ='C:/Users/Adita Raffl H/Documents/python/Tugas Akhir/Normal RSA'
    #base_dir_100000 = os.path.join(base_dir,'100000')
    nama_file_p_prime = 'bilangan prima p 1024 bit.txt'
    nama_file_q_prime = 'bilangan prima q 1024 bit.txt'
    nama_file_encrypt = 'cipher 1024 bit 300000 character.txt'
    with open(f'{base_dir}/{nama_file_p_prime}', 'r') as file:
        p = file.read()
        p = int(p)
    with open(f'{base_dir}/{nama_file_q_prime}', 'r') as file:
        q = file.read()
        q = int(q)
    with open(f'{base_dir}/{nama_file_encrypt}', 'r') as file:
        ciphertext = file.read()
    n = p*q
    e = 65537
    phi_n = math.prod([x - 1 for x in [p, q]])
    d = rsa.common.inverse(e, phi_n)
    print(f"Nilai p adalah = {p}\nNilai q adalah = {q}")
    bit_length_p = math.ceil(math.log2(p))
    bit_length_q = math.ceil(math.log2(q))
    print(bit_length_p)
    print(bit_length_q)
    bit_split_cipher = (bit_length_p//2)
    print(f"bit_split_cipher = {bit_split_cipher}")
    Ciphertext_parts = split_plaintext(ciphertext, bit_split_cipher)
    chip = []
    for tes in Ciphertext_parts:
        sss = len(tes)
        chip.append(sss)
    print(f"maksimum panjang Ciphertext_parts adalah {max(chip)}")
    if max(chip) == bit_length_p//2:
        print(True)
        before_std = get_process_memory()
        (new_plaintext_standard, time_accumulate) = RSA_Decrypt(Ciphertext_parts, d, n)
        after_std = get_process_memory()
        memory_accumulate = after_std - before_std
        before_crt = get_process_memory()
        (new_plaintext_CRT, time_accumulate_CRT) = RSA_CRT_Decrypt(Ciphertext_parts, p, q, d)
        after_crt = get_process_memory()
        memory_accumulate_CRT = after_crt - before_crt
        print(f"time std {time_accumulate}")
        print(f"time crt {time_accumulate_CRT}")
        print(f"memory std {memory_accumulate}")
        print(f"memory crt {memory_accumulate_CRT}")
    print("==============================================================================")

    #t_STD = 0
    #for total_STD in time_accumulate:
    #    t_STD += total_STD
    #print(f"Untuk {nama_file_encrypt} Total waktu standard adalah {t_STD} detik")

    #t_CRT = 0
    #for total_CRT in time_accumulate_CRT:
    #    t_CRT += total_CRT
    #print(f"Untuk {nama_file_encrypt} Total waktu CRT adalah {t_CRT} detik")

    #m_STD = 0
    #for total_STD in memory_accumulate:
    #    m_STD += total_STD
    #print(f"Untuk {nama_file_encrypt} Total memori standard adalah {m_STD} MB")
    
    #m_CRT = 0
    #for total_CRT in memory_accumulate_CRT:
    #    m_CRT += total_CRT
    #print(f"Untuk {nama_file_encrypt} Total memori CRT adalah {m_CRT} MB")

    if time_accumulate > time_accumulate_CRT:
            t_COMP = time_accumulate/time_accumulate_CRT
            t_COMP_2 = "kali lebih cepat RSA-CRT"
    if time_accumulate < time_accumulate_CRT:
            t_COMP = time_accumulate_CRT/time_accumulate
            t_COMP_2 = "kali lebih cepat RSA Standart"
    if time_accumulate == time_accumulate_CRT:
            t_COMP = "equal time execution"
            t_COMP_2 = "sama cepat"
        
    if memory_accumulate > memory_accumulate_CRT:
            m_COMP = memory_accumulate/memory_accumulate_CRT
            m_COMP_2 = "kali lebih banyak RSA Standard"
    if memory_accumulate < memory_accumulate_CRT:
            m_COMP = memory_accumulate_CRT/memory_accumulate
            m_COMP_2 = "kali lebih banyak RSA-CRT"
    if memory_accumulate == memory_accumulate_CRT:
            m_COMP = "equal memory used"
            m_COMP_2 = "sama banyak"
    Hasil_waktu_Eksekusi = f"Hasil perbandingan lama waktu eksekusi program yaitu {t_COMP} {t_COMP_2}"
    Hasil_penggunaan_memori = f"Hasil perbandingan penggunaan memori program yaitu {m_COMP} {m_COMP_2}"

    plaintext_dir = 'C:/Users/Adita Raffl H/Documents/python/Tugas Akhir'
    with open(f'{plaintext_dir}/300000 character.txt', 'r', encoding = 'utf-8') as file:
        plaintext = file.read()
    if plaintext == new_plaintext_standard and plaintext == new_plaintext_CRT:
        print("Teks ini menunjukkan Plaintext Hasil Dekripsi RSA Standart dan RSA Chinese Remainder Theorem = Plaintext Awal")
        print(Hasil_penggunaan_memori)
        print(Hasil_waktu_Eksekusi)