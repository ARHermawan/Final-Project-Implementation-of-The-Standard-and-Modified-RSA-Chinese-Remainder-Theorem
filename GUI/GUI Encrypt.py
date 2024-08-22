from tkinter import *
import tkinter.messagebox
from tkinter import filedialog
import tkinter.scrolledtext as st
import math, binascii, os
import rsa
from datetime import datetime
import sys
import timeit
import os
import psutil
sys.set_int_max_str_digits(pow(2,31)-1)

window = Tk()
window.title('Enkripsi RSA Standar dan RSA Chinese Remainder Theorem')
window.geometry('1200x550')
window.config(background='Dark gray')
var = StringVar()
prime = ['128 bit', '256 bit', '512 bit', '1024 bit', '2048 bit']
e = IntVar()
phi = '\u03C6'
#==================================================================================

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

"""## Encrypt Algorithm

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

def countDigit(n):
    count = 0
    while n != 0:
        n //= 10
        count += 1
    return count

def split_text(plaintext, panjang_n):
  plaintext_parts = []
  chunk_size = panjang_n // 5
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
  return ciphertext


def printgetprime():
    value_prime = var.get()
    Value_p_output.configure(state="normal")
    Value_q_output.configure(state="normal")
    Value_n_output.configure(state="normal")
    Value_phi_n_output.configure(state="normal")
    global p_value
    global q_value
    global n_value
    global phi_value
    global bit
    if value_prime == "128 bit":
        bit = 128
        p_value = 216723439143121828417288808956178347769
        q_value = 188433511481486788196352917103181348687
    if value_prime == "256 bit":
        bit = 256
        p_value = getprime(bit)
        q_value = getprime(bit)
    if value_prime == "512 bit":
        bit = 512
        p_value = getprime(bit)
        q_value = getprime(bit)
    if value_prime == "1024 bit":
        bit = 1024
        p_value = getprime(bit)
        q_value = getprime(bit)
    if value_prime == "2048 bit":
        bit = 2048
        p_value = getprime(bit)
        q_value = getprime(bit)
    n_value = p_value*q_value
    phi_value = math.prod([x - 1 for x in [p_value, q_value]])
    Value_p_output.delete(1.0, END)   
    Value_q_output.delete(1.0, END)   
    Value_n_output.delete(1.0, END)   
    Value_phi_n_output.delete(1.0, END)   
    Value_p_output.insert(INSERT, p_value)
    Value_q_output.insert(INSERT, q_value)
    Value_n_output.insert(INSERT, n_value)
    Value_phi_n_output.insert(INSERT, phi_value)
    Value_p_output.configure(state="disabled")
    Value_q_output.configure(state="disabled")
    Value_n_output.configure(state="disabled")
    Value_phi_n_output.configure(state="disabled")
    Check_Relatively_prime_d.configure(state="normal")
    Button_get_d.configure(state="normal")
    print(f"Nilai p adalah = {p_value}\nNilai q adalah = {q_value}")
    print(f"Nilai n adalah = {n_value}\nNilai phi n adalah = {phi_value}")

def printgetnotprime():
    value_not_prime = var.get()
    Value_p_output.configure(state="normal")
    Value_q_output.configure(state="normal")
    Value_n_output.configure(state="normal")
    Value_phi_n_output.configure(state="normal")
    global p_value
    global q_value
    global n_value
    global phi_value
    global bit
    if value_not_prime == "128 bit":
        bit = 128
        p_value = rsa.randnum.read_random_odd_int(bit)
        q_value = rsa.randnum.read_random_odd_int(bit)
    if value_not_prime == "256 bit":
        bit = 256
        p_value = rsa.randnum.read_random_odd_int(bit)
        q_value = rsa.randnum.read_random_odd_int(bit)
    if value_not_prime == "512 bit":
        bit = 512
        assert bit > 3  
        p_value = rsa.randnum.read_random_odd_int(bit)
        q_value = rsa.randnum.read_random_odd_int(bit)
    if value_not_prime == "1024 bit":
        bit = 1024
        assert bit > 3  
        p_value = rsa.randnum.read_random_odd_int(bit)
        q_value = rsa.randnum.read_random_odd_int(bit)
    if value_not_prime == "2048 bit":
        bit = 2048
        assert bit > 3  
        p_value = rsa.randnum.read_random_odd_int(bit)
        q_value = rsa.randnum.read_random_odd_int(bit)
    n_value =  p_value*q_value
    phi_value = math.prod([x - 1 for x in [p_value, q_value]])
    Value_p_output.delete(1.0, END)   
    Value_q_output.delete(1.0, END)   
    Value_n_output.delete(1.0, END)   
    Value_phi_n_output.delete(1.0, END)   
    Value_p_output.insert(INSERT, p_value)
    Value_q_output.insert(INSERT, q_value)
    Value_n_output.insert(INSERT, n_value)
    Value_phi_n_output.insert(INSERT, phi_value)
    Value_p_output.configure(state="disabled")
    Value_q_output.configure(state="disabled")
    Value_n_output.configure(state="disabled")
    Value_phi_n_output.configure(state="disabled")
    Check_Relatively_prime_d.configure(state="normal")
    Button_get_d.configure(state="normal")

def printgetinverse():
    global d_value
    global e_value
    e_value = e.get()
    if are_relatively_prime(e_value, phi_value) == 1:
        d_value = rsa.common.inverse(e_value, phi_value)
        Value_d_output.configure(state="normal")
        Value_d_output.delete(1.0, END) 
        Value_d_output.insert(INSERT, d_value)
        Value_d_output.configure(state="disabled")
        print(f"Nilai d adalah = {d_value}\nNilai e adalah = {e_value}")
    else:
        tkinter.messagebox.showinfo("Error", f'e tidak relatif prima dengan {phi}(n)')

def open_file():
    global Plaintext
    global filename
    file_path = filedialog.askopenfilename(
        title="Pilih Text File", filetypes=[("Text files", "*.txt")])
    filename = file_path.split('/')[len(file_path.split('/'))-1]
    if file_path:
        with open(file_path, 'r') as file:
            Plaintext = file.read()
            Plaintext_Output.configure(state ='normal',wrap='char')
            Plaintext_Output.delete(1.0, END)   
            Plaintext_Output.insert(INSERT, Plaintext)
            Plaintext_Output.configure(state ='disabled')
            Start_Encrypt.configure(state="normal")
            Button_getprime.configure(state="disabled")
            Button_getnotprime.configure(state="disabled")
            Getprime_output.configure(state="disabled")


    
            

def check_p_prime():
    if is_prime(p_value) == True:
        tkinter.messagebox.showinfo("Cek Prima", 'p adalah bilangan prima')
    else :
        tkinter.messagebox.showinfo("Cek Prima", 'p bukan bilangan prima')
def check_q_prime():
    if is_prime(q_value) == True:
        tkinter.messagebox.showinfo("Cek Prima", 'q adalah bilangan prima')
    else :
        tkinter.messagebox.showinfo("Cek Prima", 'q bukan bilangan prima')

def Check_n_length():
    bit_length_n = math.ceil(math.log2(n_value))
    tkinter.messagebox.showinfo("Cek Panjang n", f'Panjang n adalah {bit_length_n} bit')

def check_relatively_prime():
    global d_value
    if pow(e_value, phi_value, n_value) and pow(d_value, phi_value, n_value) == 1:
        tkinter.messagebox.showinfo("Cek Relatif Prima", f'e dan d relatif prima dengan n')
        open_button.configure(state="normal")
    else :
        tkinter.messagebox.showinfo("Cek Relatif Prima", f'e and d tidak relatif prima dengan n')
        open_button.configure(state="disabled")
        Value_d_output.configure(state="normal")
        Value_d_output.delete(1.0, END)
        Value_d_output.configure(state="disabled")
        Button_get_d.configure(state="disabled")
        Check_Relatively_prime_d.configure(state="disabled")
        
def printgetciphertext():
    global Ciphertext
    var.get()
    Plaintext_parts = split_text(Plaintext, bit)
    Ciphertext = RSA_Encrypt(Plaintext_parts, e_value, n_value, bit)
    Ciphertext_Output.configure(state ='normal',wrap='char')
    Ciphertext_Output.delete(1.0, END)   
    Ciphertext_Output.insert(INSERT, Ciphertext)
    Ciphertext_Output.configure(state ='disabled')
    print(f"Ciphertext = \n{Ciphertext}")
    Start_Encrypt.configure(state="disabled")
    open_button.configure(state="disabled")
    save_button.configure(state="normal")

def save_result():
    prime_p = f'Prime p {bit} bit {filename}.txt'
    if os.path.exists(prime_p):
        os.remove(prime_p)
    with open(prime_p, 'a', encoding = 'utf-8') as f:
        f.write(str(p_value))
        f.closed
    prime_q = f'Prime q {bit} bit {filename}.txt'
    if os.path.exists(prime_q):
        os.remove(prime_q)
    with open(prime_q, 'a', encoding = 'utf-8') as f:
        f.write(str(q_value))
        f.closed
    ciphertext_save = f'Ciphertext {bit} bit {filename}.txt'
    if os.path.exists(ciphertext_save):
        os.remove(ciphertext_save)
    with open(ciphertext_save, 'a', encoding = 'utf-8') as f:
        f.write(Ciphertext)
        f.closed
    save_button.configure(state="disabled")
    
#==================================================================================
Header = Label(window, text ="RSA Standar dan RSA Chinese Remainder Theorem",bg = 'Dark gray', fg = 'white', font = ("Courier New",15,"bold"))
Header.pack()

Prime = Label(window,bg = 'Dark gray',justify='left',text = "Panjang Kunci :", font=("Arial", 12))
Prime.place(x=20, y=50)
Getprime_output = OptionMenu(window, var,*prime)
var.set("Pilih")
Getprime_output.config(width=10)
Getprime_output.place(x=140, y=50)
Button_getprime =Button(window, width=10, height=2 ,text="Dapatkan \nPrima", command=printgetprime, fg='lime')
Button_getprime.place(x=365, y=50)

Button_getnotprime = Button(window, width=11, height=2 ,text="Dapatkan \nBukan Prima", command=printgetnotprime, fg='lime')
Button_getnotprime.place(x=260, y=50)

Value_p = Label(window,bg = 'Dark gray',justify='left',text = "Nilai p :", font=("Arial", 12))
Value_p.place(x=20, y=100)
Value_p_output= Text(window, wrap="none", width=37, height=1, state="disabled")
Value_p_output.place(x= 140, y= 102)
Check_prime_p = Button(window, text="Cek Prima", command=check_p_prime, fg='lime')
Check_prime_p.place(x=450, y= 100)

Value_q = Label(window,bg = 'Dark gray',justify='left',text = "Nilai q :", font=("Arial", 12))
Value_q.place(x=20, y=150)
Value_q_output= Text(window, wrap="none", width=37, height=1, state="disabled")
Value_q_output.place(x= 140, y= 154)
Check_prime_q = Button(window, text="Cek Prima", command=check_q_prime, fg='lime')
Check_prime_q.place(x=450, y= 152)

Value_n = Label(window,bg = 'Dark gray',justify='left',text = "Nilai n :", font=("Arial", 12))
Value_n.place(x=20, y=200)
Value_n_output= Text(window, wrap="none", width=37, height=1, state="disabled")
Value_n_output.place(x= 140, y= 204)
Check_length_n = Button(window, text="Cek panjang n", command=Check_n_length, fg='lime')
Check_length_n.place(x=450, y= 202)

Value_phi_n = Label(window,bg = 'Dark gray',justify='left',text = f"Nilai {phi}(n) :", font=("Arial", 12))
Value_phi_n.place(x=20, y=250)
Value_phi_n_output= Text(window, wrap="none", width=37, height=1, state="disabled")
Value_phi_n_output.place(x= 140, y= 254)
Check_prime_q = Button(window, text="Cek Prima", command=check_q_prime, fg='lime')

Value_e = Label(window,bg = 'Dark gray',justify='left',text = "Nilai e :", font=("Arial", 12))
Value_e.place(x=20, y=300)
Value_e_output=Radiobutton(window,bg = 'Dark gray', text = "65537", variable=e, value=65537).place(x = 140, y = 300)
Button_get_d = Button(window, width=10,text="Dapatkan nilai \nd", command=printgetinverse, fg='lime')
Button_get_d.place(x=365, y=300)


Value_d = Label(window,bg = 'Dark gray',justify='left',text = "Nilai d :", font=("Arial", 12))
Value_d.place(x=20, y=350)
Value_d_output= Text(window, wrap="none", width=37, height=1, state="disabled")
Value_d_output.place(x= 140, y= 354)
Check_Relatively_prime_d = Button(window, text="Cek Relatif \nPrima", command=check_relatively_prime, fg='lime')
Check_Relatively_prime_d.place(x=450, y= 352)

open_button = Button(window, text="Pilih File", width=20,state="disabled",command=open_file, fg='lime')
open_button.place(x= 1000, y =50)
Plaintext_Label= Label(window,bg = 'Dark gray',justify='left',text = "Plaintext :", font=("Arial", 12))
Plaintext_Label.place(x=650, y=50)
Plaintext_Output = st.ScrolledText(width = 53,height = 11,font = ("Arial",12))
Plaintext_Output.configure(state ="disabled")
Plaintext_Output.place(x = 650, y= 80)

#==================================================================================

Ciphertext_Label = Label(window,bg = 'Dark gray',justify='left',text = "Ciphertext :", font=("Arial", 12))
Ciphertext_Label.place(x=650, y=300)



Start_Encrypt = Button(window, text="Mulai Enkripsi", width=20, state="disabled", command=printgetciphertext, fg='lime')
Start_Encrypt.place(x=1000, y =300)
Ciphertext_Output = st.ScrolledText(width = 53,height = 9,font = ("Arial",12))
Ciphertext_Output.configure(state ="disabled")
Ciphertext_Output.place(x = 650, y= 330)

save_button = Button(window, text="Simpan Hasil ke File", width=20, state="disabled", command=save_result, fg='lime')
save_button.place(x=1000, y =500)
window.mainloop()