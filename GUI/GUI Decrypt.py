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
window.title('Dekripsi RSA Standar dan RSA Chinese Remainder Theorem')
window.geometry('1350x680')
window.config(background='Dark gray')
e = IntVar()
var = StringVar()
phi = '\u03C6'
#==================================================================================

def get_process_memory():
    process = psutil.Process(os.getpid())
    return process.memory_info().rss/ 1024 / 1024

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


def gcd(p: int, q: int) -> int:
    while q != 0:
        (p, q) = (q, p % q)
    return p
def are_relatively_prime(a: int, b: int) -> bool:
    d = gcd(a, b)
    return d == 1
"""## Decrypt Algorithm

"""
def power(a, b, n) :
    result = 1  
    a = a % n 
    if (a == 0) :
        return 0
 
    while (b > 0) :
        if ((b & 1) == 1) :
            result = (result * a) % n
        b = b // 2
        a = (a * a) % n
    return result

def simple_rsa_decrypt(c, d, n):
 return power(c, d, n)


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

def bytes_to_int(b):
 return int.from_bytes(b, byteorder='big')

def split_text(plaintext, panjang_n):
  plaintext_parts = []
  for i in range(0, len(plaintext), panjang_n):
    plaintext_parts.append(plaintext[i:i + panjang_n])
  return plaintext_parts

"""## RSA Execute"""


def RSA_Decrypt(ciphertext_parts, d, n):
  plaintext_new = []
  time_accumulate = []
  for cipher in ciphertext_parts:
      cipher_text = binascii.unhexlify(cipher)
      cipher_text_as_int = bytes_to_int(cipher_text)
      start = timeit.default_timer()
      plaintextnew = simple_rsa_decrypt(cipher_text_as_int, d, n)
      stop = timeit.default_timer()
      lama_eksekusi = stop - start
      time_accumulate.append(lama_eksekusi)
      plaintextnew = int_to_bytes(plaintextnew)
      plaintextnew= plaintextnew.decode()
      plaintext_new.append(plaintextnew)
  new_plaintext = [str(elemen) for elemen in plaintext_new]
  new_plaintext = ''.join(new_plaintext)
  return new_plaintext, time_accumulate

def RSA_CRT_Decrypt(ciphertext_parts, p, q, d):
  plaintext_new = []
  time_accumulate = []
  for cipher in ciphertext_parts:
      cipher_text = binascii.unhexlify(cipher)
      cipher_text_as_int = bytes_to_int(cipher_text)
      start = timeit.default_timer()
      plaintextnew = simple_rsa_crt_decrypt(cipher_text_as_int, p, q, d)
      stop = timeit.default_timer()
      lama_eksekusi = stop - start
      time_accumulate.append(lama_eksekusi)
      plaintextnew = int_to_bytes(plaintextnew)
      plaintextnew= plaintextnew.decode()
      plaintext_new.append(plaintextnew)
  new_plaintext = [str(elemen) for elemen in plaintext_new]
  new_plaintext = ''.join(new_plaintext)
  return new_plaintext, time_accumulate


def printgetprime():
    global p_value
    global q_value
    global n_value
    global phi_value
    global bit
    file_path_1 = filedialog.askopenfilename(
        title="Select a Text File", filetypes=[("Text files", "*.txt")])
    file_path_2 = filedialog.askopenfilename(
        title="Select a Text File", filetypes=[("Text files", "*.txt")])
    if file_path_1 and file_path_2:
        with open(file_path_1) as f1, open(file_path_2) as f2:
            p_value = f1.read()
            p_value = int(p_value)
            q_value = f2.read()
            q_value = int(q_value)
    n_value = p_value*q_value
    phi_value = math.prod([x - 1 for x in [p_value, q_value]])
    bit = p_value.bit_length()
    Value_p_output.configure(state="normal")
    Value_q_output.configure(state="normal")
    Value_n_output.configure(state="normal")
    Value_phi_n_output.configure(state="normal")
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
    Button_getprime.configure(state="disabled")
    print(f"Nilai p adalah = {p_value}\nNilai q adalah = {q_value}")
    print(f"Nilai n adalah = {n_value}\nNilai phi n adalah = {phi_value}")


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
        open_button.configure(state="normal")
        print(f"Nilai d adalah = {d_value}\nNilai e adalah = {e_value}")
    else:
         tkinter.messagebox.showinfo("Error", f'e tidak relatif prima dengan {phi}(n)')

def open_file():
    global Ciphertext
    file_path = filedialog.askopenfilename(
         title="Pilih Text File", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, 'r') as file:
            Ciphertext = file.read()
            Ciphertext_Output.configure(state ='normal',wrap='char')
            Ciphertext_Output.delete(1.0, END)  
            Ciphertext_Output.insert(INSERT, Ciphertext)
            Ciphertext_Output.configure(state ='disabled')
            Start_Decrypt_Standar.configure(state="normal")
            Start_Decrypt_CRT.configure(state="normal")
            open_button.configure(state="disabled")


    
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

    

def printgetnewplaintextStandar():
        global time_accumulate
        global new_plaintext_Standar
        global memory_accumulate
        bit_split_cipher = bit//2
        Ciphertext_parts = split_text(Ciphertext, bit_split_cipher)
        (new_plaintext_Standar, time_accumulate) = RSA_Decrypt(Ciphertext_parts, d_value, n_value)
        memory_accumulate = get_process_memory()
        New_Plaintext_Standar_Output.configure(state ='normal',wrap='char')
        New_Plaintext_Standar_Output.delete(1.0, END)  
        New_Plaintext_Standar_Output.insert(INSERT, new_plaintext_Standar)
        New_Plaintext_Standar_Output.configure(state ='disabled')
        Get_Time_Standar.configure(state='normal')
        Get_Memory_Standar.configure(state='normal')
        Start_Decrypt_Standar.configure(state="disabled")

def printgetnewplaintextCRT():
        global time_accumulate_CRT
        global new_plaintext_CRT
        global memory_accumulate_CRT
        bit_split_cipher = bit//2
        Ciphertext_parts = split_text(Ciphertext, bit_split_cipher)
        (new_plaintext_CRT, time_accumulate_CRT) = RSA_CRT_Decrypt(Ciphertext_parts, p_value, q_value, d_value)
        memory_accumulate_CRT = get_process_memory()
        New_Plaintext_CRT_Output.configure(state ='normal',wrap='char')
        New_Plaintext_CRT_Output.delete(1.0, END)  
        New_Plaintext_CRT_Output.insert(INSERT, new_plaintext_CRT)
        New_Plaintext_CRT_Output.configure(state ='disabled')
        Get_Time_CRT.configure(state='normal')
        Get_Memory_CRT.configure(state='normal')
        Start_Decrypt_CRT.configure(state="disabled")
        Check_plaintext.configure(state="normal")

def printgetexecutiontimeStandar():
        global t_STD
        t_STD = 0
        for total in time_accumulate:
            t_STD += total
        t_STD_print = f"{t_STD} s"
        Get_Time_Standar_Output.configure(state='normal')
        Get_Time_Standar_Output.delete(1.0, END)  
        Get_Time_Standar_Output.insert(INSERT, t_STD_print)
        Get_Time_Standar_Output.configure(state ='disabled')
        Get_Time_Standar.configure(state='disabled')

def printgetexecutiontimecrt():
        global t_CRT
        t_CRT = 0
        for total in time_accumulate_CRT:
            t_CRT += total
        t_CRT_print = f"{t_CRT} s"
        Get_Time_CRT_Output.configure(state='normal')
        Get_Time_CRT_Output.delete(1.0, END)  
        Get_Time_CRT_Output.insert(INSERT, t_CRT_print)
        Get_Time_CRT_Output.configure(state ='disabled')
        Get_Time_CRT.configure(state ='disabled')
        

def printgetmemoryusedStandar():
        m_STD_print = f"{memory_accumulate} MB"
        Get_Memory_Standar_Output.configure(state='normal')
        Get_Memory_Standar_Output.delete(1.0, END)  
        Get_Memory_Standar_Output.insert(INSERT, m_STD_print)
        Get_Memory_Standar_Output.configure(state ='disabled')
        Get_Memory_Standar.configure(state ='disabled')
def printgetmemoryusedCRT():
        m_CRT_print = f"{memory_accumulate_CRT} MB"
        Get_Memory_CRT_Output.configure(state='normal')
        Get_Memory_CRT_Output.delete(1.0, END)  
        Get_Memory_CRT_Output.insert(INSERT, m_CRT_print)
        Get_Memory_CRT_Output.configure(state ='disabled')
        Get_Memory_CRT.configure(state ='disabled')
        Comparison.configure(state="normal")
        

def printcomparison():
        global t_COMP
        global m_COMP
        global t_COMP_2
        global m_COMP_2
        if t_STD > t_CRT:
            t_COMP = t_STD/t_CRT
            t_COMP_2 = "RSA-CRT"
        if t_STD < t_CRT:
            t_COMP = t_CRT/t_STD
            t_COMP_2 = "RSA Standar"
        if t_STD == t_CRT:
            t_COMP = 1
            t_COMP_2 = "Equal"
        
        if memory_accumulate > memory_accumulate_CRT:
            m_COMP = memory_accumulate/memory_accumulate_CRT
            m_COMP_2 = "RSA "
        if memory_accumulate < memory_accumulate_CRT:
            m_COMP = memory_accumulate_CRT/memory_accumulate
            m_COMP_2 = "RSA-CRT"
        if memory_accumulate == memory_accumulate_CRT:
            m_COMP = 1
            m_COMP_2 = "Equal"
        Comparison_Output_Time.configure(state='normal')
        Comparison_Output_Time.delete(1.0, END)  
        Comparison_Output_Time.insert(INSERT, t_COMP)
        Comparison_Output_Time.configure(state ='disabled')
        
        Comparison_Output_Time_2.configure(state='normal')
        Comparison_Output_Time_2.delete(1.0, END)  
        Comparison_Output_Time_2.insert(INSERT, t_COMP_2)
        Comparison_Output_Time_2.configure(state ='disabled')
        
        Comparison_Output_Memory.configure(state='normal')
        Comparison_Output_Memory.delete(1.0, END)  
        Comparison_Output_Memory.insert(INSERT, m_COMP)
        Comparison_Output_Memory.configure(state ='disabled')
        
        Comparison_Output_Memory_2.configure(state='normal')
        Comparison_Output_Memory_2.delete(1.0, END)  
        Comparison_Output_Memory_2.insert(INSERT, m_COMP_2)
        Comparison_Output_Memory_2.configure(state ='disabled')
        
        Comparison.configure(state="disabled")

def printcheckplaintext():
    if new_plaintext_Standar == new_plaintext_CRT:
        tkinter.messagebox.showinfo("Cek Plaintext", f'Plaintext Baru RSA Standar sama dengan plaintext baru RSA-CRT')
    else:
        tkinter.messagebox.showinfo("Cek Plaintext", f'Plaintext Baru RSA Standar tidak sama dengan plaintext baru RSA-CRT')
 
#==================================================================================
Header = Label(window, text ="RSA Standar dan RSA Chinese Remainder Theorem",bg = 'Dark gray', fg = 'white', font = ("Courier New",15,"bold"))
Header.pack()


Button_getprime =Button(window, width=20 ,text="Dapatkan Prima", command=printgetprime, fg='lime')
Button_getprime.place(x=370, y=50)

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

open_button = Button(window, text="Pilih File", width=20,state="disabled",command=open_file, fg='lime')
open_button.place(x= 370, y =400)
Ciphertext_Label= Label(window,bg = 'Dark gray',justify='left',text = "Ciphertext :", font=("Arial", 12))
Ciphertext_Label.place(x=20, y=400)
Ciphertext_Output = st.ScrolledText(width = 53,height = 11,font = ("Arial",12))
Ciphertext_Output.configure(state ="disabled")
Ciphertext_Output.place(x = 20, y= 430)

#==================================================================================

New_Plaintext_Standar_Label= Label(window,bg = 'Dark gray',justify='left',text = "Plaintext Baru RSA-Standar :", font=("Arial", 12))
New_Plaintext_Standar_Label.place(x=650, y=50)
New_Plaintext_CRT_Output = Label(window,bg = 'Dark gray',justify='left',text = "Plaintext Baru RSA-CRT:", font=("Arial", 12))
New_Plaintext_CRT_Output.place(x=650, y=250)
   # A Label widget to show in toplevel


Start_Decrypt_Standar = Button(window, text="Mulai Dekripsi RSA Standar", width=20,state="disabled", command=printgetnewplaintextStandar, fg='lime')
Start_Decrypt_Standar.place(x= 1000, y =50)
New_Plaintext_Standar_Output = st.ScrolledText(window, width = 53,height = 9,font = ("Arial",12))
New_Plaintext_Standar_Output.configure(state ="disabled")
New_Plaintext_Standar_Output.place(x = 650, y= 80)

Start_Decrypt_CRT = Button(window, text="Mulai Dekripsi RSA-CRT", width=20,state="disabled", command=printgetnewplaintextCRT, fg='lime')
Start_Decrypt_CRT.place(x= 1000, y =250)
New_Plaintext_CRT_Output = st.ScrolledText(window, width = 53,height = 9,font = ("Arial",12))
New_Plaintext_CRT_Output.configure(state ="disabled")
New_Plaintext_CRT_Output.place(x = 650, y= 280)

Get_Time_Standar = Button(window, text="Dapatkan Waktu Eksekusi",state="disabled",command=printgetexecutiontimeStandar, fg='lime')
Get_Time_Standar.place(x=1160, y=80)
Get_Time_Standar_Output = Text(window, wrap="none", width=20, height=1, state="disabled")
Get_Time_Standar_Output.place(x=1160, y= 108)

Get_Time_CRT = Button(window, text="Dapatkan Waktu Eksekusi",state="disabled",command=printgetexecutiontimecrt, fg='lime')
Get_Time_CRT.place(x=1160, y=280)
Get_Time_CRT_Output = Text(window, wrap="none", width=20, height=1, state="disabled")
Get_Time_CRT_Output.place(x=1160, y= 308)

Get_Memory_Standar = Button(window, text="Dapatkan Penggunaan Memori",state="disabled", command=printgetmemoryusedStandar, fg='lime')
Get_Memory_Standar.place(x=1160, y=130)
Get_Memory_Standar_Output = Text(window, wrap="none", width=20, height=1, state="disabled")
Get_Memory_Standar_Output.place(x=1160, y= 158)

Get_Memory_CRT = Button(window, text="Dapatkan Penggunaan Memori",state="disabled", command=printgetmemoryusedCRT, fg='lime')
Get_Memory_CRT.place(x=1160, y=330)
Get_Memory_CRT_Output = Text(window, wrap="none", width=20, height=1, state="disabled")
Get_Memory_CRT_Output.place(x=1160, y= 358)

Comparison = Button(window, text="Dapatkan Perbandingan",state="disabled", command=printcomparison, fg='lime')
Comparison.place(x = 650, y=450 )
Check_plaintext = Button(window, text="Cek Plaintext Baru",state="disabled", command=printcheckplaintext, fg='lime')
Check_plaintext.place(x=1000, y=450 )

Comparison_Time = Label(window,bg = 'Dark gray',justify='left',text = "Waktu Eksekusi Tercepat :", font=("Arial", 10))
Comparison_Time.place(x=650, y=478)
Comparison_Output_Time = Text(window, wrap="none", width=20, height=1, state="disabled")
Comparison_Output_Time.place(x = 650, y=506)
Comparison_Output_Time_2 = Text(window, wrap="none", width=12, height=1, state="disabled")
Comparison_Output_Time_2.place(x = 650, y=534)

Comparison_Memory = Label(window,bg = 'Dark gray',justify='left',text = "Penggunaan Memori Tertinggi:", font=("Arial", 10))
Comparison_Memory.place(x=900, y=478)
Comparison_Output_Memory = Text(window, wrap="none", width=20, height=1, state="disabled")
Comparison_Output_Memory.place(x = 900, y=506)
Comparison_Output_Memory_2 = Text(window, wrap="none", width=12, height=1, state="disabled")
Comparison_Output_Memory_2.place(x = 900, y=534)
window.mainloop()