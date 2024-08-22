import matplotlib.pyplot as plt
import os
import numpy as np
import random
import shutil

def plot_time(data_1, data_2, characters:int):
  indices = np.arange(len(data_1))

  # Set the width of each bar
  bar_width = 0.35
  # Plot histogram for array1
  plt.figure(figsize=[10,6]) 
  plt.bar(indices, data_1, bar_width, alpha=0.5, color='b', label=f'RSA Standard')

  # Plot histogram for array2, shifting the bars to the right
  plt.bar(indices + bar_width, data_2, bar_width, alpha=0.5, color='r', label=f'RSA-CRT')

  # Annotate the plot with values above each bar
  for i, (a1, a2) in enumerate(zip(data_1, data_2)):
      maxs = max([a1,a2])
      plt.text(i, a1+(0.02*maxs), f'{a1:.3f}',ha='center', va='bottom')
      plt.text(i + bar_width, a2+(0.03*maxs), f'{a2:.3f}', ha='center', va='bottom')
  #max_y = max(max(data_1), max(data_2)) + 1  # Find the maximum value among both arrays and add 1
  #plt.ylim(0, max_y*1.2)  # Set the y-axis limit to include the maximum value

  plt.xlabel('Panjang Kunci (bit)')
  plt.ylabel('Runtime (s)')
  plt.title(f'Perbandingan Running Time RSA dengan Plaintext {characters} Karakter')
  plt.xticks(indices + bar_width / 2, [128, 256, 512, 1024, 2048])  # Set x-axis ticks to range 1 to 10
  plt.yscale('log')
  plt.legend()
  name_plot = f'Time execution {characters} characters.png'
  plt.savefig(name_plot, format="png")
  plt.close()

def plot_memory(data_1, data_2, characters:int):
  indices = np.arange(len(data_1))

  # Set the width of each bar
  bar_width = 0.35
  # Plot histogram for array1
  plt.figure(figsize=[10,6]) 
  plt.bar(indices, data_1, bar_width, alpha=0.5, color='b', label=f'RSA Standard')

  # Plot histogram for array2, shifting the bars to the right
  plt.bar(indices + bar_width, data_2, bar_width, alpha=0.5, color='r', label=f'RSA-CRT')

  # Annotate the plot with values above each bar
  for i, (a1, a2) in enumerate(zip(data_1, data_2)):
      maxs = max([a1,a2])
      plt.text(i, a1+(0.02*maxs), f'{a1:.3f}',ha='center', va='bottom')
      plt.text(i + bar_width, a2+(0.03*maxs), f'{a2:.3f}', ha='center', va='bottom')
  max_y = max(max(data_1), max(data_2)) + 1  # Find the maximum value among both arrays and add 1
  plt.ylim(0, max_y*1.2)  # Set the y-axis limit to include the maximum value

  plt.xlabel('Panjang Kunci (bit)')
  plt.ylabel('Penggunaan Memori (Mb)')
  plt.title(f'Perbandingan Penggunaan Memori RSA dengan Plaintext {characters} Karakter')
  plt.xticks(indices + bar_width / 2, [128, 256, 512, 1024, 2048])  # Set x-axis ticks to range 1 to 10
  plt.legend()
  name_plot = f'Memory used {characters} characters.png'
  plt.savefig(name_plot, format="png")
  plt.close()

def plot_comparison_memory(data_1, data_2, bit:int, characters:int, A:int):
  New_data1 = []
  New_data2 = []
  random_array = random.sample(range(len(data_1)), 10)
  for i in random_array:
    #print(i)
    New_data1.append(data_1[i])
    New_data2.append(data_2[i])
  indices = np.arange(len(New_data1))
  # Set the width of each bar
  bar_width = 0.35
  # Plot histogram for array1
  plt.figure(figsize=[10,6]) 
  plt.bar(indices, New_data1, bar_width, alpha=0.5, color='b', label='RSA Standard')

  # Plot histogram for array2, shifting the bars to the right
  plt.bar(indices + bar_width, New_data2, bar_width, alpha=0.5, color='r', label='RSA-CRT')

  # Annotate the plot with values above each bar
  for i, (a1, a2) in enumerate(zip(New_data1, New_data2)):
      maxs = max([a1,a2])
      plt.text(i, a1+(0.02*maxs), f'{a1:.3f}', ha='center', va='bottom')
      plt.text(i + bar_width, a2-(0.03*maxs), f'{a2:.3f}', ha='center', va='top')

  max_y = max(max(New_data1), max(New_data2)) + 1  # Find the maximum value among both arrays and add 1
  plt.ylim(0, max_y*1.2)  # Set the y-axis limit to include the maximum value

  plt.xlabel('Index Ciphertext')
  plt.ylabel('Memory used (MB)')
  plt.title(f'Memory Comparison Each Step of Plaintext {bit} bit {characters} characters ke {A}')
  plt.xticks(indices + bar_width / 2, random_array)  # Set x-axis ticks to range 1 to 10
  plt.legend()
  name_plot = f'Memory comparison each step of plaintext {bit} bit {characters} characters ke {A}.png'
  plt.savefig(name_plot, format="png")
  plt.close()

def plot_comparison_time(data_1, data_2, bit:int, characters:int, A:int):
  New_data1 = []
  New_data2 = []
  random_array = random.sample(range(len(data_1)), 10)
  for i in random_array:
    #print(i)
    New_data1.append(data_1[i])
    New_data2.append(data_2[i])
  indices = np.arange(len(New_data1))
  # Set the width of each bar
  bar_width = 0.35
  # Plot histogram for array1
  plt.figure(figsize=[10,6]) 
  plt.bar(indices, New_data1, bar_width, alpha=0.5, color='b', label='RSA Standard')

  # Plot histogram for array2, shifting the bars to the right
  plt.bar(indices + bar_width, New_data2, bar_width, alpha=0.5, color='r', label='RSA-CRT')

  # Annotate the plot with values above each bar
  for i, (a1, a2) in enumerate(zip(New_data1, New_data2)):
      maxs = max([a1,a2])
      plt.text(i, a1+(0.02*maxs), f'{a1:.2e}', ha='center', va='bottom')
      plt.text(i + bar_width, a2+(0.02*maxs), f'{a2:.2e}', ha='center', va='bottom')

  max_y = max(max(New_data1), max(New_data2))  # Find the maximum value among both arrays and add 1
  min_y = min(min(New_data1), min(New_data2))
  plt.ylim(min_y, max_y*1.05)  # Set the y-axis limit to include the maximum value

  plt.xlabel('Index Ciphertext')
  plt.ylabel('Time Execution (s)')
  plt.title(f'Time Execution Each Step of Plaintext {bit} bit {characters} characters ke {A}')
  plt.xticks(indices + bar_width / 2, random_array)  # Set x-axis ticks to range 1 to 10
  plt.legend()
  name_plot = f'Time Execution each step of plaintext {bit} bit {characters} characters ke {A}.png'
  plt.savefig(name_plot, format="png")
  plt.close()

def plot_grafik_time(data1, data2, data3):
  indices = np.arange(len(data1))
  plt.figure(figsize=[10,6]) 
  plt.plot(indices, data1, marker='o', linestyle='-', color='blue', label='50000 karakter')

# Plot histogram for array2, shifting the bars to the right
  plt.plot(indices, data2,  marker='o', linestyle='-', color='red', label='100000 karakter')
  
  plt.plot(indices, data3,  marker='o', linestyle='-', color='yellow', label='300000 karakter')
  for i, (a1, a2, a3) in enumerate(zip(data1, data2, data3)):
    plt.text(i, a1 + 0.1, f'{a1:.2f}', ha='center', va='bottom')
    plt.text(i, a2 + 0.1, f'{a2:.2f}', ha='center', va='bottom')
    plt.text(i, a3 + 0.1, f'{a3:.2f}', ha='center', va='bottom')

  #max_y = max(max(data1), max(data2)) + 1  # Find the maximum value among both arrays and add 1
  #plt.ylim(0, max_y)  # Set the y-axis limit to include the maximum value

  plt.xlabel('Bit')
  plt.ylabel('Pertumbuhan kecepatan)')
  plt.title(f'Pertumbuhan kecepatan RSA-CRT terhadap RSA Standard')
  plt.xticks(indices, bit)  # Set x-axis ticks to range 1 to 10
  plt.yticks(np.arange(1, 4, 0.3))
  plt.legend()
  name_plot = f'Time execution.png'
  plt.savefig(name_plot, format="png")
  plt.close()
    
def plot_grafik_memori(data1, data2, data3):
  indices = np.arange(len(data1))
  plt.figure(figsize=[10,6]) 
  plt.plot(indices, data1, marker='o', linestyle='-', color='blue', label='50000 karakter')

# Plot histogram for array2, shifting the bars to the right
  plt.plot(indices, data2,  marker='o', linestyle='-', color='red', label='100000 karakter')
  
  plt.plot(indices, data3,  marker='o', linestyle='-', color='yellow', label='300000 karakter')
  for i, (a1, a2, a3) in enumerate(zip(data1, data2, data3)):
    plt.text(i, a1 + 0.1, f'{a1:.2f}', ha='center', va='bottom')
    plt.text(i, a2 + 0.1, f'{a2:.2f}', ha='center', va='bottom')
    plt.text(i, a3 + 0.1, f'{a3:.2f}', ha='center', va='bottom')

  max_y = max(max(data1), max(data2)) + 1  # Find the maximum value among both arrays and add 1
  plt.ylim(0, max_y*1.2)  # Set the y-axis limit to include the maximum value

  plt.xlabel('Bit')
  plt.ylabel('Pertumbuhan memori)')
  plt.title(f'Pertumbuhan memori RSA-CRT terhadap RSA Standard')
  plt.xticks(indices, bit)  # Set x-axis ticks to range 1 to 10
  plt.yticks([1,2,3,4])
  plt.legend()
  name_plot = f'Memory Used.png'
  plt.savefig(name_plot, format="png")
  plt.close()
    
def directory_changes(basedir, characters,bit):
  if os.path.exists(f'{basedir}/{characters}/Pictures'):
    print("ADA 1")
    shutil.rmtree(f'{basedir}/{characters}/Pictures')
    os.mkdir(f'{basedir}/{characters}/Pictures')
  else:
    os.mkdir(f'{basedir}/{characters}/Pictures')
    print("ADA 2")

  name_plot_memory = f'Memory used {bit} bit {characters} characters.png'
  name_plot_time = f'Time execution {bit} bit {characters} characters.png'
  os.replace(f'{base_dir}/{name_plot_time}', f'{basedir}/{characters}/Pictures/{name_plot_time}')
  os.replace(f'{base_dir}/{name_plot_memory}', f'{basedir}/{characters}/Pictures/{name_plot_memory}')
  #for i in range(1,6):
  #  name_plot_comparison = f'Memory comparison each step of plaintext {bit} bit {characters} characters ke {i}.png'
  #  os.replace(f'{base_dir}/{name_plot_comparison}', f'{basedir}/{characters}/Pictures/{name_plot_comparison}')
  #  name_plot_comparison_memory = f'Time Execution each step of plaintext {bit} bit {characters} characters ke {i}.png'
  #  os.replace(f'{base_dir}/{name_plot_comparison_memory}', f'{basedir}/{characters}/Pictures/{name_plot_comparison_memory}')

    
def open_file(base_dir, characters:str, bit:str):
    d = {}
    namafile = f'{base_dir}/Hasil {characters} {bit}.txt'
    with open(namafile) as file:
        A = 0
        for item in file:
                float_list = eval(item)
                integer_list = [float(x) for x in float_list]
                d[A] = integer_list
                A += 1
    time_standard = d[0]
    time_CRT = d[1]
    memory_standard = d[2]
    memory_CRT = d[3]
    #plot_time(time_standard, time_CRT, bit, characters)
    #plot_memory(memory_standard, memory_CRT, bit, characters)
    #directory_changes(base_dir, characters,bit)
    time_std = 0
    for i in time_standard:
      time_std = time_std+i
      avg_time_std = time_std/len(time_standard)
    
    time_crt_ = 0
    for i in time_CRT:
      time_crt_ = time_crt_+i
      avg_time_crt = time_crt_/len(time_standard)
    
    memory_std = 0
    for i in memory_standard:
      memory_std = memory_std+i
      avg_memory_std = memory_std/len(time_standard)
    
    memory_crt_ = 0
    for i in memory_CRT:
      memory_crt_ = memory_crt_+i
      avg_memory_crt = memory_crt_/len(time_standard)
    
    return avg_time_std, avg_time_crt, avg_memory_std, avg_memory_crt


if __name__ == '__main__':
    bit = ['128', '256', '512', '1024', '2048']
    character = ['50000', '100000', '300000']
    base_dir = 'C:/Users/Adita Raffl H/Documents/python/Tugas Akhir'
    base_dir_2 = os.path.join(base_dir,'Hasil Coba Coba')

    time_std_10000= []
    time_crt_10000= []
    memory_std_10000 = []
    memory_crt_10000 = []
    time_std_25000= []
    time_crt_25000= []
    memory_std_25000 = []
    memory_crt_25000 = []
    time_std_50000= []
    time_crt_50000= []
    memory_std_50000 = []
    memory_crt_50000 = []
    time_std_100000= []
    time_crt_100000= []
    memory_std_100000 = []
    memory_crt_100000 = []
    time_std_300000= []
    time_crt_300000= []
    memory_std_300000 = []
    memory_crt_300000 = []
    
    for j in bit: 
        x = os.path.join(base_dir_2, j)
        time_std, time_crt, memori_std, memori_crt = open_file(x, '50000', j)
        time_std_50000.append(time_std)
        time_crt_50000.append(time_crt)
        memory_std_50000.append(memori_std)
        memory_crt_50000.append(memori_crt)

    for j in bit: 
        x = os.path.join(base_dir_2, j)
        time_std, time_crt, memori_std, memori_crt = open_file(x, '100000', j)
        time_std_100000.append(time_std)
        time_crt_100000.append(time_crt)
        memory_std_100000.append(memori_std)
        memory_crt_100000.append(memori_crt)
        
    for j in bit: 
        x = os.path.join(base_dir_2, j)
        time_std, time_crt, memori_std, memori_crt = open_file(x, '300000', j)
        time_std_300000.append(time_std)
        time_crt_300000.append(time_crt)
        memory_std_300000.append(memori_std)
        memory_crt_300000.append(memori_crt)
        
    for j in bit: 
        x = os.path.join(base_dir_2, j)
        time_std, time_crt, memori_std, memori_crt = open_file(x, '10000', j)
        time_std_10000.append(time_std)
        time_crt_10000.append(time_crt)
        memory_std_10000.append(memori_std)
        memory_crt_10000.append(memori_crt)

    for j in bit: 
        x = os.path.join(base_dir_2, j)
        time_std, time_crt, memori_std, memori_crt = open_file(x, '25000', j)
        time_std_25000.append(time_std)
        time_crt_25000.append(time_crt)
        memory_std_25000.append(memori_std)
        memory_crt_25000.append(memori_crt)

    
    plot_time(time_std_50000, time_crt_50000, '50000')
    plot_time(time_std_100000, time_crt_100000, '100000')
    plot_time(time_std_300000, time_crt_300000, '300000')
    plot_time(time_std_10000, time_crt_10000, '10000')
    plot_time(time_std_25000, time_crt_25000, '25000')
    
    plot_memory(memory_std_50000, memory_crt_50000, '50000')
    plot_memory(memory_std_100000, memory_crt_100000, '100000')
    plot_memory(memory_std_300000, memory_crt_300000, '300000')
    plot_memory(memory_std_10000, memory_crt_10000, '10000')
    plot_memory(memory_std_25000, memory_crt_25000, '25000')
