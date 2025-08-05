import os
import platform


current_dir = "."

files = [f for f in os.listdir(current_dir) if os.path.join(current_dir, f)]

ipaddresses = set()

for file in files:
    if file.endswith(".csv"):
        with open(file, "r" ) as f:
            lines = f.readlines()
            for line in lines[1:]:
                ipaddresses.add(line.split(',')[0])
                
                
sorted_list = sorted(ipaddresses)
with open("output_ip_addresses.txt", 'w+') as output:
    for line in sorted_list:
        output.write(f"IP Address: {line}\n")
       