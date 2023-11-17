import os


os.system("rm /home/runner/work/LinuxPrivEscalation/LinuxPrivEscalation/bin/privesc.elf")

print("[+] Removed privesc.elf")
print("[+] Compiling Project")

os.system("g++ -o /home/runner/work/LinuxPrivEscalation/LinuxPrivEscalation/bin/privesc.elf /home/runner/work/LinuxPrivEscalation/LinuxPrivEscalation/src/privesc.cpp -g -static")
if os.path.exists("/home/runner/work/LinuxPrivEscalation/LinuxPrivEscalation/bin/privesc.elf"):
    print("[+] Compilation Successful")
    exit (0)
else:
    print("[!] Compilication Failed")
    exit (1)


