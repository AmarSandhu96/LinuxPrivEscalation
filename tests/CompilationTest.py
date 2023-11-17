import os


os.system("rm LinuxPrivEscalation/bin/privesc.elf")

print("[+] Removed privesc.elf")
print("[+] Compiling Project")

os.system("g++ -o LinuxPrivEscalation/bin/privesc.elf LinuxPrivEsclation/src/privesc.cpp -g -static")
if os.path.exists("LinuxPrivEscalation/bin/privesc.elf"):
    print("[+] Compilation Successful")
    exit (0)
else:
    print("[!] Compilication Failed")
    exit (1)


