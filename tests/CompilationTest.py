import os


os.system("rm bin/privesc.elf")

print("[+] Removed privesc.elf")
print("[+] Compiling Project")

os.system("g++ -o bin/privesc.elf src/privesc.cpp -g -static")
if os.path.exists("bin/privesc.elf"):
    print("[+] Compilation Successful")
    exit (0)
else:
    print("[!] Compilication Failed")
    exit (1)


