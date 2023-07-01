#!/usr/bin/expect
set AttackBox 10.10.116.139
set AttackBoxPass d4c776173ca3a062

spawn scp dummyfile.elf root@$AttackBox:/tmp/
expect "password:\r"
send $AttackBoxPass\n
interact

