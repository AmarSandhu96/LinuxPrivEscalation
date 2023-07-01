#!/usr/bin/expect
set AttackBox 10.10.139.200
set AttackBoxPass b3f665953f9067dd
set VulnLinux 10.10.181.99
set VulnLinuxPass password321

spawn scp dummyfile.elf secondstage.sh root@$AttackBox:/root/
expect "root@$AttackBox's password:"
send $AttackBoxPass\n
interact

