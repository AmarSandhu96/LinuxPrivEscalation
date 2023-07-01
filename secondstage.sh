#!/usr/bin/expect
set VulnLinux 10.10.181.99
set VulnLinuxPass password321

spawn scp dummyfile.elf user@$VulnLinux:/tmp/
expect "user@$VulnLinux's password:"
send $VulnLinuxPass\n
interact
