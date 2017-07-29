#!/usr/bin/env python
# coding: utf-8

import argparse
import sys
from subprocess import Popen, PIPE, STDOUT
import IPython

def hex2bin(cont):
	result = ''.join(bin(int(x, 16))[2:].rjust(8, '0') for x in cont)
	return result[0:len(cont) * 8 + 9 - len(cont) * 8 % 9]


def pos2addr(pos):
	assert(pos % 16 == 0)
	return pos/16


def low9(addr):
	t = bin(addr)[2:]
	return int('0b' + t[-17:],2)


def high9(addr):
	t = bin(addr)[2:].rjust(27,'0')
	return int('0b' + t[:17],2)


def asm2stream(asm):
	p = Popen(('./as.py', '-f','bin','-'), stdin = PIPE, stdout=PIPE)
	patch_stream = p.communicate(asm)[0].replace(' ','')
	if not all([(x == '0' or x == '1') for x in patch_stream]):
		print("[!] as.py error : %s" % patch_stream)
		sys.exit(1)
	return patch_stream


def modify(stream, offset, asm_stream):
	stream[offset:offset+len(asm_stream)] = asm_stream



in_firmware = sys.argv[1]
data = open(in_firmware, 'rb').read()
stream = bytearray(''.join(bin(ord(x))[2:].rjust(8, '0') for x in data))

# 补零 test?
size = len(stream) + 0x900 - (len(stream) + 0x900) % 0x900
stream = stream.ljust(size,'0')

#-----------------------------------------------------------------
patch_list = []
patch_addr = []
patch_asm = []
patch_stream = ''
patch_bsize = len(patch_stream)

start_asm = [
	'ML    R20, %s\n', # location 
	'mh    R20, %s\n',
	'ml    R26, 0x1\n',
	'smp    R20, R26, 3\n',
	'bra    %s\n', # location add patch_list
]

end_asm = [
	# move program to higher random space
	'rnd    R21\n',
	'ml    R22, 0xff\n',
	'an    R21, R21, R22\n'
	'sli    R21, R21, 10\n',
	"ml    R20, 0\n",
	'mh    R20, 0x4000\n',
	'ad    R21, R21, R20\n', # random space
	'ml    R26, 0x100\n', # %s
	'smp    R21, R26, 2\n', 
	'ml    R22, 0\n',
	'ml    R20, %s\n',# size of the whole binary
	'dmt    R21, R22, R20\n',
	'smp    R21, R26, 3\n',
	'ad    R22, R21,PC\n',
	'adi    R22, R22,8\n'
	'br    R22\n'

	# set other pages NX 
	# now at random place
	'ml    R22, 1024\n',
	'smp    R22, R26, 2\n',
	
	# continue start
	'mu    R01, R01, R04\n',
	'ad    ST, R0, R1\n',
	'ml    R0, 0x1ff\n',
	'ei    R0\n',
	'or    R0, R5, R5\n',
	'mu    R1, R2, R4\n',
	#'or    ST, R00, R00\n',
	#'ml    R00, 0x3f0\n',
	#'mh    R00, 0x1ffff\n',
	#'ml    R01, 0x1\n',
	#'sts    R01, [R00 + 0, 1]\n',
	#'adi    R21, R21,0x51\n',
	'adi    R21, R21,0x4d\n',
	'br    R21\n', # relative, 0x51
	'br    R21\n'
]

assert size % 9 == 0
add_addr = size / 9
oper_addr = size / 9 + patch_bsize

print hex(add_addr)


start_asm = ''.join(x for x in start_asm) %(hex(low9(add_addr)),hex(high9(add_addr)),hex(low9(oper_addr)))
end_asm = ''.join(x for x in end_asm) % hex(add_addr + 0x100)

print start_asm
print asm2stream(start_asm)
print end_asm
print asm2stream(end_asm)
#IPython.embed()

modify(stream,(0x3c)*9,asm2stream(start_asm))
stream += asm2stream(end_asm)

open(sys.argv[2], 'wb').write(''.join(chr(int(str(stream[i:i+8]),2)) for i in range(0, len(stream), 8)))



'''
000003c:						 4a98400		 ml	 R20, 0x18400
000003f:						 4680061		 mh	 R20, 0x61		   
0000042:						 4b40001		 ml	 R26, 0x1			
0000045:						 52a6b80		 smp	R20, R26, E		 
0000048:						 e20018445	   bra	0x18445[size]

0018445:						 4aa0000		 ml	 R21, 0x0			
0018448:						 46a0400		 mh	 R21, 0x400[higher target,0x100000]		
001844b:						 52aeb00		 smp	R21, R26, RW		
001844e:						 4a80045		 ml	 R20, 0x45		   
0018451:						 4ad8400		 ml	 R22, 0x18400		
0018454:						 46c0061		 mh	 R22, 0x61  [useless]		 
0018457:						 34ada80		 dmt	R21, R22, R20[size]	   
001845a:						 52aeb80		 smp	R21, R26, E		 
001845d:						 e20100011	   bra	0x100011
'''
'''
010002c:						 0808480		 mu	 R01, R01, R04	   
010002f:						 18e8000		 or	 ST, R00, R00		
0100032:						 48003f0		 ml	 R00, 0x3f0		  
0100035:						 441ffff		 mh	 R00, 0x1ffff		
0100038:						 4820001		 ml	 R01, 0x1			
010003b:						 2c040000000000  sts	R01, [R00]		  
0100041:						 e20000051	   bra	0x51 
'''