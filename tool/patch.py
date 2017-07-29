#!/usr/bin/env python
# coding: utf-8

# assemble the specific instruction on position in firmware
# depended on as.py (put in the same directory)
# Example: ./patch.py i3_patch.bin 1772E code.S i3_patch_both.bin

import argparse
import subprocess
import sys

def main():
	if len(sys.argv) < 5:
		print('Usage: %s in_firmware address assemble_file out_firmware' % sys.argv[0])
		sys.exit(0)

	in_firmware = sys.argv[1]
	addr = int(sys.argv[2], 16)
	assemble_file = sys.argv[3]
	out_firmware = sys.argv[4]

	data = open(in_firmware, 'rb').read()
	stream = bytearray(''.join(bin(ord(x))[2:].rjust(8, '0') for x in data))

	offset = addr * 9
	p = subprocess.Popen(('./as.py', '-f', 'bin', assemble_file), stdout=subprocess.PIPE)
	asm_stream = p.stdout.read().replace(' ','')
	if not all([(x == '0' or x == '1') for x in asm_stream]):
		print("[!] as.py error : %s" % asm_stream)
		sys.exit(1)
	print('[+] stream length: %d, total %d bytes' % (len(asm_stream), len(asm_stream)/9))

	stream[offset:offset+len(asm_stream)] = asm_stream

	open(out_firmware, 'wb').write(''.join(chr(int(str(stream[i:i+8]),2)) for i in range(0, len(stream), 8)))
	print('[+] written back down ...')


if __name__ == '__main__':
	main()
