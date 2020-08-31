from coloroma_colors import *
import pefile

# Global variables 
DYNAMIC_BASE = 0x40


def get_aslr_status(is_verify, pefile_path):
	"""
	Checks whether the file has ASLR enabled. Disable if ASLR is enabled.
	"""
	print('[*] Determining if ASLR is enabled...')
	pe = pefile.PE(pefile_path)
	is_aslr = pe.OPTIONAL_HEADER.DllCharacteristics & DYNAMIC_BASE
	if is_aslr:
		if is_verify:
			print('\t[-] Verifying that ASLR is no longer active...')
			print(print_red('\t\t[!] ASLR is still active!'))
		else:
			print(print_red('\t[!] ASLR is active.'))
		return True
	else:
		if is_verify:
			print('\t[-] Verifying that ASLR is no longer active...')
			print(print_green('\t\t[!] ASLR is no longer active!\n'))
		else:
			print(print_green('\t[!] ASLR is not active. No action required.\n'))
		return False


def patch_aslr(pefile_path):
	"""
	Creates a copy of the PE file with ASLR disabled.
	"""
	pe = pefile.PE(pefile_path)
	is_aslr = pe.OPTIONAL_HEADER.DllCharacteristics & DYNAMIC_BASE
	pe.OPTIONAL_HEADER.DllCharacteristics &= ~DYNAMIC_BASE
	print('\t\t[+] Patching pefile...')
	file_name = pefile_path.split('/')[-1]
	patched_file_name = 'alsr_disabled_{}'.format(file_name)
	pefile_path = '{}/{}'.format('/'.join(pefile_path.split('/')[:-1]), patched_file_name)
	pe.write(filename=pefile_path)
	print(print_green('\t\t[!] pefile patched!\n'))
	return pefile_path