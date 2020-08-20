import pefile
import mmap
import os

class AslrRemover(object):
    DYNAMIC_BASE = 0x40

    def __init__(self, pefile_path):
        self.pefile_path = pefile_path
 

    @property
    def pefile_path(self):
        return self._pefile_path
    

    @pefile_path.setter
    def pefile_path(self, pefile_path):
        self._pefile_path = pefile_path 


    def get_aslr_status(self, is_verify):
        '''
        Checks whether the file has ASLR enabled. Disable if ASLR is enabled. 
        '''
        pe = pefile.PE(self.pefile_path)
        is_aslr = pe.OPTIONAL_HEADER.DllCharacteristics & self.DYNAMIC_BASE
        if is_aslr:
            if is_verify:
                print('\t[+] Verifying that ASLR is no longer active...')
                print('\t\t[+] ASLR is still active!')
            else:
                print('\t[+] ASLR is active.')
            return True
        else:
            if is_verify:
                print('\t[+] Verifying that ASLR is no longer active...')
                print('\t\t[+] ASLR is no longer active!')
            else:
                print('\t[+] ASLR is not active. No action required.\n')
            return False


    def patch_aslr(self):
        '''
        Create a copy of the pefile if ALSR is enabled. 
        '''
        pe = pefile.PE(self.pefile_path)
        is_aslr = pe.OPTIONAL_HEADER.DllCharacteristics & self.DYNAMIC_BASE
        pe.OPTIONAL_HEADER.DllCharacteristics &= ~self.DYNAMIC_BASE
        print('\t\t[+] Patching pefile...')
        new_file_path = [i for i in self.pefile_path.split('/')]
        new_file_path[-1] = 'patched_%s' % (new_file_path[-1])
        new_file_path ='\\'.join(new_file_path)
        self.pefile_path = new_file_path
        pe.write(filename=self.pefile_path)
        print('\t\t[+] pefile patched!')
        return self.pefile_path