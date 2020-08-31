from colorama import Fore,Style


# Colour Function Defintions
def print_green(text):
	return Fore.GREEN + Style.BRIGHT + text + Style.NORMAL + Fore.WHITE


def print_red(text):
	return Fore.RED + Style.BRIGHT + text + Style.NORMAL + Fore.WHITE