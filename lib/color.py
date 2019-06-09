#!/usr/bin/env python3

"""
Copyright (c) 2019 TheSphinx

'Truecolors' library based on colorama.
"""

import sys
from tabulate import tabulate
from datetime import datetime
from time import gmtime, strftime
from colorama import Fore, Back, Style, init

def print_info(s):
    print ("[" + Fore.CYAN + datetime.now().strftime('%H:%M:%S') + Style.RESET_ALL + "] [" + Fore.GREEN + "INFO" + Style.RESET_ALL + "] " + s)
    
def print_succ(s):
    print ("[" + Fore.CYAN + Style.BRIGHT + datetime.now().strftime('%H:%M:%S') + Style.RESET_ALL + "] [" + Fore.GREEN + Style.BRIGHT + "INFO" + Style.RESET_ALL + "] " + Style.BRIGHT + s + Style.RESET_ALL)

def print_warn(s):
    print ("[" + Fore.CYAN + datetime.now().strftime('%H:%M:%S') + Style.RESET_ALL + "] [" + Fore.YELLOW + Style.BRIGHT + "WARNING" + Style.RESET_ALL + "] " + s)

def print_errn(s):
    print ("[" + Fore.CYAN + datetime.now().strftime('%H:%M:%S') + Style.RESET_ALL + "] [" + Back.RED + Fore.WHITE + Style.BRIGHT + "CRITICAL" + Style.RESET_ALL + "] " + s)

def print_answ(s):
    sys.stdout.write(Fore.BLUE + Style.BRIGHT + "[?] " + Style.RESET_ALL + s)

def print_simple_blue(s):
    print (Fore.BLUE + Style.BRIGHT + strftime("%Y/%m/%d %H:%M:%S ", gmtime()) + s + Style.RESET_ALL)

def print_simple_errno(s):
    print (Fore.RED + Style.BRIGHT + strftime("%Y/%m/%d %H:%M:%S ", gmtime()) + s + Style.RESET_ALL)

def print_simple_succ(s):
    print (Fore.GREEN + Style.BRIGHT + strftime("%Y/%m/%d %H:%M:%S ", gmtime()) + s + Style.RESET_ALL)

def print_tabulate(list_c, headr, style): # tuple, tuple
        empty()
        print (tabulate(list_c, headers=headr, tablefmt=style))
        empty()

def empty():
    print("")