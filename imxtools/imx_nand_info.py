"""
         ___ __  ____  __  _____         _
        |_ _|  \/  \ \/ /_|_   _|__  ___| |___
         | || |\/| |>  <___|| |/ _ \/ _ \ (_-<
        |___|_|  |_/_/\_\   |_|\___/\___/_/__/

IMX Nand Information tool
=========================

This tool


"""

from argparse import ArgumentParser
from imxtools import parse_fcb, find_fcb_offset
from termcolor import colored

def main():
    parser = ArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true', default=False, dest='verbose', help='Be more verbose')
    parser.add_argument('-o', '--offset', dest='offset', help='Force FCB offset value')
    parser.add_argument('nand_dump', type=str, help='Raw NAND dump to process')
    args = parser.parse_args()

    print(colored('''
     ___ __  ____  __  _____         _
    |_ _|  \/  \ \/ /_|_   _|__  ___| |___
     | || |\/| |>  <___|| |/ _ \/ _ \ (_-<
    |___|_|  |_/_/\_\   |_|\___/\___/_/__/

      ---< IMX Nand Info >---
    ''', 'cyan', attrs=['bold']))

    # Load file
    if args.verbose:
        print('>> Loading memory dump ...')
    dump = open(args.nand_dump, 'rb').read(4096)

    # Override offset if provided
    if args.offset is not None:
        # Accept decimal and hexadecimal offset values
        if args.offset.lower().startswidth('0x'):
            offset = int(args.offset, 16)
        else:
            offset = int(args.offset)
        if args.verbose:
            print('>> Forcing FCB offset to %x' % offset)
    else:
        offset = find_fcb_offset(dump)

    if offset < 0:
        print('!!'+colored('FCB not found, check your dump.', 'red', attrs=['bold']))
    else:
        if args.verbose:
            print('>> Dumping FCB details ...')
        # Display NAND info
        fcb = dump[offset:offset+140]
        parse_fcb(fcb, verbosity=args.verbose, display=True)
