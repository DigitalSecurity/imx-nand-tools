"""
         ___ __  ____  __  _____         _
        |_ _|  \/  \ \/ /_|_   _|__  ___| |___
         | || |\/| |>  <___|| |/ _ \/ _ \ (_-<
        |___|_|  |_/_/\_\   |_|\___/\___/_/__/

IMX Nand Conversion tool
=========================

"""

from argparse import ArgumentParser
from imxtools import convert_nand_dump, find_fcb_offset, extract_firmware
from imxtools.fcb import FCB
from termcolor import colored


def main():
    parser = ArgumentParser()
    parser.add_argument('-o', '--offset', dest='offset', help='Force FCB offset value')
    parser.add_argument('-b', '--bad-block-offset', dest='bb_offset', help='Force bad block marker offset')
    parser.add_argument('-p', '--page-size', dest='page_size', help='Force page size (in bytes)')
    parser.add_argument('-m', '--metadata-size', dest='metadata_size', help='Force metadata size (in bytes)')
    parser.add_argument('-e', '--ecc-size', dest='ecc_size', help='Force ECC size (in bits)')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, dest='verbose', help='Be more verbose')
    parser.add_argument('-f', '--firmware', dest='firmware', type=int, help='Firmware number to extract (default: 1)')
    parser.add_argument('-c', '--correct', dest='ecc', action='store_true', default=False, help='Correct errors with ECC')
    parser.add_argument('nand_dump', type=str, help='Raw NAND dump to process')
    parser.add_argument('output_nand_dump', type=str, help='Output NAND dump')
    args = parser.parse_args()

    print(colored('''
     ___ __  ____  __  _____         _
    |_ _|  \/  \ \/ /_|_   _|__  ___| |___
     | || |\/| |>  <___|| |/ _ \/ _ \ (_-<
    |___|_|  |_/_/\_\   |_|\___/\___/_/__/

      ---< IMX Nand Convert >---
    ''', 'cyan', attrs=['bold']))

    # Load file
    if args.verbose:
        print('>> Loading memory dump ...')
    dump = open(args.nand_dump, 'rb').read()

    # Override offset if provided
    if args.offset is not None:
        # Accept decimal and hexadecimal offset values
        if args.offset.lower().startswidth('0x'):
            offset = int(args.offset, 16)
        else:
            offset = int(args.offset)
    else:
        offset = find_fcb_offset(dump)

    if offset < 0:
        print('!!'+colored('FCB not found, check your dump.', 'red', attrs=['bold']))
    else:
        if args.firmware is not None:
            if args.firmware in [1,2]:
                print('>> FCB found at offset 0x%08x' % offset)
                print('>> Extracting firmware #%d ...' % args.firmware)

                # Parse FCB
                fcb = FCB(dump[offset:offset+140])

                extract_firmware(dump, fcb, args.output_nand_dump, args.firmware, args.bb_offset, args.metadata_size, args.page_size, args.ecc, args.ecc_size)
            else:
                print(colored('>> Firmware index MUST be 1 OR 2.', 'red', attrs=['bold']))
        else:
            print('>> FCB found at offset 0x%08x' % offset)
            print('>> Converting image ...')
            # Display NAND info
            fcb = FCB(dump[offset:offset+140])
            convert_nand_dump(dump, fcb, args.output_nand_dump, args.bb_offset, args.metadata_size, args.page_size, args.ecc, args.ecc_size)
