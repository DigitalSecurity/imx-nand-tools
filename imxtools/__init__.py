"""
IMX Tools main module

@author Damien "virtualabs" Cauquil <damien.cauquil@digital.security>
"""
import sys
import os.path
import bchlib
import progressbar

from math import ceil
from struct import unpack
from argparse import ArgumentParser

from termcolor import colored
from imxtools.fcb import FCB, FCBError

def skip_bits(page, nbits, nbytes):
    """
    Skip bits for a given page
    """
    # compute relative shifting and complementary shifting values
    rel_shift = int(nbits%8)
    comp_shift= int(8 - rel_shift)

    # skip nbits/8 bytes first
    page = page[int(nbits/8):]
    page += bytes([0])

    if rel_shift > 0:
        # Loop over bytes and shift rel_shift bits to the left
        output = []
        for i in range(nbytes):
            output.append(
                (page[i]>>rel_shift) | ((page[i+1] << comp_shift)&0xff)
            )
    else:
        output = page
    return output

def parse_fcb(content, verbosity=None, display=False):
    """
    Parse and display the FCB structure.
    """
    fcb = FCB(content)

    # Display FCB if required
    if display:
        fcb.display()

    # return FCB info
    return fcb


def ecc_correct(block, code, ecc_strength):
    """
    Try to fix `block` with `code`, for an ECC size of `bitsize`.
    """
    ecc = bchlib.BCH(8219, ecc_strength, reverse=True)
    try:
        block_ = ecc.correct(bytes(block), bytes(code))
        return block_
    except Exception as e:
        return block


def process_page(page, fcb, ecc=False):
    """
    Split page in blocks and ecc codes.
    """
    # First, remove metadata bytes
    page_size = len(page)
    marker = page[0]
    assert(page[fcb.marker_raw_offset]==0xff)
    page = page[:fcb.marker_raw_offset] + bytes([marker]) + page[fcb.marker_raw_offset+1:]
    page = page[fcb.metadata_bytes:]

    blocks = []
    nb_blocks = fcb.nb_ecc_blocks_per_page+1

    # Iterate over each block
    n = 8
    for i in range(nb_blocks):
        # First block is processed separately
        if i==0:
            ecc_size = fcb.get_ecc_block0_size()
            ecc_strength = fcb.get_ecc_block0_strength()
            block_size = fcb.get_data_block0_size()
        else:
            ecc_size = fcb.get_ecc_blockN_size()
            ecc_strength = fcb.get_ecc_blockN_strength()
            block_size = fcb.get_data_blockN_size()

        ecc_nb_bytes = int(ecc_size/8)
        if (fcb.get_ecc_block0_size()%8 > 0):
            ecc_nb_bytes += 1
        ecc = page[block_size:block_size+ecc_nb_bytes]


        # copy block_size bytes
        block = page[:block_size]

        # try to correct block if required
        if ecc:
            block = ecc_correct(block, ecc, ecc_strength*2)

        # save block
        blocks.append(block)

        # skip ecc_size (in bits) bits
        page = skip_bits(page, block_size*8 + ecc_size, int(((block_size*8 + ecc_size)*(n-1))/8))
        n -= 1

    # Align to original page size
    output = []
    for block in blocks:
        output.extend(block)
    return bytes(output)

def extract_firmware(content, fcb, output, firmware_id, bb_marker_override=None, metadata_override=None, page_size_override=None, correct_ecc=False, ecc_size_override=None):
    """
    Convert an IMX NAND dump to memory dump.
    """
    # Apply overrides if defined
    if metadata_override is not None:
        fcb.set_metadata_bytes(metadata_override)
    if page_size_override is not None:
        fcb.set_page_data_size(page_size_override)
    if ecc_size_override is not None:
        fcb.set_ecc_size(ecc_size_override)
    if bb_marker_override is not None:
        fcb.set_bb_marker(bb_marker_override)

    # We keep only a fraction of the content, as described in the FCB
    if firmware_id == 1:
        content = content[fcb.fw1_start * fcb.total_page_size:(fcb.fw1_start + fcb.pages_fw1) * fcb.total_page_size]
    elif firmware_id == 2:
        content = content[fcb.fw2_start * fcb.total_page_size:(fcb.fw2_start + fcb.pages_fw2) * fcb.total_page_size]

    blocksize = fcb.total_page_size
    globsize = len(content)
    nbblocks = int(globsize/blocksize)

    valid_blocks = 0
    bad_blocks = 0
    output = open(output,'wb')
    bar = progressbar.ProgressBar(max_value=nbblocks)
    for i in range(nbblocks):
        bar.update(i)
        page = content[i*blocksize:(i+1)*blocksize]
        c_block = process_page(page, fcb, correct_ecc)
        output.write(c_block)
    output.close()

def convert_nand_dump(content, fcb, output, bb_marker_override=None, metadata_override=None, page_size_override=None, correct_ecc=False, ecc_size_override=None):
    """
    Convert an IMX NAND dump to memory dump.
    """
    # Apply overrides if defined
    if metadata_override is not None:
        fcb.set_metadata_bytes(metadata_override)
    if page_size_override is not None:
        fcb.set_page_data_size(page_size_override)
    if ecc_size_override is not None:
        fcb.set_ecc_size(ecc_size_override)
    if bb_marker_override is not None:
        fcb.set_bb_marker(bb_marker_override)

    blocksize = fcb.total_page_size
    globsize = len(content)
    nbblocks = int(globsize/blocksize)

    valid_blocks = 0
    bad_blocks = 0
    output = open(output,'wb')
    bar = progressbar.ProgressBar(max_value=nbblocks)
    for i in range(nbblocks):
        bar.update(i)
        page = content[i*blocksize:(i+1)*blocksize]
        c_block = process_page(page, fcb, correct_ecc)
        output.write(c_block)
    output.close()


def find_fcb_offset(content):
    """
    Find Flash Control Block offset

    @return int offset >=0 on success, -1 if an error occured.
    """
    try:
        index = content.index(b'FCB ')
        if (index > 4):
            return (index-4)
        return -1
    except ValueError as exc:
        return -1
