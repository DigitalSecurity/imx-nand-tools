"""
IMX Flash Control Block module

This module parses and allow manipulation of the Flash Control Block.

@author Damien Cauquil <damien.cauquil@digital.security>
"""

from math import ceil
from struct import unpack
from termcolor import colored

def formatval(v):
    """
    Format value string.
    """
    return colored(v, 'cyan', attrs=['bold'])

def u32le(b, offset):
    """
    Reads a LE unsigned integer from `b` at the given `offset`.
    """
    return unpack('<I', b[offset:offset+4])[0]


class FCBError(Exception):
    """
    FCB Error descriptor
    """

    def __init__(self, message):
        """
        @param  message string  Message to associate with this error.
        """
        Exception.__init__(self)
        self.message = message

    def __repr__(self):
        """
        Class representation
        """
        return '<FCBError msg="%s">' % self.message


class FCB(object):
    """
    Flash Control Block class
    """

    def __init__(self, content):
        """
        Constructor, parses the FCB content.
        """
        if len(content) >= 132:
            try:
                # Unpack all the fields
                self.magic = content[4:8]
                if self.magic != b'FCB ':
                    raise FCBError('Wrong FCB magic value (%08x instead of %08x)' % (
                        unpack('<I', self.magic),
                        unpack('<I', b'FCB ')
                    ))
                self.version = unpack('>I', content[8:12])[0]
                self.page_data_size = u32le(content, 20)
                self.total_page_size = u32le(content, 24)
                self.sectors_per_block = u32le(content, 28)
                self.nb_nands = u32le(content, 32)
                self.ecc_block_type = u32le(content, 44)
                self.ecc_block0size = u32le(content, 48)
                self.ecc_blockNsize = u32le(content, 52)
                self.ecc_block0type= u32le(content, 56)
                self.metadata_bytes = u32le(content, 60)
                self.nb_ecc_blocks_per_page = u32le(content, 64)
                self.fw1_start = u32le(content, 104)
                self.fw2_start = u32le(content, 108)
                self.pages_fw1 = u32le(content, 112)
                self.pages_fw2 = u32le(content, 116)
                self.bch_type = u32le(content, 136)
                self.bb_marker = u32le(content, 124)
                self.bb_marker_bits = u32le(content, 128)

                # We compute the raw marker offset
                self.marker_page = int(self.bb_marker/self.ecc_blockNsize)
                self.marker_offset = self.bb_marker % self.ecc_blockNsize
                self.marker_raw_offset = int(self.metadata_bytes + ceil((self.ecc_block0type*26)/8) + ceil((self.marker_page-1)*(self.ecc_block_type*26)/8) + self.bb_marker)
            except TypeError as type_exc:
                raise FCBError("Content MUST be bye of type `bytes`")
        else:
            raise FCBError("FCB content must contain at least 132 bytes")

    def get_ecc_block0_size(self):
        """
        Get the first block ECC size in bits.

        @return int ECC size in bits
        """
        return (self.ecc_block0type * 26)

    def get_ecc_block0_strength(self):
        """
        Get the first block ECC strength (BCH).

        @return int ECC strength (BCH)
        """
        return (self.ecc_block0type)

    def get_ecc_blockN_size(self):
        """
        Get the next blocks ECC size in bits.

        @return int ECC size in bits
        """
        return (self.ecc_block_type * 26)

    def get_ecc_blockN_strength(self):
        """
        Get the next blocks ECC strength (BCH).

        @return int ECC strength (BCH)
        """
        return (self.ecc_block_type)

    def get_data_block0_size(self):
        """
        Get first block data size on which the ECC is computed.

        @return int data block size
        """
        return self.ecc_block0size

    def get_data_blockN_size(self):
        """
        Get next blocks data size on which the ECC is computed.

        @return int data block size
        """
        return self.ecc_blockNsize

    def set_metadata_bytes(self, metadata_bytes):
        """
        Force metadata bytes size.

        @param metadata_bytes   int Metadata bytes size
        """
        self.metadata_bytes = metadata_bytes

    def set_page_data_size(self, page_data_size):
        """
        Set page data size.

        @param page_data_size   int Page size in bytes
        """
        self.page_data_size = page_data_size

    def set_ecc_size(self, ecc_size):
        """
        Set ECC size in bits.

        @param ecc_size int ECC size in bits.
        """
        self.ecc_block0type = int(ecc_size/26)
        self.ecc_block_type = int(ecc_size/26)

    def set_bb_marker(self, bb_marker):
        """
        Force bad block marker offset.

        @param bb_marker chr Bad block marker offset to use.
        """
        self.bb_marker = bb_marker
        # We compute the raw marker offset
        self.marker_page = int(self.bb_marker/self.ecc_blockNsize)
        self.marker_offset = self.bb_marker % self.ecc_blockNsize
        self.marker_raw_offset = int(self.metadata_bytes + ceil((self.ecc_block0type*26)/8) + ceil((self.marker_page-1)*(self.ecc_block_type*26)/8) + self.bb_marker)

    def display(self):
        """
        Display FCB to standard output.
        """
        # Display information
        print('FCB version: %d' % self.version)
        print('')
        print('---[ NAND structure ]---------')
        print(' > Page data size:\t'+ formatval('%d bytes'% self.page_data_size))
        print(' > Total page size:\t' + formatval('%d bytes (OOB: %d bytes)' % (self.total_page_size, self.total_page_size - self.page_data_size)))
        print(' > Sectors/block:\t' + formatval('%d' % self.sectors_per_block))
        print(' > Number of Nands:\t' + formatval('%d' % self.nb_nands))
        print('')
        print('---[ ECC ]--------------------')
        print(' > ECC block 0 type:\t' + formatval('%d (%d bits)' % (self.ecc_block0type, self.ecc_block0type*26)))
        print(' > ECC block 0 size:\t' + formatval('%d bytes' % self.ecc_block0size))
        print(' > ECC block N type:\t' + formatval('%d (%d bits)' % (self.ecc_block_type, self.ecc_block_type*26)))
        print(' > ECC block N size:\t' + formatval('%d bytes' % self.ecc_blockNsize))
        print(' > Metadata bytes:\t' + formatval('%d' % self.metadata_bytes))
        # Original NumEccBlocksPerPage does not include Block0
        print(' > ECC blocks/page:\t' + formatval('%d' % (self.nb_ecc_blocks_per_page +1)))
        print(' > ECC BCH Type:\t%d' % self.bch_type)
        print('')
        print('---[ BadBlocks ]--------')
        print(' > Bad block marker byte:\t' + formatval('0x%x' % self.bb_marker))
        print(' > Bad block start bit:\t\t' + formatval('0x%x' % self.bb_marker_bits))
        print(' > Bad block Marker raw offset:\t' + formatval('0x%x' % self.marker_raw_offset))
        print('')
        print('---[ Firmware Info]-----')
        print(' > Firmware #1:\t' + formatval('start @%08x (%d pages, %d bytes)' % (self.fw1_start, self.pages_fw1, self.pages_fw1*self.page_data_size)))
        print(' > Firmware #2:\t' + formatval('start @%08x (%d pages, %d bytes)' % (self.fw2_start, self.pages_fw2, self.pages_fw1*self.page_data_size)))
