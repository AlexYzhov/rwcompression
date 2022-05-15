import sys, struct, io
from os import path
from elftools.elf.elffile import ELFFile
from prettytable import PrettyTable

class Method(object):
    NO_COMPRESSION = 0
    BSS_SET_ZERO   = 1
    RW_ZERO_RLE    = 2
    RW_LZ77        = 3

class LoadDescriptor(object):
    def __init__(self, segment, vma = 0, lma = 0, filesz = 0, memsz = 0, method = Method.NO_COMPRESSION):
        self.segment = segment
        self.vma     = vma
        self.lma     = lma
        self.filesz  = filesz
        self.memsz   = memsz
        self.method  = method

class RWCompression(object):
    def __init__(self, segment):
        __vma    = segment.header['p_vaddr']
        __lma    = segment.header['p_paddr']
        __filesz = segment.header['p_filesz']
        __memsz  = segment.header['p_memsz']
        __stream = io.BytesIO(segment.data())
        __data   = __stream.read(__filesz)

        self.type = 'rw'
        self.data = __data
        self.descriptor = LoadDescriptor(
            segment = segment,
            vma     = __vma,
            lma     = 0,
            filesz  = __filesz,
            memsz   = __filesz,
            method  = Method.NO_COMPRESSION
        )

        __compressions = (self.__no_compress, self.__zero_rle_compress, self.__lz77)
        for compression in __compressions:
            (output, filesz, method) = compression(__data)
            if (filesz < self.descriptor.filesz):
                self.data = output
                self.descriptor.filesz = filesz
                self.descriptor.method = method

    def __no_compress(self, input):
        return (input, len(input), Method.NO_COMPRESSION)

    def __zero_rle_compress(self, input):
        (count, output) = (0, [])
        for i, val in enumerate(input):
            if i == 0:
                output.append(val)
                count = 1
            else:
                if val == 0 and input[i-1] == 0:
                    if count + 1 < 255:
                        count += 1
                    else:
                        output.append(0)
                        output.append(count)
                        count = 1
                else:
                    if input[i-1] == 0:
                        output.append(count)
                    output.append(val)
                    count = 1
            if i == len(input)-1 and val == 0:
                output.append(count)
        #for i, val in enumerate(output):
        #    print(str(hex(val)) + ' ' + str(chr(val)))
        return (output, len(output), Method.RW_ZERO_RLE)
    def __lz77(self, input):
        return (input, len(input), Method.RW_LZ77)

class BSSZeros(object):
    def __init__(self, segment):
        __vma    = segment.header['p_vaddr']
        __lma    = segment.header['p_paddr']
        __filesz = segment.header['p_filesz']
        __memsz  = segment.header['p_memsz']
        __bss_sz = __memsz - __filesz
        __stream = io.BytesIO(segment.data())

        __stream.seek(__filesz)
        self.type = 'bss'
        self.data = __stream.read(__bss_sz)
        self.descriptor = LoadDescriptor(
            segment = segment,
            vma     = __vma + __filesz,
            lma     = 0,
            filesz  = 0,
            memsz   = __bss_sz,
            method  = Method.BSS_SET_ZERO
        )

def genimg(fin, blocks):
    img = fin.read()
    hdr  = bytearray(0)
    phdr = bytearray(0)
    data = bytearray(0)
    output = bytearray(0)

    '''
    typedef struct hdr {
        uint32_t  magic;
        uint16_t  phoff;
        uint16_t  phnum;
        uint32_t  reserved[2];
    } hdr_t;
    '''
    hdr += bytearray(struct.pack('IHHII',
                                  0xFEE1DEAD,
                                  16,
                                  len(blocks),
                                  0,
                                  0))

    offset = 0
    for i in range(len(blocks)):
        block = blocks[i]
        descriptor = block.descriptor
        segment = descriptor.segment

        '''
        typedef struct phdr {
            uint32_t type;      /* Segment type */
            uint32_t offset;    /* Segment file offset */
            uint32_t vaddr;     /* Segment virtual address */
            uint32_t paddr;     /* Segment physical address */
            uint32_t filesz;    /* Segment size in file */
            uint32_t memsz;     /* Segment size in memory */
            uint32_t flags;     /* Segment flags */
            uint32_t align;     /* Segment alignment */
        } phdr_t;
        '''
        phdr += bytearray(struct.pack('IIIIIIII',
                                       1,
                                       len(hdr) + 32 * len(blocks) + offset,
                                       descriptor.vma,
                                       descriptor.lma,
                                       descriptor.filesz,
                                       descriptor.memsz,
                                       segment.header['p_flags'],
                                       segment.header['p_align']))
        data += bytearray(block.data)
        offset += len(block.data)

    # Collect compressed.bin
    output += hdr
    output += phdr
    output += data
    with open("compressed.bin", "wb") as fout:
        fout.write(output)

def report(blocks):
    report = PrettyTable()
    report.title = 'RW/BSS Report:'
    report.field_names = ['type', 'vma', 'lma', 'newsz', 'oldsz', 'ratio', 'method']
    report.align = 'l'
    for block in blocks:
        descriptor = block.descriptor
        segment = descriptor.segment

        vma  = descriptor.vma
        lma  = descriptor.lma
        newsz = descriptor.filesz
        oldsz = segment.header['p_filesz'] if block.type == 'rw' else segment.header['p_memsz'] - segment.header['p_filesz']
        ratio = "{:.2%}".format(newsz/oldsz)
        method = descriptor.method
        report.add_row([block.type, hex(vma), hex(lma), newsz, oldsz, ratio, method])
    print(report)

def process(elffile):
    with open(elffile, 'rb') as fin:
        blocks = []
        for segment in ELFFile(fin).iter_segments(type='PT_LOAD'):
            if segment.header['p_vaddr'] != segment.header['p_paddr']:
                blocks.append(RWCompression(segment))
            if segment.header['p_memsz'] != segment.header['p_filesz']:
                blocks.append(BSSZeros(segment))
        genimg(fin, blocks)
        report(blocks)

if __name__ == '__main__':
    elffile = sys.argv[1]
    process(elffile)
