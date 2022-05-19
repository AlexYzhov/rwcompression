import os, sys, struct, io, ctypes
from elftools.elf.elffile import ELFFile
from prettytable import PrettyTable

class Method(object):
    NO_COMPRESSION = 0
    BSS_SET_ZERO   = 1
    RW_ZERO_RLE    = 2
    RW_LZ77        = 3

class LoadDescriptor(object):
    def __init__(self, index, segment, vma = 0, lma = 0, filesz = 0, memsz = 0, method = Method.NO_COMPRESSION):
        self.index   = index
        self.segment = segment
        self.vma     = vma
        self.lma     = lma
        self.filesz  = filesz
        self.memsz   = memsz
        self.method  = method

class RWCompression(object):
    def __init__(self, index, segment):
        __vma    = segment['p_vaddr']
        __lma    = segment['p_paddr']
        __filesz = segment['p_filesz']
        __memsz  = segment['p_memsz']
        __stream = io.BytesIO(segment.data())
        __data   = __stream.read(__filesz)

        self.type = 'rw'
        self.data = __data
        self.descriptor = LoadDescriptor(
            index   = index,
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
    def __init__(self, index, segment):
        __vma    = segment['p_vaddr']
        __lma    = segment['p_paddr']
        __filesz = segment['p_filesz']
        __memsz  = segment['p_memsz']
        __bss_sz = __memsz - __filesz
        __stream = io.BytesIO(segment.data())

        __stream.seek(__filesz, 0)
        self.type = 'bss'
        self.data = __stream.read(__bss_sz)
        self.descriptor = LoadDescriptor(
            index   = index,
            segment = segment,
            vma     = __vma + __filesz,
            lma     = 0,
            filesz  = 0,
            memsz   = __bss_sz,
            method  = Method.BSS_SET_ZERO
        )

def find_symbol(elf, name):
    for section in elf.iter_sections(type='SHT_SYMTAB'):
        symbols = section.get_symbol_by_name(name)
        if symbols:
            for symbol in symbols:
                return symbol if symbol.entry['st_info']['bind'] == 'STB_GLOBAL' else None
    return None

def genimg(base, blocks):
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
                                       segment['p_flags'],
                                       segment['p_align']))
        data += bytearray(block.data)
        offset += len(block.data)

    # report
    print('__load_base__: ' + hex(base))

    # Collect compressed binary
    output += hdr
    output += phdr
    output += data
    return output

def make_elf(fin, blocks, image):
    elf = ELFFile(fin)
    for block in blocks:
        if block.descriptor.filesz:
            segment = block.descriptor.segment
            for section in elf.iter_sections(type='SHT_PROGBITS'):
                # modify section header (shdr)
                if segment.section_in_segment(section) and section['sh_addr'] == segment['p_vaddr']:
                    __sec_index = elf.get_section_index(section.name)
                    __sec_offset = elf._section_offset(__sec_index) + 20
                    __sec_filesz = ctypes.c_uint32(block.descriptor.filesz)
                    fin.seek(__sec_offset, 0)
                    fin.write(__sec_filesz)

            # modify segment header (phdr)
            __seg_index  = block.descriptor.index
            __seg_offset = elf._segment_offset(__seg_index) + 16
            __seg_filesz = ctypes.c_uint32(block.descriptor.filesz)
            fin.seek(__seg_offset, 0)
            fin.write(__seg_filesz)

            # modify segment image
            __img_start = segment['p_offset']
            __img_end   = __img_start + segment['p_filesz']
            fin.seek(__img_start, 0)
            fin.write(image)
            assert(fin.tell() <= __img_end)
            return
    return

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
        oldsz = segment['p_filesz'] if block.type == 'rw' else segment['p_memsz'] - segment['p_filesz']
        ratio = "{:.2%}".format(newsz/oldsz)
        method = descriptor.method
        report.add_row([block.type, hex(vma), hex(lma), newsz, oldsz, ratio, method])
    print(report)

def process(elffile):
    with open(elffile, 'r+b') as fin:
        # foreach and execute data compression for rw segments
        (elf, blocks, rosz_limit, rwsz_limit) = (ELFFile(fin), [], 0, 0)
        for index in range(elf.num_segments()):
            segment = elf.get_segment(index)
            if segment['p_type'] == 'PT_LOAD':
                if segment['p_vaddr'] == segment['p_paddr']:
                    # segment doesn't need data load
                    if segment['p_vaddr'] + segment['p_filesz'] > rosz_limit:
                        rosz_limit = segment['p_vaddr'] + segment['p_filesz']
                else:
                    # segment need data load
                    blocks.append(RWCompression(index, segment))
                    rwsz_limit += segment['p_filesz']
                    # split bss section
                    if segment['p_memsz'] != segment['p_filesz']:
                        blocks.append(BSSZeros(index, segment))

        # print compression report
        report(blocks)

        # generate compressed binary
        image = genimg(rosz_limit, blocks)
        if len(image) <= rwsz_limit:
            make_elf(fin, blocks, image)
        else:
            print('Error: RW size exeeds the limit: ' + hex(rwsz_limit))
            return

if __name__ == '__main__':
    elffile = sys.argv[1]
    process(elffile)
