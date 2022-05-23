import os, sys, ctypes, struct, shutil
from enum import Enum
from elftools.elf.sections import Symbol
from elftools.elf.elffile import ELFFile
from prettytable import PrettyTable

# Defines Compression Methods
Method = Enum('CompresstionMethods', ('NO_COMPRESSION', 'BSS_SET_ZERO', 'RW_ZERO_RLE', 'RW_LZ77'))

class LoadSegment(object):
    def __init__(self, index, segment):
        self.segindex = index
        self.segment  = segment
                      # (method,                data, rw_sz,               bss_sz,                                 )
        self.load     = (Method.NO_COMPRESSION, None, segment['p_filesz'], segment['p_memsz'] - segment['p_filesz'])

        # add rw segment
        __compressions = (self.__no_compress, self.__zero_rle_compress, self.__lz77)
        for compression in __compressions:
            (method, data, rw_sz) = compression(segment.data())
            if rw_sz < segment['p_filesz']:
                self.load = (method, data, rw_sz, segment['p_memsz'] - segment['p_filesz'])

    def __no_compress(self, input):
        return (Method.NO_COMPRESSION, input, len(input))

    def __zero_rle_compress(self, input):
        (count, output) = (0, [])
        for i, val in enumerate(input):
            if i == 0:
                output.append(val)
                count = 1
            else:
                if val == 0 and input[i - 1] == 0:
                    if count + 1 < 255:
                        count += 1
                    else:
                        output.append(0)
                        output.append(count)
                        count = 1
                else:
                    if input[i - 1] == 0:
                        output.append(count)
                    output.append(val)
                    count = 1
            if i == len(input) - 1 and val == 0:
                output.append(count)

        return (Method.RW_ZERO_RLE, output, len(output))

    def __lz77(self, input):
        return (Method.RW_LZ77, input, len(input))

    def patch(self, elf, prev):
        assert isinstance(elf, ELFFile), 'not a ELFFile!'

        # define param
        ptr    = 0 if prev is None else prev.segment['p_paddr']
        vma    = self.segment['p_vaddr']
        lma    = self.segment['p_paddr']
        memsz  = self.segment['p_memsz']
        method = self.load[0]
        data   = self.load[1]
        rw_sz  = self.load[2]
        bss_sz = self.load[3]

        # define data stream
        lhdr = bytearray(0)
        data = bytearray(0)

        # generate lhdr in segment
        '''
            typedef struct lhdr {
                uint32_t prev;      /* previous lhdr lma */
                uint32_t method;    /* Segment method */
                uint32_t vaddr;     /* Segment virtual address */
                uint32_t paddr;     /* Segment physical address */
                uint32_t memsz;     /* Segment size in file */
                uint32_t rw_sz;     /* Segment size in file (.data) */
                uint32_t bss_sz;    /* Segment size in file (.bss) */
                uint32_t reserved;  /* reserved datafield */
            } lhdr_t;
        '''
        lhdr += struct.pack('IIIIIIII',
                             ptr,
                             method.value,
                             vma,
                             lma,
                             memsz,
                             rw_sz,
                             bss_sz,
                             0)

        # modify filesz in section header for debug compability (shdr)
        for section in elf.iter_sections(type='SHT_PROGBITS'):
            if self.segment.section_in_segment(section):
                if section['sh_addr'] == self.segment['p_vaddr']:
                    __section_index  = elf.get_section_index(section.name)
                    __section_offset = elf._section_offset(__section_index) + 20
                    __section_filesz = ctypes.c_uint32(rw_sz + len(lhdr))
                    elf.stream.seek(__section_offset, 0)
                    elf.stream.write(__section_filesz)

        # modify filesz in segment header for debug compability (phdr)
        __segment_index  = self.segindex
        __segment_offset = elf._segment_offset(__segment_index) + 16
        __segment_filesz = ctypes.c_uint32(rw_sz + len(lhdr))
        elf.stream.seek(__segment_offset, 0)
        elf.stream.write(__segment_filesz)

        # patch segment image
        __image_start = self.segment['p_offset']
        __image_end   = self.segment['p_filesz'] + __image_start
        elf.stream.seek(__image_start, 0)
        elf.stream.write(lhdr)
        elf.stream.write(data)
        assert elf.stream.tell() <= __image_end, 'segment size overflows!'

        # return self for info collection
        return self

def __find_symbol(elf, name):
    assert isinstance(elf, ELFFile), 'not a ELFFile!'
    for section in elf.iter_sections(type='SHT_SYMTAB'):
        symbols = section.get_symbol_by_name(name)
        return symbols[0] if len(symbols) == 1 else None
    return None

def __patch(elf, prev):
    assert isinstance(elf, ELFFile), 'not a ELFFile!'

    header = __find_symbol(elf, '__load_header')
    assert isinstance(header, Symbol), 'Symbol \'__load_header\' not found or duplicated!'

    # generate lhdr at __load_header
    '''
            typedef struct lhdr {
                uint32_t prev;      /* previous lhdr lma */
                uint32_t method;    /* Segment method */
                uint32_t vaddr;     /* Segment virtual address */
                uint32_t paddr;     /* Segment physical address */
                uint32_t memsz;     /* Segment size in file */
                uint32_t rw_sz;     /* Segment size in file (.data) */
                uint32_t bss_sz;    /* Segment size in file (.bss) */
                uint32_t reserved;  /* reserved datafiled */
            } lhdr_t;
    '''
    ptr    = 0 if prev is None else prev.segment['p_paddr']
    offset = next(elf.address_offsets(header.entry['st_value'], size=0x20), None)
    data   = struct.pack('IIIIIIII',
                          ptr,
                          Method.NO_COMPRESSION.value,
                          header.entry['st_value'],
                          header.entry['st_value'],
                          0,
                          0,
                          0,
                          0)
    # patch elf
    elf.stream.seek(offset)
    elf.stream.write(bytearray(data))

def __report(blocks):
    report = PrettyTable()
    report.title = 'RW/BSS Report:'
    report.field_names = ['index', 'type', 'vma', 'lma', 'newsz', 'oldsz', 'ratio', 'method']
    report.align = 'l'
    for index in range(len(blocks)):
        block  = blocks[index]
        method = block.load[0]
        data   = block.load[1]
        rw_sz  = block.load[2]
        bss_sz = block.load[3]
        vma = block.segment['p_vaddr']
        lma = block.segment['p_paddr']

        if rw_sz > 0:
            newsz = rw_sz
            oldsz = block.segment['p_filesz']
            ratio = "{:.2%}".format(newsz/oldsz)
            report.add_row([index, 'rw', hex(vma), hex(lma), newsz, oldsz, ratio, method.name])
        if bss_sz > 0:
            newsz = 0
            oldsz = bss_sz
            ratio = "{:.2%}".format(newsz/oldsz)
            report.add_row([index, 'bss', hex(vma), hex(lma), newsz, oldsz, ratio, Method.BSS_SET_ZERO.name])
            pass
    print(report) if len(blocks) else None

def process(elffile):
    with open(elffile, 'r+b') as fin:
        (elf, info, prev) = (ELFFile(fin), [], None)
        for index in range(elf.num_segments()):
            segment = elf.get_segment(index)
            if segment['p_type'] == 'PT_LOAD' and segment['p_vaddr'] != segment['p_paddr']:
                prev = LoadSegment(index, segment).patch(elf, prev)
                info.append(prev)
        __patch(elf, prev)
        __report(info)

if __name__ == '__main__':
    # Prepare backup image
    input  = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) == 3 else os.path.dirname(sys.argv[1]) + 'patched.elf'
    shutil.copy(input, output)

    # Process image
    process(output)
