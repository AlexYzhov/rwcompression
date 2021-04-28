import sys, struct
from elftools.elf.elffile import ELFFile

def zero_rle_compress(file):
    with open(file, 'rb') as src:
        input = src.read()

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
    for i, val in enumerate(output):
        print(str(hex(val)) + ' ' + str(chr(val)))
    return (output, len(output))

def get_segments(elffile):
    segments = []
    for segment in elffile.iter_segments():
        vma = segment.header['p_vaddr']
        lma = segment.header['p_paddr']
        filesz = segment.header['p_filesz']
        memsz = segment.header['p_memsz']

        if vma != lma:
            if memsz > filesz:
                #print("This is a section mixed with bss and rw")
                pass
            elif memsz > 0 and memsz == filesz:
                #print("This is rw section")
                pass
            elif memsz > 0 and filesz == 0:
                #print("This is bss section")
                pass
        else:
            #print("This is ro section")
            pass

        segments.append((vma, lma, filesz, memsz))
    return segments

def get_sections(elffile):
    for section in elffile.iter_sections():
        name = section.header['sh_name']
        #print(name)

def select_compress_method(segment):
    pass

def generate_binary():
    pass

def generate_statictics():
    pass

def rwcompression(elf_in, bin_out):
    with open(elf_in, 'rb') as fin:
        elffile = ELFFile(fin)
        segments = get_segments(elffile)
        for segment in segments:
            print(segment)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("[ Usage ]: ./rwcompression.py input.elf output.bin")
        exit(-1)
    elf_in = sys.argv[1]
    bin_out = sys.argv[2]

    rwcompression(elf_in, bin_out)
