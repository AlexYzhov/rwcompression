/*
 ***********************************************************************
 *  Copyright (c) 2022 alex Yang
 *
 *  @file    startup_load.c
 *  @brief   此文件为启动加载程序, 负责在进入用户main()函数前准备c runtime
 *  @history
 *   Version            Date            Author          Modification
 *   V1.0.0             May-15-2022     null.yang       create file
 *
 *
 ***********************************************************************
 */

#include "stddef.h"
#include "stdint.h"
#include "string.h"

#if   defined ( __CC_ARM )
    #defien __main __main
#elif defined ( __GNUC__ )
    #define __main _mainCRTStartup
#elif defined ( __ICCARM__ )
    #define __main __iar_program_start
#endif

#define LOAD_HDR_MAGIC  (0xFEE1DEAD)

typedef enum load_method {
    NO_COMPRESSION = 0,
    BSS_SET_ZERO   = 1,
    RW_ZERO_RLE    = 2,
    RW_LZ77        = 3,
} load_method_t;

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

__attribute__((used)) static const lhdr_t __load_header;

__attribute__((always_inline, used)) inline
static void __load_zero_rle(uint8_t *vma, uint8_t *lma, size_t memsize)
{
    uint8_t *to = (uint8_t *)vma;
    uint8_t *from = (uint8_t *)lma;

    while (memsize > 0)
    {
        if (*from != 0)
        {
            *to++ = *from++;
            memsize--;
        }
        else if (*from == 0)
        {
            uint8_t val = *from++;
            uint8_t len = *from++;
            while (len-- > 0)
            {
                *to++ = val;
                memsize--;
            }
        }
    }
}

__attribute__((always_inline, used)) inline
static int __load_segment(lhdr_t *const lhdr)
{
    if (NULL == lhdr)
    {
        return -1;
    }

    uint8_t *vma  = (uint8_t *)lhdr->vaddr;
    uint8_t *lma  = (uint8_t *)lhdr->paddr;
    size_t memsz  = (size_t)lhdr->memsz;
    size_t bss_sz = (size_t)lhdr->bss_sz;

    /* load .data */
    switch (lhdr->method)
    {
        case NO_COMPRESSION:
            memcpy(vma, lma, memsz - bss_sz);
            break;
        case RW_ZERO_RLE:
            __load_zero_rle(vma, lma, memsz - bss_sz);
            break;
        case BSS_SET_ZERO:  /* no break, return error immediately */
        case RW_LZ77:       /* no break, return error immediately */
        default:
            return -1;
    }

    /* load .bss */
    memset((uint8_t *)(vma + memsz - bss_sz), 0x00, bss_sz);

    return 0;
}

__attribute__((always_inline, used)) inline
static int __load_program(lhdr_t *lhdr)
{
    if (NULL == lhdr)
    {
        return -1;
    }

    do {
        lhdr = (lhdr_t *)lhdr->prev;
        if (__load_segment(lhdr))
        {
            return -2;
        }
    } while (lhdr);

    return 0;
}

/*
 * Make sure _mainCRTStartup() procedure is stack-less,
 *   (Subroutines are all force inlined in call graph)
 * Otherwise memset .bss segment to zero may corrupt call frame itself
 */
void _mainCRTStartup(void);
void _mainCRTStartup(void)
{
    extern int main(void);

    __asm (
        "ldr r0, =__load_header\r\n"
        "bl __load_program\r\n"
        "b main\r\n"
    );
}
