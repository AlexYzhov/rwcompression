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

#define LOAD_HDR_BASE   (__data_start_base__)
#define LOAD_HDR_MAGIC  (0xFEE1DEAD)

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

typedef struct hdr {
    uint32_t  magic;
    phdr_t   *phdr;
    uint32_t  phnum;
    uint32_t  reserved;
} hdr_t;

typedef enum load_method {
    NO_COMPRESSION = 0,
    BSS_SET_ZERO   = 1,
    RW_ZERO_RLE    = 2,
    RW_LZ77        = 3,
} load_method_t;

__attribute__((always_inline)) inline 
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

__attribute__((always_inline)) inline 
static int __load_segment(phdr_t *phdr)
{
    if (NULL == phdr)
    {
        return -1;
    }

    uint8_t *vma = (uint8_t *)phdr->vaddr;
    uint8_t *lma = (uint8_t *)phdr->paddr;
    size_t memsz = (size_t)phdr->memsz;

    switch (phdr->flags)
    {
        case NO_COMPRESSION:
            memcpy(vma, lma, memsz);
            break;
        case BSS_SET_ZERO:
            memset(vma, 0x00, memsz);
            break;
        case RW_ZERO_RLE:
            __load_zero_rle(vma, lma, memsz);
            break;
        case RW_LZ77: /* no break, return error immediately */
        default:
            return -1;
    }

    return 0;
}

__attribute__((always_inline)) inline 
static int __load_program(hdr_t *hdr)
{
    if (NULL == hdr)
    {
        return -1;
    }

    if (LOAD_HDR_MAGIC != hdr->magic)
    {
        return -2;
    }
    
    for (size_t i = 0; i < hdr->phnum; i++)
    {
        phdr_t *phdr = &hdr->phdr[i];
        if (__load_segment(phdr))
        {
            return -3;
        }
    }

    return 0;
}

void _mainCRTstartup(void);
void _mainCRTstartup(void)
{
    extern int LOAD_HDR_BASE; 
    extern int main(void);
    
    hdr_t *__hdr = (hdr_t *)LOAD_HDR_BASE;
    if (__load_program(__hdr))
    {
        while (1);
    }

    __asm (
        "b main\r\n"
    );
}
