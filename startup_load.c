#include <stdint.h>
#include <stdlib.h>

#define LOAD_TABLE_BASE         (__data_start_base__)
#define LOAD_TABLE_MAGIC        (0xDEADBEEF)

#ifndef LOAD_SEGMENT_MAX_NUM
#define LOAD_SEGMENT_MAX_NUM    (16u)
#endif

typedef enum
{
    BSS_SET_ZERO    = 0,
    NO_COMPRESSION  = 1,
    ZERO_RLE        = 2,
    LZ77            = 3,
} rw_compress_t;

typedef struct
{
    uint32_t magic;
    uint32_t table_size;
    uint32_t item_size;
    uint32_t crc32;
} rw_header_t;

typedef struct
{
    uint8_t      *vma;
    uint8_t      *lma;
    size_t        memsize;
    rw_compress_t method;
} rw_item_t;

typedef struct
{
    rw_header_t header;
    rw_item_t   items[LOAD_SEGMENT_MAX_NUM];
} rw_table_t;

inline static void __load_memset(void *dst, uint8_t pattern, size_t size)
{
    uint8_t *to = (uint8_t *)dst;

    while (size > 0)
    {
        *to++ = pattern;
        size--;
    }
}

inline static void __load_memcpy(void *dst, void *src, size_t size)
{
    uint8_t *to = (uint8_t *)dst;
    uint8_t *from = (uint8_t *)src;

    while (size > 0)
    {
        *to++ = *from++;
        size--;
    }
}

// TODO: need zero_rle decompress implementation
inline static void __load_zero_rle(uint8_t *vma, uint8_t *lma, size_t memsize)
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

    return;
}

// TODO: need lz77 decompress implementation
inline static void __load_lz77(uint8_t *vma, uint8_t *lma, size_t memsize)
{
    return;
}

inline static void load_segments(rw_item_t *segment)
{
    switch (segment->method)
    {
        case BSS_SET_ZERO:
            __load_memset(segment->vma, 0x00, segment->memsize);
            break;
        case NO_COMPRESSION:
            __load_memcpy(segment->vma, segment->lma, segment->memsize);
            break;
        case ZERO_RLE:
            __load_zero_rle(segment->vma, segment->lma, segment->memsize);
            break;
        case LZ77:
            break;
        default:
            while (1);
    }
}

inline static void startup_load(void)
{
    extern char LOAD_TABLE_BASE;
    rw_table_t *table = (rw_table_t *)&LOAD_TABLE_BASE;

    for (uint32_t i = 0; i < (table->header.table_size/table->header.item_size); i++)
    {
        load_segments(&table[i]);
    }
}

__attribute__((naked)) void _mainCRTstartup(void)
{
    extern int main(void);

    startup_load();

    __asm(
        "b main"
    );
}
