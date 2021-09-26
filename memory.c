/*
 ***********************************************************************
 *  Copyright (c) 2023 alex Yang
 *
 *  @file    memory.c
 *  @brief   此文件实现了libc runtime memory api的优化实现 (arm)
 *  @history
 *   Version            Date            Author          Modification
 *   V1.0.0             Aug-09-2023     null.yang       create file
 *
 *
 ***********************************************************************
 */

#include "stddef.h"
#include "stdint.h"
#include "string.h"

void *memcpy(void *dst, const void *src, size_t n)
{
    uint8_t *dst_byte = (uint8_t *)dst;
    uint32_t *dst_word = (uint32_t *)dst_byte;
    const uint8_t *src_byte = (const uint8_t *)src;
    const uint32_t *src_word = (const uint32_t *)src_byte;

    /* make sure dst and src are in the same alignment */
    if ((((uintptr_t)dst ^ (uintptr_t)src) & 0x03) == 0u)
    {
        if ((uintptr_t)dst & 0x03 || n < sizeof(*src_word))
        {
            /* padding copy to aligned base address,
             * until cursor reaches the end */
            while ((uintptr_t)dst_byte & 0x03 && n > 0)
            {
                *dst_byte++ = *src_byte++;
                n -= sizeof(*src_byte);
            };
        }

        dst_word = (uint32_t *)dst_byte;
        src_word = (uint32_t *)src_byte;

        /* accelerated word copy from aligned base address */
        while (n >= sizeof(*src_word))
        {
            *dst_word++ = *src_word++;
            n -= sizeof(*src_word);
        };

        dst_byte = (uint8_t *)dst_word;
        src_byte = (uint8_t *)src_word;
    };

    /* unaligned byte copy left */
    while (n > 0)
    {
        *dst_byte++ = *src_byte++;
        n -= sizeof(*src_byte);
    };

    return dst;
}

void *memset(void *dst, int pattern, size_t size)
{
    uint8_t c = (uint8_t)pattern;
    uint8_t *dst_byte = (uint8_t *)dst;
    uint32_t *dst_word = (uint32_t *)dst_byte;

    if (((uintptr_t)dst & 0x03) == 0u || size < sizeof(c) * 4)
    {
        while ((uintptr_t)dst_byte & 0x03)
        {
            *dst_byte++ = c;
            size -= sizeof(c);
        };

        dst_word = (uint32_t *)dst_byte;

        while (size >= sizeof(c) * 4)
        {
            *dst_word++ = (uint32_t)((c << 24) | (c << 16) | (c << 8) | c);
            size -= sizeof(c) * 4;
        };

        dst_byte = (uint8_t *)dst_word;
    };

    while (size > 0)
    {
        *dst_byte++ = c;
        size -= sizeof(c);
    };

    return dst;
}
