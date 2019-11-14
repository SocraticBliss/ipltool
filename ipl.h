#ifndef IPL_H
#define IPL_H

#include "kirk_engine.h"

//0xF60
#define MAX_IPLBLK_DATA_SIZE (0xF60)
#define MAX_IPL_SIZE         (0xFFFFFF)
#define MAX_NUM_IPLBLKS    (MAX_IPL_SIZE / sizeof(iplEncBlk))

typedef struct
{
    u32 addr;
    u32 size;
    u32 entry;
    u32 hash;
    u32 data[MAX_IPLBLK_DATA_SIZE / sizeof(u32)];
} iplBlk;

typedef struct
{
    KIRK_CMD1_HEADER hdr;
    u8 data[sizeof(iplBlk)];
    //u8 sha1[48];
} iplEncBlk;

static inline u32 iplMemcpy(void *dst, const void *src, size_t size)
{
	u32 *_dst = (u32*)dst;
	const u32 *_src = (const u32*)src;
	u32 hash = 0;

	if (size & 3)
		return 0;

	while (size) {
		*_dst = *_src;
		hash += *_src;
		_dst++;
		_src++;
		size -= 4;
	}

	return hash;
}

#endif
