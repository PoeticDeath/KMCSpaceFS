// Copyright (c) Anthony Kerr 2023-

#pragma once

#include <stdint.h>
#include <assert.h>

typedef struct
{
	uint8_t uuid[16];
} KMCSpaceFS_UUID;

typedef struct
{
    uint64_t dev_id;
    uint64_t num_bytes;
    uint64_t bytes_used;
    uint32_t optimal_io_align;
    uint32_t optimal_io_width;
    uint32_t minimal_io_size;
    uint64_t type;
    uint64_t generation;
    uint64_t start_offset;
    uint32_t dev_group;
    uint8_t seek_speed;
    uint8_t bandwidth;
} DEV_ITEM;

typedef struct
{
    KMCSpaceFS_UUID uuid;
    unsigned long sectorsize;
    unsigned long long tablesize;
    unsigned long long extratablesize;
    unsigned long long filenamesend;
    unsigned long long tableend;
    unsigned long long size;
    unsigned long long filecount;
    unsigned long long tablestrlen;
    char* table;
    char* tablestr;
} KMCSpaceFS;

typedef struct
{
    uint64_t index;
    uint64_t transid;
    uint64_t st_size;
    uint32_t st_nlink;
    uint32_t st_uid;
    uint32_t st_gid;
    uint32_t st_mode;
    uint64_t st_atime;
    uint64_t st_ctime;
    uint64_t st_mtime;
    uint64_t otime;
} INDEX_ITEM;
