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
