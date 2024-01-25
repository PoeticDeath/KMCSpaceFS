// Copyright (c) Anthony Kerr 2023-

#pragma once

#include <stdint.h>
#include <assert.h>

#define MAX_LABEL_SIZE 0x100

typedef struct
{
	uint8_t uuid[16];
} KMCSpaceFS_UUID;

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
	PDEVICE_OBJECT DeviceObject;
	unsigned long long used_blocks;
} KMCSpaceFS;
