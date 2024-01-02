// Copyright (c) Anthony Kerr 2023-

#pragma once

#include "KMCSpaceFS.h"

#define IOCTL_KMCSPACEFS_QUERY_FILESYSTEMS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x837, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_KMCSPACEFS_PROBE_VOLUME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x83e, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_KMCSPACEFS_UNLOAD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x849, METHOD_NEITHER, FILE_ANY_ACCESS)

typedef struct
{
	uint8_t uuid[16];
	BOOL missing;
	USHORT name_length;
	WCHAR name[1];
} KMCSpaceFS_FileSystem_Device;

typedef struct
{
	uint32_t next_entry;
	uint8_t uuid[16];
	uint32_t num_devices;
	KMCSpaceFS_FileSystem_Device device;
} KMCSpaceFS_FileSystem;
