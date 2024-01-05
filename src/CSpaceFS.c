// Copyright (c) Anthony Kerr 2024-

#include "KMCSpaceFS_drv.h"

unsigned* emap = NULL;
unsigned* dmap = NULL;

bool incmp(unsigned char a, unsigned char b)
{
	if (a >= 'A' && a <= 'Z')
	{
		a += 32;
	}
	if (b >= 'A' && b <= 'Z')
	{
		b += 32;
	}
	return a == b;
}

void init_maps()
{
	static const char charmap[] = "0123456789-,.; ";
	unsigned p = 0;
	unsigned c;
	emap = ExAllocatePoolWithTag(NonPagedPool, 65536 * sizeof(unsigned), ALLOC_TAG);
	if (!emap)
	{
		ERR("out of memory\n");
		return;
	}
	dmap = ExAllocatePoolWithTag(NonPagedPool, 256 * sizeof(unsigned), ALLOC_TAG);
	if (!dmap)
	{
		ERR("out of memory\n");
		return;
	}
	for (unsigned i = 0; i < 15; i++)
	{
		for (unsigned o = 0; o < 15; o++)
		{
			c = charmap[i] << 8 | charmap[o];
			emap[c] = p;
			dmap[p] = c;
			p++;
		}
	}
}

char* encode(char* str, unsigned long long len)
{
	char* alc = NULL;
	if (len % 2)
	{
		len++;
		alc = ExAllocatePoolWithTag(NonPagedPool, len, ALLOC_TAG);
		if (!alc)
		{
			ERR("out of memory\n");
			return NULL;
		}
		alc[len - 1] = 32;
		alc[len - 2] = 46;
	}
	char* bytes = ExAllocatePoolWithTag(NonPagedPool, len / 2 + 1, ALLOC_TAG);
	if (!bytes)
	{
		ERR("out of memory\n");
		return NULL;
	}
	if (alc)
	{
		for (unsigned long long i = 0; i < len; i += 2)
		{
			bytes[i / 2] = emap[alc[i] << 8 | alc[i + 1]];
		}
		ExFreePool(alc);
	}
	else
	{
		for (unsigned long long i = 0; i < len; i += 2)
		{
			bytes[i / 2] = emap[str[i] << 8 | str[i + 1]];
		}
	}
	bytes[len / 2] = 0;
	return bytes;
}

char* decode(char* bytes, unsigned long long len)
{
	char* str = ExAllocatePoolWithTag(NonPagedPool, (len + 1) * 2, ALLOC_TAG);
	if (!str)
	{
		ERR("out of memory\n");
		return NULL;
	}
	unsigned d;
	for (unsigned long long i = 0; i < len; i++)
	{
		d = dmap[bytes[i] & 0xff];
		str[i * 2] = d >> 8;
		str[i * 2 + 1] = d & 0xff;
	}
	return str;
}

unsigned long long get_filename_index(UNICODE_STRING FileName, KMCSpaceFS KMCSFS)
{
	unsigned long long loc = 0;
	unsigned long long FileNameLen = 0;

	for (; FileName.Buffer[FileNameLen] != 0; FileNameLen++);
	if (!FileNameLen)
	{
		return 0;
	}

	unsigned j = 0;
	bool found = false;
	bool start = true;
	for (unsigned long long i = 0; i < KMCSFS.filecount + 1; i++)
	{
		for (; loc < KMCSFS.filenamesend - KMCSFS.tableend + 1; loc++)
		{
			if (((KMCSFS.table[KMCSFS.tableend + loc] & 0xff) == 255) || ((KMCSFS.table[KMCSFS.tableend + loc] & 0xff) == 42)) // 255 = file, 42 = fuse symlink
			{
				found = (j == FileNameLen);
				j = 0;
				if (found)
				{
					return i - 1;
				}
				start = true;
				if ((KMCSFS.table[KMCSFS.tableend + loc] & 0xff) == 255)
				{
					loc++;
					break;
				}
			}
			if ((incmp((KMCSFS.table[KMCSFS.tableend + loc] & 0xff), (FileName.Buffer[j] & 0xff)) || (((KMCSFS.table[KMCSFS.tableend + loc] & 0xff) == *"/") && ((FileName.Buffer[j] & 0xff) == *"\\"))) && start) // case insensitive, / and \ are the same, make sure it is not just an end or middle of filename
			{
				j++;
			}
			else
			{
				if ((KMCSFS.table[KMCSFS.tableend + loc] & 0xff) != 42)
				{
					start = false;
				}
				j = 0;
			}
		}
	}
	return 0;
}
