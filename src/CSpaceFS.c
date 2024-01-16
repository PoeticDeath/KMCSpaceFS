// Copyright (c) Anthony Kerr 2024-

#include "KMCSpaceFS_drv.h"

unsigned* emap = NULL;
unsigned* dmap = NULL;
long _fltused = 0;

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

static unsigned long attrtoATTR(unsigned long attr)
{
	unsigned long ATTR = 0;
	if (attr & FILE_ATTRIBUTE_HIDDEN) ATTR |= 32768;
	if (attr & FILE_ATTRIBUTE_READONLY) ATTR |= 4096;
	if (attr & FILE_ATTRIBUTE_SYSTEM) ATTR |= 128;
	if (attr & FILE_ATTRIBUTE_ARCHIVE) ATTR |= 2048;
	if (attr & FILE_ATTRIBUTE_DIRECTORY) ATTR |= 8192;
	if (attr & FILE_ATTRIBUTE_REPARSE_POINT) ATTR |= 1024;
	return ATTR;
}

static unsigned long ATTRtoattr(unsigned long ATTR)
{
	unsigned long attr = 0;
	if (ATTR & 32768) attr |= FILE_ATTRIBUTE_HIDDEN;
	if (ATTR & 4096) attr |= FILE_ATTRIBUTE_READONLY;
	if (ATTR & 128) attr |= FILE_ATTRIBUTE_SYSTEM;
	if (ATTR & 2048) attr |= FILE_ATTRIBUTE_ARCHIVE;
	if (ATTR & 8192) attr |= FILE_ATTRIBUTE_DIRECTORY;
	if (ATTR & 1024) attr |= FILE_ATTRIBUTE_REPARSE_POINT;
	return attr;
}

unsigned long long chtime(unsigned long long filenameindex, unsigned long long time, unsigned ch, KMCSpaceFS KMCSFS)
{ // 24 bytes per file
	unsigned o = 0;
	if (ch == 2 || ch == 3)
	{
		o = 8;
	}
	else if (ch == 4 || ch == 5)
	{
		o = 16;
	}
	if (!(ch % 2))
	{
		char tim[8] = {0};
		RtlCopyMemory(tim, KMCSFS.table + KMCSFS.filenamesend + 2 + filenameindex * 24 + o, 8);
		char ti[8] = {0};
		for (unsigned i = 0; i < 8; i++)
		{
			ti[i] = tim[7 - i];
		}
		double t;
		RtlCopyMemory(&t, ti, 8);
		return t * 10000000 + 116444736000000000;
	}
	else
	{
		double t = (time - 116444736000000000) / 10000000.0;
		char ti[8] = {0};
		RtlCopyMemory(ti, &t, 8);
		char tim[8] = {0};
		for (unsigned i = 0; i < 8; i++)
		{
			tim[i] = ti[7 - i];
		}
		RtlCopyMemory(KMCSFS.table + KMCSFS.filenamesend + 2 + filenameindex * 24 + o, tim, 8);
		return 0;
	}
}

unsigned long chwinattrs(unsigned long long filenameindex, unsigned long winattrs, KMCSpaceFS KMCSFS)
{ // Last four bytes of fileinfo
	if (!winattrs)
	{
		winattrs = (KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11 + 7] & 0xff) << 24 | (KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11 + 8] & 0xff) << 16 | (KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11 + 9] & 0xff) << 8 | KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11 + 10] & 0xff;
		return ATTRtoattr(winattrs);
	}
	else
	{
		winattrs = attrtoATTR(winattrs);
		KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11 + 7] = (winattrs >> 24) & 0xff;
		KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11 + 8] = (winattrs >> 16) & 0xff;
		KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11 + 9] = (winattrs >> 8) & 0xff;
		KMCSFS.table[KMCSFS.filenamesend + 2 + KMCSFS.filecount * 24 + filenameindex * 11 + 10] = winattrs & 0xff;
		return 0;
	}
}

static unsigned toint(unsigned char c)
{
	switch (c)
	{
	case '0':
		return 0;
	case '1':
		return 1;
	case '2':
		return 2;
	case '3':
		return 3;
	case '4':
		return 4;
	case '5':
		return 5;
	case '6':
		return 6;
	case '7':
		return 7;
	case '8':
		return 8;
	case '9':
		return 9;
	default:
		return 0;
	}
}

unsigned long long get_file_size(unsigned long long index, KMCSpaceFS KMCSFS)
{
	unsigned long long loc = 0;
	if (index)
	{
		for (unsigned long long i = 0; i < KMCSFS.tablestrlen; i++)
		{
			if (KMCSFS.tablestr[i] == *".")
			{
				loc++;
				if (loc == index)
				{
					loc = i + 1;
					break;
				}
			}
		}
	}

	bool notzero = false;
	bool multisector = false;
	unsigned cur = 0;
	unsigned long long int0 = 0;
	unsigned long long int1 = 0;
	unsigned long long int2 = 0;
	unsigned long long int3 = 0;
	unsigned long long filesize = 0;

	for (unsigned long long i = loc; i < KMCSFS.tablestrlen; i++)
	{
		if (KMCSFS.tablestr[i] == *"," || KMCSFS.tablestr[i] == *".")
		{
			if (notzero)
			{
				if (multisector)
				{
					for (unsigned long long o = 0; o < int0 - int3; o++)
					{
						filesize += KMCSFS.sectorsize;
					}
				}
				switch (cur)
				{
				case 0:
					filesize += KMCSFS.sectorsize;
					break;
				case 1:
					break;
				case 2:
					filesize += int2 - int1;
					break;
				}
			}
			cur = 0;
			int0 = 0;
			int1 = 0;
			int2 = 0;
			int3 = 0;
			multisector = false;
			if (KMCSFS.tablestr[i] == *".")
			{
				break;
			}
		}
		else if (KMCSFS.tablestr[i] == *";")
		{
			cur++;
		}
		else if (KMCSFS.tablestr[i] == *"-")
		{
			int3 = int0;
			multisector = true;
			cur = 0;
			int0 = 0;
			int1 = 0;
			int2 = 0;
		}
		else
		{
			notzero = true;
			switch (cur)
			{
			case 0:
				int0 += toint(KMCSFS.tablestr[i] & 0xff);
				if (KMCSFS.tablestr[i + 1] != *";" && KMCSFS.tablestr[i + 1] != *"," && KMCSFS.tablestr[i + 1] != *"." && KMCSFS.tablestr[i + 1] != *"-")
				{
					int0 *= 10;
				}
				break;
			case 1:
				int1 += toint(KMCSFS.tablestr[i] & 0xff);
				if (KMCSFS.tablestr[i + 1] != *";" && KMCSFS.tablestr[i + 1] != *"," && KMCSFS.tablestr[i + 1] != *"." && KMCSFS.tablestr[i + 1] != *"-")
				{
					int1 *= 10;
				}
				break;
			case 2:
				int2 += toint(KMCSFS.tablestr[i] & 0xff);
				if (KMCSFS.tablestr[i + 1] != *";" && KMCSFS.tablestr[i + 1] != *"," && KMCSFS.tablestr[i + 1] != *"." && KMCSFS.tablestr[i + 1] != *"-")
				{
					int2 *= 10;
				}
				break;
			}
		}
	}

	return filesize;
}

NTSTATUS read_file(fcb* fcb, uint8_t* data, unsigned long long start, unsigned long long length, unsigned long long index, unsigned long long* bytes_read, PIRP Irp, PDEVICE_OBJECT DeviceObject)
{
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	unsigned long long loc = 0;
	if (index)
	{
		for (unsigned long long i = 0; i < fcb->Vcb->vde->pdode->KMCSFS.tablestrlen; i++)
		{
			if (fcb->Vcb->vde->pdode->KMCSFS.tablestr[i] == *".")
			{
				loc++;
				if (loc == index)
				{
					loc = i + 1;
					break;
				}
			}
		}
	}

	uint8_t* buf = ExAllocatePoolWithTag(fcb->pool_type, sector_align(length, fcb->Vcb->vde->pdode->KMCSFS.sectorsize), ALLOC_TAG);

	if (!buf)
	{
		ERR("out of memory\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	bool init = true;
	bool notzero = false;
	bool multisector = false;
	unsigned cur = 0;
	unsigned long long int0 = 0;
	unsigned long long int1 = 0;
	unsigned long long int2 = 0;
	unsigned long long int3 = 0;
	unsigned long long filesize = 0;

	for (unsigned long long i = loc; i < fcb->Vcb->vde->pdode->KMCSFS.tablestrlen; i++)
	{
		if (fcb->Vcb->vde->pdode->KMCSFS.tablestr[i] == *"," || fcb->Vcb->vde->pdode->KMCSFS.tablestr[i] == *".")
		{
			if (notzero)
			{
				if (multisector)
				{
					for (unsigned long long o = 0; o < int0 - int3; o++)
					{
						filesize += fcb->Vcb->vde->pdode->KMCSFS.sectorsize;
						if (filesize > start)
						{
							sync_read_phys(fcb->Vcb->vde->pdode->KMCSFS.DeviceObject, IrpSp->FileObject, fcb->Vcb->vde->pdode->KMCSFS.size - fcb->Vcb->vde->pdode->KMCSFS.sectorsize - (int3 + o) * fcb->Vcb->vde->pdode->KMCSFS.sectorsize, fcb->Vcb->vde->pdode->KMCSFS.sectorsize, buf, true);
							if (init)
							{
								RtlCopyMemory(data, buf + (start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize), min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize - start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length));
								*bytes_read += min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize - start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length);
								start += min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize - start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length);
								init = false;
							}
							else
							{
								RtlCopyMemory(data + *bytes_read, buf, min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length - *bytes_read));
								start += min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length - *bytes_read);
								*bytes_read += min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length - *bytes_read);
							}
						}
					}
				}
				switch (cur)
				{
				case 0:
					filesize += fcb->Vcb->vde->pdode->KMCSFS.sectorsize;
					if (filesize > start)
					{
						sync_read_phys(fcb->Vcb->vde->pdode->KMCSFS.DeviceObject, IrpSp->FileObject, fcb->Vcb->vde->pdode->KMCSFS.size - fcb->Vcb->vde->pdode->KMCSFS.sectorsize - int0 * fcb->Vcb->vde->pdode->KMCSFS.sectorsize, fcb->Vcb->vde->pdode->KMCSFS.sectorsize, buf, true);
						if (init)
						{
							RtlCopyMemory(data, buf + (start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize), min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize - start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length));
							*bytes_read += min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize - start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length);
							start += min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize - start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length);
							init = false;
						}
						else
						{
							RtlCopyMemory(data + *bytes_read, buf, min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length - *bytes_read));
							start += min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length - *bytes_read);
							*bytes_read += min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length - *bytes_read);
						}
					}
					break;
				case 1:
					break;
				case 2:
					filesize += int2 - int1;
					if (filesize > start)
					{
						sync_read_phys(fcb->Vcb->vde->pdode->KMCSFS.DeviceObject, IrpSp->FileObject, fcb->Vcb->vde->pdode->KMCSFS.size - fcb->Vcb->vde->pdode->KMCSFS.sectorsize - int0 * fcb->Vcb->vde->pdode->KMCSFS.sectorsize + int1 - int1 % 512, sector_align(int2 - int1 + int1 % 512, 512), buf + int1 - int1 % 512, true);
						if (init)
						{
							RtlCopyMemory(data, buf + ((int1 + start) % fcb->Vcb->vde->pdode->KMCSFS.sectorsize), min(int2 - int1, length));
							start += min(int2 - int1, length);
							*bytes_read += min(int2 - int1, length);
							init = false;
						}
						else
						{
							RtlCopyMemory(data + *bytes_read, buf + int1, min(int2 - int1, length - *bytes_read));
							start += min(int2 - int1, length - *bytes_read);
							*bytes_read += min(int2 - int1, length - *bytes_read);
						}
					}
					break;
				}
			}
			if (*bytes_read == length)
			{
				ExFreePool(buf);
				return STATUS_SUCCESS;
			}
			cur = 0;
			int0 = 0;
			int1 = 0;
			int2 = 0;
			int3 = 0;
			multisector = false;
			if (fcb->Vcb->vde->pdode->KMCSFS.tablestr[i] == *".")
			{
				break;
			}
		}
		else if (fcb->Vcb->vde->pdode->KMCSFS.tablestr[i] == *";")
		{
			cur++;
		}
		else if (fcb->Vcb->vde->pdode->KMCSFS.tablestr[i] == *"-")
		{
			int3 = int0;
			multisector = true;
			cur = 0;
			int0 = 0;
			int1 = 0;
			int2 = 0;
		}
		else
		{
			notzero = true;
			switch (cur)
			{
			case 0:
				int0 += toint(fcb->Vcb->vde->pdode->KMCSFS.tablestr[i] & 0xff);
				if (fcb->Vcb->vde->pdode->KMCSFS.tablestr[i + 1] != *";" && fcb->Vcb->vde->pdode->KMCSFS.tablestr[i + 1] != *"," && fcb->Vcb->vde->pdode->KMCSFS.tablestr[i + 1] != *"." && fcb->Vcb->vde->pdode->KMCSFS.tablestr[i + 1] != *"-")
				{
					int0 *= 10;
				}
				break;
			case 1:
				int1 += toint(fcb->Vcb->vde->pdode->KMCSFS.tablestr[i] & 0xff);
				if (fcb->Vcb->vde->pdode->KMCSFS.tablestr[i + 1] != *";" && fcb->Vcb->vde->pdode->KMCSFS.tablestr[i + 1] != *"," && fcb->Vcb->vde->pdode->KMCSFS.tablestr[i + 1] != *"." && fcb->Vcb->vde->pdode->KMCSFS.tablestr[i + 1] != *"-")
				{
					int1 *= 10;
				}
				break;
			case 2:
				int2 += toint(fcb->Vcb->vde->pdode->KMCSFS.tablestr[i] & 0xff);
				if (fcb->Vcb->vde->pdode->KMCSFS.tablestr[i + 1] != *";" && fcb->Vcb->vde->pdode->KMCSFS.tablestr[i + 1] != *"," && fcb->Vcb->vde->pdode->KMCSFS.tablestr[i + 1] != *"." && fcb->Vcb->vde->pdode->KMCSFS.tablestr[i + 1] != *"-")
				{
					int2 *= 10;
				}
				break;
			}
		}
	}
	ExFreePool(buf);
	return STATUS_SUCCESS;
}
