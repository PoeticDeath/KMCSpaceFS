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
		RtlCopyMemory(alc, str, len - 1);
		alc[len - 1] = 32;
		alc[len - 2] = 46;
	}
	char* bytes = ExAllocatePoolWithTag(NonPagedPool, len / 2 + 1, ALLOC_TAG);
	if (!bytes)
	{
		ERR("out of memory\n");
		if (alc)
		{
			ExFreePool(alc);
		}
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

NTSTATUS read_file(fcb* fcb, uint8_t* data, unsigned long long start, unsigned long long length, unsigned long long index, unsigned long long* bytes_read, PIRP Irp)
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
							if (init)
							{
								sync_read_phys(fcb->Vcb->vde->pdode->KMCSFS.DeviceObject, IrpSp->FileObject, fcb->Vcb->vde->pdode->KMCSFS.size - fcb->Vcb->vde->pdode->KMCSFS.sectorsize - (int3 + o) * fcb->Vcb->vde->pdode->KMCSFS.sectorsize + (start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize) - (start % 512), min(sector_align(fcb->Vcb->vde->pdode->KMCSFS.sectorsize - start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize, 512), sector_align(length, 512)), buf + (start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize) - (start % 512), true);
								RtlCopyMemory(data, buf + (start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize), min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize - start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length));
								*bytes_read += min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize - start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length);
								start += min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize - start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length);
								init = false;
							}
							else
							{
								sync_read_phys(fcb->Vcb->vde->pdode->KMCSFS.DeviceObject, IrpSp->FileObject, fcb->Vcb->vde->pdode->KMCSFS.size - fcb->Vcb->vde->pdode->KMCSFS.sectorsize - (int3 + o) * fcb->Vcb->vde->pdode->KMCSFS.sectorsize, fcb->Vcb->vde->pdode->KMCSFS.sectorsize, buf, true);
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
						if (init)
						{
							sync_read_phys(fcb->Vcb->vde->pdode->KMCSFS.DeviceObject, IrpSp->FileObject, fcb->Vcb->vde->pdode->KMCSFS.size - fcb->Vcb->vde->pdode->KMCSFS.sectorsize - int0 * fcb->Vcb->vde->pdode->KMCSFS.sectorsize + (start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize) - (start % 512), min(sector_align(fcb->Vcb->vde->pdode->KMCSFS.sectorsize - start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize, 512), sector_align(length, 512)), buf + (start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize) - (start % 512), true);
							RtlCopyMemory(data, buf + (start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize), min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize - start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length));
							*bytes_read += min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize - start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length);
							start += min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize - start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length);
							init = false;
						}
						else
						{
							sync_read_phys(fcb->Vcb->vde->pdode->KMCSFS.DeviceObject, IrpSp->FileObject, fcb->Vcb->vde->pdode->KMCSFS.size - fcb->Vcb->vde->pdode->KMCSFS.sectorsize - int0 * fcb->Vcb->vde->pdode->KMCSFS.sectorsize, fcb->Vcb->vde->pdode->KMCSFS.sectorsize, buf, true);
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

NTSTATUS write_file(fcb* fcb, uint8_t* data, unsigned long long start, unsigned long long length, unsigned long long index, unsigned long long size, PIRP Irp)
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

	bool init = true;
	bool notzero = false;
	bool multisector = false;
	unsigned cur = 0;
	unsigned long long int0 = 0;
	unsigned long long int1 = 0;
	unsigned long long int2 = 0;
	unsigned long long int3 = 0;
	unsigned long long filesize = 0;
	unsigned long long bytes_written = 0;

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
							if (init)
							{
								sync_write_phys(fcb->Vcb->vde->pdode->KMCSFS.DeviceObject, IrpSp->FileObject, fcb->Vcb->vde->pdode->KMCSFS.size - fcb->Vcb->vde->pdode->KMCSFS.sectorsize - (int3 + o) * fcb->Vcb->vde->pdode->KMCSFS.sectorsize + (start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize), min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize - start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length), data, true);
								bytes_written += min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize - start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length);
								start += min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize - start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length);
								init = false;
							}
							else
							{
								sync_write_phys(fcb->Vcb->vde->pdode->KMCSFS.DeviceObject, IrpSp->FileObject, fcb->Vcb->vde->pdode->KMCSFS.size - fcb->Vcb->vde->pdode->KMCSFS.sectorsize - (int3 + o) * fcb->Vcb->vde->pdode->KMCSFS.sectorsize, min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length - bytes_written), data + bytes_written, true);
								start += min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length - bytes_written);
								bytes_written += min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length - bytes_written);
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
						if (init)
						{
							sync_write_phys(fcb->Vcb->vde->pdode->KMCSFS.DeviceObject, IrpSp->FileObject, fcb->Vcb->vde->pdode->KMCSFS.size - fcb->Vcb->vde->pdode->KMCSFS.sectorsize - int0 * fcb->Vcb->vde->pdode->KMCSFS.sectorsize + (start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize), min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize - start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length), data, true);
							bytes_written += min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize - start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length);
							start += min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize - start % fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length);
							init = false;
						}
						else
						{
							sync_write_phys(fcb->Vcb->vde->pdode->KMCSFS.DeviceObject, IrpSp->FileObject, fcb->Vcb->vde->pdode->KMCSFS.size - fcb->Vcb->vde->pdode->KMCSFS.sectorsize - int0 * fcb->Vcb->vde->pdode->KMCSFS.sectorsize, min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length - bytes_written), data + bytes_written, true);
							start += min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length - bytes_written);
							bytes_written += min(fcb->Vcb->vde->pdode->KMCSFS.sectorsize, length - bytes_written);
						}
					}
					break;
				case 1:
					break;
				case 2:
					filesize += int2 - int1;
					if (filesize > start)
					{
						if (init)
						{
							sync_write_phys(fcb->Vcb->vde->pdode->KMCSFS.DeviceObject, IrpSp->FileObject, fcb->Vcb->vde->pdode->KMCSFS.size - fcb->Vcb->vde->pdode->KMCSFS.sectorsize - int0 * fcb->Vcb->vde->pdode->KMCSFS.sectorsize + ((int1 + start) % fcb->Vcb->vde->pdode->KMCSFS.sectorsize), min(int2 - int1, length), data, true);
							start += min(int2 - int1, length);
							bytes_written += min(int2 - int1, length);
							init = false;
						}
						else
						{
							sync_write_phys(fcb->Vcb->vde->pdode->KMCSFS.DeviceObject, IrpSp->FileObject, fcb->Vcb->vde->pdode->KMCSFS.size - fcb->Vcb->vde->pdode->KMCSFS.sectorsize - int0 * fcb->Vcb->vde->pdode->KMCSFS.sectorsize + int1, min(int2 - int1, length - bytes_written), data + bytes_written, true);
							start += min(int2 - int1, length - bytes_written);
							bytes_written += min(int2 - int1, length - bytes_written);
						}
					}
					break;
				}
			}
			if (bytes_written == length)
			{
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
	return STATUS_SUCCESS;
}

static bool is_table_expandable(KMCSpaceFS KMCSFS, unsigned long long newsize)
{
	unsigned long long nearestsector = 0;

	bool multisector = false;
	unsigned cur = 0;
	unsigned long long int0 = 0;
	unsigned long long int1 = 0;
	unsigned long long int2 = 0;
	unsigned long long int3 = 0;

	for (unsigned long long i = 0; i < KMCSFS.tablestrlen; i++)
	{
		if (KMCSFS.tablestr[i] == *"," || KMCSFS.tablestr[i] == *".")
		{
			if (multisector)
			{
				for (unsigned long long o = 0; o < int0 - int3; o++)
				{
					nearestsector = max(nearestsector, int3 + o);
				}
			}
			switch (cur)
			{
			case 0:
				nearestsector = max(nearestsector, int0);
				break;
			case 1:
				break;
			case 2:
				nearestsector = max(nearestsector, int0);
				break;
			}
			cur = 0;
			int0 = 0;
			int1 = 0;
			int2 = 0;
			int3 = 0;
			multisector = false;
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

	return KMCSFS.size / KMCSFS.sectorsize - nearestsector > sector_align(newsize, KMCSFS.sectorsize) / KMCSFS.sectorsize;
}

NTSTATUS create_file(PIRP Irp, device_extension* Vcb, PFILE_OBJECT FileObject, UNICODE_STRING fn)
{
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

	if ((fn.Buffer[fn.Length / sizeof(WCHAR) - 1] & 0xff) == 0)
	{
		fn.Length -= sizeof(WCHAR);
	}

	if (!is_table_expandable(Vcb->vde->pdode->KMCSFS, Vcb->vde->pdode->KMCSFS.filenamesend + 2 + fn.Length / sizeof(WCHAR) + 1 + 35 * (Vcb->vde->pdode->KMCSFS.filecount + 1)))
	{
		ERR("table is not expandable\n");
		return STATUS_DISK_FULL;
	}

	char* newtablestr = ExAllocatePoolWithTag(NonPagedPool, Vcb->vde->pdode->KMCSFS.tablestrlen + 1, ALLOC_TAG);
	if (!newtablestr)
	{
		ERR("out of memory\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	char* newtable = ExAllocatePoolWithTag(NonPagedPool, Vcb->vde->pdode->KMCSFS.filenamesend + 2 + fn.Length / sizeof(WCHAR) + 1 + 35 * (Vcb->vde->pdode->KMCSFS.filecount + 1), ALLOC_TAG);
	if (!newtable)
	{
		ERR("out of memory\n");
		ExFreePool(newtablestr);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(newtable, Vcb->vde->pdode->KMCSFS.filenamesend + 2 + fn.Length / sizeof(WCHAR) + 1 + 35 * (Vcb->vde->pdode->KMCSFS.filecount + 1));

	RtlCopyMemory(newtablestr, Vcb->vde->pdode->KMCSFS.tablestr, Vcb->vde->pdode->KMCSFS.tablestrlen);
	if (newtablestr[Vcb->vde->pdode->KMCSFS.tablestrlen - 1] == 32)
	{
		newtablestr[Vcb->vde->pdode->KMCSFS.tablestrlen - 1] = 46;
		newtablestr[Vcb->vde->pdode->KMCSFS.tablestrlen] = 32;
	}
	else
	{
		newtablestr[Vcb->vde->pdode->KMCSFS.tablestrlen] = 46;
		Vcb->vde->pdode->KMCSFS.tablestrlen++;
	}

	ExFreePool(Vcb->vde->pdode->KMCSFS.tablestr);
	Vcb->vde->pdode->KMCSFS.tablestr = newtablestr;

	char* newtablestren = encode(newtablestr, Vcb->vde->pdode->KMCSFS.tablestrlen);
	if (!newtablestren)
	{
		ERR("out of memory\n");
		ExFreePool(newtablestr);
		ExFreePool(newtable);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	newtable[0] = Vcb->vde->pdode->KMCSFS.table[0];
	unsigned long long extratablesize = 5 + (Vcb->vde->pdode->KMCSFS.tablestrlen + Vcb->vde->pdode->KMCSFS.tablestrlen % 2) / 2 + Vcb->vde->pdode->KMCSFS.filenamesend - Vcb->vde->pdode->KMCSFS.tableend + 2 + fn.Length / sizeof(WCHAR) + 1 + 35 * (Vcb->vde->pdode->KMCSFS.filecount + 1);
	unsigned long long tablesize = (extratablesize + Vcb->vde->pdode->KMCSFS.sectorsize - 1) / Vcb->vde->pdode->KMCSFS.sectorsize - 1;
	newtable[1] = (tablesize >> 24) & 0xff;
	newtable[2] = (tablesize >> 16) & 0xff;
	newtable[3] = (tablesize >> 8) & 0xff;
	newtable[4] = tablesize & 0xff;
	Vcb->vde->pdode->KMCSFS.extratablesize = sector_align(extratablesize, Vcb->vde->pdode->KMCSFS.sectorsize);
	Vcb->vde->pdode->KMCSFS.tablesize = 1 + tablesize;

	RtlCopyMemory(newtable + 5, newtablestren, (Vcb->vde->pdode->KMCSFS.tablestrlen + Vcb->vde->pdode->KMCSFS.tablestrlen % 2) / 2);
	ExFreePool(newtablestren);

	RtlCopyMemory(newtable + 5 + (Vcb->vde->pdode->KMCSFS.tablestrlen + Vcb->vde->pdode->KMCSFS.tablestrlen % 2) / 2, Vcb->vde->pdode->KMCSFS.table + Vcb->vde->pdode->KMCSFS.tableend, Vcb->vde->pdode->KMCSFS.filenamesend - Vcb->vde->pdode->KMCSFS.tableend);

	newtable[5 + (Vcb->vde->pdode->KMCSFS.tablestrlen + Vcb->vde->pdode->KMCSFS.tablestrlen % 2) / 2 + Vcb->vde->pdode->KMCSFS.filenamesend - Vcb->vde->pdode->KMCSFS.tableend] = 255;
	for (unsigned long long i = 0; i < fn.Length / sizeof(WCHAR); i++)
	{
		newtable[5 + (Vcb->vde->pdode->KMCSFS.tablestrlen + Vcb->vde->pdode->KMCSFS.tablestrlen % 2) / 2 + Vcb->vde->pdode->KMCSFS.filenamesend - Vcb->vde->pdode->KMCSFS.tableend + 1 + i] = ((fn.Buffer[i] & 0xff) == 92) ? 47 : fn.Buffer[i] & 0xff;
	}
	newtable[5 + (Vcb->vde->pdode->KMCSFS.tablestrlen + Vcb->vde->pdode->KMCSFS.tablestrlen % 2) / 2 + Vcb->vde->pdode->KMCSFS.filenamesend - Vcb->vde->pdode->KMCSFS.tableend + 1 + fn.Length / sizeof(WCHAR)] = 255;
	newtable[5 + (Vcb->vde->pdode->KMCSFS.tablestrlen + Vcb->vde->pdode->KMCSFS.tablestrlen % 2) / 2 + Vcb->vde->pdode->KMCSFS.filenamesend - Vcb->vde->pdode->KMCSFS.tableend + 1 + fn.Length / sizeof(WCHAR) + 1] = 254;

	RtlCopyMemory(newtable + 5 + (Vcb->vde->pdode->KMCSFS.tablestrlen + Vcb->vde->pdode->KMCSFS.tablestrlen % 2) / 2 + Vcb->vde->pdode->KMCSFS.filenamesend - Vcb->vde->pdode->KMCSFS.tableend + 1 + fn.Length / sizeof(WCHAR) + 2, Vcb->vde->pdode->KMCSFS.table + Vcb->vde->pdode->KMCSFS.filenamesend + 2, 24 * Vcb->vde->pdode->KMCSFS.filecount);
	RtlCopyMemory(newtable + 5 + (Vcb->vde->pdode->KMCSFS.tablestrlen + Vcb->vde->pdode->KMCSFS.tablestrlen % 2) / 2 + Vcb->vde->pdode->KMCSFS.filenamesend - Vcb->vde->pdode->KMCSFS.tableend + 1 + fn.Length / sizeof(WCHAR) + 2 + 24 * (Vcb->vde->pdode->KMCSFS.filecount + 1), Vcb->vde->pdode->KMCSFS.table + Vcb->vde->pdode->KMCSFS.filenamesend + 2 + 24 * Vcb->vde->pdode->KMCSFS.filecount, 11 * Vcb->vde->pdode->KMCSFS.filecount);

	char guidmodes[11] = {0};
	unsigned long guid = 545;
	guidmodes[0] = (guid >> 16) & 0xff;
	guidmodes[1] = (guid >> 8) & 0xff;
	guidmodes[2] = guid & 0xff;
	guidmodes[3] = (guid >> 8) & 0xff;
	guidmodes[4] = guid & 0xff;
	unsigned long mode = 448 + 16429 * (IrpSp->Parameters.Create.FileAttributes & FILE_ATTRIBUTE_DIRECTORY);
	guidmodes[5] = (mode >> 8) & 0xff;
	guidmodes[6] = mode & 0xff;
	unsigned long winattrs = 2048 | attrtoATTR(IrpSp->Parameters.Create.FileAttributes);
	guidmodes[7] = (winattrs >> 24) & 0xff;
	guidmodes[8] = (winattrs >> 16) & 0xff;
	guidmodes[9] = (winattrs >> 8) & 0xff;
	guidmodes[10] = winattrs & 0xff;
	RtlCopyMemory(newtable + 5 + (Vcb->vde->pdode->KMCSFS.tablestrlen + Vcb->vde->pdode->KMCSFS.tablestrlen % 2) / 2 + Vcb->vde->pdode->KMCSFS.filenamesend - Vcb->vde->pdode->KMCSFS.tableend + 1 + fn.Length / sizeof(WCHAR) + 2 + 24 * (Vcb->vde->pdode->KMCSFS.filecount + 1) + 11 * Vcb->vde->pdode->KMCSFS.filecount, guidmodes, 11);

	ExFreePool(Vcb->vde->pdode->KMCSFS.table);
	Vcb->vde->pdode->KMCSFS.table = newtable;

	Vcb->vde->pdode->KMCSFS.filenamesend = 5 + (Vcb->vde->pdode->KMCSFS.tablestrlen + Vcb->vde->pdode->KMCSFS.tablestrlen % 2) / 2 + Vcb->vde->pdode->KMCSFS.filenamesend - Vcb->vde->pdode->KMCSFS.tableend + 1 + fn.Length / sizeof(WCHAR);
	Vcb->vde->pdode->KMCSFS.tableend = 5 + (Vcb->vde->pdode->KMCSFS.tablestrlen + Vcb->vde->pdode->KMCSFS.tablestrlen % 2) / 2;

	LARGE_INTEGER time;
	KeQuerySystemTime(&time);
	chtime(Vcb->vde->pdode->KMCSFS.filecount, time.QuadPart, 5, Vcb->vde->pdode->KMCSFS);
	chtime(Vcb->vde->pdode->KMCSFS.filecount, time.QuadPart, 1, Vcb->vde->pdode->KMCSFS);
	chtime(Vcb->vde->pdode->KMCSFS.filecount, time.QuadPart, 3, Vcb->vde->pdode->KMCSFS);

	Vcb->vde->pdode->KMCSFS.filecount++;
	sync_write_phys(Vcb->vde->pdode->KMCSFS.DeviceObject, FileObject, 0, Vcb->vde->pdode->KMCSFS.filenamesend + 2 + 35 * Vcb->vde->pdode->KMCSFS.filecount, newtable, true);

	return STATUS_SUCCESS;
}

dealloc(KMCSpaceFS* KMCSFS, unsigned long long index, unsigned long long size, unsigned long long newsize)
{
	if (size > newsize)
	{
		unsigned long long loc = 0;
		if (index)
		{
			for (unsigned long long i = 0; i < KMCSFS->tablestrlen; i++)
			{
				if (KMCSFS->tablestr[i] == *".")
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
		unsigned long long offset = loc;

		for (unsigned long long i = loc; i < KMCSFS->tablestrlen; i++)
		{
			if (KMCSFS->tablestr[i] == *"," || KMCSFS->tablestr[i] == *".")
			{
				if (notzero)
				{
					if (multisector)
					{
						unsigned long long o = 0;
						for (; o < int0 - int3; o++)
						{
							filesize += KMCSFS->sectorsize;
							if (filesize > newsize)
							{
								break;
							}
						}
						if (filesize > newsize)
						{
							if (o)
							{
								if (o == 1)
								{
									char num0[21] = {0};
									sprintf(num0, "%llu", int3);
									unsigned num0len = strlen(num0);
									RtlCopyMemory(KMCSFS->tablestr + offset + num0len, KMCSFS->tablestr + i, KMCSFS->tablestrlen - i + num0len);
									RtlZeroMemory(KMCSFS->tablestr + KMCSFS->tablestrlen - i + offset + num0len, i - offset - num0len);
									KMCSFS->tablestrlen -= i - offset - num0len;
									i = offset + num0len;
								}
								else
								{
									char num0[21] = {0};
									sprintf(num0, "%llu", int3);
									unsigned num0len = strlen(num0);
									char num1[21] = {0};
									sprintf(num1, "%llu", int3 + o - 1);
									unsigned num1len = strlen(num1);
									RtlCopyMemory(KMCSFS->tablestr + offset + num0len + 1, num1, num1len);
									RtlCopyMemory(KMCSFS->tablestr + offset + num0len + 1 + num1len, KMCSFS->tablestr + i, KMCSFS->tablestrlen - i + num0len + 1 + num1len);
									RtlZeroMemory(KMCSFS->tablestr + KMCSFS->tablestrlen - i + offset + num0len + 1 + num1len, i - offset - num0len - 1 - num1len);
									KMCSFS->tablestrlen -= i - offset - num0len - 1 - num1len;
									i = offset + num0len + 1 + num1len;
								}
							}
							else
							{
								RtlCopyMemory(KMCSFS->tablestr + offset, KMCSFS->tablestr + i, KMCSFS->tablestrlen - i);
								RtlZeroMemory(KMCSFS->tablestr + KMCSFS->tablestrlen - i + offset, i - offset);
								KMCSFS->tablestrlen -= i - offset;
								i = offset;
							}
						}
						else
						{
							offset = i;
						}
					}
					switch (cur)
					{
					case 0:
						filesize += KMCSFS->sectorsize;
						if (filesize > newsize)
						{
							RtlCopyMemory(KMCSFS->tablestr + offset, KMCSFS->tablestr + i, KMCSFS->tablestrlen - i);
							RtlZeroMemory(KMCSFS->tablestr + KMCSFS->tablestrlen - i + offset, i - offset);
							KMCSFS->tablestrlen -= i - offset;
							i = offset;
						}
						else
						{
							offset = i;
						}
						break;
					case 1:
						break;
					case 2:
						filesize += int2 - int1;
						if (filesize > newsize)
						{
							RtlCopyMemory(KMCSFS->tablestr + offset, KMCSFS->tablestr + i, KMCSFS->tablestrlen - i);
							RtlZeroMemory(KMCSFS->tablestr + KMCSFS->tablestrlen - i + offset, i - offset);
							KMCSFS->tablestrlen -= i - offset;
							i = offset;
						}
						else
						{
							offset = i;
						}
						break;
					}
				}
				cur = 0;
				int0 = 0;
				int1 = 0;
				int2 = 0;
				int3 = 0;
				multisector = false;
				if (KMCSFS->tablestr[i] == *".")
				{
					break;
				}
			}
			else if (KMCSFS->tablestr[i] == *";")
			{
				cur++;
			}
			else if (KMCSFS->tablestr[i] == *"-")
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
					int0 += toint(KMCSFS->tablestr[i] & 0xff);
					if (KMCSFS->tablestr[i + 1] != *";" && KMCSFS->tablestr[i + 1] != *"," && KMCSFS->tablestr[i + 1] != *"." && KMCSFS->tablestr[i + 1] != *"-")
					{
						int0 *= 10;
					}
					break;
				case 1:
					int1 += toint(KMCSFS->tablestr[i] & 0xff);
					if (KMCSFS->tablestr[i + 1] != *";" && KMCSFS->tablestr[i + 1] != *"," && KMCSFS->tablestr[i + 1] != *"." && KMCSFS->tablestr[i + 1] != *"-")
					{
						int1 *= 10;
					}
					break;
				case 2:
					int2 += toint(KMCSFS->tablestr[i] & 0xff);
					if (KMCSFS->tablestr[i + 1] != *";" && KMCSFS->tablestr[i + 1] != *"," && KMCSFS->tablestr[i + 1] != *"." && KMCSFS->tablestr[i + 1] != *"-")
					{
						int2 *= 10;
					}
					break;
				}
			}
		}
	}
}

bool find_block(KMCSpaceFS* KMCSFS, unsigned long long index, unsigned long long size)
{
	if (size)
	{
		unsigned long* used_bytes = ExAllocatePoolWithTag(NonPagedPool, (KMCSFS->size / KMCSFS->sectorsize - KMCSFS->tablesize) * sizeof(unsigned long), ALLOC_TAG);
		if (!used_bytes)
		{
			ERR("out of memory\n");
			return false;
		}
		RtlZeroMemory(used_bytes, (KMCSFS->size / KMCSFS->sectorsize - KMCSFS->tablesize) * sizeof(unsigned long));
		unsigned long long endsector = 0;
		unsigned long long endoffset = 0;
		unsigned long long endlength = 0;
		bool notzero = false;
		bool multisector = false;
		unsigned cur = 0;
		unsigned long long int0 = 0;
		unsigned long long int1 = 0;
		unsigned long long int2 = 0;
		unsigned long long int3 = 0;
		unsigned long long curindex = 0;
		unsigned long long cursize = 0;
		for (unsigned long long i = 0; i < KMCSFS->tablestrlen; i++)
		{
			if (KMCSFS->tablestr[i] == *"," || KMCSFS->tablestr[i] == *".")
			{
				if (notzero)
				{
					if (multisector)
					{
						for (unsigned long long o = 0; o < int0 - int3; o++)
						{
							used_bytes[int3 + o] += KMCSFS->sectorsize;
							if (curindex == index)
							{
								cursize += KMCSFS->sectorsize;
							}
						}
					}
					switch (cur)
					{
					case 0:
						used_bytes[int0] += KMCSFS->sectorsize;
						if (curindex == index)
						{
							cursize += KMCSFS->sectorsize;
						}
						break;
					case 1:
						break;
					case 2:
						used_bytes[int0] += int2 - int1;
						if (curindex == index)
						{
							cursize += int2 - int1;
							endsector = int0;
							endoffset = int1;
							endlength = int2 - int1;
						}
						break;
					}
				}
				cur = 0;
				int0 = 0;
				int1 = 0;
				int2 = 0;
				int3 = 0;
				notzero = false;
				multisector = false;
				if (KMCSFS->tablestr[i] == *".")
				{
					curindex++;
				}
			}
			else if (KMCSFS->tablestr[i] == *";")
			{
				cur++;
			}
			else if (KMCSFS->tablestr[i] == *"-")
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
					int0 += toint(KMCSFS->tablestr[i] & 0xff);
					if (KMCSFS->tablestr[i + 1] != *";" && KMCSFS->tablestr[i + 1] != *"," && KMCSFS->tablestr[i + 1] != *"." && KMCSFS->tablestr[i + 1] != *"-")
					{
						int0 *= 10;
					}
					break;
				case 1:
					int1 += toint(KMCSFS->tablestr[i] & 0xff);
					if (KMCSFS->tablestr[i + 1] != *";" && KMCSFS->tablestr[i + 1] != *"," && KMCSFS->tablestr[i + 1] != *"." && KMCSFS->tablestr[i + 1] != *"-")
					{
						int1 *= 10;
					}
					break;
				case 2:
					int2 += toint(KMCSFS->tablestr[i] & 0xff);
					if (KMCSFS->tablestr[i + 1] != *";" && KMCSFS->tablestr[i + 1] != *"," && KMCSFS->tablestr[i + 1] != *"." && KMCSFS->tablestr[i + 1] != *"-")
					{
						int2 *= 10;
					}
					break;
				}
			}
		}

		unsigned long long loc = 0;
		if (!(cursize % KMCSFS->sectorsize))
		{
			for (unsigned long long i = 0; i < KMCSFS->tablestrlen; i++)
			{
				if (KMCSFS->tablestr[i] == *".")
				{
					loc++;
					if (loc == index + 1)
					{
						loc = i;
						break;
					}
				}
			}
		}

		char* tempdata = NULL;
		unsigned long long newoffset = 0;
		unsigned long long cursector = 0;
		unsigned long long blocksneeded = (size + KMCSFS->sectorsize - 1) / KMCSFS->sectorsize;
		for (unsigned long long i = 0; i < blocksneeded; i++)
		{
			if (cursize % KMCSFS->sectorsize)
			{ // Last block was part sector
				tempdata = ExAllocatePoolWithTag(NonPagedPool, KMCSFS->sectorsize, ALLOC_TAG);
				if (!tempdata)
				{
					ERR("out of memory\n");
					ExFreePool(used_bytes);
					return false;
				}
				sync_read_phys(KMCSFS->DeviceObject, 0, KMCSFS->size - endsector * KMCSFS->sectorsize - KMCSFS->sectorsize, KMCSFS->sectorsize, tempdata, true);
				dealloc(KMCSFS, index, cursize, cursize - cursize % KMCSFS->sectorsize);
				used_bytes[endsector] -= cursize % KMCSFS->sectorsize;
				size += cursize % KMCSFS->sectorsize;
				cursize -= cursize % KMCSFS->sectorsize;
				for (unsigned long long o = 0; o < KMCSFS->tablestrlen; o++)
				{
					if (KMCSFS->tablestr[o] == *".")
					{
						loc++;
						if (loc == index + 1)
						{
							loc = o;
							break;
						}
					}
				}
			}
			if (!(size % KMCSFS->sectorsize) || i < blocksneeded - 1)
			{ // Full sector allocation
				for (; cursector < (KMCSFS->size / KMCSFS->sectorsize - KMCSFS->tablesize); cursector++)
				{
					if (!used_bytes[cursector])
					{
						if (cursize)
						{
							char* newtable = ExAllocatePoolWithTag(NonPagedPool, KMCSFS->tablestrlen + 22, ALLOC_TAG);
							if (!newtable)
							{
								ERR("out of memory\n");
								ExFreePool(used_bytes);
								return false;
							}
							RtlCopyMemory(newtable, KMCSFS->tablestr, loc);
							newtable[loc] = *",";
							char num[21] = {0};
							sprintf(num, "%llu", cursector);
							unsigned numlen = strlen(num);
							RtlCopyMemory(newtable + loc + 1, num, numlen);
							RtlCopyMemory(newtable + loc + numlen + 1, KMCSFS->tablestr + loc, KMCSFS->tablestrlen - loc);
							ExFreePool(KMCSFS->tablestr);
							KMCSFS->tablestr = newtable;
							KMCSFS->tablestrlen += numlen + 1;
							loc += numlen + 1;
							cursize += KMCSFS->sectorsize;
							used_bytes[cursector] += KMCSFS->sectorsize;
							size -= KMCSFS->sectorsize;
							KMCSFS->used_blocks++;
						}
						else
						{
							char* newtable = ExAllocatePoolWithTag(NonPagedPool, KMCSFS->tablestrlen + 21, ALLOC_TAG);
							if (!newtable)
							{
								ERR("out of memory\n");
								ExFreePool(used_bytes);
								return false;
							}
							RtlCopyMemory(newtable, KMCSFS->tablestr, loc);
							char num[21] = {0};
							sprintf(num, "%llu", cursector);
							unsigned numlen = strlen(num);
							RtlCopyMemory(newtable + loc, num, numlen);
							RtlCopyMemory(newtable + loc + numlen, KMCSFS->tablestr + loc, KMCSFS->tablestrlen - loc);
							ExFreePool(KMCSFS->tablestr);
							KMCSFS->tablestr = newtable;
							KMCSFS->tablestrlen += numlen;
							loc += numlen;
							cursize += KMCSFS->sectorsize;
							used_bytes[cursector] += KMCSFS->sectorsize;
							size -= KMCSFS->sectorsize;
							KMCSFS->used_blocks++;
						}
						break;
					}
				}
			}
			else
			{ // Part sector allocation
				char* tablestr = NULL;
				unsigned long long* used_sector_bytes = NULL;
				unsigned long long temptablestrlen = KMCSFS->tablestrlen;
				for (cursector = 0; cursector < (KMCSFS->size / KMCSFS->sectorsize - KMCSFS->tablesize); cursector++)
				{
					if (!used_bytes[cursector])
					{
						if (cursize)
						{
							char* newtable = ExAllocatePoolWithTag(NonPagedPool, KMCSFS->tablestrlen + 64, ALLOC_TAG);
							if (!newtable)
							{
								ERR("out of memory\n");
								ExFreePool(used_bytes);
								return false;
							}
							RtlCopyMemory(newtable, KMCSFS->tablestr, loc);
							newtable[loc] = *",";
							char num1[21] = {0};
							sprintf(num1, "%llu", cursector);
							unsigned num1len = strlen(num1);
							RtlCopyMemory(newtable + loc + 1, num1, num1len);
							newtable[loc + 1 + num1len] = *";";
							newtable[loc + 1 + num1len + 1] = *"0";
							newtable[loc + 1 + num1len + 2] = *";";
							char num3[21] = {0};
							sprintf(num3, "%llu", size % KMCSFS->sectorsize);
							unsigned num3len = strlen(num3);
							RtlCopyMemory(newtable + loc + 1 + num1len + 3, num3, num3len);
							RtlCopyMemory(newtable + loc + 1 + num1len + 3 + num3len, KMCSFS->tablestr + loc, KMCSFS->tablestrlen - loc);
							ExFreePool(KMCSFS->tablestr);
							KMCSFS->tablestr = newtable;
							KMCSFS->tablestrlen += num1len + num3len + 4;
							loc += num1len + num3len + 4;
							cursize += size % KMCSFS->sectorsize;
							used_bytes[cursector] += size % KMCSFS->sectorsize;
							size -= size % KMCSFS->sectorsize;
							if (used_bytes[cursector] == KMCSFS->sectorsize)
							{
								KMCSFS->used_blocks++;
							}
						}
						else
						{
							char* newtable = ExAllocatePoolWithTag(NonPagedPool, KMCSFS->tablestrlen + 63, ALLOC_TAG);
							if (!newtable)
							{
								ERR("out of memory\n");
								ExFreePool(used_bytes);
								return false;
							}
							RtlCopyMemory(newtable, KMCSFS->tablestr, loc);
							char num1[21] = {0};
							sprintf(num1, "%llu", cursector);
							unsigned num1len = strlen(num1);
							RtlCopyMemory(newtable + loc, num1, num1len);
							newtable[loc + num1len] = *";";
							newtable[loc + num1len + 1] = *"0";
							newtable[loc + num1len + 2] = *";";
							char num3[21] = {0};
							sprintf(num3, "%llu", size % KMCSFS->sectorsize);
							unsigned num3len = strlen(num3);
							RtlCopyMemory(newtable + loc + num1len + 3, num3, num3len);
							RtlCopyMemory(newtable + loc + num1len + 3 + num3len, KMCSFS->tablestr + loc, KMCSFS->tablestrlen - loc);
							ExFreePool(KMCSFS->tablestr);
							KMCSFS->tablestr = newtable;
							KMCSFS->tablestrlen += num1len + num3len + 3;
							loc += num1len + num3len + 3;
							cursize += size % KMCSFS->sectorsize;
							used_bytes[cursector] += size % KMCSFS->sectorsize;
							size -= size % KMCSFS->sectorsize;
							if (used_bytes[cursector] == KMCSFS->sectorsize)
							{
								KMCSFS->used_blocks++;
							}
						}
						break;
					}
					else if (KMCSFS->sectorsize - used_bytes[cursector] >= size % KMCSFS->sectorsize)
					{
						if (!tablestr)
						{
							tablestr = ExAllocatePoolWithTag(NonPagedPool, KMCSFS->tablestrlen, ALLOC_TAG);
							if (!tablestr)
							{
								ERR("out of memory\n");
								ExFreePool(used_bytes);
								return false;
							}
							RtlCopyMemory(tablestr, KMCSFS->tablestr, KMCSFS->tablestrlen);
						}

						if (!used_sector_bytes)
						{
							used_sector_bytes = ExAllocatePoolWithTag(NonPagedPool, KMCSFS->sectorsize / sizeof(unsigned long long), ALLOC_TAG);
							if (!used_sector_bytes)
							{
								ERR("out of memory\n");
								ExFreePool(used_bytes);
								ExFreePool(tablestr);
								return false;
							}
						}
						RtlZeroMemory(used_sector_bytes, KMCSFS->sectorsize / sizeof(unsigned long long));

						cur = 0;
						int0 = 0;
						int1 = 0;
						int2 = 0;
						unsigned long long strsize = 0;

						for (unsigned long long o = 0; o < temptablestrlen; o++)
						{
							strsize++;
							if (tablestr[o] == *"," || tablestr[o] == *".")
							{
								switch (cur)
								{
								case 0:
									if (int0 == cursector)
									{
										RtlCopyMemory(tablestr + o - strsize, tablestr + o, temptablestrlen - o);
										temptablestrlen -= strsize;
										o -= strsize;
										break;
									}
									break;
								case 1:
									break;
								case 2:
									if (int0 == cursector)
									{
										for (unsigned long long p = int1; p < int2; p++)
										{
											used_sector_bytes[p / sizeof(unsigned long long) / 8] |= ((unsigned long long)1 << (p % (sizeof(unsigned long long) * 8)));
										}
										RtlCopyMemory(tablestr + o - strsize, tablestr + o, temptablestrlen - o);
										temptablestrlen -= strsize;
										o -= strsize;
										break;
									}
									break;
								}
								cur = 0;
								int0 = 0;
								int1 = 0;
								int2 = 0;
								strsize = 0;
							}
							else if (tablestr[o] == *";")
							{
								cur++;
							}
							else if (tablestr[o] == *"-")
							{
								cur = 0;
								int0 = 0;
								int1 = 0;
								int2 = 0;
							}
							else
							{
								switch (cur)
								{
								case 0:
									int0 += toint(tablestr[o] & 0xff);
									if (tablestr[o + 1] != *";" && tablestr[o + 1] != *"," && tablestr[o + 1] != *"." && tablestr[o + 1] != *"-")
									{
										int0 *= 10;
									}
									break;
								case 1:
									int1 += toint(tablestr[o] & 0xff);
									if (tablestr[o + 1] != *";" && tablestr[o + 1] != *"," && tablestr[o + 1] != *"." && tablestr[o + 1] != *"-")
									{
										int1 *= 10;
									}
									break;
								case 2:
									int2 += toint(tablestr[o] & 0xff);
									if (tablestr[o + 1] != *";" && tablestr[o + 1] != *"," && tablestr[o + 1] != *"." && tablestr[o + 1] != *"-")
									{
										int2 *= 10;
									}
									break;
								}
							}
						}

						unsigned long long freecount = 0;
						unsigned long long offset = 0;
						for (; offset < KMCSFS->sectorsize; offset++)
						{
							if (used_sector_bytes[offset / sizeof(unsigned long long) / 8] & ((unsigned long long)1 << (offset % (sizeof(unsigned long long) * 8))))
							{
								freecount = 0;
								if (KMCSFS->sectorsize - offset < size % KMCSFS->sectorsize)
								{
									break;
								}
							}
							else
							{
								freecount++;
								if (freecount == size % KMCSFS->sectorsize)
								{
									offset++;
									break;
								}
							}
						}

						if (freecount == size % KMCSFS->sectorsize)
						{
							if (cursize)
							{
								char* newtable = ExAllocatePoolWithTag(NonPagedPool, KMCSFS->tablestrlen + 64, ALLOC_TAG);
								if (!newtable)
								{
									ERR("out of memory\n");
									ExFreePool(used_bytes);
									ExFreePool(tablestr);
									ExFreePool(used_sector_bytes);
									return false;
								}
								RtlCopyMemory(newtable, KMCSFS->tablestr, loc);
								newtable[loc] = *",";
								char num1[21] = {0};
								sprintf(num1, "%llu", cursector);
								unsigned num1len = strlen(num1);
								RtlCopyMemory(newtable + loc + 1, num1, num1len);
								newtable[loc + 1 + num1len] = *";";
								char num2[21] = {0};
								sprintf(num2, "%llu", offset - size);
								newoffset = offset - size;
								unsigned num2len = strlen(num2);
								RtlCopyMemory(newtable + loc + 1 + num1len + 1, num2, num2len);
								newtable[loc + 1 + num1len + 1 + num2len] = *";";
								char num3[21] = {0};
								sprintf(num3, "%llu", offset);
								unsigned num3len = strlen(num3);
								RtlCopyMemory(newtable + loc + 1 + num1len + 1 + num2len + 1, num3, num3len);
								RtlCopyMemory(newtable + loc + 1 + num1len + 1 + num2len + 1 + num3len, KMCSFS->tablestr + loc, KMCSFS->tablestrlen - loc);
								ExFreePool(KMCSFS->tablestr);
								KMCSFS->tablestr = newtable;
								KMCSFS->tablestrlen += num1len + 1 + num2len + 1 + num3len + 1;
								loc += num1len + 1 + num2len + 1 + num3len + 1;
								cursize += size % KMCSFS->sectorsize;
								used_bytes[cursector] += size % KMCSFS->sectorsize;
								size -= size % KMCSFS->sectorsize;
								if (used_bytes[cursector] == KMCSFS->sectorsize)
								{
									KMCSFS->used_blocks++;
								}
							}
							else
							{
								char* newtable = ExAllocatePoolWithTag(NonPagedPool, KMCSFS->tablestrlen + 63, ALLOC_TAG);
								if (!newtable)
								{
									ERR("out of memory\n");
									ExFreePool(used_bytes);
									ExFreePool(tablestr);
									ExFreePool(used_sector_bytes);
									return false;
								}
								RtlCopyMemory(newtable, KMCSFS->tablestr, loc);
								char num1[21] = {0};
								sprintf(num1, "%llu", cursector);
								unsigned num1len = strlen(num1);
								RtlCopyMemory(newtable + loc, num1, num1len);
								newtable[loc + num1len] = *";";
								char num2[21] = {0};
								sprintf(num2, "%llu", offset - size);
								newoffset = offset - size;
								unsigned num2len = strlen(num2);
								RtlCopyMemory(newtable + loc + num1len + 1, num2, num2len);
								newtable[loc + num1len + 1 + num2len] = *";";
								char num3[21] = {0};
								sprintf(num3, "%llu", offset);
								unsigned num3len = strlen(num3);
								RtlCopyMemory(newtable + loc + num1len + 1 + num2len + 1, num3, num3len);
								RtlCopyMemory(newtable + loc + num1len + 1 + num2len + 1 + num3len, KMCSFS->tablestr + loc, KMCSFS->tablestrlen - loc);
								ExFreePool(KMCSFS->tablestr);
								KMCSFS->tablestr = newtable;
								KMCSFS->tablestrlen += num1len + 1 + num2len + 1 + num3len;
								loc += num1len + 1 + num2len + 1 + num3len;
								cursize += size % KMCSFS->sectorsize;
								used_bytes[cursector] += size % KMCSFS->sectorsize;
								size -= size % KMCSFS->sectorsize;
								if (used_bytes[cursector] == KMCSFS->sectorsize)
								{
									KMCSFS->used_blocks++;
								}
							}
							break;
						}
					}
				}
				if (tablestr)
				{
					ExFreePool(tablestr);
				}
				if (used_sector_bytes)
				{
					ExFreePool(used_sector_bytes);
				}
			}
			if (tempdata)
			{
				sync_write_phys(KMCSFS->DeviceObject, 0, KMCSFS->size - cursector * KMCSFS->sectorsize - KMCSFS->sectorsize + newoffset, endlength, tempdata + endoffset, true);
				ExFreePool(tempdata);
				tempdata = NULL;
			}
		}

		ExFreePool(used_bytes);
		return !size;
	}
	else
	{
		if (!KMCSFS->used_blocks)
		{
			unsigned long* used_bytes = ExAllocatePoolWithTag(NonPagedPool, (KMCSFS->size / KMCSFS->sectorsize - KMCSFS->tablesize) * sizeof(unsigned long), ALLOC_TAG);
			if (!used_bytes)
			{
				ERR("out of memory\n");
				return false;
			}
			RtlZeroMemory(used_bytes, (KMCSFS->size / KMCSFS->sectorsize - KMCSFS->tablesize) * sizeof(unsigned long));
			bool notzero = false;
			bool multisector = false;
			unsigned cur = 0;
			unsigned long long int0 = 0;
			unsigned long long int1 = 0;
			unsigned long long int2 = 0;
			unsigned long long int3 = 0;
			for (unsigned long long i = 0; i < KMCSFS->tablestrlen; i++)
			{
				if (KMCSFS->tablestr[i] == *"," || KMCSFS->tablestr[i] == *".")
				{
					if (notzero)
					{
						if (multisector)
						{
							for (unsigned long long o = 0; o < int0 - int3; o++)
							{
								used_bytes[int3 + o] += KMCSFS->sectorsize;
								KMCSFS->used_blocks++;
							}
						}
						switch (cur)
						{
						case 0:
							used_bytes[int0] += KMCSFS->sectorsize;
							KMCSFS->used_blocks++;
							break;
						case 1:
							break;
						case 2:
							used_bytes[int0] += int2 - int1;
							if (used_bytes[int0] == KMCSFS->sectorsize)
							{
								KMCSFS->used_blocks++;
							}
							break;
						}
					}
					cur = 0;
					int0 = 0;
					int1 = 0;
					int2 = 0;
					int3 = 0;
					notzero = false;
					multisector = false;
				}
				else if (KMCSFS->tablestr[i] == *";")
				{
					cur++;
				}
				else if (KMCSFS->tablestr[i] == *"-")
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
						int0 += toint(KMCSFS->tablestr[i] & 0xff);
						if (KMCSFS->tablestr[i + 1] != *";" && KMCSFS->tablestr[i + 1] != *"," && KMCSFS->tablestr[i + 1] != *"." && KMCSFS->tablestr[i + 1] != *"-")
						{
							int0 *= 10;
						}
						break;
					case 1:
						int1 += toint(KMCSFS->tablestr[i] & 0xff);
						if (KMCSFS->tablestr[i + 1] != *";" && KMCSFS->tablestr[i + 1] != *"," && KMCSFS->tablestr[i + 1] != *"." && KMCSFS->tablestr[i + 1] != *"-")
						{
							int1 *= 10;
						}
						break;
					case 2:
						int2 += toint(KMCSFS->tablestr[i] & 0xff);
						if (KMCSFS->tablestr[i + 1] != *";" && KMCSFS->tablestr[i + 1] != *"," && KMCSFS->tablestr[i + 1] != *"." && KMCSFS->tablestr[i + 1] != *"-")
						{
							int2 *= 10;
						}
						break;
					}
				}
			}
			ExFreePool(used_bytes);
		}
		return true;
	}
}
