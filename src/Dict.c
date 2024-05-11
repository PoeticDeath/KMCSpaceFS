// Copyright (c) Anthony Kerr 2024-

#include "KMCSpaceFS_drv.h"
#include "Dict.h"
#include "Sha3.h"

Dict* CreateDict(unsigned long long size)
{
	Dict* dict = (Dict*)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(Dict) * size, ALLOC_TAG);
	if (dict == NULL)
	{
		return NULL;
	}
	RtlZeroMemory(dict, sizeof(Dict) * size);
	return dict;
}

Dict* ResizeDict(Dict* dict, unsigned long long oldsize, unsigned long long newsize)
{
	Dict* ndict = NULL;
startover:
	ndict = (Dict*)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(Dict) * newsize, ALLOC_TAG);
	if (ndict == NULL)
	{
		return NULL;
	}
	RtlZeroMemory(ndict, sizeof(Dict) * newsize);
	for (unsigned long long i = 0; i < oldsize; i++)
	{
		if (dict[i].filenameloc != NULL)
		{
			unsigned long long hash = dict[i].hash;
			unsigned long long j = hash % newsize;
			while (ndict[j].filenameloc != NULL)
			{
				j++;
			}
			if (j > newsize - 1)
			{
				ExFreePool(ndict);
				newsize += 1024;
				goto startover;
			}
			ndict[j].filenameloc = dict[i].filenameloc;
			ndict[j].hash = hash;
			ndict[j].index = dict[i].index;
		}
	}
	return ndict;
}

bool AddDictEntry(Dict* dict, PWCH filename, unsigned long long filenameloc, unsigned long long filenamelen, unsigned long long* cursize, unsigned long long* size, unsigned long long index)
{
	unsigned long long hash = 0;
	char* Filename = ExAllocatePoolWithTag(NonPagedPoolNx, filenamelen + 1, ALLOC_TAG);
	if (Filename == NULL)
	{
		return false;
	}
	for (unsigned long long i = 0; i < filenamelen; i++)
	{
		Filename[i] = filename[i] & 0xff;
	}
	sha3_HashBuffer(256, 0, Filename, filenamelen, &hash, 8);
	ExFreePool(Filename);
	unsigned long long i = hash % *size;
	while (dict[i].filenameloc != NULL)
	{
		if (dict[i].hash == hash)
		{
			ERR("This is bad!");
		}
		i++;
	}
	while (i > *size - 1)
	{
		Dict* tdict = ResizeDict(dict, *size, *size + 1024);
		if (tdict == NULL)
		{
			return false;
		}
		i = hash % *size;
		while (tdict[i].filenameloc != NULL)
		{
			i++;
		}
		ExFreePool(dict);
		dict = tdict;
		(*cursize)++;
		*size += 1024;
	}
	for (unsigned long long j = 0; j < *size; j++)
	{
		if (dict[j].filenameloc == NULL)
		{
			continue;
		}
		if (dict[j].index >= index)
		{
			dict[j].index++;
		}
		if (dict[j].filenameloc >= filenameloc)
		{
			dict[j].filenameloc += filenamelen + 1;
		}
	}
	dict[i].filenameloc = filenameloc;
	dict[i].hash = hash;
	dict[i].index = index;
	return true;
}

unsigned long long FindDictEntry(Dict* dict, char* table, unsigned long long tableend, unsigned long long size, PWCH filename, unsigned long long filenamelen)
{
	char* Filename = ExAllocatePoolWithTag(NonPagedPoolNx, filenamelen + 1, ALLOC_TAG);
	if (Filename == NULL)
	{
		return 0;
	}
	for (unsigned long long i = 0; i < filenamelen; i++)
	{
		Filename[i] = filename[i] & 0xff;
	}
	unsigned long long hash = 0;
	sha3_HashBuffer(256, 0, Filename, filenamelen, &hash, 8);
	unsigned long long o = hash % size;
	while (true)
	{
		if (dict[o].filenameloc == NULL || o > size - 1)
		{
			ExFreePool(Filename);
			return 0;
		}
		for (unsigned long long j = 0; j < filenamelen; j++)
		{
			if (!((incmp((table[tableend + dict[o].filenameloc + j] & 0xff), (Filename[j] & 0xff)) || (((table[tableend + dict[o].filenameloc + j] & 0xff) == *"/") && ((Filename[j] & 0xff) == *"\\")))))
			{
				break;
			}
			if (j == filenamelen - 1)
			{
				ExFreePool(Filename);
				return o;
			}
		}
		o++;
	}
}

void RemoveDictEntry(Dict* dict, unsigned long long size, unsigned long long dindex, unsigned long long filenamelen)
{
	unsigned long long index = dict[dindex].index;
	unsigned long long* filenameloc = dict[dindex].filenameloc;
	RtlZeroMemory(dict + dindex, sizeof(Dict));
	for (unsigned long long i = 0; i < size; i++)
	{
		if (dict[i].filenameloc == NULL)
		{
			continue;
		}
		if (dict[i].index > index)
		{
			dict[i].index--;
		}
		if (dict[i].filenameloc > filenameloc)
		{
			dict[i].filenameloc -= filenamelen + 1;
		}
	}
	return;
}
