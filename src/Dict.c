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

Dict* ResizeDict(Dict* dict, unsigned long long oldsize, unsigned long long* newsize)
{
	Dict* ndict = NULL;
startover:
	*newsize *= 2;
	ndict = CreateDict(*newsize);
	if (ndict == NULL)
	{
		*newsize = oldsize;
		return NULL;
	}
	for (unsigned long long i = 0; i < oldsize; i++)
	{
		if (dict[i].filenameloc)
		{
			unsigned long long hash = dict[i].hash;
			unsigned long long j = hash % *newsize;
			if (!j)
			{
				j++;
			}
			Dict* tdict = ndict + j;
			bool taken = ndict[j].filenameloc;
			while (tdict->ndict)
			{
				tdict = tdict->ndict;
			}
			while (ndict[j].filenameloc && j < *newsize - 1)
			{
				j++;
			}
			if (ndict[j].filenameloc || j > *newsize - 1)
			{
				ExFreePool(ndict);
				goto startover;
			}
			ndict[j].filenameloc = dict[i].filenameloc;
			ndict[j].hash = hash;
			ndict[j].index = dict[i].index;
			ndict[j].opencount = dict[i].opencount;
			ndict[j].shareaccess = dict[i].shareaccess;
			ndict[j].lock = dict[i].lock;
			ndict[j].flags = dict[i].flags;
			ndict[j].streamdeletecount = dict[i].streamdeletecount;
			ndict[j].fcb = dict[i].fcb;
			ndict[j].filename = dict[i].filename;
			if (taken)
			{
				ndict[j].pdict = tdict;
				tdict->ndict = ndict + j;
			}
		}
	}
	return ndict;
}

bool AddDictEntry(Dict** dict, PWCH filename, unsigned long long filenameloc, unsigned long long filenamelen, unsigned long long* cursize, unsigned long long* size, unsigned long long index, bool scan)
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
		if (Filename[i] == 92)
		{
			Filename[i] = 47;
		}
		if (Filename[i] >= 'A' && Filename[i] <= 'Z')
		{
			Filename[i] += 32;
		}
	}
	sha3_HashBuffer(256, 0, Filename, filenamelen, &hash, 8);
	ExFreePool(Filename);
	unsigned long long i = hash % *size;
	if (!i)
	{
		i++;
	}
	Dict* tdict = *dict + i;
	bool taken = (*dict)[i].filenameloc;
	while (tdict->ndict)
	{
		tdict = tdict->ndict;
	}
	while ((*dict)[i].filenameloc && i < *size - 1)
	{
		i++;
	}
	while ((*dict)[i].filenameloc || i > *size - 1)
	{
		Dict* ndict = ResizeDict(*dict, *size, size);
		if (ndict == NULL)
		{
			return false;
		}
		i = hash % *size;
		if (!i)
		{
			i++;
		}
		tdict = ndict + i;
		taken = ndict[i].filenameloc;
		while (tdict->ndict)
		{
			tdict = tdict->ndict;
		}
		while (ndict[i].filenameloc && i < *size - 1)
		{
			i++;
		}
		ExFreePool(*dict);
		*dict = ndict;
	}
	(*cursize)++;
	if (scan)
	{
		for (unsigned long long j = 0; j < *size; j++)
		{
			if (!(*dict)[j].filenameloc)
			{
				continue;
			}
			if ((*dict)[j].index >= index)
			{
				(*dict)[j].index++;
			}
			if ((*dict)[j].filenameloc >= filenameloc)
			{
				(*dict)[j].filenameloc += filenamelen + 1;
			}
		}
	}
	RtlZeroMemory(*dict + i, sizeof(Dict));
	(*dict)[i].hash = hash;
	(*dict)[i].filenameloc = filenameloc;
	(*dict)[i].index = index;
	if (taken)
	{
		(*dict)[i].pdict = tdict;
		tdict->ndict = *dict + i;
	}
	FsRtlInitializeFileLock(&(*dict)[i].lock, NULL, NULL);
	if (*cursize > *size * 3 / 4)
	{
		Dict* tdict = ResizeDict(*dict, *size, size);
		if (tdict == NULL)
		{
			return true;
		}
		ExFreePool(*dict);
		*dict = tdict;
	}
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
		if (Filename[i] == 92)
		{
			Filename[i] = 47;
		}
		if (Filename[i] >= 'A' && Filename[i] <= 'Z')
		{
			Filename[i] += 32;
		}
	}
	unsigned long long hash = 0;
	sha3_HashBuffer(256, 0, Filename, filenamelen, &hash, 8);
	unsigned long long o = hash % size;
	if (!o)
	{
		o++;
	}
	while (true)
	{
		if (o > size - 1)
		{
			ExFreePool(Filename);
			return 0;
		}
		if (!dict[o].filenameloc)
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
			else
			{
				if ((table[tableend + dict[o].filenameloc + j] & 0xff) != *"/")
				{
					filename[j] = table[tableend + dict[o].filenameloc + j] & 0xff;
				}
			}
			if (j == filenamelen - 1 && ((table[tableend + dict[o].filenameloc + j + 1] & 0xff) == 255 || (table[tableend + dict[o].filenameloc + j + 1] & 0xff) == 42) && dict[o].hash == hash)
			{
				ExFreePool(Filename);
				return o;
			}
		}
		if (dict[o].ndict)
		{
			o = dict[o].ndict - dict;
		}
		else
		{
			ExFreePool(Filename);
			return 0;
		}
	}
}

void RemoveDictEntry(Dict* dict, unsigned long long size, unsigned long long dindex, unsigned long long filenamelen, unsigned long long* cursize)
{
	unsigned long long index = dict[dindex].index;
	unsigned long long filenameloc = dict[dindex].filenameloc;
	FsRtlUninitializeFileLock(&dict[dindex].lock);
	if (dict[dindex].ndict)
	{
		Dict* tdict = dict[dindex].ndict;
		if (tdict->pdict->pdict)
		{
			tdict = tdict->pdict->pdict->ndict = NULL;
		}
		tdict->pdict = NULL;
		RtlZeroMemory(dict + dindex, sizeof(Dict));

		unsigned long long count = 1;
		Dict* ldict = CreateDict(count);
		if (ldict)
		{
			unsigned long long i = 0;
			while (tdict)
			{
				ldict[i] = *tdict;
				Dict* ttdict = tdict->pdict;
				RtlZeroMemory(tdict, sizeof(Dict));
				tdict = ttdict;
				i++;
			}
			while (i)
			{
				i--;
				unsigned long long ndindex = ldict[i].hash % size;
				if (!ndindex)
				{
					ndindex++;
				}
				tdict = dict + ndindex;
				bool taken = dict[ndindex].filenameloc;
				while (tdict->ndict)
				{
					tdict = tdict->ndict;
				}
				while (dict[ndindex].filenameloc && ndindex < size - 1)
				{
					ndindex++;
				}
				RtlZeroMemory(dict + ndindex, sizeof(Dict));
				dict[ndindex].hash = ldict[i].hash;
				dict[ndindex].filenameloc = ldict[i].filenameloc;
				dict[ndindex].index = ldict[i].index;
				dict[ndindex].opencount = ldict[i].opencount;
				dict[ndindex].shareaccess = ldict[i].shareaccess;
				dict[ndindex].lock = ldict[i].lock;
				dict[ndindex].flags = ldict[i].flags;
				dict[ndindex].streamdeletecount = ldict[i].streamdeletecount;
				dict[ndindex].fcb = ldict[i].fcb;
				dict[ndindex].filename = ldict[i].filename;
				if (taken)
				{
					dict[ndindex].pdict = tdict;
					tdict->ndict = dict + ndindex;
				}
			}
			ExFreePool(ldict);
		}
	}
	else if (dict[dindex].pdict)
	{
		dict[dindex].pdict->ndict = NULL;
		RtlZeroMemory(dict + dindex, sizeof(Dict));
	}
	else
	{
		RtlZeroMemory(dict + dindex, sizeof(Dict));
	}
	(*cursize)--;
	for (unsigned long long i = 0; i < size; i++)
	{
		if (!dict[i].filenameloc)
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
