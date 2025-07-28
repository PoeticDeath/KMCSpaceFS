// Copyright (c) Anthony Kerr 2024-

#pragma once

#define delete_pending 1
#define trun_on_close 2
#define stream_delete 4

typedef struct _Dict
{
	unsigned long long filenameloc;
	unsigned long long hash;
	unsigned long long index;

	unsigned long long opencount;
	SHARE_ACCESS shareaccess;
	FILE_LOCK lock;
	unsigned long long flags;
	unsigned long long streamdeletecount;
} Dict;

Dict* CreateDict(unsigned long long size);
Dict* ResizeDict(Dict* dict, unsigned long long oldsize, unsigned long long* newsize);
bool AddDictEntry(Dict** dict, PWCH filename, unsigned long long filenameloc, unsigned long long filenamelen, unsigned long long* cursize, unsigned long long* size, unsigned long long index, bool scan);
unsigned long long FindDictEntry(Dict* dict, char* table, unsigned long long tableend, unsigned long long size, PWCH filename, unsigned long long filenamelen);
void RemoveDictEntry(Dict* dict, unsigned long long size, unsigned long long dindex, unsigned long long filenamelen, unsigned long long* cursize);
