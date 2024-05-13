// Copyright (c) Anthony Kerr 2024-

#pragma once

typedef struct _Dict
{
	unsigned long long filenameloc;
	unsigned long long hash;
	unsigned long long index;
} Dict;

Dict* CreateDict(unsigned long long size);
Dict* ResizeDict(Dict* dict, unsigned long long oldsize, unsigned long long newsize);
bool AddDictEntry(Dict* dict, PWCH filename, unsigned long long filenameloc, unsigned long long filenamelen, unsigned long long* cursize, unsigned long long* size, unsigned long long index, bool scan);
unsigned long long FindDictEntry(Dict* dict, char* table, unsigned long long tableend, unsigned long long size, PWCH filename, unsigned long long filenamelen);
void RemoveDictEntry(Dict* dict, unsigned long long size, unsigned long long dindex, unsigned long long filenamelen, unsigned long long* cursize);
