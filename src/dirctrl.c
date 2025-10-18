// Copyright (c) Anthony Kerr 2024-

#include "KMCSpaceFS_drv.h"

// not currently in mingw
#ifndef _MSC_VER
#define FileIdExtdDirectoryInformation (enum _FILE_INFORMATION_CLASS)60
#define FileIdExtdBothDirectoryInformation (enum _FILE_INFORMATION_CLASS)63

typedef struct _FILE_ID_EXTD_DIR_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	ULONG EaSize;
	ULONG ReparsePointTag;
	FILE_ID_128 FileId;
	WCHAR FileName[1];
} FILE_ID_EXTD_DIR_INFORMATION, *PFILE_ID_EXTD_DIR_INFORMATION;

typedef struct _FILE_ID_EXTD_BOTH_DIR_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	ULONG EaSize;
	ULONG ReparsePointTag;
	FILE_ID_128 FileId;
	CCHAR ShortNameLength;
	WCHAR ShortName[12];
	WCHAR FileName[1];
} FILE_ID_EXTD_BOTH_DIR_INFORMATION, *PFILE_ID_EXTD_BOTH_DIR_INFORMATION;
#endif

NTSTATUS query_directory(PIRP Irp)
{
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	fcb* rfcb = NULL;
	fcb* fcb = IrpSp->FileObject->FsContext;
	ccb* ccb = IrpSp->FileObject->FsContext2;
	device_extension* Vcb = fcb ? fcb->Vcb : NULL;
	NTSTATUS Status = STATUS_INVALID_PARAMETER;
	LONG len = IrpSp->Parameters.QueryDirectory.Length;
	WCHAR* filename = NULL;
	bool first = true;
	void* buf;

	TRACE("query directory\n");

	if (!ccb)
	{
		ERR("ccb was NULL\n");
		return Status;
	}

	if (!fcb)
	{
		ERR("fcb was NULL\n");
		return Status;
	}

	if (Irp->RequestorMode == UserMode && !(ccb->access & FILE_LIST_DIRECTORY))
	{
		WARN("insufficient privileges\n");
		return STATUS_ACCESS_DENIED;
	}

	if (!Vcb)
	{
		ERR("Vcb was NULL\n");
		return Status;
	}

	Status = STATUS_SUCCESS;

	ExAcquireResourceSharedLite(&Vcb->tree_lock, true);
	ExAcquireResourceExclusiveLite(&fcb->nonpaged->dir_children_lock, true);

	buf = map_user_buffer(Irp, NormalPagePriority);

	if (Irp->MdlAddress && !buf)
	{
		ERR("map_user_buffer failed\n");
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto end;
	}

	RtlZeroMemory(buf, len);

	if (IrpSp->Flags & SL_RESTART_SCAN)
	{
		ccb->query_dir_offset = 0;
		ccb->query_dir_index = 0;
		ccb->query_dir_file_count = 0;
		if (ccb->filter.Buffer)
		{
			ExFreePool(ccb->filter.Buffer);
			ccb->filter.Buffer = NULL;
			ccb->filter.Length = 0;
		}
	}

	Irp->IoStatus.Information = 0;
	unsigned long old_offset = 0;

	filename = ExAllocatePoolWithTag(fcb->pool_type, 65536 * sizeof(WCHAR), ALLOC_TAG);
	if (!filename)
	{
		ERR("out of memory\n");
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto end;
	}

	UNICODE_STRING Filename;
	Filename.Buffer = filename;

	bool filterb = false;
	if (!ccb->filter.Buffer)
	{
		ccb->filter.Buffer = ExAllocatePoolWithTag(fcb->pool_type, 65536 * sizeof(WCHAR), ALLOC_TAG);
		if (!ccb->filter.Buffer)
		{
			ERR("out of memory\n");
			Status = STATUS_INSUFFICIENT_RESOURCES;
			goto end;
		}
	}
	else if (ccb->filter.Length)
	{
		filterb = true;
	}

	if (IrpSp->Parameters.QueryDirectory.FileName)
	{
		if (IrpSp->Parameters.QueryDirectory.FileName->Buffer[0] == 46 && IrpSp->Parameters.QueryDirectory.FileName->Length == sizeof(WCHAR))
		{
			ccb->query_dir_file_count = 1;
		}
		else if (IrpSp->Parameters.QueryDirectory.FileName->Buffer[0] == 46 && IrpSp->Parameters.QueryDirectory.FileName->Buffer[1] == 46 && IrpSp->Parameters.QueryDirectory.FileName->Length == 2 * sizeof(WCHAR))
		{
			ccb->query_dir_file_count = 2;
		}
		else if (IrpSp->Parameters.QueryDirectory.FileName->Buffer[0] != *L"*")
		{
			ccb->query_dir_file_count = 2;
			for (unsigned long long i = 0; i < IrpSp->Parameters.QueryDirectory.FileName->Length / sizeof(WCHAR); i++)
			{
				if (IrpSp->Parameters.QueryDirectory.FileName->Buffer[i] == *L"*")
				{
					filterb = true;
					break;
				}
			}
			ccb->filter.Length = IrpSp->Parameters.QueryDirectory.FileName->Length;
			if (IrpSp->Parameters.QueryDirectory.FileName->Buffer[0] == *L"/" || IrpSp->Parameters.QueryDirectory.FileName->Buffer[0] == *L"\\")
			{
				RtlCopyMemory(ccb->filter.Buffer, ccb->filename->Buffer, ccb->filename->Length);
				ccb->filter.Length += ccb->filename->Length;
				RtlCopyMemory(ccb->filter.Buffer + ccb->filename->Length / sizeof(WCHAR), IrpSp->Parameters.QueryDirectory.FileName->Buffer, IrpSp->Parameters.QueryDirectory.FileName->Length);
			}
			else
			{
				RtlCopyMemory(ccb->filter.Buffer, ccb->filename->Buffer, ccb->filename->Length);
				ccb->filter.Length += ccb->filename->Length;
				bool addedslash = false;
				if (ccb->filter.Buffer[ccb->filename->Length / sizeof(WCHAR) - 1] != *L"/" && ccb->filter.Buffer[ccb->filename->Length / sizeof(WCHAR) - 1] != *L"\\")
				{
					ccb->filter.Buffer[ccb->filename->Length / sizeof(WCHAR)] = 47;
					ccb->filter.Length += sizeof(WCHAR);
					addedslash = true;
				}
				RtlCopyMemory(ccb->filter.Buffer + ccb->filename->Length / sizeof(WCHAR) + addedslash, IrpSp->Parameters.QueryDirectory.FileName->Buffer, IrpSp->Parameters.QueryDirectory.FileName->Length);
			}
			if (!filterb && !ccb->query_dir_offset)
			{
				ccb->query_dir_index = get_filename_index(ccb->filter, &Vcb->vde->pdode->KMCSFS);
				ExFreePool(ccb->filter.Buffer);
				ccb->filter.Buffer = NULL;
				ccb->filter.Length = 0;
				if (!ccb->query_dir_index)
				{
					Status = STATUS_NO_SUCH_FILE;
					goto end;
				}
				unsigned long long curindex = 0;
				while (curindex < ccb->query_dir_index)
				{
					if ((Vcb->vde->pdode->KMCSFS.table[Vcb->vde->pdode->KMCSFS.tableend + ccb->query_dir_offset] & 0xff) == 255)
					{
						curindex++;
					}
					ccb->query_dir_offset++;
				}
			}
		}
	}

	unsigned long long lastslash = 0;
	if (ccb->query_dir_file_count == 1)
	{
		for (unsigned long long i = 0; i < ccb->filename->Length / sizeof(WCHAR); i++)
		{
			if (ccb->filename->Buffer[i] == *L"/" || ccb->filename->Buffer[i] == *L"\\")
			{
				lastslash = i;
			}
		}
	}

	while (ccb->query_dir_offset < Vcb->vde->pdode->KMCSFS.filenamesend - Vcb->vde->pdode->KMCSFS.tableend + 1)
	{
		unsigned long long query_dir_offset = ccb->query_dir_offset;
		unsigned long long query_dir_index = ccb->query_dir_index;
		unsigned long long filenamelen = 0;
		unsigned long long index;
		unsigned long long FNL = 0;

		if (ccb->query_dir_file_count > 1 || ccb->filename->Length / sizeof(WCHAR) < 2 || !buf)
		{
			for (; ccb->query_dir_offset < Vcb->vde->pdode->KMCSFS.filenamesend - Vcb->vde->pdode->KMCSFS.tableend + 1; ccb->query_dir_offset++)
			{
				if ((Vcb->vde->pdode->KMCSFS.table[Vcb->vde->pdode->KMCSFS.tableend + ccb->query_dir_offset] & 0xff) == 255 || (Vcb->vde->pdode->KMCSFS.table[Vcb->vde->pdode->KMCSFS.tableend + ccb->query_dir_offset] & 0xff) == 42) // 255 = file, 42 = fuse symlink
				{
					if (ccb->filename->Length / sizeof(WCHAR) < filenamelen)
					{
						bool isin = true;
						unsigned long long i = 0;
						for (; i < ccb->filename->Length / sizeof(WCHAR); i++)
						{
							if (!incmp(ccb->filename->Buffer[i] & 0xff, filename[i] & 0xff) && !(ccb->filename->Buffer[i] == *L"/" && filename[i] == *L"\\") && !(ccb->filename->Buffer[i] == *L"\\" && filename[i] == *L"/"))
							{
								isin = false;
								break;
							}
						}
						if (!(filename[i] == *L"/") && !(filename[i] == *L"\\") && (ccb->filename->Length > 2))
						{
							isin = false;
						}
						i++;
						for (; i < filenamelen; i++)
						{
							if (filename[i] == *L"/" || filename[i] == *L"\\")
							{
								isin = false;
								break;
							}
						}
						if (IrpSp->Parameters.QueryDirectory.FileName && IrpSp->Parameters.QueryDirectory.FileName->Length > 1)
						{
							if (IrpSp->Parameters.QueryDirectory.FileName->Buffer[0] != *L"*" && !filterb)
							{
								if (IrpSp->Parameters.QueryDirectory.FileName->Length / sizeof(WCHAR) != filenamelen - ccb->filename->Length / sizeof(WCHAR) - (ccb->filename->Length > 2))
								{
									isin = false;
								}
								else
								{
									for (i = 0; i < IrpSp->Parameters.QueryDirectory.FileName->Length / sizeof(WCHAR); i++)
									{
										if (!incmp(IrpSp->Parameters.QueryDirectory.FileName->Buffer[i] & 0xff, filename[i + ccb->filename->Length / sizeof(WCHAR) + (ccb->filename->Length > 2)] & 0xff) && !(IrpSp->Parameters.QueryDirectory.FileName->Buffer[i] == *L"/" && filename[i + ccb->filename->Length / sizeof(WCHAR) + (ccb->filename->Length > 2)] == *L"\\") && !(IrpSp->Parameters.QueryDirectory.FileName->Buffer[i] == *L"\\" && filename[i + ccb->filename->Length / sizeof(WCHAR) + (ccb->filename->Length > 2)] == *L"/"))
										{
											isin = false;
											break;
										}
									}
								}
							}
						}
						if (filterb && isin)
						{
							for (i = 0; i < ccb->filter.Length / sizeof(WCHAR) - 1; i++)
							{
								if (!incmp(ccb->filter.Buffer[i] & 0xff, filename[i] & 0xff) && !(ccb->filter.Buffer[i] == *L"/" && filename[i] == *L"\\") && !(ccb->filter.Buffer[i] == *L"\\" && filename[i] == *L"/"))
								{
									isin = false;
									break;
								}
							}
						}
						for (unsigned long long j = 0; j < filenamelen; j++)
						{
							if (filename[j] == *L":")
							{
								isin = false;
								break;
							}
						}
						if (isin)
						{
							break;
						}
					}
					filenamelen = 0;
					query_dir_index = ccb->query_dir_index;
					query_dir_offset = ccb->query_dir_offset;
					if ((Vcb->vde->pdode->KMCSFS.table[Vcb->vde->pdode->KMCSFS.tableend + ccb->query_dir_offset] & 0xff) == 255)
					{
						ccb->query_dir_index++;
					}
				}
				else
				{
					filename[filenamelen] = Vcb->vde->pdode->KMCSFS.table[Vcb->vde->pdode->KMCSFS.tableend + ccb->query_dir_offset] & 0xff;
					filenamelen++;
				}
			}
		}
		else
		{
			if (!ccb->query_dir_file_count)
			{
				index = get_filename_index(*ccb->filename, &Vcb->vde->pdode->KMCSFS);
				Filename.Buffer[ccb->filename->Length / sizeof(WCHAR) + (ccb->filename->Length > 2)] = 46;
				Filename.Buffer[ccb->filename->Length / sizeof(WCHAR) + (ccb->filename->Length > 2) + 1] = 0;
				filenamelen = 1;
				FNL = filenamelen * sizeof(WCHAR);
			}
			else
			{
				unsigned long long namelen = ccb->filename->Length;
				ccb->filename->Length = max(lastslash * sizeof(WCHAR), 2);
				index = get_filename_index(*ccb->filename, &Vcb->vde->pdode->KMCSFS);
				ccb->filename->Length = namelen;
				Filename.Buffer[ccb->filename->Length / sizeof(WCHAR) + (ccb->filename->Length > 2)] = 46;
				Filename.Buffer[ccb->filename->Length / sizeof(WCHAR) + (ccb->filename->Length > 2) + 1] = 46;
				Filename.Buffer[ccb->filename->Length / sizeof(WCHAR) + (ccb->filename->Length > 2) + 2] = 0;
				filenamelen = 2;
				FNL = filenamelen * sizeof(WCHAR);
			}
		}

		if (filenamelen)
		{
			if (!buf)
			{
				Status = STATUS_BUFFER_OVERFLOW;
				goto end;
			}
			Filename.Length = filenamelen * sizeof(WCHAR);
			if (ccb->query_dir_file_count > 1 || ccb->filename->Length / sizeof(WCHAR) < 2 || !buf)
			{
				index = ccb->query_dir_index - 1;
			}
			unsigned long long CT = chtime(index, 0, 4, Vcb->vde->pdode->KMCSFS);
			unsigned long long LAT = chtime(index, 0, 0, Vcb->vde->pdode->KMCSFS);
			unsigned long long LWT = chtime(index, 0, 2, Vcb->vde->pdode->KMCSFS);
			unsigned long long filesize = get_file_size(index, Vcb->vde->pdode->KMCSFS);
			unsigned long long AS = sector_align(filesize, Vcb->vde->pdode->KMCSFS.sectorsize);
			unsigned long winattrs = chwinattrs(index, 0, Vcb->vde->pdode->KMCSFS);
			if (ccb->query_dir_file_count > 1 || ccb->filename->Length / sizeof(WCHAR) < 2 || !buf)
			{
				FNL = Filename.Length - ccb->filename->Length - (ccb->filename->Length > 2) * sizeof(WCHAR);
			}
			unsigned long RPT = 0;
			if (winattrs & FILE_ATTRIBUTE_REPARSE_POINT)
			{
				uint8_t reparsepoint[4] = {0};
				unsigned long long bytes_read = 0;
				rfcb = create_fcb(Vcb, fcb->pool_type);
				if (!rfcb)
				{
					ERR("out of memory\n");
					break;
				}
				read_file(rfcb, reparsepoint, 0, 4, index, &bytes_read, IrpSp->FileObject);
				free_fcb(rfcb);
				reap_fcb(rfcb);
				rfcb = NULL;
				if (bytes_read != 4)
				{
					ERR("read_file failed\n");
					break;
				}
				RPT = reparsepoint[0] + (reparsepoint[1] << 8) + (reparsepoint[2] << 16) + (reparsepoint[3] << 24);
			}
			unsigned long EALEN = 0;
			unsigned long EA = (winattrs & FILE_ATTRIBUTE_REPARSE_POINT) ? RPT : EALEN;

			LONG needed;

			switch (IrpSp->Parameters.QueryDirectory.FileInformationClass)
			{
			case FileBothDirectoryInformation:
			{
				FILE_BOTH_DIR_INFORMATION* fbdi = (void*)((uint8_t*)buf + Irp->IoStatus.Information);

				needed = sector_align(offsetof(FILE_BOTH_DIR_INFORMATION, FileName) + FNL, 8);
				if (len < needed)
				{
					TRACE("buffer overflow - %li > %lu\n", needed, len);
					ccb->query_dir_offset = query_dir_offset;
					ccb->query_dir_index = query_dir_index;
					Status = STATUS_BUFFER_OVERFLOW;
					goto end;
				}

				fbdi->NextEntryOffset = needed;
				fbdi->FileIndex = 0;
				fbdi->CreationTime.QuadPart = CT;
				fbdi->LastAccessTime.QuadPart = LAT;
				fbdi->LastWriteTime.QuadPart = LWT;
				fbdi->ChangeTime.QuadPart = LWT;
				fbdi->EndOfFile.QuadPart = filesize;
				fbdi->AllocationSize.QuadPart = AS;
				fbdi->FileAttributes = winattrs;
				fbdi->FileNameLength = FNL;
				fbdi->EaSize = EA;
				fbdi->ShortNameLength = 0;

				RtlCopyMemory(fbdi->FileName, Filename.Buffer + ccb->filename->Length / sizeof(WCHAR) + (ccb->filename->Length > 2), FNL);

				len -= needed;
				break;
			}
			case FileDirectoryInformation:
			{
				FILE_DIRECTORY_INFORMATION* fdi = (void*)((uint8_t*)buf + Irp->IoStatus.Information);

				needed = sector_align(offsetof(FILE_DIRECTORY_INFORMATION, FileName) + FNL, 8);
				if (len < sizeof(FILE_DIRECTORY_INFORMATION) * first + needed * !first)
				{
					TRACE("buffer overflow - %li > %lu\n", needed, len);
					ccb->query_dir_offset = query_dir_offset;
					ccb->query_dir_index = query_dir_index;
					Status = STATUS_BUFFER_OVERFLOW;
					break;
				}

				fdi->NextEntryOffset = needed;
				fdi->FileIndex = 0;
				fdi->CreationTime.QuadPart = CT;
				fdi->LastAccessTime.QuadPart = LAT;
				fdi->LastWriteTime.QuadPart = LWT;
				fdi->ChangeTime.QuadPart = LWT;
				fdi->EndOfFile.QuadPart = filesize;
				fdi->AllocationSize.QuadPart = AS;
				fdi->FileAttributes = winattrs;
				fdi->FileNameLength = FNL;

				if (len < needed)
				{
					TRACE("buffer overflow - %li > %lu\n", needed, len);
					ccb->query_dir_offset = 0;
					ccb->query_dir_index = 0;
					Status = STATUS_BUFFER_OVERFLOW;
					len -= sizeof(FILE_DIRECTORY_INFORMATION);
					break;
				}

				RtlCopyMemory(fdi->FileName, Filename.Buffer + ccb->filename->Length / sizeof(WCHAR) + (ccb->filename->Length > 2), FNL);

				len -= needed;
				break;
			}
			case FileFullDirectoryInformation:
			{
				FILE_FULL_DIR_INFORMATION* ffdi = (void*)((uint8_t*)buf + Irp->IoStatus.Information);

				needed = sector_align(offsetof(FILE_FULL_DIR_INFORMATION, FileName) + FNL, 8);
				if (len < needed)
				{
					TRACE("buffer overflow - %li > %lu\n", needed, len);
					ccb->query_dir_offset = query_dir_offset;
					ccb->query_dir_index = query_dir_index;
					Status = STATUS_BUFFER_OVERFLOW;
					goto end;
				}

				ffdi->NextEntryOffset = needed;
				ffdi->FileIndex = 0;
				ffdi->CreationTime.QuadPart = CT;
				ffdi->LastAccessTime.QuadPart = LAT;
				ffdi->LastWriteTime.QuadPart = LWT;
				ffdi->ChangeTime.QuadPart = LWT;
				ffdi->EndOfFile.QuadPart = filesize;
				ffdi->AllocationSize.QuadPart = AS;
				ffdi->FileAttributes = winattrs;
				ffdi->FileNameLength = FNL;
				ffdi->EaSize = EA;

				RtlCopyMemory(ffdi->FileName, Filename.Buffer + ccb->filename->Length / sizeof(WCHAR) + (ccb->filename->Length > 2), FNL);

				len -= needed;
				break;
			}
			case FileIdBothDirectoryInformation:
			{
				FILE_ID_BOTH_DIR_INFORMATION* fibdi = (void*)((uint8_t*)buf + Irp->IoStatus.Information);

				needed = sector_align(offsetof(FILE_ID_BOTH_DIR_INFORMATION, FileName) + FNL, 8);
				if (len < needed)
				{
					TRACE("buffer overflow - %li > %lu\n", needed, len);
					ccb->query_dir_offset = query_dir_offset;
					ccb->query_dir_index = query_dir_index;
					Status = STATUS_BUFFER_OVERFLOW;
					goto end;
				}

				fibdi->NextEntryOffset = needed;
				fibdi->FileIndex = 0;
				fibdi->CreationTime.QuadPart = CT;
				fibdi->LastAccessTime.QuadPart = LAT;
				fibdi->LastWriteTime.QuadPart = LWT;
				fibdi->ChangeTime.QuadPart = LWT;
				fibdi->EndOfFile.QuadPart = filesize;
				fibdi->AllocationSize.QuadPart = AS;
				fibdi->FileAttributes = winattrs;
				fibdi->FileNameLength = FNL;
				fibdi->EaSize = EA;
				fibdi->ShortNameLength = 0;
				fibdi->FileId.QuadPart = 0;

				RtlCopyMemory(fibdi->FileName, Filename.Buffer + ccb->filename->Length / sizeof(WCHAR) + (ccb->filename->Length > 2), FNL);

				len -= needed;
				break;
			}
#ifndef _MSC_VER
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch"
#endif
			case FileIdExtdDirectoryInformation:
			{
				FILE_ID_EXTD_DIR_INFORMATION* fiedi = (void*)((uint8_t*)buf + Irp->IoStatus.Information);

				needed = sector_align(offsetof(FILE_ID_EXTD_DIR_INFORMATION, FileName) + FNL, 8);
				if (len < needed)
				{
					TRACE("buffer overflow - %li > %lu\n", needed, len);
					ccb->query_dir_offset = query_dir_offset;
					ccb->query_dir_index = query_dir_index;
					Status = STATUS_BUFFER_OVERFLOW;
					goto end;
				}

				fiedi->NextEntryOffset = needed;
				fiedi->FileIndex = 0;
				fiedi->CreationTime.QuadPart = CT;
				fiedi->LastAccessTime.QuadPart = LAT;
				fiedi->LastWriteTime.QuadPart = LWT;
				fiedi->ChangeTime.QuadPart = LWT;
				fiedi->EndOfFile.QuadPart = filesize;
				fiedi->AllocationSize.QuadPart = AS;
				fiedi->FileAttributes = winattrs;
				fiedi->FileNameLength = FNL;
				fiedi->EaSize = EALEN;
				fiedi->ReparsePointTag = RPT;
				RtlZeroMemory(&fiedi->FileId.Identifier, 16);

				RtlCopyMemory(fiedi->FileName, Filename.Buffer + ccb->filename->Length / sizeof(WCHAR) + (ccb->filename->Length > 2), FNL);

				len -= needed;
				break;
			}
			case FileIdExtdBothDirectoryInformation:
			{
				FILE_ID_EXTD_BOTH_DIR_INFORMATION* fiebdi = (void*)((uint8_t*)buf + Irp->IoStatus.Information);

				needed = sector_align(offsetof(FILE_ID_EXTD_BOTH_DIR_INFORMATION, FileName) + FNL, 8);
				if (len < needed)
				{
					TRACE("buffer overflow - %li > %lu\n", needed, len);
					ccb->query_dir_offset = query_dir_offset;
					ccb->query_dir_index = query_dir_index;
					Status = STATUS_BUFFER_OVERFLOW;
					goto end;
				}

				fiebdi->NextEntryOffset = needed;
				fiebdi->FileIndex = 0;
				fiebdi->CreationTime.QuadPart = CT;
				fiebdi->LastAccessTime.QuadPart = LAT;
				fiebdi->LastWriteTime.QuadPart = LWT;
				fiebdi->ChangeTime.QuadPart = LWT;
				fiebdi->EndOfFile.QuadPart = filesize;
				fiebdi->AllocationSize.QuadPart = AS;
				fiebdi->FileAttributes = winattrs;
				fiebdi->FileNameLength = FNL;
				fiebdi->EaSize = EALEN;
				fiebdi->ReparsePointTag = RPT;
				RtlZeroMemory(&fiebdi->FileId.Identifier, 16);
				fiebdi->ShortNameLength = 0;

				RtlCopyMemory(fiebdi->FileName, Filename.Buffer + ccb->filename->Length / sizeof(WCHAR) + (ccb->filename->Length > 2), FNL);

				len -= needed;
				break;
			}
#ifndef _MSC_VER
#pragma GCC diagnostic pop
#endif
			case FileNamesInformation:
			{
				FILE_NAMES_INFORMATION* fni = (void*)((uint8_t*)buf + Irp->IoStatus.Information);

				needed = sector_align(offsetof(FILE_NAMES_INFORMATION, FileName) + FNL, 8);
				if (len < needed)
				{
					TRACE("buffer overflow - %li > %lu\n", needed, len);
					ccb->query_dir_offset = query_dir_offset;
					ccb->query_dir_index = query_dir_index;
					Status = STATUS_BUFFER_OVERFLOW;
					goto end;
				}

				fni->NextEntryOffset = needed;
				fni->FileIndex = 0;
				fni->FileNameLength = FNL;

				RtlCopyMemory(fni->FileName, Filename.Buffer + ccb->filename->Length / sizeof(WCHAR) + (ccb->filename->Length > 2), FNL);

				len -= needed;
				break;
			}
			default:
				WARN("unhandled file information class %u\n", IrpSp->Parameters.QueryDirectory.FileInformationClass);
				Status = STATUS_NOT_IMPLEMENTED;
				goto end;
			}

			ccb->query_dir_file_count++;
			old_offset = Irp->IoStatus.Information;
			Irp->IoStatus.Information = IrpSp->Parameters.QueryDirectory.Length - len;
			if (IrpSp->Flags & SL_RETURN_SINGLE_ENTRY)
			{
				break;
			}
			if (NT_SUCCESS(Status))
			{
				first = false;
			}
			else
			{
				break;
			}
		}
	}

	if (!Irp->IoStatus.Information)
	{
		ccb->query_dir_offset = 0;
		ccb->query_dir_index = 0;
		if (filterb && ccb->query_dir_file_count < 3)
		{
			Status = STATUS_NO_SUCH_FILE;
		}
		else
		{
			Status = STATUS_NO_MORE_FILES;
		}
		ccb->query_dir_file_count = 0;
		if (ccb->filter.Buffer)
		{
			ExFreePool(ccb->filter.Buffer);
			ccb->filter.Buffer = NULL;
			ccb->filter.Length = 0;
		}
		goto end;
	}

end:
	ExReleaseResourceLite(&fcb->nonpaged->dir_children_lock);
	ExReleaseResourceLite(&Vcb->tree_lock);

	if (Status == STATUS_BUFFER_OVERFLOW && !first)
	{
		Status = STATUS_SUCCESS;
	}

	if (Irp->IoStatus.Information)
	{
		char* tmp[4] = {0};
		RtlCopyMemory((uint8_t*)buf + old_offset, tmp, 4);
	}

	if (filename)
	{
		ExFreePool(filename);
	}

	return Status;
}

static NTSTATUS notify_change_directory(device_extension* Vcb, PIRP Irp)
{
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	PFILE_OBJECT FileObject = IrpSp->FileObject;
	fcb* fcb = FileObject->FsContext;
	ccb* ccb = FileObject->FsContext2;
	NTSTATUS Status;

	TRACE("IRP_MN_NOTIFY_CHANGE_DIRECTORY\n");

	if (!ccb)
	{
		ERR("ccb was NULL\n");
		return STATUS_INVALID_PARAMETER;
	}

	if (Irp->RequestorMode == UserMode && !(ccb->access & FILE_LIST_DIRECTORY))
	{
		WARN("insufficient privileges\n");
		return STATUS_ACCESS_DENIED;
	}

	ExAcquireResourceSharedLite(&fcb->Vcb->tree_lock, true);
	ExAcquireResourceExclusiveLite(fcb->Header.Resource, true);

	unsigned long long index = get_filename_index(*ccb->filename, &Vcb->vde->pdode->KMCSFS);
	if (!(chwinattrs(index, 0, Vcb->vde->pdode->KMCSFS) & FILE_ATTRIBUTE_DIRECTORY))
	{
		Status = STATUS_INVALID_PARAMETER;
		goto end;
	}

	// FIXME - raise exception if FCB marked for deletion?

	TRACE("FileObject %p\n", FileObject);

	FsRtlNotifyFilterChangeDirectory(Vcb->NotifySync, &Vcb->DirNotifyList, FileObject->FsContext2, (PSTRING)ccb->filename, IrpSp->Flags & SL_WATCH_TREE, false, IrpSp->Parameters.NotifyDirectory.CompletionFilter, Irp, NULL, NULL, NULL);

	Status = STATUS_PENDING;

end:
	ExReleaseResourceLite(fcb->Header.Resource);
	ExReleaseResourceLite(&fcb->Vcb->tree_lock);

	return Status;
}

_Dispatch_type_(IRP_MJ_DIRECTORY_CONTROL)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS __stdcall DirectoryControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	PIO_STACK_LOCATION IrpSp;
	NTSTATUS Status;
	ULONG func;
	bool top_level;
	device_extension* Vcb = DeviceObject->DeviceExtension;

	FsRtlEnterFileSystem();
	ExAcquireResourceSharedLite(&op_lock, true);

	TRACE("directory control\n");

	top_level = is_top_level(Irp);

	if (Vcb && Vcb->type == VCB_TYPE_VOLUME)
	{
		Status = STATUS_INVALID_DEVICE_REQUEST;
		goto end;
	}
	else if (!Vcb || Vcb->type != VCB_TYPE_FS)
	{
		Status = STATUS_INVALID_PARAMETER;
		goto end;
	}

	IrpSp = IoGetCurrentIrpStackLocation(Irp);

	Irp->IoStatus.Information = 0;

	func = IrpSp->MinorFunction;

	switch (func)
	{
	case IRP_MN_NOTIFY_CHANGE_DIRECTORY:
		Status = notify_change_directory(Vcb, Irp);
		break;

	case IRP_MN_QUERY_DIRECTORY:
		Status = query_directory(Irp);
		break;

	default:
		WARN("unknown minor %lu\n", func);
		Status = STATUS_NOT_IMPLEMENTED;
		Irp->IoStatus.Status = Status;
		break;
	}

	if (Status == STATUS_PENDING)
	{
		goto exit;
	}

end:
	Irp->IoStatus.Status = Status;

	IoCompleteRequest(Irp, IO_DISK_INCREMENT);

exit:
	TRACE("returning %08lx\n", Status);

	if (top_level)
	{
		IoSetTopLevelIrp(NULL);
	}

	ExReleaseResourceLite(&op_lock);
	FsRtlExitFileSystem();

	return Status;
}
