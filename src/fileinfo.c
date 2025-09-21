// Copyright (c) Anthony Kerr 2024-

#include "KMCSpaceFS_drv.h"

// not currently in mingw - introduced with Windows 10
#ifndef _MSC_VER
#define FileIdInformation (enum _FILE_INFORMATION_CLASS)59
#define FileHardLinkFullIdInformation (enum _FILE_INFORMATION_CLASS)62
#define FileDispositionInformationEx (enum _FILE_INFORMATION_CLASS)64
#define FileRenameInformationEx (enum _FILE_INFORMATION_CLASS)65
#define FileStatInformation (enum _FILE_INFORMATION_CLASS)68
#define FileStatLxInformation (enum _FILE_INFORMATION_CLASS)70
#define FileCaseSensitiveInformation (enum _FILE_INFORMATION_CLASS)71
#define FileLinkInformationEx (enum _FILE_INFORMATION_CLASS)72
#define FileStorageReserveIdInformation (enum _FILE_INFORMATION_CLASS)74

typedef struct _FILE_ID_INFORMATION
{
	ULONGLONG VolumeSerialNumber;
	FILE_ID_128 FileId;
} FILE_ID_INFORMATION, *PFILE_ID_INFORMATION;

typedef struct _FILE_STAT_INFORMATION
{
	LARGE_INTEGER FileId;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG FileAttributes;
	ULONG ReparseTag;
	ULONG NumberOfLinks;
	ACCESS_MASK EffectiveAccess;
} FILE_STAT_INFORMATION, *PFILE_STAT_INFORMATION;

typedef struct _FILE_STAT_LX_INFORMATION
{
	LARGE_INTEGER FileId;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG         FileAttributes;
	ULONG         ReparseTag;
	ULONG         NumberOfLinks;
	ACCESS_MASK   EffectiveAccess;
	ULONG         LxFlags;
	ULONG         LxUid;
	ULONG         LxGid;
	ULONG         LxMode;
	ULONG         LxDeviceIdMajor;
	ULONG         LxDeviceIdMinor;
} FILE_STAT_LX_INFORMATION, *PFILE_STAT_LX_INFORMATION;

#define LX_FILE_METADATA_HAS_UID        0x01
#define LX_FILE_METADATA_HAS_GID        0x02
#define LX_FILE_METADATA_HAS_MODE       0x04
#define LX_FILE_METADATA_HAS_DEVICE_ID  0x08
#define LX_FILE_CASE_SENSITIVE_DIR      0x10

typedef struct _FILE_RENAME_INFORMATION_EX
{
	union
	{
		BOOLEAN ReplaceIfExists;
		ULONG Flags;
	};
	HANDLE RootDirectory;
	ULONG FileNameLength;
	WCHAR FileName[1];
} FILE_RENAME_INFORMATION_EX, *PFILE_RENAME_INFORMATION_EX;

typedef struct _FILE_DISPOSITION_INFORMATION_EX
{
	ULONG Flags;
} FILE_DISPOSITION_INFORMATION_EX, *PFILE_DISPOSITION_INFORMATION_EX;

typedef struct _FILE_LINK_INFORMATION_EX
{
	union
	{
		BOOLEAN ReplaceIfExists;
		ULONG Flags;
	};
	HANDLE RootDirectory;
	ULONG FileNameLength;
	WCHAR FileName[1];
} FILE_LINK_INFORMATION_EX, *PFILE_LINK_INFORMATION_EX;

typedef struct _FILE_CASE_SENSITIVE_INFORMATION
{
	ULONG Flags;
} FILE_CASE_SENSITIVE_INFORMATION, *PFILE_CASE_SENSITIVE_INFORMATION;

typedef struct _FILE_LINK_ENTRY_FULL_ID_INFORMATION
{
	ULONG NextEntryOffset;
	FILE_ID_128 ParentFileId;
	ULONG FileNameLength;
	WCHAR FileName[1];
} FILE_LINK_ENTRY_FULL_ID_INFORMATION, *PFILE_LINK_ENTRY_FULL_ID_INFORMATION;

typedef struct _FILE_LINKS_FULL_ID_INFORMATION
{
	ULONG BytesNeeded;
	ULONG EntriesReturned;
	FILE_LINK_ENTRY_FULL_ID_INFORMATION Entry;
} FILE_LINKS_FULL_ID_INFORMATION, *PFILE_LINKS_FULL_ID_INFORMATION;

#define FILE_RENAME_REPLACE_IF_EXISTS                       0x001
#define FILE_RENAME_POSIX_SEMANTICS                         0x002
#define FILE_RENAME_SUPPRESS_PIN_STATE_INHERITANCE          0x004
#define FILE_RENAME_SUPPRESS_STORAGE_RESERVE_INHERITANCE    0x008
#define FILE_RENAME_NO_INCREASE_AVAILABLE_SPACE             0x010
#define FILE_RENAME_NO_DECREASE_AVAILABLE_SPACE             0x020
#define FILE_RENAME_IGNORE_READONLY_ATTRIBUTE               0x040
#define FILE_RENAME_FORCE_RESIZE_TARGET_SR                  0x080
#define FILE_RENAME_FORCE_RESIZE_SOURCE_SR                  0x100

#define FILE_DISPOSITION_DELETE                         0x1
#define FILE_DISPOSITION_POSIX_SEMANTICS                0x2
#define FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK      0x4
#define FILE_DISPOSITION_ON_CLOSE                       0x8

#define FILE_LINK_REPLACE_IF_EXISTS                       0x001
#define FILE_LINK_POSIX_SEMANTICS                         0x002
#define FILE_LINK_SUPPRESS_STORAGE_RESERVE_INHERITANCE    0x008
#define FILE_LINK_NO_INCREASE_AVAILABLE_SPACE             0x010
#define FILE_LINK_NO_DECREASE_AVAILABLE_SPACE             0x020
#define FILE_LINK_IGNORE_READONLY_ATTRIBUTE               0x040
#define FILE_LINK_FORCE_RESIZE_TARGET_SR                  0x080
#define FILE_LINK_FORCE_RESIZE_SOURCE_SR                  0x100

#else

#define FILE_RENAME_INFORMATION_EX FILE_RENAME_INFORMATION
#define FILE_LINK_INFORMATION_EX FILE_LINK_INFORMATION

#endif

#define FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE 0x00000010

static NTSTATUS set_basic_information(device_extension* Vcb, PIRP Irp, PFILE_OBJECT FileObject)
{
	FILE_BASIC_INFORMATION* fbi = Irp->AssociatedIrp.SystemBuffer;
	fcb* fcb = FileObject->FsContext;
	ccb* ccb = FileObject->FsContext2;
	NTSTATUS Status;

	if (!ccb)
	{
		ERR("ccb was NULL\n");
		return STATUS_INVALID_PARAMETER;
	}

	TRACE("file = %p, attributes = %lx\n", FileObject, fbi->FileAttributes);

	ExAcquireResourceExclusiveLite(fcb->Header.Resource, true);

	if (fbi->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
	{
		WARN("attempted to set FILE_ATTRIBUTE_DIRECTORY on non-directory\n");
		Status = STATUS_INVALID_PARAMETER;
		goto end;
	}

	unsigned long long index = get_filename_index(*ccb->filename, &Vcb->vde->pdode->KMCSFS);

	UNICODE_STRING nostream_fn;
	nostream_fn.Buffer = ccb->filename->Buffer;
	nostream_fn.Length = 0;
	for (unsigned long i = 0; i < ccb->filename->Length / sizeof(WCHAR); i++)
	{
		if (ccb->filename->Buffer[i] == *L":")
		{
			nostream_fn.Length = i * sizeof(WCHAR);
			break;
		}
	}
	unsigned long long nostream_index = get_filename_index(nostream_fn, &fcb->Vcb->vde->pdode->KMCSFS);
	if (!nostream_index)
	{
		nostream_index = index;
	}

	// times of -2 are some sort of undocumented behaviour to do with LXSS

	if (fbi->CreationTime.QuadPart == -2)
	{
		fbi->CreationTime.QuadPart = 0;
	}

	if (fbi->LastAccessTime.QuadPart == -2)
	{
		fbi->LastAccessTime.QuadPart = 0;
	}

	if (fbi->LastWriteTime.QuadPart == -2)
	{
		fbi->LastWriteTime.QuadPart = 0;
	}

	if (fbi->ChangeTime.QuadPart == -2)
	{
		fbi->ChangeTime.QuadPart = 0;
	}

	ULONG NotifyFilter = 0;

	if (fbi->CreationTime.QuadPart != 0)
	{
		chtime(nostream_index, fbi->CreationTime.QuadPart, 5, Vcb->vde->pdode->KMCSFS);
		NotifyFilter |= FILE_NOTIFY_CHANGE_CREATION;
	}

	if (fbi->LastAccessTime.QuadPart != 0)
	{
		chtime(nostream_index, fbi->LastAccessTime.QuadPart, 1, Vcb->vde->pdode->KMCSFS);
		NotifyFilter |= FILE_NOTIFY_CHANGE_LAST_ACCESS;
	}

	if (fbi->LastWriteTime.QuadPart != 0)
	{
		chtime(nostream_index, fbi->LastWriteTime.QuadPart, 3, Vcb->vde->pdode->KMCSFS);
		NotifyFilter |= FILE_NOTIFY_CHANGE_LAST_WRITE;
	}

	// FileAttributes == 0 means don't set - undocumented, but seen in fastfat
	if (fbi->FileAttributes != 0)
	{
		unsigned long winattrs = chwinattrs(nostream_index, 0, Vcb->vde->pdode->KMCSFS);
		if (winattrs & FILE_ATTRIBUTE_DIRECTORY)
		{
			fbi->FileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
		}
		if (winattrs & FILE_ATTRIBUTE_REPARSE_POINT)
		{
			fbi->FileAttributes |= FILE_ATTRIBUTE_REPARSE_POINT;
		}
		chwinattrs(nostream_index, fbi->FileAttributes, Vcb->vde->pdode->KMCSFS);
		NotifyFilter |= FILE_NOTIFY_CHANGE_ATTRIBUTES;
	}

	Status = STATUS_SUCCESS;

	unsigned long lastslash = 0;
	for (unsigned long i = 0; i < ccb->filename->Length / sizeof(WCHAR); i++)
	{
		if (ccb->filename->Buffer[i] == *L"/" || ccb->filename->Buffer[i] == *L"\\")
		{
			lastslash = i;
		}
		if (i - lastslash > MAX_PATH - 5)
		{
			ERR("file name too long\n");
		}
	}
	FsRtlNotifyFullReportChange(Vcb->NotifySync, &Vcb->DirNotifyList, (PSTRING)ccb->filename, (lastslash + 1) * sizeof(WCHAR), NULL, NULL, NotifyFilter, FILE_ACTION_MODIFIED, NULL);

end:
	ExReleaseResourceLite(fcb->Header.Resource);

	return Status;
}

static NTSTATUS set_disposition_information(device_extension* Vcb, PIRP Irp, PFILE_OBJECT FileObject, bool ex)
{
	fcb* fcb = FileObject->FsContext;
	ccb* ccb = FileObject->FsContext2;
	ULONG flags;
	NTSTATUS Status;

	if (ex)
	{
		FILE_DISPOSITION_INFORMATION_EX* fdi = Irp->AssociatedIrp.SystemBuffer;

		flags = fdi->Flags;
	}
	else
	{
		FILE_DISPOSITION_INFORMATION* fdi = Irp->AssociatedIrp.SystemBuffer;

		flags = fdi->DeleteFile ? FILE_DISPOSITION_DELETE : 0;
	}

	ExAcquireResourceExclusiveLite(fcb->Header.Resource, true);

	TRACE("changing delete_on_close to %s for fcb %p\n", flags & FILE_DISPOSITION_DELETE ? "true" : "false", fcb);

	unsigned long winattrs = chwinattrs(get_filename_index(*ccb->filename, &Vcb->vde->pdode->KMCSFS), 0, Vcb->vde->pdode->KMCSFS);

	TRACE("atts = %lx\n", winattrs);

	if (winattrs & FILE_ATTRIBUTE_READONLY && !(flags & FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE))
	{
		TRACE("not allowing readonly file to be deleted\n");
		Status = STATUS_CANNOT_DELETE;
		goto end;
	}

	if (winattrs & FILE_ATTRIBUTE_DIRECTORY)
	{
		PIRP Irp2 = IoAllocateIrp(FileObject->DeviceObject->StackSize, false);
		if (!Irp2)
		{
			ERR("out of memory\n");
			Status = STATUS_INSUFFICIENT_RESOURCES;
			goto end;
		}
		Irp2->MdlAddress = NULL;
		PIO_STACK_LOCATION IrpSp2 = IoGetCurrentIrpStackLocation(Irp2);
		IrpSp2->FileObject = FileObject;
		IrpSp2->Parameters.QueryDirectory.FileInformationClass = FileNamesInformation;
		IrpSp2->Parameters.QueryDirectory.Length = 0;
		IrpSp2->Parameters.QueryDirectory.FileName = NULL;
		unsigned long long backupdirindex = ccb->query_dir_index;
		unsigned long long backupdiroffset = ccb->query_dir_offset;
		unsigned long long backupfilecount = ccb->query_dir_file_count;
		ccb->query_dir_index = 0;
		ccb->query_dir_offset = 0;
		ccb->query_dir_file_count = 0;
		if (query_directory(Irp2) == STATUS_BUFFER_OVERFLOW)
		{
			TRACE("directory not empty\n");
			Status = STATUS_DIRECTORY_NOT_EMPTY;
			ccb->query_dir_index = backupdirindex;
			ccb->query_dir_offset = backupdiroffset;
			ccb->query_dir_file_count = backupfilecount;
			IoFreeIrp(Irp2);
			goto end;
		}
		ccb->query_dir_index = backupdirindex;
		ccb->query_dir_offset = backupdiroffset;
		ccb->query_dir_file_count = backupfilecount;
		IoFreeIrp(Irp2);
	}

	if (!MmFlushImageSection(&fcb->nonpaged->segment_object, MmFlushForDelete))
	{
		TRACE("trying to delete file which is being mapped as an image\n");
		Status = STATUS_CANNOT_DELETE;
		goto end;
	}

	FileObject->DeletePending = flags & FILE_DISPOSITION_DELETE;
	ccb->delete_on_close = flags & FILE_DISPOSITION_DELETE;

	unsigned long long dindex = FindDictEntry(Vcb->vde->pdode->KMCSFS.dict, Vcb->vde->pdode->KMCSFS.table, Vcb->vde->pdode->KMCSFS.tableend, Vcb->vde->pdode->KMCSFS.DictSize, ccb->filename->Buffer, ccb->filename->Length / sizeof(WCHAR));
	if (dindex)
	{
		Vcb->vde->pdode->KMCSFS.dict[dindex].flags &= ~delete_pending;
		Vcb->vde->pdode->KMCSFS.dict[dindex].flags |= flags & FILE_DISPOSITION_DELETE;
	}

	Status = STATUS_SUCCESS;

end:
	ExReleaseResourceLite(fcb->Header.Resource);

	// send notification that directory is about to be deleted
	if (NT_SUCCESS(Status) && flags & FILE_DISPOSITION_DELETE && winattrs & FILE_ATTRIBUTE_DIRECTORY)
	{
		FsRtlNotifyFullChangeDirectory(Vcb->NotifySync, &Vcb->DirNotifyList, FileObject->FsContext, NULL, false, false, 0, NULL, NULL, NULL);
	}

	return Status;
}

static NTSTATUS set_end_of_file_information(device_extension* Vcb, PIRP Irp, PFILE_OBJECT FileObject, bool advance_only, bool prealloc)
{
	FILE_END_OF_FILE_INFORMATION* feofi = Irp->AssociatedIrp.SystemBuffer;
	unsigned long long index = get_filename_index(*((ccb*)FileObject->FsContext2)->filename, &Vcb->vde->pdode->KMCSFS);
	unsigned long long filesize = get_file_size(index, Vcb->vde->pdode->KMCSFS);
	if (advance_only)
	{
		return STATUS_SUCCESS;
	}
	if (feofi->EndOfFile.QuadPart > filesize)
	{
		if (!find_block(&Vcb->vde->pdode->KMCSFS, index, feofi->EndOfFile.QuadPart - filesize, FileObject))
		{
			return STATUS_DISK_FULL;
		}
	}
	else if (feofi->EndOfFile.QuadPart < filesize)
	{
		dealloc(&Vcb->vde->pdode->KMCSFS, index, filesize, feofi->EndOfFile.QuadPart);
	}

	unsigned long lastslash = 0;
	for (unsigned long i = 0; i < ((ccb*)FileObject->FsContext2)->filename->Length / sizeof(WCHAR); i++)
	{
		if (((ccb*)FileObject->FsContext2)->filename->Buffer[i] == *L"/" || ((ccb*)FileObject->FsContext2)->filename->Buffer[i] == *L"\\")
		{
			lastslash = i;
		}
		if (i - lastslash > MAX_PATH - 5)
		{
			ERR("file name too long\n");
		}
	}
	FsRtlNotifyFullReportChange(Vcb->NotifySync, &Vcb->DirNotifyList, (PSTRING)&((ccb*)FileObject->FsContext2)->filename, (lastslash + 1) * sizeof(WCHAR), NULL, NULL, FILE_NOTIFY_CHANGE_SIZE, FILE_ACTION_MODIFIED, NULL);

	return STATUS_SUCCESS;
}

static NTSTATUS set_position_information(PFILE_OBJECT FileObject, PIRP Irp)
{
	FILE_POSITION_INFORMATION* fpi = (FILE_POSITION_INFORMATION*)Irp->AssociatedIrp.SystemBuffer;

	TRACE("setting the position on %p to %I64x\n", FileObject, fpi->CurrentByteOffset.QuadPart);

	// FIXME - make sure aligned for FO_NO_INTERMEDIATE_BUFFERING

	FileObject->CurrentByteOffset = fpi->CurrentByteOffset;

	return STATUS_SUCCESS;
}

static NTSTATUS set_rename_information(device_extension* Vcb, PIRP Irp, PFILE_OBJECT FileObject, PFILE_OBJECT tfo, bool ex)
{
	FILE_RENAME_INFORMATION_EX* fri = Irp->AssociatedIrp.SystemBuffer;
	fcb* fcb = FileObject->FsContext;
	ccb* ccb = FileObject->FsContext2;
	unsigned long long dindex = 0;
	bool freenfilename = false;
	UNICODE_STRING NFileName;
	IO_STATUS_BLOCK iosb;
	NTSTATUS Status;
	ULONG flags;
	
	if (ex)
	{
		flags = fri->Flags;
	}
	else
	{
		flags = fri->ReplaceIfExists ? FILE_RENAME_REPLACE_IF_EXISTS : 0;
	}

	TRACE("tfo = %p\n", tfo);
	TRACE("Flags = %lx\n", flags);
	TRACE("RootDirectory = %p\n", fri->RootDirectory);

	if (!tfo)
	{
		freenfilename = true;
		unsigned long lastslash = 0;
		for (unsigned long i = 0; i < ccb->filename->Length / sizeof(WCHAR); i++)
		{
			if (ccb->filename->Buffer[i] == *L"/" || ccb->filename->Buffer[i] == *L"\\")
			{
				lastslash = i;
			}
			if (i - lastslash > MAX_PATH - 5)
			{
				ERR("file name too long\n");
			}
		}
		NFileName.Length = (lastslash + 1) * sizeof(WCHAR) + fri->FileNameLength;
		NFileName.Buffer = ExAllocatePoolWithTag(NonPagedPoolNx, NFileName.Length, ALLOC_TAG);
		if (!NFileName.Buffer)
		{
			ERR("out of memory\n");
			Status = STATUS_INSUFFICIENT_RESOURCES;
			goto exit;
		}
		RtlCopyMemory(NFileName.Buffer, ccb->filename->Buffer, (lastslash + 1) * sizeof(WCHAR));
		RtlCopyMemory(NFileName.Buffer + lastslash + 1, fri->FileName, fri->FileNameLength);
	}
	else
	{
		NFileName = tfo->FileName;
	}

	UNICODE_STRING newccbfn;
	newccbfn.Buffer = ExAllocatePoolWithTag(NonPagedPoolNx, NFileName.Length, ALLOC_TAG);
	if (!newccbfn.Buffer)
	{
		ERR("out of memory\n");
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto exit;
	}
	RtlCopyMemory(newccbfn.Buffer, NFileName.Buffer, NFileName.Length);
	newccbfn.Length = NFileName.Length;

	TRACE("New FileName = %.*S\n", (int)(NFileName.Length / sizeof(WCHAR)), NFileName.Buffer);
	TRACE("Old FileName = %.*S\n", (int)(ccb->filename->Length / sizeof(WCHAR)), ccb->filename->Buffer);

	if (ccb->filename->Length == NFileName.Length)
	{
		bool same = true;
		for (unsigned long long i = 0; i < ccb->filename->Length / sizeof(WCHAR); i++)
		{
			if (!incmp(ccb->filename->Buffer[i], NFileName.Buffer[i]))
			{
				same = false;
				break;
			}
		}
		if (same)
		{
			TRACE("file names are the same, not renaming\n");
			Status = STATUS_SUCCESS;
			goto exit;
		}
	}

	unsigned long long tfo_index = get_filename_index(NFileName, &Vcb->vde->pdode->KMCSFS);
	if (tfo_index)
	{
		unsigned long winattrs = chwinattrs(tfo_index, 0, Vcb->vde->pdode->KMCSFS);
		if (winattrs & FILE_ATTRIBUTE_DIRECTORY)
		{
			Status = STATUS_ACCESS_DENIED;
			goto exit;
		}
		if (!(flags & FILE_RENAME_REPLACE_IF_EXISTS))
		{
			Status = STATUS_OBJECT_NAME_COLLISION;
			goto exit;
		}
		dindex = FindDictEntry(Vcb->vde->pdode->KMCSFS.dict, Vcb->vde->pdode->KMCSFS.table, Vcb->vde->pdode->KMCSFS.tableend, Vcb->vde->pdode->KMCSFS.DictSize, NFileName.Buffer, NFileName.Length / sizeof(WCHAR));
		if (dindex)
		{
			if (Vcb->vde->pdode->KMCSFS.dict[dindex].opencount)
			{
				Status = STATUS_ACCESS_DENIED;
				goto exit;
			}
		}
		delete_file(&Vcb->vde->pdode->KMCSFS, NFileName, tfo_index, FileObject);
		UNICODE_STRING stfo;
		stfo.Buffer = NFileName.Buffer + 1;
		stfo.Length = NFileName.Length - sizeof(WCHAR);
		unsigned long long stfo_index = get_filename_index(stfo, &Vcb->vde->pdode->KMCSFS);
		if (stfo_index)
		{
			delete_file(&Vcb->vde->pdode->KMCSFS, stfo, stfo_index, FileObject);
		}
	}

	unsigned long winattrs = chwinattrs(get_filename_index(*ccb->filename, &Vcb->vde->pdode->KMCSFS), 0, Vcb->vde->pdode->KMCSFS);
	if (winattrs & FILE_ATTRIBUTE_DIRECTORY)
	{
		WCHAR* filename = ExAllocatePoolWithTag(NonPagedPoolNx, 65536 * sizeof(WCHAR), ALLOC_TAG);
		if (!filename)
		{
			ERR("out of memory\n");
			Status = STATUS_INSUFFICIENT_RESOURCES;
			goto exit;
		}
		WCHAR* newfilename = ExAllocatePoolWithTag(NonPagedPoolNx, 65536 * sizeof(WCHAR), ALLOC_TAG);
		if (!newfilename)
		{
			ERR("out of memory\n");
			ExFreePool(filename);
			Status = STATUS_INSUFFICIENT_RESOURCES;
			goto exit;
		}
		unsigned long long filenamelen = 0;
		UNICODE_STRING Filename;
		Filename.Buffer = filename;
		for (unsigned long long offset = 0; offset < Vcb->vde->pdode->KMCSFS.filenamesend - Vcb->vde->pdode->KMCSFS.tableend + 1; offset++)
		{
			if ((Vcb->vde->pdode->KMCSFS.table[Vcb->vde->pdode->KMCSFS.tableend + offset] & 0xff) == 255 || (Vcb->vde->pdode->KMCSFS.table[Vcb->vde->pdode->KMCSFS.tableend + offset] & 0xff) == 42) // 255 = file, 42 = fuse symlink
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
					if (isin)
					{
						Filename.Length = filenamelen * sizeof(WCHAR);
						dindex = FindDictEntry(Vcb->vde->pdode->KMCSFS.dict, Vcb->vde->pdode->KMCSFS.table, Vcb->vde->pdode->KMCSFS.tableend, Vcb->vde->pdode->KMCSFS.DictSize, Filename.Buffer, Filename.Length / sizeof(WCHAR));
						if (dindex)
						{
							if (Vcb->vde->pdode->KMCSFS.dict[dindex].opencount)
							{
								ExFreePool(filename);
								ExFreePool(newfilename);
								Status = STATUS_ACCESS_DENIED;
								goto exit;
							}
							if (Vcb->vde->pdode->KMCSFS.dict[dindex].fcb)
							{
								CcFlushCache(&Vcb->vde->pdode->KMCSFS.dict[dindex].fcb->nonpaged->segment_object, NULL, 0, &iosb);
							}
						}
					}
				}
				filenamelen = 0;
			}
			else
			{
				filename[filenamelen] = Vcb->vde->pdode->KMCSFS.table[Vcb->vde->pdode->KMCSFS.tableend + offset] & 0xff;
				filenamelen++;
			}
		}
		dindex = FindDictEntry(Vcb->vde->pdode->KMCSFS.dict, Vcb->vde->pdode->KMCSFS.table, Vcb->vde->pdode->KMCSFS.tableend, Vcb->vde->pdode->KMCSFS.DictSize, ccb->filename->Buffer, ccb->filename->Length / sizeof(WCHAR));
		if (dindex)
		{
			if (Vcb->vde->pdode->KMCSFS.dict[dindex].fcb)
			{
				CcFlushCache(&Vcb->vde->pdode->KMCSFS.dict[dindex].fcb->nonpaged->segment_object, NULL, 0, &iosb);
			}
		}
		filenamelen = 0;
		UNICODE_STRING NewFilename;
		NewFilename.Buffer = newfilename;
		for (unsigned long long offset = 0; offset < Vcb->vde->pdode->KMCSFS.filenamesend - Vcb->vde->pdode->KMCSFS.tableend + 1; offset++)
		{
			if ((Vcb->vde->pdode->KMCSFS.table[Vcb->vde->pdode->KMCSFS.tableend + offset] & 0xff) == 255 || (Vcb->vde->pdode->KMCSFS.table[Vcb->vde->pdode->KMCSFS.tableend + offset] & 0xff) == 42) // 255 = file, 42 = fuse symlink
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
					if (!(filename[i] == *L":") && !(filename[i] == *L"/") && !(filename[i] == *L"\\") && (ccb->filename->Length > 2))
					{
						isin = false;
					}
					i++;
					if (isin)
					{
						Filename.Length = filenamelen * sizeof(WCHAR);
						unsigned long long j = 0;
						for (; j < NFileName.Length / sizeof(WCHAR); j++)
						{
							newfilename[j] = NFileName.Buffer[j];
						}
						if (filename[i - 1] == *L":")
						{
							newfilename[j] = 58;
						}
						else
						{
							newfilename[j] = 92;
						}
						j++;
						for (; i < filenamelen; i++)
						{
							newfilename[j] = filename[i];
							j++;
						}
						NewFilename.Length = j * sizeof(WCHAR);
						rename_file(&Vcb->vde->pdode->KMCSFS, Filename, NewFilename, FileObject);
						UNICODE_STRING SFilename;
						SFilename.Buffer = Filename.Buffer + 1;
						SFilename.Length = Filename.Length - sizeof(WCHAR);
						UNICODE_STRING SNewFilename;
						SNewFilename.Buffer = NewFilename.Buffer + 1;
						SNewFilename.Length = NewFilename.Length - sizeof(WCHAR);
						unsigned long long sindex = get_filename_index(SFilename, &Vcb->vde->pdode->KMCSFS);
						if (sindex)
						{
							rename_file(&Vcb->vde->pdode->KMCSFS, SFilename, SNewFilename, FileObject);
						}
						offset += j;
						offset -= filenamelen;
					}
				}
				filenamelen = 0;
			}
			else
			{
				filename[filenamelen] = Vcb->vde->pdode->KMCSFS.table[Vcb->vde->pdode->KMCSFS.tableend + offset] & 0xff;
				filenamelen++;
			}
		}
		ExFreePool(filename);
		ExFreePool(newfilename);
	}

	unsigned long lastslash = 0;
	for (unsigned long i = 0; i < ccb->filename->Length / sizeof(WCHAR); i++)
	{
		if (ccb->filename->Buffer[i] == *L"/" || ccb->filename->Buffer[i] == *L"\\")
		{
			lastslash = i;
		}
		if (i - lastslash > MAX_PATH - 5)
		{
			ERR("file name too long\n");
		}
	}
	FsRtlNotifyFullReportChange(Vcb->NotifySync, &Vcb->DirNotifyList, (PSTRING)ccb->filename, (lastslash + 1) * sizeof(WCHAR), NULL, NULL, (ccb->options & FILE_DIRECTORY_FILE) ? FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME, FILE_ACTION_RENAMED_OLD_NAME, NULL);

	Status = rename_file(&Vcb->vde->pdode->KMCSFS, *ccb->filename, NFileName, FileObject);

	UNICODE_STRING sfn;
	sfn.Buffer = ccb->filename->Buffer + 1;
	sfn.Length = ccb->filename->Length - sizeof(WCHAR);

	UNICODE_STRING nsfn;
	nsfn.Buffer = NFileName.Buffer + 1;
	nsfn.Length = NFileName.Length - sizeof(WCHAR);

	if (NT_SUCCESS(Status))
	{
		Status = rename_file(&Vcb->vde->pdode->KMCSFS, sfn, nsfn, FileObject);
	}

	if (NT_SUCCESS(Status))
	{
		ExFreePool(ccb->filename->Buffer);
		ccb->filename->Buffer = newccbfn.Buffer;
		ccb->filename->Length = newccbfn.Length;
	}

	lastslash = 0;
	for (unsigned long i = 0; i < NFileName.Length / sizeof(WCHAR); i++)
	{
		if (NFileName.Buffer[i] == *L"/" || NFileName.Buffer[i] == *L"\\")
		{
			lastslash = i;
		}
		if (i - lastslash > MAX_PATH - 5)
		{
			ERR("file name too long\n");
		}
	}
	FsRtlNotifyFullReportChange(Vcb->NotifySync, &Vcb->DirNotifyList, (PSTRING)&NFileName, (lastslash + 1) * sizeof(WCHAR), NULL, NULL, (ccb->options & FILE_DIRECTORY_FILE) ? FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME, FILE_ACTION_RENAMED_NEW_NAME, NULL);

exit:
	if (NFileName.Buffer && freenfilename)
	{
		ExFreePool(NFileName.Buffer);
	}
	if (!NT_SUCCESS(Status))
	{
		if (newccbfn.Buffer)
		{
			ExFreePool(newccbfn.Buffer);
		}
	}
	return Status;
}

_Dispatch_type_(IRP_MJ_SET_INFORMATION)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS __stdcall SetInformation(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS Status;
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	device_extension* Vcb = DeviceObject->DeviceExtension;
	fcb* fcb = IrpSp->FileObject->FsContext;
	ccb* ccb = IrpSp->FileObject->FsContext2;
	bool top_level;

	FsRtlEnterFileSystem();
	ExAcquireResourceExclusiveLite(&op_lock, true);

	top_level = is_top_level(Irp);

	Irp->IoStatus.Information = 0;

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

	if (!(Vcb->Vpb->Flags & VPB_MOUNTED))
	{
		Status = STATUS_ACCESS_DENIED;
		goto end;
	}

	if (Vcb->readonly && IrpSp->Parameters.SetFile.FileInformationClass != FilePositionInformation)
	{
		Status = STATUS_MEDIA_WRITE_PROTECTED;
		goto end;
	}

	if (!fcb)
	{
		ERR("no fcb\n");
		Status = STATUS_INVALID_PARAMETER;
		goto end;
	}

	if (!ccb)
	{
		ERR("no ccb\n");
		Status = STATUS_INVALID_PARAMETER;
		goto end;
	}

	Status = STATUS_NOT_IMPLEMENTED;

	TRACE("set information\n");

	switch (IrpSp->Parameters.SetFile.FileInformationClass)
	{
	case FileAllocationInformation:
	{
		TRACE("FileAllocationInformation\n");

		if (Irp->RequestorMode == UserMode && !(ccb->access & FILE_WRITE_DATA))
		{
			WARN("insufficient privileges\n");
			Status = STATUS_ACCESS_DENIED;
			break;
		}

		Status = set_end_of_file_information(Vcb, Irp, IrpSp->FileObject, false, true);
		break;
	}

	case FileBasicInformation:
	{
		TRACE("FileBasicInformation\n");

		if (Irp->RequestorMode == UserMode && !(ccb->access & FILE_WRITE_ATTRIBUTES))
		{
			WARN("insufficient privileges\n");
			Status = STATUS_ACCESS_DENIED;
			break;
		}

		Status = set_basic_information(Vcb, Irp, IrpSp->FileObject);

		break;
	}

	case FileDispositionInformation:
	{
		TRACE("FileDispositionInformation\n");

		if (Irp->RequestorMode == UserMode && !(ccb->access & DELETE))
		{
			WARN("insufficient privileges\n");
			Status = STATUS_ACCESS_DENIED;
			break;
		}

		Status = set_disposition_information(Vcb, Irp, IrpSp->FileObject, false);

		break;
	}

	case FileEndOfFileInformation:
	{
		TRACE("FileEndOfFileInformation\n");

		if (Irp->RequestorMode == UserMode && !(ccb->access & (FILE_WRITE_DATA | FILE_APPEND_DATA)))
		{
			WARN("insufficient privileges\n");
			Status = STATUS_ACCESS_DENIED;
			break;
		}

		Status = set_end_of_file_information(Vcb, Irp, IrpSp->FileObject, IrpSp->Parameters.SetFile.AdvanceOnly, false);

		break;
	}

	case FileLinkInformation:
		TRACE("FileLinkInformation\n");
		//Status = set_link_information(Vcb, Irp, IrpSp->FileObject, IrpSp->Parameters.SetFile.FileObject, false);
		break;

	case FilePositionInformation:
		TRACE("FilePositionInformation\n");
		Status = set_position_information(IrpSp->FileObject, Irp);
		break;

	case FileRenameInformation:
		TRACE("FileRenameInformation\n");
		Status = set_rename_information(Vcb, Irp, IrpSp->FileObject, IrpSp->Parameters.SetFile.FileObject, false);
		break;

	case FileValidDataLengthInformation:
	{
		TRACE("FileValidDataLengthInformation\n");

		if (Irp->RequestorMode == UserMode && !(ccb->access & (FILE_WRITE_DATA | FILE_APPEND_DATA)))
		{
			WARN("insufficient privileges\n");
			Status = STATUS_ACCESS_DENIED;
			break;
		}

		//Status = set_valid_data_length_information(Vcb, Irp, IrpSp->FileObject);

		break;
	}

#ifndef _MSC_VER
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch"
#endif
	case FileDispositionInformationEx:
	{
		TRACE("FileDispositionInformationEx\n");

		if (Irp->RequestorMode == UserMode && !(ccb->access & DELETE))
		{
			WARN("insufficient privileges\n");
			Status = STATUS_ACCESS_DENIED;
			break;
		}

		Status = set_disposition_information(Vcb, Irp, IrpSp->FileObject, true);

		break;
	}

	case FileRenameInformationEx:
		TRACE("FileRenameInformationEx\n");
		Status = set_rename_information(Vcb, Irp, IrpSp->FileObject, IrpSp->Parameters.SetFile.FileObject, true);
		break;

	case FileLinkInformationEx:
		TRACE("FileLinkInformationEx\n");
		//Status = set_link_information(Vcb, Irp, IrpSp->FileObject, IrpSp->Parameters.SetFile.FileObject, true);
		break;

	case FileCaseSensitiveInformation:
		TRACE("FileCaseSensitiveInformation\n");

		if (Irp->RequestorMode == UserMode && !(ccb->access & FILE_WRITE_ATTRIBUTES))
		{
			WARN("insufficient privileges\n");
			Status = STATUS_ACCESS_DENIED;
			break;
		}

		//Status = set_case_sensitive_information(Irp);
		break;

	case FileStorageReserveIdInformation:
		WARN("unimplemented FileInformationClass FileStorageReserveIdInformation\n");
		break;

#ifndef _MSC_VER
#pragma GCC diagnostic pop
#endif

	default:
		WARN("unknown FileInformationClass %u\n", IrpSp->Parameters.SetFile.FileInformationClass);
	}

end:
	Irp->IoStatus.Status = Status;

	TRACE("returning %08lx\n", Status);

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	if (top_level)
	{
		IoSetTopLevelIrp(NULL);
	}

	ExReleaseResourceLite(&op_lock);
	FsRtlExitFileSystem();

	return Status;
}

static NTSTATUS fill_in_file_basic_information(FILE_BASIC_INFORMATION* fbi, LONG* length, fcb* fcb, unsigned long long nostream_index)
{
	RtlZeroMemory(fbi, sizeof(FILE_BASIC_INFORMATION));

	*length -= sizeof(FILE_BASIC_INFORMATION);

	fbi->CreationTime.QuadPart = chtime(nostream_index, 0, 4, fcb->Vcb->vde->pdode->KMCSFS);
	fbi->LastAccessTime.QuadPart = chtime(nostream_index, 0, 0, fcb->Vcb->vde->pdode->KMCSFS);
	fbi->LastWriteTime.QuadPart = chtime(nostream_index, 0, 2, fcb->Vcb->vde->pdode->KMCSFS);
	fbi->ChangeTime.QuadPart = fbi->LastWriteTime.QuadPart;
	fbi->FileAttributes = chwinattrs(nostream_index, 0, fcb->Vcb->vde->pdode->KMCSFS);

	return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_standard_information(FILE_STANDARD_INFORMATION* fsi, fcb* fcb, ccb* ccb, LONG* length, unsigned long long index)
{
	RtlZeroMemory(fsi, sizeof(FILE_STANDARD_INFORMATION));

	*length -= sizeof(FILE_STANDARD_INFORMATION);

	unsigned long long dindex = FindDictEntry(fcb->Vcb->vde->pdode->KMCSFS.dict, fcb->Vcb->vde->pdode->KMCSFS.table, fcb->Vcb->vde->pdode->KMCSFS.tableend, fcb->Vcb->vde->pdode->KMCSFS.DictSize, ccb->filename->Buffer, ccb->filename->Length / sizeof(WCHAR));

	fsi->EndOfFile.QuadPart = get_file_size(index, fcb->Vcb->vde->pdode->KMCSFS);
	fsi->AllocationSize.QuadPart = sector_align(fsi->EndOfFile.QuadPart, fcb->Vcb->vde->pdode->KMCSFS.sectorsize);
	fsi->NumberOfLinks = 1;
	fsi->DeletePending = fcb->Vcb->vde->pdode->KMCSFS.dict[dindex].flags & delete_pending;
	fsi->Directory = chwinattrs(index, 0, fcb->Vcb->vde->pdode->KMCSFS) & FILE_ATTRIBUTE_DIRECTORY;

	return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_internal_information(FILE_INTERNAL_INFORMATION* fii, fcb* fcb, LONG* length, unsigned long long nostream_index)
{
	*length -= sizeof(FILE_INTERNAL_INFORMATION);

	fii->IndexNumber.QuadPart = nostream_index;

	return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_position_information(FILE_POSITION_INFORMATION* fpi, PFILE_OBJECT FileObject, LONG* length)
{
	RtlZeroMemory(fpi, sizeof(FILE_POSITION_INFORMATION));

	*length -= sizeof(FILE_POSITION_INFORMATION);

	fpi->CurrentByteOffset = FileObject->CurrentByteOffset;

	return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_name_information(FILE_NAME_INFORMATION* fni, fcb* fcb, LONG* length, ccb* ccb)
{
	*length -= offsetof(FILE_NAME_INFORMATION, FileName[0]);

	fni->FileNameLength = ccb->filename->Length;
	RtlCopyMemory(fni->FileName, ccb->filename->Buffer, min(fni->FileNameLength, *length));
	*length -= min(fni->FileNameLength, *length);

	if (*length < fni->FileNameLength)
	{
		WARN("overflow\n");
		return STATUS_BUFFER_OVERFLOW;
	}

	return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_attribute_information(FILE_ATTRIBUTE_TAG_INFORMATION* ati, fcb* fcb, ccb* ccb, LONG* length, unsigned long long index, unsigned long long nostream_index, PFILE_OBJECT FileObject)
{
	*length -= sizeof(FILE_ATTRIBUTE_TAG_INFORMATION);

	ati->FileAttributes = chwinattrs(nostream_index, 0, fcb->Vcb->vde->pdode->KMCSFS);
	ati->ReparseTag = 0;
	if (ati->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
	{
		uint8_t reparsepoint[4] = { 0 };
		unsigned long long bytes_read = 0;
		read_file(fcb, reparsepoint, 0, 4, index, &bytes_read, FileObject);
		if (bytes_read != 4)
		{
			ERR("read_file failed\n");
		}
		ati->ReparseTag = reparsepoint[0] + (reparsepoint[1] << 8) + (reparsepoint[2] << 16) + (reparsepoint[3] << 24);
	}

	return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_stream_information(FILE_STREAM_INFORMATION* fsi, fcb* fcb, ccb* ccb, LONG* length, unsigned long long nostream_index)
{
	RtlZeroMemory(fsi, *length);

	LONG reqsize = 0;
	FILE_STREAM_INFORMATION* entry, *lastentry;
	NTSTATUS Status;

	UNICODE_STRING nostreamname;
	nostreamname.Buffer = ccb->filename->Buffer;
	nostreamname.Length = ccb->filename->Length;

	for (unsigned long i = 0; i < nostreamname.Length / sizeof(WCHAR); i++)
	{
		if (nostreamname.Buffer[i] == *L":")
		{
			nostreamname.Length = i * sizeof(WCHAR);
			break;
		}
	}

	static const WCHAR datasuf[] = L":$DATA";
	UNICODE_STRING suf;

	suf.Buffer = (WCHAR*)datasuf;
	suf.Length = suf.MaximumLength = sizeof(datasuf) - sizeof(WCHAR);

	WCHAR* filename = NULL;
	unsigned long winattrs = chwinattrs(nostream_index, 0, fcb->Vcb->vde->pdode->KMCSFS);

	ExAcquireResourceSharedLite(&fcb->nonpaged->dir_children_lock, true);

	TRACE("length = %li\n", *length);

	entry = fsi;
	lastentry = NULL;

	if (!(winattrs & FILE_ATTRIBUTE_DIRECTORY))
	{
		ULONG off = (ULONG)sector_align(sizeof(FILE_STREAM_INFORMATION) + suf.Length, sizeof(LONGLONG));
		reqsize += off;
		if (*length < reqsize)
		{
			WARN("overflow\n");
			Status = STATUS_BUFFER_OVERFLOW;
			reqsize -= off;
			goto end;
		}

		entry->NextEntryOffset = 0;
		entry->StreamNameLength = suf.Length + sizeof(WCHAR);
		entry->StreamSize.QuadPart = get_file_size(nostream_index, fcb->Vcb->vde->pdode->KMCSFS);
		entry->StreamAllocationSize.QuadPart = sector_align(entry->StreamSize.QuadPart, fcb->Vcb->vde->pdode->KMCSFS.sectorsize);

		entry->StreamName[0] = ':';
		RtlCopyMemory(&entry->StreamName + 1, suf.Buffer, suf.Length);

		lastentry = entry;
		entry = (FILE_STREAM_INFORMATION*)((uint8_t*)entry + off);
	}

	filename = ExAllocatePoolWithTag(NonPagedPoolNx, 65536 * sizeof(WCHAR), ALLOC_TAG);
	if (!filename)
	{
		ERR("out of memory\n");
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto end;
	}

	unsigned long long filenamelen = 0;
	unsigned long long stream_start = 0;
	unsigned long long tableoffset = 0;
	unsigned long long index = 0;

	while (tableoffset < fcb->Vcb->vde->pdode->KMCSFS.filenamesend - fcb->Vcb->vde->pdode->KMCSFS.tableend + 1)
	{
		filenamelen = 0;
		for (; tableoffset < fcb->Vcb->vde->pdode->KMCSFS.filenamesend - fcb->Vcb->vde->pdode->KMCSFS.tableend + 1; tableoffset++)
		{
			if ((fcb->Vcb->vde->pdode->KMCSFS.table[fcb->Vcb->vde->pdode->KMCSFS.tableend + tableoffset] & 0xff) == 255 || (fcb->Vcb->vde->pdode->KMCSFS.table[fcb->Vcb->vde->pdode->KMCSFS.tableend + tableoffset] & 0xff) == 42) // 255 = file, 42 = fuse symlink
			{
				if (nostreamname.Length / sizeof(WCHAR) < filenamelen)
				{
					bool isin = true;
					unsigned long long i = 0;
					for (; i < nostreamname.Length / sizeof(WCHAR); i++)
					{
						if (!incmp(nostreamname.Buffer[i] & 0xff, filename[i] & 0xff) && !(nostreamname.Buffer[i] == *L"/" && filename[i] == *L"\\") && !(nostreamname.Buffer[i] == *L"\\" && filename[i] == *L"/"))
						{
							isin = false;
							break;
						}
					}
					if (!(filename[i] == *L":"))
					{
						isin = false;
					}
					stream_start = i;
					i++;
					if (isin)
					{
						break;
					}
				}
				filenamelen = 0;
				if ((fcb->Vcb->vde->pdode->KMCSFS.table[fcb->Vcb->vde->pdode->KMCSFS.tableend + tableoffset] & 0xff) == 255)
				{
					index++;
				}
			}
			else
			{
				filename[filenamelen] = fcb->Vcb->vde->pdode->KMCSFS.table[fcb->Vcb->vde->pdode->KMCSFS.tableend + tableoffset] & 0xff;
				filenamelen++;
			}
		}

		if (filenamelen)
		{
			ULONG off = (ULONG)sector_align(sizeof(FILE_STREAM_INFORMATION) + (filenamelen - stream_start) * sizeof(WCHAR) + suf.Length, sizeof(LONGLONG));
			reqsize += off;
			if (*length < reqsize)
			{
				WARN("overflow\n");
				Status = STATUS_BUFFER_OVERFLOW;
				reqsize -= off;
				goto end;
			}

			entry->NextEntryOffset = 0;
			entry->StreamNameLength = (filenamelen - stream_start) * sizeof(WCHAR);
			entry->StreamSize.QuadPart = get_file_size(index - 1, fcb->Vcb->vde->pdode->KMCSFS);
			entry->StreamAllocationSize.QuadPart = sector_align(entry->StreamSize.QuadPart, fcb->Vcb->vde->pdode->KMCSFS.sectorsize);

			entry->StreamName[0] = ':';
			RtlCopyMemory(&entry->StreamName + 1, filename + stream_start + 1, entry->StreamNameLength - sizeof(WCHAR));
			RtlCopyMemory(&entry->StreamName + entry->StreamNameLength / sizeof(WCHAR), suf.Buffer, suf.Length);
			entry->StreamNameLength += suf.Length;

			if (lastentry)
			{
				lastentry->NextEntryOffset = (uint32_t)((uint8_t*)entry - (uint8_t*)lastentry);
			}

			lastentry = entry;
			entry = (FILE_STREAM_INFORMATION*)((uint8_t*)entry + off);
		}
	}

	Status = STATUS_SUCCESS;

end:
	ExReleaseResourceLite(&fcb->nonpaged->dir_children_lock);
	*length -= reqsize;
	if (filename)
	{
		ExFreePool(filename);
	}

	return Status;
}

static NTSTATUS fill_in_file_network_open_information(FILE_NETWORK_OPEN_INFORMATION* fnoi, fcb* fcb, LONG* length, unsigned long long index, unsigned long long nostream_index)
{
	if (*length < sizeof(FILE_NETWORK_OPEN_INFORMATION))
	{
		WARN("overflow\n");
		return STATUS_BUFFER_OVERFLOW;
	}

	RtlZeroMemory(fnoi, sizeof(FILE_NETWORK_OPEN_INFORMATION));

	*length -= sizeof(FILE_NETWORK_OPEN_INFORMATION);

	fnoi->CreationTime.QuadPart = chtime(nostream_index, 0, 4, fcb->Vcb->vde->pdode->KMCSFS);
	fnoi->LastAccessTime.QuadPart = chtime(nostream_index, 0, 0, fcb->Vcb->vde->pdode->KMCSFS);
	fnoi->LastWriteTime.QuadPart = chtime(nostream_index, 0, 2, fcb->Vcb->vde->pdode->KMCSFS);
	fnoi->ChangeTime.QuadPart = fnoi->LastWriteTime.QuadPart;
	fnoi->EndOfFile.QuadPart = get_file_size(index, fcb->Vcb->vde->pdode->KMCSFS);
	fnoi->AllocationSize.QuadPart = sector_align(fnoi->EndOfFile.QuadPart, fcb->Vcb->vde->pdode->KMCSFS.sectorsize);
	fnoi->FileAttributes = chwinattrs(nostream_index, 0, fcb->Vcb->vde->pdode->KMCSFS);

	return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_id_information(FILE_ID_INFORMATION* fii, fcb* fcb, LONG* length, unsigned long long index)
{
	RtlCopyMemory(&fii->VolumeSerialNumber, &fcb->Vcb->vde->pdode->KMCSFS.uuid, sizeof(uint64_t));
	RtlCopyMemory(&fii->FileId.Identifier, &index, 8);
	fii->FileId.Identifier[8] = 0;
	fii->FileId.Identifier[9] = 0;
	fii->FileId.Identifier[10] = 0;
	fii->FileId.Identifier[11] = 0;
	fii->FileId.Identifier[12] = 0;
	fii->FileId.Identifier[13] = 0;
	fii->FileId.Identifier[14] = 0;
	fii->FileId.Identifier[15] = 0;

	*length -= sizeof(FILE_ID_INFORMATION);

	return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_stat_information(FILE_STAT_INFORMATION* fsi, fcb* fcb, ccb* ccb, LONG* length, unsigned long long index, unsigned long long nostream_index, PFILE_OBJECT FileObject)
{
	RtlZeroMemory(fsi, sizeof(FILE_STAT_INFORMATION));

	*length -= sizeof(FILE_STAT_INFORMATION);

	fsi->FileId.QuadPart = index;
	fsi->CreationTime.QuadPart = chtime(nostream_index, 0, 4, fcb->Vcb->vde->pdode->KMCSFS);
	fsi->LastAccessTime.QuadPart = chtime(nostream_index, 0, 0, fcb->Vcb->vde->pdode->KMCSFS);
	fsi->LastWriteTime.QuadPart = chtime(nostream_index, 0, 2, fcb->Vcb->vde->pdode->KMCSFS);
	fsi->ChangeTime.QuadPart = fsi->LastWriteTime.QuadPart;
	fsi->EndOfFile.QuadPart = get_file_size(index, fcb->Vcb->vde->pdode->KMCSFS);
	fsi->AllocationSize.QuadPart = sector_align(fsi->EndOfFile.QuadPart, fcb->Vcb->vde->pdode->KMCSFS.sectorsize);
	fsi->FileAttributes = chwinattrs(nostream_index, 0, fcb->Vcb->vde->pdode->KMCSFS);
	fsi->ReparseTag = 0;
	if (fsi->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
	{
		uint8_t reparsepoint[4] = { 0 };
		unsigned long long bytes_read = 0;
		read_file(fcb, reparsepoint, 0, 4, index, &bytes_read, FileObject);
		if (bytes_read != 4)
		{
			ERR("read_file failed\n");
		}
		fsi->ReparseTag = reparsepoint[0] + (reparsepoint[1] << 8) + (reparsepoint[2] << 16) + (reparsepoint[3] << 24);
	}
	fsi->NumberOfLinks = 1;
	fsi->EffectiveAccess = ccb->access;

	return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_case_sensitive_information(FILE_CASE_SENSITIVE_INFORMATION* fcsi, fcb* fcb, LONG* length)
{
	fcsi->Flags = 1;

	*length -= sizeof(FILE_CASE_SENSITIVE_INFORMATION);

	return STATUS_SUCCESS;
}

static NTSTATUS query_info(device_extension* Vcb, PFILE_OBJECT FileObject, PIRP Irp)
{
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	LONG length = IrpSp->Parameters.QueryFile.Length;
	fcb* fcb = FileObject->FsContext;
	ccb* ccb = FileObject->FsContext2;
	NTSTATUS Status;

	TRACE("(%p, %p, %p)\n", Vcb, FileObject, Irp);
	TRACE("fcb = %p\n", fcb);

	if (fcb == Vcb->volume_fcb)
	{
		return STATUS_INVALID_PARAMETER;
	}

	if (!ccb)
	{
		ERR("ccb is NULL\n");
		return STATUS_INVALID_PARAMETER;
	}

	unsigned long long index = get_filename_index(*ccb->filename, &fcb->Vcb->vde->pdode->KMCSFS);
	if (!index)
	{
		ERR("index is 0\n");
		return STATUS_INVALID_PARAMETER;
	}

	UNICODE_STRING nostream_fn;
	nostream_fn.Buffer = ccb->filename->Buffer;
	nostream_fn.Length = 0;
	for (unsigned long i = 0; i < ccb->filename->Length / sizeof(WCHAR); i++)
	{
		if (ccb->filename->Buffer[i] == *L":")
		{
			nostream_fn.Length = i * sizeof(WCHAR);
			break;
		}
	}
	unsigned long long nostream_index = get_filename_index(nostream_fn, &fcb->Vcb->vde->pdode->KMCSFS);
	if (!nostream_index)
	{
		nostream_index = index;
	}

	switch (IrpSp->Parameters.QueryFile.FileInformationClass)
	{
	case FileAllInformation:
	{
		FILE_ALL_INFORMATION* fai = Irp->AssociatedIrp.SystemBuffer;

		TRACE("FileAllInformation\n");

		if (Irp->RequestorMode != KernelMode && !(ccb->access & (FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES)))
		{
			WARN("insufficient privileges\n");
			Status = STATUS_ACCESS_DENIED;
			goto exit;
		}

		// Access, mode, and alignment are all filled in by the kernel

		if (length > 0)
		{
			fill_in_file_basic_information(&fai->BasicInformation, &length, fcb, nostream_index);
		}

		if (length > 0)
		{
			fill_in_file_standard_information(&fai->StandardInformation, fcb, ccb, &length, index);
		}

		if (length > 0)
		{
			fill_in_file_internal_information(&fai->InternalInformation, fcb, &length, nostream_index);
		}

		length -= sizeof(FILE_ACCESS_INFORMATION);

		if (length > 0)
		{
			fill_in_file_position_information(&fai->PositionInformation, FileObject, &length);
		}

		length -= sizeof(FILE_MODE_INFORMATION);

		length -= sizeof(FILE_ALIGNMENT_INFORMATION);

		if (length > 0)
		{
			fill_in_file_name_information(&fai->NameInformation, fcb, &length, ccb);
		}

		Status = STATUS_SUCCESS;

		break;
	}

	case FileAttributeTagInformation:
	{
		FILE_ATTRIBUTE_TAG_INFORMATION* ati = Irp->AssociatedIrp.SystemBuffer;

		TRACE("FileAttributeTagInformation\n");

		if (Irp->RequestorMode != KernelMode && !(ccb->access & (FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES)))
		{
			WARN("insufficient privileges\n");
			Status = STATUS_ACCESS_DENIED;
			goto exit;
		}

		ExAcquireResourceSharedLite(&Vcb->tree_lock, true);
		Status = fill_in_file_attribute_information(ati, fcb, ccb, &length, index, nostream_index, FileObject);
		ExReleaseResourceLite(&Vcb->tree_lock);

		break;
	}

	case FileBasicInformation:
	{
		FILE_BASIC_INFORMATION* fbi = Irp->AssociatedIrp.SystemBuffer;

		TRACE("FileBasicInformation\n");

		if (Irp->RequestorMode != KernelMode && !(ccb->access & (FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES)))
		{
			WARN("insufficient privileges\n");
			Status = STATUS_ACCESS_DENIED;
			goto exit;
		}

		if (IrpSp->Parameters.QueryFile.Length < sizeof(FILE_BASIC_INFORMATION))
		{
			WARN("overflow\n");
			Status = STATUS_BUFFER_OVERFLOW;
			goto exit;
		}

		Status = fill_in_file_basic_information(fbi, &length, fcb, nostream_index);
		break;
	}

	case FileInternalInformation:
	{
		FILE_INTERNAL_INFORMATION* fii = Irp->AssociatedIrp.SystemBuffer;

		TRACE("FileInternalInformation\n");

		Status = fill_in_file_internal_information(fii, fcb, &length, nostream_index);

		break;
	}

	case FileNameInformation:
	{
		FILE_NAME_INFORMATION* fni = Irp->AssociatedIrp.SystemBuffer;

		TRACE("FileNameInformation\n");

		Status = fill_in_file_name_information(fni, fcb, &length, ccb);

		break;
	}

	case FileNetworkOpenInformation:
	{
		FILE_NETWORK_OPEN_INFORMATION* fnoi = Irp->AssociatedIrp.SystemBuffer;

		TRACE("FileNetworkOpenInformation\n");

		if (Irp->RequestorMode != KernelMode && !(ccb->access & (FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES)))
		{
			WARN("insufficient privileges\n");
			Status = STATUS_ACCESS_DENIED;
			goto exit;
		}

		Status = fill_in_file_network_open_information(fnoi, fcb, &length, index, nostream_index);

		break;
	}

	case FilePositionInformation:
	{
		FILE_POSITION_INFORMATION* fpi = Irp->AssociatedIrp.SystemBuffer;

		TRACE("FilePositionInformation\n");

		Status = fill_in_file_position_information(fpi, FileObject, &length);

		break;
	}

	case FileStandardInformation:
	{
		FILE_STANDARD_INFORMATION* fsi = Irp->AssociatedIrp.SystemBuffer;

		TRACE("FileStandardInformation\n");

		if (IrpSp->Parameters.QueryFile.Length < sizeof(FILE_STANDARD_INFORMATION))
		{
			WARN("overflow\n");
			Status = STATUS_BUFFER_OVERFLOW;
			goto exit;
		}

		Status = fill_in_file_standard_information(fsi, fcb, ccb, &length, index);

		break;
	}

	case FileStreamInformation:
	{
		FILE_STREAM_INFORMATION* fsi = Irp->AssociatedIrp.SystemBuffer;

		TRACE("FileStreamInformation\n");

		Status = fill_in_file_stream_information(fsi, fcb, ccb, &length, nostream_index);

		break;
	}

	case FileNormalizedNameInformation:
	{
		FILE_NAME_INFORMATION* fni = Irp->AssociatedIrp.SystemBuffer;

		TRACE("FileNormalizedNameInformation\n");

		Status = fill_in_file_name_information(fni, fcb, &length, ccb);

		break;
	}

	case FileRemoteProtocolInformation:
		TRACE("FileRemoteProtocolInformation\n");
		Status = STATUS_INVALID_PARAMETER;
		goto exit;

#ifndef _MSC_VER
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch"
#endif

	case FileIdInformation:
	{
		FILE_ID_INFORMATION* fii = Irp->AssociatedIrp.SystemBuffer;

		if (IrpSp->Parameters.QueryFile.Length < sizeof(FILE_ID_INFORMATION))
		{
			WARN("overflow\n");
			Status = STATUS_BUFFER_OVERFLOW;
			goto exit;
		}

		TRACE("FileIdInformation\n");

		Status = fill_in_file_id_information(fii, fcb, &length, index);

		break;
	}

	case FileStatInformation:
	{
		FILE_STAT_INFORMATION* fsi = Irp->AssociatedIrp.SystemBuffer;

		if (IrpSp->Parameters.QueryFile.Length < sizeof(FILE_STAT_INFORMATION))
		{
			WARN("overflow\n");
			Status = STATUS_BUFFER_OVERFLOW;
			goto exit;
		}

		TRACE("FileStatInformation\n");

		Status = fill_in_file_stat_information(fsi, fcb, ccb, &length, index, nostream_index, FileObject);

		break;
	}

	/*case FileStatLxInformation:
	{
		FILE_STAT_LX_INFORMATION* fsli = Irp->AssociatedIrp.SystemBuffer;

		if (IrpSp->Parameters.QueryFile.Length < sizeof(FILE_STAT_LX_INFORMATION))
		{
			WARN("overflow\n");
			Status = STATUS_BUFFER_OVERFLOW;
			goto exit;
		}

		TRACE("FileStatLxInformation\n");

		Status = fill_in_file_stat_lx_information(fsli, fcb, ccb, &length);

		break;
	}*/

	case FileCaseSensitiveInformation:
	{
		FILE_CASE_SENSITIVE_INFORMATION* fcsi = Irp->AssociatedIrp.SystemBuffer;

		if (IrpSp->Parameters.QueryFile.Length < sizeof(FILE_CASE_SENSITIVE_INFORMATION))
		{
			WARN("overflow\n");
			Status = STATUS_BUFFER_OVERFLOW;
			goto exit;
		}

		TRACE("FileCaseSensitiveInformation\n");

		Status = fill_in_file_case_sensitive_information(fcsi, fcb, &length);

		break;
	}

#ifndef _MSC_VER
#pragma GCC diagnostic pop
#endif

	default:
		WARN("unknown FileInformationClass %u\n", IrpSp->Parameters.QueryFile.FileInformationClass);
		Status = STATUS_INVALID_PARAMETER;
		goto exit;
	}

	if (length < 0)
	{
		length = 0;
		Status = STATUS_BUFFER_OVERFLOW;
	}

	Irp->IoStatus.Information = IrpSp->Parameters.QueryFile.Length - length;

exit:
	TRACE("query_info returning %08lx\n", Status);

	return Status;
}

_Dispatch_type_(IRP_MJ_QUERY_INFORMATION)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS __stdcall QueryInformation(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	PIO_STACK_LOCATION IrpSp;
	NTSTATUS Status;
	fcb* fcb;
	device_extension* Vcb = DeviceObject->DeviceExtension;
	bool top_level;

	FsRtlEnterFileSystem();
	ExAcquireResourceExclusiveLite(&op_lock, true);

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

	Irp->IoStatus.Information = 0;

	TRACE("query information\n");

	IrpSp = IoGetCurrentIrpStackLocation(Irp);

	fcb = IrpSp->FileObject->FsContext;
	TRACE("fcb = %p\n", fcb);

	Status = query_info(fcb->Vcb, IrpSp->FileObject, Irp);

end:
	TRACE("returning %08lx\n", Status);

	Irp->IoStatus.Status = Status;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	if (top_level)
	{
		IoSetTopLevelIrp(NULL);
	}

	ExReleaseResourceLite(&op_lock);
	FsRtlExitFileSystem();

	return Status;
}
