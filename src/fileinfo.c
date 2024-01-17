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

static NTSTATUS fill_in_file_basic_information(FILE_BASIC_INFORMATION* fbi, LONG* length, fcb* fcb, unsigned long long index)
{
	RtlZeroMemory(fbi, sizeof(FILE_BASIC_INFORMATION));

	*length -= sizeof(FILE_BASIC_INFORMATION);

	fbi->CreationTime.QuadPart = chtime(index, 0, 4, fcb->Vcb->vde->pdode->KMCSFS);
	fbi->LastAccessTime.QuadPart = chtime(index, 0, 0, fcb->Vcb->vde->pdode->KMCSFS);
	fbi->LastWriteTime.QuadPart = chtime(index, 0, 2, fcb->Vcb->vde->pdode->KMCSFS);
	fbi->ChangeTime.QuadPart = fbi->LastWriteTime.QuadPart;
	fbi->FileAttributes = chwinattrs(index, 0, fcb->Vcb->vde->pdode->KMCSFS);

	return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_standard_information(FILE_STANDARD_INFORMATION* fsi, fcb* fcb, LONG* length, unsigned long long index)
{
	RtlZeroMemory(fsi, sizeof(FILE_STANDARD_INFORMATION));

	*length -= sizeof(FILE_STANDARD_INFORMATION);

	fsi->EndOfFile.QuadPart = get_file_size(index, fcb->Vcb->vde->pdode->KMCSFS);
	fsi->AllocationSize.QuadPart = sector_align(fsi->EndOfFile.QuadPart, fcb->Vcb->vde->pdode->KMCSFS.sectorsize);
	fsi->NumberOfLinks = 1;
	fsi->DeletePending = false;
	fsi->Directory = chwinattrs(index, 0, fcb->Vcb->vde->pdode->KMCSFS) & FILE_ATTRIBUTE_DIRECTORY;

	return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_internal_information(FILE_INTERNAL_INFORMATION* fii, fcb* fcb, LONG* length, unsigned long long index)
{
	*length -= sizeof(FILE_INTERNAL_INFORMATION);

	fii->IndexNumber.QuadPart = index;

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

	if (*length < ccb->filename.Length)
	{
		WARN("overflow\n");
		return STATUS_BUFFER_OVERFLOW;
	}

	fni->FileNameLength = ccb->filename.Length;
	RtlCopyMemory(fni->FileName, ccb->filename.Buffer, ccb->filename.Length);

	return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_attribute_information(FILE_ATTRIBUTE_TAG_INFORMATION* ati, fcb* fcb, ccb* ccb, LONG* length, unsigned long long index)
{
	*length -= sizeof(FILE_ATTRIBUTE_TAG_INFORMATION);

	ati->FileAttributes = chwinattrs(index, 0, fcb->Vcb->vde->pdode->KMCSFS);
	ati->ReparseTag = 0;

	return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_network_open_information(FILE_NETWORK_OPEN_INFORMATION* fnoi, fcb* fcb, LONG* length, unsigned long long index)
{
	if (*length < sizeof(FILE_NETWORK_OPEN_INFORMATION))
	{
		WARN("overflow\n");
		return STATUS_BUFFER_OVERFLOW;
	}

	RtlZeroMemory(fnoi, sizeof(FILE_NETWORK_OPEN_INFORMATION));

	*length -= sizeof(FILE_NETWORK_OPEN_INFORMATION);

	fnoi->CreationTime.QuadPart = chtime(index, 0, 4, fcb->Vcb->vde->pdode->KMCSFS);
	fnoi->LastAccessTime.QuadPart = chtime(index, 0, 0, fcb->Vcb->vde->pdode->KMCSFS);
	fnoi->LastWriteTime.QuadPart = chtime(index, 0, 2, fcb->Vcb->vde->pdode->KMCSFS);
	fnoi->ChangeTime.QuadPart = fnoi->LastWriteTime.QuadPart;
	fnoi->EndOfFile.QuadPart = get_file_size(index, fcb->Vcb->vde->pdode->KMCSFS);
	fnoi->AllocationSize.QuadPart = sector_align(fnoi->EndOfFile.QuadPart, fcb->Vcb->vde->pdode->KMCSFS.sectorsize);
	fnoi->FileAttributes = chwinattrs(index, 0, fcb->Vcb->vde->pdode->KMCSFS);

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

static NTSTATUS fill_in_file_stat_information(FILE_STAT_INFORMATION* fsi, fcb* fcb, ccb* ccb, LONG* length, unsigned long long index)
{
	RtlZeroMemory(fsi, sizeof(FILE_STAT_INFORMATION));

	*length -= sizeof(FILE_STAT_INFORMATION);

	fsi->FileId.QuadPart = index;
	fsi->CreationTime.QuadPart = chtime(index, 0, 4, fcb->Vcb->vde->pdode->KMCSFS);
	fsi->LastAccessTime.QuadPart = chtime(index, 0, 0, fcb->Vcb->vde->pdode->KMCSFS);
	fsi->LastWriteTime.QuadPart = chtime(index, 0, 2, fcb->Vcb->vde->pdode->KMCSFS);
	fsi->ChangeTime.QuadPart = fsi->LastWriteTime.QuadPart;
	fsi->EndOfFile.QuadPart = get_file_size(index, fcb->Vcb->vde->pdode->KMCSFS);
	fsi->AllocationSize.QuadPart = sector_align(fsi->EndOfFile.QuadPart, fcb->Vcb->vde->pdode->KMCSFS.sectorsize);
	fsi->FileAttributes = chwinattrs(index, 0, fcb->Vcb->vde->pdode->KMCSFS);
	fsi->ReparseTag = 0;
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

	unsigned long long index = get_filename_index(ccb->filename, fcb->Vcb->vde->pdode->KMCSFS);
	if (!index)
	{
		ERR("index is 0\n");
		return STATUS_INVALID_PARAMETER;
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
			fill_in_file_basic_information(&fai->BasicInformation, &length, fcb, index);
		}

		if (length > 0)
		{
			fill_in_file_standard_information(&fai->StandardInformation, fcb, &length, index);
		}

		if (length > 0)
		{
			fill_in_file_internal_information(&fai->InternalInformation, fcb, &length, index);
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
		Status = fill_in_file_attribute_information(ati, fcb, ccb, &length, index);
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

		Status = fill_in_file_basic_information(fbi, &length, fcb, index);
		break;
	}

	case FileInternalInformation:
	{
		FILE_INTERNAL_INFORMATION* fii = Irp->AssociatedIrp.SystemBuffer;

		TRACE("FileInternalInformation\n");

		Status = fill_in_file_internal_information(fii, fcb, &length, index);

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

		Status = fill_in_file_network_open_information(fnoi, fcb, &length, index);

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

		Status = fill_in_file_standard_information(fsi, fcb, &length, index);

		break;
	}

	/*case FileStreamInformation:
	{
		FILE_STREAM_INFORMATION* fsi = Irp->AssociatedIrp.SystemBuffer;

		TRACE("FileStreamInformation\n");

		Status = fill_in_file_stream_information(fsi, &length);

		break;
	}*/

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

		Status = fill_in_file_stat_information(fsi, fcb, ccb, &length, index);

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
	TRACE("fcb->subvol = %p\n", fcb->subvol);

	Status = query_info(fcb->Vcb, IrpSp->FileObject, Irp);

end:
	TRACE("returning %08lx\n", Status);

	Irp->IoStatus.Status = Status;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	if (top_level)
	{
		IoSetTopLevelIrp(NULL);
	}

	FsRtlExitFileSystem();

	return Status;
}
