// Copyright (c) Anthony Kerr 2024-

#include <sys/stat.h>
#include "KMCSpaceFS_drv.h"
#include <ntddstor.h>

extern PDEVICE_OBJECT devobj;

static const WCHAR datastring[] = L"::$DATA";

static const char root_dir[] = "$Root";
static const WCHAR root_dir_utf16[] = L"$Root";

#ifndef _MSC_VER
typedef struct _FILE_TIMESTAMPS
{
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
} FILE_TIMESTAMPS, *PFILE_TIMESTAMPS;
#endif

static const GUID GUID_ECP_ATOMIC_CREATE = {0x4720bd83, 0x52ac, 0x4104, {0xa1, 0x30, 0xd1, 0xec, 0x6a, 0x8c, 0xc8, 0xe5}};
static const GUID GUID_ECP_QUERY_ON_CREATE = {0x1aca62e9, 0xabb4, 0x4ff2, {0xbb, 0x5c, 0x1c, 0x79, 0x02, 0x5e, 0x41, 0x7f}};
static const GUID GUID_ECP_CREATE_REDIRECTION = {0x188d6bd6, 0xa126, 0x4fa8, {0xbd, 0xf2, 0x1c, 0xcd, 0xf8, 0x96, 0xf3, 0xe0}};

#ifndef SL_IGNORE_READONLY_ATTRIBUTE
#define SL_IGNORE_READONLY_ATTRIBUTE 0x40 // introduced in Windows 10, not in mingw
#endif

typedef struct
{
	device_extension* Vcb;
	ACCESS_MASK granted_access;
	NTSTATUS Status;
	KEVENT event;
} oplock_context;

fcb* create_fcb(device_extension* Vcb, POOL_TYPE pool_type)
{
	fcb* fcb;

	if (pool_type == NonPagedPoolNx)
	{
		fcb = ExAllocatePoolWithTag(pool_type, sizeof(struct _fcb), ALLOC_TAG);
		if (!fcb)
		{
			ERR("out of memory\n");
			return NULL;
		}
	}
	else
	{
		fcb = ExAllocateFromPagedLookasideList(&Vcb->fcb_lookaside);
		if (!fcb)
		{
			ERR("out of memory\n");
			return NULL;
		}
	}

#ifdef DEBUG_FCB_REFCOUNTS
	WARN("allocating fcb %p\n", fcb);
#endif
	RtlZeroMemory(fcb, sizeof(struct _fcb));
	fcb->pool_type = pool_type;

	fcb->Vcb = Vcb;

	fcb->Header.NodeTypeCode = KMCSpaceFS_NODE_TYPE_FCB;
	fcb->Header.NodeByteSize = sizeof(struct _fcb);

	fcb->nonpaged = ExAllocateFromNPagedLookasideList(&Vcb->fcb_np_lookaside);
	if (!fcb->nonpaged)
	{
		ERR("out of memory\n");

		if (pool_type == NonPagedPoolNx)
		{
			ExFreePool(fcb);
		}
		else
		{
			ExFreeToPagedLookasideList(&Vcb->fcb_lookaside, fcb);
		}

		return NULL;
	}
	RtlZeroMemory(fcb->nonpaged, sizeof(struct _fcb_nonpaged));

	ExInitializeResourceLite(&fcb->nonpaged->paging_resource);
	fcb->Header.PagingIoResource = &fcb->nonpaged->paging_resource;

	ExInitializeFastMutex(&fcb->nonpaged->HeaderMutex);
	FsRtlSetupAdvancedHeader(&fcb->Header, &fcb->nonpaged->HeaderMutex);

	fcb->refcount = 1;
#ifdef DEBUG_FCB_REFCOUNTS
	WARN("fcb %p: refcount now %i\n", fcb, fcb->refcount);
#endif

	ExInitializeResourceLite(&fcb->nonpaged->resource);
	fcb->Header.Resource = &fcb->nonpaged->resource;

	ExInitializeResourceLite(&fcb->nonpaged->dir_children_lock);

	InitializeListHead(&fcb->extents);

	return fcb;
}

static __inline void debug_create_options(ULONG RequestedOptions)
{
	if (RequestedOptions != 0)
	{
		ULONG options = RequestedOptions;

		TRACE("requested options:\n");

		if (options & FILE_DIRECTORY_FILE)
		{
			TRACE("    FILE_DIRECTORY_FILE\n");
			options &= ~FILE_DIRECTORY_FILE;
		}

		if (options & FILE_WRITE_THROUGH)
		{
			TRACE("    FILE_WRITE_THROUGH\n");
			options &= ~FILE_WRITE_THROUGH;
		}

		if (options & FILE_SEQUENTIAL_ONLY)
		{
			TRACE("    FILE_SEQUENTIAL_ONLY\n");
			options &= ~FILE_SEQUENTIAL_ONLY;
		}

		if (options & FILE_NO_INTERMEDIATE_BUFFERING)
		{
			TRACE("    FILE_NO_INTERMEDIATE_BUFFERING\n");
			options &= ~FILE_NO_INTERMEDIATE_BUFFERING;
		}

		if (options & FILE_SYNCHRONOUS_IO_ALERT)
		{
			TRACE("    FILE_SYNCHRONOUS_IO_ALERT\n");
			options &= ~FILE_SYNCHRONOUS_IO_ALERT;
		}

		if (options & FILE_SYNCHRONOUS_IO_NONALERT)
		{
			TRACE("    FILE_SYNCHRONOUS_IO_NONALERT\n");
			options &= ~FILE_SYNCHRONOUS_IO_NONALERT;
		}

		if (options & FILE_NON_DIRECTORY_FILE)
		{
			TRACE("    FILE_NON_DIRECTORY_FILE\n");
			options &= ~FILE_NON_DIRECTORY_FILE;
		}

		if (options & FILE_CREATE_TREE_CONNECTION)
		{
			TRACE("    FILE_CREATE_TREE_CONNECTION\n");
			options &= ~FILE_CREATE_TREE_CONNECTION;
		}

		if (options & FILE_COMPLETE_IF_OPLOCKED)
		{
			TRACE("    FILE_COMPLETE_IF_OPLOCKED\n");
			options &= ~FILE_COMPLETE_IF_OPLOCKED;
		}

		if (options & FILE_NO_EA_KNOWLEDGE)
		{
			TRACE("    FILE_NO_EA_KNOWLEDGE\n");
			options &= ~FILE_NO_EA_KNOWLEDGE;
		}

		if (options & FILE_OPEN_REMOTE_INSTANCE)
		{
			TRACE("    FILE_OPEN_REMOTE_INSTANCE\n");
			options &= ~FILE_OPEN_REMOTE_INSTANCE;
		}

		if (options & FILE_RANDOM_ACCESS)
		{
			TRACE("    FILE_RANDOM_ACCESS\n");
			options &= ~FILE_RANDOM_ACCESS;
		}

		if (options & FILE_DELETE_ON_CLOSE)
		{
			TRACE("    FILE_DELETE_ON_CLOSE\n");
			options &= ~FILE_DELETE_ON_CLOSE;
		}

		if (options & FILE_OPEN_BY_FILE_ID)
		{
			TRACE("    FILE_OPEN_BY_FILE_ID\n");
			options &= ~FILE_OPEN_BY_FILE_ID;
		}

		if (options & FILE_OPEN_FOR_BACKUP_INTENT)
		{
			TRACE("    FILE_OPEN_FOR_BACKUP_INTENT\n");
			options &= ~FILE_OPEN_FOR_BACKUP_INTENT;
		}

		if (options & FILE_NO_COMPRESSION)
		{
			TRACE("    FILE_NO_COMPRESSION\n");
			options &= ~FILE_NO_COMPRESSION;
		}

#if NTDDI_VERSION >= NTDDI_WIN7
		if (options & FILE_OPEN_REQUIRING_OPLOCK)
		{
			TRACE("    FILE_OPEN_REQUIRING_OPLOCK\n");
			options &= ~FILE_OPEN_REQUIRING_OPLOCK;
		}

		if (options & FILE_DISALLOW_EXCLUSIVE)
		{
			TRACE("    FILE_DISALLOW_EXCLUSIVE\n");
			options &= ~FILE_DISALLOW_EXCLUSIVE;
		}
#endif

		if (options & FILE_RESERVE_OPFILTER)
		{
			TRACE("    FILE_RESERVE_OPFILTER\n");
			options &= ~FILE_RESERVE_OPFILTER;
		}

		if (options & FILE_OPEN_REPARSE_POINT)
		{
			TRACE("    FILE_OPEN_REPARSE_POINT\n");
			options &= ~FILE_OPEN_REPARSE_POINT;
		}

		if (options & FILE_OPEN_NO_RECALL)
		{
			TRACE("    FILE_OPEN_NO_RECALL\n");
			options &= ~FILE_OPEN_NO_RECALL;
		}

		if (options & FILE_OPEN_FOR_FREE_SPACE_QUERY)
		{
			TRACE("    FILE_OPEN_FOR_FREE_SPACE_QUERY\n");
			options &= ~FILE_OPEN_FOR_FREE_SPACE_QUERY;
		}

		if (options)
		{
			TRACE("    unknown options: %lx\n", options);
		}
	}
	else
	{
		TRACE("requested options: (none)\n");
	}
}

static NTSTATUS open_file(PDEVICE_OBJECT DeviceObject, _Requires_lock_held_(_Curr_->tree_lock) device_extension* Vcb, PIRP Irp, oplock_context** opctx)
{
	PFILE_OBJECT FileObject = NULL;
	ULONG RequestedDisposition;
	ULONG options;
	NTSTATUS Status = STATUS_INVALID_PARAMETER;
	NTSTATUS Parent_Status;
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	POOL_TYPE pool_type = IrpSp->Flags & SL_OPEN_PAGING_FILE ? NonPagedPoolNx : PagedPool;
	ACCESS_MASK granted_access, parent_granted_access;
	UNICODE_STRING fn;
	bool created = false;
	bool has_parent_perm = false;
	unsigned long long index = 0;
	unsigned long long dindex = 0;

	Irp->IoStatus.Information = 0;

	RequestedDisposition = ((IrpSp->Parameters.Create.Options >> 24) & 0xff);
	options = IrpSp->Parameters.Create.Options & FILE_VALID_OPTION_FLAGS;

	if (options & FILE_DIRECTORY_FILE && RequestedDisposition == FILE_SUPERSEDE)
	{
		WARN("error - supersede requested with FILE_DIRECTORY_FILE\n");
		return STATUS_INVALID_PARAMETER;
	}

	FileObject = IrpSp->FileObject;

	if (!FileObject)
	{
		ERR("FileObject was NULL\n");
		return STATUS_INVALID_PARAMETER;
	}

	debug_create_options(options);

	switch (RequestedDisposition)
	{
	case FILE_SUPERSEDE:
		TRACE("requested disposition: FILE_SUPERSEDE\n");
		break;

	case FILE_CREATE:
		TRACE("requested disposition: FILE_CREATE\n");
		break;

	case FILE_OPEN:
		TRACE("requested disposition: FILE_OPEN\n");
		break;

	case FILE_OPEN_IF:
		TRACE("requested disposition: FILE_OPEN_IF\n");
		break;

	case FILE_OVERWRITE:
		TRACE("requested disposition: FILE_OVERWRITE\n");
		break;

	case FILE_OVERWRITE_IF:
		TRACE("requested disposition: FILE_OVERWRITE_IF\n");
		break;

	default:
		ERR("unknown disposition: %lx\n", RequestedDisposition);
		Status = STATUS_NOT_IMPLEMENTED;
		goto exit;
	}

	TRACE("(%.*S)\n", (int)(FileObject->FileName.Length / sizeof(WCHAR)), FileObject->FileName.Buffer);

	if (!(IrpSp->Parameters.Create.SecurityContext->AccessState->Flags & TOKEN_HAS_TRAVERSE_PRIVILEGE))
	{
		TRACE("no traverse privilege\n");
		Status = STATUS_ACCESS_DENIED;
		goto exit;
	}

	if (FileObject->FileName.Length)
	{
		if (FileObject->FileName.Buffer[FileObject->FileName.Length / sizeof(WCHAR) - 1] == 42 && FileObject->FileName.Length > 2)
		{
			if (RequestedDisposition & FILE_CREATE)
			{
				Status = STATUS_OBJECT_NAME_INVALID;
				goto exit;
			}
			FileObject->FileName.Buffer[FileObject->FileName.Length / sizeof(WCHAR) - 1] = 0;
			FileObject->FileName.Length -= sizeof(WCHAR);
		}
		if (FileObject->FileName.Buffer[FileObject->FileName.Length / sizeof(WCHAR) - 1] == 92 && FileObject->FileName.Length > 2)
		{
			if (RequestedDisposition & FILE_CREATE && !(options & FILE_DIRECTORY_FILE))
			{
				Status = STATUS_OBJECT_NAME_INVALID;
				goto exit;
			}
			FileObject->FileName.Buffer[FileObject->FileName.Length / sizeof(WCHAR) - 1] = 0;
			FileObject->FileName.Length -= sizeof(WCHAR);
		}
		if (FileObject->FileName.Buffer[FileObject->FileName.Length / sizeof(WCHAR) - 1] == 92 && FileObject->FileName.Length > 2)
		{
			Status = STATUS_OBJECT_NAME_INVALID;
			goto exit;
		}
		if (FileObject->FileName.Buffer[FileObject->FileName.Length / sizeof(WCHAR) - 1] == 42 && FileObject->FileName.Length > 2)
		{
			if (RequestedDisposition & FILE_CREATE)
			{
				Status = STATUS_OBJECT_NAME_INVALID;
				goto exit;
			}
			FileObject->FileName.Buffer[FileObject->FileName.Length / sizeof(WCHAR) - 1] = 0;
			FileObject->FileName.Length -= sizeof(WCHAR);
		}
		if (FileObject->FileName.Buffer[FileObject->FileName.Length / sizeof(WCHAR) - 1] == 92 && FileObject->FileName.Length > 2)
		{
			if (RequestedDisposition & FILE_CREATE && !(options & FILE_DIRECTORY_FILE))
			{
				Status = STATUS_OBJECT_NAME_INVALID;
				goto exit;
			}
			FileObject->FileName.Buffer[FileObject->FileName.Length / sizeof(WCHAR) - 1] = 0;
			FileObject->FileName.Length -= sizeof(WCHAR);
		}
		if (FileObject->FileName.Buffer[0] != *L"\\")
		{
			UNICODE_STRING fn2;
			if (FileObject->RelatedFileObject && FileObject->RelatedFileObject->FileName.Length > 2)
			{
				fn2.Length = FileObject->RelatedFileObject->FileName.Length + FileObject->FileName.Length + sizeof(WCHAR);
				fn2.Buffer = ExAllocatePoolWithTag(pool_type, fn2.Length, ALLOC_TAG);
				if (!fn2.Buffer)
				{
					ERR("out of memory\n");
					Status = STATUS_INSUFFICIENT_RESOURCES;
					goto exit;
				}
				RtlCopyMemory(fn2.Buffer, FileObject->RelatedFileObject->FileName.Buffer, FileObject->RelatedFileObject->FileName.Length);
				fn2.Buffer[FileObject->RelatedFileObject->FileName.Length / sizeof(WCHAR)] = *L"\\";
				RtlCopyMemory(fn2.Buffer + FileObject->RelatedFileObject->FileName.Length / sizeof(WCHAR) + 1, FileObject->FileName.Buffer, FileObject->FileName.Length);
			}
			else
			{
				fn2.Length = FileObject->FileName.Length + sizeof(WCHAR);
				fn2.Buffer = ExAllocatePoolWithTag(pool_type, fn2.Length, ALLOC_TAG);
				if (!fn2.Buffer)
				{
					ERR("out of memory\n");
					Status = STATUS_INSUFFICIENT_RESOURCES;
					goto exit;
				}
				fn2.Buffer[0] = *L"\\";
				RtlCopyMemory(fn2.Buffer + 1, FileObject->FileName.Buffer, FileObject->FileName.Length);
			}
			ExFreePool(FileObject->FileName.Buffer);
			FileObject->FileName = fn2;
		}
		fn = FileObject->FileName;
	}
	else
	{
		fn.Length = sizeof(WCHAR);
		fn.Buffer = ExAllocatePoolWithTag(pool_type, fn.Length, ALLOC_TAG);
		if (!fn.Buffer)
		{
			ERR("out of memory\n");
			Status = STATUS_INSUFFICIENT_RESOURCES;
			goto exit;
		}
		fn.Buffer[0] = *L"\\";
	}

	TRACE("(%.*S)\n", (int)(fn.Length / sizeof(WCHAR)), fn.Buffer);
	TRACE("FileObject = %p\n", FileObject);

	unsigned long lastslash = 0;
	for (unsigned long i = 0; i < fn.Length / sizeof(WCHAR); i++)
	{
		if (fn.Buffer[i] == *L"/" || fn.Buffer[i] == *L"\\")
		{
			lastslash = i;
		}
		if (i - lastslash > MAX_PATH - 5)
		{
			ERR("file name too long\n");
			Status = STATUS_OBJECT_NAME_INVALID;
			goto exit;
		}
	}

	if (Vcb->readonly && (RequestedDisposition == FILE_SUPERSEDE || RequestedDisposition == FILE_CREATE || RequestedDisposition == FILE_OVERWRITE))
	{
		Status = STATUS_MEDIA_WRITE_PROTECTED;
		goto exit;
	}

	if (IrpSp->Flags & SL_OPEN_TARGET_DIRECTORY)
	{
		fn.Length = max(lastslash, 1) * sizeof(WCHAR);
	}

open:
	if (RequestedDisposition == FILE_OPEN || RequestedDisposition == FILE_OPEN_IF || RequestedDisposition == FILE_CREATE)
	{
		index = get_filename_index(fn, &Vcb->vde->pdode->KMCSFS);
		if (index)
		{
			unsigned long winattrs = chwinattrs(index, 0, Vcb->vde->pdode->KMCSFS);
			Status = AccessCheck(Irp, Vcb, &fn, &granted_access);
			if (IrpSp->Parameters.Create.SecurityContext->DesiredAccess & (MAXIMUM_ALLOWED | DELETE | FILE_READ_ATTRIBUTES) && !NT_SUCCESS(Status))
			{
				UNICODE_STRING parentfn;
				parentfn.Length = max(lastslash, 1) * sizeof(WCHAR);
				parentfn.Buffer = fn.Buffer;
				ACCESS_MASK desiredaccess = IrpSp->Parameters.Create.SecurityContext->DesiredAccess;
				ACCESS_MASK parent_granted;
				IrpSp->Parameters.Create.SecurityContext->DesiredAccess = (MAXIMUM_ALLOWED & desiredaccess) ? (FILE_DELETE_CHILD | FILE_LIST_DIRECTORY) : (((DELETE & desiredaccess) ? FILE_DELETE_CHILD : 0) | ((FILE_READ_ATTRIBUTES & desiredaccess) ? FILE_LIST_DIRECTORY : 0));
				Status = AccessCheck(Irp, Vcb, &parentfn, &parent_granted);
				if (parent_granted & FILE_DELETE_CHILD)
				{
					desiredaccess &= ~DELETE;
				}
				if (parent_granted & FILE_LIST_DIRECTORY)
				{
					desiredaccess &= ~FILE_READ_ATTRIBUTES;
				}
				IrpSp->Parameters.Create.SecurityContext->DesiredAccess = desiredaccess;
				Status = AccessCheck(Irp, Vcb, &fn, &granted_access);
				if (parent_granted & FILE_DELETE_CHILD)
				{
					granted_access |= DELETE;
				}
				if (parent_granted & FILE_LIST_DIRECTORY)
				{
					granted_access |= FILE_READ_ATTRIBUTES;
				}
			}
			if (created && !NT_SUCCESS(Status))
			{
				if (has_parent_perm)
				{
					Status = Parent_Status;
					granted_access = IrpSp->Parameters.Create.SecurityContext->DesiredAccess;
				}
				else
				{
					UNICODE_STRING securityfn;
					securityfn.Length = fn.Length - sizeof(WCHAR);
					securityfn.Buffer = fn.Buffer + 1;
					unsigned long long securityindex = get_filename_index(securityfn, &Vcb->vde->pdode->KMCSFS);
					delete_file(&Vcb->vde->pdode->KMCSFS, securityfn, securityindex, FileObject);
					delete_file(&Vcb->vde->pdode->KMCSFS, fn, index, FileObject);
				}
			}
			if (!NT_SUCCESS(Status))
			{
				TRACE("AccessCheck failed, returning %08lx\n", Status);
				goto exit;
			}
			if (winattrs & FILE_ATTRIBUTE_READONLY && !(IrpSp->Flags & SL_IGNORE_READONLY_ATTRIBUTE))
			{
				ACCESS_MASK allowed = READ_CONTROL | SYNCHRONIZE | ACCESS_SYSTEM_SECURITY | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_EXECUTE | FILE_LIST_DIRECTORY | FILE_TRAVERSE;
				if (!Vcb->readonly)
				{
					allowed |= DELETE | WRITE_OWNER | WRITE_DAC | FILE_WRITE_ATTRIBUTES;
					if (winattrs & FILE_ATTRIBUTE_DIRECTORY)
					{
						allowed |= FILE_ADD_SUBDIRECTORY | FILE_ADD_FILE | FILE_DELETE_CHILD;
					}
				}
				granted_access &= allowed;
				IrpSp->Parameters.Create.SecurityContext->AccessState->PreviouslyGrantedAccess &= allowed;
			}
			dindex = FindDictEntry(Vcb->vde->pdode->KMCSFS.dict, Vcb->vde->pdode->KMCSFS.table, Vcb->vde->pdode->KMCSFS.tableend, Vcb->vde->pdode->KMCSFS.DictSize, fn.Buffer, fn.Length / sizeof(WCHAR));
			if (dindex)
			{
				if (Vcb->vde->pdode->KMCSFS.dict[dindex].opencount)
				{
					if (Vcb->vde->pdode->KMCSFS.dict[dindex].delete_pending)
					{
						Status = STATUS_ACCESS_DENIED;
						goto exit;
					}
					Status = IoCheckShareAccess(granted_access, IrpSp->Parameters.Create.ShareAccess, FileObject, &Vcb->vde->pdode->KMCSFS.dict[dindex].shareaccess, false);
					if (!NT_SUCCESS(Status))
					{
						TRACE("IoCheckShareAccess failed, returning %08lx\n", Status);
						goto exit;
					}
					IoUpdateShareAccess(FileObject, &Vcb->vde->pdode->KMCSFS.dict[dindex].shareaccess);
				}
				else
				{
					IoSetShareAccess(granted_access, IrpSp->Parameters.Create.ShareAccess, FileObject, &Vcb->vde->pdode->KMCSFS.dict[dindex].shareaccess);
					FsRtlUninitializeFileLock(&Vcb->vde->pdode->KMCSFS.dict[dindex].lock);
					FsRtlInitializeFileLock(&Vcb->vde->pdode->KMCSFS.dict[dindex].lock, NULL, NULL);
				}
				Vcb->vde->pdode->KMCSFS.dict[dindex].opencount++;
			}
			if (winattrs & FILE_ATTRIBUTE_REPARSE_POINT && !(options & FILE_OPEN_REPARSE_POINT))
			{
				Status = STATUS_REPARSE;
			}
		}
		else
		{
			Status = STATUS_OBJECT_NAME_NOT_FOUND;
		}
	}
	else if (RequestedDisposition == FILE_OVERWRITE || RequestedDisposition == FILE_OVERWRITE_IF || RequestedDisposition == FILE_SUPERSEDE)
	{
		index = get_filename_index(fn, &Vcb->vde->pdode->KMCSFS);
		if (index)
		{
			if (chwinattrs(index, 0, Vcb->vde->pdode->KMCSFS) & FILE_ATTRIBUTE_READONLY && !(IrpSp->Flags & SL_IGNORE_READONLY_ATTRIBUTE))
			{
				Status = STATUS_ACCESS_DENIED;
				goto exit;
			}
			else
			{
				Status = AccessCheck(Irp, Vcb, &fn, &granted_access);
				if (!NT_SUCCESS(Status))
				{
					TRACE("AccessCheck failed, returning %08lx\n", Status);
					goto exit;
				}
				if (options & FILE_DIRECTORY_FILE)
				{
					IrpSp->Parameters.Create.FileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
				}
				else
				{
					IrpSp->Parameters.Create.FileAttributes &= ~FILE_ATTRIBUTE_DIRECTORY;
				}
				granted_access |= FILE_WRITE_DATA;
				IrpSp->Parameters.Create.ShareAccess |= FILE_SHARE_WRITE;
				dindex = FindDictEntry(Vcb->vde->pdode->KMCSFS.dict, Vcb->vde->pdode->KMCSFS.table, Vcb->vde->pdode->KMCSFS.tableend, Vcb->vde->pdode->KMCSFS.DictSize, fn.Buffer, fn.Length / sizeof(WCHAR));
				if (dindex)
				{
					if (Vcb->vde->pdode->KMCSFS.dict[dindex].opencount)
					{
						if (Vcb->vde->pdode->KMCSFS.dict[dindex].delete_pending)
						{
							Status = STATUS_ACCESS_DENIED;
							goto exit;
						}
						Status = IoCheckShareAccess(granted_access, IrpSp->Parameters.Create.ShareAccess, FileObject, &Vcb->vde->pdode->KMCSFS.dict[dindex].shareaccess, false);
						if (!NT_SUCCESS(Status))
						{
							TRACE("IoCheckShareAccess failed, returning %08lx\n", Status);
							goto exit;
						}
						IoUpdateShareAccess(FileObject, &Vcb->vde->pdode->KMCSFS.dict[dindex].shareaccess);
					}
					else
					{
						IoSetShareAccess(granted_access, IrpSp->Parameters.Create.ShareAccess, FileObject, &Vcb->vde->pdode->KMCSFS.dict[dindex].shareaccess);
						FsRtlUninitializeFileLock(&Vcb->vde->pdode->KMCSFS.dict[dindex].lock);
						FsRtlInitializeFileLock(&Vcb->vde->pdode->KMCSFS.dict[dindex].lock, NULL, NULL);
					}
					Vcb->vde->pdode->KMCSFS.dict[dindex].opencount++;
				}
				chwinattrs(index, IrpSp->Parameters.Create.FileAttributes | FILE_ATTRIBUTE_ARCHIVE, Vcb->vde->pdode->KMCSFS);
				dealloc(&Vcb->vde->pdode->KMCSFS, index, get_file_size(index, Vcb->vde->pdode->KMCSFS), 0);

				FsRtlNotifyFullReportChange(Vcb->NotifySync, &Vcb->DirNotifyList, (PSTRING)&fn, (lastslash + 1) * sizeof(WCHAR), NULL, NULL, FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE, FILE_ACTION_MODIFIED, NULL);
			}
		}
		else
		{
			Status = STATUS_OBJECT_NAME_NOT_FOUND;
		}
	}

loaded:
	if (Status == STATUS_REPARSE)
	{
		unsigned long long filesize = get_file_size(index, Vcb->vde->pdode->KMCSFS);
		REPARSE_DATA_BUFFER* data = ExAllocatePoolWithTag(NonPagedPoolNx, filesize, ALLOC_TAG);
		if (!data)
		{
			ERR("out of memory\n");
			Status = STATUS_INSUFFICIENT_RESOURCES;
			goto exit;
		}
		unsigned long long bytes_read = 0;
		fcb* fcb = create_fcb(Vcb, NonPagedPoolNx);
		if (!fcb)
		{
			ERR("out of memory\n");
			ExFreePool(data);
			Status = STATUS_INSUFFICIENT_RESOURCES;
			goto exit;
		}
		read_file(fcb, (uint8_t*)data, 0, filesize, index, &bytes_read, FileObject);
		if (bytes_read != filesize)
		{
			ERR("read_file returned %I64u\n", bytes_read);
			free_fcb(fcb);
			reap_fcb(fcb);
			ExFreePool(data);
			Status = STATUS_INTERNAL_ERROR;
			goto exit;
		}
		free_fcb(fcb);
		reap_fcb(fcb);

		RtlCopyMemory(&Irp->IoStatus.Information, data, sizeof(ULONG));
		Irp->Tail.Overlay.AuxiliaryBuffer = (void*)data;
		goto exit;
	}

	if (NT_SUCCESS(Status))
	{
		if (RequestedDisposition == FILE_CREATE && !created)
		{
			TRACE("file already exists, returning STATUS_OBJECT_NAME_COLLISION\n");
			Status = STATUS_OBJECT_NAME_COLLISION;
			Vcb->vde->pdode->KMCSFS.dict[dindex].opencount--;
			goto exit;
		}
	}
	else if (Status == STATUS_OBJECT_NAME_NOT_FOUND)
	{
		if (RequestedDisposition == FILE_OPEN || RequestedDisposition == FILE_OVERWRITE)
		{
			TRACE("file doesn't exist, returning STATUS_OBJECT_NAME_NOT_FOUND\n");
			goto exit;
		}
	}
	else if (Status == STATUS_OBJECT_PATH_NOT_FOUND || Status == STATUS_OBJECT_NAME_INVALID)
	{
		TRACE("open_fileref returned %08lx\n", Status);
		goto exit;
	}
	else
	{
		ERR("open_fileref returned %08lx\n", Status);
		goto exit;
	}

	if (NT_SUCCESS(Status))
	{
		FileObject->FsContext = create_fcb(Vcb, pool_type);
		if (!FileObject->FsContext)
		{
			ERR("create_fcb returned NULL\n");
			Status = STATUS_INSUFFICIENT_RESOURCES;
			goto exit;
		}

		ccb* ccb = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(*ccb), ALLOC_TAG);
		if (!ccb)
		{
			ERR("out of memory\n");
			Status = STATUS_INSUFFICIENT_RESOURCES;
			goto exit;
		}

		RtlZeroMemory(ccb, sizeof(*ccb));

		ccb->NodeType = KMCSpaceFS_NODE_TYPE_CCB;
		ccb->NodeSize = sizeof(*ccb);
		ccb->disposition = RequestedDisposition;
		ccb->options = options;
		ccb->query_dir_offset = 0;
		ccb->query_dir_index = 0;
		ccb->query_dir_file_count = 0;
		ccb->access = granted_access;
		ccb->filename.Buffer = fn.Buffer;
		ccb->filename.Length = fn.Length;

		InterlockedIncrement(&Vcb->open_files);

		FileObject->FsContext2 = ccb;
		FileObject->SectionObjectPointer = &((fcb*)FileObject->FsContext)->nonpaged->segment_object;

		switch (RequestedDisposition)
		{
		case FILE_SUPERSEDE:
			Irp->IoStatus.Information = FILE_SUPERSEDED;
			break;

		case FILE_OPEN:
		case FILE_OPEN_IF:
			Irp->IoStatus.Information = FILE_OPENED;
			break;

		case FILE_OVERWRITE:
		case FILE_OVERWRITE_IF:
			Irp->IoStatus.Information = FILE_OVERWRITTEN;
			break;
		}

		if (IrpSp->Flags & SL_OPEN_PAGING_FILE)
		{
			((fcb*)FileObject->FsContext)->Header.Flags2 |= FSRTL_FLAG2_IS_PAGING_FILE;
		}
	}
	else
	{
		if (options & FILE_DIRECTORY_FILE)
		{
			IrpSp->Parameters.Create.FileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
		}
		else
		{
			IrpSp->Parameters.Create.FileAttributes &= ~FILE_ATTRIBUTE_DIRECTORY;
		}
		Status = create_file(Irp, Vcb, FileObject, fn);
		if (NT_SUCCESS(Status))
		{
			IrpSp->Parameters.Create.FileAttributes = 0;
			UNICODE_STRING securityfn;
			securityfn.Length = fn.Length - sizeof(WCHAR);
			securityfn.Buffer = fn.Buffer + 1;
			Status = create_file(Irp, Vcb, FileObject, securityfn);
			if (NT_SUCCESS(Status))
			{
				unsigned long long securityindex = get_filename_index(securityfn, &Vcb->vde->pdode->KMCSFS);
				UNICODE_STRING parentsecurityfn;
				parentsecurityfn.Length = (max(lastslash, 1) - 1) * sizeof(WCHAR);
				parentsecurityfn.Buffer = fn.Buffer + 1;
				unsigned long long parentsecurityindex = get_filename_index(parentsecurityfn, &Vcb->vde->pdode->KMCSFS);
				unsigned long long filesize = get_file_size(parentsecurityindex, Vcb->vde->pdode->KMCSFS);
				uint8_t* security = ExAllocatePoolWithTag(NonPagedPoolNx, filesize, ALLOC_TAG);
				if (!security)
				{
					ERR("out of memory\n");
					Status = STATUS_INSUFFICIENT_RESOURCES;
					goto delsecfile;
				}
				unsigned long long bytes_read = 0;
				fcb* fcb = create_fcb(Vcb, NonPagedPoolNx);
				if (!fcb)
				{
					ERR("out of memory\n");
					ExFreePool(security);
					Status = STATUS_INSUFFICIENT_RESOURCES;
					goto delsecfile;
				}
				read_file(fcb, security, 0, filesize, parentsecurityindex, &bytes_read, FileObject);
				if (bytes_read != filesize)
				{
					ERR("read_file returned %I64u\n", bytes_read);
					free_fcb(fcb);
					reap_fcb(fcb);
					ExFreePool(security);
					Status = STATUS_INTERNAL_ERROR;
					goto delsecfile;
				}
				free_fcb(fcb);
				reap_fcb(fcb);
				if (IrpSp->Parameters.Create.SecurityContext->AccessState->SecurityDescriptor)
				{
					WCHAR* securityW = ExAllocatePoolWithTag(NonPagedPoolNx, (filesize + 1) * sizeof(WCHAR), ALLOC_TAG);
					if (!securityW)
					{
						ERR("out of memory\n");
						ExFreePool(security);
						Status = STATUS_INSUFFICIENT_RESOURCES;
						goto delsecfile;
					}
					for (unsigned long long i = 0; i < filesize; i++)
					{
						securityW[i] = security[i];
					}
					securityW[filesize] = 0;
					ExFreePool(security);
					SECURITY_DESCRIPTOR* parent_sec;
					ULONG BufLen;
					if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(securityW, SDDL_REVISION, &parent_sec, &BufLen, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION))
					{
						ERR("out of memory\n");
						ExFreePool(securityW);
						Status = STATUS_INSUFFICIENT_RESOURCES;
						goto delsecfile;
					}
					ExFreePool(securityW);
					SECURITY_DESCRIPTOR* new_sec;
					SeAssignSecurity(parent_sec, IrpSp->Parameters.Create.SecurityContext->AccessState->SecurityDescriptor, &new_sec, options & FILE_DIRECTORY_FILE, &IrpSp->Parameters.Create.SecurityContext->AccessState->SubjectSecurityContext, IoGetFileObjectGenericMapping(), NonPagedPoolNx);
					has_parent_perm = SeAccessCheck(parent_sec, &IrpSp->Parameters.Create.SecurityContext->AccessState->SubjectSecurityContext, false, FILE_ADD_FILE, 0, NULL, IoGetFileObjectGenericMapping(), IrpSp->Flags & SL_FORCE_ACCESS_CHECK ? UserMode : Irp->RequestorMode, &parent_granted_access, &Parent_Status);
					ExFreePool(parent_sec);
					if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(new_sec, SDDL_REVISION, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION, &securityW, &(ULONG)filesize))
					{
						ERR("out of memory\n");
						SeDeassignSecurity(&new_sec);
						Status = STATUS_INSUFFICIENT_RESOURCES;
						goto delsecfile;
					}
					SeDeassignSecurity(&new_sec);
					security = NULL;
					security = ExAllocatePoolWithTag(NonPagedPoolNx, filesize, ALLOC_TAG);
					if (!security)
					{
						ERR("out of memory\n");
						ExFreePool(securityW);
						Status = STATUS_INSUFFICIENT_RESOURCES;
						goto delsecfile;
					}
					for (unsigned long long i = 0; i < filesize; i++)
					{
						security[i] = securityW[i] & 0xff;
					}
					ExFreePool(securityW);
				}
				fcb = create_fcb(Vcb, NonPagedPoolNx);
				if (!fcb)
				{
					ERR("out of memory\n");
					ExFreePool(security);
					Status = STATUS_INSUFFICIENT_RESOURCES;
					goto delsecfile;
				}
				else
				{
					if (find_block(&Vcb->vde->pdode->KMCSFS, securityindex, filesize, FileObject))
					{
						Status = write_file(fcb, security, 0, filesize, securityindex, filesize, FileObject);
					}
					else
					{
						Status = STATUS_DISK_FULL;
					}
					free_fcb(fcb);
					reap_fcb(fcb);
					ExFreePool(security);
				}
delsecfile:
				if (NT_SUCCESS(Status))
				{
					Irp->IoStatus.Information = FILE_CREATED;
					created = true;

					FsRtlNotifyFullReportChange(Vcb->NotifySync, &Vcb->DirNotifyList, (PSTRING)&fn, (lastslash + 1) * sizeof(WCHAR), NULL, NULL, (options & FILE_DIRECTORY_FILE) ? FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME, FILE_ACTION_ADDED, NULL);

					goto open;
				}
				else
				{
					delete_file(&Vcb->vde->pdode->KMCSFS, securityfn, securityindex, FileObject);
				}
			}
			if (!NT_SUCCESS(Status))
			{
				index = get_filename_index(fn, &Vcb->vde->pdode->KMCSFS);
				delete_file(&Vcb->vde->pdode->KMCSFS, fn, index, FileObject);
				goto exit;
			}
		}
	}

	if (NT_SUCCESS(Status) && !(options & FILE_NO_INTERMEDIATE_BUFFERING))
	{
		FileObject->Flags |= FO_CACHE_SUPPORTED;
	}

exit:
	if (Status == STATUS_SUCCESS)
	{
		fcb* fcb2;

		IrpSp->Parameters.Create.SecurityContext->AccessState->PreviouslyGrantedAccess |= granted_access;
		IrpSp->Parameters.Create.SecurityContext->AccessState->RemainingDesiredAccess &= ~(granted_access | MAXIMUM_ALLOWED);

		if (!FileObject->Vpb)
		{
			FileObject->Vpb = DeviceObject->Vpb;
		}

		fcb2 = FileObject->FsContext;
	}
	else if (Status != STATUS_REPARSE && Status != STATUS_OBJECT_NAME_NOT_FOUND && Status != STATUS_OBJECT_PATH_NOT_FOUND)
	{
		TRACE("returning %08lx\n", Status);
	}

	return Status;
}

static NTSTATUS verify_vcb(device_extension* Vcb, PIRP Irp)
{
	NTSTATUS Status;
	LIST_ENTRY* le;
	bool need_verify = false;

	ExAcquireResourceSharedLite(&Vcb->tree_lock, true);

	le = Vcb->devices.Flink;
	while (le != &Vcb->devices)
	{
		device* dev = CONTAINING_RECORD(le, device, list_entry);

		if (dev->devobj && dev->removable)
		{
			ULONG cc;
			IO_STATUS_BLOCK iosb;

			Status = dev_ioctl(dev->devobj, IOCTL_STORAGE_CHECK_VERIFY, NULL, 0, &cc, sizeof(ULONG), true, &iosb);

			if (IoIsErrorUserInduced(Status))
			{
				ERR("IOCTL_STORAGE_CHECK_VERIFY returned %08lx (user-induced)\n", Status);
				need_verify = true;
			}
			else if (!NT_SUCCESS(Status))
			{
				ERR("IOCTL_STORAGE_CHECK_VERIFY returned %08lx\n", Status);
				goto end;
			}
			else if (iosb.Information < sizeof(ULONG))
			{
				ERR("iosb.Information was too short\n");
				Status = STATUS_INTERNAL_ERROR;
			}
			else if (cc != dev->change_count)
			{
				dev->devobj->Flags |= DO_VERIFY_VOLUME;
				need_verify = true;
			}
		}

		le = le->Flink;
	}

	Status = STATUS_SUCCESS;

end:
	ExReleaseResourceLite(&Vcb->tree_lock);

	if (need_verify)
	{
		PDEVICE_OBJECT devobj;

		devobj = IoGetDeviceToVerify(Irp->Tail.Overlay.Thread);
		IoSetDeviceToVerify(Irp->Tail.Overlay.Thread, NULL);

		if (!devobj)
		{
			devobj = IoGetDeviceToVerify(PsGetCurrentThread());
			IoSetDeviceToVerify(PsGetCurrentThread(), NULL);
		}

		devobj = Vcb->Vpb ? Vcb->Vpb->RealDevice : NULL;

		if (devobj)
		{
			Status = IoVerifyVolume(devobj, false);
		}
		else
		{
			Status = STATUS_VERIFY_REQUIRED;
		}
	}

	return Status;
}

static bool has_manage_volume_privilege(ACCESS_STATE* access_state, KPROCESSOR_MODE processor_mode)
{
	PRIVILEGE_SET privset;

	privset.PrivilegeCount = 1;
	privset.Control = PRIVILEGE_SET_ALL_NECESSARY;
	privset.Privilege[0].Luid = RtlConvertLongToLuid(SE_MANAGE_VOLUME_PRIVILEGE);
	privset.Privilege[0].Attributes = 0;

	return SePrivilegeCheck(&privset, &access_state->SubjectSecurityContext, processor_mode) ? true : false;
}

_Dispatch_type_(IRP_MJ_CREATE)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS __stdcall Create(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS Status;
	PIO_STACK_LOCATION IrpSp;
	device_extension* Vcb = DeviceObject->DeviceExtension;
	bool top_level, locked = false;
	oplock_context* opctx = NULL;

	FsRtlEnterFileSystem();
	ExAcquireResourceExclusiveLite(&op_lock, true);

	TRACE("create (flags = %lx)\n", Irp->Flags);

	top_level = is_top_level(Irp);

	/* return success if just called for FS device object */
	if (DeviceObject == devobj)
	{
		TRACE("create called for FS device object\n");

		Irp->IoStatus.Information = FILE_OPENED;
		Status = STATUS_SUCCESS;

		goto exit;
	}
	else if (Vcb && Vcb->type == VCB_TYPE_VOLUME)
	{
		Status = vol_create(DeviceObject, Irp);
		goto exit;
	}
	else if (!Vcb || Vcb->type != VCB_TYPE_FS)
	{
		Status = STATUS_INVALID_PARAMETER;
		goto exit;
	}

	if (!(Vcb->Vpb->Flags & VPB_MOUNTED))
	{
		Status = STATUS_DEVICE_NOT_READY;
		goto exit;
	}

	if (Vcb->removing)
	{
		Status = STATUS_ACCESS_DENIED;
		goto exit;
	}

	Status = verify_vcb(Vcb, Irp);
	if (!NT_SUCCESS(Status))
	{
		ERR("verify_vcb returned %08lx\n", Status);
		goto exit;
	}

	ExAcquireResourceSharedLite(&Vcb->load_lock, true);
	locked = true;

	IrpSp = IoGetCurrentIrpStackLocation(Irp);

	if (IrpSp->Flags != 0)
	{
		uint32_t flags = IrpSp->Flags;

		TRACE("flags:\n");

		if (flags & SL_CASE_SENSITIVE)
		{
			TRACE("SL_CASE_SENSITIVE\n");
			flags &= ~SL_CASE_SENSITIVE;
		}

		if (flags & SL_FORCE_ACCESS_CHECK)
		{
			TRACE("SL_FORCE_ACCESS_CHECK\n");
			flags &= ~SL_FORCE_ACCESS_CHECK;
		}

		if (flags & SL_OPEN_PAGING_FILE)
		{
			TRACE("SL_OPEN_PAGING_FILE\n");
			flags &= ~SL_OPEN_PAGING_FILE;
		}

		if (flags & SL_OPEN_TARGET_DIRECTORY)
		{
			TRACE("SL_OPEN_TARGET_DIRECTORY\n");
			flags &= ~SL_OPEN_TARGET_DIRECTORY;
		}

		if (flags & SL_STOP_ON_SYMLINK)
		{
			TRACE("SL_STOP_ON_SYMLINK\n");
			flags &= ~SL_STOP_ON_SYMLINK;
		}

		if (flags & SL_IGNORE_READONLY_ATTRIBUTE)
		{
			TRACE("SL_IGNORE_READONLY_ATTRIBUTE\n");
			flags &= ~SL_IGNORE_READONLY_ATTRIBUTE;
		}

		if (flags)
		{
			WARN("unknown flags: %x\n", flags);
		}
	}
	else
	{
		TRACE("flags: (none)\n");
	}

	if (!IrpSp->FileObject)
	{
		ERR("FileObject was NULL\n");
		Status = STATUS_INVALID_PARAMETER;
		goto exit;
	}

	if (IrpSp->FileObject->RelatedFileObject)
	{
		fcb* relatedfcb = IrpSp->FileObject->RelatedFileObject->FsContext;

		if (relatedfcb && relatedfcb->Vcb != Vcb)
		{
			WARN("RelatedFileObject was for different device\n");
			Status = STATUS_INVALID_PARAMETER;
			goto exit;
		}
	}

	// opening volume
	if (IrpSp->FileObject->FileName.Length == 0 && !IrpSp->FileObject->RelatedFileObject)
	{
		ULONG RequestedDisposition = ((IrpSp->Parameters.Create.Options >> 24) & 0xff);
		ULONG RequestedOptions = IrpSp->Parameters.Create.Options & FILE_VALID_OPTION_FLAGS;
#ifdef DEBUG_FCB_REFCOUNTS
		LONG rc;
#endif
		ccb* ccb;

		TRACE("open operation for volume\n");

		if (RequestedDisposition != FILE_OPEN && RequestedDisposition != FILE_OPEN_IF)
		{
			Status = STATUS_ACCESS_DENIED;
			goto exit;
		}

		if (RequestedOptions & FILE_DIRECTORY_FILE)
		{
			Status = STATUS_NOT_A_DIRECTORY;
			goto exit;
		}

		ccb = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(*ccb), ALLOC_TAG);
		if (!ccb)
		{
			ERR("out of memory\n");
			Status = STATUS_INSUFFICIENT_RESOURCES;
			goto exit;
		}

		RtlZeroMemory(ccb, sizeof(*ccb));

		ccb->NodeType = KMCSpaceFS_NODE_TYPE_CCB;
		ccb->NodeSize = sizeof(*ccb);
		ccb->disposition = RequestedDisposition;
		ccb->options = RequestedOptions;
		ccb->query_dir_offset = 0;
		ccb->query_dir_index = 0;
		ccb->query_dir_file_count = 0;
		ccb->access = IrpSp->Parameters.Create.SecurityContext->AccessState->PreviouslyGrantedAccess;
		ccb->manage_volume_privilege = has_manage_volume_privilege(IrpSp->Parameters.Create.SecurityContext->AccessState, IrpSp->Flags & SL_FORCE_ACCESS_CHECK ? UserMode : Irp->RequestorMode);

#ifdef DEBUG_FCB_REFCOUNTS
		rc = InterlockedIncrement(&Vcb->volume_fcb->refcount);
		WARN("fcb %p: refcount now %i (volume)\n", Vcb->volume_fcb, rc);
#else
		InterlockedIncrement(&Vcb->volume_fcb->refcount);
#endif
		IrpSp->FileObject->FsContext = Vcb->volume_fcb;
		IrpSp->FileObject->FsContext2 = ccb;

		IrpSp->FileObject->SectionObjectPointer = &Vcb->volume_fcb->nonpaged->segment_object;

		if (!IrpSp->FileObject->Vpb)
		{
			IrpSp->FileObject->Vpb = DeviceObject->Vpb;
		}

		InterlockedIncrement(&Vcb->open_files);

		Irp->IoStatus.Information = FILE_OPENED;
		Status = STATUS_SUCCESS;
	}
	else
	{
		bool skip_lock;

		TRACE("file name: %.*S\n", (int)(IrpSp->FileObject->FileName.Length / sizeof(WCHAR)), IrpSp->FileObject->FileName.Buffer);

		if (IrpSp->FileObject->RelatedFileObject)
		{
			TRACE("related file = %p\n", IrpSp->FileObject->RelatedFileObject);
		}

		// Don't lock again if we're being called from within CcCopyRead etc.
		skip_lock = ExIsResourceAcquiredExclusiveLite(&Vcb->tree_lock);

		if (!skip_lock)
		{
			ExAcquireResourceSharedLite(&Vcb->tree_lock, true);
		}

		Status = open_file(DeviceObject, Vcb, Irp, &opctx);

		if (!skip_lock)
		{
			ExReleaseResourceLite(&Vcb->tree_lock);
		}
	}

exit:
	if (Status != STATUS_PENDING)
	{
		Irp->IoStatus.Status = Status;
		IoCompleteRequest(Irp, NT_SUCCESS(Status) ? IO_DISK_INCREMENT : IO_NO_INCREMENT);
	}

	if (locked)
	{
		ExReleaseResourceLite(&Vcb->load_lock);
	}

	if (Status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&opctx->event, Executive, KernelMode, false, NULL);
		Status = opctx->Status;
		ExFreePool(opctx);
	}

	TRACE("create returning %08lx\n", Status);

	if (top_level)
	{
		IoSetTopLevelIrp(NULL);
	}

	ExReleaseResourceLite(&op_lock);
	FsRtlExitFileSystem();

	return Status;
}
