// Copyright (c) Anthony Kerr 2024-

#include "KMCSpaceFS_drv.h"
#include <ntdddisk.h>

#ifndef FSCTL_CSV_CONTROL
#define FSCTL_CSV_CONTROL CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 181, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#ifndef FSCTL_QUERY_VOLUME_CONTAINER_STATE
#define FSCTL_QUERY_VOLUME_CONTAINER_STATE CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 228, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#ifndef FSCTL_QUERY_VOLUME_CONTAINER_STATE2
#define FSCTL_QUERY_VOLUME_CONTAINER_STATE2 0x9023c //CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 572, METHOD_BUFFERED, FILE_ANY_ACCESS) This should work but doesn't...
#endif

#ifndef FSCTL_GET_INTEGRITY_INFORMATION
#define FSCTL_GET_INTEGRITY_INFORMATION CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 159, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#ifndef FSCTL_SET_INTEGRITY_INFORMATION
#define FSCTL_SET_INTEGRITY_INFORMATION CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 160, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#endif

#ifndef FSCTL_DUPLICATE_EXTENTS_TO_FILE
#define FSCTL_DUPLICATE_EXTENTS_TO_FILE CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 209, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#endif

static NTSTATUS is_volume_mounted(device_extension* Vcb, PIRP Irp)
{
    NTSTATUS Status;
    ULONG cc;
    IO_STATUS_BLOCK iosb;
    bool verify = false;
    LIST_ENTRY* le;

    ExAcquireResourceSharedLite(&Vcb->tree_lock, true);

    le = Vcb->devices.Flink;
    while (le != &Vcb->devices)
    {
        device* dev = CONTAINING_RECORD(le, device, list_entry);

        if (dev->devobj && dev->removable)
        {
            Status = dev_ioctl(dev->devobj, IOCTL_STORAGE_CHECK_VERIFY, NULL, 0, &cc, sizeof(ULONG), false, &iosb);

            if (iosb.Information != sizeof(ULONG))
            {
                cc = 0;
            }

            if (Status == STATUS_VERIFY_REQUIRED || (NT_SUCCESS(Status) && cc != dev->change_count))
            {
                dev->devobj->Flags |= DO_VERIFY_VOLUME;
                verify = true;
            }

            if (NT_SUCCESS(Status) && iosb.Information == sizeof(ULONG))
            {
                dev->change_count = cc;
            }

            if (!NT_SUCCESS(Status) || verify)
            {
                IoSetHardErrorOrVerifyDevice(Irp, dev->devobj);
                ExReleaseResourceLite(&Vcb->tree_lock);

                return verify ? STATUS_VERIFY_REQUIRED : Status;
            }
        }

        le = le->Flink;
    }

    ExReleaseResourceLite(&Vcb->tree_lock);

    return STATUS_SUCCESS;
}

static NTSTATUS fs_get_statistics(void* buffer, DWORD buflen, ULONG_PTR* retlen)
{
    FILESYSTEM_STATISTICS* fss;

    WARN("STUB: FSCTL_FILESYSTEM_GET_STATISTICS\n");

    // This is hideously wrong, but at least it stops SMB from breaking

    if (buflen < sizeof(FILESYSTEM_STATISTICS))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    fss = buffer;
    RtlZeroMemory(fss, sizeof(FILESYSTEM_STATISTICS));

    fss->Version = 1;
    fss->FileSystemType = FILESYSTEM_STATISTICS_TYPE_NTFS;
    fss->SizeOfCompleteStructure = sizeof(FILESYSTEM_STATISTICS);

    *retlen = sizeof(FILESYSTEM_STATISTICS);

    return STATUS_SUCCESS;
}

static NTSTATUS fs_control_query_persistent_volume_state(void* buffer, DWORD inbuflen, DWORD outbuflen, ULONG_PTR* retlen)
{
	FILE_FS_PERSISTENT_VOLUME_INFORMATION* info;

    if (!buffer)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (sizeof(FILE_FS_PERSISTENT_VOLUME_INFORMATION) > inbuflen || sizeof(FILE_FS_PERSISTENT_VOLUME_INFORMATION) > outbuflen)
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

    info = buffer;
    if (info->Version != 1 || !(info->FlagMask & PERSISTENT_VOLUME_STATE_SHORT_NAME_CREATION_DISABLED))
    {
		return STATUS_INVALID_PARAMETER;
	}

    RtlZeroMemory(info, sizeof(FILE_FS_PERSISTENT_VOLUME_INFORMATION));
    info->VolumeFlags = PERSISTENT_VOLUME_STATE_SHORT_NAME_CREATION_DISABLED;

    *retlen = sizeof(FILE_FS_PERSISTENT_VOLUME_INFORMATION);

	return STATUS_SUCCESS;
}

static NTSTATUS get_reparse_point(PFILE_OBJECT FileObject, void* buffer, DWORD buflen, ULONG_PTR* retlen)
{
    if (!FileObject)
    {
        return STATUS_INVALID_PARAMETER;
    }
    ccb* ccb = FileObject->FsContext2;
    fcb* fcb = FileObject->FsContext;
    unsigned long long index = get_filename_index(ccb->filename, &fcb->Vcb->vde->pdode->KMCSFS);
    unsigned long winattrs = chwinattrs(index, 0, fcb->Vcb->vde->pdode->KMCSFS);
    if (winattrs & FILE_ATTRIBUTE_REPARSE_POINT)
	{
		unsigned long long filesize = get_file_size(index, fcb->Vcb->vde->pdode->KMCSFS);
		if (buflen < filesize)
		{
			return STATUS_BUFFER_OVERFLOW;
		}
		*retlen = filesize;
        PIRP Irp2 = IoAllocateIrp(fcb->Vcb->vde->pdode->KMCSFS.DeviceObject->StackSize, false);
        if (!Irp2)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}
        Irp2->Flags = IRP_NOCACHE;
        unsigned long long bytes_read = 0;
        read_file(fcb, buffer, 0, filesize, index, &bytes_read, Irp2);
        if (bytes_read != filesize)
        {
            return STATUS_INTERNAL_ERROR;
        }
		return STATUS_SUCCESS;
	}
    else
	{
        return STATUS_NOT_A_REPARSE_POINT;
	}
}

static void update_volumes(device_extension* Vcb)
{
	LIST_ENTRY* le;
	volume_device_extension* vde = Vcb->vde;
	pdo_device_extension* pdode = vde->pdode;

	ExAcquireResourceSharedLite(&Vcb->tree_lock, true);

	ExAcquireResourceExclusiveLite(&pdode->child_lock, true);

	le = pdode->children.Flink;
	while (le != &pdode->children)
	{
		volume_child* vc = CONTAINING_RECORD(le, volume_child, list_entry);

		le = le->Flink;
	}

	ExReleaseResourceLite(&pdode->child_lock);

	ExReleaseResourceLite(&Vcb->tree_lock);
}

NTSTATUS dismount_volume(device_extension* Vcb, bool shutdown, PIRP Irp)
{
	NTSTATUS Status;
	bool open_files;

	TRACE("FSCTL_DISMOUNT_VOLUME\n");

	if (!(Vcb->Vpb->Flags & VPB_MOUNTED))
	{
		return STATUS_SUCCESS;
	}

	if (!shutdown)
	{
		if (Vcb->disallow_dismount || Vcb->page_file_count != 0)
		{
			WARN("attempting to dismount boot volume or one containing a pagefile\n");
			return STATUS_ACCESS_DENIED;
		}

		Status = FsRtlNotifyVolumeEvent(Vcb->root_file, FSRTL_VOLUME_DISMOUNT);
		if (!NT_SUCCESS(Status))
		{
			WARN("FsRtlNotifyVolumeEvent returned %08lx\n", Status);
		}
	}

	ExAcquireResourceExclusiveLite(&Vcb->tree_lock, true);

	Vcb->removing = true;

	open_files = Vcb->open_files > 0;

	if (Vcb->vde)
	{
		update_volumes(Vcb);
		Vcb->vde->mounted_device = NULL;
	}

	ExReleaseResourceLite(&Vcb->tree_lock);

	if (!open_files)
	{
		uninit(Vcb);
	}

	return STATUS_SUCCESS;
}

NTSTATUS fsctl_request(PDEVICE_OBJECT DeviceObject, PIRP* Pirp, uint32_t type)
{
    PIRP Irp = *Pirp;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status;

    switch (type)
    {
    case FSCTL_REQUEST_OPLOCK_LEVEL_1:
    case FSCTL_REQUEST_OPLOCK_LEVEL_2:
    case FSCTL_REQUEST_BATCH_OPLOCK:
    case FSCTL_OPLOCK_BREAK_ACKNOWLEDGE:
    case FSCTL_OPBATCH_ACK_CLOSE_PENDING:
    case FSCTL_OPLOCK_BREAK_NOTIFY:
    case FSCTL_OPLOCK_BREAK_ACK_NO_2:
    case FSCTL_REQUEST_FILTER_OPLOCK:
    case FSCTL_REQUEST_OPLOCK:
        WARN("STUB: FSCTL_REQUEST_OPLOCK\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_LOCK_VOLUME:
        WARN("STUB: FSCTL_LOCK_VOLUME\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_UNLOCK_VOLUME:
        WARN("STUB: FSCTL_UNLOCK_VOLUME\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_DISMOUNT_VOLUME:
        Status = dismount_volume(DeviceObject->DeviceExtension, false, Irp);
        break;

    case FSCTL_IS_VOLUME_MOUNTED:
        Status = is_volume_mounted(DeviceObject->DeviceExtension, Irp);
        break;

    case FSCTL_IS_PATHNAME_VALID:
        WARN("STUB: FSCTL_IS_PATHNAME_VALID\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_MARK_VOLUME_DIRTY:
        WARN("STUB: FSCTL_MARK_VOLUME_DIRTY\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_QUERY_RETRIEVAL_POINTERS:
        WARN("STUB: FSCTL_QUERY_RETRIEVAL_POINTERS\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_GET_COMPRESSION:
        WARN("STUB: FSCTL_GET_COMPRESSION\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_SET_COMPRESSION:
        WARN("STUB: FSCTL_SET_COMPRESSION\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_SET_BOOTLOADER_ACCESSED:
        WARN("STUB: FSCTL_SET_BOOTLOADER_ACCESSED\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_INVALIDATE_VOLUMES:
        WARN("STUB: FSCTL_INVALIDATE_VOLUMES\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_QUERY_FAT_BPB:
        WARN("STUB: FSCTL_QUERY_FAT_BPB\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_FILESYSTEM_GET_STATISTICS:
        Status = fs_get_statistics(Irp->AssociatedIrp.SystemBuffer, IrpSp->Parameters.FileSystemControl.OutputBufferLength, &Irp->IoStatus.Information);
        break;

    case FSCTL_GET_NTFS_VOLUME_DATA:
        WARN("STUB: FSCTL_GET_NTFS_VOLUME_DATA\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_GET_NTFS_FILE_RECORD:
        WARN("STUB: FSCTL_GET_NTFS_FILE_RECORD\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_GET_VOLUME_BITMAP:
        WARN("STUB: FSCTL_GET_VOLUME_BITMAP\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_GET_RETRIEVAL_POINTERS:
        WARN("STUB: FSCTL_GET_RETRIEVAL_POINTERS\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_MOVE_FILE:
        WARN("STUB: FSCTL_MOVE_FILE\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_IS_VOLUME_DIRTY:
        WARN("STUB: FSCTL_IS_VOLUME_DIRTY\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_ALLOW_EXTENDED_DASD_IO:
        WARN("STUB: FSCTL_ALLOW_EXTENDED_DASD_IO\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_FIND_FILES_BY_SID:
        WARN("STUB: FSCTL_FIND_FILES_BY_SID\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_SET_OBJECT_ID:
        WARN("STUB: FSCTL_SET_OBJECT_ID\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_GET_OBJECT_ID:
        WARN("STUB: FSCTL_GET_OBJECT_ID\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_DELETE_OBJECT_ID:
        WARN("STUB: FSCTL_DELETE_OBJECT_ID\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_SET_REPARSE_POINT:
        WARN("STUB: FSCTL_SET_REPARSE_POINT\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_GET_REPARSE_POINT:
        WARN("STUB: FSCTL_GET_REPARSE_POINT\n");
        Status = get_reparse_point(IrpSp->FileObject, Irp->AssociatedIrp.SystemBuffer, IrpSp->Parameters.FileSystemControl.OutputBufferLength, &Irp->IoStatus.Information);
        break;

    case FSCTL_DELETE_REPARSE_POINT:
        WARN("STUB: FSCTL_DELETE_REPARSE_POINT\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_ENUM_USN_DATA:
        WARN("STUB: FSCTL_ENUM_USN_DATA\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_SECURITY_ID_CHECK:
        WARN("STUB: FSCTL_SECURITY_ID_CHECK\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_READ_USN_JOURNAL:
        WARN("STUB: FSCTL_READ_USN_JOURNAL\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_SET_OBJECT_ID_EXTENDED:
        WARN("STUB: FSCTL_SET_OBJECT_ID_EXTENDED\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_CREATE_OR_GET_OBJECT_ID:
        WARN("STUB: FSCTL_CREATE_OR_GET_OBJECT_ID\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_SET_SPARSE:
        WARN("STUB: FSCTL_SET_SPARSE\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_SET_ZERO_DATA:
        WARN("STUB: FSCTL_SET_ZERO_DATA\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_QUERY_ALLOCATED_RANGES:
        WARN("STUB: FSCTL_QUERY_ALLOCATED_RANGES\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_ENABLE_UPGRADE:
        WARN("STUB: FSCTL_ENABLE_UPGRADE\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_SET_ENCRYPTION:
        WARN("STUB: FSCTL_SET_ENCRYPTION\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_ENCRYPTION_FSCTL_IO:
        WARN("STUB: FSCTL_ENCRYPTION_FSCTL_IO\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_WRITE_RAW_ENCRYPTED:
        WARN("STUB: FSCTL_WRITE_RAW_ENCRYPTED\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_READ_RAW_ENCRYPTED:
        WARN("STUB: FSCTL_READ_RAW_ENCRYPTED\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_CREATE_USN_JOURNAL:
        WARN("STUB: FSCTL_CREATE_USN_JOURNAL\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_READ_FILE_USN_DATA:
        WARN("STUB: FSCTL_READ_FILE_USN_DATA\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_WRITE_USN_CLOSE_RECORD:
        WARN("STUB: FSCTL_WRITE_USN_CLOSE_RECORD\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_EXTEND_VOLUME:
        WARN("STUB: FSCTL_EXTEND_VOLUME\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_QUERY_USN_JOURNAL:
        WARN("STUB: FSCTL_QUERY_USN_JOURNAL\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_DELETE_USN_JOURNAL:
        WARN("STUB: FSCTL_DELETE_USN_JOURNAL\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_MARK_HANDLE:
        WARN("STUB: FSCTL_MARK_HANDLE\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_SIS_COPYFILE:
        WARN("STUB: FSCTL_SIS_COPYFILE\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_SIS_LINK_FILES:
        WARN("STUB: FSCTL_SIS_LINK_FILES\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_RECALL_FILE:
        WARN("STUB: FSCTL_RECALL_FILE\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_READ_FROM_PLEX:
        WARN("STUB: FSCTL_READ_FROM_PLEX\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_FILE_PREFETCH:
        WARN("STUB: FSCTL_FILE_PREFETCH\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

#if _WIN32_WINNT >= 0x0600
    case FSCTL_MAKE_MEDIA_COMPATIBLE:
        WARN("STUB: FSCTL_MAKE_MEDIA_COMPATIBLE\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_SET_DEFECT_MANAGEMENT:
        WARN("STUB: FSCTL_SET_DEFECT_MANAGEMENT\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_QUERY_SPARING_INFO:
        WARN("STUB: FSCTL_QUERY_SPARING_INFO\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_QUERY_ON_DISK_VOLUME_INFO:
        WARN("STUB: FSCTL_QUERY_ON_DISK_VOLUME_INFO\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_SET_VOLUME_COMPRESSION_STATE:
        WARN("STUB: FSCTL_SET_VOLUME_COMPRESSION_STATE\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_TXFS_MODIFY_RM:
        WARN("STUB: FSCTL_TXFS_MODIFY_RM\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_TXFS_QUERY_RM_INFORMATION:
        WARN("STUB: FSCTL_TXFS_QUERY_RM_INFORMATION\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_TXFS_ROLLFORWARD_REDO:
        WARN("STUB: FSCTL_TXFS_ROLLFORWARD_REDO\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_TXFS_ROLLFORWARD_UNDO:
        WARN("STUB: FSCTL_TXFS_ROLLFORWARD_UNDO\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_TXFS_START_RM:
        WARN("STUB: FSCTL_TXFS_START_RM\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_TXFS_SHUTDOWN_RM:
        WARN("STUB: FSCTL_TXFS_SHUTDOWN_RM\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_TXFS_READ_BACKUP_INFORMATION:
        WARN("STUB: FSCTL_TXFS_READ_BACKUP_INFORMATION\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_TXFS_WRITE_BACKUP_INFORMATION:
        WARN("STUB: FSCTL_TXFS_WRITE_BACKUP_INFORMATION\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_TXFS_CREATE_SECONDARY_RM:
        WARN("STUB: FSCTL_TXFS_CREATE_SECONDARY_RM\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_TXFS_GET_METADATA_INFO:
        WARN("STUB: FSCTL_TXFS_GET_METADATA_INFO\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_TXFS_GET_TRANSACTED_VERSION:
        WARN("STUB: FSCTL_TXFS_GET_TRANSACTED_VERSION\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_TXFS_SAVEPOINT_INFORMATION:
        WARN("STUB: FSCTL_TXFS_SAVEPOINT_INFORMATION\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_TXFS_CREATE_MINIVERSION:
        WARN("STUB: FSCTL_TXFS_CREATE_MINIVERSION\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_TXFS_TRANSACTION_ACTIVE:
        WARN("STUB: FSCTL_TXFS_TRANSACTION_ACTIVE\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_SET_ZERO_ON_DEALLOCATION:
        WARN("STUB: FSCTL_SET_ZERO_ON_DEALLOCATION\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_SET_REPAIR:
        WARN("STUB: FSCTL_SET_REPAIR\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_GET_REPAIR:
        WARN("STUB: FSCTL_GET_REPAIR\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_WAIT_FOR_REPAIR:
        WARN("STUB: FSCTL_WAIT_FOR_REPAIR\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_INITIATE_REPAIR:
        WARN("STUB: FSCTL_INITIATE_REPAIR\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_CSC_INTERNAL:
        WARN("STUB: FSCTL_CSC_INTERNAL\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_SHRINK_VOLUME:
        WARN("STUB: FSCTL_SHRINK_VOLUME\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_SET_SHORT_NAME_BEHAVIOR:
        WARN("STUB: FSCTL_SET_SHORT_NAME_BEHAVIOR\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_DFSR_SET_GHOST_HANDLE_STATE:
        WARN("STUB: FSCTL_DFSR_SET_GHOST_HANDLE_STATE\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_TXFS_LIST_TRANSACTION_LOCKED_FILES:
        WARN("STUB: FSCTL_TXFS_LIST_TRANSACTION_LOCKED_FILES\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_TXFS_LIST_TRANSACTIONS:
        WARN("STUB: FSCTL_TXFS_LIST_TRANSACTIONS\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_QUERY_PAGEFILE_ENCRYPTION:
        WARN("STUB: FSCTL_QUERY_PAGEFILE_ENCRYPTION\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_RESET_VOLUME_ALLOCATION_HINTS:
        WARN("STUB: FSCTL_RESET_VOLUME_ALLOCATION_HINTS\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_TXFS_READ_BACKUP_INFORMATION2:
        WARN("STUB: FSCTL_TXFS_READ_BACKUP_INFORMATION2\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_CSV_CONTROL:
        WARN("STUB: FSCTL_CSV_CONTROL\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;
#endif

    // TRACE rather than WARN because Windows 10 spams this undocumented fsctl
    case FSCTL_QUERY_VOLUME_CONTAINER_STATE:
    case FSCTL_QUERY_VOLUME_CONTAINER_STATE2:
        Status = fs_control_query_persistent_volume_state(Irp->AssociatedIrp.SystemBuffer, IrpSp->Parameters.FileSystemControl.InputBufferLength, IrpSp->Parameters.FileSystemControl.OutputBufferLength, &Irp->IoStatus.Information);
        break;

    case FSCTL_GET_INTEGRITY_INFORMATION:
        WARN("STUB: FSCTL_GET_INTEGRITY_INFORMATION\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_SET_INTEGRITY_INFORMATION:
        WARN("STUB: FSCTL_SET_INTEGRITY_INFORMATION\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    case FSCTL_DUPLICATE_EXTENTS_TO_FILE:
        WARN("STUB: FSCTL_DUPLICATE_EXTENTS_TO_FILE\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;

    default:
        WARN("unknown control code %lx (DeviceType = %lx, Access = %lx, Function = %lx, Method = %lx)\n", IrpSp->Parameters.FileSystemControl.FsControlCode, (IrpSp->Parameters.FileSystemControl.FsControlCode & 0xff0000) >> 16, (IrpSp->Parameters.FileSystemControl.FsControlCode & 0xc000) >> 14, (IrpSp->Parameters.FileSystemControl.FsControlCode & 0x3ffc) >> 2, IrpSp->Parameters.FileSystemControl.FsControlCode & 0x3);
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    return Status;
}
