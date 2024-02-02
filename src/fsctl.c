// Copyright (c) Anthony Kerr 2024-

#include "KMCSpaceFS_drv.h"

#ifndef FSCTL_CSV_CONTROL
#define FSCTL_CSV_CONTROL CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 181, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#ifndef FSCTL_QUERY_VOLUME_CONTAINER_STATE
#define FSCTL_QUERY_VOLUME_CONTAINER_STATE CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 228, METHOD_BUFFERED, FILE_ANY_ACCESS)
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
        WARN("STUB: FSCTL_IS_VOLUME_MOUNTED\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
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
        WARN("STUB: FSCTL_FILESYSTEM_GET_STATISTICS\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
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
        Status = STATUS_INVALID_DEVICE_REQUEST;
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
        TRACE("STUB: FSCTL_QUERY_VOLUME_CONTAINER_STATE\n");
        Status = STATUS_INVALID_DEVICE_REQUEST;
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
