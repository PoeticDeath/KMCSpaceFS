// Copyright (c) Anthony Kerr 2024-

#include "KMCSpaceFS_drv.h"

static NTSTATUS do_write(device_extension* Vcb, PIRP Irp, bool wait)
{
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	PFILE_OBJECT FileObject = IrpSp->FileObject;
	NTSTATUS Status;

	if (!FileObject)
	{
		ERR("error - FileObject was NULL\n");
		Status = STATUS_ACCESS_DENIED;
		goto exit;
	}

	if (FileObject->Flags & FO_CLEANUP_COMPLETE)
	{
		TRACE("FileObject %p already cleaned up\n", FileObject);
		Status = STATUS_SUCCESS;
		goto exit;
	}

	fcb* fcb = FileObject->FsContext;
	ccb* ccb = FileObject->FsContext2;
	unsigned long long length = IrpSp->Parameters.Write.Length;
	LARGE_INTEGER offset = IrpSp->Parameters.Write.ByteOffset;
	uint8_t* buf;

	if (!Irp->AssociatedIrp.SystemBuffer)
	{
		buf = map_user_buffer(Irp, fcb && fcb->Header.Flags2 & FSRTL_FLAG2_IS_PAGING_FILE ? HighPagePriority : NormalPagePriority);

		if (Irp->MdlAddress && !buf)
		{
			ERR("MmGetSystemAddressForMdlSafe returned NULL\n");
			Status = STATUS_INSUFFICIENT_RESOURCES;
			goto exit;
		}
	}
	else
	{
		buf = Irp->AssociatedIrp.SystemBuffer;
	}

	if (length == 0)
	{
		Status = STATUS_SUCCESS;
		goto exit;
	}

	unsigned long long index = get_filename_index(ccb->filename, &Vcb->vde->pdode->KMCSFS);
	unsigned long long size = get_file_size(index, Vcb->vde->pdode->KMCSFS);

	if (offset.LowPart == FILE_WRITE_TO_END_OF_FILE && offset.HighPart == -1)
	{
		offset.QuadPart = size;
	}
	unsigned long long start = offset.QuadPart;

	if (start + length > size)
	{
		if (find_block(&Vcb->vde->pdode->KMCSFS, index, start + length - size))
		{
			size = start + length;
		}
		else
		{
			Status = STATUS_DISK_FULL;
			goto exit;
		}
	}

	Status = write_file(fcb, buf, start, length, index, size, Irp);

	if (NT_SUCCESS(Status))
	{
		Irp->IoStatus.Information = length;
		if (FileObject->Flags & FO_SYNCHRONOUS_IO && !(Irp->Flags & IRP_PAGING_IO))
		{
			FileObject->CurrentByteOffset.QuadPart = start + length;
		}
	}
	else if (FileObject->Flags & FO_SYNCHRONOUS_IO && !(Irp->Flags & IRP_PAGING_IO))
	{
		FileObject->CurrentByteOffset.QuadPart = start;
	}

exit:
	return Status;
}

_Dispatch_type_(IRP_MJ_WRITE)
_Function_class_(DRIVER_DISPATCH)
__attribute__((nonnull(1,2)))
NTSTATUS __stdcall Write(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS Status = STATUS_INVALID_PARAMETER;
	bool top_level;
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	device_extension* Vcb = DeviceObject->DeviceExtension;
	PFILE_OBJECT FileObject = IrpSp->FileObject;
	fcb* fcb = FileObject ? FileObject->FsContext : NULL;
	ccb* ccb = FileObject ? FileObject->FsContext2 : NULL;
	bool wait = FileObject ? IoIsOperationSynchronous(Irp) : true;

	FsRtlEnterFileSystem();
	ExAcquireResourceExclusiveLite(&op_lock, true);

	top_level = is_top_level(Irp);

	if (Vcb && Vcb->type == VCB_TYPE_VOLUME)
	{
		Status = vol_write(DeviceObject, Irp);
		goto exit;
	}
	else if (!Vcb || Vcb->type != VCB_TYPE_FS)
	{
		Status = STATUS_INVALID_PARAMETER;
		goto end;
	}

	if (!fcb)
	{
		ERR("fcb was NULL\n");
		Status = STATUS_INVALID_PARAMETER;
		goto end;
	}

	if (!ccb)
	{
		ERR("ccb was NULL\n");
		Status = STATUS_INVALID_PARAMETER;
		goto end;
	}

	if (Irp->RequestorMode == UserMode && !(ccb->access & (FILE_WRITE_DATA | FILE_APPEND_DATA)))
	{
		WARN("insufficient permissions\n");
		Status = STATUS_ACCESS_DENIED;
		goto end;
	}

	if (fcb == Vcb->volume_fcb)
	{
		TRACE("writing directly to volume\n");

		IoSkipCurrentIrpStackLocation(Irp);

		Status = IoCallDriver(Vcb->Vpb->RealDevice, Irp);
		goto exit;
	}

	if (Vcb->readonly)
	{
		Status = STATUS_MEDIA_WRITE_PROTECTED;
		goto end;
	}

	unsigned long long dindex = FindDictEntry(Vcb->vde->pdode->KMCSFS.dict, Vcb->vde->pdode->KMCSFS.table, Vcb->vde->pdode->KMCSFS.tableend, Vcb->vde->pdode->KMCSFS.DictSize, ccb->filename.Buffer, ccb->filename.Length / sizeof(WCHAR));
	if (!dindex)
	{
		ERR("failed to find dict entry\n");
		Status = STATUS_SUCCESS;
		goto end;
	}
	if (!wait && !FsRtlCheckLockForWriteAccess(&Vcb->vde->pdode->KMCSFS.dict[dindex].lock, Irp))
	{
		WARN("failed to acquire write lock\n");
		Status = STATUS_FILE_LOCK_CONFLICT;
		goto end;
	}

	try
	{
		// Don't offload jobs when doing paging IO - otherwise this can lead to
		// deadlocks in CcCopyWrite.
		if (Irp->Flags & IRP_PAGING_IO)
		{
			wait = true;
		}

		Status = do_write(Vcb, Irp, wait);
	}
	except(EXCEPTION_EXECUTE_HANDLER)
	{
		Status = GetExceptionCode();
	}

end:
	Irp->IoStatus.Status = Status;

	TRACE("wrote %Iu bytes\n", Irp->IoStatus.Information);

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

exit:
	if (top_level)
	{
		IoSetTopLevelIrp(NULL);
	}

	TRACE("returning %08lx\n", Status);

	ExReleaseResourceLite(&op_lock);
	FsRtlExitFileSystem();

	return Status;
}
