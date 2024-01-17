// Copyright (c) Anthony Kerr 2024-

#include "KMCSpaceFS_drv.h"

static NTSTATUS do_read(PIRP Irp, bool wait, unsigned long long* bytes_read)
{
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	PFILE_OBJECT FileObject = IrpSp->FileObject;
	fcb* fcb = FileObject->FsContext;
	ccb* ccb = FileObject->FsContext2;
	uint8_t* data = NULL;
	NTSTATUS Status = STATUS_INVALID_PARAMETER;
	unsigned long long length = IrpSp->Parameters.Read.Length;
	unsigned long long start = IrpSp->Parameters.Read.ByteOffset.QuadPart;

	*bytes_read = 0;

	if (!fcb || !fcb->Vcb || !ccb)
	{
		return STATUS_INTERNAL_ERROR;
	}

	TRACE("fcb = %p\n", fcb);
	TRACE("offset = %I64x, length = %lx\n", start, length);
	TRACE("paging_io = %s, no cache = %s\n", Irp->Flags & IRP_PAGING_IO ? "true" : "false", Irp->Flags & IRP_NOCACHE ? "true" : "false");

	unsigned long long index = get_filename_index(ccb->filename, fcb->Vcb->vde->pdode->KMCSFS);

	if (chwinattrs(index, 0, fcb->Vcb->vde->pdode->KMCSFS) & FILE_ATTRIBUTE_DIRECTORY)
	{
		TRACE("tried to read a directory\n");
		return STATUS_INVALID_DEVICE_REQUEST;
	}

	if (length == 0)
	{
		TRACE("tried to read zero bytes\n");
		return STATUS_SUCCESS;
	}

	unsigned long long size = get_file_size(index, fcb->Vcb->vde->pdode->KMCSFS);

	if (start >= size)
	{
		TRACE("tried to read with offset after file end (%I64x >= %I64x)\n", start, size);
		return STATUS_END_OF_FILE;
	}

	TRACE("FileObject %p fcb %p FileSize = %I64x\n", FileObject, fcb, size);

	data = map_user_buffer(Irp, fcb->Header.Flags2 & FSRTL_FLAG2_IS_PAGING_FILE ? HighPagePriority : NormalPagePriority);

	if (Irp->MdlAddress && !data)
	{
		ERR("MmGetSystemAddressForMdlSafe returned NULL\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	if (length + start >= size)
	{
		length = size - start;
	}

	Status = read_file(fcb, data, start, length, index, bytes_read, Irp);

	TRACE("read %lu bytes\n", *bytes_read);

	Irp->IoStatus.Information = *bytes_read;

	return Status;
}

_Dispatch_type_(IRP_MJ_READ)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS __stdcall Read(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	device_extension* Vcb = DeviceObject->DeviceExtension;
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	PFILE_OBJECT FileObject = IrpSp->FileObject;
	unsigned long long bytes_read = 0;
	NTSTATUS Status = STATUS_INVALID_PARAMETER;
	bool top_level;
	fcb* fcb;
	ccb* ccb;
	bool acquired_fcb_lock = false, wait;

	FsRtlEnterFileSystem();

	top_level = is_top_level(Irp);

	TRACE("read\n");

	if (Vcb && Vcb->type == VCB_TYPE_VOLUME)
	{
		Status = vol_read(DeviceObject, Irp);
		goto exit2;
	}
	else if (!Vcb || Vcb->type != VCB_TYPE_FS)
	{
		goto end;
	}

	Irp->IoStatus.Information = 0;

	fcb = FileObject->FsContext;

	if (!fcb)
	{
		ERR("fcb was NULL\n");
		Status = STATUS_INVALID_PARAMETER;
		goto exit;
	}

	ccb = FileObject->FsContext2;

	if (!ccb)
	{
		ERR("ccb was NULL\n");
		Status = STATUS_INVALID_PARAMETER;
		goto exit;
	}

	if (Irp->RequestorMode == UserMode && !(ccb->access & FILE_READ_DATA))
	{
		WARN("insufficient privileges\n");
		Status = STATUS_ACCESS_DENIED;
		goto exit;
	}

	if (fcb == Vcb->volume_fcb)
	{
		TRACE("reading volume FCB\n");

		IoSkipCurrentIrpStackLocation(Irp);

		Status = IoCallDriver(Vcb->Vpb->RealDevice, Irp);

		goto exit2;
	}

	wait = IoIsOperationSynchronous(Irp);

	// Don't offload jobs when doing paging IO - otherwise this can lead to
	// deadlocks in CcCopyRead.
	if (Irp->Flags & IRP_PAGING_IO)
	{
		wait = true;
	}

	if (!(Irp->Flags & IRP_PAGING_IO) && FileObject->SectionObjectPointer && FileObject->SectionObjectPointer->DataSectionObject)
	{
		IO_STATUS_BLOCK iosb;

		CcFlushCache(FileObject->SectionObjectPointer, &IrpSp->Parameters.Read.ByteOffset, IrpSp->Parameters.Read.Length, &iosb);
		if (!NT_SUCCESS(iosb.Status))
		{
			ERR("CcFlushCache returned %08lx\n", iosb.Status);
			Status = iosb.Status;
			goto exit;
		}
	}

	if (!ExIsResourceAcquiredSharedLite(fcb->Header.Resource))
	{
		if (!ExAcquireResourceSharedLite(fcb->Header.Resource, wait))
		{
			Status = STATUS_PENDING;
			IoMarkIrpPending(Irp);
			goto exit;
		}

		acquired_fcb_lock = true;
	}

	Status = do_read(Irp, wait, &bytes_read);

	if (acquired_fcb_lock)
	{
		ExReleaseResourceLite(fcb->Header.Resource);
	}

exit:
	if (FileObject->Flags & FO_SYNCHRONOUS_IO && !(Irp->Flags & IRP_PAGING_IO))
	{
		FileObject->CurrentByteOffset.QuadPart = IrpSp->Parameters.Read.ByteOffset.QuadPart + (NT_SUCCESS(Status) ? bytes_read : 0);
	}

end:
	Irp->IoStatus.Status = Status;

	TRACE("Irp->IoStatus.Status = %081x\n", Irp->IoStatus.Status);
	TRACE("Irp->IoStatus.Information = %Iu\n", Irp->IoStatus.Information);

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

exit2:
	if (top_level)
	{
		IoSetTopLevelIrp(NULL);
	}

	FsRtlExitFileSystem();

	return Status;
}
