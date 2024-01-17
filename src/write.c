// Copyright (c) Anthony Kerr 2024-

#include "KMCSpaceFS_drv.h"

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

	try
	{
		// Don't offload jobs when doing paging IO - otherwise this can lead to
		// deadlocks in CcCopyWrite.
		if (Irp->Flags & IRP_PAGING_IO)
		{
			wait = true;
		}

		//Status = write_file(Vcb, Irp, wait, false);
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

	FsRtlExitFileSystem();

	return Status;
}
