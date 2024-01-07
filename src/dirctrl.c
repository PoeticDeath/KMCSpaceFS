// Copyright (c) Anthony Kerr 2024-

#include "KMCSpaceFS_drv.h"

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

    unsigned long long index = get_filename_index(ccb->filename, Vcb->vde->pdode->KMCSFS);
    if (!(chwinattrs(index, 0, Vcb->vde->pdode->KMCSFS) & FILE_ATTRIBUTE_DIRECTORY))
    {
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    // FIXME - raise exception if FCB marked for deletion?

    TRACE("FileObject %p\n", FileObject);

    FsRtlNotifyFilterChangeDirectory(Vcb->NotifySync, &Vcb->DirNotifyList, FileObject->FsContext2, (PSTRING)&ccb->filename, IrpSp->Flags & SL_WATCH_TREE, false, IrpSp->Parameters.NotifyDirectory.CompletionFilter, Irp, NULL, NULL, NULL);

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

    //case IRP_MN_QUERY_DIRECTORY:
    //    Status = query_directory(Irp);
    //    break;

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

    FsRtlExitFileSystem();

    return Status;
}
