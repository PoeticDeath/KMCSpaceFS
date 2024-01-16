// Copyright (c) Anthony Kerr 2024-

#include "KMCSpaceFS_drv.h"

_Dispatch_type_(IRP_MJ_QUERY_SECURITY)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS __stdcall QuerySecurity(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS Status;
    SECURITY_DESCRIPTOR* sd;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    device_extension* Vcb = DeviceObject->DeviceExtension;
    ULONG buflen;
    bool top_level;
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    ccb* ccb = FileObject ? FileObject->FsContext2 : NULL;

    FsRtlEnterFileSystem();

    TRACE("query security\n");

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

    if (!ccb)
    {
        ERR("no ccb\n");
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    if (Irp->RequestorMode == UserMode && !(ccb->access & READ_CONTROL))
    {
        WARN("insufficient permissions\n");
        Status = STATUS_ACCESS_DENIED;
        goto end;
    }

    Status = STATUS_SUCCESS;

    Irp->IoStatus.Information = 0;

    if (IrpSp->Parameters.QuerySecurity.SecurityInformation & OWNER_SECURITY_INFORMATION)
    {
        TRACE("OWNER_SECURITY_INFORMATION\n");
    }

    if (IrpSp->Parameters.QuerySecurity.SecurityInformation & GROUP_SECURITY_INFORMATION)
    {
        TRACE("GROUP_SECURITY_INFORMATION\n");
    }

    if (IrpSp->Parameters.QuerySecurity.SecurityInformation & DACL_SECURITY_INFORMATION)
    {
        TRACE("DACL_SECURITY_INFORMATION\n");
    }

    if (IrpSp->Parameters.QuerySecurity.SecurityInformation & SACL_SECURITY_INFORMATION)
    {
        TRACE("SACL_SECURITY_INFORMATION\n");
    }

    TRACE("length = %lu\n", IrpSp->Parameters.QuerySecurity.Length);

    sd = map_user_buffer(Irp, NormalPagePriority);
    TRACE("sd = %p\n", sd);

    if (Irp->MdlAddress && !sd)
    {
        ERR("MmGetSystemAddressForMdlSafe returned NULL\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }

    buflen = IrpSp->Parameters.QuerySecurity.Length;

    UNICODE_STRING securityfile;
    securityfile.Length = ccb->filename.Length - sizeof(WCHAR);
    securityfile.Buffer = ccb->filename.Buffer + 1;
    unsigned long long index = get_filename_index(securityfile, Vcb->vde->pdode->KMCSFS);
    unsigned long long filesize = get_file_size(index, Vcb->vde->pdode->KMCSFS);
    char* security = ExAllocatePoolWithTag(NonPagedPool, filesize, ALLOC_TAG);
    if (!security)
    {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    unsigned long long bytes_read = 0;
    fcb* fcb = create_fcb(Vcb, NonPagedPool);
    if (!fcb)
    {
        ERR("out of memory\n");
        ExFreePool(security);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    PIRP Irp2 = IoAllocateIrp(Vcb->vde->pdode->KMCSFS.DeviceObject->StackSize, false);
    if (!Irp2)
    {
        ERR("out of memory\n");
        free_fcb(fcb);
        reap_fcb(fcb);
        ExFreePool(security);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    Irp2->Flags |= IRP_NOCACHE;
    read_file(fcb, security, 0, filesize, index, &bytes_read, Irp2, Vcb->vde->pdode->KMCSFS.DeviceObject);
    if (bytes_read != filesize)
    {
        ERR("read_file returned %I64u\n", bytes_read);
        IoFreeIrp(Irp2);
        free_fcb(fcb);
        reap_fcb(fcb);
        ExFreePool(security);
        return STATUS_INTERNAL_ERROR;
    }

    // Convert string to security descriptor

    IoFreeIrp(Irp2);
    free_fcb(fcb);
    reap_fcb(fcb);
    ExFreePool(security);

    if (NT_SUCCESS(Status))
    {
        Irp->IoStatus.Information = IrpSp->Parameters.QuerySecurity.Length;
    }
    else if (Status == STATUS_BUFFER_TOO_SMALL)
    {
        Irp->IoStatus.Information = buflen;
        Status = STATUS_BUFFER_OVERFLOW;
    }
    else
    {
        Irp->IoStatus.Information = 0;
    }

end:
    TRACE("Irp->IoStatus.Information = %Iu\n", Irp->IoStatus.Information);

    Irp->IoStatus.Status = Status;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    if (top_level)
    {
        IoSetTopLevelIrp(NULL);
    }

    TRACE("returning %08lx\n", Status);

    FsRtlExitFileSystem();

    return Status;
}
