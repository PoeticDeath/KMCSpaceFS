//Copyright (c) Anthony Kerr 2024-

#include <sys/stat.h>
#include "KMCSpaceFS_drv.h"
#include <ntddstor.h>

extern PDEVICE_OBJECT devobj;

static const WCHAR datastring[] = L"::$DATA";

static const char root_dir[] = "$Root";
static const WCHAR root_dir_utf16[] = L"$Root";

typedef struct _FILE_TIMESTAMPS
{
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
} FILE_TIMESTAMPS, * PFILE_TIMESTAMPS;

static const GUID GUID_ECP_ATOMIC_CREATE = {0x4720bd83, 0x52ac, 0x4104, {0xa1, 0x30, 0xd1, 0xec, 0x6a, 0x8c, 0xc8, 0xe5}};
static const GUID GUID_ECP_QUERY_ON_CREATE = {0x1aca62e9, 0xabb4, 0x4ff2, {0xbb, 0x5c, 0x1c, 0x79, 0x02, 0x5e, 0x41, 0x7f}};
static const GUID GUID_ECP_CREATE_REDIRECTION = {0x188d6bd6, 0xa126, 0x4fa8, {0xbd, 0xf2, 0x1c, 0xcd, 0xf8, 0x96, 0xf3, 0xe0}};

typedef struct
{
    device_extension* Vcb;
    ACCESS_MASK granted_access;
    file_ref* fileref;
    NTSTATUS Status;
    KEVENT event;
} oplock_context;

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

        ccb = ExAllocatePoolWithTag(NonPagedPool, sizeof(*ccb), ALLOC_TAG);
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
    /*else
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

        ExAcquireResourceSharedLite(&Vcb->fileref_lock, true);

        Status = open_file(DeviceObject, Vcb, Irp, &opctx);

        ExReleaseResourceLite(&Vcb->fileref_lock);

        if (!skip_lock)
        {
            ExReleaseResourceLite(&Vcb->tree_lock);
        }
    }*/

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

    FsRtlExitFileSystem();

    return Status;
}
