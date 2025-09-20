// Copyright (c) Anthony Kerr 2025-

#include "KMCSpaceFS_drv.h"

FAST_IO_DISPATCH FastIoDispatch;

_Function_class_(FAST_IO_QUERY_BASIC_INFO)
static BOOLEAN __stdcall fast_query_basic_info(PFILE_OBJECT FileObject, BOOLEAN wait, PFILE_BASIC_INFORMATION fbi, PIO_STATUS_BLOCK IoStatus, PDEVICE_OBJECT DeviceObject)
{
    fcb* fcb;
    ccb* ccb;

    UNUSED(DeviceObject);

    FsRtlEnterFileSystem();

    TRACE("(%p, %u, %p, %p, %p)\n", FileObject, wait, fbi, IoStatus, DeviceObject);

    if (!FileObject)
    {
        FsRtlExitFileSystem();
        return false;
    }

    fcb = FileObject->FsContext;

    if (!fcb)
    {
        FsRtlExitFileSystem();
        return false;
    }

    ccb = FileObject->FsContext2;

    if (!ccb)
    {
        FsRtlExitFileSystem();
        return false;
    }

    if (!(ccb->access & (FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES)))
    {
        FsRtlExitFileSystem();
        return false;
    }

    if (!ExAcquireResourceSharedLite(fcb->Header.Resource, wait))
    {
        FsRtlExitFileSystem();
        return false;
    }

    UNICODE_STRING nostream_fn;
    nostream_fn.Buffer = ccb->filename->Buffer;
    nostream_fn.Length = 0;
    for (unsigned long i = 0; i < ccb->filename->Length / sizeof(WCHAR); i++)
    {
        if (ccb->filename->Buffer[i] == *L":")
        {
            nostream_fn.Length = i * sizeof(WCHAR);
            break;
        }
    }
    unsigned long long nostream_index = get_filename_index(nostream_fn, &fcb->Vcb->vde->pdode->KMCSFS);
    if (!nostream_index)
    {
		nostream_index = get_filename_index(*ccb->filename, &fcb->Vcb->vde->pdode->KMCSFS);
    }

    fbi->CreationTime.QuadPart = chtime(nostream_index, 0, 4, fcb->Vcb->vde->pdode->KMCSFS);
    fbi->LastAccessTime.QuadPart = chtime(nostream_index, 0, 0, fcb->Vcb->vde->pdode->KMCSFS);
    fbi->LastWriteTime.QuadPart = chtime(nostream_index, 0, 2, fcb->Vcb->vde->pdode->KMCSFS);
    fbi->ChangeTime.QuadPart = fbi->LastWriteTime.QuadPart;

    unsigned long winattrs = chwinattrs(nostream_index, 0, fcb->Vcb->vde->pdode->KMCSFS);
    fbi->FileAttributes = !winattrs ? FILE_ATTRIBUTE_NORMAL : winattrs;

    IoStatus->Status = STATUS_SUCCESS;
    IoStatus->Information = sizeof(FILE_BASIC_INFORMATION);

    ExReleaseResourceLite(fcb->Header.Resource);

    FsRtlExitFileSystem();

    return true;
}

_Function_class_(FAST_IO_QUERY_STANDARD_INFO)
static BOOLEAN __stdcall fast_query_standard_info(PFILE_OBJECT FileObject, BOOLEAN wait, PFILE_STANDARD_INFORMATION fsi, PIO_STATUS_BLOCK IoStatus, PDEVICE_OBJECT DeviceObject)
{
    fcb* fcb;
    ccb* ccb;

    UNUSED(DeviceObject);

    FsRtlEnterFileSystem();

    TRACE("(%p, %u, %p, %p, %p)\n", FileObject, wait, fsi, IoStatus, DeviceObject);

    if (!FileObject)
    {
        FsRtlExitFileSystem();
        return false;
    }

    fcb = FileObject->FsContext;
    ccb = FileObject->FsContext2;

    if (!fcb)
    {
        FsRtlExitFileSystem();
        return false;
    }

    if (!ExAcquireResourceSharedLite(fcb->Header.Resource, wait))
    {
        FsRtlExitFileSystem();
        return false;
    }

	unsigned long long index = get_filename_index(*ccb->filename, &fcb->Vcb->vde->pdode->KMCSFS);
    unsigned long long dindex = FindDictEntry(fcb->Vcb->vde->pdode->KMCSFS.dict, fcb->Vcb->vde->pdode->KMCSFS.table, fcb->Vcb->vde->pdode->KMCSFS.tableend, fcb->Vcb->vde->pdode->KMCSFS.DictSize, ccb->filename->Buffer, ccb->filename->Length / sizeof(WCHAR));

    fsi->EndOfFile.QuadPart = get_file_size(index, fcb->Vcb->vde->pdode->KMCSFS);
    fsi->AllocationSize.QuadPart = sector_align(fsi->EndOfFile.QuadPart, fcb->Vcb->vde->pdode->KMCSFS.sectorsize);
    fsi->NumberOfLinks = 1;
    fsi->DeletePending = fcb->Vcb->vde->pdode->KMCSFS.dict[dindex].flags & delete_pending;
    fsi->Directory = chwinattrs(index, 0, fcb->Vcb->vde->pdode->KMCSFS) & FILE_ATTRIBUTE_DIRECTORY;

    IoStatus->Status = STATUS_SUCCESS;
    IoStatus->Information = sizeof(FILE_STANDARD_INFORMATION);

    ExReleaseResourceLite(fcb->Header.Resource);

    FsRtlExitFileSystem();

    return true;
}

_Function_class_(FAST_IO_CHECK_IF_POSSIBLE)
static BOOLEAN __stdcall fast_io_check_if_possible(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length, BOOLEAN Wait, ULONG LockKey, BOOLEAN CheckForReadOperation, PIO_STATUS_BLOCK IoStatus, PDEVICE_OBJECT DeviceObject)
{
    fcb* fcb = FileObject->FsContext;
	ccb* ccb = FileObject->FsContext2;
    LARGE_INTEGER len2;

    UNUSED(Wait);
    UNUSED(IoStatus);
    UNUSED(DeviceObject);

    len2.QuadPart = Length;

    unsigned long long dindex = FindDictEntry(fcb->Vcb->vde->pdode->KMCSFS.dict, fcb->Vcb->vde->pdode->KMCSFS.table, fcb->Vcb->vde->pdode->KMCSFS.tableend, fcb->Vcb->vde->pdode->KMCSFS.DictSize, ccb->filename->Buffer, ccb->filename->Length / sizeof(WCHAR));

    if (CheckForReadOperation)
    {
        if (FsRtlFastCheckLockForRead(&fcb->Vcb->vde->pdode->KMCSFS.dict[dindex].lock, FileOffset, &len2, LockKey, FileObject, PsGetCurrentProcess()))
        {
            return true;
        }
    }
    else
    {
        if (!fcb->Vcb->readonly && FsRtlFastCheckLockForWrite(&fcb->Vcb->vde->pdode->KMCSFS.dict[dindex].lock, FileOffset, &len2, LockKey, FileObject, PsGetCurrentProcess()))
        {
            return true;
        }
    }

    return false;
}

_Function_class_(FAST_IO_QUERY_NETWORK_OPEN_INFO)
static BOOLEAN __stdcall fast_io_query_network_open_info(PFILE_OBJECT FileObject, BOOLEAN Wait, FILE_NETWORK_OPEN_INFORMATION* fnoi, PIO_STATUS_BLOCK IoStatus, PDEVICE_OBJECT DeviceObject)
{
    fcb* fcb;
    ccb* ccb;

    UNUSED(Wait);
    UNUSED(IoStatus); // FIXME - really? What about IoStatus->Information?
    UNUSED(DeviceObject);

    FsRtlEnterFileSystem();

    TRACE("(%p, %u, %p, %p, %p)\n", FileObject, Wait, fnoi, IoStatus, DeviceObject);

    RtlZeroMemory(fnoi, sizeof(FILE_NETWORK_OPEN_INFORMATION));

    fcb = FileObject->FsContext;

    if (!fcb || fcb == fcb->Vcb->volume_fcb)
    {
        FsRtlExitFileSystem();
        return false;
    }

    ccb = FileObject->FsContext2;

    if (!ccb)
    {
        FsRtlExitFileSystem();
        return false;
    }

	unsigned long long index = get_filename_index(*ccb->filename, &fcb->Vcb->vde->pdode->KMCSFS);

    UNICODE_STRING nostream_fn;
    nostream_fn.Buffer = ccb->filename->Buffer;
    nostream_fn.Length = 0;
    for (unsigned long i = 0; i < ccb->filename->Length / sizeof(WCHAR); i++)
    {
        if (ccb->filename->Buffer[i] == *L":")
        {
            nostream_fn.Length = i * sizeof(WCHAR);
            break;
        }
    }
    unsigned long long nostream_index = get_filename_index(nostream_fn, &fcb->Vcb->vde->pdode->KMCSFS);
    if (!nostream_index)
    {
        nostream_index = index;
    }

    fnoi->CreationTime.QuadPart = chtime(nostream_index, 0, 4, fcb->Vcb->vde->pdode->KMCSFS);
    fnoi->LastAccessTime.QuadPart = chtime(nostream_index, 0, 0, fcb->Vcb->vde->pdode->KMCSFS);
    fnoi->LastWriteTime.QuadPart = chtime(nostream_index, 0, 2, fcb->Vcb->vde->pdode->KMCSFS);
    fnoi->ChangeTime.QuadPart = fnoi->LastWriteTime.QuadPart;

    fnoi->EndOfFile.QuadPart = get_file_size(index, fcb->Vcb->vde->pdode->KMCSFS);
    fnoi->AllocationSize.QuadPart = sector_align(fnoi->EndOfFile.QuadPart, fcb->Vcb->vde->pdode->KMCSFS.sectorsize);
	unsigned long winattrs = chwinattrs(nostream_index, 0, fcb->Vcb->vde->pdode->KMCSFS);
    fnoi->FileAttributes = !winattrs ? FILE_ATTRIBUTE_NORMAL : winattrs;

    FsRtlExitFileSystem();

    return true;
}

_Function_class_(FAST_IO_ACQUIRE_FOR_MOD_WRITE)
static NTSTATUS __stdcall fast_io_acquire_for_mod_write(PFILE_OBJECT FileObject, PLARGE_INTEGER EndingOffset, struct _ERESOURCE** ResourceToRelease, PDEVICE_OBJECT DeviceObject)
{
    fcb* fcb;

    TRACE("(%p, %I64x, %p, %p)\n", FileObject, EndingOffset ? EndingOffset->QuadPart : 0, ResourceToRelease, DeviceObject);

    UNUSED(EndingOffset);
    UNUSED(DeviceObject);

    fcb = FileObject->FsContext;

    if (!fcb)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // Make sure we don't get interrupted by the flush thread, which can cause a deadlock

    if (!ExAcquireResourceSharedLite(&fcb->Vcb->tree_lock, false))
    {
        return STATUS_CANT_WAIT;
    }

    if (!ExAcquireResourceExclusiveLite(fcb->Header.Resource, false))
    {
        ExReleaseResourceLite(&fcb->Vcb->tree_lock);
        TRACE("returning STATUS_CANT_WAIT\n");
        return STATUS_CANT_WAIT;
    }

    // Ideally this would be PagingIoResource, but that doesn't play well with copy-on-write,
    // as we can't guarantee that we won't need to do any reallocations.

    *ResourceToRelease = fcb->Header.Resource;

    TRACE("returning STATUS_SUCCESS\n");

    return STATUS_SUCCESS;
}

_Function_class_(FAST_IO_RELEASE_FOR_MOD_WRITE)
static NTSTATUS __stdcall fast_io_release_for_mod_write(PFILE_OBJECT FileObject, struct _ERESOURCE* ResourceToRelease, PDEVICE_OBJECT DeviceObject)
{
    fcb* fcb;

    TRACE("(%p, %p, %p)\n", FileObject, ResourceToRelease, DeviceObject);

    UNUSED(DeviceObject);

    fcb = FileObject->FsContext;

    ExReleaseResourceLite(ResourceToRelease);

    ExReleaseResourceLite(&fcb->Vcb->tree_lock);

    return STATUS_SUCCESS;
}

_Function_class_(FAST_IO_ACQUIRE_FOR_CCFLUSH)
static NTSTATUS __stdcall fast_io_acquire_for_ccflush(PFILE_OBJECT FileObject, PDEVICE_OBJECT DeviceObject)
{
    UNUSED(FileObject);
    UNUSED(DeviceObject);

    IoSetTopLevelIrp((PIRP)FSRTL_CACHE_TOP_LEVEL_IRP);

    return STATUS_SUCCESS;
}

_Function_class_(FAST_IO_RELEASE_FOR_CCFLUSH)
static NTSTATUS __stdcall fast_io_release_for_ccflush(PFILE_OBJECT FileObject, PDEVICE_OBJECT DeviceObject)
{
    UNUSED(FileObject);
    UNUSED(DeviceObject);

    if (IoGetTopLevelIrp() == (PIRP)FSRTL_CACHE_TOP_LEVEL_IRP)
    {
        IoSetTopLevelIrp(NULL);
    }

    return STATUS_SUCCESS;
}

_Function_class_(FAST_IO_WRITE)
static BOOLEAN __stdcall fast_io_write(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length, BOOLEAN Wait, ULONG LockKey, PVOID Buffer, PIO_STATUS_BLOCK IoStatus, PDEVICE_OBJECT DeviceObject)
{
    fcb* fcb = FileObject->FsContext;
    bool ret;

    FsRtlEnterFileSystem();

    if (!ExAcquireResourceSharedLite(&fcb->Vcb->tree_lock, Wait))
    {
        FsRtlExitFileSystem();
        return false;
    }

    ret = FsRtlCopyWrite(FileObject, FileOffset, Length, Wait, LockKey, Buffer, IoStatus, DeviceObject);

    ExReleaseResourceLite(&fcb->Vcb->tree_lock);

    FsRtlExitFileSystem();

    return ret;
}

_Function_class_(FAST_IO_LOCK)
static BOOLEAN __stdcall fast_io_lock(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, PLARGE_INTEGER Length, PEPROCESS ProcessId, ULONG Key, BOOLEAN FailImmediately, BOOLEAN ExclusiveLock, PIO_STATUS_BLOCK IoStatus, PDEVICE_OBJECT DeviceObject)
{
    BOOLEAN ret;
    fcb* fcb = FileObject->FsContext;
	ccb* ccb = FileObject->FsContext2;

    UNUSED(DeviceObject);

    TRACE("(%p, %I64x, %I64x, %p, %lx, %u, %u, %p, %p)\n", FileObject, FileOffset ? FileOffset->QuadPart : 0, Length ? Length->QuadPart : 0, ProcessId, Key, FailImmediately, ExclusiveLock, IoStatus, DeviceObject);

	unsigned long long index = get_filename_index(*ccb->filename, &fcb->Vcb->vde->pdode->KMCSFS);
	unsigned long long winattrs = chwinattrs(index, 0, fcb->Vcb->vde->pdode->KMCSFS);

    if (winattrs & FILE_ATTRIBUTE_DIRECTORY)
    {
        WARN("can only lock files\n");
        IoStatus->Status = STATUS_INVALID_PARAMETER;
        IoStatus->Information = 0;
        return true;
    }

    FsRtlEnterFileSystem();
    ExAcquireResourceSharedLite(fcb->Header.Resource, true);

	unsigned long long dindex = FindDictEntry(fcb->Vcb->vde->pdode->KMCSFS.dict, fcb->Vcb->vde->pdode->KMCSFS.table, fcb->Vcb->vde->pdode->KMCSFS.tableend, fcb->Vcb->vde->pdode->KMCSFS.DictSize, ccb->filename->Buffer, ccb->filename->Length / sizeof(WCHAR));
    ret = FsRtlFastLock(&fcb->Vcb->vde->pdode->KMCSFS.dict[dindex].lock, FileObject, FileOffset, Length, ProcessId, Key, FailImmediately, ExclusiveLock, IoStatus, NULL, false);

    ExReleaseResourceLite(fcb->Header.Resource);
    FsRtlExitFileSystem();

    return ret;
}

_Function_class_(FAST_IO_UNLOCK_SINGLE)
static BOOLEAN __stdcall fast_io_unlock_single(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, PLARGE_INTEGER Length, PEPROCESS ProcessId, ULONG Key, PIO_STATUS_BLOCK IoStatus, PDEVICE_OBJECT DeviceObject)
{
    fcb* fcb = FileObject->FsContext;
	ccb* ccb = FileObject->FsContext2;

    UNUSED(DeviceObject);

    TRACE("(%p, %I64x, %I64x, %p, %lx, %p, %p)\n", FileObject, FileOffset ? FileOffset->QuadPart : 0, Length ? Length->QuadPart : 0, ProcessId, Key, IoStatus, DeviceObject);

    IoStatus->Information = 0;

	unsigned long long index = get_filename_index(*ccb->filename, &fcb->Vcb->vde->pdode->KMCSFS);
	unsigned long long winattrs = chwinattrs(index, 0, fcb->Vcb->vde->pdode->KMCSFS);

    if (winattrs & FILE_ATTRIBUTE_DIRECTORY)
    {
        WARN("can only lock files\n");
        IoStatus->Status = STATUS_INVALID_PARAMETER;
        return true;
    }

    FsRtlEnterFileSystem();

	unsigned long long dindex = FindDictEntry(fcb->Vcb->vde->pdode->KMCSFS.dict, fcb->Vcb->vde->pdode->KMCSFS.table, fcb->Vcb->vde->pdode->KMCSFS.tableend, fcb->Vcb->vde->pdode->KMCSFS.DictSize, ccb->filename->Buffer, ccb->filename->Length / sizeof(WCHAR));
    IoStatus->Status = FsRtlFastUnlockSingle(&fcb->Vcb->vde->pdode->KMCSFS.dict[dindex].lock, FileObject, FileOffset, Length, ProcessId, Key, NULL, false);

    fcb->Header.IsFastIoPossible = fcb->Vcb->readonly ? FastIoIsNotPossible : FastIoIsPossible;

    FsRtlExitFileSystem();

    return true;
}

_Function_class_(FAST_IO_UNLOCK_ALL)
static BOOLEAN __stdcall fast_io_unlock_all(PFILE_OBJECT FileObject, PEPROCESS ProcessId, PIO_STATUS_BLOCK IoStatus, PDEVICE_OBJECT DeviceObject)
{
    fcb* fcb = FileObject->FsContext;
	ccb* ccb = FileObject->FsContext2;

    UNUSED(DeviceObject);

    TRACE("(%p, %p, %p, %p)\n", FileObject, ProcessId, IoStatus, DeviceObject);

    IoStatus->Information = 0;

	unsigned long long index = get_filename_index(*ccb->filename, &fcb->Vcb->vde->pdode->KMCSFS);
	unsigned long long winattrs = chwinattrs(index, 0, fcb->Vcb->vde->pdode->KMCSFS);

    if (winattrs & FILE_ATTRIBUTE_DIRECTORY)
    {
        WARN("can only lock files\n");
        IoStatus->Status = STATUS_INVALID_PARAMETER;
        return true;
    }

    FsRtlEnterFileSystem();

    ExAcquireResourceSharedLite(fcb->Header.Resource, true);

	unsigned long long dindex = FindDictEntry(fcb->Vcb->vde->pdode->KMCSFS.dict, fcb->Vcb->vde->pdode->KMCSFS.table, fcb->Vcb->vde->pdode->KMCSFS.tableend, fcb->Vcb->vde->pdode->KMCSFS.DictSize, ccb->filename->Buffer, ccb->filename->Length / sizeof(WCHAR));
    IoStatus->Status = FsRtlFastUnlockAll(&fcb->Vcb->vde->pdode->KMCSFS.dict[dindex].lock, FileObject, ProcessId, NULL);

	fcb->Header.IsFastIoPossible = fcb->Vcb->readonly ? FastIoIsNotPossible : FastIoIsPossible;

    ExReleaseResourceLite(fcb->Header.Resource);

    FsRtlExitFileSystem();

    return true;
}

_Function_class_(FAST_IO_UNLOCK_ALL_BY_KEY)
static BOOLEAN __stdcall fast_io_unlock_all_by_key(PFILE_OBJECT FileObject, PVOID ProcessId, ULONG Key, PIO_STATUS_BLOCK IoStatus, PDEVICE_OBJECT DeviceObject)
{
    fcb* fcb = FileObject->FsContext;
	ccb* ccb = FileObject->FsContext2;

    UNUSED(DeviceObject);

    TRACE("(%p, %p, %lx, %p, %p)\n", FileObject, ProcessId, Key, IoStatus, DeviceObject);

    IoStatus->Information = 0;

	unsigned long long index = get_filename_index(*ccb->filename, &fcb->Vcb->vde->pdode->KMCSFS);
	unsigned long long winattrs = chwinattrs(index, 0, fcb->Vcb->vde->pdode->KMCSFS);

    if (winattrs & FILE_ATTRIBUTE_DIRECTORY)
    {
        WARN("can only lock files\n");
        IoStatus->Status = STATUS_INVALID_PARAMETER;
        return true;
    }

    FsRtlEnterFileSystem();

    ExAcquireResourceSharedLite(fcb->Header.Resource, true);

	unsigned long long dindex = FindDictEntry(fcb->Vcb->vde->pdode->KMCSFS.dict, fcb->Vcb->vde->pdode->KMCSFS.table, fcb->Vcb->vde->pdode->KMCSFS.tableend, fcb->Vcb->vde->pdode->KMCSFS.DictSize, ccb->filename->Buffer, ccb->filename->Length / sizeof(WCHAR));
    IoStatus->Status = FsRtlFastUnlockAllByKey(&fcb->Vcb->vde->pdode->KMCSFS.dict[dindex].lock, FileObject, ProcessId, Key, NULL);

	fcb->Header.IsFastIoPossible = fcb->Vcb->readonly ? FastIoIsNotPossible : FastIoIsPossible;

    ExReleaseResourceLite(fcb->Header.Resource);

    FsRtlExitFileSystem();

    return true;
}

static void __stdcall fast_io_acquire_for_create_section(_In_ PFILE_OBJECT FileObject)
{
    fcb* fcb;

    TRACE("(%p)\n", FileObject);

    if (!FileObject)
    {
        return;
    }

    fcb = FileObject->FsContext;

    if (!fcb)
    {
        return;
    }

    ExAcquireResourceSharedLite(&fcb->Vcb->tree_lock, true);
    ExAcquireResourceExclusiveLite(fcb->Header.Resource, true);
}

static void __stdcall fast_io_release_for_create_section(_In_ PFILE_OBJECT FileObject)
{
    fcb* fcb;

    TRACE("(%p)\n", FileObject);

    if (!FileObject)
    {
        return;
    }

    fcb = FileObject->FsContext;

    if (!fcb)
    {
        return;
    }

    ExReleaseResourceLite(fcb->Header.Resource);
    ExReleaseResourceLite(&fcb->Vcb->tree_lock);
}

void init_fast_io_dispatch(FAST_IO_DISPATCH** fiod)
{
    RtlZeroMemory(&FastIoDispatch, sizeof(FastIoDispatch));

    FastIoDispatch.SizeOfFastIoDispatch = sizeof(FAST_IO_DISPATCH);

    FastIoDispatch.FastIoCheckIfPossible = fast_io_check_if_possible;
    FastIoDispatch.FastIoRead = FsRtlCopyRead;
    FastIoDispatch.FastIoWrite = fast_io_write;
    FastIoDispatch.FastIoQueryBasicInfo = fast_query_basic_info;
    FastIoDispatch.FastIoQueryStandardInfo = fast_query_standard_info;
    FastIoDispatch.FastIoLock = fast_io_lock;
    FastIoDispatch.FastIoUnlockSingle = fast_io_unlock_single;
    FastIoDispatch.FastIoUnlockAll = fast_io_unlock_all;
    FastIoDispatch.FastIoUnlockAllByKey = fast_io_unlock_all_by_key;
    FastIoDispatch.AcquireFileForNtCreateSection = fast_io_acquire_for_create_section;
    FastIoDispatch.ReleaseFileForNtCreateSection = fast_io_release_for_create_section;
    FastIoDispatch.FastIoQueryNetworkOpenInfo = fast_io_query_network_open_info;
    FastIoDispatch.AcquireForModWrite = fast_io_acquire_for_mod_write;
    FastIoDispatch.MdlRead = FsRtlMdlReadDev;
    FastIoDispatch.MdlReadComplete = FsRtlMdlReadCompleteDev;
    FastIoDispatch.PrepareMdlWrite = FsRtlPrepareMdlWriteDev;
    FastIoDispatch.MdlWriteComplete = FsRtlMdlWriteCompleteDev;
    FastIoDispatch.ReleaseForModWrite = fast_io_release_for_mod_write;
    FastIoDispatch.AcquireForCcFlush = fast_io_acquire_for_ccflush;
    FastIoDispatch.ReleaseForCcFlush = fast_io_release_for_ccflush;

    *fiod = &FastIoDispatch;
}