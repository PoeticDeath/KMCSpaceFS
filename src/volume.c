// Copyright (c) Anthony Kerr 2023-

#include "KMCSpaceFS_drv.h"
#include <mountdev.h>
#include <ntddvol.h>
#include <ntddstor.h>
#include <ntdddisk.h>
#include <wdmguid.h>

#define IOCTL_VOLUME_IS_DYNAMIC  CTL_CODE(IOCTL_VOLUME_BASE, 18, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VOLUME_POST_ONLINE CTL_CODE(IOCTL_VOLUME_BASE, 25, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

extern PDRIVER_OBJECT drvobj;
extern PDEVICE_OBJECT devobj;
extern PDEVICE_OBJECT busobj;
extern ERESOURCE pdo_list_lock;
extern LIST_ENTRY pdo_list;
extern UNICODE_STRING registry_path;
extern tIoUnregisterPlugPlayNotificationEx fIoUnregisterPlugPlayNotificationEx;

NTSTATUS mountmgr_add_drive_letter(PDEVICE_OBJECT mountmgr, PUNICODE_STRING devpath)
{
    NTSTATUS Status;
    ULONG mmdltsize;
    MOUNTMGR_DRIVE_LETTER_TARGET* mmdlt;
    MOUNTMGR_DRIVE_LETTER_INFORMATION mmdli;

    mmdltsize = (ULONG)offsetof(MOUNTMGR_DRIVE_LETTER_TARGET, DeviceName[0]) + devpath->Length;

    mmdlt = ExAllocatePoolWithTag(NonPagedPool, mmdltsize, ALLOC_TAG);
    if (!mmdlt)
    {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    mmdlt->DeviceNameLength = devpath->Length;
    RtlCopyMemory(&mmdlt->DeviceName, devpath->Buffer, devpath->Length);
    TRACE("mmdlt = %.*S\n", (int)(mmdlt->DeviceNameLength / sizeof(WCHAR)), mmdlt->DeviceName);

    Status = dev_ioctl(mountmgr, IOCTL_MOUNTMGR_NEXT_DRIVE_LETTER, mmdlt, mmdltsize, &mmdli, sizeof(MOUNTMGR_DRIVE_LETTER_INFORMATION), false, NULL);

    if (!NT_SUCCESS(Status))
    {
        ERR("IOCTL_MOUNTMGR_NEXT_DRIVE_LETTER returned %08lx\n", Status);
    }
    else
    {
        TRACE("DriveLetterWasAssigned = %u, CurrentDriveLetter = %c\n", mmdli.DriveLetterWasAssigned, mmdli.CurrentDriveLetter);
    }

    ExFreePool(mmdlt);

    return Status;
}

_Function_class_(DRIVER_NOTIFICATION_CALLBACK_ROUTINE)
NTSTATUS __stdcall pnp_removal(PVOID NotificationStructure, PVOID Context)
{
    TARGET_DEVICE_REMOVAL_NOTIFICATION* tdrn = (TARGET_DEVICE_REMOVAL_NOTIFICATION*)NotificationStructure;
    pdo_device_extension* pdode = (pdo_device_extension*)Context;

    if (RtlCompareMemory(&tdrn->Event, &GUID_TARGET_DEVICE_QUERY_REMOVE, sizeof(GUID)) == sizeof(GUID))
    {
        TRACE("GUID_TARGET_DEVICE_QUERY_REMOVE\n");

        if (pdode->vde && pdode->vde->mounted_device)
        {
            pnp_query_remove_device(pdode->vde->mounted_device, NULL);
        }
    }

    return STATUS_SUCCESS;
}

typedef struct
{
    LIST_ENTRY list_entry;
    UNICODE_STRING name;
    NTSTATUS Status;
    unsigned long sectorsize;
    unsigned long tablesize;
    unsigned long long extratablesize;
    unsigned long long filenamesend;
    unsigned long long tableend;
} drive_letter_removal;

static void drive_letter_callback2(pdo_device_extension* pdode, PDEVICE_OBJECT mountmgr)
{
    LIST_ENTRY* le;
    LIST_ENTRY dlrlist;

    InitializeListHead(&dlrlist);

    ExAcquireResourceExclusiveLite(&pdode->child_lock, true);

    le = pdode->children.Flink;

    while (le != &pdode->children)
    {
        drive_letter_removal* dlr;

        volume_child* vc = CONTAINING_RECORD(le, volume_child, list_entry);

        dlr = ExAllocatePoolWithTag(PagedPool, sizeof(drive_letter_removal), ALLOC_TAG);
        if (!dlr)
        {
            ERR("out of memory\n");

            while (!IsListEmpty(&dlrlist))
            {
                dlr = CONTAINING_RECORD(RemoveHeadList(&dlrlist), drive_letter_removal, list_entry);

                ExFreePool(dlr->name.Buffer);
                ExFreePool(dlr);
            }

            ExReleaseResourceLite(&pdode->child_lock);
            return;
        }

        dlr->name.Length = dlr->name.MaximumLength = vc->pnp_name.Length + (3 * sizeof(WCHAR));
        dlr->name.Buffer = ExAllocatePoolWithTag(PagedPool, dlr->name.Length, ALLOC_TAG);

        if (!dlr->name.Buffer)
        {
            ERR("out of memory\n");

            ExFreePool(dlr);

            while (!IsListEmpty(&dlrlist))
            {
                dlr = CONTAINING_RECORD(RemoveHeadList(&dlrlist), drive_letter_removal, list_entry);

                ExFreePool(dlr->name.Buffer);
                ExFreePool(dlr);
            }

            ExReleaseResourceLite(&pdode->child_lock);
            return;
        }

        RtlCopyMemory(dlr->name.Buffer, L"\\??", 3 * sizeof(WCHAR));
        RtlCopyMemory(&dlr->name.Buffer[3], vc->pnp_name.Buffer, vc->pnp_name.Length);

        InsertTailList(&dlrlist, &dlr->list_entry);

        le = le->Flink;
    }

    ExReleaseResourceLite(&pdode->child_lock);

    le = dlrlist.Flink;
    while (le != &dlrlist)
    {
        drive_letter_removal* dlr = CONTAINING_RECORD(le, drive_letter_removal, list_entry);

        dlr->Status = remove_drive_letter(mountmgr, &dlr->name);

        if (!NT_SUCCESS(dlr->Status) && dlr->Status != STATUS_NOT_FOUND)
        {
            WARN("remove_drive_letter returned %08lx\n", dlr->Status);
        }

        le = le->Flink;
    }

    // set vc->had_drive_letter

    ExAcquireResourceExclusiveLite(&pdode->child_lock, true);

    while (!IsListEmpty(&dlrlist))
    {
        drive_letter_removal* dlr = CONTAINING_RECORD(RemoveHeadList(&dlrlist), drive_letter_removal, list_entry);

        le = pdode->children.Flink;

        while (le != &pdode->children)
        {
            volume_child* vc = CONTAINING_RECORD(le, volume_child, list_entry);

            if ((vc->sectorsize == dlr->sectorsize) && (vc->tablesize == dlr->tablesize) && (vc->filenamesend == dlr->filenamesend) && (vc->tableend = dlr->tableend))
            {
                vc->had_drive_letter = NT_SUCCESS(dlr->Status);
                break;
            }

            le = le->Flink;
        }

        ExFreePool(dlr->name.Buffer);
        ExFreePool(dlr);
    }

    ExReleaseResourceLite(&pdode->child_lock);
}

_Function_class_(IO_WORKITEM_ROUTINE)
static void __stdcall drive_letter_callback(pdo_device_extension* pdode)
{
    NTSTATUS Status;
    UNICODE_STRING mmdevpath;
    PDEVICE_OBJECT mountmgr;
    PFILE_OBJECT mountmgrfo;

    RtlInitUnicodeString(&mmdevpath, MOUNTMGR_DEVICE_NAME);
    Status = IoGetDeviceObjectPointer(&mmdevpath, FILE_READ_ATTRIBUTES, &mountmgrfo, &mountmgr);
    if (!NT_SUCCESS(Status))
    {
        ERR("IoGetDeviceObjectPointer returned %08lx\n", Status);
        return;
    }

    drive_letter_callback2(pdode, mountmgr);

    ObDereferenceObject(mountmgrfo);
}

void add_volume_device(unsigned long sectorsize, unsigned long tablesize, unsigned long long extratablesize, unsigned long long filenamesend, unsigned long long tableend, PUNICODE_STRING devpath, uint64_t length, ULONG disk_num, ULONG part_num) {
    NTSTATUS Status;
    LIST_ENTRY* le;
    PDEVICE_OBJECT DeviceObject;
    volume_child* vc;
    PFILE_OBJECT FileObject;
    UNICODE_STRING devpath2;
    bool inserted = false, new_pdo = false;
    pdo_device_extension* pdode = NULL;
    PDEVICE_OBJECT pdo = NULL;
    bool process_drive_letters = false;

    if (devpath->Length == 0)
    {
        return;
    }

    ExAcquireResourceExclusiveLite(&pdo_list_lock, true);

    le = pdo_list.Flink;
    while (le != &pdo_list)
    {
        pdo_device_extension* pdode2 = CONTAINING_RECORD(le, pdo_device_extension, list_entry);

        if ((pdode2->sectorsize == sectorsize) && (pdode2->tablesize == tablesize) && (pdode2->filenamesend == filenamesend) && (pdode2->tableend = tableend))
        {
            pdode = pdode2;
            break;
        }

        le = le->Flink;
    }

    Status = IoGetDeviceObjectPointer(devpath, FILE_READ_ATTRIBUTES, &FileObject, &DeviceObject);
    if (!NT_SUCCESS(Status))
    {
        ERR("IoGetDeviceObjectPointer returned %08lx\n", Status);
        ExReleaseResourceLite(&pdo_list_lock);
        return;
    }

    if (!pdode)
    {
        if (no_pnp)
        {
            Status = IoReportDetectedDevice(drvobj, InterfaceTypeUndefined, 0xFFFFFFFF, 0xFFFFFFFF, NULL, NULL, 0, &pdo);

            if (!NT_SUCCESS(Status))
            {
                ERR("IoReportDetectedDevice returned %08lx\n", Status);
                ExReleaseResourceLite(&pdo_list_lock);
                return;
            }

            pdode = ExAllocatePoolWithTag(NonPagedPool, sizeof(pdo_device_extension), ALLOC_TAG);

            if (!pdode)
            {
                ERR("out of memory\n");
                ExReleaseResourceLite(&pdo_list_lock);
                return;
            }
        }
        else
        {
            Status = IoCreateDevice(drvobj, sizeof(pdo_device_extension), NULL, FILE_DEVICE_DISK, FILE_AUTOGENERATED_DEVICE_NAME | FILE_DEVICE_SECURE_OPEN, false, &pdo);
            if (!NT_SUCCESS(Status))
            {
                ERR("IoCreateDevice returned %08lx\n", Status);
                ExReleaseResourceLite(&pdo_list_lock);
                goto fail;
            }

            pdo->Flags |= DO_BUS_ENUMERATED_DEVICE;

            pdode = pdo->DeviceExtension;
        }

        RtlZeroMemory(pdode, sizeof(pdo_device_extension));

        pdode->type = VCB_TYPE_PDO;
        pdode->pdo = pdo;
        pdode->sectorsize = sectorsize;
        pdode->tablesize = tablesize;
        pdode->extratablesize = extratablesize;
        pdode->filenamesend = filenamesend;
        pdode->tableend = tableend;

        ExInitializeResourceLite(&pdode->child_lock);
        InitializeListHead(&pdode->children);
        pdode->num_children = 0;
        pdode->children_loaded = 0;

        pdo->Flags &= ~DO_DEVICE_INITIALIZING;
        pdo->SectorSize = (USHORT)sectorsize;

        ExAcquireResourceExclusiveLite(&pdode->child_lock, true);

        new_pdo = true;
    }
    else
    {
        ExAcquireResourceExclusiveLite(&pdode->child_lock, true);
        ExConvertExclusiveToSharedLite(&pdo_list_lock);

        le = pdode->children.Flink;
        while (le != &pdode->children)
        {
            volume_child* vc2 = CONTAINING_RECORD(le, volume_child, list_entry);

            if ((vc2->sectorsize == sectorsize) && (vc2->tablesize == tablesize) && (vc2->filenamesend == filenamesend) && (vc2->tableend = tableend))
            {
                // duplicate, ignore
                ExReleaseResourceLite(&pdode->child_lock);
                ExReleaseResourceLite(&pdo_list_lock);
                goto fail;
            }

            le = le->Flink;
        }
    }

    vc = ExAllocatePoolWithTag(PagedPool, sizeof(volume_child), ALLOC_TAG);
    if (!vc)
    {
        ERR("out of memory\n");

        ExReleaseResourceLite(&pdode->child_lock);
        ExReleaseResourceLite(&pdo_list_lock);

        goto fail;
    }

    vc->sectorsize = sectorsize;
    vc->tablesize = tablesize;
    vc->extratablesize = extratablesize;
    vc->filenamesend = filenamesend;
    vc->tableend = tableend;
    vc->notification_entry = NULL;
    vc->boot_volume = false;

    Status = IoRegisterPlugPlayNotification(EventCategoryTargetDeviceChange, 0, FileObject, drvobj, pnp_removal, pdode, &vc->notification_entry);
    if (!NT_SUCCESS(Status))
    {
        WARN("IoRegisterPlugPlayNotification returned %08lx\n", Status);
    }

    vc->devobj = DeviceObject;
    vc->fileobj = FileObject;

    devpath2 = *devpath;

    // The PNP path sometimes begins \\?\ and sometimes \??\. We need to remove this prefix
    // so we can compare properly if the device is removed.
    if (devpath->Length > 4 * sizeof(WCHAR) && devpath->Buffer[0] == '\\' && (devpath->Buffer[1] == '\\' || devpath->Buffer[1] == '?') && devpath->Buffer[2] == '?' && devpath->Buffer[3] == '\\')
    {
        devpath2.Buffer = &devpath2.Buffer[3];
        devpath2.Length -= 3 * sizeof(WCHAR);
        devpath2.MaximumLength -= 3 * sizeof(WCHAR);
    }

    vc->pnp_name.Length = vc->pnp_name.MaximumLength = devpath2.Length;
    vc->pnp_name.Buffer = ExAllocatePoolWithTag(PagedPool, devpath2.Length, ALLOC_TAG);

    if (vc->pnp_name.Buffer)
    {
        RtlCopyMemory(vc->pnp_name.Buffer, devpath2.Buffer, devpath2.Length);
    }
    else
    {
        ERR("out of memory\n");
        vc->pnp_name.Length = vc->pnp_name.MaximumLength = 0;
    }

    vc->size = length;
    vc->disk_num = disk_num;
    vc->part_num = part_num;
    vc->had_drive_letter = false;

    if (!inserted)
    {
        InsertTailList(&pdode->children, &vc->list_entry);
    }

    pdode->children_loaded++;

    if (pdode->vde && pdode->vde->mounted_device)
    {
        device_extension* Vcb = pdode->vde->mounted_device->DeviceExtension;

        ExAcquireResourceExclusiveLite(&Vcb->tree_lock, true);

        le = Vcb->devices.Flink;
        while (le != &Vcb->devices)
        {
            device* dev = CONTAINING_RECORD(le, device, list_entry);

            if (!dev->devobj && (dev->sectorsize == sectorsize) && (dev->tablesize == tablesize) && (dev->filenamesend == filenamesend) && (dev->tableend = tableend))
            {
                dev->devobj = DeviceObject;
                dev->disk_num = disk_num;
                dev->part_num = part_num;
                init_device(Vcb, dev, false);
                break;
            }

            le = le->Flink;
        }

        ExReleaseResourceLite(&Vcb->tree_lock);
    }

    if (DeviceObject->Characteristics & FILE_REMOVABLE_MEDIA)
    {
        pdode->removable = true;

        if (pdode->vde && pdode->vde->device)
        {
            pdode->vde->device->Characteristics |= FILE_REMOVABLE_MEDIA;
        }
    }

    if (pdode->num_children == pdode->children_loaded || (pdode->children_loaded == 1))
    {
        if ((!new_pdo || !no_pnp) && pdode->vde)
        {
            Status = IoSetDeviceInterfaceState(&pdode->vde->bus_name, true);
            if (!NT_SUCCESS(Status))
            {
                WARN("IoSetDeviceInterfaceState returned %08lx\n", Status);
            }
        }

        process_drive_letters = true;
    }

    ExReleaseResourceLite(&pdode->child_lock);

    if (new_pdo)
    {
        InsertTailList(&pdo_list, &pdode->list_entry);
    }

    ExReleaseResourceLite(&pdo_list_lock);

    if (process_drive_letters)
    {
        drive_letter_callback(pdode);
    }

    if (new_pdo)
    {
        if (no_pnp)
        {
            AddDevice(drvobj, pdo);
            //boot_add_device(pdo);
        }
        else
        {
            bus_device_extension* bde = busobj->DeviceExtension;
            IoInvalidateDeviceRelations(bde->buspdo, BusRelations);
        }
    }

    return;

fail:
    ObDereferenceObject(FileObject);
}
