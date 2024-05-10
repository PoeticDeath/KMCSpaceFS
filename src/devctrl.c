// Copyright (c) Anthony Kerr 2024-

#include "KMCSpaceFS_drv.h"
#include <ntdddisk.h>
#include <mountdev.h>
#include <diskguid.h>

extern PDRIVER_OBJECT drvobj;
extern LIST_ENTRY VcbList;
extern ERESOURCE global_loading_lock;

static NTSTATUS mountdev_query_stable_guid(device_extension* Vcb, PIRP Irp)
{
	MOUNTDEV_STABLE_GUID* msg = Irp->UserBuffer;
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

	TRACE("IOCTL_MOUNTDEV_QUERY_STABLE_GUID\n");

	if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MOUNTDEV_STABLE_GUID))
	{
		return STATUS_INVALID_PARAMETER;
	}

	RtlCopyMemory(&msg->StableGuid, &Vcb->vde->pdode->KMCSFS.uuid, sizeof(GUID));

	Irp->IoStatus.Information = sizeof(MOUNTDEV_STABLE_GUID);

	return STATUS_SUCCESS;
}

static NTSTATUS is_writable(device_extension* Vcb)
{
	TRACE("IOCTL_DISK_IS_WRITABLE\n");

	return Vcb->readonly ? STATUS_MEDIA_WRITE_PROTECTED : STATUS_SUCCESS;
}

static NTSTATUS query_filesystems(void* data, ULONG length)
{
	NTSTATUS Status;
	LIST_ENTRY* le, *le2;
	KMCSpaceFS_FileSystem* csfs = NULL;
	ULONG itemsize;

	ExAcquireResourceSharedLite(&global_loading_lock, true);

	if (IsListEmpty(&VcbList))
	{
		if (length < sizeof(KMCSpaceFS_FileSystem))
		{
			Status = STATUS_BUFFER_OVERFLOW;
			goto end;
		}
		else
		{
			RtlZeroMemory(data, sizeof(KMCSpaceFS_FileSystem));
			Status = STATUS_SUCCESS;
			goto end;
		}
	}

	le = VcbList.Flink;

	while (le != &VcbList)
	{
		device_extension* Vcb = CONTAINING_RECORD(le, device_extension, list_entry);
		KMCSpaceFS_FileSystem_Device* csfsd;

		if (csfs)
		{
			csfs->next_entry = itemsize;
			csfs = (KMCSpaceFS_FileSystem*)((uint8_t*)csfs + itemsize);
		}
		else
		{
			csfs = data;
		}

		if (length < offsetof(KMCSpaceFS_FileSystem, device))
		{
			Status = STATUS_BUFFER_OVERFLOW;
			goto end;
		}

		itemsize = offsetof(KMCSpaceFS_FileSystem, device);
		length -= offsetof(KMCSpaceFS_FileSystem, device);

		csfs->next_entry = 0;
		RtlCopyMemory(&csfs->uuid, &Vcb->vde->pdode->KMCSFS.uuid, sizeof(KMCSpaceFS_UUID));

		ExAcquireResourceSharedLite(&Vcb->tree_lock, true);

		csfs->num_devices = (uint32_t)1;

		csfsd = NULL;

		le2 = Vcb->devices.Flink;
		while (le2 != &Vcb->devices)
		{
			device* dev = CONTAINING_RECORD(le2, device, list_entry);
			MOUNTDEV_NAME mdn;

			if (csfsd)
			{
				csfsd = (KMCSpaceFS_FileSystem_Device*)((uint8_t*)csfsd + offsetof(KMCSpaceFS_FileSystem_Device, name[0]) + csfsd->name_length);
			}
			else
			{
				csfsd = &csfs->device;
			}

			if (length < offsetof(KMCSpaceFS_FileSystem_Device, name[0]))
			{
				ExReleaseResourceLite(&Vcb->tree_lock);
				Status = STATUS_BUFFER_OVERFLOW;
				goto end;
			}

			itemsize += (ULONG)offsetof(KMCSpaceFS_FileSystem_Device, name[0]);
			length -= (ULONG)offsetof(KMCSpaceFS_FileSystem_Device, name[0]);

			RtlCopyMemory(&csfsd->uuid, &Vcb->vde->pdode->KMCSFS.uuid, sizeof(KMCSpaceFS_UUID));

			if (dev->devobj)
			{
				Status = dev_ioctl(dev->devobj, IOCTL_MOUNTDEV_QUERY_DEVICE_NAME, NULL, 0, &mdn, sizeof(MOUNTDEV_NAME), true, NULL);
				if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW)
				{
					ExReleaseResourceLite(&Vcb->tree_lock);
					ERR("IOCTL_MOUNTDEV_QUERY_DEVICE_NAME returned %08lx\n", Status);
					goto end;
				}

				if (mdn.NameLength > length)
				{
					ExReleaseResourceLite(&Vcb->tree_lock);
					Status = STATUS_BUFFER_OVERFLOW;
					goto end;
				}

				Status = dev_ioctl(dev->devobj, IOCTL_MOUNTDEV_QUERY_DEVICE_NAME, NULL, 0, &csfsd->name_length, (ULONG)offsetof(MOUNTDEV_NAME, Name[0]) + mdn.NameLength, true, NULL);
				if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW)
				{
					ExReleaseResourceLite(&Vcb->tree_lock);
					ERR("IOCTL_MOUNTDEV_QUERY_DEVICE_NAME returned %08lx\n", Status);
					goto end;
				}

				itemsize += csfsd->name_length;
				length -= csfsd->name_length;
			}
			else
			{
				csfsd->missing = true;
				csfsd->name_length = 0;
			}

			le2 = le2->Flink;
		}

		ExReleaseResourceLite(&Vcb->tree_lock);

		le = le->Flink;
	}

	Status = STATUS_SUCCESS;

end:
	ExReleaseResourceLite(&global_loading_lock);

	return Status;
}

static NTSTATUS probe_volume(void* data, ULONG length, KPROCESSOR_MODE processor_mode)
{
	MOUNTDEV_NAME* mdn = (MOUNTDEV_NAME*)data;
	UNICODE_STRING path, pnp_name;
	NTSTATUS Status;
	PDEVICE_OBJECT DeviceObject;
	PFILE_OBJECT FileObject;
	const GUID* guid;

	if (length < sizeof(MOUNTDEV_NAME))
	{
		return STATUS_INVALID_PARAMETER;
	}

	if (length < offsetof(MOUNTDEV_NAME, Name[0]) + mdn->NameLength)
	{
		return STATUS_INVALID_PARAMETER;
	}

	TRACE("%.*S\n", (int)(mdn->NameLength / sizeof(WCHAR)), mdn->Name);

	if (!SeSinglePrivilegeCheck(RtlConvertLongToLuid(SE_MANAGE_VOLUME_PRIVILEGE), processor_mode))
	{
		return STATUS_PRIVILEGE_NOT_HELD;
	}

	path.Buffer = mdn->Name;
	path.Length = path.MaximumLength = mdn->NameLength;

	Status = IoGetDeviceObjectPointer(&path, FILE_READ_ATTRIBUTES, &FileObject, &DeviceObject);
	if (!NT_SUCCESS(Status))
	{
		ERR("IoGetDeviceObjectPointer returned %08lx\n", Status);
		return Status;
	}

	Status = get_device_pnp_name(DeviceObject, &pnp_name, &guid);
	if (!NT_SUCCESS(Status))
	{
		ERR("get_device_pnp_name returned %08lx\n", Status);
		ObDereferenceObject(FileObject);
		return Status;
	}

	if (RtlCompareMemory(guid, &GUID_DEVINTERFACE_DISK, sizeof(GUID)) == sizeof(GUID))
	{
		Status = dev_ioctl(DeviceObject, IOCTL_DISK_UPDATE_PROPERTIES, NULL, 0, NULL, 0, true, NULL);
		if (!NT_SUCCESS(Status))
		{
			WARN("IOCTL_DISK_UPDATE_PROPERTIES returned %08lx\n", Status);
		}
	}

	ObDereferenceObject(FileObject);

	volume_removal(&pnp_name);

	if (RtlCompareMemory(guid, &GUID_DEVINTERFACE_DISK, sizeof(GUID)) == sizeof(GUID))
	{
		disk_arrival(&pnp_name);
	}
	else
	{
		volume_arrival(&pnp_name, false);
	}

	return STATUS_SUCCESS;
}

static NTSTATUS ioctl_unload(PIRP Irp)
{
	if (!SeSinglePrivilegeCheck(RtlConvertLongToLuid(SE_LOAD_DRIVER_PRIVILEGE), Irp->RequestorMode))
	{
		ERR("insufficient privileges\n");
		return STATUS_PRIVILEGE_NOT_HELD;
	}

	do_shutdown(Irp);

	return STATUS_SUCCESS;
}

static NTSTATUS control_ioctl(PIRP Irp)
{
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS Status;

	switch (IrpSp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_KMCSPACEFS_QUERY_FILESYSTEMS:
		Status = query_filesystems(map_user_buffer(Irp, NormalPagePriority), IrpSp->Parameters.FileSystemControl.OutputBufferLength);
		break;

	case IOCTL_KMCSPACEFS_PROBE_VOLUME:
		Status = probe_volume(Irp->AssociatedIrp.SystemBuffer, IrpSp->Parameters.FileSystemControl.InputBufferLength, Irp->RequestorMode);
		break;

	case IOCTL_KMCSPACEFS_UNLOAD:
		Status = ioctl_unload(Irp);
		break;

	default:
		TRACE("unhandled ioctl %lx\n", IrpSp->Parameters.DeviceIoControl.IoControlCode);
		Status = STATUS_NOT_IMPLEMENTED;
		break;
	}

	return Status;
}

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS __stdcall DeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	ExAcquireResourceExclusiveLite(&op_lock, true);

	NTSTATUS Status;
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	device_extension* Vcb = DeviceObject->DeviceExtension;
	bool top_level;

	FsRtlEnterFileSystem();

	top_level = is_top_level(Irp);

	Irp->IoStatus.Information = 0;

	if (Vcb)
	{
		if (Vcb->type == VCB_TYPE_CONTROL)
		{
			Status = control_ioctl(Irp);
			goto end;
		}
		else if (Vcb->type == VCB_TYPE_VOLUME)
		{
			Status = vol_device_control(DeviceObject, Irp);
			goto end;
		}
		else if (Vcb->type != VCB_TYPE_FS)
		{
			Status = STATUS_INVALID_PARAMETER;
			goto end;
		}
	}
	else
	{
		Status = STATUS_INVALID_PARAMETER;
		goto end;
	}

	switch (IrpSp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_MOUNTDEV_QUERY_STABLE_GUID:
		Status = mountdev_query_stable_guid(Vcb, Irp);
		goto end;

	case IOCTL_DISK_IS_WRITABLE:
		Status = is_writable(Vcb);
		goto end;

	default:
		TRACE("unhandled control code %lx\n", IrpSp->Parameters.DeviceIoControl.IoControlCode);
		break;
	}

	IoSkipCurrentIrpStackLocation(Irp);

	Status = IoCallDriver(Vcb->Vpb->RealDevice, Irp);

	goto end2;

end:
	Irp->IoStatus.Status = Status;

	if (Status != STATUS_PENDING)
	{
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
	}

end2:
	TRACE("returning %08lx\n", Status);

	if (top_level)
	{
		IoSetTopLevelIrp(NULL);
	}

	FsRtlExitFileSystem();

	ExReleaseResourceLite(&op_lock);

	return Status;
}
