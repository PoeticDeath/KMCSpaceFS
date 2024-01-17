// Copyright (c) Anthony Kerr 2024-

#include "KMCSpaceFS_drv.h"

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
