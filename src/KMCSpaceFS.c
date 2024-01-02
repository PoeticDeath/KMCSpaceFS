// Copyright (c) Anthony Kerr 2023-

#ifdef _DEBUG
#define DEBUG
#endif

#include "KMCSpaceFS_drv.h"
#ifndef _MSC_VER
#include <cpuid.h>
#else
#include <intrin.h>
#endif
#include <ntddscsi.h>
#include "KMCSpaceFS.h"
#include <ata.h>

#ifndef _MSC_VER
#include <initguid.h>
#include <ntddstor.h>
#undef INITGUID
#endif

#include <ntdddisk.h>
#include <ntddvol.h>

#ifdef _MSC_VER
#include <initguid.h>
#include <ntddstor.h>
#undef INITGUID
#endif

#include <ntstrsafe.h>

static const WCHAR device_name[] = {'\\','C','S','p','a','c','e','F','S',0};
static const WCHAR dosdevice_name[] = {'\\','D','o','s','D','e','v','i','c','e','s','\\','C','S','p','a','c','e','F','S',0};

// {12950673-B60F-4F05-A947-9A61685B3639}
DEFINE_GUID(KMCSpaceFSBusInterface, 0x12950673, 0xb60f, 0x4f05, 0xa9, 0x47, 0x9a, 0x61, 0x68, 0x5b, 0x36, 0x39);

PDRIVER_OBJECT drvobj;
PDEVICE_OBJECT devobj, busobj;
LIST_ENTRY uid_map_list, gid_map_list;
uint32_t debug_log_level = 0;
uint32_t mount_flush_interval = 30;
uint32_t mount_readonly = 0;
uint32_t no_pnp = 0;
bool log_started = false;
UNICODE_STRING log_device, log_file, registry_path;
tIoUnregisterPlugPlayNotificationEx fIoUnregisterPlugPlayNotificationEx;
void* notification_entry = NULL, * notification_entry2 = NULL, * notification_entry3 = NULL;
ERESOURCE pdo_list_lock;
LIST_ENTRY pdo_list;
HANDLE degraded_wait_handle = NULL, mountmgr_thread_handle = NULL;
bool degraded_wait = true;
KEVENT mountmgr_thread_event;
bool shutting_down = false;
ERESOURCE boot_lock;
bool is_windows_8;

typedef struct
{
	KEVENT Event;
	IO_STATUS_BLOCK iosb;
} read_context;

bool is_top_level(_In_ PIRP Irp)
{
	if (!IoGetTopLevelIrp())
	{
		IoSetTopLevelIrp(Irp);
		return true;
	}

	return false;
}

_Function_class_(DRIVER_UNLOAD)
static void __stdcall DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING dosdevice_nameW;

	TRACE("(%p)\n", DriverObject);

	dosdevice_nameW.Buffer = (WCHAR*)dosdevice_name;
	dosdevice_nameW.Length = dosdevice_nameW.MaximumLength = sizeof(dosdevice_name) - sizeof(WCHAR);

	IoDeleteSymbolicLink(&dosdevice_nameW);
	IoDeleteDevice(DriverObject->DeviceObject);

	// FIXME - free volumes and their devpaths

#ifdef _DEBUG
	if (comfo)
	{
		ObDereferenceObject(comfo);
	}

	if (log_handle)
	{
		ZwClose(log_handle);
	}
#endif

	ExDeleteResourceLite(&pdo_list_lock);

	if (log_device.Buffer)
	{
		ExFreePool(log_device.Buffer);
	}

	if (log_file.Buffer)
	{
		ExFreePool(log_file.Buffer);
	}

	if (registry_path.Buffer)
	{
		ExFreePool(registry_path.Buffer);
	}

#ifdef _DEBUG
	ExDeleteResourceLite(&log_lock);
#endif
}

#ifdef _DEBUG
PFILE_OBJECT comfo = NULL;
PDEVICE_OBJECT comdo = NULL;
HANDLE log_handle = NULL;
ERESOURCE log_lock;
HANDLE serial_thread_handle = NULL;

_Function_class_(IO_COMPLETION_ROUTINE)
static NTSTATUS __stdcall dbg_completion(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp, _In_ PVOID conptr)
{
	read_context* context = conptr;

	UNUSED(DeviceObject);

	context->iosb = Irp->IoStatus;
	KeSetEvent(&context->Event, 0, false);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

#define DEBUG_MESSAGE_LEN 1024

void _debug_message(_In_ const char* func, _In_ char* s, ...)
{
	LARGE_INTEGER offset;
	PIO_STACK_LOCATION IrpSp;
	NTSTATUS Status;
	PIRP Irp;
	va_list ap;
	char* buf2, * buf;
	read_context context;
	uint32_t length;

	buf2 = ExAllocatePoolWithTag(NonPagedPool, DEBUG_MESSAGE_LEN, ALLOC_TAG);

	if (!buf2)
	{
		DbgPrint("Couldn't allocate buffer in debug_message\n");
		return;
	}

	sprintf(buf2, "%p:%s:", (void*)PsGetCurrentThread(), func);
	buf = &buf2[strlen(buf2)];

	va_start(ap, s);

	RtlStringCbVPrintfA(buf, DEBUG_MESSAGE_LEN - strlen(buf2), s, ap);

	ExAcquireResourceSharedLite(&log_lock, true);

	if (!log_started || (log_device.Length == 0 && log_file.Length == 0))
	{
		DbgPrint(buf2);
	}
	else if (log_device.Length > 0)
	{
		if (!comdo)
		{
			DbgPrint(buf2);
			goto exit2;
		}

		length = (uint32_t)strlen(buf2);

		offset.u.LowPart = 0;
		offset.u.HighPart = 0;

		RtlZeroMemory(&context, sizeof(read_context));

		KeInitializeEvent(&context.Event, NotificationEvent, false);

		Irp = IoAllocateIrp(comdo->StackSize, false);

		if (!Irp)
		{
			DbgPrint("IoAllocateIrp failed\n");
			goto exit2;
		}

		IrpSp = IoGetNextIrpStackLocation(Irp);
		IrpSp->MajorFunction = IRP_MJ_WRITE;
		IrpSp->FileObject = comfo;

		if (comdo->Flags & DO_BUFFERED_IO)
		{
			Irp->AssociatedIrp.SystemBuffer = buf2;

			Irp->Flags = IRP_BUFFERED_IO;
		}
		else if (comdo->Flags & DO_DIRECT_IO)
		{
			Irp->MdlAddress = IoAllocateMdl(buf2, length, false, false, NULL);
			if (!Irp->MdlAddress)
			{
				DbgPrint("IoAllocateMdl failed\n");
				goto exit;
			}

			MmBuildMdlForNonPagedPool(Irp->MdlAddress);
		}
		else
		{
			Irp->UserBuffer = buf2;
		}

		IrpSp->Parameters.Write.Length = length;
		IrpSp->Parameters.Write.ByteOffset = offset;

		Irp->UserIosb = &context.iosb;

		Irp->UserEvent = &context.Event;

		IoSetCompletionRoutine(Irp, dbg_completion, &context, true, true, true);

		Status = IoCallDriver(comdo, Irp);

		if (Status == STATUS_PENDING)
		{
			KeWaitForSingleObject(&context.Event, Executive, KernelMode, false, NULL);
			Status = context.iosb.Status;
		}

		if (comdo->Flags & DO_DIRECT_IO)
		{
			IoFreeMdl(Irp->MdlAddress);
		}

		if (!NT_SUCCESS(Status))
		{
			DbgPrint("failed to write to COM1 - error %08lx\n", Status);
			goto exit;
		}

	exit:
		IoFreeIrp(Irp);
	}
	else if (log_handle != NULL)
	{
		IO_STATUS_BLOCK iosb;

		length = (uint32_t)strlen(buf2);

		Status = ZwWriteFile(log_handle, NULL, NULL, NULL, &iosb, buf2, length, NULL, NULL);

		if (!NT_SUCCESS(Status))
		{
			DbgPrint("failed to write to file - error %08lx\n", Status);
		}
	}

exit2:
	ExReleaseResourceLite(&log_lock);

	va_end(ap);

	if (buf2)
	{
		ExFreePool(buf2);
	}
}
#endif

#if defined(_X86_) || defined(_AMD64_)
static void check_cpu()
{
	bool have_sse2 = false, have_sse42 = false, have_avx2 = false;
	int cpu_info[4];

	__cpuid(cpu_info, 1);
	have_sse42 = cpu_info[2] & (1 << 20);
	have_sse2 = cpu_info[3] & (1 << 26);

	__cpuidex(cpu_info, 7, 0);
	have_avx2 = cpu_info[1] & (1 << 5);

	if (have_avx2)
	{
		// check Windows has enabled AVX2 - Windows 10 doesn't immediately

		if (__readcr4() & (1 << 18))
		{
			uint32_t xcr0;

#ifdef _MSC_VER
			xcr0 = (uint32_t)_xgetbv(0);
#else
			__asm__("xgetbv" : "=a" (xcr0) : "c" (0) : "edx");
#endif

			if ((xcr0 & 6) != 6)
			{
				have_avx2 = false;
			}
		}
		else
		{
			have_avx2 = false;
		}
	}

	if (have_sse42)
	{
		TRACE("SSE4.2 is supported\n");
	}
	else
	{
		TRACE("SSE4.2 not supported\n");
	}

	if (have_sse2)
	{
		TRACE("SSE2 is supported\n");
	}
	else
	{
		TRACE("SSE2 is not supported\n");
	}

	if (have_avx2)
	{
		TRACE("AVX2 is supported\n");
	}
	else
	{
		TRACE("AVX2 is not supported\n");
	}
}
#endif

#ifdef _DEBUG
static void init_serial(bool first_time);

_Function_class_(KSTART_ROUTINE)
static void __stdcall serial_thread(void* context)
{
	LARGE_INTEGER due_time;
	KTIMER timer;

	UNUSED(context);

	KeInitializeTimer(&timer);

	due_time.QuadPart = (uint64_t)-10000000;

	KeSetTimer(&timer, due_time, NULL);

	while (true)
	{
		KeWaitForSingleObject(&timer, Executive, KernelMode, false, NULL);

		init_serial(false);

		if (comdo)
		{
			break;
		}

		KeSetTimer(&timer, due_time, NULL);
	}

	KeCancelTimer(&timer);

	PsTerminateSystemThread(STATUS_SUCCESS);

	serial_thread_handle = NULL;
}

static void init_serial(bool first_time)
{
	NTSTATUS Status;

	Status = IoGetDeviceObjectPointer(&log_device, FILE_WRITE_DATA, &comfo, &comdo);
	if (!NT_SUCCESS(Status))
	{
		ERR("IoGetDeviceObjectPointer returned %08lx\n", Status);

		if (first_time)
		{
			OBJECT_ATTRIBUTES oa;

			InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

			Status = PsCreateSystemThread(&serial_thread_handle, 0, &oa, NULL, NULL, serial_thread, NULL);
			if (!NT_SUCCESS(Status))
			{
				ERR("PsCreateSystemThread returned %08lx\n", Status);
				return;
			}
		}
	}
}

static void init_logging()
{
	ExAcquireResourceExclusiveLite(&log_lock, true);

	if (log_device.Length > 0)
	{
		init_serial(true);
	}
	else if (log_file.Length > 0)
	{
		NTSTATUS Status;
		OBJECT_ATTRIBUTES oa;
		IO_STATUS_BLOCK iosb;
		char* dateline;
		LARGE_INTEGER time;
		TIME_FIELDS tf;

		InitializeObjectAttributes(&oa, &log_file, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		Status = ZwCreateFile(&log_handle, FILE_WRITE_DATA, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE | FILE_WRITE_THROUGH | FILE_SYNCHRONOUS_IO_ALERT, NULL, 0);
		if (!NT_SUCCESS(Status))
		{
			ERR("ZwCreateFile returned %08lx\n", Status);
			goto end;
		}

		if (iosb.Information == FILE_OPENED)
		{ // already exists
			FILE_STANDARD_INFORMATION fsi;
			FILE_POSITION_INFORMATION fpi;

			static const char delim[] = "\n---\n";

			// move to end of file

			Status = ZwQueryInformationFile(log_handle, &iosb, &fsi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
			if (!NT_SUCCESS(Status))
			{
				ERR("ZwQueryInformationFile returned %08lx\n", Status);
				goto end;
			}

			fpi.CurrentByteOffset = fsi.EndOfFile;

			Status = ZwSetInformationFile(log_handle, &iosb, &fpi, sizeof(FILE_POSITION_INFORMATION), FilePositionInformation);
			if (!NT_SUCCESS(Status))
			{
				ERR("ZwSetInformationFile returned %08lx\n", Status);
				goto end;
			}

			Status = ZwWriteFile(log_handle, NULL, NULL, NULL, &iosb, (void*)delim, sizeof(delim) - 1, NULL, NULL);
			if (!NT_SUCCESS(Status))
			{
				ERR("ZwWriteFile returned %08lx\n", Status);
				goto end;
			}
		}

		dateline = ExAllocatePoolWithTag(PagedPool, 256, ALLOC_TAG);

		if (!dateline)
		{
			ERR("out of memory\n");
			goto end;
		}

		KeQuerySystemTime(&time);

		RtlTimeToTimeFields(&time, &tf);

		sprintf(dateline, "Starting logging at %04i-%02i-%02i %02i:%02i:%02i\n", tf.Year, tf.Month, tf.Day, tf.Hour, tf.Minute, tf.Second);

		Status = ZwWriteFile(log_handle, NULL, NULL, NULL, &iosb, dateline, (ULONG)strlen(dateline), NULL, NULL);
		ExFreePool(dateline);
		if (!NT_SUCCESS(Status))
		{
			ERR("ZwWriteFile returned %08lx\n", Status);
			goto end;
		}
	}

end:
	ExReleaseResourceLite(&log_lock);
}
#endif

_Function_class_(IO_COMPLETION_ROUTINE)
static NTSTATUS __stdcall read_completion(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp, _In_ PVOID conptr)
{
	read_context* context = conptr;

	UNUSED(DeviceObject);

	context->iosb = Irp->IoStatus;
	KeSetEvent(&context->Event, 0, false);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS sync_read_phys(_In_ PDEVICE_OBJECT DeviceObject, _In_ PFILE_OBJECT FileObject, _In_ uint64_t StartingOffset, _In_ ULONG Length, _Out_writes_bytes_(Length) PUCHAR Buffer, _In_ bool override)
{
	IO_STATUS_BLOCK IoStatus;
	LARGE_INTEGER Offset;
	PIRP Irp;
	PIO_STACK_LOCATION IrpSp;
	NTSTATUS Status;
	read_context context;

	RtlZeroMemory(&context, sizeof(read_context));
	KeInitializeEvent(&context.Event, NotificationEvent, false);

	Offset.QuadPart = (LONGLONG)StartingOffset;

	Irp = IoAllocateIrp(DeviceObject->StackSize, false);

	if (!Irp)
	{
		ERR("IoAllocateIrp failed\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	Irp->Flags |= IRP_NOCACHE;
	IrpSp = IoGetNextIrpStackLocation(Irp);
	IrpSp->MajorFunction = IRP_MJ_READ;
	IrpSp->FileObject = FileObject;

	if (override)
	{
		IrpSp->Flags |= SL_OVERRIDE_VERIFY_VOLUME;
	}

	if (DeviceObject->Flags & DO_BUFFERED_IO)
	{
		Irp->AssociatedIrp.SystemBuffer = ExAllocatePoolWithTag(NonPagedPool, Length, ALLOC_TAG);
		if (!Irp->AssociatedIrp.SystemBuffer)
		{
			ERR("out of memory\n");
			Status = STATUS_INSUFFICIENT_RESOURCES;
			goto exit;
		}

		Irp->Flags |= IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_INPUT_OPERATION;

		Irp->UserBuffer = Buffer;
	}
	else if (DeviceObject->Flags & DO_DIRECT_IO)
	{
		Irp->MdlAddress = IoAllocateMdl(Buffer, Length, false, false, NULL);
		if (!Irp->MdlAddress)
		{
			ERR("IoAllocateMdl failed\n");
			Status = STATUS_INSUFFICIENT_RESOURCES;
			goto exit;
		}

		Status = STATUS_SUCCESS;

		try
		{
			MmProbeAndLockPages(Irp->MdlAddress, KernelMode, IoWriteAccess);
		} except(EXCEPTION_EXECUTE_HANDLER)
		{
			Status = GetExceptionCode();
		}

		if (!NT_SUCCESS(Status))
		{
			ERR("MmProbeAndLockPages threw exception %08lx\n", Status);
			IoFreeMdl(Irp->MdlAddress);
			goto exit;
		}
	}
	else
	{
		Irp->UserBuffer = Buffer;
	}

	IrpSp->Parameters.Read.Length = Length;
	IrpSp->Parameters.Read.ByteOffset = Offset;

	Irp->UserIosb = &IoStatus;

	Irp->UserEvent = &context.Event;

	IoSetCompletionRoutine(Irp, read_completion, &context, true, true, true);

	Status = IoCallDriver(DeviceObject, Irp);

	if (Status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&context.Event, Executive, KernelMode, false, NULL);
		Status = context.iosb.Status;
	}

	if (DeviceObject->Flags & DO_DIRECT_IO)
	{
		MmUnlockPages(Irp->MdlAddress);
		IoFreeMdl(Irp->MdlAddress);
	}

exit:
	IoFreeIrp(Irp);

	return Status;
}

static bool is_device_removable(_In_ PDEVICE_OBJECT devobj)
{
	NTSTATUS Status;
	STORAGE_HOTPLUG_INFO shi;

	Status = dev_ioctl(devobj, IOCTL_STORAGE_GET_HOTPLUG_INFO, NULL, 0, &shi, sizeof(STORAGE_HOTPLUG_INFO), true, NULL);
	if (!NT_SUCCESS(Status))
	{
		ERR("dev_ioctl returned %08lx\n", Status);
		return false;
	}

	return shi.MediaRemovable != 0 ? true : false;
}

static ULONG get_device_change_count(_In_ PDEVICE_OBJECT devobj)
{
	NTSTATUS Status;
	ULONG cc;
	IO_STATUS_BLOCK iosb;

	Status = dev_ioctl(devobj, IOCTL_STORAGE_CHECK_VERIFY, NULL, 0, &cc, sizeof(ULONG), true, &iosb);
	if (!NT_SUCCESS(Status))
	{
		ERR("dev_ioctl returned %08lx\n", Status);
		return 0;
	}

	if (iosb.Information < sizeof(ULONG))
	{
		ERR("iosb.Information was too short\n");
		return 0;
	}

	return cc;
}

void init_device(_In_ device_extension* Vcb, _Inout_ device* dev, _In_ bool get_nums)
{
	NTSTATUS Status;
	ULONG aptelen;
	ATA_PASS_THROUGH_EX* apte;
	STORAGE_PROPERTY_QUERY spq;
	DEVICE_TRIM_DESCRIPTOR dtd;

	dev->removable = is_device_removable(dev->devobj);
	dev->change_count = dev->removable ? get_device_change_count(dev->devobj) : 0;

	if (get_nums)
	{
		STORAGE_DEVICE_NUMBER sdn;

		Status = dev_ioctl(dev->devobj, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &sdn, sizeof(STORAGE_DEVICE_NUMBER), true, NULL);
		if (!NT_SUCCESS(Status))
		{
			WARN("IOCTL_STORAGE_GET_DEVICE_NUMBER returned %08lx\n", Status);
			dev->disk_num = 0xffffffff;
			dev->part_num = 0xffffffff;
		}
		else
		{
			dev->disk_num = sdn.DeviceNumber;
			dev->part_num = sdn.PartitionNumber;
		}
	}

	dev->trim = false;
	dev->readonly = false;
	dev->reloc = false;
	dev->num_trim_entries = 0;
	dev->stats_changed = false;
	InitializeListHead(&dev->trim_list);

	if (!dev->readonly)
	{
		Status = dev_ioctl(dev->devobj, IOCTL_DISK_IS_WRITABLE, NULL, 0, NULL, 0, true, NULL);
		if (Status == STATUS_MEDIA_WRITE_PROTECTED)
		{
			dev->readonly = true;
		}
	}

	aptelen = sizeof(ATA_PASS_THROUGH_EX) + 512;
	apte = ExAllocatePoolWithTag(NonPagedPool, aptelen, ALLOC_TAG);
	if (!apte)
	{
		ERR("out of memory\n");
		return;
	}

	RtlZeroMemory(apte, aptelen);

	apte->Length = sizeof(ATA_PASS_THROUGH_EX);
	apte->AtaFlags = ATA_FLAGS_DATA_IN;
	apte->DataTransferLength = aptelen - sizeof(ATA_PASS_THROUGH_EX);
	apte->TimeOutValue = 3;
	apte->DataBufferOffset = apte->Length;
	apte->CurrentTaskFile[6] = IDE_COMMAND_IDENTIFY;

	Status = dev_ioctl(dev->devobj, IOCTL_ATA_PASS_THROUGH, apte, aptelen, apte, aptelen, true, NULL);

	if (!NT_SUCCESS(Status))
	{
		TRACE("IOCTL_ATA_PASS_THROUGH returned %08lx for IDENTIFY DEVICE\n", Status);
	}
	else
	{
		IDENTIFY_DEVICE_DATA* idd = (IDENTIFY_DEVICE_DATA*)((uint8_t*)apte + sizeof(ATA_PASS_THROUGH_EX));

		if (idd->CommandSetSupport.FlushCache)
		{
			dev->can_flush = true;
			TRACE("FLUSH CACHE supported\n");
		}
		else
		{
			TRACE("FLUSH CACHE not supported\n");
		}
	}

	ExFreePool(apte);

#ifdef DEBUG_TRIM_EMULATION
	dev->trim = true;
	Vcb->trim = true;
#else
	spq.PropertyId = StorageDeviceTrimProperty;
	spq.QueryType = PropertyStandardQuery;
	spq.AdditionalParameters[0] = 0;

	Status = dev_ioctl(dev->devobj, IOCTL_STORAGE_QUERY_PROPERTY, &spq, sizeof(STORAGE_PROPERTY_QUERY), &dtd, sizeof(DEVICE_TRIM_DESCRIPTOR), true, NULL);
	if (NT_SUCCESS(Status))
	{
		if (dtd.TrimEnabled)
		{
			dev->trim = true;
			Vcb->trim = true;
			TRACE("TRIM supported\n");
		}
		else
		{
			TRACE("TRIM not supported\n");
		}
	}
#endif

	RtlZeroMemory(dev->stats, sizeof(uint64_t) * 5);
}

NTSTATUS dev_ioctl(_In_ PDEVICE_OBJECT DeviceObject, _In_ ULONG ControlCode, _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer, _In_ ULONG InputBufferSize, _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer, _In_ ULONG OutputBufferSize, _In_ bool Override, _Out_opt_ IO_STATUS_BLOCK* iosb)
{
	PIRP Irp;
	KEVENT Event;
	NTSTATUS Status;
	PIO_STACK_LOCATION IrpSp;
	IO_STATUS_BLOCK IoStatus;

	KeInitializeEvent(&Event, NotificationEvent, false);

	Irp = IoBuildDeviceIoControlRequest(ControlCode, DeviceObject, InputBuffer, InputBufferSize, OutputBuffer, OutputBufferSize, false, &Event, &IoStatus);

	if (!Irp) return STATUS_INSUFFICIENT_RESOURCES;

	if (Override)
	{
		IrpSp = IoGetNextIrpStackLocation(Irp);
		IrpSp->Flags |= SL_OVERRIDE_VERIFY_VOLUME;
	}

	Status = IoCallDriver(DeviceObject, Irp);

	if (Status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&Event, Executive, KernelMode, false, NULL);
		Status = IoStatus.Status;
	}

	if (iosb)
	{
		*iosb = IoStatus;
	}

	return Status;
}

_Function_class_(KSTART_ROUTINE)
static void __stdcall degraded_wait_thread(_In_ void* context)
{
	KTIMER timer;
	LARGE_INTEGER delay;

	UNUSED(context);

	KeInitializeTimer(&timer);

	delay.QuadPart = -30000000; // wait three seconds
	KeSetTimer(&timer, delay, NULL);
	KeWaitForSingleObject(&timer, Executive, KernelMode, false, NULL);

	TRACE("timer expired\n");

	degraded_wait = false;

	ZwClose(degraded_wait_handle);
	degraded_wait_handle = NULL;

	PsTerminateSystemThread(STATUS_SUCCESS);
}

_Function_class_(DRIVER_ADD_DEVICE)
NTSTATUS __stdcall AddDevice(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT PhysicalDeviceObject)
{
	LIST_ENTRY* le;
	NTSTATUS Status;
	pdo_device_extension* pdode = NULL;
	PDEVICE_OBJECT voldev;
	volume_device_extension* vde;
	UNICODE_STRING volname;

	TRACE("(%p, %p)\n", DriverObject, PhysicalDeviceObject);

	UNUSED(DriverObject);

	ExAcquireResourceSharedLite(&pdo_list_lock, true);

	le = pdo_list.Flink;
	while (le != &pdo_list)
	{
		pdo_device_extension* pdode2 = CONTAINING_RECORD(le, pdo_device_extension, list_entry);

		if (pdode2->pdo == PhysicalDeviceObject)
		{
			pdode = pdode2;
			break;
		}

		le = le->Flink;
	}

	if (!pdode)
	{
		WARN("unrecognized PDO %p\n", PhysicalDeviceObject);
		Status = STATUS_NOT_SUPPORTED;
		goto end;
	}

	ExAcquireResourceExclusiveLite(&pdode->child_lock, true);

	if (pdode->vde)
	{ // if already done, return success
		Status = STATUS_SUCCESS;
		goto end2;
	}

	volname.Length = volname.MaximumLength = 22 * sizeof(WCHAR);
	volname.Buffer = ExAllocatePoolWithTag(PagedPool, volname.MaximumLength, ALLOC_TAG); // FIXME - when do we free this?
	if (!volname.Buffer)
	{
		ERR("out of memory\n");
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto end2;
	}

	RtlCopyMemory(volname.Buffer, L"\\Device\\CSpaceFS{129}", 22 * sizeof(WCHAR));

	Status = IoCreateDevice(drvobj, sizeof(volume_device_extension), &volname, FILE_DEVICE_DISK, is_windows_8 ? FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSAL : 0, false, &voldev);
	if (!NT_SUCCESS(Status))
	{
		ERR("IoCreateDevice returned %08lx\n", Status);
		goto end2;
	}

	voldev->SectorSize = PhysicalDeviceObject->SectorSize;
	voldev->Flags |= DO_DIRECT_IO;

	vde = voldev->DeviceExtension;
	vde->type = VCB_TYPE_VOLUME;
	vde->name = volname;
	vde->device = voldev;
	vde->mounted_device = NULL;
	vde->pdo = PhysicalDeviceObject;
	vde->pdode = pdode;
	vde->removing = false;
	vde->dead = false;
	vde->open_count = 0;

	Status = IoRegisterDeviceInterface(PhysicalDeviceObject, &GUID_DEVINTERFACE_VOLUME, NULL, &vde->bus_name);
	if (!NT_SUCCESS(Status))
	{
		WARN("IoRegisterDeviceInterface returned %08lx\n", Status);
	}

	vde->attached_device = IoAttachDeviceToDeviceStack(voldev, PhysicalDeviceObject);

	pdode->vde = vde;

	if (pdode->removable)
	{
		voldev->Characteristics |= FILE_REMOVABLE_MEDIA;
	}

	//if ()
	//{
	//	voldev->Flags |= DO_SYSTEM_BOOT_PARTITION;
	//	PhysicalDeviceObject->Flags |= DO_SYSTEM_BOOT_PARTITION;
	//}

	voldev->Flags &= ~DO_DEVICE_INITIALIZING;

	Status = IoSetDeviceInterfaceState(&vde->bus_name, true);
	if (!NT_SUCCESS(Status))
	{
		WARN("IoSetDeviceInterfaceState returned %08lx\n", Status);
	}

	Status = STATUS_SUCCESS;

end2:
	ExReleaseResourceLite(&pdode->child_lock);

end:
	ExReleaseResourceLite(&pdo_list_lock);

	return Status;
}

_Function_class_(DRIVER_INITIALIZE)
NTSTATUS __stdcall DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS Status;
	PDEVICE_OBJECT DeviceObject;
	UNICODE_STRING device_nameW;
	UNICODE_STRING dosdevice_nameW;
	control_device_extension* cde;
	bus_device_extension* bde;
	HANDLE regh;
	OBJECT_ATTRIBUTES oa, system_thread_attributes;
	ULONG dispos;
	RTL_OSVERSIONINFOW ver;

	ver.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);

	Status = RtlGetVersion(&ver);
	if (!NT_SUCCESS(Status))
	{
		ERR("RtlGetVersion returned %08lx\n", Status);
		return Status;
	}

	is_windows_8 = ver.dwMajorVersion > 6 || (ver.dwMajorVersion == 6 && ver.dwMinorVersion >= 2);

#ifdef _DEBUG
	ExInitializeResourceLite(&log_lock);
#endif
	log_device.Buffer = NULL;
	log_device.Length = log_device.MaximumLength = 0;
	log_file.Buffer = NULL;
	log_file.Length = log_file.MaximumLength = 0;

	registry_path.Length = registry_path.MaximumLength = RegistryPath->Length;
	registry_path.Buffer = ExAllocatePoolWithTag(PagedPool, registry_path.Length, ALLOC_TAG);

	if (!registry_path.Buffer)
	{
		ERR("out of memory\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlCopyMemory(registry_path.Buffer, RegistryPath->Buffer, registry_path.Length);

	read_registry(&registry_path, false);

#ifdef _DEBUG
	if (debug_log_level > 0)
	{
		init_logging();
	}

	log_started = true;
#endif

	TRACE("DriverEntry\n");

#if defined(_X86_) || defined(_AMD64_)
	check_cpu();
#endif

	drvobj = DriverObject;

	DriverObject->DriverUnload = DriverUnload;

	DriverObject->DriverExtension->AddDevice = AddDevice;

	////DriverObject->MajorFunction[IRP_MJ_CREATE]                   = Create;
	//DriverObject->MajorFunction[IRP_MJ_CLOSE]                    = Close;
	//DriverObject->MajorFunction[IRP_MJ_READ]                     = Read;
	//DriverObject->MajorFunction[IRP_MJ_WRITE]                    = Write;
	//DriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION]        = QueryInformation;
	//DriverObject->MajorFunction[IRP_MJ_SET_INFORMATION]          = SetInformation;
	//DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS]            = FlushBuffers;
	/////DriverObject->MajorFunction[IRP_MJ_QUERY_VOLUME_INFORMATION] = QueryVolumeInformation;
	//DriverObject->MajorFunction[IRP_MJ_SET_VOLUME_INFORMATION]   = SetVolumeInformation;
	//////DriverObject->MajorFunction[IRP_MJ_DIRECTORY_CONTROL]        = DirectoryControl;
	//DriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL]      = FileSystemControl;
	///DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]           = DeviceControl;
	//DriverObject->MajorFunction[IRP_MJ_SHUTDOWN]                 = Shutdown;
	//DriverObject->MajorFunction[IRP_MJ_LOCK_CONTROL]             = LockControl;
	//DriverObject->MajorFunction[IRP_MJ_CLEANUP]                  = Cleanup;
	//DriverObject->MajorFunction[IRP_MJ_QUERY_SECURITY]           = QuerySecurity;
	//DriverObject->MajorFunction[IRP_MJ_SET_SECURITY]             = SetSecurity;
	//DriverObject->MajorFunction[IRP_MJ_POWER]                    = Power;
	//DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL]           = SystemControl;
	DriverObject->MajorFunction[IRP_MJ_PNP]                      = Pnp;

	device_nameW.Buffer = (WCHAR*)device_name;
	device_nameW.Length = device_nameW.MaximumLength = sizeof(device_name) - sizeof(WCHAR);
	dosdevice_nameW.Buffer = (WCHAR*)dosdevice_name;
	dosdevice_nameW.Length = dosdevice_nameW.MaximumLength = sizeof(dosdevice_name) - sizeof(WCHAR);

	Status = IoCreateDevice(DriverObject, sizeof(control_device_extension), &device_nameW, FILE_DEVICE_DISK_FILE_SYSTEM, FILE_DEVICE_SECURE_OPEN, false, &DeviceObject);
	if (!NT_SUCCESS(Status))
	{
		ERR("IoCreateDevice returned %08lx\n", Status);
		return Status;
	}

	devobj = DeviceObject;
	cde = (control_device_extension*)devobj->DeviceExtension;

	RtlZeroMemory(cde, sizeof(control_device_extension));

	cde->type = VCB_TYPE_CONTROL;

	DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	Status = IoCreateSymbolicLink(&dosdevice_nameW, &device_nameW);
	if (!NT_SUCCESS(Status))
	{
		ERR("IoCreateSymbolicLink returned %08lx\n", Status);
		return Status;
	}

	ExInitializeResourceLite(&pdo_list_lock);

	InitializeListHead(&pdo_list);

	InitializeObjectAttributes(&oa, RegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	Status = ZwCreateKey(&regh, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, &dispos);
	if (!NT_SUCCESS(Status))
	{
		ERR("ZwCreateKey returned %08lx\n", Status);
		return Status;
	}

	watch_registry(regh);

	Status = IoCreateDevice(DriverObject, sizeof(bus_device_extension), NULL, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, false, &busobj);
	if (!NT_SUCCESS(Status))
	{
		ERR("IoCreateDevice returned %08lx\n", Status);
		return Status;
	}

	bde = (bus_device_extension*)busobj->DeviceExtension;

	RtlZeroMemory(bde, sizeof(bus_device_extension));

	bde->type = VCB_TYPE_BUS;

	Status = IoReportDetectedDevice(drvobj, InterfaceTypeUndefined, 0xFFFFFFFF, 0xFFFFFFFF, NULL, NULL, 0, &bde->buspdo);
	if (!NT_SUCCESS(Status))
	{
		ERR("IoReportDetectedDevice returned %08lx\n", Status);
		return Status;
	}

	Status = IoRegisterDeviceInterface(bde->buspdo, &KMCSpaceFSBusInterface, NULL, &bde->bus_name);
	if (!NT_SUCCESS(Status))
	{
		WARN("IoRegisterDeviceInterface returned %08lx\n", Status);
	}

	bde->attached_device = IoAttachDeviceToDeviceStack(busobj, bde->buspdo);

	busobj->Flags &= ~DO_DEVICE_INITIALIZING;

	Status = IoSetDeviceInterfaceState(&bde->bus_name, true);
	if (!NT_SUCCESS(Status))
	{
		WARN("IoSetDeviceInterfaceState returned %08lx\n", Status);
	}

	IoInvalidateDeviceRelations(bde->buspdo, BusRelations);

	InitializeObjectAttributes(&system_thread_attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	Status = PsCreateSystemThread(&degraded_wait_handle, 0, &system_thread_attributes, NULL, NULL, degraded_wait_thread, NULL);
	if (!NT_SUCCESS(Status))
	{
		WARN("PsCreateSystemThread returned %08lx\n", Status);
	}

	ExInitializeResourceLite(&boot_lock);

	Status = IoRegisterPlugPlayNotification(EventCategoryDeviceInterfaceChange, PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES, (PVOID)&GUID_DEVINTERFACE_VOLUME, DriverObject, volume_notification, NULL, &notification_entry2);
	if (!NT_SUCCESS(Status))
	{
		ERR("IoRegisterPlugPlayNotification returned %08lx\n", Status);
	}

	Status = IoRegisterPlugPlayNotification(EventCategoryDeviceInterfaceChange, PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES, (PVOID)&GUID_DEVINTERFACE_HIDDEN_VOLUME, DriverObject, volume_notification, NULL, &notification_entry3);
	if (!NT_SUCCESS(Status))
	{
		ERR("IoRegisterPlugPlayNotification returned %08lx\n", Status);
	}

	Status = IoRegisterPlugPlayNotification(EventCategoryDeviceInterfaceChange, PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES, (PVOID)&GUID_DEVINTERFACE_DISK, DriverObject, pnp_notification, DriverObject, &notification_entry);
	if (!NT_SUCCESS(Status))
	{
		ERR("IoRegisterPlugPlayNotification returned %08lx\n", Status);
	}

	KeInitializeEvent(&mountmgr_thread_event, NotificationEvent, false);

	Status = PsCreateSystemThread(&mountmgr_thread_handle, 0, &system_thread_attributes, NULL, NULL, mountmgr_thread, NULL);
	if (!NT_SUCCESS(Status))
	{
		WARN("PsCreateSystemThread returned %08lx\n", Status);
	}

	IoRegisterFileSystem(DeviceObject);

	return STATUS_SUCCESS;
}
