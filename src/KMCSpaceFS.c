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

static const WCHAR device_name[] = { '\\','C','S','p','a','c','e','F','S',0};
static const WCHAR dosdevice_name[] = { '\\','D','o','s','D','e','v','i','c','e','s','\\','C','S','p','a','c','e','F','S',0};

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
ERESOURCE pdo_list_lock;
LIST_ENTRY pdo_list;
ERESOURCE boot_lock;

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

	/*
	DriverObject->DriverUnload = DriverUnload;

	DriverObject->DriverExtension->AddDevice = AddDevice;

	DriverObject->MajorFunction[IRP_MJ_CREATE]                   = Create;
	DriverObject->MajorFunction[IRP_MJ_CLOSE]                    = Close;
	DriverObject->MajorFunction[IRP_MJ_READ]                     = Read;
	DriverObject->MajorFunction[IRP_MJ_WRITE]                    = Write;
	DriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION]        = QueryInformation;
	DriverObject->MajorFunction[IRP_MJ_SET_INFORMATION]          = SetInformation;
	DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS]            = FlushBuffers;
	DriverObject->MajorFunction[IRP_MJ_QUERY_VOLUME_INFORMATION] = QueryVolumeInformation;
	DriverObject->MajorFunction[IRP_MJ_SET_VOLUME_INFORMATION]   = SetVolumeInformation;
	DriverObject->MajorFunction[IRP_MJ_DIRECTORY_CONTROL]        = DirectoryControl;
	DriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL]      = FileSystemControl;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]           = DeviceControl;
	DriverObject->MajorFunction[IRP_MJ_SHUTDOWN]                 = Shutdown;
	DriverObject->MajorFunction[IRP_MJ_LOCK_CONTROL]             = LockControl;
	DriverObject->MajorFunction[IRP_MJ_CLEANUP]                  = Cleanup;
	DriverObject->MajorFunction[IRP_MJ_QUERY_SECURITY]           = QuerySecurity;
	DriverObject->MajorFunction[IRP_MJ_SET_SECURITY]             = SetSecurity;
	DriverObject->MajorFunction[IRP_MJ_POWER]                    = Power;
	DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL]           = SystemControl;*/
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

	ExInitializeResourceLite(&boot_lock);

	IoRegisterFileSystem(DeviceObject);

	return STATUS_SUCCESS;
}
