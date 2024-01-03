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
LIST_ENTRY VcbList;
ERESOURCE global_loading_lock;
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

static NTSTATUS get_device_pnp_name_guid(_In_ PDEVICE_OBJECT DeviceObject, _Out_ PUNICODE_STRING pnp_name, _In_ const GUID* guid)
{
	NTSTATUS Status;
	WCHAR* list = NULL, * s;

	Status = IoGetDeviceInterfaces((PVOID)guid, NULL, 0, &list);
	if (!NT_SUCCESS(Status))
	{
		ERR("IoGetDeviceInterfaces returned %08lx\n", Status);
		return Status;
	}

	s = list;
	while (s[0] != 0)
	{
		PFILE_OBJECT FileObject;
		PDEVICE_OBJECT devobj;
		UNICODE_STRING name;

		name.Length = name.MaximumLength = (USHORT)wcslen(s) * sizeof(WCHAR);
		name.Buffer = s;

		if (NT_SUCCESS(IoGetDeviceObjectPointer(&name, FILE_READ_ATTRIBUTES, &FileObject, &devobj)))
		{
			if (DeviceObject == devobj || DeviceObject == FileObject->DeviceObject)
			{
				ObDereferenceObject(FileObject);

				pnp_name->Buffer = ExAllocatePoolWithTag(PagedPool, name.Length, ALLOC_TAG);
				if (!pnp_name->Buffer)
				{
					ERR("out of memory\n");
					Status = STATUS_INSUFFICIENT_RESOURCES;
					goto end;
				}

				RtlCopyMemory(pnp_name->Buffer, name.Buffer, name.Length);
				pnp_name->Length = pnp_name->MaximumLength = name.Length;

				Status = STATUS_SUCCESS;
				goto end;
			}

			ObDereferenceObject(FileObject);
		}

		s = &s[wcslen(s) + 1];
	}

	pnp_name->Length = pnp_name->MaximumLength = 0;
	pnp_name->Buffer = 0;

	Status = STATUS_NOT_FOUND;

end:
	if (list)
	{
		ExFreePool(list);
	}

	return Status;
}

NTSTATUS get_device_pnp_name(_In_ PDEVICE_OBJECT DeviceObject, _Out_ PUNICODE_STRING pnp_name, _Out_ const GUID** guid)
{
	NTSTATUS Status;

	Status = get_device_pnp_name_guid(DeviceObject, pnp_name, &GUID_DEVINTERFACE_VOLUME);
	if (NT_SUCCESS(Status))
	{
		*guid = &GUID_DEVINTERFACE_VOLUME;
		return Status;
	}

	Status = get_device_pnp_name_guid(DeviceObject, pnp_name, &GUID_DEVINTERFACE_HIDDEN_VOLUME);
	if (NT_SUCCESS(Status))
	{
		*guid = &GUID_DEVINTERFACE_HIDDEN_VOLUME;
		return Status;
	}

	Status = get_device_pnp_name_guid(DeviceObject, pnp_name, &GUID_DEVINTERFACE_DISK);
	if (NT_SUCCESS(Status))
	{
		*guid = &GUID_DEVINTERFACE_DISK;
		return Status;
	}

	return STATUS_NOT_FOUND;
}

// simplified version of FsRtlAreNamesEqual, which can be a bottleneck!
static bool compare_strings(const UNICODE_STRING* us1, const UNICODE_STRING* us2)
{
	if (us1->Length != us2->Length)
	{
		return false;
	}

	WCHAR* s1 = us1->Buffer;
	WCHAR* s2 = us2->Buffer;

	for (unsigned int i = 0; i < us1->Length / sizeof(WCHAR); i++)
	{
		WCHAR c1 = *s1;
		WCHAR c2 = *s2;

		if (c1 != c2)
		{
			if (c1 >= 'a' && c1 <= 'z')
			{
				c1 = c1 - 'a' + 'A';
			}

			if (c2 >= 'a' && c2 <= 'z')
			{
				c2 = c2 - 'a' + 'A';
			}

			if (c1 != c2)
			{
				return false;
			}
		}

		s1++;
		s2++;
	}

	return true;
}

#define INIT_UNICODE_STRING(var, val) UNICODE_STRING us##var; us##var.Buffer = (WCHAR*)val; us##var.Length = us##var.MaximumLength = sizeof(val) - sizeof(WCHAR);

// This function exists because we have to lie about our FS type in certain situations.
// MPR!MprGetConnection queries the FS type, and compares it to a whitelist. If it doesn't match,
// it will return ERROR_NO_NET_OR_BAD_PATH, which prevents UAC from working.
// The command mklink refuses to create hard links on anything other than NTFS, so we have to
// blacklist cmd.exe too.

static bool lie_about_fs_type()
{
	NTSTATUS Status;
	PROCESS_BASIC_INFORMATION pbi;
	PPEB peb;
	LIST_ENTRY* le;
	ULONG retlen;
#ifdef _AMD64_
	ULONG_PTR wow64info;
#endif

	INIT_UNICODE_STRING(mpr, L"MPR.DLL");
	INIT_UNICODE_STRING(cmd, L"CMD.EXE");
	INIT_UNICODE_STRING(fsutil, L"FSUTIL.EXE");
	INIT_UNICODE_STRING(storsvc, L"STORSVC.DLL");
	INIT_UNICODE_STRING(javaw, L"JAVAW.EXE");

	/* Not doing a Volkswagen, honest! Some IFS tests won't run if not recognized FS. */
	INIT_UNICODE_STRING(ifstest, L"IFSTEST.EXE");

	if (!PsGetCurrentProcess())
	{
		return false;
	}

#ifdef _AMD64_
	Status = ZwQueryInformationProcess(NtCurrentProcess(), ProcessWow64Information, &wow64info, sizeof(wow64info), NULL);

	if (NT_SUCCESS(Status) && wow64info != 0)
	{
		return true;
	}
#endif

	Status = ZwQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &retlen);
	if (!NT_SUCCESS(Status))
	{
		ERR("ZwQueryInformationProcess returned %08lx\n", Status);
		return false;
	}

	if (!pbi.PebBaseAddress)
	{
		return false;
	}

	peb = pbi.PebBaseAddress;

	if (!peb->Ldr)
	{
		return false;
	}

	le = peb->Ldr->InMemoryOrderModuleList.Flink;
	while (le != &peb->Ldr->InMemoryOrderModuleList)
	{
		LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(le, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		bool blacklist = false;

		if (entry->FullDllName.Length >= usmpr.Length)
		{
			UNICODE_STRING name;

			name.Buffer = &entry->FullDllName.Buffer[(entry->FullDllName.Length - usmpr.Length) / sizeof(WCHAR)];
			name.Length = name.MaximumLength = usmpr.Length;

			blacklist = compare_strings(&name, &usmpr);
		}

		if (!blacklist && entry->FullDllName.Length >= uscmd.Length)
		{
			UNICODE_STRING name;

			name.Buffer = &entry->FullDllName.Buffer[(entry->FullDllName.Length - uscmd.Length) / sizeof(WCHAR)];
			name.Length = name.MaximumLength = uscmd.Length;

			blacklist = compare_strings(&name, &uscmd);
		}

		if (!blacklist && entry->FullDllName.Length >= usfsutil.Length)
		{
			UNICODE_STRING name;

			name.Buffer = &entry->FullDllName.Buffer[(entry->FullDllName.Length - usfsutil.Length) / sizeof(WCHAR)];
			name.Length = name.MaximumLength = usfsutil.Length;

			blacklist = compare_strings(&name, &usfsutil);
		}

		if (!blacklist && entry->FullDllName.Length >= usstorsvc.Length)
		{
			UNICODE_STRING name;

			name.Buffer = &entry->FullDllName.Buffer[(entry->FullDllName.Length - usstorsvc.Length) / sizeof(WCHAR)];
			name.Length = name.MaximumLength = usstorsvc.Length;

			blacklist = compare_strings(&name, &usstorsvc);
		}

		if (!blacklist && entry->FullDllName.Length >= usjavaw.Length)
		{
			UNICODE_STRING name;

			name.Buffer = &entry->FullDllName.Buffer[(entry->FullDllName.Length - usjavaw.Length) / sizeof(WCHAR)];
			name.Length = name.MaximumLength = usjavaw.Length;

			blacklist = compare_strings(&name, &usjavaw);
		}

		if (!blacklist && entry->FullDllName.Length >= usifstest.Length)
		{
			UNICODE_STRING name;

			name.Buffer = &entry->FullDllName.Buffer[(entry->FullDllName.Length - usifstest.Length) / sizeof(WCHAR)];
			name.Length = name.MaximumLength = usifstest.Length;

			blacklist = compare_strings(&name, &usifstest);
		}

		if (blacklist)
		{
			void** frames;
			ULONG i, num_frames;

			frames = ExAllocatePoolWithTag(PagedPool, 256 * sizeof(void*), ALLOC_TAG);
			if (!frames)
			{
				ERR("out of memory\n");
				return false;
			}

			num_frames = RtlWalkFrameChain(frames, 256, 1);

			for (i = 0; i < num_frames; i++)
			{
				// entry->Reserved3[1] appears to be the image size
				if (frames[i] >= entry->DllBase && (ULONG_PTR)frames[i] <= (ULONG_PTR)entry->DllBase + (ULONG_PTR)entry->Reserved3[1])
				{
					ExFreePool(frames);
					return true;
				}
			}

			ExFreePool(frames);
		}

		le = le->Flink;
	}

	return false;
}

static void calculate_total_space(_In_ device_extension* Vcb, _Out_ uint64_t* totalsize, _Out_ uint64_t* freespace)
{
	*totalsize = Vcb->vde->pdode->KMCSFS.size - (Vcb->vde->pdode->KMCSFS.tablesize * Vcb->vde->pdode->KMCSFS.sectorsize);
	*freespace = *totalsize;//
}

_Dispatch_type_(IRP_MJ_QUERY_VOLUME_INFORMATION)
_Function_class_(DRIVER_DISPATCH)
static NTSTATUS __stdcall QueryVolumeInformation(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	PIO_STACK_LOCATION IrpSp;
	NTSTATUS Status;
	ULONG BytesCopied = 0;
	device_extension* Vcb = DeviceObject->DeviceExtension;
	bool top_level;

	FsRtlEnterFileSystem();

	TRACE("query volume information\n");
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

	Status = STATUS_NOT_IMPLEMENTED;

	switch (IrpSp->Parameters.QueryVolume.FsInformationClass)
	{
	case FileFsAttributeInformation:
	{
		FILE_FS_ATTRIBUTE_INFORMATION* data = Irp->AssociatedIrp.SystemBuffer;
		bool overflow = false;
		static const WCHAR ntfs[] = L"NTFS";
		static const WCHAR KMCSpaceFS[] = L"KMCSpaceFS";
		const WCHAR* fs_name;
		ULONG fs_name_len, orig_fs_name_len;

		if (Irp->RequestorMode == UserMode && lie_about_fs_type())
		{
			fs_name = ntfs;
			orig_fs_name_len = fs_name_len = sizeof(ntfs) - sizeof(WCHAR);
		}
		else
		{
			fs_name = KMCSpaceFS;
			orig_fs_name_len = fs_name_len = sizeof(KMCSpaceFS) - sizeof(WCHAR);
		}

		TRACE("FileFsAttributeInformation\n");

		if (IrpSp->Parameters.QueryVolume.Length < sizeof(FILE_FS_ATTRIBUTE_INFORMATION) - sizeof(WCHAR) + fs_name_len)
		{
			if (IrpSp->Parameters.QueryVolume.Length > sizeof(FILE_FS_ATTRIBUTE_INFORMATION) - sizeof(WCHAR))
			{
				fs_name_len = IrpSp->Parameters.QueryVolume.Length - sizeof(FILE_FS_ATTRIBUTE_INFORMATION) + sizeof(WCHAR);
			}
			else
			{
				fs_name_len = 0;
			}

			overflow = true;
		}

		data->FileSystemAttributes = FILE_CASE_PRESERVED_NAMES | FILE_CASE_SENSITIVE_SEARCH | FILE_UNICODE_ON_DISK | FILE_NAMED_STREAMS | FILE_SUPPORTS_HARD_LINKS | FILE_PERSISTENT_ACLS | FILE_SUPPORTS_REPARSE_POINTS | FILE_SUPPORTS_SPARSE_FILES | FILE_SUPPORTS_OBJECT_IDS | FILE_SUPPORTS_OPEN_BY_FILE_ID | FILE_SUPPORTS_BLOCK_REFCOUNTING | FILE_SUPPORTS_POSIX_UNLINK_RENAME;
		if (Vcb->readonly)
		{
			data->FileSystemAttributes |= FILE_READ_ONLY_VOLUME;
		}

		// should also be FILE_FILE_COMPRESSION when supported
		data->MaximumComponentNameLength = 255; // FIXME - check
		data->FileSystemNameLength = orig_fs_name_len;
		RtlCopyMemory(data->FileSystemName, fs_name, fs_name_len);

		BytesCopied = sizeof(FILE_FS_ATTRIBUTE_INFORMATION) - sizeof(WCHAR) + fs_name_len;
		Status = overflow ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
		break;
	}

	case FileFsDeviceInformation:
	{
		FILE_FS_DEVICE_INFORMATION* ffdi = Irp->AssociatedIrp.SystemBuffer;

		TRACE("FileFsDeviceInformation\n");

		ffdi->DeviceType = FILE_DEVICE_DISK;

		ExAcquireResourceSharedLite(&Vcb->tree_lock, true);
		ffdi->Characteristics = Vcb->Vpb->RealDevice->Characteristics;
		ExReleaseResourceLite(&Vcb->tree_lock);

		if (Vcb->readonly)
		{
			ffdi->Characteristics |= FILE_READ_ONLY_DEVICE;
		}
		else
		{
			ffdi->Characteristics &= ~FILE_READ_ONLY_DEVICE;
		}

		BytesCopied = sizeof(FILE_FS_DEVICE_INFORMATION);
		Status = STATUS_SUCCESS;

		break;
	}

	case FileFsFullSizeInformation:
	{
		FILE_FS_FULL_SIZE_INFORMATION* ffsi = Irp->AssociatedIrp.SystemBuffer;

		TRACE("FileFsFullSizeInformation\n");

		calculate_total_space(Vcb, (uint64_t*)&ffsi->TotalAllocationUnits.QuadPart, (uint64_t*)&ffsi->ActualAvailableAllocationUnits.QuadPart);
		ffsi->CallerAvailableAllocationUnits.QuadPart = ffsi->ActualAvailableAllocationUnits.QuadPart;
		ffsi->SectorsPerAllocationUnit = Vcb->vde->pdode->KMCSFS.sectorsize / 512;
		ffsi->BytesPerSector = 512;

		BytesCopied = sizeof(FILE_FS_FULL_SIZE_INFORMATION);
		Status = STATUS_SUCCESS;

		break;
	}

	case FileFsObjectIdInformation:
	{
		FILE_FS_OBJECTID_INFORMATION* ffoi = Irp->AssociatedIrp.SystemBuffer;

		TRACE("FileFsObjectIdInformation\n");

		RtlCopyMemory(ffoi->ObjectId, &Vcb->vde->pdode->KMCSFS.uuid.uuid[0], sizeof(UCHAR) * 16);
		RtlZeroMemory(ffoi->ExtendedInfo, sizeof(ffoi->ExtendedInfo));

		BytesCopied = sizeof(FILE_FS_OBJECTID_INFORMATION);
		Status = STATUS_SUCCESS;

		break;
	}

	case FileFsSizeInformation:
	{
		FILE_FS_SIZE_INFORMATION* ffsi = Irp->AssociatedIrp.SystemBuffer;

		TRACE("FileFsSizeInformation\n");

		calculate_total_space(Vcb, (uint64_t*)&ffsi->TotalAllocationUnits.QuadPart, (uint64_t*)&ffsi->AvailableAllocationUnits.QuadPart);
		ffsi->SectorsPerAllocationUnit = Vcb->vde->pdode->KMCSFS.sectorsize / 512;
		ffsi->BytesPerSector = 512;

		BytesCopied = sizeof(FILE_FS_SIZE_INFORMATION);
		Status = STATUS_SUCCESS;

		break;
	}

	/*case FileFsVolumeInformation:
	{
		FILE_FS_VOLUME_INFORMATION* data = Irp->AssociatedIrp.SystemBuffer;
		FILE_FS_VOLUME_INFORMATION ffvi;
		bool overflow = false;
		ULONG label_len, orig_label_len;

		TRACE("FileFsVolumeInformation\n");
		TRACE("max length = %lu\n", IrpSp->Parameters.QueryVolume.Length);

		ExAcquireResourceSharedLite(&Vcb->tree_lock, true);

		Status = utf8_to_utf16(NULL, 0, &label_len, Vcb->superblock.label, (ULONG)strlen(Vcb->superblock.label));
		if (!NT_SUCCESS(Status))
		{
			ERR("utf8_to_utf16 returned %08lx\n", Status);
			ExReleaseResourceLite(&Vcb->tree_lock);
			break;
		}

		orig_label_len = label_len;

		if (IrpSp->Parameters.QueryVolume.Length < offsetof(FILE_FS_VOLUME_INFORMATION, VolumeLabel) + label_len) {
			if (IrpSp->Parameters.QueryVolume.Length > offsetof(FILE_FS_VOLUME_INFORMATION, VolumeLabel))
			{
				label_len = IrpSp->Parameters.QueryVolume.Length - offsetof(FILE_FS_VOLUME_INFORMATION, VolumeLabel);
			}
			else
			{
				label_len = 0;
			}

			overflow = true;
		}

		TRACE("label_len = %lu\n", label_len);

		RtlZeroMemory(&ffvi, offsetof(FILE_FS_VOLUME_INFORMATION, VolumeLabel));

		ffvi.VolumeSerialNumber = Vcb->vde->pdode->KMCSFS.uuid.uuid[12] << 24 | Vcb->vde->pdode->KMCSFS.uuid.uuid[13] << 16 | Vcb->vde->pdode->KMCSFS.uuid.uuid[14] << 8 | Vcb->vde->pdode->KMCSFS.uuid.uuid[15];
		ffvi.VolumeLabelLength = orig_label_len;

		RtlCopyMemory(data, &ffvi, min(offsetof(FILE_FS_VOLUME_INFORMATION, VolumeLabel), IrpSp->Parameters.QueryVolume.Length));

		if (label_len > 0)
		{
			ULONG bytecount;

			Status = utf8_to_utf16(&data->VolumeLabel[0], label_len, &bytecount, Vcb->superblock.label, (ULONG)strlen(Vcb->superblock.label));
			if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW)
			{
				ERR("utf8_to_utf16 returned %08lx\n", Status);
				ExReleaseResourceLite(&Vcb->tree_lock);
				break;
			}

			TRACE("label = %.*S\n", (int)(label_len / sizeof(WCHAR)), data->VolumeLabel);
		}

		ExReleaseResourceLite(&Vcb->tree_lock);

		BytesCopied = offsetof(FILE_FS_VOLUME_INFORMATION, VolumeLabel) + label_len;
		Status = overflow ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
		break;
	}*/

#ifdef _MSC_VER // not in mingw yet
	case FileFsSectorSizeInformation:
	{
		FILE_FS_SECTOR_SIZE_INFORMATION* data = Irp->AssociatedIrp.SystemBuffer;

		data->LogicalBytesPerSector = 512;
		data->PhysicalBytesPerSectorForAtomicity = Vcb->vde->pdode->KMCSFS.sectorsize;
		data->PhysicalBytesPerSectorForPerformance = Vcb->vde->pdode->KMCSFS.sectorsize;
		data->FileSystemEffectivePhysicalBytesPerSectorForAtomicity = Vcb->vde->pdode->KMCSFS.sectorsize;
		data->ByteOffsetForSectorAlignment = 0;
		data->ByteOffsetForPartitionAlignment = 0;

		data->Flags = SSINFO_FLAGS_ALIGNED_DEVICE | SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE;

		if (Vcb->trim && !Vcb->options.no_trim)
		{
			data->Flags |= SSINFO_FLAGS_TRIM_ENABLED;
		}

		BytesCopied = sizeof(FILE_FS_SECTOR_SIZE_INFORMATION);
		Status = STATUS_SUCCESS;

		break;
	}
#endif

	default:
		Status = STATUS_INVALID_PARAMETER;
		WARN("unknown FsInformationClass %u\n", IrpSp->Parameters.QueryVolume.FsInformationClass);
		break;
	}

	if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW)
	{
		Irp->IoStatus.Information = 0;
	}
	else
	{
		Irp->IoStatus.Information = BytesCopied;
	}

end:
	Irp->IoStatus.Status = Status;

	IoCompleteRequest(Irp, IO_DISK_INCREMENT);

	if (top_level)
	{
		IoSetTopLevelIrp(NULL);
	}

	TRACE("query volume information returning %08lx\n", Status);

	FsRtlExitFileSystem();

	return Status;
}

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
		}
		except(EXCEPTION_EXECUTE_HANDLER)
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
	UNICODE_STRING volname;
	ULONG i;
	WCHAR* s;
	pdo_device_extension* pdode = NULL;
	PDEVICE_OBJECT voldev;
	volume_device_extension* vde;
	UNICODE_STRING arc_name_us;
	WCHAR* anp;

	static const WCHAR arc_name_prefix[] = L"\\ArcName\\CSpaceFS(";

	WCHAR arc_name[(sizeof(arc_name_prefix) / sizeof(WCHAR)) - 1 + 37];

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

	volname.Length = volname.MaximumLength = (sizeof(KMCSPACEFS_VOLUME_PREFIX) - sizeof(WCHAR)) + ((36 + 1) * sizeof(WCHAR));
	volname.Buffer = ExAllocatePoolWithTag(PagedPool, volname.MaximumLength, ALLOC_TAG); // FIXME - when do we free this?

	if (!volname.Buffer)
	{
		ERR("out of memory\n");
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto end2;
	}

	RtlCopyMemory(volname.Buffer, KMCSPACEFS_VOLUME_PREFIX, sizeof(KMCSPACEFS_VOLUME_PREFIX) - sizeof(WCHAR));
	RtlCopyMemory(arc_name, arc_name_prefix, sizeof(arc_name_prefix) - sizeof(WCHAR));

	anp = &arc_name[(sizeof(arc_name_prefix) / sizeof(WCHAR)) - 1];
	s = &volname.Buffer[(sizeof(KMCSPACEFS_VOLUME_PREFIX) / sizeof(WCHAR)) - 1];

	for (i = 0; i < 16; i++)
	{
		*s = *anp = hex_digit(pdode->KMCSFS.uuid.uuid[i] >> 4);
		s++;
		anp++;

		*s = *anp = hex_digit(pdode->KMCSFS.uuid.uuid[i] & 0xf);
		s++;
		anp++;

		if (i == 3 || i == 5 || i == 7 || i == 9)
		{
			*s = *anp = '-';
			s++;
			anp++;
		}
	}

	*s = '}';
	*anp = ')';

	Status = IoCreateDevice(drvobj, sizeof(volume_device_extension), &volname, FILE_DEVICE_DISK, is_windows_8 ? FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSAL : 0, false, &voldev);
	if (!NT_SUCCESS(Status))
	{
		ERR("IoCreateDevice returned %08lx\n", Status);
		goto end2;
	}

	arc_name_us.Buffer = arc_name;
	arc_name_us.Length = arc_name_us.MaximumLength = sizeof(arc_name);

	Status = IoCreateSymbolicLink(&arc_name_us, &volname);
	if (!NT_SUCCESS(Status))
	{
		WARN("IoCreateSymbolicLink returned %08lx\n", Status);
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

	if (RtlCompareMemory(&boot_uuid, &pdode->KMCSFS.uuid, sizeof(KMCSpaceFS_UUID)) == sizeof(KMCSpaceFS_UUID))
	{
		voldev->Flags |= DO_SYSTEM_BOOT_PARTITION;
		PhysicalDeviceObject->Flags |= DO_SYSTEM_BOOT_PARTITION;
	}

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

	DriverObject->MajorFunction[IRP_MJ_CREATE]                   = Create;
	//DriverObject->MajorFunction[IRP_MJ_CLOSE]                    = Close;
	//DriverObject->MajorFunction[IRP_MJ_READ]                     = Read;
	//DriverObject->MajorFunction[IRP_MJ_WRITE]                    = Write;
	//DriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION]        = QueryInformation;
	//DriverObject->MajorFunction[IRP_MJ_SET_INFORMATION]          = SetInformation;
	//DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS]            = FlushBuffers;
	DriverObject->MajorFunction[IRP_MJ_QUERY_VOLUME_INFORMATION] = QueryVolumeInformation;
	//DriverObject->MajorFunction[IRP_MJ_SET_VOLUME_INFORMATION]   = SetVolumeInformation;
	///DriverObject->MajorFunction[IRP_MJ_DIRECTORY_CONTROL]        = DirectoryControl;
	//DriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL]      = FileSystemControl;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]           = DeviceControl;
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

	InitializeListHead(&VcbList);
	ExInitializeResourceLite(&global_loading_lock);
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

	check_system_root();

	return STATUS_SUCCESS;
}
