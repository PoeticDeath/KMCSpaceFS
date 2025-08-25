// Copyright (c) Anthony Kerr 2023-

#pragma once

#undef _WIN32_WINNT
#undef NTDDI_VERSION

#define _WIN32_WINNT 0x0601
#define NTDDI_VERSION 0x0A000002 // WIN10_RS1
#define _CRT_SECURE_NO_WARNINGS
#define _NO_CRT_STDIO_INLINE

#ifdef _MSC_VER
#define funcname __FUNCTION__
#else
#define funcname __func__
#endif

#include <ntifs.h>
#include <ntddk.h>
#include <mountmgr.h>
#include <windef.h>
#include <wdm.h>

#ifdef _MSC_VER
#pragma warning(pop)
#else
#pragma GCC diagnostic pop
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "KMCSpaceFS.h"
#include "KMCSpaceFSioctl.h"

extern uint32_t mount_flush_interval;
extern uint32_t mount_readonly;
extern uint32_t no_pnp;

#ifndef __GNUC__
#define __attribute__(x)
#endif

#define TRACE(s, ...) DbgPrint("KMCSpaceFS TRACE : %s : " s, funcname, ##__VA_ARGS__)
#define WARN(s, ...) DbgPrint("KMCSpaceFS WARN : %s : " s, funcname, ##__VA_ARGS__)
#define ERR(s, ...) DbgPrint("KMCSpaceFS ERR : %s : " s, funcname, ##__VA_ARGS__)

#define ALLOC_TAG 0x70534B41 //'AKSp'
#define KMCSpaceFS_NODE_TYPE_CCB 0x2295
#define KMCSpaceFS_NODE_TYPE_FCB 0x2296
#define UNUSED(x) (void)(x)
#define VCB_TYPE_FS      1
#define VCB_TYPE_CONTROL 2
#define VCB_TYPE_VOLUME  3
#define VCB_TYPE_PDO     4
#define VCB_TYPE_BUS     5

#define KMCSPACEFS_VOLUME_PREFIX L"\\Device\\CSpaceFS{"

#define hex_digit(c) ((c) <= 9) ? ((c) + '0') : ((c) - 10 + 'a')

#if defined(_MSC_VER) || defined(__clang__)
#define try __try
#define except __except
#define finally __finally
#define leave __leave
#else
#define try if (1)
#define except(x) if (0 && (x))
#define finally if (1)
#define leave
#endif

typedef struct _fcb_nonpaged
{
	FAST_MUTEX HeaderMutex;
	SECTION_OBJECT_POINTERS segment_object;
	ERESOURCE resource;
	ERESOURCE paging_resource;
	ERESOURCE dir_children_lock;
} fcb_nonpaged;

typedef struct
{
	uint8_t type;
	ANSI_STRING utf8;
	UNICODE_STRING name;
	UNICODE_STRING name_uc;
	ULONG size;
	bool root_dir;
	LIST_ENTRY list_entry_index;
} dir_child;

typedef struct _fcb
{
	FSRTL_ADVANCED_FCB_HEADER Header;
	struct _fcb_nonpaged* nonpaged;
	LONG refcount;
	POOL_TYPE pool_type;
	struct _device_extension* Vcb;
	uint8_t type;
	bool deleted;
	PKTHREAD lazy_writer_thread;
	LIST_ENTRY extents;
	ANSI_STRING reparse_xattr;
	bool inode_item_changed;
	LIST_ENTRY list_entry;
	LIST_ENTRY list_entry_all;
	LIST_ENTRY list_entry_dirty;
} fcb;

typedef struct _ccb
{
	USHORT NodeType;
	CSHORT NodeSize;
	ULONG disposition;
	ULONG options;
	uint64_t query_dir_offset;
	uint64_t query_dir_index;
	uint64_t query_dir_file_count;
	ACCESS_MASK access;
	UNICODE_STRING filename;
	UNICODE_STRING filter;
	bool manage_volume_privilege;
	bool delete_on_close;
} ccb;

typedef struct
{
	PDEVICE_OBJECT devobj;
	PFILE_OBJECT fileobj;
	bool removable;
	bool readonly;
	bool reloc;
	bool trim;
	bool can_flush;
	ULONG change_count;
	ULONG disk_num;
	ULONG part_num;
	uint64_t stats[5];
	bool stats_changed;
	LIST_ENTRY space;
	LIST_ENTRY list_entry;
	ULONG num_trim_entries;
	LIST_ENTRY trim_list;
} device;

typedef struct
{
	bool readonly;
	uint32_t flush_interval;
	bool no_trim;
	uint64_t subvol_id;
} mount_options;

typedef struct _device_extension
{
	uint32_t type;
	mount_options options;
	PVPB Vpb;
	PDEVICE_OBJECT devobj;
	struct _volume_device_extension* vde;
	LIST_ENTRY devices;
	bool readonly;
	bool trim;
	bool removing;
	bool disallow_dismount;
	LONG page_file_count;
	fcb* volume_fcb;
	LONG open_files;
	ERESOURCE load_lock;
	bool need_write;
	_Has_lock_level_(tree_lock) ERESOURCE tree_lock;
	PNOTIFY_SYNC NotifySync;
	LIST_ENTRY DirNotifyList;
	PFILE_OBJECT root_file;
	PAGED_LOOKASIDE_LIST fcb_lookaside;
	NPAGED_LOOKASIDE_LIST fcb_np_lookaside;
	LIST_ENTRY list_entry;
} device_extension;

typedef struct
{
	uint32_t type;
} control_device_extension;

typedef struct
{
	uint32_t type;
	PDEVICE_OBJECT buspdo;
	PDEVICE_OBJECT attached_device;
	UNICODE_STRING bus_name;
} bus_device_extension;

typedef struct
{
	PDEVICE_OBJECT devobj;
	PFILE_OBJECT fileobj;
	UNICODE_STRING pnp_name;
	uint64_t size;
	bool had_drive_letter;
	void* notification_entry;
	ULONG disk_num;
	ULONG part_num;
	bool boot_volume;
	LIST_ENTRY list_entry;

	KMCSpaceFS KMCSFS;
} volume_child;

typedef struct _volume_device_extension
{
	uint32_t type;
	UNICODE_STRING name;
	PDEVICE_OBJECT device;
	PDEVICE_OBJECT mounted_device;
	PDEVICE_OBJECT pdo;
	struct pdo_device_extension* pdode;
	UNICODE_STRING bus_name;
	PDEVICE_OBJECT attached_device;
	bool removing;
	bool dead;
	LONG open_count;
} volume_device_extension;

typedef struct pdo_device_extension
{
	uint32_t type;
	volume_device_extension* vde;
	PDEVICE_OBJECT pdo;
	bool removable;
	bool dont_report;

	uint64_t num_children;
	uint64_t children_loaded;
	ERESOURCE child_lock;
	LIST_ENTRY children;

	KMCSpaceFS KMCSFS;

	LIST_ENTRY list_entry;
} pdo_device_extension;

static __inline void* map_user_buffer(PIRP Irp, ULONG priority)
{
	if (!Irp->MdlAddress)
	{
		return Irp->UserBuffer;
	}
	else
	{
		return MmGetSystemAddressForMdlSafe(Irp->MdlAddress, priority | MdlMappingNoExecute);
	}
}

_Post_satisfies_(return >= n)
__inline static uint64_t sector_align(_In_ uint64_t n, _In_ uint64_t a)
{
	if (n & (a - 1))
	{
		n = (n + a) & ~(a - 1);
	}

	return n;
}

// in registry.c
void read_registry(PUNICODE_STRING regpath, bool refresh);
void watch_registry(HANDLE regh);
NTSTATUS registry_mark_volume_mounted(KMCSpaceFS_UUID uuid);
NTSTATUS registry_mark_volume_unmounted(KMCSpaceFS_UUID uuid);
NTSTATUS registry_load_volume_options(device_extension* Vcb);

// in pnp.c
_Dispatch_type_(IRP_MJ_PNP)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS __stdcall Pnp(PDEVICE_OBJECT DeviceObject, PIRP Irp);

NTSTATUS pnp_surprise_removal(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS pnp_query_remove_device(PDEVICE_OBJECT DeviceObject, PIRP Irp);

// in search.c
NTSTATUS remove_drive_letter(PDEVICE_OBJECT mountmgr, PUNICODE_STRING devpath);

_Function_class_(KSTART_ROUTINE)
void __stdcall mountmgr_thread(_In_ void* context);

_Function_class_(DRIVER_NOTIFICATION_CALLBACK_ROUTINE)
NTSTATUS __stdcall pnp_notification(PVOID NotificationStructure, PVOID Context);

void disk_arrival(PUNICODE_STRING devpath);
bool volume_arrival(PUNICODE_STRING devpath, bool fve_callback);
void volume_removal(PUNICODE_STRING devpath);

_Function_class_(DRIVER_NOTIFICATION_CALLBACK_ROUTINE)
NTSTATUS __stdcall volume_notification(PVOID NotificationStructure, PVOID Context);

typedef NTSTATUS(__stdcall* tIoUnregisterPlugPlayNotificationEx)(PVOID NotificationEntry);

bool remove_volume_child(_Inout_ _Requires_exclusive_lock_held_(_Curr_->child_lock) _Releases_exclusive_lock_(_Curr_->child_lock) _In_ volume_device_extension* vde, _In_ volume_child* vc, _In_ bool skip_dev);

// in KMCSpaceFS.c
bool is_top_level(_In_ PIRP Irp);
NTSTATUS dev_ioctl(_In_ PDEVICE_OBJECT DeviceObject, _In_ ULONG ControlCode, _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer, _In_ ULONG InputBufferSize, _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer, _In_ ULONG OutputBufferSize, _In_ bool Override, _Out_opt_ IO_STATUS_BLOCK* iosb);
NTSTATUS sync_read_phys(_In_ PDEVICE_OBJECT DeviceObject, _In_ PFILE_OBJECT FileObject, _In_ uint64_t StartingOffset, _In_ ULONG Length, _Out_writes_bytes_(Length) PUCHAR Buffer, _In_ bool override);
NTSTATUS sync_write_phys(_In_ PDEVICE_OBJECT DeviceObject, _In_ PFILE_OBJECT FileObject, _In_ uint64_t StartingOffset, _In_ ULONG Length, _Out_writes_bytes_(Length) PUCHAR Buffer, _In_ bool override);
void init_device(_In_ device_extension* Vcb, _Inout_ device* dev, _In_ bool get_nums);
NTSTATUS get_device_pnp_name(_In_ PDEVICE_OBJECT DeviceObject, _Out_ PUNICODE_STRING pnp_name, _Out_ const GUID** guid);
void uninit(_In_ device_extension* Vcb);
extern ERESOURCE op_lock;
bool is_windows_7;

_Function_class_(DRIVER_ADD_DEVICE)
NTSTATUS __stdcall AddDevice(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT PhysicalDeviceObject);

void free_fcb(_Inout_ fcb* fcb);
void reap_fcb(fcb* fcb);
void do_shutdown(PIRP Irp);

// in volume.c
NTSTATUS vol_create(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS vol_close(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS vol_read(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS vol_write(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS vol_device_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
void add_volume_device(KMCSpaceFS KMCSFS, PUNICODE_STRING devpath, uint64_t length, ULONG disk_num, ULONG part_num);
NTSTATUS mountmgr_add_drive_letter(PDEVICE_OBJECT mountmgr, PUNICODE_STRING devpath);

_Function_class_(DRIVER_NOTIFICATION_CALLBACK_ROUTINE)
NTSTATUS __stdcall pnp_removal(PVOID NotificationStructure, PVOID Context);

void free_vol(volume_device_extension* vde);

// in boot.c
void check_system_root();
void boot_add_device(DEVICE_OBJECT* pdo);
extern KMCSpaceFS_UUID boot_uuid;

// in devctrl.c
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS __stdcall DeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

// in create.c
_Dispatch_type_(IRP_MJ_CREATE)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS __stdcall Create(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

fcb* create_fcb(device_extension* Vcb, POOL_TYPE pool_type);

// in CSpaceFS.c
extern unsigned* emap;
extern unsigned* dmap;
void init_maps();
char* encode(char* str, unsigned long long len);
char* decode(char* bytes, unsigned long long len);
unsigned long long get_filename_index(UNICODE_STRING FileName, KMCSpaceFS* KMCSFS);
bool incmp(unsigned char a, unsigned char b);
unsigned long long chtime(unsigned long long filenameindex, unsigned long long time, unsigned ch, KMCSpaceFS KMCSFS);
unsigned long chwinattrs(unsigned long long filenameindex, unsigned long winattrs, KMCSpaceFS KMCSFS);
unsigned long long get_file_size(unsigned long long index, KMCSpaceFS KMCSFS);
NTSTATUS read_file(fcb* fcb, uint8_t* data, unsigned long long start, unsigned long long length, unsigned long long index, unsigned long long* bytes_read, PFILE_OBJECT file_object);
NTSTATUS write_file(fcb* fcb, uint8_t* data, unsigned long long start, unsigned long long length, unsigned long long index, unsigned long long size, PFILE_OBJECT file_object);
NTSTATUS create_file(PIRP Irp, device_extension* Vcb, PFILE_OBJECT FileObject, UNICODE_STRING fn);
bool find_block(KMCSpaceFS* KMCSFS, unsigned long long index, unsigned long long size, PFILE_OBJECT FileObject);
dealloc(KMCSpaceFS* KMCSFS, unsigned long long index, unsigned long long size, unsigned long long newsize);
bool delete_file(KMCSpaceFS* KMCSFS, UNICODE_STRING filename, unsigned long long index, PFILE_OBJECT FileObject);
NTSTATUS rename_file(KMCSpaceFS* KMCSFS, UNICODE_STRING fn, UNICODE_STRING nfn, PFILE_OBJECT FileObject);

// in dirctrl.c
_Dispatch_type_(IRP_MJ_DIRECTORY_CONTROL)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS __stdcall DirectoryControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

NTSTATUS query_directory(PIRP Irp);

// in fileinfo.c
_Dispatch_type_(IRP_MJ_QUERY_INFORMATION)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS __stdcall QueryInformation(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

_Dispatch_type_(IRP_MJ_SET_INFORMATION)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS __stdcall SetInformation(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

// in read.c
_Dispatch_type_(IRP_MJ_READ)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS __stdcall Read(PDEVICE_OBJECT DeviceObject, PIRP Irp);

// in security.c
_Dispatch_type_(IRP_MJ_QUERY_SECURITY)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS __stdcall QuerySecurity(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

_Dispatch_type_(IRP_MJ_SET_SECURITY)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS __stdcall SetSecurity(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

NTSTATUS AccessCheck(PIRP Irp, device_extension* Vcb, UNICODE_STRING* FileName, ACCESS_MASK* granted_access);
BOOL WINAPI ConvertSecurityDescriptorToStringSecurityDescriptorW(PSECURITY_DESCRIPTOR SecurityDescriptor, DWORD SDRevision, SECURITY_INFORMATION RequestedInformation, LPWSTR* OutputString, PULONG OutputLen);
BOOL WINAPI ConvertStringSecurityDescriptorToSecurityDescriptorW(LPCWSTR StringSecurityDescriptor, DWORD StringSDRevision, PSECURITY_DESCRIPTOR* SecurityDescriptor, PULONG SecurityDescriptorSize, SECURITY_INFORMATION SecurityInformation);
#define SDDL_REVISION 1

// in write.c
_Dispatch_type_(IRP_MJ_WRITE)
_Function_class_(DRIVER_DISPATCH)
__attribute__((nonnull(1,2)))
NTSTATUS __stdcall Write(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

// in fsctl.c
NTSTATUS dismount_volume(device_extension* Vcb, bool shutdown, PIRP Irp);
NTSTATUS fsctl_request(PDEVICE_OBJECT DeviceObject, PIRP* Pirp, uint32_t type);

// in fastio.c
void init_fast_io_dispatch(FAST_IO_DISPATCH** fiod);

// not in DDK headers - taken from winternl.h
typedef struct _LDR_DATA_TABLE_ENTRY
{
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID Reserved3[2];
	UNICODE_STRING FullDllName;
	BYTE Reserved4[8];
	PVOID Reserved5[3];
	union
	{
		ULONG CheckSum;
		PVOID Reserved6;
	};
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA
{
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef VOID(NTAPI* PPS_POST_PROCESS_INIT_ROUTINE)(VOID);

typedef struct _PEB
{
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	BYTE Reserved4[104];
	PVOID Reserved5[52];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE Reserved6[128];
	PVOID Reserved7[1];
	ULONG SessionId;
} PEB, *PPEB;
