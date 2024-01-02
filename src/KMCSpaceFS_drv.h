// Copyright (c) Anthony Kerr 2023-

#pragma once

#undef _WIN32_WINNT
#undef NTDDI_VERSION

#define _WIN32_WINNT 0x0601
#define NTDDI_VERSION 0x06020000 // Win 8
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

#ifdef _DEBUG
extern bool log_started;
extern uint32_t debug_log_level;

#define MSG(fn, s, level, ...) (!log_started || level <= debug_log_level) ? _debug_message(fn, s, ##__VA_ARGS__) : (void)0
void _debug_message(_In_ const char* func, _In_ char* s, ...) __attribute__((format(printf, 2, 3)));
#else
#define MSG(s, ...) do { } while(0)
#endif

#define TRACE(s, ...) do { } while(0)
#define WARN(s, ...) MSG(funcname, s, 2, ##__VA_ARGS__)
#define ERR(s, ...) DbgPrint("KMCSpaceFS ERR : %s : " s, funcname, ##__VA_ARGS__)

#define ALLOC_TAG 0x7442484D //'MHBt'
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

typedef struct
{
    uint64_t index;
    uint8_t type;
    ANSI_STRING utf8;
    UNICODE_STRING name;
    UNICODE_STRING name_uc;
    ULONG size;
    struct _file_ref* fileref;
    bool root_dir;
    LIST_ENTRY list_entry_index;
} dir_child;

typedef struct _fcb
{
    FSRTL_ADVANCED_FCB_HEADER Header;
    struct _fcb_nonpaged* nonpaged;
    LONG refcount;
    struct _device_extension* Vcb;
    struct _root* subvol;
    uint8_t type;
    SECURITY_DESCRIPTOR* sd;
    FILE_LOCK lock;
    bool deleted;
    PKTHREAD lazy_writer_thread;
    ULONG atts;
    SHARE_ACCESS share_access;
    LIST_ENTRY extents;
    ANSI_STRING reparse_xattr;
    LIST_ENTRY hardlinks;
    struct _file_ref* fileref;
    bool inode_item_changed;
    OPLOCK oplock;
    LIST_ENTRY list_entry;
    LIST_ENTRY list_entry_all;
    LIST_ENTRY list_entry_dirty;
} fcb;

typedef struct _file_ref
{
    fcb* fcb;
    ANSI_STRING oldutf8;
    uint64_t oldindex;
    bool delete_on_close;
    bool posix_delete;
    bool deleted;
    bool created;
    LIST_ENTRY children;
    LONG refcount;
    LONG open_count;
    struct _file_ref* parent;
    dir_child* dc;

    bool dirty;

    LIST_ENTRY list_entry;
    LIST_ENTRY list_entry_dirty;
} file_ref;

typedef struct
{
    PDEVICE_OBJECT devobj;
    PFILE_OBJECT fileobj;
    DEV_ITEM devitem;
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
    LONG page_file_count;
    file_ref* root_fileref;
    LONG open_files;
    bool need_write;
    _Has_lock_level_(tree_lock) ERESOURCE tree_lock;
    PFILE_OBJECT root_file;
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
NTSTATUS registry_load_volume_options(device_extension* Vcb);
void watch_registry(HANDLE regh);

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

// in KMCSpaceFS.c
bool is_top_level(_In_ PIRP Irp);
NTSTATUS dev_ioctl(_In_ PDEVICE_OBJECT DeviceObject, _In_ ULONG ControlCode, _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer, _In_ ULONG InputBufferSize, _Out_writes_bytes_opt_(OutputBufferSize) PVOID OutputBuffer, _In_ ULONG OutputBufferSize, _In_ bool Override, _Out_opt_ IO_STATUS_BLOCK* iosb);
NTSTATUS sync_read_phys(_In_ PDEVICE_OBJECT DeviceObject, _In_ PFILE_OBJECT FileObject, _In_ uint64_t StartingOffset, _In_ ULONG Length, _Out_writes_bytes_(Length) PUCHAR Buffer, _In_ bool override);
void init_device(_In_ device_extension* Vcb, _Inout_ device* dev, _In_ bool get_nums);

_Function_class_(DRIVER_ADD_DEVICE)
NTSTATUS __stdcall AddDevice(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT PhysicalDeviceObject);

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
