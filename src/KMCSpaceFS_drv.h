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
    bool readonly;
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
    uint64_t devid;
    uint64_t generation;
    PDEVICE_OBJECT devobj;
    PFILE_OBJECT fileobj;
    UNICODE_STRING pnp_name;
    uint64_t size;
    bool seeding;
    bool had_drive_letter;
    void* notification_entry;
    ULONG disk_num;
    ULONG part_num;
    bool boot_volume;
    LIST_ENTRY list_entry;
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

    LIST_ENTRY list_entry;
} pdo_device_extension;

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
