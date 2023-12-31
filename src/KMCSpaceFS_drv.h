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
#define VCB_TYPE_CONTROL 2
#define VCB_TYPE_BUS     5

typedef struct
{
    bool readonly;
    uint32_t flush_interval;
} mount_options;

typedef struct _device_extension
{
    uint32_t type;
    mount_options options;
    PDEVICE_OBJECT devobj;
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

// in registry.c
void read_registry(PUNICODE_STRING regpath, bool refresh);
NTSTATUS registry_load_volume_options(device_extension* Vcb);
void watch_registry(HANDLE regh);
