// Copyright (c) Anthony Kerr 2023-

#pragma once

#undef _WIN32_WINNT
#undef NTDDI_VERSION

#define _WIN32_WINNT 0x0601
#define NTDDI_VERSION 0x06020000 // Win 8
#define _CRT_SECURE_NO_WARNINGS
#define _NO_CRT_STDIO_INLINE

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
