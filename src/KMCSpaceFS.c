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

static const WCHAR device_name[] = { '\\','K','M','C','S','p','a','c','e','F','S',0};
static const WCHAR dosdevice_name[] = { '\\','D','o','s','D','e','v','i','c','e','s','\\','K','M','C','S','p','a','c','e','F','S',0};

_Function_class_(DRIVER_INITIALIZE)
NTSTATUS __stdcall DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS Status;

	/*
	DriverObject->DriverUnload = DriverUnload;

	DriverObject->MajorFunction[IRP_MJ_CREATE]                   = Create;
	DriverObject->MajorFunction[IRP_MJ_CLOSE]                    = Close;
	DriverObject->MajorFunction[IRP_MJ_READ]                     = Read;
	DriverObject->MajorFunction[IRP_MJ_WRITE]                    = Write;
	DriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION]        = QueryInformation;
	DriverObject->MajorFunction[IRP_MJ_SET_INFORMATION]          = SetInformation;
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
	DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL]           = SystemControl;
	DriverObject->MajorFunction[IRP_MJ_PNP]                      = Pnp;
	DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS]            = FlushBuffers;
	*/

	Status = IoCreateDevice(DriverObject, 0, &device_name, FILE_DEVICE_DISK_FILE_SYSTEM, 0, FALSE, &DriverObject->DeviceObject);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	Status = IoCreateSymbolicLink(&dosdevice_name, &device_name);
	if (!NT_SUCCESS(Status))
	{
		IoDeleteDevice(DriverObject->DeviceObject);
		return Status;
	}

	return Status;
}
