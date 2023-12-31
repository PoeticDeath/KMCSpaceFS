// Copyright (c) Anthony Kerr 2023-

#include "KMCSpaceFS_drv.h"

extern UNICODE_STRING log_device, log_file, registry_path;

#ifdef _DEBUG
extern HANDLE log_handle;
extern ERESOURCE log_lock;
extern PFILE_OBJECT comfo;
extern PDEVICE_OBJECT comdo;
#endif

WORK_QUEUE_ITEM wqi;

#define is_hex(c) ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))

static bool is_uuid(ULONG namelen, WCHAR* name)
{
    ULONG i;

    if (namelen != 36 * sizeof(WCHAR))
    {
        return false;
    }

    for (i = 0; i < 36; i++)
    {
        if (i == 8 || i == 13 || i == 18 || i == 23)
        {
            if (name[i] != '-')
            {
                return false;
            }
        }
        else if (!is_hex(name[i]))
        {
            return false;
        }
    }

    return true;
}

typedef struct {
    UNICODE_STRING name;
    LIST_ENTRY list_entry;
} key_name;

static void reset_subkeys(HANDLE h, PUNICODE_STRING reg_path)
{
    NTSTATUS Status;
    KEY_BASIC_INFORMATION* kbi;
    ULONG kbilen = sizeof(KEY_BASIC_INFORMATION) - sizeof(WCHAR) + (255 * sizeof(WCHAR)), retlen, index = 0;
    LIST_ENTRY key_names, * le;

    InitializeListHead(&key_names);

    kbi = ExAllocatePoolWithTag(PagedPool, kbilen, ALLOC_TAG);
    if (!kbi)
    {
        ERR("out of memory\n");
        return;
    }

    do
    {
        Status = ZwEnumerateKey(h, index, KeyBasicInformation, kbi, kbilen, &retlen);
        index++;
        if (NT_SUCCESS(Status))
        {
            key_name* kn;

            TRACE("key: %.*S\n", (int)(kbi->NameLength / sizeof(WCHAR)), kbi->Name);

            if (is_uuid(kbi->NameLength, kbi->Name))
            {
                kn = ExAllocatePoolWithTag(PagedPool, sizeof(key_name), ALLOC_TAG);
                if (!kn)
                {
                    ERR("out of memory\n");
                    goto end;
                }

                kn->name.Length = kn->name.MaximumLength = (USHORT)min(0xffff, kbi->NameLength);
                kn->name.Buffer = ExAllocatePoolWithTag(PagedPool, kn->name.MaximumLength, ALLOC_TAG);
                if (!kn->name.Buffer)
                {
                    ERR("out of memory\n");
                    ExFreePool(kn);
                    goto end;
                }

                RtlCopyMemory(kn->name.Buffer, kbi->Name, kn->name.Length);

                InsertTailList(&key_names, &kn->list_entry);
            }
        }
        else if (Status != STATUS_NO_MORE_ENTRIES)
        {
            ERR("ZwEnumerateKey returned %08lx\n", Status);
        }
    } while (NT_SUCCESS(Status));

    le = key_names.Flink;
    while (le != &key_names)
    {
        key_name* kn = CONTAINING_RECORD(le, key_name, list_entry);
        UNICODE_STRING path;

        path.Length = path.MaximumLength = reg_path->Length + sizeof(WCHAR) + kn->name.Length;
        path.Buffer = ExAllocatePoolWithTag(PagedPool, path.Length, ALLOC_TAG);

        if (!path.Buffer)
        {
            ERR("out of memory\n");
            goto end;
        }

        RtlCopyMemory(path.Buffer, reg_path->Buffer, reg_path->Length);
        path.Buffer[reg_path->Length / sizeof(WCHAR)] = '\\';
        RtlCopyMemory(&path.Buffer[(reg_path->Length / sizeof(WCHAR)) + 1], kn->name.Buffer, kn->name.Length);

        ExFreePool(path.Buffer);

        le = le->Flink;
    }

end:
    while (!IsListEmpty(&key_names))
    {
        key_name* kn;

        le = RemoveHeadList(&key_names);
        kn = CONTAINING_RECORD(le, key_name, list_entry);

        if (kn->name.Buffer)
        {
            ExFreePool(kn->name.Buffer);
        }

        ExFreePool(kn);
    }

    ExFreePool(kbi);
}

static void get_registry_value(HANDLE h, WCHAR* string, ULONG type, void* val, ULONG size)
{
    ULONG kvfilen;
    KEY_VALUE_FULL_INFORMATION* kvfi;
    UNICODE_STRING us;
    NTSTATUS Status;

    RtlInitUnicodeString(&us, string);

    kvfi = NULL;
    kvfilen = 0;
    Status = ZwQueryValueKey(h, &us, KeyValueFullInformation, kvfi, kvfilen, &kvfilen);

    if ((Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) && kvfilen > 0)
    {
        kvfi = ExAllocatePoolWithTag(PagedPool, kvfilen, ALLOC_TAG);
        if (!kvfi)
        {
            ERR("out of memory\n");
            ZwClose(h);
            return;
        }

        Status = ZwQueryValueKey(h, &us, KeyValueFullInformation, kvfi, kvfilen, &kvfilen);
        if (NT_SUCCESS(Status))
        {
            if (kvfi->Type == type && kvfi->DataLength >= size)
            {
                RtlCopyMemory(val, ((uint8_t*)kvfi) + kvfi->DataOffset, size);
            }
            else
            {
                Status = ZwDeleteValueKey(h, &us);
                if (!NT_SUCCESS(Status))
                {
                    ERR("ZwDeleteValueKey returned %08lx\n", Status);
                }

                Status = ZwSetValueKey(h, &us, 0, type, val, size);
                if (!NT_SUCCESS(Status))
                {
                    ERR("ZwSetValueKey returned %08lx\n", Status);
                }
            }
        }

        ExFreePool(kvfi);
    }
    else if (Status == STATUS_OBJECT_NAME_NOT_FOUND)
    {
        Status = ZwSetValueKey(h, &us, 0, type, val, size);
        if (!NT_SUCCESS(Status))
        {
            ERR("ZwSetValueKey returned %08lx\n", Status);
        }
    }
    else
    {
        ERR("ZwQueryValueKey returned %08lx\n", Status);
    }
}

void read_registry(PUNICODE_STRING regpath, bool refresh) {
    OBJECT_ATTRIBUTES oa;
    NTSTATUS Status;
    HANDLE h;
    ULONG dispos;
#ifdef _DEBUG
    KEY_VALUE_FULL_INFORMATION* kvfi;
    ULONG kvfilen, old_debug_log_level = debug_log_level;
    UNICODE_STRING us, old_log_file, old_log_device;

    static const WCHAR def_log_file[] = L"\\??\\C:\\KMCSpaceFS.log";
#endif

    InitializeObjectAttributes(&oa, regpath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    Status = ZwCreateKey(&h, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, &dispos);
    if (!NT_SUCCESS(Status))
    {
        ERR("ZwCreateKey returned %08lx\n", Status);
        return;
    }

    if (!refresh)
    {
        reset_subkeys(h, regpath);
    }

    get_registry_value(h, L"Readonly", REG_DWORD, &mount_readonly, sizeof(mount_readonly));

    if (!refresh)
    {
        get_registry_value(h, L"NoPNP", REG_DWORD, &no_pnp, sizeof(no_pnp));
    }

    if (mount_flush_interval == 0)
    {
        mount_flush_interval = 1;
    }

#ifdef _DEBUG
    get_registry_value(h, L"DebugLogLevel", REG_DWORD, &debug_log_level, sizeof(debug_log_level));

    RtlInitUnicodeString(&us, L"LogDevice");

    kvfi = NULL;
    kvfilen = 0;
    Status = ZwQueryValueKey(h, &us, KeyValueFullInformation, kvfi, kvfilen, &kvfilen);

    old_log_device = log_device;

    log_device.Length = log_device.MaximumLength = 0;
    log_device.Buffer = NULL;

    if ((Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) && kvfilen > 0)
    {
        kvfi = ExAllocatePoolWithTag(PagedPool, kvfilen, ALLOC_TAG);
        if (!kvfi)
        {
            ERR("out of memory\n");
            ZwClose(h);
            return;
        }

        Status = ZwQueryValueKey(h, &us, KeyValueFullInformation, kvfi, kvfilen, &kvfilen);
        if (NT_SUCCESS(Status))
        {
            if ((kvfi->Type == REG_SZ || kvfi->Type == REG_EXPAND_SZ) && kvfi->DataLength >= sizeof(WCHAR))
            {
                log_device.Length = log_device.MaximumLength = (USHORT)min(0xffff, kvfi->DataLength);
                log_device.Buffer = ExAllocatePoolWithTag(PagedPool, log_device.MaximumLength, ALLOC_TAG);
                if (!log_device.Buffer)
                {
                    ERR("out of memory\n");
                    ExFreePool(kvfi);
                    ZwClose(h);
                    return;
                }

                RtlCopyMemory(log_device.Buffer, ((uint8_t*)kvfi) + kvfi->DataOffset, log_device.Length);
                if (log_device.Buffer[(log_device.Length / sizeof(WCHAR)) - 1] == 0)
                {
                    log_device.Length -= sizeof(WCHAR);
                }
            }
            else
            {
                ERR("LogDevice was type %lu, length %lu\n", kvfi->Type, kvfi->DataLength);

                Status = ZwDeleteValueKey(h, &us);
                if (!NT_SUCCESS(Status))
                {
                    ERR("ZwDeleteValueKey returned %08lx\n", Status);
                }
            }
        }

        ExFreePool(kvfi);
    }
    else if (Status != STATUS_OBJECT_NAME_NOT_FOUND)
    {
        ERR("ZwQueryValueKey returned %08lx\n", Status);
    }

    ExAcquireResourceExclusiveLite(&log_lock, true);

    if (refresh && (log_device.Length != old_log_device.Length || RtlCompareMemory(log_device.Buffer, old_log_device.Buffer, log_device.Length) != log_device.Length || (!comfo && log_device.Length > 0) || (old_debug_log_level == 0 && debug_log_level > 0) || (old_debug_log_level > 0 && debug_log_level == 0)))
    {
        if (comfo)
        {
            ObDereferenceObject(comfo);
        }

        if (log_handle)
        {
            ZwClose(log_handle);
            log_handle = NULL;
        }

        comfo = NULL;
        comdo = NULL;

        if (log_device.Length > 0 && debug_log_level > 0)
        {
            Status = IoGetDeviceObjectPointer(&log_device, FILE_WRITE_DATA, &comfo, &comdo);
            if (!NT_SUCCESS(Status))
            {
                DbgPrint("IoGetDeviceObjectPointer returned %08lx\n", Status);
            }
        }
    }

    ExReleaseResourceLite(&log_lock);

    if (old_log_device.Buffer)
    {
        ExFreePool(old_log_device.Buffer);
    }

    RtlInitUnicodeString(&us, L"LogFile");

    kvfi = NULL;
    kvfilen = 0;
    Status = ZwQueryValueKey(h, &us, KeyValueFullInformation, kvfi, kvfilen, &kvfilen);

    old_log_file = log_file;

    if ((Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) && kvfilen > 0)
    {
        kvfi = ExAllocatePoolWithTag(PagedPool, kvfilen, ALLOC_TAG);
        if (!kvfi)
        {
            ERR("out of memory\n");
            ZwClose(h);
            return;
        }

        Status = ZwQueryValueKey(h, &us, KeyValueFullInformation, kvfi, kvfilen, &kvfilen);
        if (NT_SUCCESS(Status))
        {
            if ((kvfi->Type == REG_SZ || kvfi->Type == REG_EXPAND_SZ) && kvfi->DataLength >= sizeof(WCHAR))
            {
                log_file.Length = log_file.MaximumLength = (USHORT)min(0xffff, kvfi->DataLength);
                log_file.Buffer = ExAllocatePoolWithTag(PagedPool, log_file.MaximumLength, ALLOC_TAG);
                if (!log_file.Buffer)
                {
                    ERR("out of memory\n");
                    ExFreePool(kvfi);
                    ZwClose(h);
                    return;
                }

                RtlCopyMemory(log_file.Buffer, ((uint8_t*)kvfi) + kvfi->DataOffset, log_file.Length);

                if (log_file.Buffer[(log_file.Length / sizeof(WCHAR)) - 1] == 0)
                {
                    log_file.Length -= sizeof(WCHAR);
                }
            }
            else
            {
                ERR("LogFile was type %lu, length %lu\n", kvfi->Type, kvfi->DataLength);

                Status = ZwDeleteValueKey(h, &us);
                if (!NT_SUCCESS(Status))
                {
                    ERR("ZwDeleteValueKey returned %08lx\n", Status);
                }

                log_file.Length = 0;
            }
        }
        else
        {
            ERR("ZwQueryValueKey returned %08lx\n", Status);
            log_file.Length = 0;
        }

        ExFreePool(kvfi);
    }
    else if (Status == STATUS_OBJECT_NAME_NOT_FOUND)
    {
        Status = ZwSetValueKey(h, &us, 0, REG_SZ, (void*)def_log_file, sizeof(def_log_file));
        if (!NT_SUCCESS(Status))
        {
            ERR("ZwSetValueKey returned %08lx\n", Status);
        }

        log_file.Length = 0;
    }
    else
    {
        ERR("ZwQueryValueKey returned %08lx\n", Status);
        log_file.Length = 0;
    }

    if (log_file.Length == 0)
    {
        log_file.Length = log_file.MaximumLength = sizeof(def_log_file) - sizeof(WCHAR);
        log_file.Buffer = ExAllocatePoolWithTag(PagedPool, log_file.MaximumLength, ALLOC_TAG);
        if (!log_file.Buffer)
        {
            ERR("out of memory\n");
            ZwClose(h);
            return;
        }

        RtlCopyMemory(log_file.Buffer, def_log_file, log_file.Length);
    }

    ExAcquireResourceExclusiveLite(&log_lock, true);

    if (refresh && (log_file.Length != old_log_file.Length || RtlCompareMemory(log_file.Buffer, old_log_file.Buffer, log_file.Length) != log_file.Length || (!log_handle && log_file.Length > 0) || (old_debug_log_level == 0 && debug_log_level > 0) || (old_debug_log_level > 0 && debug_log_level == 0)))
    {
        if (log_handle)
        {
            ZwClose(log_handle);
            log_handle = NULL;
        }

        if (!comfo && log_file.Length > 0 && refresh && debug_log_level > 0)
        {
            IO_STATUS_BLOCK iosb;

            InitializeObjectAttributes(&oa, &log_file, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

            Status = ZwCreateFile(&log_handle, FILE_WRITE_DATA, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE | FILE_WRITE_THROUGH | FILE_SYNCHRONOUS_IO_ALERT, NULL, 0);
            if (!NT_SUCCESS(Status))
            {
                DbgPrint("ZwCreateFile returned %08lx\n", Status);
                log_handle = NULL;
            }
        }
    }

    ExReleaseResourceLite(&log_lock);

    if (old_log_file.Buffer)
    {
        ExFreePool(old_log_file.Buffer);
    }
#endif

    ZwClose(h);
}

_Function_class_(WORKER_THREAD_ROUTINE)
static void __stdcall registry_work_item(PVOID Parameter)
{
	NTSTATUS Status;
	IO_STATUS_BLOCK iosb;
	HANDLE regh = (HANDLE)Parameter;

	TRACE("registry changed\n");

	read_registry(&registry_path, true);

	Status = ZwNotifyChangeKey(regh, NULL, (PVOID)&wqi, (PVOID)DelayedWorkQueue, &iosb, REG_NOTIFY_CHANGE_LAST_SET, true, NULL, 0, true);
	if (!NT_SUCCESS(Status))
	{
		ERR("ZwNotifyChangeKey failed: %081X\n", Status);
	}
}

void watch_registry(HANDLE regh)
{
	NTSTATUS Status;
	IO_STATUS_BLOCK iosb;

	ExInitializeWorkItem(&wqi, registry_work_item, regh);

	Status = ZwNotifyChangeKey(regh, NULL, (PVOID)&wqi, (PVOID)DelayedWorkQueue, &iosb, REG_NOTIFY_CHANGE_LAST_SET, true, NULL, 0, true);
	if (!NT_SUCCESS(Status))
	{
		ERR("ZwNotifyChangeKey failed: %081X\n", Status);
	}
}