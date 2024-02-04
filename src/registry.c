// Copyright (c) Anthony Kerr 2023-

#include "KMCSpaceFS_drv.h"

extern UNICODE_STRING registry_path;

#ifdef _DEBUG
extern HANDLE log_handle;
extern ERESOURCE log_lock;
extern PFILE_OBJECT comfo;
extern PDEVICE_OBJECT comdo;
#endif

WORK_QUEUE_ITEM wqi;

static const WCHAR option_mounted[] = L"Mounted";

NTSTATUS registry_mark_volume_mounted(KMCSpaceFS_UUID uuid)
{
	UNICODE_STRING path, mountedus;
	ULONG i, j;
	NTSTATUS Status;
	OBJECT_ATTRIBUTES oa;
	HANDLE h;
	DWORD data;

	path.Length = path.MaximumLength = registry_path.Length + (37 * sizeof(WCHAR));
	path.Buffer = ExAllocatePoolWithTag(PagedPool, path.Length, ALLOC_TAG);

	if (!path.Buffer)
	{
		ERR("out of memory\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlCopyMemory(path.Buffer, registry_path.Buffer, registry_path.Length);
	i = registry_path.Length / sizeof(WCHAR);

	path.Buffer[i] = '\\';
	i++;

	for (j = 0; j < 16; j++)
	{
		path.Buffer[i] = hex_digit((uuid.uuid[j] & 0xF0) >> 4);
		path.Buffer[i + 1] = hex_digit(uuid.uuid[j] & 0xF);

		i += 2;

		if (j == 3 || j == 5 || j == 7 || j == 9)
		{
			path.Buffer[i] = '-';
			i++;
		}
	}

	InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	Status = ZwCreateKey(&h, KEY_SET_VALUE, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
	if (!NT_SUCCESS(Status))
	{
		ERR("ZwCreateKey returned %08lx\n", Status);
		goto end;
	}

	mountedus.Buffer = (WCHAR*)option_mounted;
	mountedus.Length = mountedus.MaximumLength = sizeof(option_mounted) - sizeof(WCHAR);

	data = 1;

	Status = ZwSetValueKey(h, &mountedus, 0, REG_DWORD, &data, sizeof(DWORD));
	if (!NT_SUCCESS(Status))
	{
		ERR("ZwSetValueKey returned %08lx\n", Status);
		goto end2;
	}

	Status = STATUS_SUCCESS;

end2:
	ZwClose(h);

end:
	ExFreePool(path.Buffer);

	return Status;
}

static NTSTATUS registry_mark_volume_unmounted_path(PUNICODE_STRING path)
{
	HANDLE h;
	OBJECT_ATTRIBUTES oa;
	NTSTATUS Status;
	ULONG index, kvbilen = sizeof(KEY_VALUE_BASIC_INFORMATION) - sizeof(WCHAR) + (255 * sizeof(WCHAR)), retlen;
	KEY_VALUE_BASIC_INFORMATION* kvbi;
	bool has_options = false;
	UNICODE_STRING mountedus;

	// If a volume key has any options in it, we set Mounted to 0 and return. Otherwise,
	// we delete the whole thing.

	kvbi = ExAllocatePoolWithTag(PagedPool, kvbilen, ALLOC_TAG);
	if (!kvbi)
	{
		ERR("out of memory\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	InitializeObjectAttributes(&oa, path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	Status = ZwOpenKey(&h, KEY_QUERY_VALUE | KEY_SET_VALUE | DELETE, &oa);
	if (!NT_SUCCESS(Status))
	{
		ERR("ZwOpenKey returned %08lx\n", Status);
		goto end;
	}

	index = 0;

	mountedus.Buffer = (WCHAR*)option_mounted;
	mountedus.Length = mountedus.MaximumLength = sizeof(option_mounted) - sizeof(WCHAR);

	do
	{
		Status = ZwEnumerateValueKey(h, index, KeyValueBasicInformation, kvbi, kvbilen, &retlen);

		index++;

		if (NT_SUCCESS(Status))
		{
			UNICODE_STRING us;

			us.Length = us.MaximumLength = (USHORT)kvbi->NameLength;
			us.Buffer = kvbi->Name;

			if (!FsRtlAreNamesEqual(&mountedus, &us, true, NULL))
			{
				has_options = true;
				break;
			}
		}
		else if (Status != STATUS_NO_MORE_ENTRIES)
		{
			ERR("ZwEnumerateValueKey returned %08lx\n", Status);
			goto end2;
		}
	} while (NT_SUCCESS(Status));

	if (has_options)
	{
		DWORD data = 0;

		Status = ZwSetValueKey(h, &mountedus, 0, REG_DWORD, &data, sizeof(DWORD));
		if (!NT_SUCCESS(Status))
		{
			ERR("ZwSetValueKey returned %08lx\n", Status);
			goto end2;
		}
	}
	else
	{
		Status = ZwDeleteKey(h);
		if (!NT_SUCCESS(Status))
		{
			ERR("ZwDeleteKey returned %08lx\n", Status);
			goto end2;
		}
	}

	Status = STATUS_SUCCESS;

end2:
	ZwClose(h);

end:
	ExFreePool(kvbi);

	return Status;
}

NTSTATUS registry_mark_volume_unmounted(KMCSpaceFS_UUID uuid)
{
	UNICODE_STRING path;
	NTSTATUS Status;
	ULONG i, j;

	path.Length = path.MaximumLength = registry_path.Length + (37 * sizeof(WCHAR));
	path.Buffer = ExAllocatePoolWithTag(PagedPool, path.Length, ALLOC_TAG);

	if (!path.Buffer)
	{
		ERR("out of memory\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlCopyMemory(path.Buffer, registry_path.Buffer, registry_path.Length);
	i = registry_path.Length / sizeof(WCHAR);

	path.Buffer[i] = '\\';
	i++;

	for (j = 0; j < 16; j++)
	{
		path.Buffer[i] = hex_digit((uuid.uuid[j] & 0xF0) >> 4);
		path.Buffer[i + 1] = hex_digit(uuid.uuid[j] & 0xF);

		i += 2;

		if (j == 3 || j == 5 || j == 7 || j == 9)
		{
			path.Buffer[i] = '-';
			i++;
		}
	}

	Status = registry_mark_volume_unmounted_path(&path);
	if (!NT_SUCCESS(Status))
	{
		ERR("registry_mark_volume_unmounted_path returned %08lx\n", Status);
		goto end;
	}

	Status = STATUS_SUCCESS;

end:
	ExFreePool(path.Buffer);

	return Status;
}

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

typedef struct
{
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

void read_registry(PUNICODE_STRING regpath, bool refresh)
{
	OBJECT_ATTRIBUTES oa;
	NTSTATUS Status;
	HANDLE h;
	ULONG dispos;
#ifdef _DEBUG
	KEY_VALUE_FULL_INFORMATION* kvfi;
	ULONG kvfilen;
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
