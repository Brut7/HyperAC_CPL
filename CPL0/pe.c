#include "pe.h"
#include "memory.h"
#include "mmu.h"

PIMAGE_NT_HEADERS GetNtHeaders(_In_ ULONG64 Base)
{
	NTSTATUS status = STATUS_SUCCESS;
	PIMAGE_NT_HEADERS nt = NULL;
	IMAGE_DOS_HEADER dos = { 0 };


	status = SafeVirtualCopy(&dos, (CONST PVOID)Base, sizeof(IMAGE_DOS_HEADER));
	if (!NT_SUCCESS(status) || dos.e_magic != IMAGE_DOS_SIGNATURE)
	{
		return NULL;
	}

	nt = MMU_Alloc(sizeof(IMAGE_NT_HEADERS));
	status = SafeVirtualCopy(nt, (CONST PVOID)(Base + dos.e_lfanew), sizeof(IMAGE_NT_HEADERS));
	if (!NT_SUCCESS(status) || nt->Signature != IMAGE_NT_SIGNATURE)
	{
		MMU_Free(nt);
		return NULL;
	}

	return nt;
}

PIMAGE_EXPORT_DIRECTORY GetExportDirectory(_In_ ULONG64 Base, _In_ PIMAGE_NT_HEADERS Nt)
{
	

	LONG export_va = 0;
	PIMAGE_EXPORT_DIRECTORY export_dir = NULL;
	NTSTATUS status = STATUS_SUCCESS;

	export_va = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (export_va == 0)
	{
		return NULL;
	}

	export_dir = (PIMAGE_EXPORT_DIRECTORY)MMU_Alloc(sizeof(IMAGE_EXPORT_DIRECTORY));
	status = SafeVirtualCopy(export_dir, (CONST PVOID)(Base + export_va), sizeof(IMAGE_EXPORT_DIRECTORY));
	if (!NT_SUCCESS(status))
	{
		MMU_Free(export_dir);
		return NULL;
	}

	return export_dir;
}

ULONG64 FindExport(_In_ ULONG64 Base, _In_ CONST CHAR* Name)
{
	

	PIMAGE_EXPORT_DIRECTORY export_dir = NULL;
	PIMAGE_NT_HEADERS nt = NULL;
	USHORT* export_func_ord = NULL;
	ULONG* export_func_va = NULL;
	SIZE_T name_length = 0;
	CHAR* export_name = NULL;
	ULONG export_name_va = 0;
	NTSTATUS status = STATUS_SUCCESS;

	if (Base == 0)
	{
		return 0;
	}

	nt = GetNtHeaders(Base);
	if (nt == NULL)
	{
		return NULL;
	}

	export_dir = GetExportDirectory(Base, nt);
	MMU_Free(nt);

	if (export_dir == NULL)
	{
		return 0;
	}

	export_func_ord = MMU_Alloc(export_dir->NumberOfFunctions * sizeof(USHORT));
	export_func_va = MMU_Alloc(export_dir->NumberOfFunctions * sizeof(ULONG));

	status = SafeVirtualCopy(export_func_ord, (CONST PVOID)(Base + export_dir->AddressOfNameOrdinals), export_dir->NumberOfFunctions * sizeof(USHORT));
	if (!NT_SUCCESS(status))
	{
		MMU_Free(export_func_ord);
		MMU_Free(export_func_va);
		return 0;
	}

	status = SafeVirtualCopy(export_func_va, (CONST PVOID)(Base + export_dir->AddressOfFunctions), export_dir->NumberOfFunctions * sizeof(ULONG));
	if (!NT_SUCCESS(status))
	{
		MMU_Free(export_func_ord);
		MMU_Free(export_func_va);
		return 0;
	}

	name_length = strlen(Name);
	export_name = MMU_Alloc(name_length + 1);

	for (ULONG i = 0; i < export_dir->NumberOfNames; ++i)
	{
		status = SafeVirtualCopy(&export_name_va, (CONST PVOID)(Base + export_dir->AddressOfNames + i * sizeof(ULONG)), sizeof(ULONG));
		if (!NT_SUCCESS(status))
		{
			continue;
		}

		status = SafeVirtualCopy(export_name, (CONST PVOID)(Base + export_name_va), name_length);
		if (!NT_SUCCESS(status) || strncmp(export_name, Name, name_length) != 0)
		{
			continue;
		}

		MMU_Free(export_dir);
		MMU_Free(export_name);
		MMU_Free(export_func_ord);
		MMU_Free(export_func_va);
		return Base + export_func_va[export_func_ord[i]];
	}

	MMU_Free(export_dir);
	MMU_Free(export_name);
	MMU_Free(export_func_ord);
	MMU_Free(export_func_va);
	return 0;
}