#include "pe.h"
#include "memory.h"

NTSTATUS SafeGetNtHeader(_In_ ULONG64 Base, _Out_ PIMAGE_NT_HEADERS* pNTH)
{
	NTSTATUS status = STATUS_SUCCESS;
	IMAGE_DOS_HEADER dos = { 0 };
	IMAGE_NT_HEADERS nt = { 0 };

	status = SafeCopy(&dos, (CONST PVOID)Base, sizeof(dos));
	if (!NT_SUCCESS(status) || dos.e_magic != IMAGE_DOS_SIGNATURE)
	{
		return status;
	}

	status = SafeCopy(&nt, (CONST PVOID)(Base + dos.e_lfanew), sizeof(nt));
	if (!NT_SUCCESS(status) || nt.Signature != IMAGE_NT_SIGNATURE)
	{
		return status;
	}

	*pNTH = (IMAGE_NT_HEADERS*)(Base + dos.e_lfanew);
	return status;
}

ULONG64 FindExport(_In_ ULONG64 Base, _In_ CONST CHAR* Name)
{
	PAGED_CODE();

	PIMAGE_NT_HEADERS nt = NULL;
	ULONG export_va = 0;
	PIMAGE_EXPORT_DIRECTORY export_dir = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	ULONG* export_names_va = NULL;
	CHAR* export_name = NULL;
	USHORT* export_func_ord = NULL;
	ULONG* export_func_va = NULL;

	if (Base == 0)
	{
		return 0;
	}

	status = SafeGetNtHeader(Base, &nt);
	if (!NT_SUCCESS(status))
	{
		return 0;
	}

	export_va = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (export_va == 0)
	{
		return 0;
	}

	export_dir = (PIMAGE_EXPORT_DIRECTORY)(Base + export_va);
	export_func_ord = (PUSHORT)(Base + export_dir->AddressOfNameOrdinals);
	export_func_va = (PULONG)(Base + export_dir->AddressOfFunctions);
	export_names_va = (ULONG*)(Base + export_dir->AddressOfNames);

	for (ULONG i = 0; i < export_dir->NumberOfNames; ++i)
	{
		export_name = (CHAR*)(Base + export_names_va[i]);
		if (!strcmp(export_name, Name))
		{
			return Base + export_func_va[export_func_ord[i]];
		}
	}

	return 0;
}