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