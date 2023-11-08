#ifndef H_PE
#define H_PE

#include <ntdef.h>	
#include <ntimage.h>

NTSTATUS SafeGetNtHeader(_In_ ULONG64 Base, _Out_ PIMAGE_NT_HEADERS* pNTH);
ULONG64 FindExport(_In_ ULONG64 Base, _In_ CONST CHAR* Name);

#endif // H_PE