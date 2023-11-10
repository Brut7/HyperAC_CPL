#ifndef H_PE
#define H_PE

#include <ntdef.h>	
#include <ntimage.h>

PIMAGE_NT_HEADERS GetNtHeaders(_In_ ULONG64 Base);
PIMAGE_EXPORT_DIRECTORY GetExportDirectory(_In_ ULONG64 Base, _In_ PIMAGE_NT_HEADERS Nt);
ULONG64 FindExport(_In_ ULONG64 Base, _In_ CONST CHAR* Name);

#endif // H_PE