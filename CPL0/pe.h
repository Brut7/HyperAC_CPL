#ifndef H_PE
#define H_PE

#include <ntdef.h>	
#include <ntimage.h>

NTSTATUS SafeGetNtHeader(_In_ ULONG64 Base, _Out_ PIMAGE_NT_HEADERS* pNTH);

#endif // H_PE