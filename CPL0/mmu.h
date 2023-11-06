#ifndef H_MMU
#define H_MMU

#include <ntifs.h>
#include <ntddk.h>

typedef struct _MMU_POOL_HEADER {
	ULONG Tag;
	SIZE_T Size;
	UCHAR Data[];
}MMU_POOL_HEADER, *PMMU_POOL_HEADER;

static const ULONG MMU_POOL_TAGS[8] = {
	'CPL0',	'CPL1',	'CPL2',	'CPL3',	'CPL4',	'CPL5',	'CPL6',	'CPL7'
};

PVOID MMU_Alloc(_In_ SIZE_T Size);
VOID MMU_Free(_In_ PVOID Address);

#endif // H_MMU