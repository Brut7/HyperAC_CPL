#include "mmu.h"
#include "config.h"

PVOID MMU_Alloc(_In_ SIZE_T Size) {
	PMMU_POOL_HEADER header = NULL;
	PVOID data = NULL;

	header = (PMMU_POOL_HEADER)ExAllocatePool(PagedPool, sizeof(MMU_POOL_HEADER) + Size);
	if (!header) {
		return NULL;
	}

	header->Tag = MMU_POOL_TAGS[__rdtsc() % ARRAYSIZE(MMU_POOL_TAGS)];
	header->Size = Size;

	data = (PVOID)&header->Data;
	memset(data, 0, Size);

	InterlockedIncrement(&g_AllocCount);
	return data;
}

VOID MMU_Free(_In_ PVOID Addr) {
	PMMU_POOL_HEADER header = NULL;

	header = (PMMU_POOL_HEADER)((ULONG64)Addr - sizeof(MMU_POOL_HEADER));
	ExFreePoolWithTag(header, header->Tag);

	InterlockedIncrement(&g_FreeCount);
}