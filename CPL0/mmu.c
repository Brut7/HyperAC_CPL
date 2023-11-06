#include "mmu.h"
#include "config.h"

PVOID MMU_Alloc(_In_ SIZE_T Size) {
	PAGED_CODE();

	PMMU_POOL_HEADER header = NULL;
	PVOID data = NULL;

	if (Size == 0)
	{
		return NULL;
	}

	header = (PMMU_POOL_HEADER)ExAllocatePool(PagedPool, MMU_HEADER_SIZE + Size);
	if (!header) {
		__fastfail(FAST_FAIL_POOL_ERROR);
	}

	header->Tag = MMU_POOL_TAGS[__rdtsc() % ARRAYSIZE(MMU_POOL_TAGS)];
	header->Size = Size;

	data = (PVOID)&header->Data;
	memset(data, 0, Size);

	InterlockedIncrement64(&g_AllocCount);
	return data;
}

VOID MMU_Free(_In_ PVOID Address) {
	PAGED_CODE();

	PMMU_POOL_HEADER header = NULL;

	if (Address == 0)
	{
		return;
	}

	header = (PMMU_POOL_HEADER)((ULONG64)Address - MMU_HEADER_SIZE);
	memset(&header->Data, 0, header->Size);
	ExFreePoolWithTag(header, header->Tag);

	InterlockedIncrement64(&g_FreeCount);
}