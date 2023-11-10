#include "mmu.h"
#include "config.h"

PVOID MMU_Alloc(_In_ SIZE_T Size)
{
	PVOID pool = NULL;

	if (Size == 0)
	{
		return NULL;
	}

	pool = ExAllocatePool(NonPagedPool, Size);
	if (!pool)
	{
		__fastfail(FAST_FAIL_POOL_ERROR);
	}

	memset(pool, 0, Size);

	InterlockedIncrement64(&g_AllocCount);
	return pool;
}

VOID MMU_Free(_In_ PVOID Pool)
{
	PAGED_CODE();

	if (Pool == 0)
	{
		return;
	}

	ExFreePoolWithTag(Pool, 0);
	InterlockedIncrement64(&g_FreeCount);
}