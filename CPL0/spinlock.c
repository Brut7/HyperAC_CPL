#include "spinlock.h"

VOID SpinlockAcquire(_Inout_ PSPINLOCK Spinlock)
{
	while (InterlockedCompareExchange(&Spinlock->Lock, 1, 0) != 0)
	{
		_mm_pause();
	}
}

VOID SpinlockRelease(_Inout_ PSPINLOCK Spinlock)
{
	InterlockedExchange(&Spinlock->Lock, 0);
}
