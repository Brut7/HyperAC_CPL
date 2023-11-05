#ifndef H_SPINLOCK
#define H_SPINLOCK

#include <ntifs.h>
#include <intrin.h>

typedef struct _SPINLOCK
{
	volatile LONG Lock;
} SPINLOCK, *PSPINLOCK;

VOID SpinlockAcquire(_Inout_ PSPINLOCK Spinlock);
VOID SpinlockRelease(_Inout_ PSPINLOCK Spinlock);

#endif // H_SPINLOCK