#include "flow.h"

VOID Sleep(ULONG64 Milliseconds)
{
	LARGE_INTEGER interval = { 0 };
	interval.QuadPart = -10000 * Milliseconds;
	KeDelayExecutionThread(KernelMode, FALSE, &interval);
}