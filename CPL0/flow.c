#include "flow.h"

VOID Sleep(_In_ LONG64 Milliseconds)
{
	LARGE_INTEGER interval = { 0 };
	interval.QuadPart = -10000 * Milliseconds;
	KeDelayExecutionThread(KernelMode, FALSE, &interval);
}