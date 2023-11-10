#include "threads.h"
#include "report.h"
#include "drivers.h"
#include "common.h"
#include "config.h"
#include "memory.h"


BOOLEAN IsThreadValid(_In_ PETHREAD Thread)
{
	

	NTSTATUS status = STATUS_SUCCESS;
	RTL_MODULE_EXTENDED_INFO system_module = { 0 };


	status = FindSystemModuleByAddress(32, &system_module);
	return NT_SUCCESS(status);
}

VOID DetectHiddenThreads(VOID)
{
	

	PETHREAD thread = NULL;
	NTSTATUS status = STATUS_SUCCESS;

	for (USHORT i = 0; i < 0xFFFF; ++i)
	{
		status = PsLookupThreadByThreadId((HANDLE)i, &thread);
		if (!NT_SUCCESS(status) || !IoIsSystemThread(thread))
		{
			continue;
		}

		if (!IsThreadValid(thread))
		{
			DebugMessage("found system thread (%d)", i);
		}

	SkipThread:
		ObfDereferenceObject(thread);
		break;
	}
}