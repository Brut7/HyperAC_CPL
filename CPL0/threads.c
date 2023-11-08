#include "threads.h"
#include "report.h"
#include "drivers.h"
#include "common.h"
#include "config.h"
#include "memory.h"


BOOLEAN IsThreadValid(_In_ PETHREAD Thread)
{
	PAGED_CODE();

	NTSTATUS status = STATUS_SUCCESS;
	CONTEXT context = { 0 };
	RTL_MODULE_EXTENDED_INFO system_module = { 0 };


	context.ContextFlags = CONTEXT_ALL;
	PsGetContextThread(Thread, &context, KernelMode);

	DebugMessage("found rip: %p", context.Rip);
	status = FindSystemModuleByAddress(context.Rip, &system_module);
	return NT_SUCCESS(status);
}

VOID DetectHiddenThreads(VOID)
{
	PAGED_CODE();

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
	}
}