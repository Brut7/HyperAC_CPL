#include "main.h"
#include "config.h"
#include "common.h"
#include "hv.h"
#include "flow.h"
#include "memory.h"
#include "sha256.h"
#include "mmu.h"
#include "pt.h"
#include "callbacks.h"
#include "drivers.h"
#include "threads.h"


VOID WorkItemRoutine(PVOID Context)
{
	CR3 cr3 = { .AsUInt = __readcr3() };

	SCAN_CONTEXT ctx = { 0 };
	ctx.HashCount = 0;
	ctx.Mode = KernelMode;

	WalkPageTables(cr3, OnEachPage, &ctx);
	DebugMessage("Context: %p\n", Context);

	MMU_Free(Context);
}

VOID MainThread(_In_opt_ PVOID Context)
{
	UNREFERENCED_PARAMETER(Context);
	PAGED_CODE();

	NTSTATUS status = STATUS_SUCCESS;
	PWORK_QUEUE_ITEM worker = NULL;



	InterlockedIncrement(&g_ThreadCount);

	PeformVmExitCheck();

	//worker = (PWORK_QUEUE_ITEM)MMU_Alloc(sizeof(WORK_QUEUE_ITEM));
	//DebugMessage("worker: %p\n", worker);

	//ExInitializeWorkItem(worker, WorkItemRoutine, worker);
	//ExQueueWorkItem(worker, BackgroundWorkQueue);
	//

	RTL_MODULE_EXTENDED_INFO ci;
	if (NT_SUCCESS(FindSystemModuleByName("CI.dll", &ci)))
	{
		DebugMessage("black men dont cheat %p (%s)", ci.ImageBase, ci.FullPathName);
	}

	while (InterlockedExchange(&g_UnloadThreads, g_UnloadThreads) == FALSE)
	{
		ValidateReportList();

		// Allocate the work item

		//DetectHiddenThreads();

		Sleep(1000);
	}

ExitThread:
	InterlockedDecrement(&g_ThreadCount);
	PsTerminateSystemThread(STATUS_SUCCESS);
}