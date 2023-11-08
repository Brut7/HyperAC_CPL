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
#include "pe.h"

VOID ScannerWorker(PVOID Context)
{
	PAGED_CODE();

	CR3 cr3 = { 0 };
	PEPROCESS process = NULL;
	PLIST_ENTRY head = NULL;
	ULONG active_threads = 0;
	SCAN_CONTEXT ctx = { 0 };

	InterlockedIncrement(&g_ThreadCount);

	MMU_Free(Context);

	head = (PLIST_ENTRY)((ULONG64)PsInitialSystemProcess + 0x448); // ActiveProcessLinks
	for (PLIST_ENTRY curr = head->Flink; curr != head; curr = curr->Flink)
	{
		process = (PEPROCESS)((ULONG64)curr - 0x448); // ActiveProcessLinks
		active_threads = *(volatile ULONG*)((ULONG64)process + 0x5f0); // ActiveThreads
		if (active_threads > 0)
		{
			KeAttachProcess(process);
			cr3.AsUInt = __readcr3();
			KeDetachProcess();

			ctx.Mode = UserMode;
			WalkPageTables(cr3, OnEachPage, &ctx);
		}
	}

	cr3.AsUInt = __readcr3();
	ctx.Mode = KernelMode;
	WalkPageTables(cr3, OnEachPage, &ctx);

	DebugMessage("finished scanning");
	InterlockedDecrement(&g_ThreadCount);
}

VOID MainThread(_In_opt_ PVOID Context)
{
	UNREFERENCED_PARAMETER(Context);
	PAGED_CODE();

	NTSTATUS status = STATUS_SUCCESS;
	PWORK_QUEUE_ITEM worker = NULL;

	InterlockedIncrement(&g_ThreadCount);

	PeformVmExitCheck();

	worker = (PWORK_QUEUE_ITEM)MMU_Alloc(sizeof(WORK_QUEUE_ITEM));
	ExInitializeWorkItem(worker, ScannerWorker, worker);
	ExQueueWorkItem(worker, BackgroundWorkQueue);

	while (InterlockedExchange(&g_UnloadThreads, g_UnloadThreads) == FALSE)
	{
		ValidateReportList();

		// DetectHiddenThreads();

		Sleep(100);
	}

ExitThread:
	InterlockedDecrement(&g_ThreadCount);
	PsTerminateSystemThread(STATUS_SUCCESS);
}