#include "main.h"
#include "config.h"
#include "common.h"
#include "hv.h"
#include "flow.h"
#include "memory.h"
#include "mmu.h"
#include "pt.h"
#include "callbacks.h"
#include "drivers.h"
#include "threads.h"
#include "pe.h"
#include "hash.h"

VOID ScannerWorker(PVOID Context)
{
	PAGED_CODE();

	CR3 cr3 = { 0 };
	SCAN_CONTEXT ctx = { 0 };

	InterlockedIncrement(&g_ThreadCount);
	InterlockedIncrement(&g_PT_Walking);

	MMU_Free(Context);

	if (g_GameProcess != NULL)
	{
		KeAttachProcess(g_GameProcess);
		cr3.AsUInt = __readcr3();
		KeDetachProcess();

		ctx.Mode = UserMode;
		WalkPageTables(cr3, OnEachPage, &ctx);
	}

	cr3.AsUInt = __readcr3();
	ctx.Mode = KernelMode;
	WalkPageTables(cr3, OnEachPage, &ctx);

	DebugMessage("finished scanning");
	InterlockedDecrement(&g_PT_Walking);
	InterlockedDecrement(&g_ThreadCount);
}

VOID MainThread(_In_opt_ PVOID Context)
{
	UNREFERENCED_PARAMETER(Context);
	PAGED_CODE();

	NTSTATUS status = STATUS_SUCCESS;
	PWORK_QUEUE_ITEM worker = NULL;

	InterlockedIncrement(&g_ThreadCount);

	(VOID)MD5_Init();
	(VOID)SHA1_Init();
	(VOID)SHA256_Init();

	PeformVmExitCheck();

	RTL_MODULE_EXTENDED_INFO ci;
	if (NT_SUCCESS(FindSystemModuleByName("CI.dll", &ci)))
	{
		g_CiCheckSignedFile = FindExport(ci.ImageBase, "CiCheckSignedFile");
	}

	while (InterlockedExchange(&g_UnloadThreads, g_UnloadThreads) == FALSE)
	{
		ValidateReportList();

		if (InterlockedExchange(&g_PT_Walking, g_PT_Walking) == 0)
		{
			DebugMessage("added work");
			worker = (PWORK_QUEUE_ITEM)MMU_Alloc(sizeof(WORK_QUEUE_ITEM));
			ExInitializeWorkItem(worker, ScannerWorker, worker);
			ExQueueWorkItem(worker, BackgroundWorkQueue);
		}
		else
		{
			DebugMessage("already working!");
		}

		//// DetectHiddenThreads();

		Sleep(1500);
	}

ExitThread:
	InterlockedDecrement(&g_ThreadCount);
	PsTerminateSystemThread(STATUS_SUCCESS);
}