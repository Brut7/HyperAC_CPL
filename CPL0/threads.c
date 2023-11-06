#include "threads.h"
#include "config.h"
#include "common.h"
#include "hv.h"
#include "flow.h"
#include "memory.h"
#include "sha256.h"
#include "mmu.h"
#include "pt.h"
#include "callbacks.h"


VOID ScannerThread(_In_opt_ PVOID Context)
{
	UNREFERENCED_PARAMETER(Context);
	PAGED_CODE();

	CR3 cr3 = { 0 };
	NTSTATUS status = STATUS_SUCCESS;

	InterlockedIncrement(&g_ThreadCount);

	while (InterlockedExchange(&g_UnloadThreads, g_UnloadThreads) == FALSE)
	{
		ValidateReportList();

		Sleep(100);
	}

ExitThread:
	InterlockedDecrement(&g_ThreadCount);
	PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID MainThread(_In_opt_ PVOID Context)
{
	InterlockedIncrement(&g_ThreadCount);

	PeformVmExitCheck();

	while (InterlockedExchange(&g_UnloadThreads, g_UnloadThreads) == FALSE)
	{
		ValidateReportList();

		Sleep(100);
	}

ExitThread:
	InterlockedDecrement(&g_ThreadCount);
	PsTerminateSystemThread(STATUS_SUCCESS);
}