#include "main.h"
#include "config.h"
#include "common.h"
#include "hv.h"
#include "flow.h"

VOID MainThread(_In_opt_ PVOID Context)
{
	InterlockedIncrement(&g_ThreadCount);
	
	HV_PeformVmExitCheck();

	while (g_Unloading == FALSE)
	{
		DebugMessage("hello");
		Sleep(1000);
	}

	InterlockedDecrement(&g_ThreadCount);
	PsTerminateSystemThread(STATUS_SUCCESS);
}