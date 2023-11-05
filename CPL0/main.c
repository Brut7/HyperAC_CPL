#include "main.h"
#include "config.h"
#include "common.h"
#include "hv.h"
#include "flow.h"

VOID MainThread(_In_opt_ PVOID Context)
{
	InterlockedIncrement(&g_ThreadCount);

	//HV_FaultVmExit();
	//DebugMessage("HV_FaultVmExit");

	while (g_Unloading == FALSE)
	{
		HV_PeformVmExitCheck();

		Sleep(500);
	}

	InterlockedDecrement(&g_ThreadCount);
	PsTerminateSystemThread(STATUS_SUCCESS);
}