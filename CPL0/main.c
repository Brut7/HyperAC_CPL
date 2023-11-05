#include "main.h"
#include "config.h"
#include "common.h"
#include "hv.h"

VOID MainThread(_In_opt_ PVOID Context) {
	InterlockedIncrement(&g_ThreadCount);

	while (g_Unloading == FALSE) {
		HV_PeformVmExitCheck();

		DebugMessage("hello");
		KeDelayExecutionThread(KernelMode, FALSE, &_1ms);
	}

	InterlockedDecrement(&g_ThreadCount);
	PsTerminateSystemThread(STATUS_SUCCESS);
}