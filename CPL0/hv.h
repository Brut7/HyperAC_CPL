#ifndef H_HV
#define H_HV

#include <ntifs.h>
#include <minwindef.h>

VOID HV_PeformVmExitCheck();
VOID HV_FaultVmExit();

#pragma alloc_text(PAGE, HV_PeformVmExitCheck)
#pragma alloc_text(PAGE, HV_FaultVmExit)

#endif // H_HV