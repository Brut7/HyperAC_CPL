#ifndef H_HV
#define H_HV

#include <ntifs.h>
#include <minwindef.h>

VOID PeformVmExitCheck(VOID);
VOID FaultVmExit(VOID);

#pragma alloc_text(PAGE, PeformVmExitCheck)
#pragma alloc_text(PAGE, FaultVmExit)

#endif // H_HV