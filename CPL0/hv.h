#ifndef H_HV
#define H_HV

#include <ntifs.h>
#include <minwindef.h>

VOID HV_PeformVmExitCheck();

#pragma alloc_text(PAGE, HV_PeformVmExitCheck)

#endif // H_HV