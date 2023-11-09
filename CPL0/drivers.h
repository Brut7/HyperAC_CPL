#ifndef H_DRIVERS
#define H_DRIVERS

#include <ntifs.h>
#include "common.h"

NTSTATUS PopulateSystemModules(_Out_ PSYSTEM_MODULES pSystemModules);
NTSTATUS FindSystemModuleByAddress(_In_ ULONG64 Address, _Out_ PRTL_MODULE_EXTENDED_INFO pSystemModule);
NTSTATUS FindSystemModuleByName(_In_ CONST CHAR* ModuleName, _Out_ PRTL_MODULE_EXTENDED_INFO pSystemModule);

#pragma alloc_text(PAGE, PopulateSystemModules)
#pragma alloc_text(PAGE, FindSystemModuleByAddress)
#pragma alloc_text(PAGE, FindSystemModuleByName)

#endif // H_DRIVERS