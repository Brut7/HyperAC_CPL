#ifndef H_DRIVERS
#define H_DRIVERS

#include <ntifs.h>
#include "common.h"

NTSTATUS PopulateSystemModules(_Out_ PSYSTEM_MODULES pSystemModules);
NTSTATUS FindSystemModuleByAddress(_In_ ULONG64 Address, PRTL_MODULE_EXTENDED_INFO _Out_ pSystemModule);
NTSTATUS FindSystemModuleByName(_In_ CONST CHAR* ModuleName, PRTL_MODULE_EXTENDED_INFO pSystemModule);

#endif // H_DRIVERS