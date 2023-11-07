#ifndef H_DRIVERS
#define H_DRIVERS

#include <ntifs.h>
#include "common.h"

NTSTATUS PopulateSystemModules(_Out_ PSYSTEM_MODULES pSystemModules);

#endif // H_DRIVERS