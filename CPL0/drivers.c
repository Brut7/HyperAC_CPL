#include "drivers.h"
#include "mmu.h"
#include "common.h"
#include "config.h"

NTSTATUS PopulateSystemModules(_Out_ PSYSTEM_MODULES pSystemModules)
{
    PAGED_CODE();

    if (pSystemModules == NULL)
    {
		return STATUS_INVALID_PARAMETER;
	}

    NTSTATUS status = STATUS_SUCCESS;
    ULONG req_size = 0;
    PRTL_MODULE_EXTENDED_INFO modules = NULL;

    status = RtlQueryModuleInformation(&req_size, sizeof(RTL_MODULE_EXTENDED_INFO), NULL);
    if (!NT_SUCCESS(status))
    {
        DebugMessage("RtlQueryModuleInformation failed: 0x%08X\n", status);
        return status;
    }

    modules = (PRTL_MODULE_EXTENDED_INFO)MMU_Alloc(req_size);

    status = RtlQueryModuleInformation(&req_size, sizeof(RTL_MODULE_EXTENDED_INFO), modules);
    if (!NT_SUCCESS(status))
    {
        DebugMessage("RtlQueryModuleInformation failed: 0x%08X\n", status);
        MMU_Free(modules);
        return status;
    }

    pSystemModules->Count = req_size / sizeof(RTL_MODULE_EXTENDED_INFO);
    pSystemModules->Modules = modules;
    return status;
}