#include "drivers.h"
#include "mmu.h"
#include "common.h"
#include "config.h"
#include "pe.h"

NTSTATUS PopulateSystemModules(_Out_ PSYSTEM_MODULES pSystemModules)
{
    PAGED_CODE();

    NTSTATUS status = STATUS_SUCCESS;
    ULONG req_size = 0;
    PRTL_MODULE_EXTENDED_INFO modules = NULL;

    if (pSystemModules == NULL)
    {
		return STATUS_INVALID_PARAMETER;
	}

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

NTSTATUS FindSystemModuleByAddress(_In_ ULONG64 Address, PRTL_MODULE_EXTENDED_INFO _Out_ pSystemModule)
{
    PAGED_CODE();

    NTSTATUS status = STATUS_SUCCESS;
    RTL_MODULE_EXTENDED_INFO system_module = { 0 };
    PIMAGE_NT_HEADERS nt = NULL;
    PIMAGE_SECTION_HEADER section = NULL;
    ULONG64 sec_start = 0;
    ULONG64 sec_end = 0;
    SYSTEM_MODULES system_modules = { 0 };

    if (Address == 0)
    {
        return;
    }

    status = PopulateSystemModules(&system_modules);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    for (ULONG i = 0; i < system_modules.Count; ++i)
    {
        system_module = system_modules.Modules[i];

        status = SafeGetNtHeader(system_module.ImageBase, &nt);
        if (!NT_SUCCESS(status))
        {
            continue;
        }

        section = IMAGE_FIRST_SECTION(nt);
        for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
        {
            if ((section->Characteristics & IMAGE_SCN_CNT_CODE) != NULL 
                && (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != NULL)
            {
                sec_start = (ULONG64)system_module.ImageBase + section->VirtualAddress;
                sec_end = sec_start + section->Misc.VirtualSize;

                if (Address >= sec_start && Address < sec_end)
                {
                    MMU_Free(system_modules.Modules);
                    *pSystemModule = system_module;
                    return STATUS_SUCCESS;
                }
            }
        }
    }

    MMU_Free(system_modules.Modules);
    return STATUS_NOT_FOUND;
}

NTSTATUS FindSystemModuleByName(_In_ CONST CHAR* ModuleName, PRTL_MODULE_EXTENDED_INFO pSystemModule)
{
    PAGED_CODE();

    NTSTATUS status = STATUS_SUCCESS;
    RTL_MODULE_EXTENDED_INFO system_module = { 0 };
    SYSTEM_MODULES system_modules = { 0 };

    status = PopulateSystemModules(&system_modules);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    for (ULONG i = 0; i < system_modules.Count; ++i)
    {
        system_module = system_modules.Modules[i];
        if (strstr(system_module.FullPathName, ModuleName) != 0)
        {
            *pSystemModule = system_module;
            MMU_Free(system_modules.Modules);
            return STATUS_SUCCESS;
        }
    }

    MMU_Free(system_modules.Modules);
    return STATUS_NOT_FOUND;
}