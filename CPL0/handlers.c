#include "handlers.h"
#include "config.h"
#include <ioc.h>
#include <ntifs.h>
#include "mmu.h"
#include "hwid.h"
#include <bcrypt.h>

NTSTATUS IOCTL_GetHWID(_Inout_ PVOID Buffer, _Out_ SIZE_T* pSize) {
    PAGED_CODE();

    CPL0_GET_HWID_REQ req = *(CPL0_GET_HWID_REQ*)Buffer;
    PCPL0_GET_HWID_RES res = (PCPL0_GET_HWID_RES)Buffer;

    switch (req.Type)
    {
    case BootGUID: HWID_GetBootUUID(&res->Hash); break;
    case MonitorEDID: HWID_GetMonitorEDID(&res->Hash); break;
    }

    *pSize = sizeof(CPL0_GET_HWID_RES);
    return STATUS_SUCCESS;
}
