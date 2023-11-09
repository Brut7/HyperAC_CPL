#include "handlers.h"
#include "config.h"
#include <ioc.h>
#include <ntifs.h>
#include "mmu.h"
#include "hwid.h"
#include <bcrypt.h>

NTSTATUS IOCTL_GetHWID(_Inout_ PVOID Buffer, _Out_ SIZE_T* pSize)
{
    

    CPL0_GET_HWID_REQ req = {0}; 
    PCPL0_GET_HWID_RES res = NULL;
    
    req = *(CPL0_GET_HWID_REQ*)Buffer;
    res = (PCPL0_GET_HWID_RES)Buffer;

    switch (req.Type)
    {
    case BootGUID: HWID_GetBootUUID(&res->Hash); break;
    case MonitorEDID: HWID_GetMonitorEDID(&res->Hash); break;
    }

    *pSize = sizeof(CPL0_GET_HWID_RES);
    return STATUS_SUCCESS;
}

NTSTATUS IOCTL_GetReportsSize(_Inout_ PVOID Buffer, _Out_ SIZE_T* pSize)
{
    

    CPL0_GET_REPORTS_SIZE_REQ req = { 0 };
    PCPL0_GET_REPORTS_SIZE_RES res = NULL;
    USHORT report_count = 0;
    REPORT_NODE* report = NULL;
    SIZE_T total_size = 0;

    req = *(CPL0_GET_REPORTS_SIZE_REQ*)Buffer;
    res = (PCPL0_GET_REPORTS_SIZE_RES)Buffer;

    report_count = GetReportCount();
    if (report_count == 0)
    {
        *pSize = sizeof(CPL0_GET_REPORTS_SIZE_RES);
        return STATUS_SUCCESS;
    }

    for (USHORT i = 0; i < report_count; ++i)
    {
		report = GetReportNode(i);
		if (report == NULL)
		{
            break;
		}

        total_size += REPORT_HEADER_SIZE + report->DataSize;
    }

    res->Size = total_size;
    *pSize = sizeof(CPL0_GET_REPORTS_SIZE_RES);
    return STATUS_SUCCESS;
}

NTSTATUS IOCTL_GetReports(_Inout_ PVOID Buffer, _Out_ SIZE_T* pSize)
{
    

    CPL0_GET_REPORTS_REQ req = { 0 };
    PCPL0_GET_REPORTS_RES res = NULL;
    USHORT report_count = 0;
    REPORT_NODE* report = NULL;
    SIZE_T size_left = 0;
    SIZE_T total_size = 0;
    USHORT node_index = 0;
    SIZE_T node_size = 0;
    PVOID cursor = NULL;

    req = *(CPL0_GET_REPORTS_REQ*)Buffer;
    res = (PCPL0_GET_REPORTS_RES)Buffer;

    total_size = req.Size;

    report_count = GetReportCount();
    if (report_count == 0)
    {
        *pSize = sizeof(CPL0_GET_REPORTS_RES);
        return STATUS_SUCCESS;
    }

    size_left = total_size;
    cursor = res->Reports;
    while (size_left)
    {
        report = GetReportNode(node_index);
        if (report == NULL)
        {
            *pSize = sizeof(CPL0_GET_REPORTS_RES) - size_left;
            return STATUS_SUCCESS;
        }

        if (report->DataSize > size_left)
        {
            break;
        }

        node_size = REPORT_HEADER_SIZE + report->DataSize;
        memcpy(cursor, report, node_size);
        cursor = (PVOID)((ULONG64)cursor + node_size);
        size_left -= node_size;

        ++node_index;
    }

    *pSize = total_size;
    return STATUS_SUCCESS;
}
