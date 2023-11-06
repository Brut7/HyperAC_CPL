#include "entry.h"

#include <ntddk.h>
#include <ntifs.h>

#include "config.h"
#include "ioctl.h"
#include "main.h"
#include "common.h"
#include "flow.h"

static VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    PAGED_CODE();

    g_Unloading = TRUE;
    while (InterlockedExchange8(&g_ThreadCount, g_ThreadCount) > 0)
    {
        Sleep(1);
    }

    if (g_MainThread != NULL)
    {
        ZwClose(g_MainThread);
    }

    if (g_SigScanThread != NULL)
    {
        ZwClose(g_SigScanThread);
    }

    FreeReportList(&g_ReportHead);

    DebugMessage("Freed: %u / Allocated: %u", g_FreeCount, g_AllocCount);

    IoDeleteSymbolicLink(&g_SymbolicLinkName);
    IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    PAGED_CODE();

    g_DriverObject = DriverObject;

    DebugMessage("DriverEntry called\n");

    NTSTATUS status = STATUS_SUCCESS;

    status = IoCreateDevice(DriverObject, NULL, &g_DeviceName,
        FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE,
        &DriverObject->DeviceObject);
    if (!NT_SUCCESS(status))
    {
        DebugMessage("IoCreateDevice failed: 0x%08X\n", status);
        return status;
    }

    status = IoCreateSymbolicLink(&g_SymbolicLinkName, &g_DeviceName);
    if (!NT_SUCCESS(status))
    {
        DebugMessage("IoCreateSymbolicLink failed: 0x%08X\n", status);
        IoDeleteDevice(DriverObject->DeviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    status = PsCreateSystemThread(&g_MainThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, MainThread, NULL);
    if (!NT_SUCCESS(status))
    {
        DebugMessage("PsCreateSystemThread failed: 0x%08X\n", status);
        DriverUnload(DriverObject);
        return status;
    }

    status = PsCreateSystemThread(&g_SigScanThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, SigScanThread, NULL);
    if (!NT_SUCCESS(status))
    {
        DebugMessage("PsCreateSystemThread failed: 0x%08X\n", status);
        DriverUnload(DriverObject);
        return status;
    }

    return status;
}