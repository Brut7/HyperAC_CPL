#include "entry.h"

#include <ntddk.h>
#include <ntifs.h>

#include "config.h"
#include "ioctl.h"
#include "main.h"
#include "common.h"
#include "flow.h"
#include "callbacks.h"

static VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    

    InterlockedExchange(&g_UnloadThreads, TRUE);

    UnregisterCallbacks();
    FreeConfig();

    IoDeleteSymbolicLink(&g_SymbolicLinkName);
    IoDeleteDevice(DriverObject->DeviceObject);

    while (InterlockedExchange8(&g_ThreadCount, g_ThreadCount) > 0)
    {
        _mm_pause();
    }
   
    DebugMessage("Freed: %u / Allocated: %u", g_FreeCount, g_AllocCount);

}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    

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

    status = RegisterCallbacks();
    if (!NT_SUCCESS(status))
    {
		DebugMessage("RegisterCallbacks failed: 0x%08X\n", status);
		DriverUnload(DriverObject);
		return STATUS_UNSUCCESSFUL;
    }

    return status;
}