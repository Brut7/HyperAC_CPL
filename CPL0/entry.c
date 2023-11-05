#include "entry.h"

#include <ntddk.h>
#include <ntifs.h>

#include "config.h"
#include "ioctl.h"

static VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);
  PAGED_CODE();

  IoDeleteSymbolicLink(&g_SymbolicLinkName);
  IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(RegistryPath);
  PAGED_CODE();

  NTSTATUS status = STATUS_SUCCESS;

  status = IoCreateDevice(DriverObject, NULL, &g_DeviceName,
                          FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE,
                          &DriverObject->DeviceObject);
  if (!NT_SUCCESS(status)) {
    DebugMessage("IoCreateDevice failed: 0x%08X\n", status);
    return status;
  }

  status = IoCreateSymbolicLink(&g_SymbolicLinkName, &g_DeviceName);
  if (!NT_SUCCESS(status)) {
    DebugMessage("IoCreateSymbolicLink failed: 0x%08X\n", status);
    IoDeleteDevice(DriverObject->DeviceObject);
    return status;
  }

  DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreate;
  DriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceClose;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
  DriverObject->DriverUnload = DriverUnload;
  return STATUS_SUCCESS;
}