#ifndef H_IOCTL
#define H_IOCTL

#include <ntifs.h>

NTSTATUS HandleGetStatus(_Inout_ void* Buffer, _Out_ size_t* pSize);
NTSTATUS DeviceControl(_In_ PDRIVER_OBJECT DriverObject, _Inout_ PIRP Irp);
NTSTATUS DeviceClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
NTSTATUS DeviceCreate(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);

#pragma alloc_text(PAGE, HandleGetStatus)
#pragma alloc_text(PAGE, DeviceControl)
#pragma alloc_text(PAGE, DeviceClose)
#pragma alloc_text(PAGE, DeviceCreate)

#endif // H_IOCTL