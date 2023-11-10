#ifndef H_IOCTL
#define H_IOCTL

#include <ntifs.h>

NTSTATUS DeviceControl(_In_ PDRIVER_OBJECT DriverObject, _Inout_ PIRP Irp);
NTSTATUS DeviceClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
NTSTATUS DeviceCreate(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);

#endif // H_IOCTL