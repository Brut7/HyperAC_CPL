#include "ioctl.h"
#include "config.h"
#include "handlers.h"
#include <ioc.h>

#include <ntddk.h>

NTSTATUS DeviceControl(_In_ PDRIVER_OBJECT DriverObject, _Inout_ PIRP Irp) {
    UNREFERENCED_PARAMETER(DriverObject);
    

    Irp->IoStatus.Information = 0;

    PIO_STACK_LOCATION stack = NULL;
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    ULONG ctl_code = 0;

    stack = IoGetCurrentIrpStackLocation(Irp);
    ctl_code = stack->Parameters.DeviceIoControl.IoControlCode;

    switch (ctl_code)
    {
    case IOCTL_GET_HWID:
    {
        status = IOCTL_GetHWID(Irp->AssociatedIrp.SystemBuffer, &Irp->IoStatus.Information);
    } break;
    case IOCTL_GET_REPORTS_SIZE:
    {
        status = IOCTL_GetReportsSize(Irp->AssociatedIrp.SystemBuffer, &Irp->IoStatus.Information);
    } break;
    case IOCTL_GET_REPORTS:
    {
        status = IOCTL_GetReports(Irp->AssociatedIrp.SystemBuffer, &Irp->IoStatus.Information);
    } break;
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    Irp->IoStatus.Status = status;
    return status;
}

NTSTATUS DeviceClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DeviceCreate(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}