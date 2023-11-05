#include "ioctl.h"
#include "config.h"
#include <io.h>

#include <ntddk.h>

NTSTATUS HandleGetStatus(_Inout_ void* Buffer, _Out_ size_t* pSize) {
    CPL0_GET_STATUS_REQ req = *(CPL0_GET_STATUS_REQ*)Buffer;
    PCPL0_GET_STATUS_RES res = (PCPL0_GET_STATUS_RES)Buffer;

    res->output = 256;
    res->output = req.input * 2;

    *pSize = sizeof(CPL0_GET_STATUS_RES);
    return STATUS_SUCCESS;
}

NTSTATUS DeviceControl(_In_ PDRIVER_OBJECT DriverObject, _Inout_ PIRP Irp) {
    UNREFERENCED_PARAMETER(DriverObject);
    PAGED_CODE();

    PIO_STACK_LOCATION stack = NULL;
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    Irp->IoStatus.Information = 0;

    stack = IoGetCurrentIrpStackLocation(Irp);
    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_HYPERAC_GET_STATUS: {
        status = HandleGetStatus(Irp->AssociatedIrp.SystemBuffer, &Irp->IoStatus.Information);
    } break;
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    Irp->IoStatus.Status = status;
    return status;
}

NTSTATUS DeviceClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PAGED_CODE();

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DeviceCreate(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PAGED_CODE();

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}