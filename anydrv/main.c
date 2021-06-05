/*

    MIT License

    Copyright (c) 2021 Kento Oki

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

*/

#include "main.h"

_Dispatch_type_( IRP_MJ_CREATE )
_Dispatch_type_( IRP_MJ_CLOSE )
DRIVER_DISPATCH AcCreateClose;

_Dispatch_type_( IRP_MJ_DEVICE_CONTROL )
DRIVER_DISPATCH AcDeviceControl;

DRIVER_UNLOAD AcUnloadDriver;

VOID PrintIrpInfo( PIRP Irp );

NTSTATUS
AcDeviceControl
(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    NTSTATUS            ntStatus = STATUS_SUCCESS;
    PIO_STACK_LOCATION  irpSp;          // current stack location
    ULONG               inBufLength;    // length of input buffer
    ULONG               outBufLength;   // length of output buffer
    PCHAR               inBuf = NULL, outBuf = NULL; // pointer to Input and output buffer

    UNREFERENCED_PARAMETER( DeviceObject );

    PAGED_CODE();

    irpSp = IoGetCurrentIrpStackLocation( Irp );
    inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    if ( !inBufLength || !outBufLength )
    {
        ntStatus = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    switch ( irpSp->Parameters.DeviceIoControl.IoControlCode )
    {
    case IOCTL_AC_MAP_PHYSICAL_MEMORY:
    {
        //
        // map physical memory
        //

        AC_KDPRINT( "IOCTL_AC_MAP_PHYSICAL_MEMORY Requested\n" );

        PrintIrpInfo( Irp );

        inBuf = Irp->AssociatedIrp.SystemBuffer;
        outBuf = Irp->AssociatedIrp.SystemBuffer;

        PAC_MAP_PHYSICAL_MEMORY_REQUEST request = 
            ( PAC_MAP_PHYSICAL_MEMORY_REQUEST )inBuf;

        AcMapPhysicalMemoryForUser(
            ( UINT_PTR* )outBuf,        // result mapped va
            request->PhysicalAddress,   // physical address to map
            request->Size );            // size

        Irp->IoStatus.Information = sizeof( UINT_PTR );

        break;
    }
    case IOCTL_AC_UNMAP_PHYSICAL_MEMORY:
    {
        //
        // unmap mapped virtual memory
        //

        AC_KDPRINT( "IOCTL_AC_UNMAP_PHYSICAL_MEMORY Requested\n" );

        PrintIrpInfo( Irp );

        inBuf = Irp->AssociatedIrp.SystemBuffer;
        outBuf = Irp->AssociatedIrp.SystemBuffer;

        PAC_UNMAP_VIRTUAL_MEMORY_REQUEST request = 
            ( PAC_UNMAP_VIRTUAL_MEMORY_REQUEST )inBuf;

        ntStatus = AcUnmapMappedPhysicalMemoryForUser( 
            request->VirtualAddress, 
            request->Size );

        Irp->IoStatus.Information = NT_SUCCESS( ntStatus );

        break;
    }
    default:
    {
        ntStatus = STATUS_INVALID_DEVICE_REQUEST;

        AC_KDPRINT( "ERROR: unknown IOCTL code specified: 0x%x\n",
            irpSp->Parameters.DeviceIoControl.IoControlCode );

        Irp->IoStatus.Information = 0;

        break;
    }
    } // switch ( irpSp->Parameters.DeviceIoControl.IoControlCode )

Exit:
    Irp->IoStatus.Status = ntStatus;

    IoCompleteRequest( Irp, IO_NO_INCREMENT );

    return ntStatus;
}

VOID
PrintIrpInfo
(
    PIRP Irp
)
{
    PIO_STACK_LOCATION  irpSp;
    irpSp = IoGetCurrentIrpStackLocation( Irp );

    PAGED_CODE();

    AC_KDPRINT( "Irp->AssociatedIrp.SystemBuffer = 0x%p\n",
        Irp->AssociatedIrp.SystemBuffer );
    AC_KDPRINT( "Irp->UserBuffer = 0x%p\n", Irp->UserBuffer );
    AC_KDPRINT( "irpSp->Parameters.DeviceIoControl.Type3InputBuffer = 0x%p\n",
        irpSp->Parameters.DeviceIoControl.Type3InputBuffer );
    AC_KDPRINT( "irpSp->Parameters.DeviceIoControl.InputBufferLength = %d\n",
        irpSp->Parameters.DeviceIoControl.InputBufferLength );
    AC_KDPRINT( "irpSp->Parameters.DeviceIoControl.OutputBufferLength = %d\n",
        irpSp->Parameters.DeviceIoControl.OutputBufferLength );

    return;
}

NTSTATUS DispatchDriverEntry
(
    IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath
)
{
    NTSTATUS        ntStatus;
    UNICODE_STRING  ntDeviceNameUs;
    UNICODE_STRING  dosDeviceNameUs;
    PDEVICE_OBJECT  deviceObject = NULL;

    UNREFERENCED_PARAMETER( RegistryPath );

    RtlInitUnicodeString( &ntDeviceNameUs, AC_NT_DEVICE_NAME );

    ntStatus = IoCreateDevice(
        DriverObject,                   // our driver object
        0,                              // we don't use a device extension
        &ntDeviceNameUs,                // device name
        FILE_DEVICE_UNKNOWN,            // device type
        FILE_DEVICE_SECURE_OPEN,        // device characteristics
        FALSE,                          // not an exclusive device
        &deviceObject );                // returned pointer to Device Object

    if ( !NT_SUCCESS( ntStatus ) )
    {
        AC_KDPRINT( "Failed to create device\n" );
        return ntStatus;
    }

    DriverObject->MajorFunction[ IRP_MJ_CREATE ]            = AcCreateClose;
    DriverObject->MajorFunction[ IRP_MJ_CLOSE ]             = AcCreateClose;
    DriverObject->MajorFunction[ IRP_MJ_DEVICE_CONTROL ]    = AcDeviceControl;
    DriverObject->DriverUnload                              = AcUnloadDriver;

    RtlInitUnicodeString( &dosDeviceNameUs, AC_DOS_DEVICE_NAME );

    ntStatus = IoCreateSymbolicLink( &dosDeviceNameUs, &ntDeviceNameUs );

    if ( !NT_SUCCESS( ntStatus ) )
    {
        AC_KDPRINT( "Failed to create symbolic link\n" );
        AC_KDPRINT( " ---> NTSTATUS: 0x%lX\n", ntStatus );

        IoDeleteDevice( deviceObject );
    }

    return ntStatus;
}

//
// this will be called by the I/O system when the IOCTL is opened or closed
//
NTSTATUS
AcCreateClose
(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    UNREFERENCED_PARAMETER( DeviceObject );

    PAGED_CODE();

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest( Irp, IO_NO_INCREMENT );

    return STATUS_SUCCESS;
}

//
// this will be called when the driver being unloaded
//
VOID
AcUnloadDriver
(
    IN PDRIVER_OBJECT DriverObject
)
{
    PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
    UNICODE_STRING dosDeviceNameUs;

    PAGED_CODE();

    AC_KDPRINT( "Unload Driver\n" );

    RtlInitUnicodeString( &dosDeviceNameUs, AC_DOS_DEVICE_NAME );
    IoDeleteSymbolicLink( &dosDeviceNameUs );

    if ( deviceObject != NULL )
    {
        IoDeleteDevice( deviceObject );
    }
}

//
// this will be called after the driver loaded
//
NTSTATUS DriverInitialize
(
    IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    return STATUS_SUCCESS;
}

//
// main entry point of this driver
//
NTSTATUS DriverEntry
(
    IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath
)
{
    AC_KDPRINT( "Driver Entry\n" );
    return DispatchDriverEntry( DriverObject, RegistryPath );
}