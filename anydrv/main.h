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

#pragma once

#ifndef _AC_MAIN_H_
#define _AC_MAIN_H_

#include <ntddk.h>

#include "dbg.h"
#include "pmem.h"

#define AC_NT_DEVICE_NAME      L"\\Device\\ANYCALL_IO"
#define AC_DOS_DEVICE_NAME     L"\\DosDevices\\ANYCALL_IO"

#define AC_IOCTL_TYPE 40000

#define IOCTL_AC_MAP_PHYSICAL_MEMORY \
    CTL_CODE( AC_IOCTL_TYPE, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS  )

#define IOCTL_AC_UNMAP_PHYSICAL_MEMORY \
    CTL_CODE( AC_IOCTL_TYPE, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS  )

typedef struct _AC_MAP_PHYSICAL_MEMORY_REQUEST
{
	UINT_PTR PhysicalAddress;
	SIZE_T Size;
} AC_MAP_PHYSICAL_MEMORY_REQUEST, * PAC_MAP_PHYSICAL_MEMORY_REQUEST;

typedef struct _AC_UNMAP_VIRTUAL_MEMORY_REQUEST
{
	UINT_PTR VirtualAddress;
	SIZE_T Size;
} AC_UNMAP_VIRTUAL_MEMORY_REQUEST, * PAC_UNMAP_VIRTUAL_MEMORY_REQUEST;

#endif // _AC_MAIN_H_