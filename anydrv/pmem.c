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

#include "pmem.h"

NTSTATUS
AcMapPhysicalMemoryForUser
(
	OUT PUINT_PTR VirtualAddress,
	IN UINT_PTR PhysicalAddress,
	IN SIZE_T Size
)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	UNICODE_STRING ObjectNameUs;
	OBJECT_ATTRIBUTES ObjectAttributes;
	HANDLE SectionHandle;
	PVOID Object;
	ULONG IsIOSpace;
	PHYSICAL_ADDRESS PhysicalAddressStart;
	PHYSICAL_ADDRESS PhysicalAddressEnd;
	PHYSICAL_ADDRESS ViewBase;
	BOOLEAN HalTranslateResult1, HalTranslateResult2;
	PUCHAR pBaseAddress = NULL;

	AC_KDPRINT( "\nCalled %s\n", __FUNCTION__ );

	AC_KDPRINT( " ---> Physical Address: 0x%llX\n", PhysicalAddress );
	AC_KDPRINT( " ---> Size            : 0x%lX\n", Size );

	//
	// zero buffer is our responsibility in anycall interface architecture
	//
	*VirtualAddress = 0;

	PHYSICAL_ADDRESS _PhysicalAddress;
	_PhysicalAddress.QuadPart = PhysicalAddress;

	RtlInitUnicodeString( &ObjectNameUs, L"\\Device\\PhysicalMemory" );

	InitializeObjectAttributes( &ObjectAttributes,
		&ObjectNameUs,
		OBJ_CASE_INSENSITIVE,
		( HANDLE )NULL,
		( PSECURITY_DESCRIPTOR )NULL );

	ntStatus = ZwOpenSection(
		&SectionHandle, SECTION_ALL_ACCESS, &ObjectAttributes );

	if ( !NT_SUCCESS( ntStatus ) )
	{
		AC_KDPRINT( "ERROR: failed to open section with ZwOpenSection (0x%lX)",
			ntStatus );
		return ntStatus;
	}

	AC_KDPRINT( "Section Handle Opened 0x%p\n", SectionHandle );

	ntStatus = ObReferenceObjectByHandle( 
		SectionHandle,
		SECTION_ALL_ACCESS,
		( POBJECT_TYPE )NULL,
		KernelMode,
		&Object,
		( POBJECT_HANDLE_INFORMATION )NULL );

	if ( !NT_SUCCESS( ntStatus ) )
	{
		AC_KDPRINT( "ERROR: failed to reference object by handle with ObReferenceObjectByHandle" );
		ZwClose( SectionHandle );
		return ntStatus;
	}

	PhysicalAddressStart.QuadPart = ( ULONGLONG )( ULONG_PTR )PhysicalAddress;
	PhysicalAddressEnd.QuadPart = PhysicalAddressStart.QuadPart + Size;

	IsIOSpace = 0;
	HalTranslateResult1 = 
		HalTranslateBusAddress( 0, 0, PhysicalAddressStart, &IsIOSpace, &PhysicalAddressStart );

	IsIOSpace = 0;
	HalTranslateResult2 = 
		HalTranslateBusAddress( 0, 0, PhysicalAddressEnd, &IsIOSpace, &PhysicalAddressEnd );

	if ( !HalTranslateResult1 || !HalTranslateResult2 )
	{
		AC_KDPRINT( "ERROR: HalTranslateBusAddress Failed\n" );
		ZwClose( SectionHandle );
		return STATUS_UNSUCCESSFUL;
	}

	Size = ( SIZE_T )PhysicalAddressEnd.QuadPart - ( SIZE_T )PhysicalAddressStart.QuadPart;

	ViewBase = PhysicalAddressStart;

	ntStatus = ZwMapViewOfSection(
		SectionHandle,
		NtCurrentProcess(),
		&pBaseAddress,
		0L,
		Size,
		&ViewBase,
		&Size,
		ViewShare,
		0,
		PAGE_READWRITE | PAGE_NOCACHE );

	if ( !NT_SUCCESS( ntStatus ) )
	{
		AC_KDPRINT( "ERROR: ZwMapViewOfSection Failed (0x%lX)\n", ntStatus );
		ZwClose( SectionHandle );
		return ntStatus;
	}

	pBaseAddress += PhysicalAddressStart.QuadPart - ViewBase.QuadPart;
	*VirtualAddress = pBaseAddress;

	AC_KDPRINT( "SUCCESS: physical memory 0x%llX mapped to virtual memory 0x%llX\n",
		PhysicalAddress, *VirtualAddress );

	ZwClose( SectionHandle );

	return ntStatus;
}

NTSTATUS AcUnmapMappedPhysicalMemoryForUser(
	IN UINT_PTR VirtualAddress,
	IN SIZE_T Size )
{
	AC_KDPRINT( "\nCalled AcUnmapMappedPhysicalMemoryForUser\n" );

	AC_KDPRINT( " ---> Virtual Address : 0x%llX\n", VirtualAddress );
	AC_KDPRINT( " ---> Size            : 0x%lX\n", Size );

	NTSTATUS ntStatus = STATUS_SUCCESS;

	ntStatus = ZwUnmapViewOfSection( NtCurrentProcess(), VirtualAddress );

	if ( !NT_SUCCESS( ntStatus ) )
	{
		AC_KDPRINT( "ERROR: ZwUnmapViewOfSection failed\n" );
		return ntStatus;
	}

	return ntStatus;
}
