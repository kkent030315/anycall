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
#include <windows.h>
#include <cstdint>
#include <vector>
#include <mutex>

#include "logger.hpp"
#include "io.hpp"
#include "nt.hpp"

typedef struct _AC_MAP_PHYSICAL_MEMORY_REQUEST
{
	uint64_t physical_address;
	size_t size;
} AC_MAP_PHYSICAL_MEMORY_REQUEST, * PAC_MAP_PHYSICAL_MEMORY_REQUEST;

typedef struct _AC_UNMAP_VIRTUAL_MEMORY_REQUEST
{
	uint64_t virtual_address;
	size_t size;
} AC_UNMAP_VIRTUAL_MEMORY_REQUEST, * PAC_UNMAP_VIRTUAL_MEMORY_REQUEST;

typedef struct _MAPPED_VA_INFORMATION
{
	uint64_t virtual_address;
	size_t size;
} MAPPED_VA_INFORMATION, * PMAPPED_VA_INFORMATION;

namespace driver
{
	//
	// map arbitrary physical memory to our process virtual memory
	//
	uint64_t map_physical_memory( uint64_t physical_address, size_t size )
	{
		uint64_t mapped_va = 0;

		AC_MAP_PHYSICAL_MEMORY_REQUEST request;
		request.physical_address = physical_address;
		request.size = size;

		io::request_ioctl(
			IOCTL_AC_MAP_PHYSICAL_MEMORY,
			&request,
			sizeof( AC_MAP_PHYSICAL_MEMORY_REQUEST ),
			&mapped_va,
			sizeof( uint64_t ),
			true );

		return mapped_va;
	}

	//
	// unmap mapped virtual memory
	// size is not actually required to process on driver side
	//
	void unmap_physical_memory( 
		uint64_t virtual_address, size_t size,
		const bool should_erase = true )
	{
		uint64_t fake = 0; // unused

		AC_UNMAP_VIRTUAL_MEMORY_REQUEST request;
		request.virtual_address = virtual_address;
		request.size = size;

		io::request_ioctl(
			IOCTL_AC_UNMAP_PHYSICAL_MEMORY,
			&request,
			sizeof( AC_UNMAP_VIRTUAL_MEMORY_REQUEST ),
			&fake,
			sizeof( uint64_t ),
			true );
	}
} // namespace driver