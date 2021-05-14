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
#include <vector>
#include <cstdint>

#include "logger.hpp"

typedef struct _HOOK_INFORMATION
{
	void* source;
	void* detour;
	std::vector<uint8_t> original_bytes;
} HOOK_INFORMATION, * PHOOK_INFORMATION;

namespace hook
{
	//
	// store hooked functions in order to restore
	//
	inline std::vector<HOOK_INFORMATION> hooked_functions;
	
	//
	// x64 inline hook shellcode
	// http://sandsprite.com/blogs/index.php?uid=7&pid=235&year=2012
	//
	inline const uint8_t shellcode[12] = {
		0x48, 0xb8,                              // mov rax, 0xaddress ; set detour address to rax
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // 0xaddress          ; detour function address
		0xff, 0xe0 };                            // jmp rax            ; jmp to detour function

	//
	// wrapper for memcpy in order to copy into read-only memory
	//
	void copy_memory( void* dst, void* src, size_t size )
	{
		DWORD old_protection;

		// make it rwx
		if ( !VirtualProtect( ( LPVOID )dst, size, PAGE_EXECUTE_READWRITE, &old_protection ) )
			return;

		memcpy( dst, src, size );

		// restore memory protection
		if ( !VirtualProtect( ( LPVOID )dst, size, old_protection, NULL ) )
			return;
	}

	//
	// fast and simple inline-hook
	//
	bool hook( 
		void* source,           // function to hook
		void* detour,           // detour function
		bool writable = false ) // in order to prevent useless VirtualProtect calls
	{
		std::vector<uint8_t> shell( sizeof( shellcode ) );
		std::vector<uint8_t> original( sizeof( shellcode ) );

		//
		// create copy of shellcode
		//
		memcpy( &shell[ 0 ], &shellcode[ 0 ], sizeof( shellcode ) );

		//
		// 0xaddress
		//
		memcpy( &shell[ 2 ], &detour, sizeof( uint64_t ) );

		//
		// cache original bytes in order to unhook
		//
		memcpy( &original[ 0 ], source, sizeof( shellcode ) );

		//
		// hook it
		// for syscall-inline-hooks, it's always writable (rwx)
		//
		if ( writable )
		{
			// prevent useless VirtualProtect calls
			memcpy( source, &shell[ 0 ], sizeof( shellcode ) );
		}
		else
		{
			copy_memory( source, &shell[ 0 ], sizeof( shellcode ) );
		}

		HOOK_INFORMATION information;
		information.source = ( void* )( uint64_t )source;
		information.detour = ( void* )( uint64_t )detour;
		information.original_bytes = original;

		//
		// save information in order to restore
		//
		hooked_functions.push_back( information );
	}

	//
	// since we loop every each entry until find
	// one that matches address, this will cause
	// performance issue if we have a lots of entries.
	//
	bool unhook( void* source, const bool writable = false )
	{
		// no entries
		if ( hooked_functions.size() <= 0 )
		{
			return false;
		}

		//
		// enumerate every single entries
		// stupid way
		//
		for ( auto entry = hooked_functions.begin();
			  entry != hooked_functions.end();
			  entry++ )
		{
			if ( entry->source == source )
			{
				//
				// restore original bytes
				//
				if ( writable )
				{
					memcpy(
						entry->source,
						&entry->original_bytes[ 0 ],
						sizeof( shellcode ) );
				}
				else
				{
					copy_memory(
						entry->source,
						&entry->original_bytes[ 0 ],
						sizeof( shellcode ) );
				}

				hooked_functions.erase( entry );
				return true;
			}
		}

		return false;
	}
}