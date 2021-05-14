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
#include <fstream>

#include "logger.hpp"
#include "nt.hpp"

#define CHECK_HANDLE(x) (x && x != INVALID_HANDLE_VALUE)
#define MIN_ADDRESS ((ULONG_PTR)0x8000000000000000)

typedef struct _PHYSICAL_ADDRESS_RANGE
{
	uint64_t start_pa;	// start physical address
	uint64_t end_pa;	// end physical address
} PHYSICAL_ADDRESS_RANGE, * PPHYSICAL_ADDRESS_RANGE;

typedef struct _SYSMODULE_RESULT
{
	uint64_t base_address;			// base address of the module
	std::string image_full_path;	// full path of the module
} SYSMODULE_RESULT, * PSYSMODULE_RESULT;

namespace helper
{
	inline SYSMODULE_RESULT ntoskrnl_cache;

	//
	// print hex
	// for example: 0x00 0x00 0x00 0x00 0x00 ... 
	//
	void print_hex( const std::string_view prefix, void* buffer, size_t length )
	{
		if ( !prefix.empty() )
			LOG( "%s", prefix.data() );

		for ( auto i = 0; i < length; i++ )
		{
			// hello terrible expression
			LOG( "0x%02X ", 
				*( byte* )( ( uint64_t )buffer + ( 0x2 * i ) ) & 0x000000FF );
		}

		LOG( "\n" );
	}

	//
	// read file
	//
	std::vector<uint8_t> read_file( const char* file_name )
	{
		std::streampos fileSize;
		std::ifstream file( file_name, std::ios::binary );

		file.seekg( 0, std::ios::end );
		fileSize = file.tellg();
		file.seekg( 0, std::ios::beg );

		std::vector<uint8_t> fileData( fileSize );
		file.read( ( char* )&fileData[ 0 ], fileSize );

		return fileData;
	}

	//
	// wrapper for `_dupenv_s` since getenv is vulnerable
	//
	bool lookup_env( const char* env, std::string* result )
	{
		char* buffer = 0;
		size_t size = 0;

		if ( _dupenv_s( &buffer, &size, env ) == 0 )
		{
			if ( !buffer )
			{
				return false;
			}
			
			*result = buffer;
			free( buffer );
		}
		else
		{
			return false;
		}

		return true;
	}

	//
	// replace "\\SystemRoot\\" with system-env value if exists
	//
	void replace_systemroot( std::string& str )
	{
		std::string env_value;
		lookup_env( "SYSTEMROOT", &env_value );

		str.replace(
			str.find( "\\SystemRoot\\" ),
			sizeof( "\\SystemRoot\\" ) - 1,
			env_value.append( "\\" )
		);
	}

	bool query_physical_memory_ranges( std::vector< PHYSICAL_ADDRESS_RANGE >& result )
	{
		LSTATUS status;
		HKEY registry_key;
		DWORD type, size;
		LPBYTE buffer;

		//
		// open registry key
		//
		RegOpenKeyEx(
			HKEY_LOCAL_MACHINE,
			TEXT( "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory" ),
			0,
			KEY_READ,
			&registry_key );

		//
		// query value size first
		//
		status = RegQueryValueEx(
			registry_key,
			TEXT( ".Translated" ),
			NULL,
			&type,
			NULL, &size );

		if ( status != ERROR_SUCCESS )
		{
			LOG( "[!] failed to query value size\n" );
			LOG_ERROR();

			return false;
		}

		//
		// allocate buffer
		//
		buffer = ( LPBYTE )VirtualAlloc(
			NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );

		if ( !buffer )
		{
			LOG( "[!] failed to allocate buffer\n" );
			LOG_ERROR();

			return false;
		}

		//
		// query value
		//
		status = RegQueryValueEx(
			registry_key,
			TEXT( ".Translated" ),
			NULL,
			&type,
			buffer, &size );

		if ( status != ERROR_SUCCESS )
		{
			LOG( "[!] failed to query value\n" );
			LOG_ERROR();

			VirtualFree( buffer, NULL, MEM_RELEASE );

			return false;
		}

		DWORD count = *( DWORD* )( buffer + 0x10 );
		LPBYTE entry = buffer + 0x18;

		for ( auto i = 0; i < count; i++ )
		{
			result.push_back({
				*( uint64_t* )( entry + 0x0 ),
				*( uint64_t* )( entry + 0x8 )} );

			//
			// next entry
			//
			entry += 0x14;
		}

		VirtualFree( buffer, NULL, MEM_RELEASE );
		RegCloseKey( registry_key );

		return true;
	}

	uint64_t find_export(
		std::string module_name,
		const std::string_view export_name )
	{
		replace_systemroot( module_name );

		//
		// temporally map target module to our virtual memory
		//
		const void* module_base =
			LoadLibraryEx(
				module_name.data(),				// file name
				NULL,							// file handle
				DONT_RESOLVE_DLL_REFERENCES );	// flags

		if ( !module_base )
		{
			LOG( "[!] failed to obtain module handle of %s\n", module_name.data() );
			LOG_ERROR();

			return NULL;
		}

		PIMAGE_DOS_HEADER pdos_header;
		PIMAGE_NT_HEADERS pnt_headers;
		PIMAGE_EXPORT_DIRECTORY pexport_directory;

		pdos_header = ( PIMAGE_DOS_HEADER )module_base;

		if ( pdos_header->e_magic != IMAGE_DOS_SIGNATURE )
		{
			LOG( "[!] invalid dos signature: 0x%lX \n", pdos_header->e_magic );
			FreeLibrary( ( HMODULE )module_base );
			return NULL;
		}

		pnt_headers = ( PIMAGE_NT_HEADERS )
			( (uint64_t)module_base + pdos_header->e_lfanew );

		if ( pnt_headers->Signature != IMAGE_NT_SIGNATURE )
		{
			LOG( "[!] invalid nt headers signature: 0x%lX \n", pnt_headers->Signature );
			FreeLibrary( ( HMODULE )module_base );
			return NULL;
		}

		DWORD export_directory = pnt_headers->OptionalHeader
			.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress;

		if ( !export_directory )
		{
			LOG( "[!] invalid nt headers\n", pnt_headers->Signature );
			FreeLibrary( ( HMODULE )module_base );
			return NULL;
		}

		pexport_directory = ( PIMAGE_EXPORT_DIRECTORY )
			( ( uint64_t )module_base + export_directory );

		PDWORD functions = ( PDWORD )
			( ( uint64_t )module_base + pexport_directory->AddressOfFunctions );

		PDWORD names = ( PDWORD )
			( ( uint64_t )module_base + pexport_directory->AddressOfNames );

		PWORD ordinals = ( PWORD )
			( ( uint64_t )module_base + pexport_directory->AddressOfNameOrdinals );

		for ( auto idx = 0;
			  idx < pexport_directory->NumberOfFunctions;
			  idx++ )
		{
			const auto name = reinterpret_cast< char* >
				( ( uint64_t )module_base + names[ idx ] );

			if ( export_name.compare( name ) == 0 )
			{
				uint64_t result = ( uint64_t )functions[ ordinals[ idx ] ];
				FreeLibrary( ( HMODULE )module_base );

				return result;
			}
		}

		FreeLibrary( ( HMODULE )module_base );
		return NULL;
	}

	SYSMODULE_RESULT find_sysmodule_address(
		const std::string_view target_module_name )
	{
		const HMODULE module_handle = GetModuleHandle( TEXT( "ntdll.dll" ) );

		if ( !CHECK_HANDLE( module_handle ) )
		{
			LOG( "[!] failed to obtain ntdll.dll handle. (0x%lX)\n", module_handle );
			return {};
		}

		pNtQuerySystemInformation NtQuerySystemInformation =
			( pNtQuerySystemInformation )GetProcAddress( module_handle, "NtQuerySystemInformation" );

		if ( !NtQuerySystemInformation )
		{
			LOG( "[!] failed to locate NtQuerySystemInformation. (0x%lX)\n", GetLastError() );
			return {};
		}

		NTSTATUS status;
		PVOID buffer;
		ULONG alloc_size = 0x10000;
		ULONG needed_size;

		do
		{
			buffer = calloc( 1, alloc_size );

			if ( !buffer )
			{
				LOG( "[!] failed to allocate buffer for query (0). (0x%lX)\n", GetLastError() );
				return {};
			}

			status = NtQuerySystemInformation(
				SystemModuleInformation,
				buffer,
				alloc_size,
				&needed_size
			);

			if ( !NT_SUCCESS( status ) && status != STATUS_INFO_LENGTH_MISMATCH )
			{
				LOG( "[!] failed to query system module information. NTSTATUS: 0x%llX\n", status );
				free( buffer );
				return {};
			}

			if ( status == STATUS_INFO_LENGTH_MISMATCH )
			{
				free( buffer );
				buffer = NULL;
				alloc_size *= 2;
			}
		} while ( status == STATUS_INFO_LENGTH_MISMATCH );

		if ( !buffer )
		{
			LOG( "[!] failed to allocate buffer for query (1). (0x%lX)\n", GetLastError() );
			return {};
		}

		PSYSTEM_MODULE_INFORMATION module_information = ( PSYSTEM_MODULE_INFORMATION )buffer;

		for ( ULONG i = 0; i < module_information->Count; i++ )
		{
			SYSTEM_MODULE_INFORMATION_ENTRY module_entry = module_information->Modules[ i ];
			ULONG_PTR module_address = ( ULONG_PTR )module_entry.DllBase;

			if ( module_address < MIN_ADDRESS )
			{
				continue;
			}

			PCHAR module_name = module_entry.ImageName + module_entry.ModuleNameOffset;

			if ( target_module_name.compare( module_name ) == 0 )
			{
				return {
					module_address,
					std::string( module_entry.ImageName ) };
			}
		}

		free( buffer );
		return {};
	}

	uint64_t find_ntoskrnl_export(
		const std::string_view export_name,
		const bool as_rva = false )
	{
		if ( !ntoskrnl_cache.base_address )
		{
			SYSMODULE_RESULT ntoskrnl = 
				find_sysmodule_address( "ntoskrnl.exe" );

			if ( !ntoskrnl.base_address )
			{
				LOG( "[!] failed to locate ntoskrnl.exe\n" );
				LOG_ERROR();

				return NULL;
			}

			ntoskrnl_cache = ntoskrnl;
		}

		//
		// find target function from EAT
		//
		const auto export_address = find_export(
			ntoskrnl_cache.image_full_path, export_name );

		return as_rva ?
			export_address : 
			ntoskrnl_cache.base_address + export_address;
	}
} // namespace helper