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
#include <winioctl.h>
#include <vector>
#include <cstdint>
#include <string_view>

#define ANYCALL_INVOKE( function_name, ... ) \
			libanycall::invoke< function_name >( \
				( void* )libanycall::find_ntoskrnl_export( \
					#function_name ), __VA_ARGS__ );

namespace libanycall
{
	extern "C" void* syscall_handler();

	extern bool init(
		std::string_view module_name,
		std::string_view function_name );

	extern uint64_t find_ntoskrnl_export(
		const std::string_view export_name,
		const bool as_rva = false );

	extern void* get_procedure();
	extern bool hook( void* source, void* detour, bool writable = false );
	extern bool unhook( void* source, bool writable = false );

	template < class FnType, class ... Args >
	std::invoke_result_t< FnType, Args... > invoke(
		void* detour, Args ... augments )
	{
		libanycall::hook( get_procedure(), detour, true );

		const auto invoke_result =
			reinterpret_cast< FnType >( syscall_handler )( augments ... );

		libanycall::unhook( get_procedure(), true );

		return invoke_result;
	}

	template < class FnType, class ... Args >
	std::invoke_result_t< FnType, Args... > invoke_void(
		void* detour, Args ... augments )
	{
		libanycall::hook( get_procedure(), detour, true );

		reinterpret_cast< FnType >( syscall_handler )( augments ... );

		libanycall::unhook( get_procedure(), true );
	}

} // namespace libanycall