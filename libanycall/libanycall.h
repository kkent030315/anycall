#pragma once
#include <windows.h>
#include <winioctl.h>
#include <vector>
#include <cstdint>
#include <string_view>

#define ANYCALL_INVOKE( function_name, ... ) \
			libanycall::invoke< function_name >( \
				( void* )libanycall::find_ntoskrnl_export( \
					#function_name ) );

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

} // namespace libanycall