#include "pch.h"
#include "libanycall.h"

#include "../anycall/io.hpp"
#include "../anycall/helper.hpp"
#include "../anycall/hook.hpp"
#include "../anycall/syscall.hpp"

#define ANYCALL_API_IMPL 

ANYCALL_API_IMPL bool libanycall::init( 
	std::string_view module_name,
	std::string_view function_name )
{
	return 
		io::init() && 
		syscall::setup( module_name, function_name );
}

ANYCALL_API_IMPL void* libanycall::get_procedure()
{
	return syscall::function;
}

ANYCALL_API_IMPL bool libanycall::hook( 
	void* source, void* detour, bool writable )
{
	return hook::hook( source, detour, writable );
}

ANYCALL_API_IMPL bool libanycall::unhook(
	void* source, bool writable )
{
	return hook::unhook( source, writable );
}

ANYCALL_API_IMPL uint64_t libanycall::find_ntoskrnl_export(
	const std::string_view export_name,
	const bool as_rva )
{
	return helper::find_ntoskrnl_export( export_name, as_rva );
}