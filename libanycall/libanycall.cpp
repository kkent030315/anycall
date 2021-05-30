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

#include "pch.h"
#include "libanycall.h"

#include "../anycall/io.hpp"
#include "../anycall/helper.hpp"
#include "../anycall/hook.hpp"
#include "../anycall/syscall.hpp"
#include "../anycall/driver.hpp"

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

ANYCALL_API_IMPL uint64_t libanycall::map_physical_memory(
    uint64_t physical_address, size_t size )
{
    return driver::map_physical_memory( physical_address, size );
}

ANYCALL_API_IMPL void libanycall::unmap_physical_memory( 
    uint64_t virtual_address, size_t size )
{
    driver::unmap_physical_memory( virtual_address, size );
}