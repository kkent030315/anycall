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

#include <iostream>

#include "logger.hpp"
#include "io.hpp"
#include "syscall.hpp"

#define DEFAULT_MODULE_NAME "ntdll.dll"
#define DEFAULT_FUNCTION_NAME "NtTraceControl"

int main( const int argc, const char** argv, const char** envp )
{
    SetConsoleTitle( TEXT( "anycall by Kento Oki at www.godeye.club" ) );
    LOG( "\n[=] \"anycall\" by Kento Oki at www.godeye.club\n" );

    const bool use_default = argc < 3;
    const auto module_name = argv[ 1 ];
    const auto function_name = argv[ 2 ];

    if ( use_default )
    {
        LOG( "\n" );
        LOG( "[:] usage: anycall.exe [module_name] [function_name]\n" );
        LOG( "[:] -   module_name: module which contains hook function\n" );
        LOG( "[:] - function_name: function that exported by kernel\n" );
        LOG( "[:] -                this will be used to proxy syscalls we hook\n" );
        LOG( "\n" );

        LOG( "[:] using defaults: [\"%s\"] [\"%s\"]\n\n",
            DEFAULT_MODULE_NAME, DEFAULT_FUNCTION_NAME );
    }

    if ( !io::init() )
    {
        LOG( "[!] failed to init io\n" );
        std::cin.ignore();
        return EXIT_FAILURE;
    }

    //
    // we can hook ANY functions that exported by ntoskrnl
    //
    if ( !syscall::setup(
        use_default ? DEFAULT_MODULE_NAME : module_name,        // module name
        use_default ? DEFAULT_FUNCTION_NAME : function_name ) ) // function name
    {
        LOG( "[!] failed to setup syscall-hook\n" );
        std::cin.ignore();
        return EXIT_FAILURE;
    }

    //
    // wow, PsGetCurrentProcessId is kernel function but?
    //
    uint32_t process_id = ( uint32_t )SYSCALL( PsGetCurrentProcessId );
    LOG( "\n[:] PsGetCurrentProcessId: 0x%llX (%d)\n", process_id, process_id );

    std::cin.ignore();
    return EXIT_SUCCESS;
}