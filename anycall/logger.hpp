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
#include <iostream>

//
// if 1, enable debug prints
//
#define ANYCALL_LOG_ENABLED 1

#if ANYCALL_LOG_ENABLED
#define LOG(format, ...) \
	logger::log(format, __VA_ARGS__)
#else
#define LOG 
#endif

#define LOG_ERROR() \
	logger::log("[!] failed at %s:%d, (0x%lX)\n", __FILE__, __LINE__, GetLastError())

namespace logger
{
	//
	// just a wrapper for `printf`
	//
	template <typename ... T>
	__forceinline void log( const char* format, T const& ... args )
	{
		printf( format, args ... );
	}
}