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

#include "logger.hpp"

#define AC_DEVICE_NAME "\\\\.\\\\ANYCALL_IO"
#define AC_IOCTL_TYPE 40000

#define IOCTL_AC_MAP_PHYSICAL_MEMORY \
    CTL_CODE( AC_IOCTL_TYPE, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS  )

#define IOCTL_AC_UNMAP_PHYSICAL_MEMORY \
    CTL_CODE( AC_IOCTL_TYPE, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS  )

namespace io
{
    inline HANDLE device_handle;

    bool init()
    {
        device_handle = CreateFile(
            TEXT( AC_DEVICE_NAME ),
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            NULL,
            NULL );

        if ( !device_handle || device_handle == INVALID_HANDLE_VALUE )
        {
            LOG( "[!] \033[0;101;30mfailed to obtain device handle\033[0m\n" );
            LOG_ERROR();
            return false;
        }

        LOG( "[+] device handle opened: 0x%p\n", device_handle );

        return true;
    }

    //
    // wrapper for DeviceIoControl
    //
    bool request_ioctl(
        const uint32_t ioctl_code,
        void* in_buffer, const size_t in_buffer_size,
        void* out_buffer, const size_t out_buffer_size,
        const bool strict = false // if true, check bytes returned
    )
    {
        if ( !device_handle ||
              device_handle == INVALID_HANDLE_VALUE )
        {
            LOG( "[!] \033[0;101;30minvalid device handle\033[0m\n" );
            return false;
        }

        DWORD bytes_returned = 0;

        //
        // send the ioctl request
        //
        const bool result = DeviceIoControl(
            device_handle,      // device handle
            ioctl_code,         // ioctl code
            in_buffer,          // input buffer
            in_buffer_size,     // input buffer size
            out_buffer,         // output buffer
            out_buffer_size,    // output buffer size
            &bytes_returned,     // bytes returned
            NULL );

        if ( strict )
        {
            if ( !bytes_returned )
            {
                LOG( "[!] \033[0;101;30mfailed to complete ioctl request\033[0m\n" );
                LOG_ERROR();
                return false;
            }
        }

        return result;
    }
} // namespace io