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

#ifndef PAGE_SIZE
#define PAGE_SIZE (1024 * 4)
#endif

//
// arch: x64
// virtual address definition
//
typedef union _virtual_address_t
{
    PVOID value;
    struct
    {
        uint64_t offset     : 12;
        uint64_t pt_index   : 9;
        uint64_t pd_index   : 9;
        uint64_t pdpt_index : 9;
        uint64_t pml4_index : 9;
        uint64_t reserved   : 16;
    };
} virtual_address_t, * pvirtual_address_t;

//
// arch: x64
// page map level 4 entry definition
//
typedef union _pml4e
{
    uint64_t value;
    struct
    {
        uint64_t present             : 1;
        uint64_t writable            : 1;
        uint64_t user_access         : 1;
        uint64_t write_through       : 1;
        uint64_t cache_disabled      : 1;
        uint64_t accessed            : 1;
        uint64_t ignored_3           : 1;
        uint64_t size                : 1;
        uint64_t ignored_2           : 4;
        uint64_t pfn                 : 36;
        uint64_t reserved_1          : 4;
        uint64_t ignored_1           : 11;
        uint64_t execution_disabled  : 1;
    };
} pml4e, * ppml4e;

//
// arch: x64
// page directory pointer table entry definition
//
typedef union _pdpte
{
    uint64_t value;
    struct
    {
        uint64_t present                : 1;
        uint64_t writable               : 1;
        uint64_t user_access            : 1;
        uint64_t write_through          : 1;
        uint64_t cache_disabled         : 1;
        uint64_t accessed               : 1;
        uint64_t ignored_3              : 1;
        uint64_t size                   : 1;
        uint64_t ignored_2              : 4;
        uint64_t pfn                    : 36;
        uint64_t reserved_1             : 4;
        uint64_t ignored_1              : 11;
        uint64_t execution_disabled     : 1;
    };
} pdpte, * ppdpte;

//
// arch: x64
// page directory entry definition
//
typedef union _pde
{
    uint64_t value;
    struct
    {
        uint64_t present                : 1;
        uint64_t writable               : 1;
        uint64_t user_access            : 1;
        uint64_t write_through          : 1;
        uint64_t cache_disabled         : 1;
        uint64_t accessed               : 1;
        uint64_t ignored1               : 1;
        uint64_t size                   : 1;
        uint64_t ignored_2              : 4;
        uint64_t pfn                    : 36;
        uint64_t reserved_1             : 4;
        uint64_t ignored_1              : 11;
        uint64_t execution_disabled     : 1;
    };
} pde, * ppde;

//
// arch: x64
// page table entry definition
//
typedef union _pte
{
    uint64_t value;
    struct
    {
        uint64_t present                : 1;
        uint64_t writable               : 1;
        uint64_t user_access            : 1;
        uint64_t write_through          : 1;
        uint64_t cache_disabled         : 1;
        uint64_t accessed               : 1;
        uint64_t dirty                  : 1;
        uint64_t access_type            : 1;
        uint64_t global                 : 1;
        uint64_t ignored_2              : 3;
        uint64_t pfn                    : 36;
        uint64_t reserved_1             : 4;
        uint64_t ignored_3              : 7;
        uint64_t protection_key         : 4;
        uint64_t execution_disabled     : 1;
    };
} pte, * ppte;