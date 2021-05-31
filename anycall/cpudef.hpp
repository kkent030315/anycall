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

#ifndef CLZLL64
#define CLZLL64( x ) ( int )__lzcnt64( x )
#endif

#define LOG2( x ) \
    ( ( unsigned ) \
        ( 8 * sizeof ( unsigned long long ) - CLZLL64( ( x ) ) - 1 ) )

#ifndef PAGE_SIZE
#define PAGE_SIZE ( 1024 * 4 )
#endif

#ifndef PAGE_SHIFT
#define PAGE_SHIFT LOG2( PAGE_SIZE )
#endif

//
// arch: x64
// virtual address definition
//
typedef union _VIRTUAL_ADDRESS
{
    PVOID value;
    struct
    {
        uint64_t offset : 12;
        uint64_t pt_index : 9;
        uint64_t pd_index : 9;
        uint64_t pdp_index : 9;
        uint64_t pml4_index : 9;
        uint64_t reserved : 16;
    };
} VIRTUAL_ADDRESS, * PVIRTUAL_ADDRESS;

//
// arch: x64
// page map level 4 entry definition
//
typedef union _PML4E
{
    uint64_t value;
    struct
    {
        uint64_t present : 1;
        uint64_t writable : 1;
        uint64_t user_access : 1;
        uint64_t write_through : 1;
        uint64_t cache_disabled : 1;
        uint64_t accessed : 1;
        uint64_t ignored_3 : 1;
        uint64_t size : 1;
        uint64_t ignored_2 : 4;
        uint64_t pfn : 36;
        uint64_t reserved_1 : 4;
        uint64_t ignored_1 : 11;
        uint64_t execution_disabled : 1;
    };
} PML4E, * PPML4E;

//
// arch: x64
// page directory pointer entry definition
//
typedef union PDPE
{
    uint64_t value;
    struct
    {
        uint64_t present : 1;
        uint64_t writable : 1;
        uint64_t user_access : 1;
        uint64_t write_through : 1;
        uint64_t cache_disabled : 1;
        uint64_t accessed : 1;
        uint64_t ignored_3 : 1;
        uint64_t size : 1;
        uint64_t ignored_2 : 4;
        uint64_t pfn : 36;
        uint64_t reserved_1 : 4;
        uint64_t ignored_1 : 11;
        uint64_t execution_disabled : 1;
    };
} PDPE, * PPDPE;

//
// arch: x64
// page directory entry definition
//
typedef union _PDE
{
    uint64_t value;
    struct
    {
        uint64_t present : 1;
        uint64_t writable : 1;
        uint64_t user_access : 1;
        uint64_t write_through : 1;
        uint64_t cache_disabled : 1;
        uint64_t accessed : 1;
        uint64_t ignored1 : 1;
        uint64_t size : 1;
        uint64_t ignored_2 : 4;
        uint64_t pfn : 36;
        uint64_t reserved_1 : 4;
        uint64_t ignored_1 : 11;
        uint64_t execution_disabled : 1;
    };
} PDE, * PPDE;

//
// arch: x64
// page table entry definition
//
typedef union _PTE
{
    uint64_t value;
    struct
    {
        uint64_t present : 1;
        uint64_t writable : 1;
        uint64_t user_access : 1;
        uint64_t write_through : 1;
        uint64_t cache_disabled : 1;
        uint64_t accessed : 1;
        uint64_t dirty : 1;
        uint64_t access_type : 1;
        uint64_t global : 1;
        uint64_t ignored_2 : 3;
        uint64_t pfn : 36;
        uint64_t reserved_1 : 4;
        uint64_t ignored_3 : 7;
        uint64_t protection_key : 4;
        uint64_t execution_disabled : 1;
    };
} PTE, * PPTE;