#pragma once
#include <windows.h>

#include "nt.hpp"

namespace smep
{
	bool is_smep_enabled()
	{
		NTSTATUS nt_status;
		SYSTEM_SPECULATION_CONTROL_INFORMATION spec_information;
		PFN_NT_QUERY_SYSTEM_INFORMATION pNtQuerySystemInformation;

		pNtQuerySystemInformation = 
			( PFN_NT_QUERY_SYSTEM_INFORMATION )
			GetProcAddress( 
				GetModuleHandle( TEXT( "ntdll.dll" ) ), 
				"NtQuerySystemInformation" );

		if ( !pNtQuerySystemInformation )
		{
			return false;
		}

		nt_status = pNtQuerySystemInformation(
			SystemSpeculationControlInformation,
			&spec_information,
			sizeof( spec_information ),
			NULL );

		if ( !NT_SUCCESS( nt_status ) )
		{
			return false;
		}

		return 
			spec_information
			.SpeculationControlFlags
			.SmepPresent ? true : false;
	}
} // namespace smep