#pragma once

// custom function
typedef NTSTATUS(WINAPI* _RtlAdjustPrivilege)(
	ULONG Privilege, BOOL Enable,
	BOOL CurrentThread, PULONG Enabled);

_RtlAdjustPrivilege MRtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlAdjustPrivilege");