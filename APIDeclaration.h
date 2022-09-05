#pragma once
#include <Windows.h>

typedef HANDLE(WINAPI* _CreateFileA)(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
	);

typedef HANDLE(WINAPI* _CreateFileMappingA)(
	HANDLE					hFile,
	LPSECURITY_ATTRIBUTES	lpFileMappingAttributes,
	DWORD					flProtect,
	DWORD	                dwMaximumSizeHigh,
	DWORD					dwMaximumSizeLow,
	PCSTR					lpName
	);

typedef LPVOID(WINAPI* _MapViewOfFile)(
	HANDLE hFileMappingObject,
	DWORD  dwDesiredAccess,
	DWORD  dwFileOffsetHigh,
	DWORD  dwFileOffsetLow,
	SIZE_T dwNumberOfBytesToMap
	);

typedef NTSTATUS(NTAPI* _ZwProtectVirtualMemory)(
	HANDLE	ProcessHandle,
	PVOID	BaseAddress,
	PSIZE_T	RegionSize,
	ULONG	NewProtect,
	PULONG	OldProtect
	);