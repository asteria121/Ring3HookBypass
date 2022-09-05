#pragma once
#include <Windows.h>
#include "APIDeclaration.h"

/// <summary>
/// DLL 주소에서 함수 주소를 찾음. GetProcAddress와 동일함.
/// </summary>
/// <param name="dllAddress">dll 주소</param>
/// <param name="functionName">함수 이름</param>
/// <returns>함수 주소</returns>
PBYTE FindFunctionAddress(LPVOID dllAddress, const char* functionName)
{
	PBYTE pBase = reinterpret_cast<PBYTE>(dllAddress);
	auto* pNT = reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pBase)->e_lfanew);
	auto* pExportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(pBase + pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	if (reinterpret_cast<UINT_PTR>(functionName) <= MAXWORD)
	{
		WORD Ordinal = reinterpret_cast<WORD>(functionName);
		DWORD RVA = reinterpret_cast<DWORD*>(pBase + pExportDir->AddressOfFunctions)[Ordinal];
		return pBase + RVA;
	}

	DWORD max = pExportDir->NumberOfNames - 1;
	DWORD min = 0;

	while (min <= max)
	{
		DWORD mid = (min + max) >> 1;

		DWORD CurrNameRVA = reinterpret_cast<DWORD*>(pBase + pExportDir->AddressOfNames)[mid];
		char* szName = reinterpret_cast<char*>(pBase + CurrNameRVA);

		int cmp = strcmp(szName, functionName);
		if (cmp < 0)
			min = mid + 1;
		else if (cmp > 0)
			max = mid - 1;
		else
		{
			WORD Ordinal = reinterpret_cast<WORD*>(pBase + pExportDir->AddressOfNameOrdinals)[mid];
			DWORD RVA = reinterpret_cast<DWORD*>(pBase + pExportDir->AddressOfFunctions)[Ordinal];
			return pBase + RVA;
		}
	}

	return nullptr;
}

/// <summary>
/// 유저모드 후킹이 되어있을 경우 시스템콜 번호를 추출할 수 없기 때문에 수동으로 DLL 파일을 매핑하여 추출한다.
/// IAT 후킹은 GetProcAddress 사용시 후킹 엔진이 설정한 주소로 가기 때문에 시스템콜 번호를 추출할 수 없음.
/// 인라인 후킹은 MOV EAX, syscallId -> JMP, 후킹 엔진이 설정한 주소로 되어있기 때문에 시스템콜 번호를 추출할 수 없음.
/// </summary>
/// <returns>NTDLL 매핑 주소</returns>
HMODULE NTDLLManualMapping()
{
	char ntdllPath[MAX_PATH];
	if (GetWindowsDirectoryA(ntdllPath, MAX_PATH) == NULL)
		return NULL;
	lstrcatA(ntdllPath, "\\System32\\ntdll.dll"); // %windir%\\System32\\ntdll.dll

	HANDLE dllFile = CreateFileA(ntdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	HANDLE dllMapping = CreateFileMappingA(dllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	LPVOID dllAddress = MapViewOfFile(dllMapping, FILE_MAP_READ, 0, 0, 0);

	return (HMODULE)dllAddress;
}

template<typename T = NTSTATUS>
class UnhookEngine
{
public:
	UnhookEngine(LPCSTR functionName);
	~UnhookEngine();
	template<typename... Args>
	T operator()(Args... arg);

private:
	UINT32 GetSyscallId(const PBYTE functionAddress);
	INT32 GetSyscallShellcode(const UINT32 syscallId);
	PBYTE shellcode;
};

template<typename T> template<typename... Args>
T UnhookEngine<T>::operator()(Args... arg)
{
	if (shellcode == NULL)
		return T(0);

	typedef T(__cdecl* targetFunction)(Args...);
	targetFunction pFunc = targetFunction(shellcode);

	return pFunc(arg...);
}

/// <summary>
/// UnhookEngine 클래스 생성자를 통해 함수 이름과 형태를 전달 후 쉘코드로 생성.
/// </summary>
/// <typeparam name="T">함수 원형</typeparam>
/// <param name="functionName">함수 이름</param>
template<typename T>
UnhookEngine<T>::UnhookEngine(LPCSTR functionName)
{
	HMODULE ntdllAddress = NTDLLManualMapping();
	if (ntdllAddress == NULL)
		printf("UnhookEngine: %s ntdll 매핑 실패.\n", functionName);

	PBYTE functionAddress = (PBYTE)FindFunctionAddress(ntdllAddress, functionName);
	if (functionAddress == NULL)
		printf("UnhookEngine: %s ntdll에서 함수 주소를 찾을 수 없음.\n", functionName);
	else
		printf("UnhookEngine: %s의 주소 찾음. 0x%08x\n", functionName, functionAddress);

	switch (GetSyscallShellcode(GetSyscallId(functionAddress)))
	{
	case 0:
		printf("UnhookEngine: %s 시스템콜 쉘코드 생성 완료.\n", functionName);
		break;
	case 1:
		printf("UnhookEngine: %s 시스템콜 번호 추출 실패.\n", functionName);
		break;
	case 2:
		printf("UnhookEngine: %s 시스템콜 쉘코드 메모리 할당 실패.\n", functionName);
		break;
	default:
		printf("UnhookEngine: %s 알 수 없는 오류.\n", functionName);
		break;
	}
	
}

/// <summary>
/// UnhookEngine 클래스 소멸자 호출시 할당했던 쉘코드 메모리 영역은 할당 해제함.
/// </summary>
/// <typeparam name="T">함수 원형</typeparam>
template<typename T>
UnhookEngine<T>::~UnhookEngine()
{
	if (shellcode != NULL)
		VirtualFree(shellcode, NULL, MEM_RELEASE);

	printf("UnhookEngine: 쉘코드 할당 해제 완료.\n");
}

/// <summary>
/// functionAddress의 시스템콜 번호를 동적으로 추출한다.
/// 윈도우 버전에 따라 시스템콜 번호는 다르기 때문에 동적으로 추출해야함.
/// </summary>
/// <typeparam name="T">함수 원형</typeparam>
/// <param name="functionAddress">함수 주소</param>
/// <returns>시스템콜 번호</returns>
template<typename T>
UINT32 UnhookEngine<T>::GetSyscallId(const PBYTE functionAddress)
{
	if (functionAddress == NULL)
		return 0;

	for (INT32 i = 0; i < 0xF; i++)
	{
		if (*(functionAddress + i) == 0xB8) // MOV EAX
		{
			UINT32 syscallId = *PUINT(functionAddress + i + 1);
			printf("SyscallId: %d\n", syscallId);
			return syscallId;
		}
	}

	return 0;
}

/// <summary>
/// 시스템콜 번호를 입력받아 시스템콜을 수행하는 실행가능한 쉘코드 주소를 UnhookEngine 멤버변수 shellcode에 할당한다.
/// x64와 x86 은 서로 어셈블리어가 다르기 때문에 시스템콜 쉘코드 또한 다름.
/// </summary>
/// <typeparam name="T">함수 원형</typeparam>
/// <param name="syscallId">시스템콜 번호</param>
template<typename T>
int UnhookEngine<T>::GetSyscallShellcode(const UINT32 syscallId)
{
	if (syscallId == 0)
		return 1;

#ifdef _WIN64
	BYTE syscallShellcode[]
	{
		0x4C, 0x8B, 0xD1,				// MOV R10, RCX 
		0xB8, 0x00, 0x00, 0x00, 0x00,	// MOV EAX, syscallId
		0x0F, 0x05,					    // SYSCALL
		0xC3							// RET
	};

	*PDWORD(syscallShellcode + 4) = syscallId;
#elif _WIN32
	BYTE syscallShellcode[]
	{
		0xB8, 0x00, 0x00, 0x00, 0x00,	// MOV EAX, syscallId
		0xBA, 0x00, 0x00, 0x00, 0x00,	// MOV EDX, Wow64Transition Address
		0xFF, 0xD2,						// CALL EDX
		0xC3							// RET
	};

	*PDWORD(syscallShellcode + 1) = syscallId;
	*PDWORD(syscallShellcode + 6) = *(PDWORD)GetProcAddress(GetModuleHandleA("ntdll.dll"), "Wow64Transition");
	// TODO: Wow64가 아닌 실제 32비트 윈도우에서는 작동하지 않음. sysenter를 사용?
#endif

	// EXECUTE 권한이 있는 메모리 할당 후 쉘코드 복사
	this->shellcode = (PBYTE)VirtualAlloc(NULL, sizeof(syscallShellcode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (this->shellcode == NULL)
	{
		return 2;
	}
	else
	{
		RtlCopyMemory(this->shellcode, syscallShellcode, sizeof(syscallShellcode));
		return 0;
	}
}