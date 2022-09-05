#pragma once
#include <Windows.h>
#include "APIDeclaration.h"

/// <summary>
/// DLL �ּҿ��� �Լ� �ּҸ� ã��. GetProcAddress�� ������.
/// </summary>
/// <param name="dllAddress">dll �ּ�</param>
/// <param name="functionName">�Լ� �̸�</param>
/// <returns>�Լ� �ּ�</returns>
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
/// ������� ��ŷ�� �Ǿ����� ��� �ý����� ��ȣ�� ������ �� ���� ������ �������� DLL ������ �����Ͽ� �����Ѵ�.
/// IAT ��ŷ�� GetProcAddress ���� ��ŷ ������ ������ �ּҷ� ���� ������ �ý����� ��ȣ�� ������ �� ����.
/// �ζ��� ��ŷ�� MOV EAX, syscallId -> JMP, ��ŷ ������ ������ �ּҷ� �Ǿ��ֱ� ������ �ý����� ��ȣ�� ������ �� ����.
/// </summary>
/// <returns>NTDLL ���� �ּ�</returns>
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
/// UnhookEngine Ŭ���� �����ڸ� ���� �Լ� �̸��� ���¸� ���� �� ���ڵ�� ����.
/// </summary>
/// <typeparam name="T">�Լ� ����</typeparam>
/// <param name="functionName">�Լ� �̸�</param>
template<typename T>
UnhookEngine<T>::UnhookEngine(LPCSTR functionName)
{
	HMODULE ntdllAddress = NTDLLManualMapping();
	if (ntdllAddress == NULL)
		printf("UnhookEngine: %s ntdll ���� ����.\n", functionName);

	PBYTE functionAddress = (PBYTE)FindFunctionAddress(ntdllAddress, functionName);
	if (functionAddress == NULL)
		printf("UnhookEngine: %s ntdll���� �Լ� �ּҸ� ã�� �� ����.\n", functionName);
	else
		printf("UnhookEngine: %s�� �ּ� ã��. 0x%08x\n", functionName, functionAddress);

	switch (GetSyscallShellcode(GetSyscallId(functionAddress)))
	{
	case 0:
		printf("UnhookEngine: %s �ý����� ���ڵ� ���� �Ϸ�.\n", functionName);
		break;
	case 1:
		printf("UnhookEngine: %s �ý����� ��ȣ ���� ����.\n", functionName);
		break;
	case 2:
		printf("UnhookEngine: %s �ý����� ���ڵ� �޸� �Ҵ� ����.\n", functionName);
		break;
	default:
		printf("UnhookEngine: %s �� �� ���� ����.\n", functionName);
		break;
	}
	
}

/// <summary>
/// UnhookEngine Ŭ���� �Ҹ��� ȣ��� �Ҵ��ߴ� ���ڵ� �޸� ������ �Ҵ� ������.
/// </summary>
/// <typeparam name="T">�Լ� ����</typeparam>
template<typename T>
UnhookEngine<T>::~UnhookEngine()
{
	if (shellcode != NULL)
		VirtualFree(shellcode, NULL, MEM_RELEASE);

	printf("UnhookEngine: ���ڵ� �Ҵ� ���� �Ϸ�.\n");
}

/// <summary>
/// functionAddress�� �ý����� ��ȣ�� �������� �����Ѵ�.
/// ������ ������ ���� �ý����� ��ȣ�� �ٸ��� ������ �������� �����ؾ���.
/// </summary>
/// <typeparam name="T">�Լ� ����</typeparam>
/// <param name="functionAddress">�Լ� �ּ�</param>
/// <returns>�ý����� ��ȣ</returns>
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
/// �ý����� ��ȣ�� �Է¹޾� �ý������� �����ϴ� ���డ���� ���ڵ� �ּҸ� UnhookEngine ������� shellcode�� �Ҵ��Ѵ�.
/// x64�� x86 �� ���� ������ �ٸ��� ������ �ý����� ���ڵ� ���� �ٸ�.
/// </summary>
/// <typeparam name="T">�Լ� ����</typeparam>
/// <param name="syscallId">�ý����� ��ȣ</param>
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
	// TODO: Wow64�� �ƴ� ���� 32��Ʈ �����쿡���� �۵����� ����. sysenter�� ���?
#endif

	// EXECUTE ������ �ִ� �޸� �Ҵ� �� ���ڵ� ����
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