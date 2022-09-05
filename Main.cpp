#include <iostream>

#include "UnhookEngine.h" // templete, inline 함수 사용시 선언과 정의를 .h, .cpp로 나눌 수 없음

int main()
{
	ULONG oldProtect;
	SIZE_T size = 1;
	PVOID imageBase = GetModuleHandle(NULL);

	UnhookEngine<_ZwProtectVirtualMemory> sZwProtectVirtualMemory("ZwProtectVirtualMemory"); // ZwProtectVirtualMemory 시스템콜 객체 생성
	NTSTATUS status = (NTSTATUS)sZwProtectVirtualMemory(GetCurrentProcess(), &imageBase, &size, PAGE_READONLY, &oldProtect);
	printf("ZwProtectVirtualMemory NTSTATUS = 0x%08x\n", status);

	return 0;
}