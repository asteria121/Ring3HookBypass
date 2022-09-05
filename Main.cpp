#include <iostream>

#include "UnhookEngine.h" // templete, inline �Լ� ���� ����� ���Ǹ� .h, .cpp�� ���� �� ����

int main()
{
	ULONG oldProtect;
	SIZE_T size = 1;
	PVOID imageBase = GetModuleHandle(NULL);

	UnhookEngine<_ZwProtectVirtualMemory> sZwProtectVirtualMemory("ZwProtectVirtualMemory"); // ZwProtectVirtualMemory �ý����� ��ü ����
	NTSTATUS status = (NTSTATUS)sZwProtectVirtualMemory(GetCurrentProcess(), &imageBase, &size, PAGE_READONLY, &oldProtect);
	printf("ZwProtectVirtualMemory NTSTATUS = 0x%08x\n", status);

	return 0;
}