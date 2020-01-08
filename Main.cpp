#include "KrankModules.hpp"
#include <iostream>
#include <stdio.h>
#include <Windows.h>

int main()
{
	KRANK::MODULE::KRANK_MODULE_INFORMATION Kernel32 = KRANK::MODULE::KrankGetModule(L"kernel32.dll");

	printf("%ws\n0x%016x\n0x%04x\n\n",
		Kernel32.Name,
		Kernel32.BaseAddress,
		Kernel32.Size
	);

	unsigned long BeepWithKrank = KRANK::MODULE::KrankGetFunction(&Kernel32, "Beep");
	unsigned long BeepWithWinapi = reinterpret_cast<decltype(BeepWithWinapi)>
		(GetProcAddress(GetModuleHandleA("kernel32.dll"), "Beep"));

	printf("Beep With Krank: 0x%016x\nBeep With Winapi: 0x%016x\n\n",
		BeepWithKrank,
		BeepWithWinapi
	);

	if(KRANK::MODULE::KrankHideModule(&Kernel32))
	{
		printf("Module has been hidden!\n\n");
	}

	else
	{
		printf("Module could not be hidden!\n\n");
	}

	getchar();

	return false;
}