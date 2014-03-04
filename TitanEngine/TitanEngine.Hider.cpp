#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.Hider.h"

// TitanEngine.Hider.functions:
__declspec(dllexport) void* TITCALL GetPEBLocation(HANDLE hProcess)
{
	typedef NTSTATUS(WINAPI *fNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
    ULONG RequiredLen = 0;
	void * PebAddress = 0;
    PPROCESS_BASIC_INFORMATION myProcessBasicInformation = (PPROCESS_BASIC_INFORMATION)VirtualAlloc(NULL, sizeof(PROCESS_BASIC_INFORMATION) * 4, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    
	if(!myProcessBasicInformation)
        return 0;

    fNtQueryInformationProcess cNtQueryInformationProcess = (fNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtQueryInformationProcess");

    if(cNtQueryInformationProcess != NULL)
    {
        if(cNtQueryInformationProcess(hProcess, ProcessBasicInformation, myProcessBasicInformation, sizeof(PROCESS_BASIC_INFORMATION), &RequiredLen) == STATUS_SUCCESS)
        {
            PebAddress = (void*)myProcessBasicInformation->PebBaseAddress;
        }
        else
        {
            if(cNtQueryInformationProcess(hProcess, ProcessBasicInformation, myProcessBasicInformation, RequiredLen, &RequiredLen) == STATUS_SUCCESS)
            {
                PebAddress = (void*)myProcessBasicInformation->PebBaseAddress;
            }
        }
	}

	VirtualFree(myProcessBasicInformation, 0, MEM_RELEASE);
    return PebAddress;
}

#ifndef _WIN64
typedef BOOL (WINAPI * tIsWow64Process)(HANDLE hProcess,PBOOL Wow64Process);

static bool IsThisProcessWow64()
{
	BOOL bIsWow64 = FALSE;
	tIsWow64Process fnIsWow64Process = (tIsWow64Process)GetProcAddress(GetModuleHandleA("kernel32.dll"), "IsWow64Process");

	if (fnIsWow64Process)
	{
		fnIsWow64Process(GetCurrentProcess(), &bIsWow64);
	}

	return (bIsWow64 != FALSE);
}

__declspec(dllexport) void* TITCALL GetPEBLocation64(HANDLE hProcess)
{
	if (IsThisProcessWow64())
	{
		//Only WOW64 processes have 2 PEBs
		DWORD peb32 = (DWORD)GetPEBLocation(hProcess);
		peb32 += 0x1000; //PEB64 after PEB32
		return (void *)peb32;
	}

	return 0;
}

#endif

__declspec(dllexport) bool TITCALL HideDebugger(HANDLE hProcess, DWORD PatchAPILevel)
{
    return ChangeHideDebuggerState(hProcess, PatchAPILevel, true);
}

__declspec(dllexport) bool TITCALL UnHideDebugger(HANDLE hProcess, DWORD PatchAPILevel)
{
    return ChangeHideDebuggerState(hProcess, PatchAPILevel, false);
}