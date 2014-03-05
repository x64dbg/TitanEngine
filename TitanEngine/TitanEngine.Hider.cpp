#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.Hider.h"

// TitanEngine.Hider.functions:
__declspec(dllexport) void* TITCALL GetPEBLocation(HANDLE hProcess)
{
    ULONG RequiredLen = 0;
    void * PebAddress = 0;
    PPROCESS_BASIC_INFORMATION myProcessBasicInformation = (PPROCESS_BASIC_INFORMATION)VirtualAlloc(NULL, sizeof(PROCESS_BASIC_INFORMATION) * 4, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);

    if(!myProcessBasicInformation)
        return 0;

    if(NtQueryInformationProcess(hProcess, ProcessBasicInformation, myProcessBasicInformation, sizeof(PROCESS_BASIC_INFORMATION), &RequiredLen) == STATUS_SUCCESS)
    {
        PebAddress = (void*)myProcessBasicInformation->PebBaseAddress;
    }
    else
    {
        if(NtQueryInformationProcess(hProcess, ProcessBasicInformation, myProcessBasicInformation, RequiredLen, &RequiredLen) == STATUS_SUCCESS)
        {
            PebAddress = (void*)myProcessBasicInformation->PebBaseAddress;
        }
    }


    VirtualFree(myProcessBasicInformation, 0, MEM_RELEASE);
    return PebAddress;
}

__declspec(dllexport) void* TITCALL GetPEBLocation64(HANDLE hProcess)
{
#ifndef _WIN64
    if (IsThisProcessWow64())
    {
        //Only WOW64 processes have 2 PEBs
        DWORD peb32 = (DWORD)GetPEBLocation(hProcess);
        if (peb32)
        {
            peb32 += 0x1000; //PEB64 after PEB32
            return (void *)peb32;
        }
    }
#endif //_WIN64
    return 0;
}

__declspec(dllexport) bool TITCALL HideDebugger(HANDLE hProcess, DWORD PatchAPILevel)
{
    return ChangeHideDebuggerState(hProcess, PatchAPILevel, true);
}

__declspec(dllexport) bool TITCALL UnHideDebugger(HANDLE hProcess, DWORD PatchAPILevel)
{
    return ChangeHideDebuggerState(hProcess, PatchAPILevel, false);
}
