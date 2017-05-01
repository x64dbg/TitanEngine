#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.Hider.h"

// TitanEngine.Hider.functions:
__declspec(dllexport) void* TITCALL GetPEBLocation(HANDLE hProcess)
{
    ULONG RequiredLen = 0;
    void* PebAddress = 0;
    PROCESS_BASIC_INFORMATION myProcessBasicInformation[5] = {0};

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

    return PebAddress;
}

__declspec(dllexport) void* TITCALL GetTEBLocation(HANDLE hThread)
{
    ULONG RequiredLen = 0;
    void* TebAddress = 0;
    THREAD_BASIC_INFORMATION myThreadBasicInformation[5] = {0};

    if(NtQueryInformationThread(hThread, ThreadBasicInformation, myThreadBasicInformation, sizeof(THREAD_BASIC_INFORMATION), &RequiredLen) == STATUS_SUCCESS)
    {
        TebAddress = (void*)myThreadBasicInformation->TebBaseAddress;
    }
    else
    {
        if(NtQueryInformationThread(hThread, ThreadBasicInformation, myThreadBasicInformation, RequiredLen, &RequiredLen) == STATUS_SUCCESS)
        {
            TebAddress = (void*)myThreadBasicInformation->TebBaseAddress;
        }
    }

    return TebAddress;
}

__declspec(dllexport) void* TITCALL GetTEBLocation64(HANDLE hThread)
{
#ifndef _WIN64
    if(IsThisProcessWow64())
    {
        //Only WOW64 processes have 2 PEBs and 2 TEBs
        DWORD teb32 = (DWORD)GetTEBLocation(hThread);
        if(teb32)
        {
            teb32 -= 0x2000; //TEB64 before TEB32
            return (void*)teb32;
        }
    }
#endif //_WIN64
    return 0;
}

__declspec(dllexport) void* TITCALL GetPEBLocation64(HANDLE hProcess)
{
#ifndef _WIN64
    if(IsThisProcessWow64())
    {
        //Only WOW64 processes have 2 PEBs
        DWORD peb32 = (DWORD)GetPEBLocation(hProcess);
        if(peb32)
        {
			// this offset is WRONG as of Win10 Creators Update.See comment in Global.Engine.Hider.cpp:192
            peb32 += 0x1000; //PEB64 after PEB32
            return (void*)peb32;
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
