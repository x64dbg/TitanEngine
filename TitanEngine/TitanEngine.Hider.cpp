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
    //TODO: this might return garbage on Windows 10
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
    void* PebAddress = 0;
#ifndef _WIN64
    if(IsThisProcessWow64())
    {
        typedef NTSTATUS(WINAPI * t_NtWow64QueryInformationProcess64)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
        static auto _NtWow64QueryInformationProcess64 = (t_NtWow64QueryInformationProcess64)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWow64QueryInformationProcess64");
        if(_NtWow64QueryInformationProcess64)
        {
            struct PROCESS_BASIC_INFORMATION64
            {
                DWORD ExitStatus;
                DWORD64 PebBaseAddress;
                DWORD64 AffinityMask;
                DWORD BasePriority;
                DWORD64 UniqueProcessId;
                DWORD64 InheritedFromUniqueProcessId;
            } myProcessBasicInformation[5];

            ULONG RequiredLen = 0;

            if(_NtWow64QueryInformationProcess64(hProcess, ProcessBasicInformation, myProcessBasicInformation, sizeof(PROCESS_BASIC_INFORMATION64), &RequiredLen) == STATUS_SUCCESS)
            {
                PebAddress = (void*)myProcessBasicInformation->PebBaseAddress;
            }
            else
            {
                if(_NtWow64QueryInformationProcess64(hProcess, ProcessBasicInformation, myProcessBasicInformation, RequiredLen, &RequiredLen) == STATUS_SUCCESS)
                {
                    PebAddress = (void*)myProcessBasicInformation->PebBaseAddress;
                }
            }
        }
    }
#endif //_WIN64
    return PebAddress;
}

__declspec(dllexport) bool TITCALL HideDebugger(HANDLE hProcess, DWORD PatchAPILevel)
{
    return ChangeHideDebuggerState(hProcess, PatchAPILevel, true);
}

__declspec(dllexport) bool TITCALL UnHideDebugger(HANDLE hProcess, DWORD PatchAPILevel)
{
    return ChangeHideDebuggerState(hProcess, PatchAPILevel, false);
}
