#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.Hider.h"

// TitanEngine.Hider.functions:
__declspec(dllexport) void* TITCALL GetPEBLocation(HANDLE hProcess)
{
    ULONG RequiredLen = NULL;
    PPROCESS_BASIC_INFORMATION myProcessBasicInformation = (PPROCESS_BASIC_INFORMATION)VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    if(!myProcessBasicInformation)
        return 0;
#if !defined(_WIN64)
    typedef NTSTATUS(WINAPI *fZwQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
#else
    typedef NTSTATUS(__fastcall *fZwQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
#endif
    LPVOID ZwQueryInformationProcess = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"),"ZwQueryInformationProcess");
    fZwQueryInformationProcess cZwQueryInformationProcess = (fZwQueryInformationProcess)(ZwQueryInformationProcess);

    if(cZwQueryInformationProcess != NULL)
    {
        if(cZwQueryInformationProcess(hProcess, ProcessBasicInformation, myProcessBasicInformation, sizeof PROCESS_BASIC_INFORMATION, &RequiredLen) == STATUS_SUCCESS)
        {
            return (void*)myProcessBasicInformation->PebBaseAddress;
        }
        else
        {
            if(cZwQueryInformationProcess(hProcess, ProcessBasicInformation, myProcessBasicInformation, RequiredLen, &RequiredLen) == STATUS_SUCCESS)
            {
                return (void*)myProcessBasicInformation->PebBaseAddress;
            }
        }
    }
    return NULL;
}

__declspec(dllexport) bool TITCALL HideDebugger(HANDLE hProcess, DWORD PatchAPILevel)
{
    return ChangeHideDebuggerState(hProcess, PatchAPILevel, true);
}

__declspec(dllexport) bool TITCALL UnHideDebugger(HANDLE hProcess, DWORD PatchAPILevel)
{
    return ChangeHideDebuggerState(hProcess, PatchAPILevel, false);
}