#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.Hook.h"
#include "Global.Debugger.h"

// Global.Engine.Hook.functions:
void EngineFakeLoadLibraryReturn()
{

    ULONG_PTR ParameterData;
    LPDEBUG_EVENT currentDBGEvent;
    HANDLE currentProcess;

    currentDBGEvent = (LPDEBUG_EVENT)GetDebugData();
    currentProcess = dbgProcessInformation.hProcess;
    if(currentProcess != NULL)
    {
#if !defined(_WIN64)
        ParameterData = (ULONG_PTR)GetFunctionParameter(currentProcess, UE_FUNCTION_STDCALL_RET, 1, UE_PARAMETER_DWORD);
        if(ParameterData != NULL)
        {
            if(engineFakeDLLHandle != NULL)
            {
                SetContextData(UE_EAX, engineFakeDLLHandle);
            }
            else
            {
                SetContextData(UE_EAX, 0x10000000);
            }
        }
#else
        ParameterData = (ULONG_PTR)GetFunctionParameter(currentProcess, UE_FUNCTION_FASTCALL, 1, UE_PARAMETER_QWORD);
        if(ParameterData != NULL)
        {
            if(engineFakeDLLHandle != NULL)
            {
                SetContextData(UE_RAX, engineFakeDLLHandle);
            }
            else
            {
                SetContextData(UE_RAX, 0x10000000);
            }
        }
#endif
    }
}

void EngineFakeGetProcAddressReturn()
{

    ULONG_PTR ParameterData;
    LPDEBUG_EVENT currentDBGEvent;
    HANDLE currentProcess;

    currentDBGEvent = (LPDEBUG_EVENT)GetDebugData();
    currentProcess = dbgProcessInformation.hProcess;
    if(currentProcess != NULL)
    {
#if !defined(_WIN64)
        ParameterData = (ULONG_PTR)GetFunctionParameter(currentProcess, UE_FUNCTION_STDCALL_RET, 1, UE_PARAMETER_DWORD);
        if(ParameterData != NULL)
        {
            SetContextData(UE_EAX, (ULONG_PTR)ImporterGetRemoteAPIAddress(currentProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitProcess")));
        }
#else
        ParameterData = (ULONG_PTR)GetFunctionParameter(currentProcess, UE_FUNCTION_FASTCALL, 1, UE_PARAMETER_QWORD);
        if(ParameterData != NULL)
        {
            SetContextData(UE_RAX, (ULONG_PTR)ImporterGetRemoteAPIAddress(currentProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitProcess")));
        }
#endif
    }
}