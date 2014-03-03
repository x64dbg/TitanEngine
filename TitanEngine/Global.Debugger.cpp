#include "stdafx.h"
#include "definitions.h"
#include "Global.Debugger.h"
#include "Global.Engine.h"

HARDWARE_DATA DebugRegister[4] = {};
PROCESS_INFORMATION dbgProcessInformation = {};
CustomHandler myDBGCustomHandler = {};
PCustomHandler DBGCustomHandler = &myDBGCustomHandler;
ExpertDebug expertDebug = {};
STARTUPINFOW dbgStartupInfo = {};
LPVOID DebugModuleEntryPointCallBack;
LPVOID DebugExeFileEntryPointCallBack;
ULONG_PTR DebugModuleEntryPoint;
ULONG_PTR DebugModuleImageBase;

ULONG_PTR engineAttachedProcessCallBack = NULL;
ULONG_PTR engineReserveModuleBase = NULL;
unsigned long long engineDebuggingMainModuleBase = NULL;
ULONG_PTR engineDebuggingDLLBase = NULL;
bool engineAttachedToProcess = false;
bool engineDebuggingDLL = false;
wchar_t* engineDebuggingDLLFullFileName;
wchar_t* engineDebuggingDLLFileName;

// Global.Debugger.functions:
long DebugLoopInSecondThread(LPVOID InputParameter)
{
    __try
    {
        if(InputParameter == NULL)
        {
            InitDebugExW(expertDebug.szFileName, expertDebug.szCommandLine, expertDebug.szCurrentFolder, expertDebug.EntryCallBack);
        }
        else
        {
            InitDLLDebugW(expertDebug.szFileName, expertDebug.ReserveModuleBase, expertDebug.szCommandLine, expertDebug.szCurrentFolder, expertDebug.EntryCallBack);
        }
        DebugLoop();
        return(NULL);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return(-1);
    }
}

void DebuggerReset()
{
    if(engineResetCustomHandler)
    {
        RtlZeroMemory(&myDBGCustomHandler, sizeof CustomHandler);
    }
}