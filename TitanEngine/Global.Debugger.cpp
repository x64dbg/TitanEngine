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
ULONG_PTR DebugAttachedProcessCallBack = NULL;
ULONG_PTR DebugReserveModuleBase = NULL;
ULONG_PTR DebugDebuggingMainModuleBase = NULL;
ULONG_PTR DebugDebuggingDLLBase = NULL;
bool DebugAttachedToProcess = false;
bool DebugRemoveDebugPrivilege = false;
bool DebugDebuggingDLL = false;
wchar_t* DebugDebuggingDLLFullFileName;
wchar_t* DebugDebuggingDLLFileName;
DEBUG_EVENT DBGEvent = {};
DEBUG_EVENT TerminateDBGEvent = {};
DWORD ProcessExitCode = 0;
HANDLE DBGFileHandle;
std::vector<ULONG_PTR> tlsCallBackList;
std::vector<PROCESS_ITEM_DATA> hListProcess;
int engineStepCount = INFINITE;
LPVOID engineStepCallBack = NULL;
bool engineStepActive = false;
bool engineProcessIsNowDetached = false;
DWORD DBGCode = DBG_CONTINUE;
bool engineFileIsBeingDebugged = false;
ULONG_PTR engineFakeDLLHandle = NULL;
LPVOID engineAttachedProcessDebugInfo = NULL;
wchar_t szDebuggerName[512];
bool DebugStepFinal = false;
LPVOID StepOutCallBack = NULL;

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

void ClearProcessList()
{
    std::vector<PROCESS_ITEM_DATA>().swap(hListProcess);
}

void ClearTlsCallBackList()
{
    std::vector<ULONG_PTR>().swap(tlsCallBackList);
}

void StepOutStepCallBack()
{
    BYTE cipch = 0x90;
    MemoryReadSafe(dbgProcessInformation.hProcess, (void*)GetContextData(UE_CIP), &cipch, sizeof(cipch), 0);
    if(cipch == 0xC3 || cipch == 0xC2) //ret
    {
        if(DebugStepFinal)
            StepOver(StepOutCallBack);
        else
        {
            typedef void(TITCALL *fCustomBreakPoint)();
            __try
            {
                ((fCustomBreakPoint)StepOutCallBack)();
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
            }            
        }
    }
    else
        StepOver(StepOutStepCallBack);
}
