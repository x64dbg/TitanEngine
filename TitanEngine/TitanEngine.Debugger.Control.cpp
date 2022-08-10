#include "stdafx.h"
#include "definitions.h"
#include "Global.Debugger.h"
#include "Global.Handle.h"
#include "Global.Threader.h"
#include "Global.Librarian.h"
#include "Global.Engine.h"

__declspec(dllexport) void TITCALL ForceClose()
{
    //manage process list
    ClearProcessList();
    //manage thread list
    ClearThreadList();
    //manage library list
    int libcount = (int)hListLibrary.size();
    for(int i = 0; i < libcount; i++)
    {
        if(hListLibrary.at(i).hFileMappingView != NULL)
        {
            UnmapViewOfFile(hListLibrary.at(i).hFileMappingView);
            EngineCloseHandle(hListLibrary.at(i).hFileMapping);
        }
    }
    ClearLibraryList();

    if(!engineProcessIsNowDetached)
    {
        StopDebug();
    }
    RtlZeroMemory(&dbgProcessInformation, sizeof PROCESS_INFORMATION);
    if(DebugDebuggingDLL)
        DeleteFileW(szDebuggerName);
    DebugDebuggingDLL = false;
    DebugExeFileEntryPointCallBack = NULL;
}

__declspec(dllexport) void TITCALL StepInto(LPVOID StepCallBack)
{
    EnterCriticalSection(&engineStepActiveCr);
    if (!engineStepActive)
    {
        ULONG_PTR ueCurrentPosition = GetContextData(UE_CIP);
        unsigned char instr[16];
        MemoryReadSafe(dbgProcessInformation.hProcess, (void*)ueCurrentPosition, instr, sizeof(instr), 0);
        char* DisassembledString = (char*)StaticDisassembleEx(ueCurrentPosition, (LPVOID)instr);
        if (strstr(DisassembledString, "PUSHF"))
            StepOver(StepCallBack);
        else if (strstr(DisassembledString, "POP SS") || strstr(DisassembledString, "MOV SS")) //prevent the 'PUSH SS', 'POP SS' step trick
        {
            ueCurrentPosition += StaticLengthDisassemble((void*)instr);
            SetBPX(ueCurrentPosition, UE_BREAKPOINT_TYPE_INT3 + UE_SINGLESHOOT, StepCallBack);
        }
        else
        {
            CONTEXT myDBGContext;
            HANDLE hActiveThread = EngineOpenThread(THREAD_GETSETSUSPEND, false, DBGEvent.dwThreadId);
            myDBGContext.ContextFlags = ContextControlFlags;
            GetThreadContext(hActiveThread, &myDBGContext);
            myDBGContext.EFlags |= UE_TRAP_FLAG;
            SetThreadContext(hActiveThread, &myDBGContext);
            EngineCloseHandle(hActiveThread);
            engineStepActive = true;
            engineStepCallBack = StepCallBack;
            engineStepCount = 0;
        }
    }
    LeaveCriticalSection(&engineStepActiveCr);
}

__declspec(dllexport) void TITCALL StepOver(LPVOID StepCallBack)
{
    ULONG_PTR ueCurrentPosition = GetContextData(UE_CIP);
    unsigned char instr[16];
    MemoryReadSafe(dbgProcessInformation.hProcess, (void*)ueCurrentPosition, instr, sizeof(instr), 0);
    char* DisassembledString = (char*)StaticDisassembleEx(ueCurrentPosition, (LPVOID)instr);
    if(strstr(DisassembledString, "CALL") || strstr(DisassembledString, "REP") || strstr(DisassembledString, "PUSHF"))
    {
        ueCurrentPosition += StaticLengthDisassemble((void*)instr);
        SetBPX(ueCurrentPosition, UE_BREAKPOINT_TYPE_INT3 + UE_SINGLESHOOT, StepCallBack);
    }
    else
        StepInto(StepCallBack);
}

__declspec(dllexport) void TITCALL StepOut(LPVOID StepOut, bool StepFinal)
{
    DebugStepFinal = StepFinal;
    StepOutCallBack = StepOut;
    StepOver(StepOutStepCallBack);
}

__declspec(dllexport) void TITCALL SingleStep(DWORD StepCount, LPVOID StepCallBack)
{
    StepInto(StepCallBack);
    engineStepCount = StepCount - 1; //We already stepped once
}

__declspec(dllexport) void TITCALL SetNextDbgContinueStatus(DWORD SetDbgCode)
{
    if(SetDbgCode != DBG_CONTINUE)
    {
        DBGCode = DBG_EXCEPTION_NOT_HANDLED;
    }
    else
    {
        DBGCode = DBG_CONTINUE;
    }
}
