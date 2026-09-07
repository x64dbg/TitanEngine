#include "stdafx.h"
#include "definitions.h"
#include "Global.Debugger.h"
#include "Global.Handle.h"
#include "Global.Threader.h"
#include "Global.Librarian.h"
#include "Global.Engine.h"
#include "Global.Engine.Context.h"

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
    RtlZeroMemory(&dbgProcessInformation, sizeof(PROCESS_INFORMATION));
    if(DebugDebuggingDLL)
        DeleteFileW(szDebuggerName);
    DebugDebuggingDLL = false;
    DebugExeFileEntryPointCallBack = NULL;
}

__declspec(dllexport) void TITCALL StepInto(LPVOID StepCallBack)
{
#ifndef _WIN64
    // A WOW64 transition through `ljmp 33h` cannot be completed reliably with
    // the x86 trap flag. Treat the return address already on the x86 stack as
    // an engine-owned one-shot step target instead. The frontend only requests
    // StepInto and does not need to know which execution mechanism is used.
    if(engineWow64SingleStepWorkaround)
    {
        unsigned char data[7] = {};
        auto cip = GetContextData(UE_CIP);
        if(MemoryReadSafe(dbgProcessInformation.hProcess, (void*)cip, data, sizeof(data), nullptr) &&
                data[0] == 0xEA && data[5] == 0x33 && data[6] == 0x00)
        {
            ULONG_PTR returnAddress = 0;
            auto csp = GetContextData(UE_CSP);
            if(MemoryReadSafe(dbgProcessInformation.hProcess, (void*)csp, &returnAddress,
                              sizeof(returnAddress), nullptr) &&
                    SetBPX(returnAddress, UE_SINGLESHOOT, StepCallBack))
                return;
        }
    }
#endif
    EnterCriticalSection(&engineStepActiveCr);
    // Arm a single-step for the current event thread only. State is per-thread, so a
    // step already pending on another thread does not block this one.
    if(engineStepThreads.find(DBGEvent.dwThreadId) == engineStepThreads.end())
    {
        ULONG_PTR ueCurrentPosition = GetContextData(UE_CIP);
        bool is32Bit = EngineGetCurrentContextMode() == EngineContextMode::X86;
        unsigned char instr[16];
        MemoryReadSafe(dbgProcessInformation.hProcess, (void*)ueCurrentPosition, instr, sizeof(instr), 0);
        char* DisassembledString = (char*)EngineStaticDisassembleEx(ueCurrentPosition, (LPVOID)instr, is32Bit);
        if(strstr(DisassembledString, "PUSHF"))
            StepOver(StepCallBack);
        else if(strstr(DisassembledString, "POP SS") || strstr(DisassembledString, "MOV SS"))  //prevent the 'PUSH SS', 'POP SS' step trick
        {
            ueCurrentPosition += EngineStaticLengthDisassemble((void*)instr, is32Bit);
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
            engineStepThreads[DBGEvent.dwThreadId] = { StepCallBack, 0 };
        }
    }
    LeaveCriticalSection(&engineStepActiveCr);
}

__declspec(dllexport) void TITCALL StepOver(LPVOID StepCallBack)
{
    ULONG_PTR ueCurrentPosition = GetContextData(UE_CIP);
    bool is32Bit = EngineGetCurrentContextMode() == EngineContextMode::X86;
    unsigned char instr[16];
    MemoryReadSafe(dbgProcessInformation.hProcess, (void*)ueCurrentPosition, instr, sizeof(instr), 0);
    char* DisassembledString = (char*)EngineStaticDisassembleEx(ueCurrentPosition, (LPVOID)instr, is32Bit);
    if(strstr(DisassembledString, "CALL") || strstr(DisassembledString, "REP") || strstr(DisassembledString, "PUSHF"))
    {
        ueCurrentPosition += EngineStaticLengthDisassemble((void*)instr, is32Bit);
        SetBPX(ueCurrentPosition, UE_BREAKPOINT_TYPE_INT3 + UE_SINGLESHOOT, StepCallBack);
    }
    else
        StepInto(StepCallBack);
}

__declspec(dllexport) void TITCALL StepOut(LPVOID StepOut, bool StepFinal)
{
    DebugStepFinal = StepFinal;
    StepOutCallBack = StepOut;
    StepOver(CallbackToObjectPointer(&StepOutStepCallBack));
}

__declspec(dllexport) void TITCALL SingleStep(DWORD StepCount, LPVOID StepCallBack)
{
    StepInto(StepCallBack);
    EnterCriticalSection(&engineStepActiveCr);
    auto it = engineStepThreads.find(DBGEvent.dwThreadId);
    if(it != engineStepThreads.end())
        it->second.count = StepCount - 1; //We already stepped once
    LeaveCriticalSection(&engineStepActiveCr);
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
