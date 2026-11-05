#include "stdafx.h"
#include "definitions.h"
#include "Global.Debugger.h"
#include "Global.Handle.h"
#include "Global.Threader.h"
#include "Global.Librarian.h"
#include "Global.Engine.h"
#include "Global.Engine.Context.h"
#include <algorithm>

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
            EngineEventThread hActiveThread(THREAD_GETSETSUSPEND);
            myDBGContext.ContextFlags = ContextControlFlags;
            GetThreadContext(hActiveThread.get(), &myDBGContext);
            myDBGContext.EFlags |= UE_TRAP_FLAG;
            SetThreadContext(hActiveThread.get(), &myDBGContext);
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

// StepIntoThreads: calls (one per traced event) and, per thread, the call at which to check its trap
// flag again and the interval between the checks
static uint64_t stepThreadsCall = 0;
static std::unordered_map<DWORD, std::pair<uint64_t, uint32_t>> stepThreadsCheck;
// threads whose trap flag a check set again: their step may be pending (see StepCancelThreads)
static std::unordered_set<DWORD> stepThreadsRearmed;

// Arms a single-step with this callback on every thread of the debuggee that has none, so that the
// steps of all the threads are reported in the order the threads execute their instructions. A
// thread about to execute PUSHF, POP SS or MOV SS is left running (StepInto steps over these with a
// breakpoint) and is armed by a later call, as are the excluded threads.
__declspec(dllexport) void TITCALL StepIntoThreads(LPVOID StepCallBack, const DWORD* ExcludedThreads, DWORD ExcludedCount)
{
    EnterCriticalSection(&engineStepActiveCr);
    bool is32Bit = EngineGetCurrentContextMode() == EngineContextMode::X86;
    stepThreadsCall++;
    engineStepThreadsActive = true;
    stepThreadsRearmed.erase(DBGEvent.dwThreadId);
    for(auto & thread : hListThread)
    {
        if(thread.hThread == NULL || thread.hThread == INVALID_HANDLE_VALUE)
            continue;
        if(ExcludedThreads && std::find(ExcludedThreads, ExcludedThreads + ExcludedCount, thread.dwThreadId) != ExcludedThreads + ExcludedCount)
            continue;
        auto armed = engineStepThreads.find(thread.dwThreadId);
        if(armed != engineStepThreads.end())
        {
            auto & check = stepThreadsCheck[thread.dwThreadId];
            if(thread.dwThreadId == DBGEvent.dwThreadId || armed->second.callback != StepCallBack || check.second == 0)
            {
                check = { stepThreadsCall + 1, 1 };
                continue;
            }
            if(stepThreadsCall < check.first)
                continue;
            // A thread can lose its trap flag without reporting a step: NtContinue (start of a
            // thread, dispatch of an exception or an APC) and NtSetContextThread load a whole
            // context. Check it, less and less often while the thread stays silent (blocked).
            ULONG_PTR flags = GetContextDataEx(thread.hThread, UE_EFLAGS);
            if(flags & UE_TRAP_FLAG)
                check.second = check.second < 32 ? check.second * 2 : 64;
            else
            {
                // either the flag was lost, or the thread executed its instruction and its step
                // event is queued (the debug loop clears the flag again before its callback)
                SetContextDataEx(thread.hThread, UE_EFLAGS, flags | UE_TRAP_FLAG);
                stepThreadsRearmed.insert(thread.dwThreadId);
                check.second = 1;
            }
            check.first = stepThreadsCall + check.second;
            continue;
        }
        ULONG_PTR ip = GetContextDataEx(thread.hThread, UE_CIP);
        unsigned char instr[16];
        if(!ip || !MemoryReadSafe(dbgProcessInformation.hProcess, (void*)ip, instr, sizeof(instr), 0))
            continue;
        const char* DisassembledString = (const char*)EngineStaticDisassembleEx(ip, (LPVOID)instr, is32Bit);
        if(strstr(DisassembledString, "PUSHF") || strstr(DisassembledString, "POP SS") || strstr(DisassembledString, "MOV SS"))
            continue;
        ULONG_PTR flags = GetContextDataEx(thread.hThread, UE_EFLAGS);
        if(SetContextDataEx(thread.hThread, UE_EFLAGS, flags | UE_TRAP_FLAG))
        {
            // a queued step of a cancelled trace is now delivered to this callback
            engineStaleSteps.erase(thread.dwThreadId);
            engineStepThreads[thread.dwThreadId] = { StepCallBack, 0 };
            stepThreadsCheck[thread.dwThreadId] = { stepThreadsCall + 1, 1 };
        }
    }
    LeaveCriticalSection(&engineStepActiveCr);
}

// Cancels the single-steps armed with this callback on the threads other than the one of the
// current event. A thread whose trap flag is already consumed executed its instruction and its
// single-step event is pending: that event is swallowed when it arrives.
__declspec(dllexport) void TITCALL StepCancelThreads(LPVOID StepCallBack)
{
    EnterCriticalSection(&engineStepActiveCr);
    for(auto it = engineStepThreads.begin(); it != engineStepThreads.end();)
    {
        if(it->first == DBGEvent.dwThreadId || it->second.callback != StepCallBack)
        {
            ++it;
            continue;
        }
        HANDLE hThread = NULL;
        for(auto & thread : hListThread)
            if(thread.dwThreadId == it->first)
                hThread = thread.hThread;
        if(hThread != NULL && hThread != INVALID_HANDLE_VALUE)
        {
            ULONG_PTR flags = GetContextDataEx(hThread, UE_EFLAGS);
            if(flags & UE_TRAP_FLAG)
                SetContextDataEx(hThread, UE_EFLAGS, flags & ~UE_TRAP_FLAG);
            if(!(flags & UE_TRAP_FLAG) || stepThreadsRearmed.count(it->first))
                engineStaleSteps.insert(it->first);
        }
        it = engineStepThreads.erase(it);
    }
    stepThreadsCheck.clear();
    stepThreadsRearmed.clear();
    engineStepThreadsActive = false;
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
