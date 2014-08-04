#include "stdafx.h"
#include "definitions.h"
#include "Global.Debugger.h"
#include "Global.Engine.h"
#include "Global.Handle.h"
#include "Global.Engine.Threading.h"

__declspec(dllexport) bool TITCALL GetContextFPUDataEx(HANDLE hActiveThread, void* FPUSaveArea)
{
    if(FPUSaveArea)
    {
        CONTEXT DBGContext;
        memset(&DBGContext, 0, sizeof(CONTEXT));
        DBGContext.ContextFlags = CONTEXT_ALL;

        if(SuspendThread(hActiveThread) == (DWORD) - 1)
            return false;

        if(!GetThreadContext(hActiveThread, &DBGContext))
        {
            ResumeThread(hActiveThread);
            return false;
        }
        ResumeThread(hActiveThread);
#ifndef _WIN64
        memcpy(FPUSaveArea, &DBGContext.FloatSave, sizeof(FLOATING_SAVE_AREA));
#else
        memcpy(FPUSaveArea, &DBGContext.FltSave, sizeof(XMM_SAVE_AREA32));
#endif
        return true;
    }
    return false;
}

__declspec(dllexport) ULONG_PTR TITCALL GetContextDataEx(HANDLE hActiveThread, DWORD IndexOfRegister)
{
    ULONG_PTR retValue = 0;
    CONTEXT DBGContext;
    memset(&DBGContext, 0, sizeof(CONTEXT));
    DBGContext.ContextFlags = CONTEXT_ALL;

    if(SuspendThread(hActiveThread) == (DWORD) - 1)
        return retValue;

    if(!GetThreadContext(hActiveThread, &DBGContext))
    {
        ResumeThread(hActiveThread);
        return retValue;
    }
    ResumeThread(hActiveThread);

#ifdef _WIN64 //x64
    if(IndexOfRegister == UE_EAX)
    {
        retValue = DBGContext.Rax & 0xFFFFFFFF;
    }
    else if(IndexOfRegister == UE_EBX)
    {
        retValue = DBGContext.Rbx & 0xFFFFFFFF;
    }
    else if(IndexOfRegister == UE_ECX)
    {
        retValue = DBGContext.Rcx & 0xFFFFFFFF;
    }
    else if(IndexOfRegister == UE_EDX)
    {
        retValue = DBGContext.Rdx & 0xFFFFFFFF;
    }
    else if(IndexOfRegister == UE_EDI)
    {
        retValue = DBGContext.Rdi & 0xFFFFFFFF;
    }
    else if(IndexOfRegister == UE_ESI)
    {
        retValue = DBGContext.Rsi & 0xFFFFFFFF;
    }
    else if(IndexOfRegister == UE_EBP)
    {
        retValue = DBGContext.Rbp & 0xFFFFFFFF;
    }
    else if(IndexOfRegister == UE_ESP)
    {
        retValue = DBGContext.Rsp & 0xFFFFFFFF;
    }
    else if(IndexOfRegister == UE_EIP)
    {
        retValue = DBGContext.Rip & 0xFFFFFFFF;
    }
    else if(IndexOfRegister == UE_EFLAGS)
    {
        retValue = DBGContext.EFlags & 0xFFFFFFFF;
    }
    else if(IndexOfRegister == UE_RAX)
    {
        retValue = DBGContext.Rax;
    }
    else if(IndexOfRegister == UE_RBX)
    {
        retValue = DBGContext.Rbx;
    }
    else if(IndexOfRegister == UE_RCX)
    {
        retValue = DBGContext.Rcx;
    }
    else if(IndexOfRegister == UE_RDX)
    {
        retValue = DBGContext.Rdx;
    }
    else if(IndexOfRegister == UE_RDI)
    {
        retValue = DBGContext.Rdi;
    }
    else if(IndexOfRegister == UE_RSI)
    {
        retValue = DBGContext.Rsi;
    }
    else if(IndexOfRegister == UE_RBP)
    {
        retValue = DBGContext.Rbp;
    }
    else if(IndexOfRegister == UE_RSP)
    {
        retValue = DBGContext.Rsp;
    }
    else if(IndexOfRegister == UE_RIP)
    {
        retValue = DBGContext.Rip;
    }
    else if(IndexOfRegister == UE_RFLAGS)
    {
        retValue = DBGContext.EFlags;
    }
    else if(IndexOfRegister == UE_R8)
    {
        retValue = DBGContext.R8;
    }
    else if(IndexOfRegister == UE_R9)
    {
        retValue = DBGContext.R9;
    }
    else if(IndexOfRegister == UE_R10)
    {
        retValue = DBGContext.R10;
    }
    else if(IndexOfRegister == UE_R11)
    {
        retValue = DBGContext.R11;
    }
    else if(IndexOfRegister == UE_R12)
    {
        retValue = DBGContext.R12;
    }
    else if(IndexOfRegister == UE_R13)
    {
        retValue = DBGContext.R13;
    }
    else if(IndexOfRegister == UE_R14)
    {
        retValue = DBGContext.R14;
    }
    else if(IndexOfRegister == UE_R15)
    {
        retValue = DBGContext.R15;
    }
    else if(IndexOfRegister == UE_CIP)
    {
        retValue = DBGContext.Rip;
    }
    else if(IndexOfRegister == UE_CSP)
    {
        retValue = DBGContext.Rsp;
    }
#else //x86
    if(IndexOfRegister == UE_EAX)
    {
        retValue = DBGContext.Eax;
    }
    else if(IndexOfRegister == UE_EBX)
    {
        retValue = DBGContext.Ebx;
    }
    else if(IndexOfRegister == UE_ECX)
    {
        retValue = DBGContext.Ecx;
    }
    else if(IndexOfRegister == UE_EDX)
    {
        retValue = DBGContext.Edx;
    }
    else if(IndexOfRegister == UE_EDI)
    {
        retValue = DBGContext.Edi;
    }
    else if(IndexOfRegister == UE_ESI)
    {
        retValue = DBGContext.Esi;
    }
    else if(IndexOfRegister == UE_EBP)
    {
        retValue = DBGContext.Ebp;
    }
    else if(IndexOfRegister == UE_ESP)
    {
        retValue = DBGContext.Esp;
    }
    else if(IndexOfRegister == UE_EIP)
    {
        retValue = DBGContext.Eip;
    }
    else if(IndexOfRegister == UE_CIP)
    {
        retValue = DBGContext.Eip;
    }
    else if(IndexOfRegister == UE_CSP)
    {
        retValue = DBGContext.Esp;
    }
#endif
    else if(IndexOfRegister == UE_EFLAGS)
    {
        retValue = DBGContext.EFlags;
    }
    else if(IndexOfRegister == UE_DR0)
    {
        retValue = DBGContext.Dr0;
    }
    else if(IndexOfRegister == UE_DR1)
    {
        retValue = DBGContext.Dr1;
    }
    else if(IndexOfRegister == UE_DR2)
    {
        retValue = DBGContext.Dr2;
    }
    else if(IndexOfRegister == UE_DR3)
    {
        retValue = DBGContext.Dr3;
    }
    else if(IndexOfRegister == UE_DR6)
    {
        retValue = DBGContext.Dr6;
    }
    else if(IndexOfRegister == UE_DR7)
    {
        retValue = DBGContext.Dr7;
    }
    else if(IndexOfRegister == UE_SEG_GS)
    {
        retValue = DBGContext.SegGs;
    }
    else if(IndexOfRegister == UE_SEG_FS)
    {
        retValue = DBGContext.SegFs;
    }
    else if(IndexOfRegister == UE_SEG_ES)
    {
        retValue = DBGContext.SegEs;
    }
    else if(IndexOfRegister == UE_SEG_DS)
    {
        retValue = DBGContext.SegDs;
    }
    else if(IndexOfRegister == UE_SEG_CS)
    {
        retValue = DBGContext.SegCs;
    }
    else if(IndexOfRegister == UE_SEG_SS)
    {
        retValue = DBGContext.SegSs;
    }
    return retValue;
}

__declspec(dllexport) ULONG_PTR TITCALL GetContextData(DWORD IndexOfRegister)
{
    HANDLE hActiveThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, false, DBGEvent.dwThreadId);
    ULONG_PTR ContextReturn = GetContextDataEx(hActiveThread, IndexOfRegister);
    EngineCloseHandle(hActiveThread);
    return ContextReturn;
}

__declspec(dllexport) bool TITCALL SetContextFPUDataEx(HANDLE hActiveThread, void* FPUSaveArea)
{
    if(FPUSaveArea)
    {
        CONTEXT DBGContext;
        memset(&DBGContext, 0, sizeof(CONTEXT));
        DBGContext.ContextFlags = CONTEXT_ALL;

        if(SuspendThread(hActiveThread) == (DWORD) - 1)
            return false;

        if(!GetThreadContext(hActiveThread, &DBGContext))
        {
            ResumeThread(hActiveThread);
            return false;
        }
#ifndef _WIN64
        memcpy(&DBGContext.FloatSave, FPUSaveArea, sizeof(FLOATING_SAVE_AREA));
#else
        memcpy(&DBGContext.FltSave, FPUSaveArea, sizeof(XMM_SAVE_AREA32));
#endif
        if(SetThreadContext(hActiveThread, &DBGContext))
        {
            ResumeThread(hActiveThread);
            return true;
        }
        ResumeThread(hActiveThread);
    }
    return false;
}

__declspec(dllexport) bool TITCALL SetContextDataEx(HANDLE hActiveThread, DWORD IndexOfRegister, ULONG_PTR NewRegisterValue)
{
    CONTEXT DBGContext;
    memset(&DBGContext, 0, sizeof(CONTEXT));
    DBGContext.ContextFlags = CONTEXT_ALL;

    if(SuspendThread(hActiveThread) == (DWORD) - 1)
        return false;

    if(!GetThreadContext(hActiveThread, &DBGContext))
    {
        ResumeThread(hActiveThread);
        return false;
    }

#ifdef _WIN64 //x64
    if(IndexOfRegister == UE_EAX)
    {
        NewRegisterValue = DBGContext.Rax - (DWORD)DBGContext.Rax + NewRegisterValue;
        DBGContext.Rax = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_EBX)
    {
        NewRegisterValue = DBGContext.Rbx - (DWORD)DBGContext.Rbx + NewRegisterValue;
        DBGContext.Rbx = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_ECX)
    {
        NewRegisterValue = DBGContext.Rcx - (DWORD)DBGContext.Rcx + NewRegisterValue;
        DBGContext.Rcx = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_EDX)
    {
        NewRegisterValue = DBGContext.Rdx - (DWORD)DBGContext.Rdx + NewRegisterValue;
        DBGContext.Rdx = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_EDI)
    {
        NewRegisterValue = DBGContext.Rdi - (DWORD)DBGContext.Rdi + NewRegisterValue;
        DBGContext.Rdi = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_ESI)
    {
        NewRegisterValue = DBGContext.Rsi - (DWORD)DBGContext.Rsi + NewRegisterValue;
        DBGContext.Rsi = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_EBP)
    {
        NewRegisterValue = DBGContext.Rbp - (DWORD)DBGContext.Rbp + NewRegisterValue;
        DBGContext.Rbp = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_ESP)
    {
        NewRegisterValue = DBGContext.Rsp - (DWORD)DBGContext.Rsp + NewRegisterValue;
        DBGContext.Rsp = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_EIP)
    {
        NewRegisterValue = DBGContext.Rip - (DWORD)DBGContext.Rip + NewRegisterValue;
        DBGContext.Rip = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_EFLAGS)
    {
        DBGContext.EFlags = (DWORD)NewRegisterValue;
    }
    else if(IndexOfRegister == UE_RAX)
    {
        DBGContext.Rax = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_RBX)
    {
        DBGContext.Rbx = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_RCX)
    {
        DBGContext.Rcx = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_RDX)
    {
        DBGContext.Rdx = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_RDI)
    {
        DBGContext.Rdi = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_RSI)
    {
        DBGContext.Rsi = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_RBP)
    {
        DBGContext.Rbp = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_RSP)
    {
        DBGContext.Rsp = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_RIP)
    {
        DBGContext.Rip = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_RFLAGS)
    {
        DBGContext.EFlags = (DWORD)NewRegisterValue;
    }
    else if(IndexOfRegister == UE_R8)
    {
        DBGContext.R8 = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_R9)
    {
        DBGContext.R9 = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_R10)
    {
        DBGContext.R10 = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_R11)
    {
        DBGContext.R11 = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_R12)
    {
        DBGContext.R12 = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_R13)
    {
        DBGContext.R13 = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_R14)
    {
        DBGContext.R14 = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_R15)
    {
        DBGContext.R15 = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_CIP)
    {
        DBGContext.Rip = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_CSP)
    {
        DBGContext.Rsp = NewRegisterValue;
    }
#else //x86
    if(IndexOfRegister == UE_EAX)
    {
        DBGContext.Eax = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_EBX)
    {
        DBGContext.Ebx = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_ECX)
    {
        DBGContext.Ecx = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_EDX)
    {
        DBGContext.Edx = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_EDI)
    {
        DBGContext.Edi = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_ESI)
    {
        DBGContext.Esi = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_EBP)
    {
        DBGContext.Ebp = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_ESP)
    {
        DBGContext.Esp = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_EIP)
    {
        DBGContext.Eip = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_EFLAGS)
    {
        DBGContext.EFlags = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_CIP)
    {
        DBGContext.Eip = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_CSP)
    {
        DBGContext.Esp = NewRegisterValue;
    }
#endif
    else if(IndexOfRegister == UE_DR0)
    {
        DBGContext.Dr0 = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_DR1)
    {
        DBGContext.Dr1 = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_DR2)
    {
        DBGContext.Dr2 = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_DR3)
    {
        DBGContext.Dr3 = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_DR6)
    {
        DBGContext.Dr6 = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_DR7)
    {
        DBGContext.Dr7 = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_SEG_GS)
    {
        DBGContext.SegGs = (WORD)NewRegisterValue;
    }
    else if(IndexOfRegister == UE_SEG_FS)
    {
        DBGContext.SegFs = (WORD)NewRegisterValue;
    }
    else if(IndexOfRegister == UE_SEG_ES)
    {
        DBGContext.SegEs = (WORD)NewRegisterValue;
    }
    else if(IndexOfRegister == UE_SEG_DS)
    {
        DBGContext.SegDs = (WORD)NewRegisterValue;
    }
    else if(IndexOfRegister == UE_SEG_CS)
    {
        DBGContext.SegCs = (WORD)NewRegisterValue;
    }
    else if(IndexOfRegister == UE_SEG_SS)
    {
        DBGContext.SegSs = (WORD)NewRegisterValue;
    }
    else
    {
        ResumeThread(hActiveThread);
        return false;
    }

    if(SetThreadContext(hActiveThread, &DBGContext))
    {
        ResumeThread(hActiveThread);
        return true;
    }

    ResumeThread(hActiveThread);
    return false;
}

__declspec(dllexport) bool TITCALL SetContextData(DWORD IndexOfRegister, ULONG_PTR NewRegisterValue)
{
    HANDLE hActiveThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | THREAD_GET_CONTEXT, false, DBGEvent.dwThreadId);
    bool ContextReturn = SetContextDataEx(hActiveThread, IndexOfRegister, NewRegisterValue);
    EngineCloseHandle(hActiveThread);
    return ContextReturn;
}
