#include "stdafx.h"
#include "definitions.h"
#include "Global.Debugger.h"
#include "Global.Engine.h"
#include "Global.Handle.h"
#include "Global.Engine.Threading.h"

static CONTEXT DBGContext = {};

__declspec(dllexport) bool TITCALL GetContextFPUDataEx(HANDLE hActiveThread, void* FPUSaveArea)
{
    MutexLocker locker("DBGContext"); //lock DBGContext
    if(FPUSaveArea)
    {
        RtlZeroMemory(&DBGContext, sizeof CONTEXT);
        DBGContext.ContextFlags = CONTEXT_ALL;
        if(!GetThreadContext(hActiveThread, &DBGContext))
            return false;
#ifndef _WIN64
        RtlMoveMemory(FPUSaveArea, &DBGContext.FloatSave, sizeof FLOATING_SAVE_AREA);
#else
        RtlMoveMemory(FPUSaveArea, &DBGContext.FltSave, sizeof XMM_SAVE_AREA32);
#endif
        return true;
    }
    return false;
}

__declspec(dllexport) long long TITCALL GetContextDataEx(HANDLE hActiveThread, DWORD IndexOfRegister)
{
    MutexLocker locker("DBGContext"); //lock DBGContext
    RtlZeroMemory(&DBGContext, sizeof CONTEXT);
    DBGContext.ContextFlags = CONTEXT_ALL;
    GetThreadContext(hActiveThread, &DBGContext);
#ifdef _WIN64
    if(IndexOfRegister == UE_EAX)
    {
        return((DWORD)DBGContext.Rax);
    }
    else if(IndexOfRegister == UE_EBX)
    {
        return((DWORD)DBGContext.Rbx);
    }
    else if(IndexOfRegister == UE_ECX)
    {
        return((DWORD)DBGContext.Rcx);
    }
    else if(IndexOfRegister == UE_EDX)
    {
        return((DWORD)DBGContext.Rdx);
    }
    else if(IndexOfRegister == UE_EDI)
    {
        return((DWORD)DBGContext.Rdi);
    }
    else if(IndexOfRegister == UE_ESI)
    {
        return((DWORD)DBGContext.Rsi);
    }
    else if(IndexOfRegister == UE_EBP)
    {
        return((DWORD)DBGContext.Rbp);
    }
    else if(IndexOfRegister == UE_ESP)
    {
        return((DWORD)DBGContext.Rsp);
    }
    else if(IndexOfRegister == UE_EIP)
    {
        return((DWORD)DBGContext.Rip);
    }
    else if(IndexOfRegister == UE_EFLAGS)
    {
        return((DWORD)DBGContext.EFlags);
    }
    else if(IndexOfRegister == UE_RAX)
    {
        return(DBGContext.Rax);
    }
    else if(IndexOfRegister == UE_RBX)
    {
        return(DBGContext.Rbx);
    }
    else if(IndexOfRegister == UE_RCX)
    {
        return(DBGContext.Rcx);
    }
    else if(IndexOfRegister == UE_RDX)
    {
        return(DBGContext.Rdx);
    }
    else if(IndexOfRegister == UE_RDI)
    {
        return(DBGContext.Rdi);
    }
    else if(IndexOfRegister == UE_RSI)
    {
        return(DBGContext.Rsi);
    }
    else if(IndexOfRegister == UE_RBP)
    {
        return(DBGContext.Rbp);
    }
    else if(IndexOfRegister == UE_RSP)
    {
        return(DBGContext.Rsp);
    }
    else if(IndexOfRegister == UE_RIP)
    {
        return(DBGContext.Rip);
    }
    else if(IndexOfRegister == UE_RFLAGS)
    {
        return(DBGContext.EFlags);
    }
    else if(IndexOfRegister == UE_DR0)
    {
        return(DBGContext.Dr0);
    }
    else if(IndexOfRegister == UE_DR1)
    {
        return(DBGContext.Dr1);
    }
    else if(IndexOfRegister == UE_DR2)
    {
        return(DBGContext.Dr2);
    }
    else if(IndexOfRegister == UE_DR3)
    {
        return(DBGContext.Dr3);
    }
    else if(IndexOfRegister == UE_DR6)
    {
        return(DBGContext.Dr6);
    }
    else if(IndexOfRegister == UE_DR7)
    {
        return(DBGContext.Dr7);
    }
    else if(IndexOfRegister == UE_R8)
    {
        return(DBGContext.R8);
    }
    else if(IndexOfRegister == UE_R9)
    {
        return(DBGContext.R9);
    }
    else if(IndexOfRegister == UE_R10)
    {
        return(DBGContext.R10);
    }
    else if(IndexOfRegister == UE_R11)
    {
        return(DBGContext.R11);
    }
    else if(IndexOfRegister == UE_R12)
    {
        return(DBGContext.R12);
    }
    else if(IndexOfRegister == UE_R13)
    {
        return(DBGContext.R13);
    }
    else if(IndexOfRegister == UE_R14)
    {
        return(DBGContext.R14);
    }
    else if(IndexOfRegister == UE_R15)
    {
        return(DBGContext.R15);
    }
    else if(IndexOfRegister == UE_CIP)
    {
        return(DBGContext.Rip);
    }
    else if(IndexOfRegister == UE_CSP)
    {
        return(DBGContext.Rsp);
    }
    else if(IndexOfRegister == UE_SEG_GS)
    {
        return(DBGContext.SegGs);
    }
    else if(IndexOfRegister == UE_SEG_FS)
    {
        return(DBGContext.SegFs);
    }
    else if(IndexOfRegister == UE_SEG_ES)
    {
        return(DBGContext.SegEs);
    }
    else if(IndexOfRegister == UE_SEG_DS)
    {
        return(DBGContext.SegDs);
    }
    else if(IndexOfRegister == UE_SEG_CS)
    {
        return(DBGContext.SegCs);
    }
    else if(IndexOfRegister == UE_SEG_SS)
    {
        return(DBGContext.SegSs);
    }
#else
    if(IndexOfRegister == UE_EAX)
    {
        return(DBGContext.Eax);
    }
    else if(IndexOfRegister == UE_EBX)
    {
        return(DBGContext.Ebx);
    }
    else if(IndexOfRegister == UE_ECX)
    {
        return(DBGContext.Ecx);
    }
    else if(IndexOfRegister == UE_EDX)
    {
        return(DBGContext.Edx);
    }
    else if(IndexOfRegister == UE_EDI)
    {
        return(DBGContext.Edi);
    }
    else if(IndexOfRegister == UE_ESI)
    {
        return(DBGContext.Esi);
    }
    else if(IndexOfRegister == UE_EBP)
    {
        return(DBGContext.Ebp);
    }
    else if(IndexOfRegister == UE_ESP)
    {
        return(DBGContext.Esp);
    }
    else if(IndexOfRegister == UE_EIP)
    {
        return(DBGContext.Eip);
    }
    else if(IndexOfRegister == UE_EFLAGS)
    {
        return(DBGContext.EFlags);
    }
    else if(IndexOfRegister == UE_DR0)
    {
        return(DBGContext.Dr0);
    }
    else if(IndexOfRegister == UE_DR1)
    {
        return(DBGContext.Dr1);
    }
    else if(IndexOfRegister == UE_DR2)
    {
        return(DBGContext.Dr2);
    }
    else if(IndexOfRegister == UE_DR3)
    {
        return(DBGContext.Dr3);
    }
    else if(IndexOfRegister == UE_DR6)
    {
        return(DBGContext.Dr6);
    }
    else if(IndexOfRegister == UE_DR7)
    {
        return(DBGContext.Dr7);
    }
    else if(IndexOfRegister == UE_CIP)
    {
        return(DBGContext.Eip);
    }
    else if(IndexOfRegister == UE_CSP)
    {
        return(DBGContext.Esp);
    }
    else if(IndexOfRegister == UE_SEG_GS)
    {
        return(DBGContext.SegGs);
    }
    else if(IndexOfRegister == UE_SEG_FS)
    {
        return(DBGContext.SegFs);
    }
    else if(IndexOfRegister == UE_SEG_ES)
    {
        return(DBGContext.SegEs);
    }
    else if(IndexOfRegister == UE_SEG_DS)
    {
        return(DBGContext.SegDs);
    }
    else if(IndexOfRegister == UE_SEG_CS)
    {
        return(DBGContext.SegCs);
    }
    else if(IndexOfRegister == UE_SEG_SS)
    {
        return(DBGContext.SegSs);
    }
#endif
    return NULL;
}

__declspec(dllexport) long long TITCALL GetContextData(DWORD IndexOfRegister)
{
    MutexLocker locker("DBGContext"); //lock DBGContext
    HANDLE hActiveThread = OpenThread(THREAD_GET_CONTEXT, false, DBGEvent.dwThreadId);
    long long ContextReturn = GetContextDataEx(hActiveThread, IndexOfRegister);
    EngineCloseHandle(hActiveThread);
    return(ContextReturn);
}

__declspec(dllexport) bool TITCALL SetContextFPUDataEx(HANDLE hActiveThread, void* FPUSaveArea)
{
    MutexLocker locker("DBGContext"); //lock DBGContext
    if(FPUSaveArea)
    {
        RtlZeroMemory(&DBGContext, sizeof CONTEXT);
        DBGContext.ContextFlags = CONTEXT_ALL;
        if(!GetThreadContext(hActiveThread, &DBGContext))
            return(false);
#ifndef _WIN64
        RtlMoveMemory(&DBGContext.FloatSave, FPUSaveArea, sizeof FLOATING_SAVE_AREA);
#else
        RtlMoveMemory(&DBGContext.FltSave, FPUSaveArea, sizeof XMM_SAVE_AREA32);
#endif
        if(SetThreadContext(hActiveThread, &DBGContext))
            return true;
    }
    return false;
}

__declspec(dllexport) bool TITCALL SetContextDataEx(HANDLE hActiveThread, DWORD IndexOfRegister, ULONG_PTR NewRegisterValue)
{
    MutexLocker locker("DBGContext"); //lock DBGContext
    RtlZeroMemory(&DBGContext, sizeof CONTEXT);
    DBGContext.ContextFlags = CONTEXT_ALL;
    if(!GetThreadContext(hActiveThread, &DBGContext))
        return false;
    SuspendThread(hActiveThread);
#ifdef _WIN64
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
#else
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
    else if(IndexOfRegister == UE_CIP)
    {
        DBGContext.Eip = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_CSP)
    {
        DBGContext.Esp = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_SEG_GS)
    {
        DBGContext.SegGs = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_SEG_FS)
    {
        DBGContext.SegFs = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_SEG_ES)
    {
        DBGContext.SegEs = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_SEG_DS)
    {
        DBGContext.SegDs = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_SEG_CS)
    {
        DBGContext.SegCs = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_SEG_SS)
    {
        DBGContext.SegSs = NewRegisterValue;
    }
#endif
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
    MutexLocker locker("DBGContext"); //lock DBGContext
    HANDLE hActiveThread = OpenThread(THREAD_SUSPEND_RESUME|THREAD_SET_CONTEXT|THREAD_GET_CONTEXT, false, DBGEvent.dwThreadId);
    bool ContextReturn = SetContextDataEx(hActiveThread, IndexOfRegister, NewRegisterValue);
    EngineCloseHandle(hActiveThread);
    return(ContextReturn);
}