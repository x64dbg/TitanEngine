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
        DBGContext.ContextFlags = CONTEXT_ALL | CONTEXT_FLOATING_POINT;

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

__declspec(dllexport) bool TITCALL GetFullContextDataEx(HANDLE hActiveThread, TITAN_ENGINE_CONTEXT_t* titcontext)
{
    ULONG_PTR retValue = 0;
    CONTEXT DBGContext;
    memset(&DBGContext, 0, sizeof(CONTEXT));
    DBGContext.ContextFlags = CONTEXT_ALL | CONTEXT_FLOATING_POINT | CONTEXT_EXTENDED_REGISTERS;
    int i;

    if(SuspendThread(hActiveThread) == (DWORD) - 1)
        return false;

    if(!GetThreadContext(hActiveThread, &DBGContext))
    {
        ResumeThread(hActiveThread);
        return false;
    }
    ResumeThread(hActiveThread);

    titcontext->eflags = DBGContext.EFlags;
    titcontext->dr0 = DBGContext.Dr0;
    titcontext->dr1 = DBGContext.Dr1;
    titcontext->dr2 = DBGContext.Dr2;
    titcontext->dr3 = DBGContext.Dr3;
    titcontext->dr6 = DBGContext.Dr6;
    titcontext->dr7 = DBGContext.Dr7;
    titcontext->gs = (unsigned short) DBGContext.SegGs;
    titcontext->fs = (unsigned short) DBGContext.SegFs;
    titcontext->es = (unsigned short) DBGContext.SegEs;
    titcontext->ds = (unsigned short) DBGContext.SegDs;
    titcontext->cs = (unsigned short) DBGContext.SegCs;
    titcontext->ss = (unsigned short) DBGContext.SegSs;

#ifdef _WIN64 //x64
    titcontext->cax = DBGContext.Rax;
    titcontext->cbx = DBGContext.Rbx;
    titcontext->ccx = DBGContext.Rcx;
    titcontext->cdx = DBGContext.Rdx;
    titcontext->cdi = DBGContext.Rdi;
    titcontext->csi = DBGContext.Rsi;
    titcontext->cbp = DBGContext.Rbp;
    titcontext->csp = DBGContext.Rsp;
    titcontext->cip = DBGContext.Rip;
    titcontext->r8 = DBGContext.R8;
    titcontext->r9 = DBGContext.R9;
    titcontext->r10 = DBGContext.R10;
    titcontext->r11 = DBGContext.R11;
    titcontext->r12 = DBGContext.R12;
    titcontext->r13 = DBGContext.R13;
    titcontext->r14 = DBGContext.R14;
    titcontext->r15 = DBGContext.R15;

    titcontext->x87fpu.ControlWord = DBGContext.FltSave.ControlWord;
    titcontext->x87fpu.StatusWord = DBGContext.FltSave.StatusWord;
    titcontext->x87fpu.TagWord = DBGContext.FltSave.TagWord;
    titcontext->x87fpu.ErrorSelector = DBGContext.FltSave.ErrorSelector;
    titcontext->x87fpu.ErrorOffset = DBGContext.FltSave.ErrorOffset;
    titcontext->x87fpu.DataSelector = DBGContext.FltSave.DataSelector;
    titcontext->x87fpu.DataOffset = DBGContext.FltSave.DataOffset;
    // Skip titcontext->x87fpu.Cr0NpxState
    titcontext->MxCsr = DBGContext.FltSave.MxCsr;

    for(i = 0; i < 8; i++)
        memcpy(&(titcontext->RegisterArea[i * 10]), & DBGContext.FltSave.FloatRegisters[i], 10);

    for(i = 0; i < 16; i++)
        memcpy(& (titcontext->XmmRegisters[i]), & (DBGContext.FltSave.XmmRegisters[i]), sizeof(*titcontext->XmmRegisters));

#else //x86
    titcontext->cax = DBGContext.Eax;
    titcontext->cbx = DBGContext.Ebx;
    titcontext->ccx = DBGContext.Ecx;
    titcontext->cdx = DBGContext.Edx;
    titcontext->cdi = DBGContext.Edi;
    titcontext->csi = DBGContext.Esi;
    titcontext->cbp = DBGContext.Ebp;
    titcontext->csp = DBGContext.Esp;
    titcontext->cip = DBGContext.Eip;

    titcontext->x87fpu.ControlWord = DBGContext.FloatSave.ControlWord;
    titcontext->x87fpu.StatusWord = DBGContext.FloatSave.StatusWord;
    titcontext->x87fpu.TagWord = DBGContext.FloatSave.TagWord;
    titcontext->x87fpu.ErrorSelector = DBGContext.FloatSave.ErrorSelector;
    titcontext->x87fpu.ErrorOffset = DBGContext.FloatSave.ErrorOffset;
    titcontext->x87fpu.DataSelector = DBGContext.FloatSave.DataSelector;
    titcontext->x87fpu.DataOffset = DBGContext.FloatSave.DataOffset;
    titcontext->x87fpu.Cr0NpxState = DBGContext.FloatSave.Cr0NpxState;

    memcpy(titcontext->RegisterArea, DBGContext.FloatSave.RegisterArea, 80);

    // MXCSR ExtendedRegisters[24]
    titcontext->MxCsr = DBGContext.ExtendedRegisters[24];

    // for x86 copy the 8 Xmm Registers from ExtendedRegisters[(10+n)*16]; (n is the index of the xmm register) to the XMM register
    for(i = 0; i < 8; i++)
        memcpy(& (titcontext->XmmRegisters[i]),  & DBGContext.ExtendedRegisters[(10 + i) * 16], sizeof(*titcontext->XmmRegisters));
#endif

#define GetSTInTOPStackFromStatusWord(StatusWord) ((StatusWord & 0x3800) >> 11)
#define Getx87r0PositionInRegisterArea(STInTopStack) ((8 - STInTopStack) % 8)
#define Calculatex87registerPositionInRegisterArea(x87r0_position, index) (((x87r0_position + index) % 8))
#define GetRegisterAreaOf87register(register_area, x87r0_position, index) (((char *) register_area) + 10 * Calculatex87registerPositionInRegisterArea(x87r0_position, i) )
#define GetSTValueFromIndex(x87r0_position, index) ((x87r0_position + index) % 8)

    int STInTopStack = GetSTInTOPStackFromStatusWord(titcontext->x87fpu.StatusWord);
    DWORD x87r0_position = Getx87r0PositionInRegisterArea(STInTopStack);
    for(i = 0; i < 8; i++)
        titcontext->mmx[i] = * ((int64_t*) GetRegisterAreaOf87register(titcontext->RegisterArea, x87r0_position, i));


    /*
    GET Actual TOP register from StatusWord to order the FPUx87registers like in the FPU internal order.
    The TOP field (bits 13-11) is where the FPU keeps track of which of its 80-bit registers is at the TOP.
    The register number for the FPU's internal numbering system of the 80-bit registers would be displayed in that field.
    When the programmer specifies one of the FPU 80-bit registers ST(x) in an instruction, the FPU adds (modulo 8) the ST number
    supplied to the value in this TOP field to determine in which of its registers the required data is located.
    */
    /*
    int STInTopStack = GetSTInTOPStackFromStatusWord(titcontext->x87fpu.StatusWord);
    DWORD x87r0_position = Getx87r0PositionInRegisterArea(STInTopStack);
    */
    for(i = 0; i < 8; i++)
    {
        memcpy(titcontext->x87fpu.x87FPURegister[i].data, GetRegisterAreaOf87register(titcontext->RegisterArea, x87r0_position, i), 10);
        titcontext->x87fpu.x87FPURegister[i].st_value = GetSTValueFromIndex(x87r0_position, i);
    }

    return true;
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
        DBGContext.ContextFlags = CONTEXT_ALL | CONTEXT_FLOATING_POINT;

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
