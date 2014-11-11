#include "stdafx.h"
#include "definitions.h"
#include "Global.Debugger.h"
#include "Global.Engine.h"
#include "Global.Handle.h"
#include "Global.Engine.Threading.h"

__declspec(dllexport) void TITCALL GetMMXRegisters(uint64_t mmx[8], TITAN_ENGINE_CONTEXT_t* titcontext)
{
    int STInTopStack = GetSTInTOPStackFromStatusWord(titcontext->x87fpu.StatusWord);
    DWORD x87r0_position = Getx87r0PositionInRegisterArea(STInTopStack);
    int i;

    for(i = 0; i < 8; i++)
        mmx[i] = * ((uint64_t*) GetRegisterAreaOf87register(titcontext->RegisterArea, x87r0_position, i));
}

__declspec(dllexport) void TITCALL Getx87FPURegisters(x87FPURegister_t x87FPURegisters[8], TITAN_ENGINE_CONTEXT_t* titcontext)
{

    /*
    GET Actual TOP register from StatusWord to order the FPUx87registers like in the FPU internal order.
    The TOP field (bits 13-11) is where the FPU keeps track of which of its 80-bit registers is at the TOP.
    The register number for the FPU's internal numbering system of the 80-bit registers would be displayed in that field.
    When the programmer specifies one of the FPU 80-bit registers ST(x) in an instruction, the FPU adds (modulo 8) the ST number
    supplied to the value in this TOP field to determine in which of its registers the required data is located.
    */

    int STInTopStack = GetSTInTOPStackFromStatusWord(titcontext->x87fpu.StatusWord);
    DWORD x87r0_position = Getx87r0PositionInRegisterArea(STInTopStack);
    int i;

    for(i = 0; i < 8; i++)
    {
        memcpy(x87FPURegisters[i].data, GetRegisterAreaOf87register(titcontext->RegisterArea, x87r0_position, i), 10);
        x87FPURegisters[i].st_value = GetSTValueFromIndex(x87r0_position, i);
        x87FPURegisters[i].tag = (int)((titcontext->x87fpu.TagWord >> (i * 2)) & 0x3);
    }
}

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


__declspec(dllexport) bool TITCALL _SetFullContextDataEx(HANDLE hActiveThread, TITAN_ENGINE_CONTEXT_t* titcontext)
{
    CONTEXT DBGContext;
    int i;

    memset(&DBGContext, 0, sizeof(DBGContext));

    DBGContext.ContextFlags = CONTEXT_ALL | CONTEXT_FLOATING_POINT | CONTEXT_EXTENDED_REGISTERS;

    if(!GetThreadContext(hActiveThread, &DBGContext))
    {
        ResumeThread(hActiveThread);
        return false;
    }

    DBGContext.EFlags = titcontext->eflags;
    DBGContext.Dr0 = titcontext->dr0;
    DBGContext.Dr1 = titcontext->dr1;
    DBGContext.Dr2 = titcontext->dr2;
    DBGContext.Dr3 = titcontext->dr3;
    DBGContext.Dr6 = titcontext->dr6;
    DBGContext.Dr7 = titcontext->dr7;
    DBGContext.SegGs = titcontext->gs;
    DBGContext.SegFs = titcontext->fs;
    DBGContext.SegEs = titcontext->es;
    DBGContext.SegDs = titcontext->ds;
    DBGContext.SegCs = titcontext->cs;
    DBGContext.SegSs = titcontext->ss;

#ifdef _WIN64 //x64
    DBGContext.Rax = titcontext->cax;
    DBGContext.Rbx = titcontext->cbx;
    DBGContext.Rcx = titcontext->ccx;
    DBGContext.Rdx = titcontext->cdx;
    DBGContext.Rdi = titcontext->cdi;
    DBGContext.Rsi = titcontext->csi;
    DBGContext.Rbp = titcontext->cbp;
    DBGContext.Rsp = titcontext->csp;
    DBGContext.Rip = titcontext->cip;
    DBGContext.R8 = titcontext->r8;
    DBGContext.R9 = titcontext->r9;
    DBGContext.R10 = titcontext->r10;
    DBGContext.R11 = titcontext->r11;
    DBGContext.R12 = titcontext->r12;
    DBGContext.R13 = titcontext->r13;
    DBGContext.R14 = titcontext->r14;
    DBGContext.R15 = titcontext->r15;

    DBGContext.FltSave.ControlWord = titcontext->x87fpu.ControlWord;
    DBGContext.FltSave.StatusWord = titcontext->x87fpu.StatusWord;
    memcpy(& (DBGContext.FltSave.TagWord), & (titcontext->x87fpu.TagWord), sizeof(titcontext->x87fpu.TagWord));
#ifdef _WIN64
#define WIN64_CASTDWORDTOWORD (WORD)
#else
#define WIN64_CASTDWORDTOWORD (DWORD)
#endif
    DBGContext.FltSave.ErrorSelector = WIN64_CASTDWORDTOWORD titcontext->x87fpu.ErrorSelector;
    DBGContext.FltSave.ErrorOffset = titcontext->x87fpu.ErrorOffset;
    DBGContext.FltSave.DataSelector = WIN64_CASTDWORDTOWORD titcontext->x87fpu.DataSelector;
    DBGContext.FltSave.DataOffset = titcontext->x87fpu.DataOffset;
    // Skip titcontext->x87fpu.Cr0NpxState
    DBGContext.FltSave.MxCsr = titcontext->MxCsr;

    for(i = 0; i < 8; i++)
        memcpy(& DBGContext.FltSave.FloatRegisters[i], &(titcontext->RegisterArea[i * 10]), 10);

    for(i = 0; i < 16; i++)
        memcpy(& (DBGContext.FltSave.XmmRegisters[i]), & (titcontext->XmmRegisters[i]), 16);

#else //x86
    DBGContext.Eax = titcontext->cax;
    DBGContext.Ebx = titcontext->cbx;
    DBGContext.Ecx = titcontext->ccx;
    DBGContext.Edx = titcontext->cdx;
    DBGContext.Edi = titcontext->cdi;
    DBGContext.Esi = titcontext->csi;
    DBGContext.Ebp = titcontext->cbp;
    DBGContext.Esp = titcontext->csp;
    DBGContext.Eip = titcontext->cip;

    DBGContext.FloatSave.ControlWord = titcontext->x87fpu.ControlWord;
    DBGContext.FloatSave.StatusWord = titcontext->x87fpu.StatusWord;
    DBGContext.FloatSave.TagWord = titcontext->x87fpu.TagWord;
    DBGContext.FloatSave.ErrorSelector = titcontext->x87fpu.ErrorSelector;
    DBGContext.FloatSave.ErrorOffset = titcontext->x87fpu.ErrorOffset;
    DBGContext.FloatSave.DataSelector = titcontext->x87fpu.DataSelector;
    DBGContext.FloatSave.DataOffset = titcontext->x87fpu.DataOffset;
    DBGContext.FloatSave.Cr0NpxState = titcontext->x87fpu.Cr0NpxState;

    memcpy(DBGContext.FloatSave.RegisterArea, titcontext->RegisterArea, 80);

    // MXCSR ExtendedRegisters[24]
    memcpy(& (DBGContext.ExtendedRegisters[24]), & titcontext->MxCsr, sizeof(titcontext->MxCsr));

    // for x86 copy the 8 Xmm Registers from ExtendedRegisters[(10+n)*16]; (n is the index of the xmm register) to the XMM register
    for(i = 0; i < 8; i++)
        memcpy(& DBGContext.ExtendedRegisters[(10 + i) * 16], &(titcontext->XmmRegisters[i]), 16);
#endif

    return SetThreadContext(hActiveThread, & DBGContext) ? true : false;
}

__declspec(dllexport) bool TITCALL SetFullContextDataEx(HANDLE hActiveThread, TITAN_ENGINE_CONTEXT_t* titcontext)
{
    bool returnf;

    if(SuspendThread(hActiveThread) == (DWORD) - 1)
        return false;

    returnf = _SetFullContextDataEx(hActiveThread, titcontext);

    ResumeThread(hActiveThread);

    return returnf;
}

__declspec(dllexport) bool TITCALL _GetFullContextDataEx(HANDLE hActiveThread, TITAN_ENGINE_CONTEXT_t* titcontext)
{
    CONTEXT DBGContext;
    int i;

    memset(&DBGContext, 0, sizeof(CONTEXT));

    DBGContext.ContextFlags = CONTEXT_ALL | CONTEXT_FLOATING_POINT | CONTEXT_EXTENDED_REGISTERS;

    if(!GetThreadContext(hActiveThread, &DBGContext))
        return false;

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
    memcpy(& (titcontext->x87fpu.TagWord), & (DBGContext.FltSave.TagWord), sizeof(titcontext->x87fpu.TagWord));
    titcontext->x87fpu.ErrorSelector = DBGContext.FltSave.ErrorSelector;
    titcontext->x87fpu.ErrorOffset = DBGContext.FltSave.ErrorOffset;
    titcontext->x87fpu.DataSelector = DBGContext.FltSave.DataSelector;
    titcontext->x87fpu.DataOffset = DBGContext.FltSave.DataOffset;
    // Skip titcontext->x87fpu.Cr0NpxState
    titcontext->MxCsr = DBGContext.FltSave.MxCsr;

    for(i = 0; i < 8; i++)
        memcpy(&(titcontext->RegisterArea[i * 10]), & DBGContext.FltSave.FloatRegisters[i], 10);

    for(i = 0; i < 16; i++)
        memcpy(& (titcontext->XmmRegisters[i]), & (DBGContext.FltSave.XmmRegisters[i]), 16);

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

    titcontext->x87fpu.ControlWord = (WORD) DBGContext.FloatSave.ControlWord;
    titcontext->x87fpu.StatusWord = (WORD) DBGContext.FloatSave.StatusWord;
    titcontext->x87fpu.TagWord = (WORD) DBGContext.FloatSave.TagWord;
    titcontext->x87fpu.ErrorSelector = DBGContext.FloatSave.ErrorSelector;
    titcontext->x87fpu.ErrorOffset = DBGContext.FloatSave.ErrorOffset;
    titcontext->x87fpu.DataSelector = DBGContext.FloatSave.DataSelector;
    titcontext->x87fpu.DataOffset = DBGContext.FloatSave.DataOffset;
    titcontext->x87fpu.Cr0NpxState = DBGContext.FloatSave.Cr0NpxState;

    memcpy(titcontext->RegisterArea, DBGContext.FloatSave.RegisterArea, 80);

    // MXCSR ExtendedRegisters[24]
    memcpy(& (titcontext->MxCsr), & (DBGContext.ExtendedRegisters[24]), sizeof(titcontext->MxCsr));

    // for x86 copy the 8 Xmm Registers from ExtendedRegisters[(10+n)*16]; (n is the index of the xmm register) to the XMM register
    for(i = 0; i < 8; i++)
        memcpy(&(titcontext->XmmRegisters[i]),  & DBGContext.ExtendedRegisters[(10 + i) * 16], 16);
#endif

    GetAVXContext(hActiveThread, titcontext);

    return true;
}

__declspec(dllexport) bool TITCALL GetFullContextDataEx(HANDLE hActiveThread, TITAN_ENGINE_CONTEXT_t* titcontext)
{
    bool returnf;

    if(SuspendThread(hActiveThread) == (DWORD) - 1)
        return false;

    returnf = _GetFullContextDataEx(hActiveThread, titcontext);

    ResumeThread(hActiveThread);

    return returnf;
}

__declspec(dllexport) ULONG_PTR TITCALL GetContextDataEx(HANDLE hActiveThread, DWORD IndexOfRegister)
{
    ULONG_PTR retValue = 0;
    TITAN_ENGINE_CONTEXT_t titcontext;

    if(SuspendThread(hActiveThread) == (DWORD) - 1)
        return false;

    memset(&titcontext, 0, sizeof(titcontext));

    if(! _GetFullContextDataEx(hActiveThread, & titcontext))
    {
        ResumeThread(hActiveThread);
        return false;
    }
    ResumeThread(hActiveThread);

#ifdef _WIN64 //x64
    if(IndexOfRegister == UE_EAX)
    {
        retValue = titcontext.cax & 0xFFFFFFFF;
    }
    else if(IndexOfRegister == UE_EBX)
    {
        retValue = titcontext.cbx & 0xFFFFFFFF;
    }
    else if(IndexOfRegister == UE_ECX)
    {
        retValue = titcontext.ccx & 0xFFFFFFFF;
    }
    else if(IndexOfRegister == UE_EDX)
    {
        retValue = titcontext.cdx & 0xFFFFFFFF;
    }
    else if(IndexOfRegister == UE_EDI)
    {
        retValue = titcontext.cdi & 0xFFFFFFFF;
    }
    else if(IndexOfRegister == UE_ESI)
    {
        retValue = titcontext.csi & 0xFFFFFFFF;
    }
    else if(IndexOfRegister == UE_EBP)
    {
        retValue = titcontext.cbp & 0xFFFFFFFF;
    }
    else if(IndexOfRegister == UE_ESP)
    {
        retValue = titcontext.csp & 0xFFFFFFFF;
    }
    else if(IndexOfRegister == UE_EIP)
    {
        retValue = titcontext.cip & 0xFFFFFFFF;
    }
    else if(IndexOfRegister == UE_EFLAGS)
    {
        retValue = titcontext.eflags & 0xFFFFFFFF;
    }
    else if(IndexOfRegister == UE_RAX)
    {
        retValue = titcontext.cax;
    }
    else if(IndexOfRegister == UE_RBX)
    {
        retValue = titcontext.cbx;
    }
    else if(IndexOfRegister == UE_RCX)
    {
        retValue = titcontext.ccx;
    }
    else if(IndexOfRegister == UE_RDX)
    {
        retValue = titcontext.cdx;
    }
    else if(IndexOfRegister == UE_RDI)
    {
        retValue = titcontext.cdi;
    }
    else if(IndexOfRegister == UE_RSI)
    {
        retValue = titcontext.csi;
    }
    else if(IndexOfRegister == UE_RBP)
    {
        retValue = titcontext.cbp;
    }
    else if(IndexOfRegister == UE_RSP)
    {
        retValue = titcontext.csp;
    }
    else if(IndexOfRegister == UE_RIP)
    {
        retValue = titcontext.cip;
    }
    else if(IndexOfRegister == UE_RFLAGS)
    {
        retValue = titcontext.eflags;
    }
    else if(IndexOfRegister == UE_R8)
    {
        retValue = titcontext.r8;
    }
    else if(IndexOfRegister == UE_R9)
    {
        retValue = titcontext.r9;
    }
    else if(IndexOfRegister == UE_R10)
    {
        retValue = titcontext.r10;
    }
    else if(IndexOfRegister == UE_R11)
    {
        retValue = titcontext.r11;
    }
    else if(IndexOfRegister == UE_R12)
    {
        retValue = titcontext.r12;
    }
    else if(IndexOfRegister == UE_R13)
    {
        retValue = titcontext.r13;
    }
    else if(IndexOfRegister == UE_R14)
    {
        retValue = titcontext.r14;
    }
    else if(IndexOfRegister == UE_R15)
    {
        retValue = titcontext.r15;
    }
    else if(IndexOfRegister == UE_CIP)
    {
        retValue = titcontext.cip;
    }
    else if(IndexOfRegister == UE_CSP)
    {
        retValue = titcontext.csp;
    }
#else //x86
    if(IndexOfRegister == UE_EAX)
    {
        retValue = titcontext.cax;
    }
    else if(IndexOfRegister == UE_EBX)
    {
        retValue = titcontext.cbx;
    }
    else if(IndexOfRegister == UE_ECX)
    {
        retValue = titcontext.ccx;
    }
    else if(IndexOfRegister == UE_EDX)
    {
        retValue = titcontext.cdx;
    }
    else if(IndexOfRegister == UE_EDI)
    {
        retValue = titcontext.cdi;
    }
    else if(IndexOfRegister == UE_ESI)
    {
        retValue = titcontext.csi;
    }
    else if(IndexOfRegister == UE_EBP)
    {
        retValue = titcontext.cbp;
    }
    else if(IndexOfRegister == UE_ESP)
    {
        retValue = titcontext.csp;
    }
    else if(IndexOfRegister == UE_EIP)
    {
        retValue = titcontext.cip;
    }
    else if(IndexOfRegister == UE_CIP)
    {
        retValue = titcontext.cip;
    }
    else if(IndexOfRegister == UE_CSP)
    {
        retValue = titcontext.csp;
    }
#endif
    else if(IndexOfRegister == UE_X87_STATUSWORD)
    {
        retValue = titcontext.x87fpu.StatusWord;
    }
    else if(IndexOfRegister == UE_X87_CONTROLWORD)
    {
        retValue = titcontext.x87fpu.ControlWord;
    }
    else if(IndexOfRegister == UE_X87_TAGWORD)
    {
        retValue = titcontext.x87fpu.TagWord;
    }
    else if(IndexOfRegister == UE_MXCSR)
    {
        retValue = titcontext.MxCsr;
    }
    else if(IndexOfRegister == UE_EFLAGS)
    {
        retValue = titcontext.eflags;
    }
    else if(IndexOfRegister == UE_DR0)
    {
        retValue = titcontext.dr0;
    }
    else if(IndexOfRegister == UE_DR1)
    {
        retValue = titcontext.dr1;
    }
    else if(IndexOfRegister == UE_DR2)
    {
        retValue = titcontext.dr2;
    }
    else if(IndexOfRegister == UE_DR3)
    {
        retValue = titcontext.dr3;
    }
    else if(IndexOfRegister == UE_DR6)
    {
        retValue = titcontext.dr6;
    }
    else if(IndexOfRegister == UE_DR7)
    {
        retValue = titcontext.dr7;
    }
    else if(IndexOfRegister == UE_SEG_GS)
    {
        retValue = titcontext.gs;
    }
    else if(IndexOfRegister == UE_SEG_FS)
    {
        retValue = titcontext.fs;
    }
    else if(IndexOfRegister == UE_SEG_ES)
    {
        retValue = titcontext.es;
    }
    else if(IndexOfRegister == UE_SEG_DS)
    {
        retValue = titcontext.ds;
    }
    else if(IndexOfRegister == UE_SEG_CS)
    {
        retValue = titcontext.cs;
    }
    else if(IndexOfRegister == UE_SEG_SS)
    {
        retValue = titcontext.ss;
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
    TITAN_ENGINE_CONTEXT_t titcontext;
    bool returnf;

    if(SuspendThread(hActiveThread) == (DWORD) - 1)
        return false;

    memset(&titcontext, 0, sizeof(titcontext));

    if(! _GetFullContextDataEx(hActiveThread, & titcontext))
    {
        ResumeThread(hActiveThread);
        return false;
    }

#ifdef _WIN64 //x64
    if(IndexOfRegister == UE_EAX)
    {
        NewRegisterValue = titcontext.cax - (DWORD)titcontext.cax + NewRegisterValue;
        titcontext.cax = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_EBX)
    {
        NewRegisterValue = titcontext.cbx - (DWORD)titcontext.cbx + NewRegisterValue;
        titcontext.cbx = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_ECX)
    {
        NewRegisterValue = titcontext.ccx - (DWORD)titcontext.ccx + NewRegisterValue;
        titcontext.ccx = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_EDX)
    {
        NewRegisterValue = titcontext.cdx - (DWORD)titcontext.cdx + NewRegisterValue;
        titcontext.cdx = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_EDI)
    {
        NewRegisterValue = titcontext.cdi - (DWORD)titcontext.cdi + NewRegisterValue;
        titcontext.cdi = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_ESI)
    {
        NewRegisterValue = titcontext.csi - (DWORD)titcontext.csi + NewRegisterValue;
        titcontext.csi = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_EBP)
    {
        NewRegisterValue = titcontext.cbp - (DWORD)titcontext.cbp + NewRegisterValue;
        titcontext.cbp = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_ESP)
    {
        NewRegisterValue = titcontext.csp - (DWORD)titcontext.csp + NewRegisterValue;
        titcontext.csp = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_EIP)
    {
        NewRegisterValue = titcontext.cip - (DWORD)titcontext.cip + NewRegisterValue;
        titcontext.cip = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_EFLAGS)
    {
        titcontext.eflags = (DWORD)NewRegisterValue;
    }
    else if(IndexOfRegister == UE_RAX)
    {
        titcontext.cax = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_RBX)
    {
        titcontext.cbx = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_RCX)
    {
        titcontext.ccx = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_RDX)
    {
        titcontext.cdx = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_RDI)
    {
        titcontext.cdi = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_RSI)
    {
        titcontext.csi = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_RBP)
    {
        titcontext.cbp = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_RSP)
    {
        titcontext.csp = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_RIP)
    {
        titcontext.cip = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_RFLAGS)
    {
        titcontext.eflags = (unsigned int) NewRegisterValue;
    }
    else if(IndexOfRegister == UE_R8)
    {
        titcontext.r8 = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_R9)
    {
        titcontext.r9 = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_R10)
    {
        titcontext.r10 = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_R11)
    {
        titcontext.r11 = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_R12)
    {
        titcontext.r12 = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_R13)
    {
        titcontext.r13 = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_R14)
    {
        titcontext.r14 = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_R15)
    {
        titcontext.r15 = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_CIP)
    {
        titcontext.cip = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_CSP)
    {
        titcontext.csp = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_XMM8)
    {
        memcpy(& (titcontext.XmmRegisters[8]), (void*) NewRegisterValue, 16);
    }
    else if(IndexOfRegister == UE_XMM9)
    {
        memcpy(& (titcontext.XmmRegisters[9]), (void*) NewRegisterValue, 16);
    }
    else if(IndexOfRegister == UE_XMM10)
    {
        memcpy(& (titcontext.XmmRegisters[10]), (void*) NewRegisterValue, 16);
    }
    else if(IndexOfRegister == UE_XMM11)
    {
        memcpy(& (titcontext.XmmRegisters[11]), (void*) NewRegisterValue, 16);
    }
    else if(IndexOfRegister == UE_XMM12)
    {
        memcpy(& (titcontext.XmmRegisters[12]), (void*) NewRegisterValue, 16);
    }
    else if(IndexOfRegister == UE_XMM13)
    {
        memcpy(& (titcontext.XmmRegisters[13]), (void*) NewRegisterValue, 16);
    }
    else if(IndexOfRegister == UE_XMM14)
    {
        memcpy(& (titcontext.XmmRegisters[14]), (void*) NewRegisterValue, 16);
    }
    else if(IndexOfRegister == UE_XMM15)
    {
        memcpy(& (titcontext.XmmRegisters[15]), (void*) NewRegisterValue, 16);
    }
#else //x86
    if(IndexOfRegister == UE_EAX)
    {
        titcontext.cax = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_EBX)
    {
        titcontext.cbx = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_ECX)
    {
        titcontext.ccx = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_EDX)
    {
        titcontext.cdx = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_EDI)
    {
        titcontext.cdi = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_ESI)
    {
        titcontext.csi = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_EBP)
    {
        titcontext.cbp = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_ESP)
    {
        titcontext.csp = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_EIP)
    {
        titcontext.cip = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_EFLAGS)
    {
        titcontext.eflags = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_CIP)
    {
        titcontext.cip = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_CSP)
    {
        titcontext.csp = NewRegisterValue;
    }
#endif
    else if(IndexOfRegister == UE_DR0)
    {
        titcontext.dr0 = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_DR1)
    {
        titcontext.dr1 = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_DR2)
    {
        titcontext.dr2 = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_DR3)
    {
        titcontext.dr3 = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_DR6)
    {
        titcontext.dr6 = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_DR7)
    {
        titcontext.dr7 = NewRegisterValue;
    }
    else if(IndexOfRegister == UE_SEG_GS)
    {
        titcontext.gs = (unsigned short)NewRegisterValue;
    }
    else if(IndexOfRegister == UE_SEG_FS)
    {
        titcontext.fs = (unsigned short)NewRegisterValue;
    }
    else if(IndexOfRegister == UE_SEG_ES)
    {
        titcontext.es = (unsigned short)NewRegisterValue;
    }
    else if(IndexOfRegister == UE_SEG_DS)
    {
        titcontext.ds = (unsigned short)NewRegisterValue;
    }
    else if(IndexOfRegister == UE_SEG_CS)
    {
        titcontext.cs = (unsigned short)NewRegisterValue;
    }
    else if(IndexOfRegister == UE_SEG_SS)
    {
        titcontext.ss = (unsigned short)NewRegisterValue;
    }
    else if(IndexOfRegister == UE_X87_STATUSWORD)
    {
        titcontext.x87fpu.StatusWord = (unsigned short)NewRegisterValue;
    }
    else if(IndexOfRegister == UE_X87_CONTROLWORD)
    {
        titcontext.x87fpu.ControlWord = (unsigned short)NewRegisterValue;
    }
    else if(IndexOfRegister == UE_X87_TAGWORD)
    {
        titcontext.x87fpu.TagWord = (unsigned short)NewRegisterValue;
    }
    else if(IndexOfRegister == UE_MXCSR)
    {
        titcontext.MxCsr = (unsigned short)NewRegisterValue;
    }
    else if(IndexOfRegister == UE_XMM0)
    {
        memcpy(& (titcontext.XmmRegisters[0]), (void*) NewRegisterValue, 16);
    }
    else if(IndexOfRegister == UE_XMM1)
    {
        memcpy(& (titcontext.XmmRegisters[1]), (void*) NewRegisterValue, 16);
    }
    else if(IndexOfRegister == UE_XMM2)
    {
        memcpy(& (titcontext.XmmRegisters[2]), (void*) NewRegisterValue, 16);
    }
    else if(IndexOfRegister == UE_XMM3)
    {
        memcpy(& (titcontext.XmmRegisters[3]), (void*) NewRegisterValue, 16);
    }
    else if(IndexOfRegister == UE_XMM4)
    {
        memcpy(& (titcontext.XmmRegisters[4]), (void*) NewRegisterValue, 16);
    }
    else if(IndexOfRegister == UE_XMM5)
    {
        memcpy(& (titcontext.XmmRegisters[5]), (void*) NewRegisterValue, 16);
    }
    else if(IndexOfRegister == UE_XMM6)
    {
        memcpy(& (titcontext.XmmRegisters[6]), (void*) NewRegisterValue, 16);
    }
    else if(IndexOfRegister == UE_XMM7)
    {
        memcpy(& (titcontext.XmmRegisters[7]), (void*) NewRegisterValue, 16);
    }
    else if(IndexOfRegister == UE_MMX0)
    {
        int STInTopStack = GetSTInTOPStackFromStatusWord(titcontext.x87fpu.StatusWord);
        DWORD x87r0_position = Getx87r0PositionInRegisterArea(STInTopStack);

        memcpy(((uint64_t*) GetRegisterAreaOf87register(titcontext.RegisterArea, x87r0_position, 0)), (char*) NewRegisterValue, 8);
    }
    else if(IndexOfRegister == UE_MMX1)
    {
        int STInTopStack = GetSTInTOPStackFromStatusWord(titcontext.x87fpu.StatusWord);
        DWORD x87r0_position = Getx87r0PositionInRegisterArea(STInTopStack);

        memcpy(((uint64_t*) GetRegisterAreaOf87register(titcontext.RegisterArea, x87r0_position, 1)), (char*) NewRegisterValue, 8);
    }
    else if(IndexOfRegister == UE_MMX2)
    {
        int STInTopStack = GetSTInTOPStackFromStatusWord(titcontext.x87fpu.StatusWord);
        DWORD x87r0_position = Getx87r0PositionInRegisterArea(STInTopStack);

        memcpy(((uint64_t*) GetRegisterAreaOf87register(titcontext.RegisterArea, x87r0_position, 2)), (char*) NewRegisterValue, 8);
    }
    else if(IndexOfRegister == UE_MMX3)
    {
        int STInTopStack = GetSTInTOPStackFromStatusWord(titcontext.x87fpu.StatusWord);
        DWORD x87r0_position = Getx87r0PositionInRegisterArea(STInTopStack);

        memcpy(((uint64_t*) GetRegisterAreaOf87register(titcontext.RegisterArea, x87r0_position, 3)), (char*) NewRegisterValue, 8);
    }
    else if(IndexOfRegister == UE_MMX4)
    {
        int STInTopStack = GetSTInTOPStackFromStatusWord(titcontext.x87fpu.StatusWord);
        DWORD x87r0_position = Getx87r0PositionInRegisterArea(STInTopStack);

        memcpy(((uint64_t*) GetRegisterAreaOf87register(titcontext.RegisterArea, x87r0_position, 4)), (char*) NewRegisterValue, 8);
    }
    else if(IndexOfRegister == UE_MMX5)
    {
        int STInTopStack = GetSTInTOPStackFromStatusWord(titcontext.x87fpu.StatusWord);
        DWORD x87r0_position = Getx87r0PositionInRegisterArea(STInTopStack);

        memcpy(((uint64_t*) GetRegisterAreaOf87register(titcontext.RegisterArea, x87r0_position, 5)), (char*) NewRegisterValue, 8);
    }
    else if(IndexOfRegister == UE_MMX6)
    {
        int STInTopStack = GetSTInTOPStackFromStatusWord(titcontext.x87fpu.StatusWord);
        DWORD x87r0_position = Getx87r0PositionInRegisterArea(STInTopStack);

        memcpy(((uint64_t*) GetRegisterAreaOf87register(titcontext.RegisterArea, x87r0_position, 6)), (char*) NewRegisterValue, 8);
    }
    else if(IndexOfRegister == UE_MMX7)
    {
        int STInTopStack = GetSTInTOPStackFromStatusWord(titcontext.x87fpu.StatusWord);
        DWORD x87r0_position = Getx87r0PositionInRegisterArea(STInTopStack);

        memcpy(((uint64_t*) GetRegisterAreaOf87register(titcontext.RegisterArea, x87r0_position, 7)), (char*) NewRegisterValue, 8);
    }
    else if(IndexOfRegister == UE_x87_r0)
    {
        int STInTopStack = GetSTInTOPStackFromStatusWord(titcontext.x87fpu.StatusWord);
        DWORD x87r0_position = Getx87r0PositionInRegisterArea(STInTopStack);

        memcpy(((uint64_t*) GetRegisterAreaOf87register(titcontext.RegisterArea, x87r0_position, 0)), (char*) NewRegisterValue, 10);
    }
    else if(IndexOfRegister == UE_x87_r1)
    {
        int STInTopStack = GetSTInTOPStackFromStatusWord(titcontext.x87fpu.StatusWord);
        DWORD x87r0_position = Getx87r0PositionInRegisterArea(STInTopStack);

        memcpy(((uint64_t*) GetRegisterAreaOf87register(titcontext.RegisterArea, x87r0_position, 1)), (char*) NewRegisterValue, 10);
    }
    else if(IndexOfRegister == UE_x87_r2)
    {
        int STInTopStack = GetSTInTOPStackFromStatusWord(titcontext.x87fpu.StatusWord);
        DWORD x87r0_position = Getx87r0PositionInRegisterArea(STInTopStack);

        memcpy(((uint64_t*) GetRegisterAreaOf87register(titcontext.RegisterArea, x87r0_position, 2)), (char*) NewRegisterValue, 10);
    }
    else if(IndexOfRegister == UE_x87_r3)
    {
        int STInTopStack = GetSTInTOPStackFromStatusWord(titcontext.x87fpu.StatusWord);
        DWORD x87r0_position = Getx87r0PositionInRegisterArea(STInTopStack);

        memcpy(((uint64_t*) GetRegisterAreaOf87register(titcontext.RegisterArea, x87r0_position, 3)), (char*) NewRegisterValue, 10);
    }
    else if(IndexOfRegister == UE_x87_r4)
    {
        int STInTopStack = GetSTInTOPStackFromStatusWord(titcontext.x87fpu.StatusWord);
        DWORD x87r0_position = Getx87r0PositionInRegisterArea(STInTopStack);

        memcpy(((uint64_t*) GetRegisterAreaOf87register(titcontext.RegisterArea, x87r0_position, 4)), (char*) NewRegisterValue, 10);
    }
    else if(IndexOfRegister == UE_x87_r5)
    {
        int STInTopStack = GetSTInTOPStackFromStatusWord(titcontext.x87fpu.StatusWord);
        DWORD x87r0_position = Getx87r0PositionInRegisterArea(STInTopStack);

        memcpy(((uint64_t*) GetRegisterAreaOf87register(titcontext.RegisterArea, x87r0_position, 5)), (char*) NewRegisterValue, 10);
    }
    else if(IndexOfRegister == UE_x87_r6)
    {
        int STInTopStack = GetSTInTOPStackFromStatusWord(titcontext.x87fpu.StatusWord);
        DWORD x87r0_position = Getx87r0PositionInRegisterArea(STInTopStack);

        memcpy(((uint64_t*) GetRegisterAreaOf87register(titcontext.RegisterArea, x87r0_position, 6)), (char*) NewRegisterValue, 10);
    }
    else if(IndexOfRegister == UE_x87_r7)
    {
        int STInTopStack = GetSTInTOPStackFromStatusWord(titcontext.x87fpu.StatusWord);
        DWORD x87r0_position = Getx87r0PositionInRegisterArea(STInTopStack);

        memcpy(((uint64_t*) GetRegisterAreaOf87register(titcontext.RegisterArea, x87r0_position, 7)), (char*) NewRegisterValue, 10);
    }
    else if(IndexOfRegister == UE_YMM0)
        memcpy(& (titcontext.YmmRegisters[32 * 0]), (void*) NewRegisterValue, 32);
    else if(IndexOfRegister == UE_YMM1)
        memcpy(& (titcontext.YmmRegisters[32 * 1]), (void*) NewRegisterValue, 32);
    else if(IndexOfRegister == UE_YMM2)
        memcpy(& (titcontext.YmmRegisters[32 * 2]), (void*) NewRegisterValue, 32);
    else if(IndexOfRegister == UE_YMM3)
        memcpy(& (titcontext.YmmRegisters[32 * 3]), (void*) NewRegisterValue, 32);
    else if(IndexOfRegister == UE_YMM4)
        memcpy(& (titcontext.YmmRegisters[32 * 4]), (void*) NewRegisterValue, 32);
    else if(IndexOfRegister == UE_YMM5)
        memcpy(& (titcontext.YmmRegisters[32 * 5]), (void*) NewRegisterValue, 32);
    else if(IndexOfRegister == UE_YMM6)
        memcpy(& (titcontext.YmmRegisters[32 * 6]), (void*) NewRegisterValue, 32);
    else if(IndexOfRegister == UE_YMM7)
        memcpy(& (titcontext.YmmRegisters[32 * 7]), (void*) NewRegisterValue, 32);
    else if(IndexOfRegister == UE_YMM8)
        memcpy(& (titcontext.YmmRegisters[32 * 8]), (void*) NewRegisterValue, 32);
    else if(IndexOfRegister == UE_YMM9)
        memcpy(& (titcontext.YmmRegisters[32 * 9]), (void*) NewRegisterValue, 32);
    else if(IndexOfRegister == UE_YMM10)
        memcpy(& (titcontext.YmmRegisters[32 * 10]), (void*) NewRegisterValue, 32);
    else if(IndexOfRegister == UE_YMM11)
        memcpy(& (titcontext.YmmRegisters[32 * 11]), (void*) NewRegisterValue, 32);
    else if(IndexOfRegister == UE_YMM12)
        memcpy(& (titcontext.YmmRegisters[32 * 12]), (void*) NewRegisterValue, 32);
    else if(IndexOfRegister == UE_YMM13)
        memcpy(& (titcontext.YmmRegisters[32 * 13]), (void*) NewRegisterValue, 32);
    else if(IndexOfRegister == UE_YMM14)
        memcpy(& (titcontext.YmmRegisters[32 * 14]), (void*) NewRegisterValue, 32);
    else if(IndexOfRegister == UE_YMM15)
        memcpy(& (titcontext.YmmRegisters[32 * 15]), (void*) NewRegisterValue, 32);
    else
    {
        ResumeThread(hActiveThread);
        return false;
    }

    returnf = _SetFullContextDataEx(hActiveThread, &titcontext);

    ResumeThread(hActiveThread);

    return returnf;
}

__declspec(dllexport) bool TITCALL SetContextData(DWORD IndexOfRegister, ULONG_PTR NewRegisterValue)
{
    HANDLE hActiveThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | THREAD_GET_CONTEXT, false, DBGEvent.dwThreadId);
    bool ContextReturn = SetContextDataEx(hActiveThread, IndexOfRegister, NewRegisterValue);
    EngineCloseHandle(hActiveThread);
    return ContextReturn;
}

#undef CONTEXT_XSTATE

#if defined(_M_X64)
#define CONTEXT_XSTATE                      (0x00100040)
#else
#define CONTEXT_XSTATE                      (0x00010040)
#endif


#define XSTATE_AVX                          (XSTATE_GSSE)
#define XSTATE_MASK_AVX                     (XSTATE_MASK_GSSE)

typedef DWORD64(WINAPI* PGETENABLEDXSTATEFEATURES)();
PGETENABLEDXSTATEFEATURES pfnGetEnabledXStateFeatures = NULL;

typedef BOOL (WINAPI* PINITIALIZECONTEXT)(PVOID Buffer, DWORD ContextFlags, PCONTEXT* Context, PDWORD ContextLength);
PINITIALIZECONTEXT pfnInitializeContext = NULL;

typedef BOOL (WINAPI* PGETXSTATEFEATURESMASK)(PCONTEXT Context, PDWORD64 FeatureMask);
PGETXSTATEFEATURESMASK pfnGetXStateFeaturesMask = NULL;

typedef PVOID(WINAPI* LOCATEXSTATEFEATURE)(PCONTEXT Context, DWORD FeatureId, PDWORD Length);
LOCATEXSTATEFEATURE pfnLocateXStateFeature = NULL;

typedef BOOL (WINAPI* SETXSTATEFEATURESMASK)(PCONTEXT Context, DWORD64 FeatureMask);
SETXSTATEFEATURESMASK pfnSetXStateFeaturesMask = NULL;

bool InitXState(void)
{
    bool returnf = false;
    static bool init = false;

    if(init)
        return true;

    HMODULE hm = GetModuleHandleA("kernel32.dll");
    if(hm == NULL)
    {
        return returnf;
    }
    pfnGetEnabledXStateFeatures = (PGETENABLEDXSTATEFEATURES)GetProcAddress(hm, "GetEnabledXStateFeatures");
    pfnInitializeContext = (PINITIALIZECONTEXT)GetProcAddress(hm, "InitializeContext");
    pfnGetXStateFeaturesMask = (PGETXSTATEFEATURESMASK)GetProcAddress(hm, "GetXStateFeaturesMask");
    pfnLocateXStateFeature = (LOCATEXSTATEFEATURE)GetProcAddress(hm, "LocateXStateFeature");
    pfnSetXStateFeaturesMask = (SETXSTATEFEATURESMASK)GetProcAddress(hm, "SetXStateFeaturesMask");

    if
    (
        pfnGetEnabledXStateFeatures == NULL
        || pfnInitializeContext == NULL
        || pfnGetXStateFeaturesMask == NULL
        || pfnLocateXStateFeature == NULL
        || pfnSetXStateFeaturesMask == NULL
    )
    {
        return returnf;
    }
    init = true;

    return true;
}

__declspec(dllexport) bool TITCALL GetAVXContext(HANDLE hActiveThread, TITAN_ENGINE_CONTEXT_t* titcontext)
{
    PVOID Buffer;
    PCONTEXT Context;
    DWORD ContextSize;
    DWORD FeatureLength;
    ULONG Index;
    BOOL Success;
    PM128A Ymm;
    DWORD64 FeatureMask;
    bool returnf = false;

    if(InitXState() == false)
        return returnf;

    FeatureMask = pfnGetEnabledXStateFeatures();
    if((FeatureMask & XSTATE_MASK_AVX) == 0)
        return returnf;

    ContextSize = 0;
    Success = pfnInitializeContext(NULL,
                                   CONTEXT_ALL | CONTEXT_XSTATE,
                                   NULL,
                                   &ContextSize);

    if((Success == TRUE) || (GetLastError() != ERROR_INSUFFICIENT_BUFFER))
        return returnf;

    Buffer = calloc(1, ContextSize);
    if(Buffer == NULL)
        return returnf;

    Success = pfnInitializeContext(Buffer,
                                   CONTEXT_ALL | CONTEXT_XSTATE,
                                   &Context,
                                   &ContextSize);

    if(Success == FALSE)
        goto Cleanup;

    Success = pfnSetXStateFeaturesMask(Context, XSTATE_MASK_AVX);
    if(Success == FALSE)
        goto Cleanup;

    Success = GetThreadContext(hActiveThread, Context);
    if(Success == FALSE)
        goto Cleanup;

    Success = pfnGetXStateFeaturesMask(Context, &FeatureMask);
    if(Success == FALSE)
        goto Cleanup;

    Ymm = (PM128A)pfnLocateXStateFeature(Context, XSTATE_AVX, &FeatureLength);

    for(Index = 0; Index < FeatureLength / sizeof(* Ymm); Index += 1)
    {
        memcpy
        (
            (char*) & (titcontext->YmmRegisters[32 * Index]),
            &titcontext->XmmRegisters[Index],
            sizeof(titcontext->XmmRegisters[Index])
        );
        memcpy
        (
            ((char*) & (titcontext->YmmRegisters[32 * Index])) + sizeof(titcontext->XmmRegisters[Index]),
            &Ymm[Index],
            sizeof(Ymm[Index])
        );
    }

    returnf = true;

Cleanup:
    free(Buffer);

    return returnf;
}

