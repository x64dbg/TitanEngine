#include "stdafx.h"
#include "definitions.h"
#include "Global.Debugger.h"
#include "Global.Engine.h"
#include "Global.Handle.h"
#include "Global.Engine.Threading.h"
#include "Global.Engine.Context.h"

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

    for(int i = 0; i < 8; i++)
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

__declspec(dllexport) bool TITCALL SetFullContextDataEx(HANDLE hActiveThread, TITAN_ENGINE_CONTEXT_t* titcontext)
{
    bool returnf;

    if(SuspendThread(hActiveThread) == (DWORD) - 1)
        return false;

    returnf = _SetFullContextDataEx(hActiveThread, titcontext, false);

    ResumeThread(hActiveThread);

    return returnf;
}

__declspec(dllexport) bool TITCALL GetFullContextDataEx(HANDLE hActiveThread, TITAN_ENGINE_CONTEXT_t* titcontext)
{
    // While a debug event is handled the threads are frozen: no need to suspend
    if(EngineContextCacheActive())
        return _GetFullContextDataEx(hActiveThread, titcontext, true);

    bool returnf;

    if(SuspendThread(hActiveThread) == (DWORD) - 1)
        return false;

    returnf = _GetFullContextDataEx(hActiveThread, titcontext, true);

    ResumeThread(hActiveThread);

    return returnf;
}

__declspec(dllexport) ULONG_PTR TITCALL GetContextDataEx(HANDLE hActiveThread, DWORD IndexOfRegister)
{
    ULONG_PTR retValue = 0;
    TITAN_ENGINE_CONTEXT_t titcontext;

    // While a debug event is handled the threads are frozen: no need to suspend
    const bool frozen = EngineContextCacheActive();
    if(!frozen && SuspendThread(hActiveThread) == (DWORD) - 1)
        return false;

    memset(&titcontext, 0, sizeof(titcontext));

    if(! _GetFullContextDataEx(hActiveThread, & titcontext, false))
    {
        if(!frozen)
            ResumeThread(hActiveThread);
        return false;
    }
    if(!frozen)
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
    EngineEventThread hActiveThread(THREAD_GETSETSUSPEND);
    return GetContextDataEx(hActiveThread.get(), IndexOfRegister);
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
    bool avx_priority = false;

    if(SuspendThread(hActiveThread) == (DWORD) - 1)
        return false;

    memset(&titcontext, 0, sizeof(titcontext));

    if(! _GetFullContextDataEx(hActiveThread, & titcontext, IndexOfRegister >= UE_MXCSR))
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
    else if(IndexOfRegister == UE_YMM8)
    {
        avx_priority = true;
        memcpy(& (titcontext.YmmRegisters[8]), (void*) NewRegisterValue, 32);
    }
    else if(IndexOfRegister == UE_YMM9)
    {
        avx_priority = true;
        memcpy(& (titcontext.YmmRegisters[9]), (void*) NewRegisterValue, 32);
    }
    else if(IndexOfRegister == UE_YMM10)
    {
        avx_priority = true;
        memcpy(& (titcontext.YmmRegisters[10]), (void*) NewRegisterValue, 32);
    }
    else if(IndexOfRegister == UE_YMM11)
    {
        avx_priority = true;
        memcpy(& (titcontext.YmmRegisters[11]), (void*) NewRegisterValue, 32);
    }
    else if(IndexOfRegister == UE_YMM12)
    {
        avx_priority = true;
        memcpy(& (titcontext.YmmRegisters[12]), (void*) NewRegisterValue, 32);
    }
    else if(IndexOfRegister == UE_YMM13)
    {
        avx_priority = true;
        memcpy(& (titcontext.YmmRegisters[13]), (void*) NewRegisterValue, 32);
    }
    else if(IndexOfRegister == UE_YMM14)
    {
        avx_priority = true;
        memcpy(& (titcontext.YmmRegisters[14]), (void*) NewRegisterValue, 32);
    }
    else if(IndexOfRegister == UE_YMM15)
    {
        avx_priority = true;
        memcpy(& (titcontext.YmmRegisters[15]), (void*) NewRegisterValue, 32);
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
    {
        avx_priority = true;
        memcpy(& (titcontext.YmmRegisters[0]), (void*) NewRegisterValue, 32);
    }
    else if(IndexOfRegister == UE_YMM1)
    {
        avx_priority = true;
        memcpy(& (titcontext.YmmRegisters[1]), (void*) NewRegisterValue, 32);
    }
    else if(IndexOfRegister == UE_YMM2)
    {
        avx_priority = true;
        memcpy(& (titcontext.YmmRegisters[2]), (void*) NewRegisterValue, 32);
    }
    else if(IndexOfRegister == UE_YMM3)
    {
        avx_priority = true;
        memcpy(& (titcontext.YmmRegisters[3]), (void*) NewRegisterValue, 32);
    }
    else if(IndexOfRegister == UE_YMM4)
    {
        avx_priority = true;
        memcpy(& (titcontext.YmmRegisters[4]), (void*) NewRegisterValue, 32);
    }
    else if(IndexOfRegister == UE_YMM5)
    {
        avx_priority = true;
        memcpy(& (titcontext.YmmRegisters[5]), (void*) NewRegisterValue, 32);
    }
    else if(IndexOfRegister == UE_YMM6)
    {
        avx_priority = true;
        memcpy(& (titcontext.YmmRegisters[6]), (void*) NewRegisterValue, 32);
    }
    else if(IndexOfRegister == UE_YMM7)
    {
        avx_priority = true;
        memcpy(& (titcontext.YmmRegisters[7]), (void*) NewRegisterValue, 32);
    }
    else
    {
        ResumeThread(hActiveThread);
        return false;
    }

    returnf = _SetFullContextDataEx(hActiveThread, &titcontext, avx_priority);

    ResumeThread(hActiveThread);

    return returnf;
}

__declspec(dllexport) bool TITCALL SetContextData(DWORD IndexOfRegister, ULONG_PTR NewRegisterValue)
{
    EngineEventThread hActiveThread(THREAD_GETSETSUSPEND);
    return SetContextDataEx(hActiveThread.get(), IndexOfRegister, NewRegisterValue);
}

__declspec(dllexport) bool TITCALL SetAVXContext(HANDLE hActiveThread, TITAN_ENGINE_CONTEXT_t* titcontext)
{
    if(InitXState() == false)
        return false;

    DWORD ContextSize = 0;
    BOOL Success = _InitializeContext(NULL,
                                      CONTEXT_ALL | CONTEXT_XSTATE,
                                      NULL,
                                      &ContextSize);

    if((Success == TRUE) || (GetLastError() != ERROR_INSUFFICIENT_BUFFER))
        return false;

    DynBuf dataBuffer(ContextSize);
    PVOID Buffer = dataBuffer.GetPtr();
    if(Buffer == NULL)
        return false;

    PCONTEXT Context;
    Success = _InitializeContext(Buffer,
                                 CONTEXT_ALL | CONTEXT_XSTATE,
                                 &Context,
                                 &ContextSize);
    if(Success == FALSE)
        return false;

    if(_SetXStateFeaturesMask(Context, XSTATE_MASK_AVX) == FALSE)
    {
        if(_SetXStateFeaturesMask(Context, XSTATE_MASK_LEGACY_SSE) == FALSE)
            return false;
    }

    if(GetThreadContext(hActiveThread, Context) == FALSE)
        return false;

    DWORD64 FeatureMask;
    if(_GetXStateFeaturesMask(Context, &FeatureMask) == FALSE)
        return false;

    DWORD FeatureLength;
    XmmRegister_t* Sse = (XmmRegister_t*)_LocateXStateFeature(Context, XSTATE_LEGACY_SSE, &FeatureLength);
    XmmRegister_t* Avx = (XmmRegister_t*)_LocateXStateFeature(Context, XSTATE_AVX, NULL);
    int NumberOfRegisters = FeatureLength / sizeof(Sse[0]);

    if(Sse != NULL) //If the feature is unsupported by the processor it will return NULL
    {
        for(int i = 0; i < NumberOfRegisters; i++)
            Sse[i] = titcontext->YmmRegisters[i].Low;
    }

    if(Avx != NULL) //If the feature is unsupported by the processor it will return NULL
    {
        for(int i = 0; i < NumberOfRegisters; i++)
            Avx[i] = titcontext->YmmRegisters[i].High;
    }

    return (SetThreadContext(hActiveThread, Context) == TRUE);
}

__declspec(dllexport) bool TITCALL GetAVXContext(HANDLE hActiveThread, TITAN_ENGINE_CONTEXT_t* titcontext)
{
    if(InitXState() == false)
        return false;

    uint64_t generation;
    if(EngineContextCacheLoad(hActiveThread, ContextCacheAvx, titcontext->YmmRegisters, sizeof(titcontext->YmmRegisters), generation))
        return true;

    DWORD ContextSize = 0;
    BOOL Success = _InitializeContext(NULL,
                                      CONTEXT_ALL | CONTEXT_XSTATE,
                                      NULL,
                                      &ContextSize);

    if((Success == TRUE) || (GetLastError() != ERROR_INSUFFICIENT_BUFFER))
        return false;

    DynBuf dataBuffer(ContextSize);
    PVOID Buffer = dataBuffer.GetPtr();
    if(Buffer == NULL)
        return false;

    PCONTEXT Context;
    Success = _InitializeContext(Buffer,
                                 CONTEXT_ALL | CONTEXT_XSTATE,
                                 &Context,
                                 &ContextSize);
    if(Success == FALSE)
        return false;

    if(_SetXStateFeaturesMask(Context, XSTATE_MASK_AVX) == FALSE)
    {
        if(_SetXStateFeaturesMask(Context, XSTATE_MASK_LEGACY_SSE) == FALSE)
            return false;
    }

    if(GetThreadContext(hActiveThread, Context) == FALSE)
        return false;

    DWORD64 FeatureMask;
    if(_GetXStateFeaturesMask(Context, &FeatureMask) == FALSE)
        return false;

    DWORD FeatureLength;
    XmmRegister_t* Sse = (XmmRegister_t*)_LocateXStateFeature(Context, XSTATE_LEGACY_SSE, &FeatureLength);
    XmmRegister_t* Avx = (XmmRegister_t*)_LocateXStateFeature(Context, XSTATE_AVX, NULL);
    int NumberOfRegisters = FeatureLength / sizeof(Sse[0]);

    if(Sse != NULL) //If the feature is unsupported by the processor it will return NULL
    {
        for(int i = 0; i < NumberOfRegisters; i++)
            titcontext->YmmRegisters[i].Low = Sse[i];
    }

    if(Avx != NULL) //If the feature is unsupported by the processor it will return NULL
    {
        for(int i = 0; i < NumberOfRegisters; i++)
            titcontext->YmmRegisters[i].High = Avx[i];
    }

    if(Sse != NULL && Avx != NULL)
        EngineContextCacheStore(hActiveThread, ContextCacheAvx, titcontext->YmmRegisters, sizeof(titcontext->YmmRegisters), generation);

    // The legacy part of the context is the one of CONTEXT_ALL: one system call fills both caches
    CONTEXT full;
    memcpy(&full, Context, sizeof(full));
    full.ContextFlags = EngineContextCacheFlags;
    EngineContextCacheStore(hActiveThread, ContextCacheFull, &full, sizeof(full), generation);

    return true;
}

// AVX-512 constants
#ifndef XSTATE_MASK_AVX512
#define XSTATE_AVX512_KMASK                 (5)
#define XSTATE_AVX512_ZMM_H                 (6)
#define XSTATE_AVX512_ZMM                   (7)
#define XSTATE_MASK_AVX512                  ((1ui64 << (XSTATE_AVX512_KMASK)) | \
                                             (1ui64 << (XSTATE_AVX512_ZMM_H)) | \
                                             (1ui64 << (XSTATE_AVX512_ZMM)))
#endif

static bool SetAVX512ContextFallbackToAVX(HANDLE hActiveThread, TITAN_ENGINE_CONTEXT_AVX512_t* titcontext)
{
    // Fall back to using AVX and ignore the rest
    TITAN_ENGINE_CONTEXT_t Avx;
    memset(&Avx, 0, sizeof(Avx));
    for(int i = 0; i < _countof(Avx.YmmRegisters); i++)
    {
        Avx.YmmRegisters[i] = titcontext->ZmmRegisters[i].Low;
    }
    return SetAVXContext(hActiveThread, &Avx);
}

__declspec(dllexport) bool TITCALL SetAVX512Context(HANDLE hActiveThread, TITAN_ENGINE_CONTEXT_AVX512_t* titcontext)
{
    if(InitXState() == false)
        return false;

    DWORD64 FeatureMask = _GetEnabledXStateFeatures();
    if((FeatureMask & XSTATE_MASK_AVX512) == 0)
        return SetAVX512ContextFallbackToAVX(hActiveThread, titcontext);

    DWORD ContextSize = 0;
    BOOL Success = _InitializeContext(NULL,
                                      CONTEXT_ALL | CONTEXT_XSTATE,
                                      NULL,
                                      &ContextSize);

    if((Success == TRUE) || (GetLastError() != ERROR_INSUFFICIENT_BUFFER))
        return false;

    DynBuf dataBuffer(ContextSize);
    PVOID Buffer = dataBuffer.GetPtr();
    if(Buffer == NULL)
        return false;

    PCONTEXT Context;
    Success = _InitializeContext(Buffer,
                                 CONTEXT_ALL | CONTEXT_XSTATE,
                                 &Context,
                                 &ContextSize);
    if(Success == FALSE)
        return false;

    if(_SetXStateFeaturesMask(Context, XSTATE_MASK_AVX | XSTATE_MASK_AVX512) == FALSE)
        return SetAVX512ContextFallbackToAVX(hActiveThread, titcontext);

    if(GetThreadContext(hActiveThread, Context) == FALSE)
        return false;

    if(_GetXStateFeaturesMask(Context, &FeatureMask) == FALSE)
        return false;

    DWORD FeatureLengthSse;
    DWORD FeatureLengthAvx;
    DWORD FeatureLengthAvx512_KMASK;
    DWORD FeatureLengthAvx512_ZMM_H;
    DWORD FeatureLengthAvx512_ZMM;
    XmmRegister_t* Sse = (XmmRegister_t*)_LocateXStateFeature(Context, XSTATE_LEGACY_SSE, &FeatureLengthSse);
    XmmRegister_t* Avx = (XmmRegister_t*)_LocateXStateFeature(Context, XSTATE_AVX, &FeatureLengthAvx);
    ULONGLONG* Avx512_KMASK = (ULONGLONG*)_LocateXStateFeature(Context, XSTATE_AVX512_KMASK, &FeatureLengthAvx512_KMASK);
    ZmmRegister_t* Avx512_ZMM = (ZmmRegister_t*)_LocateXStateFeature(Context, XSTATE_AVX512_ZMM, &FeatureLengthAvx512_ZMM);
    YmmRegister_t* Avx512_ZMM_H = (YmmRegister_t*)_LocateXStateFeature(Context, XSTATE_AVX512_ZMM_H, &FeatureLengthAvx512_ZMM_H);

    if(Sse != NULL)  //If the feature is unsupported by the processor it will return NULL
    {
        for(int i = 0; i < MIN(FeatureLengthSse / sizeof(XmmRegister_t), _countof(titcontext->ZmmRegisters)); i++)
            Sse[i] = titcontext->ZmmRegisters[i].Low.Low;
    }

    if(Avx != NULL)  //If the feature is unsupported by the processor it will return NULL
    {
        for(int i = 0; i < MIN(FeatureLengthAvx / sizeof(XmmRegister_t), _countof(titcontext->ZmmRegisters)); i++)
            Avx[i] = titcontext->ZmmRegisters[i].Low.High;
    }

    if(Avx512_ZMM_H != NULL)  //If the feature is unsupported by the processor it will return NULL
    {
        for(int i = 0; i < MIN(FeatureLengthAvx512_ZMM_H / sizeof(YmmRegister_t), _countof(titcontext->ZmmRegisters)); i++)
            Avx512_ZMM_H[i] = titcontext->ZmmRegisters[i].High;
    }

#ifdef _WIN64
    if(Avx512_ZMM != NULL)  //If the feature is unsupported by the processor it will return NULL
    {
        for(int i = 0; i < MIN(FeatureLengthAvx512_ZMM / sizeof(ZmmRegister_t), _countof(titcontext->ZmmRegisters) - FeatureLengthAvx / sizeof(XmmRegister_t)); i++)
            Avx512_ZMM[i] = titcontext->ZmmRegisters[i + FeatureLengthAvx / sizeof(XmmRegister_t)];
    }
#endif // _WIN64

    if(Avx512_KMASK != NULL)  //If the feature is unsupported by the processor it will return NULL
    {
        for(int i = 0; i < MIN(FeatureLengthAvx512_KMASK / sizeof(ULONGLONG), _countof(titcontext->Opmask)); i++)
            Avx512_KMASK[i] = titcontext->Opmask[i];
    }

    return (SetThreadContext(hActiveThread, Context) == TRUE);
}

static bool GetAVX512ContextFallbackToAVX(HANDLE hActiveThread, TITAN_ENGINE_CONTEXT_AVX512_t* titcontext)
{
    // Fall back to using AVX and fill the rest with 0
    TITAN_ENGINE_CONTEXT_t Avx;
    memset(titcontext, 0, sizeof(*titcontext));
    if(GetAVXContext(hActiveThread, &Avx))
    {
        for(int i = 0; i < _countof(Avx.YmmRegisters); i++)
            titcontext->ZmmRegisters[i].Low = Avx.YmmRegisters[i];
        return true;
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL GetAVX512Context(HANDLE hActiveThread, TITAN_ENGINE_CONTEXT_AVX512_t* titcontext)
{
    if(InitXState() == false)
        return false;

    DWORD64 FeatureMask = _GetEnabledXStateFeatures();
    if((FeatureMask & XSTATE_MASK_AVX512) == 0)  //XSTATE_MASK_AVX512
        return GetAVX512ContextFallbackToAVX(hActiveThread, titcontext);

    uint64_t generation;
    if(EngineContextCacheLoad(hActiveThread, ContextCacheAvx512, titcontext, sizeof(*titcontext), generation))
        return true;

    DWORD ContextSize = 0;
    BOOL Success = _InitializeContext(NULL,
                                      CONTEXT_ALL | CONTEXT_XSTATE,
                                      NULL,
                                      &ContextSize);

    if((Success == TRUE) || (GetLastError() != ERROR_INSUFFICIENT_BUFFER))
        return false;

    DynBuf dataBuffer(ContextSize);
    PVOID Buffer = dataBuffer.GetPtr();
    if(Buffer == NULL)
        return false;

    PCONTEXT Context;
    Success = _InitializeContext(Buffer,
                                 CONTEXT_ALL | CONTEXT_XSTATE,
                                 &Context,
                                 &ContextSize);
    if(Success == FALSE)
        return false;

    if(_SetXStateFeaturesMask(Context, XSTATE_MASK_AVX | XSTATE_MASK_AVX512) == FALSE)
        return GetAVX512ContextFallbackToAVX(hActiveThread, titcontext);

    if(GetThreadContext(hActiveThread, Context) == FALSE)
        return false;

    if(_GetXStateFeaturesMask(Context, &FeatureMask) == FALSE)
        return false;

    DWORD FeatureLengthSse;
    DWORD FeatureLengthAvx;
    DWORD FeatureLengthAvx512_KMASK;
    DWORD FeatureLengthAvx512_ZMM_H;
    DWORD FeatureLengthAvx512_ZMM;
    XmmRegister_t* Sse = (XmmRegister_t*)_LocateXStateFeature(Context, XSTATE_LEGACY_SSE, &FeatureLengthSse);
    XmmRegister_t* Avx = (XmmRegister_t*)_LocateXStateFeature(Context, XSTATE_AVX, &FeatureLengthAvx);
    ULONGLONG* Avx512_KMASK = (ULONGLONG*)_LocateXStateFeature(Context, XSTATE_AVX512_KMASK, &FeatureLengthAvx512_KMASK);
    ZmmRegister_t* Avx512_ZMM = (ZmmRegister_t*)_LocateXStateFeature(Context, XSTATE_AVX512_ZMM, &FeatureLengthAvx512_ZMM);
    YmmRegister_t* Avx512_ZMM_H = (YmmRegister_t*)_LocateXStateFeature(Context, XSTATE_AVX512_ZMM_H, &FeatureLengthAvx512_ZMM_H);

    if(Sse != NULL)  //If the feature is unsupported by the processor it will return NULL
    {
        for(int i = 0; i < MIN(FeatureLengthSse / sizeof(XmmRegister_t), _countof(titcontext->ZmmRegisters)); i++)
            titcontext->ZmmRegisters[i].Low.Low = Sse[i];
    }

    if(Avx != NULL)  //If the feature is unsupported by the processor it will return NULL
    {
        for(int i = 0; i < MIN(FeatureLengthAvx / sizeof(XmmRegister_t), _countof(titcontext->ZmmRegisters)); i++)
            titcontext->ZmmRegisters[i].Low.High = Avx[i];
    }

    if(Avx512_ZMM_H != NULL)  //If the feature is unsupported by the processor it will return NULL
    {
        for(int i = 0; i < MIN(FeatureLengthAvx512_ZMM_H / sizeof(YmmRegister_t), _countof(titcontext->ZmmRegisters)); i++)
            titcontext->ZmmRegisters[i].High = Avx512_ZMM_H[i];
    }

#ifdef _WIN64
    if(Avx512_ZMM != NULL)  //If the feature is unsupported by the processor it will return NULL
    {
        for(int i = 0; i < MIN(FeatureLengthAvx512_ZMM / sizeof(ZmmRegister_t), _countof(titcontext->ZmmRegisters) - FeatureLengthAvx / sizeof(XmmRegister_t)); i++)
            titcontext->ZmmRegisters[i + FeatureLengthAvx / sizeof(XmmRegister_t)] = Avx512_ZMM[i];
    }
#endif // _WIN64

    if(Avx512_KMASK != NULL)  //If the feature is unsupported by the processor it will return NULL
    {
        for(int i = 0; i < MIN(FeatureLengthAvx512_KMASK / sizeof(ULONGLONG), _countof(titcontext->Opmask)); i++)
            titcontext->Opmask[i] = Avx512_KMASK[i];
    }

    if(Sse != NULL && Avx != NULL && Avx512_KMASK != NULL && Avx512_ZMM_H != NULL)
        EngineContextCacheStore(hActiveThread, ContextCacheAvx512, titcontext, sizeof(*titcontext), generation);

    return true;
}
