#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.Context.h"

PGETENABLEDXSTATEFEATURES _GetEnabledXStateFeatures = NULL;
PINITIALIZECONTEXT _InitializeContext = NULL;
PGETXSTATEFEATURESMASK _GetXStateFeaturesMask = NULL;
LOCATEXSTATEFEATURE _LocateXStateFeature = NULL;
SETXSTATEFEATURESMASK _SetXStateFeaturesMask = NULL;

bool _SetFullContextDataEx(HANDLE hActiveThread, TITAN_ENGINE_CONTEXT_t* titcontext, bool AVX_PRIORITY)
{
    CONTEXT DBGContext;
    memset(&DBGContext, 0, sizeof(DBGContext));

    DBGContext.ContextFlags = CONTEXT_ALL | CONTEXT_FLOATING_POINT | CONTEXT_EXTENDED_REGISTERS;

    if(!GetThreadContext(hActiveThread, &DBGContext))
    {
        ResumeThread(hActiveThread);
        return false;
    }

    DBGContext.EFlags = (DWORD)titcontext->eflags;
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

    for(int i = 0; i < 8; i++)
        memcpy(& DBGContext.FltSave.FloatRegisters[i], &(titcontext->RegisterArea[i * 10]), 10);

    for(int i = 0; i < 16; i++)
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
    for(int i = 0; i < 8; i++)
        memcpy(& DBGContext.ExtendedRegisters[(10 + i) * 16], &(titcontext->XmmRegisters[i]), 16);
#endif

    bool returnf = SetThreadContext(hActiveThread, & DBGContext) ? true : false;

    if(AVX_PRIORITY)
        SetAVXContext(hActiveThread, titcontext);

    return returnf;
}

bool _GetFullContextDataEx(HANDLE hActiveThread, TITAN_ENGINE_CONTEXT_t* titcontext, bool avx)
{
    CONTEXT DBGContext;
    memset(&DBGContext, 0, sizeof(CONTEXT));
    memset(titcontext, 0, sizeof(TITAN_ENGINE_CONTEXT_t));

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

    for(int i = 0; i < 8; i++)
        memcpy(&(titcontext->RegisterArea[i * 10]), & DBGContext.FltSave.FloatRegisters[i], 10);

    for(int i = 0; i < 16; i++)
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
    for(int i = 0; i < 8; i++)
        memcpy(&(titcontext->XmmRegisters[i]),  & DBGContext.ExtendedRegisters[(10 + i) * 16], 16);
#endif

    if(avx)
        GetAVXContext(hActiveThread, titcontext);

    return true;
}

bool InitXState()
{
    static bool init = false;
    if(!init)
    {
        init = true;
        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        if(kernel32 != NULL)
        {
            _GetEnabledXStateFeatures = (PGETENABLEDXSTATEFEATURES)GetProcAddress(kernel32, "GetEnabledXStateFeatures");
            _InitializeContext = (PINITIALIZECONTEXT)GetProcAddress(kernel32, "InitializeContext");
            _GetXStateFeaturesMask = (PGETXSTATEFEATURESMASK)GetProcAddress(kernel32, "GetXStateFeaturesMask");
            _LocateXStateFeature = (LOCATEXSTATEFEATURE)GetProcAddress(kernel32, "LocateXStateFeature");
            _SetXStateFeaturesMask = (SETXSTATEFEATURESMASK)GetProcAddress(kernel32, "SetXStateFeaturesMask");
        }
    }
    return (_GetEnabledXStateFeatures != NULL &&
            _InitializeContext != NULL &&
            _GetXStateFeaturesMask != NULL &&
            _LocateXStateFeature != NULL &&
            _SetXStateFeaturesMask != NULL);
}