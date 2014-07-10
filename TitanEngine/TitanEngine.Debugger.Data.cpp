#include "stdafx.h"
#include "definitions.h"
#include "Global.Debugger.h"

//TODO: never changed LOL
static DWORD CurrentExceptionsNumber = 0;

__declspec(dllexport) void TITCALL ClearExceptionNumber()
{
    CurrentExceptionsNumber = 0;
}

__declspec(dllexport) long TITCALL CurrentExceptionNumber()
{
    return(CurrentExceptionsNumber);
}

__declspec(dllexport) void* TITCALL GetDebugData()
{
    return(&DBGEvent);
}

__declspec(dllexport) void* TITCALL GetTerminationData()
{
    return(&TerminateDBGEvent);
}

__declspec(dllexport) long TITCALL GetExitCode()
{
    return(ProcessExitCode);
}

__declspec(dllexport) ULONG_PTR TITCALL GetDebuggedDLLBaseAddress()
{
    return((ULONG_PTR)DebugDebuggingDLLBase);
}

__declspec(dllexport) ULONG_PTR TITCALL GetDebuggedFileBaseAddress()
{
    return (ULONG_PTR)DebugDebuggingMainModuleBase;
}

__declspec(dllexport) void TITCALL SetCustomHandler(DWORD ExceptionId, LPVOID CallBack)
{
    if(ExceptionId == UE_CH_BREAKPOINT)
    {
        DBGCustomHandler->chBreakPoint = (ULONG_PTR)CallBack;
    }
    else if(ExceptionId == UE_CH_SINGLESTEP)
    {
        DBGCustomHandler->chSingleStep = (ULONG_PTR)CallBack;
    }
    else if(ExceptionId == UE_CH_ACCESSVIOLATION)
    {
        DBGCustomHandler->chAccessViolation = (ULONG_PTR)CallBack;
    }
    else if(ExceptionId == UE_CH_ILLEGALINSTRUCTION)
    {
        DBGCustomHandler->chIllegalInstruction = (ULONG_PTR)CallBack;
    }
    else if(ExceptionId == UE_CH_NONCONTINUABLEEXCEPTION)
    {
        DBGCustomHandler->chNonContinuableException = (ULONG_PTR)CallBack;
    }
    else if(ExceptionId == UE_CH_ARRAYBOUNDSEXCEPTION)
    {
        DBGCustomHandler->chArrayBoundsException = (ULONG_PTR)CallBack;
    }
    else if(ExceptionId == UE_CH_FLOATDENORMALOPERAND)
    {
        DBGCustomHandler->chFloatDenormalOperand = (ULONG_PTR)CallBack;
    }
    else if(ExceptionId == UE_CH_FLOATDEVIDEBYZERO)
    {
        DBGCustomHandler->chFloatDevideByZero = (ULONG_PTR)CallBack;
    }
    else if(ExceptionId == UE_CH_INTEGERDEVIDEBYZERO)
    {
        DBGCustomHandler->chIntegerDevideByZero = (ULONG_PTR)CallBack;
    }
    else if(ExceptionId == UE_CH_INTEGEROVERFLOW)
    {
        DBGCustomHandler->chIntegerOverflow = (ULONG_PTR)CallBack;
    }
    else if(ExceptionId == UE_CH_PRIVILEGEDINSTRUCTION)
    {
        DBGCustomHandler->chPrivilegedInstruction = (ULONG_PTR)CallBack;
    }
    else if(ExceptionId == UE_CH_PAGEGUARD)
    {
        DBGCustomHandler->chPageGuard = (ULONG_PTR)CallBack;
    }
    else if(ExceptionId == UE_CH_EVERYTHINGELSE)
    {
        DBGCustomHandler->chEverythingElse = (ULONG_PTR)CallBack;
    }
    else if(ExceptionId == UE_CH_CREATETHREAD)
    {
        DBGCustomHandler->chCreateThread = (ULONG_PTR)CallBack;
    }
    else if(ExceptionId == UE_CH_EXITTHREAD)
    {
        DBGCustomHandler->chExitThread = (ULONG_PTR)CallBack;
    }
    else if(ExceptionId == UE_CH_CREATEPROCESS)
    {
        DBGCustomHandler->chCreateProcess = (ULONG_PTR)CallBack;
    }
    else if(ExceptionId == UE_CH_EXITPROCESS)
    {
        DBGCustomHandler->chExitProcess = (ULONG_PTR)CallBack;
    }
    else if(ExceptionId == UE_CH_LOADDLL)
    {
        DBGCustomHandler->chLoadDll = (ULONG_PTR)CallBack;
    }
    else if(ExceptionId == UE_CH_UNLOADDLL)
    {
        DBGCustomHandler->chUnloadDll = (ULONG_PTR)CallBack;
    }
    else if(ExceptionId == UE_CH_OUTPUTDEBUGSTRING)
    {
        DBGCustomHandler->chOutputDebugString = (ULONG_PTR)CallBack;
    }
    else if(ExceptionId == UE_CH_AFTEREXCEPTIONPROCESSING)
    {
        DBGCustomHandler->chAfterException = (ULONG_PTR)CallBack;
    }
    else if(ExceptionId == UE_CH_SYSTEMBREAKPOINT)
    {
        DBGCustomHandler->chSystemBreakpoint = (ULONG_PTR)CallBack;
    }
    else if(ExceptionId == UE_CH_UNHANDLEDEXCEPTION)
    {
        DBGCustomHandler->chUnhandledException = (ULONG_PTR)CallBack;
    }
    else if(ExceptionId == UE_CH_RIPEVENT)
    {
        DBGCustomHandler->chRipEvent = (ULONG_PTR)CallBack;
    }
    else if(ExceptionId == UE_CH_DEBUGEVENT)
    {
        DBGCustomHandler->chDebugEvent = (ULONG_PTR)CallBack;
    }
}

__declspec(dllexport) PROCESS_INFORMATION* TITCALL TitanGetProcessInformation()
{
    return(&dbgProcessInformation);
}

__declspec(dllexport) STARTUPINFOW* TITCALL TitanGetStartupInformation()
{
    return(&dbgStartupInfo);
}

__declspec(dllexport) bool TITCALL IsFileBeingDebugged()
{
    return(engineFileIsBeingDebugged);
}

__declspec(dllexport) void TITCALL SetErrorModel(bool DisplayErrorMessages)
{

    if(DisplayErrorMessages)
    {
        SetErrorMode(NULL);
    }
    else
    {
        SetErrorMode(SEM_FAILCRITICALERRORS);
    }
}