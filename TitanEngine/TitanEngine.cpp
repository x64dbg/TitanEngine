//
// TitanEngine SDK 2.0.3
// TitanEngine.cpp : Defines the exported functions for the DLL application.
//

// Global.constants
#include "stdafx.h"

// Windows libs
#include <time.h>
#include <stdlib.h>
#include <Imagehlp.h>
#include <Tlhelp32.h>
#include <ShellApi.h>
#include <CommDlg.h>
#include <psapi.h>
#include <intrin.h>
#include <vector>
// Global.Engine:
#include "resource.h"
#include "definitions.h"
// scylla wrapper
#include "scylla_wrapper.h"

//New includes
#include "Global.Engine.h"
#include "Global.Handle.h"
#include "Global.Mapping.h"
#include "Global.Engine.Extension.h"
#include "Global.Engine.Hash.h"
#include "Global.Realigner.h"
#include "Global.Engine.Hider.h"
#include "Global.Threader.h"
#include "Global.Debugger.h"
#include "Global.Breakpoints.h"
#include "Global.Librarian.h"
#include "Global.TLS.h"

#define TE_VER_MAJOR 2
#define TE_VER_MIDDLE 1
#define TE_VER_MINOR 0

/*#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0'" \
						"processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")*/

// Global.variables:



LPVOID expTableData = NULL;
LPVOID expTableDataCWP = NULL;
ULONG_PTR expImageBase = 0;
DWORD expExportNumber = 0;
bool expNamePresent = false;
DWORD expExportAddress[1000];
DWORD expSortedNamePointers[1000];
ULONG_PTR expNamePointers[1000];
DWORD expNameHashes[1000];
WORD expOrdinals[1000];
IMAGE_EXPORT_DIRECTORY expExportData;
int engineCurrentPlatform = UE_PLATFORM_x86;

bool engineBackupTLSx64 = false;

LPVOID engineBackupArrayOfCallBacks = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
DWORD engineBackupNumberOfCallBacks = NULL;
DWORD engineBackupTLSAddress = NULL;
IMAGE_TLS_DIRECTORY32 engineBackupTLSDataX86 = {};
IMAGE_TLS_DIRECTORY64 engineBackupTLSDataX64 = {};


//wchar_t* DebugDebuggingDLLReserveFileName;

ULONG_PTR engineReservedMemoryLeft[UE_MAX_RESERVED_MEMORY_LEFT];
HANDLE engineReservedMemoryProcess = NULL;


//wchar_t szReserveModuleName[512];

// Global.Engine.TraceOEP:
GenericOEPTracerData glbEntryTracerData = {};
// Global.Engine.Dependency:
LPVOID engineDependencyFiles;
LPVOID engineDependencyFilesCWP;
// Global.Engine.Window:
HWND EngineBoxHandle;
HWND EngineWindowHandle;
char szWindowUnpackerName[128];
char szWindowUnpackerTitle[128];
char szWindowUnpackerLongTitle[128];
char szWindowUnpackerAuthor[128];
void* EngineStartUnpackingCallBack;
// Global.Engine.Simplify
bool EngineUnpackerOptionLogData;
bool EngineUnpackerFileImporterInit;
bool EngineUnpackerOptionRealingFile;
bool EngineUnpackerOptionMoveOverlay;
bool EngineUnpackerOptionRelocationFix;
ULONG_PTR EngineUnpackerOptionUnpackedOEP;
wchar_t szEngineUnpackerInputFile[MAX_PATH];
wchar_t szEngineUnpackerOutputFile[MAX_PATH];
wchar_t szEngineUnpackerSnapShot1[MAX_PATH];
wchar_t szEngineUnpackerSnapShot2[MAX_PATH];
FILE_STATUS_INFO EngineUnpackerFileStatus = {};
LPPROCESS_INFORMATION pEngineUnpackerProcessHandle;
std::vector<UnpackerInformation> EngineUnpackerBreakInfo;
// Global.Engine.Hooks:
DWORD buffPatchedEntrySize = 0x3000;
void* CwpBuffPatchedEntry;
void* buffPatchedEntry;
std::vector<HOOK_ENTRY> hookEntry;


__declspec(dllexport) void TITCALL ForceClose()
{
    /*wchar_t szTempName[MAX_PATH];
    wchar_t szTempFolder[MAX_PATH];*/
    PPROCESS_ITEM_DATA hListProcessPtr = NULL;
    PTHREAD_ITEM_DATA hListThreadPtr = NULL;
    PLIBRARY_ITEM_DATAW hListLibraryPtr = NULL;

    if(hListProcess != NULL)
    {
        hListProcessPtr = (PPROCESS_ITEM_DATA)hListProcess;
        while(hListProcessPtr->hProcess != NULL)
        {
            __try
            {
                EngineCloseHandle(hListProcessPtr->hFile);
                EngineCloseHandle(hListProcessPtr->hProcess);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {

            }
            hListProcessPtr = (PPROCESS_ITEM_DATA)((ULONG_PTR)hListProcessPtr + sizeof PROCESS_ITEM_DATA);
        }
        RtlZeroMemory(hListProcess, MAX_DEBUG_DATA * sizeof PROCESS_ITEM_DATA);
    }
    if(hListThread != NULL)
    {
        hListThreadPtr = (PTHREAD_ITEM_DATA)hListThread;
        while(hListThreadPtr->hThread != NULL)
        {
            if(hListThreadPtr->hThread != (HANDLE)-1)
            {
                __try
                {
                    if(EngineCloseHandle(hListThreadPtr->hThread))
                    {
                        hListThreadPtr->hThread = NULL;
                        hListThreadPtr->dwThreadId = NULL;
                        hListThreadPtr->ThreadLocalBase = NULL;
                        hListThreadPtr->ThreadStartAddress = NULL;
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    hListThreadPtr->hThread = NULL;
                    hListThreadPtr->dwThreadId = NULL;
                    hListThreadPtr->ThreadLocalBase = NULL;
                    hListThreadPtr->ThreadStartAddress = NULL;
                }
            }
            hListThreadPtr = (PTHREAD_ITEM_DATA)((ULONG_PTR)hListThreadPtr + sizeof THREAD_ITEM_DATA);
        }
        RtlZeroMemory(hListThread, MAX_DEBUG_DATA * sizeof THREAD_ITEM_DATA);
    }
    if(hListLibrary != NULL)
    {
        hListLibraryPtr = (PLIBRARY_ITEM_DATAW)hListLibrary;
        while(hListLibraryPtr->hFile != NULL)
        {
            if(hListLibraryPtr->hFile != (HANDLE)-1)
            {
                if(hListLibraryPtr->hFileMappingView != NULL)
                {
                    UnmapViewOfFile(hListLibraryPtr->hFileMappingView);
                    __try
                    {
                        EngineCloseHandle(hListLibraryPtr->hFileMapping);
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {

                    }
                }
                __try
                {
                    EngineCloseHandle(hListLibraryPtr->hFile);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {

                }
            }
            hListLibraryPtr = (PLIBRARY_ITEM_DATAW)((ULONG_PTR)hListLibraryPtr + sizeof LIBRARY_ITEM_DATAW);
        }
        RtlZeroMemory(hListLibrary, MAX_DEBUG_DATA * sizeof LIBRARY_ITEM_DATAW);
    }
    if(!engineProcessIsNowDetached)
    {
        StopDebug();
    }
    RtlZeroMemory(&dbgProcessInformation, sizeof PROCESS_INFORMATION);
    /*if(DebugDebuggingDLL)
    {
        RtlZeroMemory(&szTempName, sizeof szTempName);
        RtlZeroMemory(&szTempFolder, sizeof szTempFolder);
        if(GetTempPathW(MAX_PATH, szTempFolder) < MAX_PATH)
        {
            if(GetTempFileNameW(szTempFolder, L"DeleteTempFile", GetTickCount(), szTempName))
            {
                DeleteFileW(szTempName);
                if(!MoveFileW(szDebuggerName, szTempName))
                {
                    DeleteFileW(szDebuggerName);
                }
                else
                {
                    DeleteFileW(szTempName);
                }
            }
            RtlZeroMemory(&szTempName, sizeof szTempName);
            if(GetTempFileNameW(szTempFolder, L"DeleteTempFile", GetTickCount() + 1, szTempName))
            {
                DeleteFileW(szTempName);
                if(!MoveFileW(szReserveModuleName, szTempName))
                {
                    DeleteFileW(szReserveModuleName);
                }
                else
                {
                    DeleteFileW(szTempName);
                }
            }
        }
    }*/
    DebugDebuggingDLL = false;
    DebugExeFileEntryPointCallBack = NULL;
}
__declspec(dllexport) void TITCALL StepInto(LPVOID StepCallBack)
{
    ULONG_PTR ueContext = NULL;

    ueContext = (ULONG_PTR)GetContextData(UE_EFLAGS);
    if(!(ueContext & 0x100))
    {
        ueContext = ueContext ^ 0x100;
    }
    SetContextData(UE_EFLAGS, ueContext);
    engineStepActive = true;
    engineStepCallBack = StepCallBack;
    engineStepCount = NULL;
}
__declspec(dllexport) void TITCALL StepOver(LPVOID StepCallBack)
{
    ULONG_PTR ueCurrentPosition = NULL;
#if !defined(_WIN64)
    ueCurrentPosition = (ULONG_PTR)GetContextData(UE_EIP);
#else
    ueCurrentPosition = GetContextData(UE_RIP);
#endif
    unsigned char instr[16];
    ReadProcessMemory(dbgProcessInformation.hProcess, (void*)ueCurrentPosition, instr, sizeof(instr), 0);
    char* DisassembledString=(char*)StaticDisassembleEx(ueCurrentPosition, (LPVOID)instr);
    if(strstr(DisassembledString, "CALL")||strstr(DisassembledString, "REP")||strstr(DisassembledString, "PUSHF"))
    {
        ueCurrentPosition+=StaticLengthDisassemble((void*)instr);
        SetBPX(ueCurrentPosition, UE_BREAKPOINT_TYPE_INT3+UE_SINGLESHOOT, StepCallBack);
    }
    else
        StepInto(StepCallBack);
}

__declspec(dllexport) void TITCALL SingleStep(DWORD StepCount, LPVOID StepCallBack)
{

    ULONG_PTR ueContext = NULL;

    ueContext = (ULONG_PTR)GetContextData(UE_EFLAGS);
    if(!(ueContext & 0x100))
    {
        ueContext = ueContext ^ 0x100;
    }
    SetContextData(UE_EFLAGS, ueContext);
    engineStepActive = true;
    engineStepCount = (int)StepCount;
    engineStepCallBack = StepCallBack;
    engineStepCount--;
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

__declspec(dllexport) bool TITCALL AttachDebugger(DWORD ProcessId, bool KillOnExit, LPVOID DebugInfo, LPVOID CallBack)
{

    typedef void(WINAPI *fDebugSetProcessKillOnExit)(bool KillExitingDebugee);
    fDebugSetProcessKillOnExit myDebugSetProcessKillOnExit;
    LPVOID funcDebugSetProcessKillOnExit = NULL;

    if(ProcessId != NULL && dbgProcessInformation.hProcess == NULL)
    {
        RtlZeroMemory(&BreakPointBuffer, sizeof BreakPointBuffer);
        if(DebugActiveProcess(ProcessId))
        {
            if(KillOnExit)
            {
                funcDebugSetProcessKillOnExit = GetProcAddress(GetModuleHandleA("kernel32.dll"), "DebugSetProcessKillOnExit");
                if(funcDebugSetProcessKillOnExit != NULL)
                {
                    myDebugSetProcessKillOnExit = (fDebugSetProcessKillOnExit)(funcDebugSetProcessKillOnExit);
                    myDebugSetProcessKillOnExit(KillOnExit);
                }
            }
            BreakPointSetCount = 0;
            DebugDebuggingDLL = false;
            DebugAttachedToProcess = true;
            DebugAttachedProcessCallBack = (ULONG_PTR)CallBack;
            engineAttachedProcessDebugInfo = DebugInfo;
            dbgProcessInformation.dwProcessId = ProcessId;
            DebugLoop();
            DebugAttachedToProcess = false;
            DebugAttachedProcessCallBack = NULL;
            return(true);
        }
    }
    else
    {
        return(false);
    }
    return(false);
}
__declspec(dllexport) bool TITCALL DetachDebugger(DWORD ProcessId)
{
    typedef bool(WINAPI *fDebugActiveProcessStop)(DWORD dwProcessId);
    fDebugActiveProcessStop myDebugActiveProcessStop;
    LPVOID funcDebugActiveProcessStop = NULL;
    bool FuncReturn = false;

    if(ProcessId != NULL)
    {
        funcDebugActiveProcessStop = GetProcAddress(GetModuleHandleA("kernel32.dll"), "DebugActiveProcessStop");
        if(funcDebugActiveProcessStop != NULL)
        {
            myDebugActiveProcessStop = (fDebugActiveProcessStop)(funcDebugActiveProcessStop);
            FuncReturn = myDebugActiveProcessStop(ProcessId);
            engineProcessIsNowDetached = true;
            Sleep(250);
        }
        DebugAttachedToProcess = false;
        if(FuncReturn)
        {
            return(true);
        }
        else
        {
            return(false);
        }
    }
    return(false);
}
__declspec(dllexport) bool TITCALL DetachDebuggerEx(DWORD ProcessId)
{

    HANDLE hActiveThread;
    CONTEXT myDBGContext;
    PTHREAD_ITEM_DATA hListThreadPtr = (PTHREAD_ITEM_DATA)hListThread;

    if(hListThreadPtr != NULL)
    {
        ThreaderPauseProcess();
        while(hListThreadPtr->hThread != NULL)
        {
            hActiveThread = OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_QUERY_INFORMATION, false, hListThreadPtr->dwThreadId);
            myDBGContext.ContextFlags = CONTEXT_CONTROL;
            GetThreadContext(hActiveThread, &myDBGContext);
            if((myDBGContext.EFlags & 0x100))
            {
                myDBGContext.EFlags = myDBGContext.EFlags ^ 0x100;
            }
            if(!(myDBGContext.EFlags & 0x10000))
            {
                myDBGContext.EFlags = myDBGContext.EFlags ^ 0x10000;
            }
            SetThreadContext(hActiveThread, &myDBGContext);
            EngineCloseHandle(hActiveThread);
            hListThreadPtr = (PTHREAD_ITEM_DATA)((ULONG_PTR)hListThreadPtr + sizeof THREAD_ITEM_DATA);
        }
        ContinueDebugEvent(DBGEvent.dwProcessId, DBGEvent.dwThreadId, DBG_CONTINUE);
        ThreaderResumeProcess();
        return(DetachDebugger(ProcessId));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) void TITCALL AutoDebugEx(char* szFileName, bool ReserveModuleBase, char* szCommandLine, char* szCurrentFolder, DWORD TimeOut, LPVOID EntryCallBack)
{

    wchar_t* PtrUniFileName = NULL;
    wchar_t uniFileName[MAX_PATH] = {};
    wchar_t* PtrUniCommandLine = NULL;
    wchar_t uniCommandLine[MAX_PATH] = {};
    wchar_t* PtrUniCurrentFolder = NULL;
    wchar_t uniCurrentFolder[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        MultiByteToWideChar(CP_ACP, NULL, szCommandLine, lstrlenA(szCommandLine)+1, uniCommandLine, sizeof(uniCommandLine)/(sizeof(uniCommandLine[0])));
        MultiByteToWideChar(CP_ACP, NULL, szCurrentFolder, lstrlenA(szCurrentFolder)+1, uniCurrentFolder, sizeof(uniCurrentFolder)/(sizeof(uniCurrentFolder[0])));
        if(szFileName != NULL)
        {
            PtrUniFileName = &uniFileName[0];
        }
        if(szCommandLine != NULL)
        {
            PtrUniCommandLine = &uniCommandLine[0];
        }
        if(szCurrentFolder != NULL)
        {
            PtrUniCurrentFolder = &uniCurrentFolder[0];
        }
        return(AutoDebugExW(PtrUniFileName, ReserveModuleBase, PtrUniCommandLine, PtrUniCurrentFolder, TimeOut, EntryCallBack));
    }
}
__declspec(dllexport) void TITCALL AutoDebugExW(wchar_t* szFileName, bool ReserveModuleBase, wchar_t* szCommandLine, wchar_t* szCurrentFolder, DWORD TimeOut, LPVOID EntryCallBack)
{
    DebugReserveModuleBase = NULL;
    DWORD ThreadId;
    DWORD ExitCode = 0;
    HANDLE hSecondThread;
    bool FileIsDll = false;
#if !defined(_WIN64)
    PE32Struct PEStructure;
#else
    PE64Struct PEStructure;
#endif

    if(TimeOut == NULL)
    {
        TimeOut = INFINITE;
    }

    if(szFileName != NULL)
    {
        RtlZeroMemory(&expertDebug, sizeof ExpertDebug);
        expertDebug.ExpertModeActive = true;
        expertDebug.szFileName = szFileName;
        expertDebug.szCommandLine = szCommandLine;
        expertDebug.szCurrentFolder = szCurrentFolder;
        expertDebug.ReserveModuleBase = ReserveModuleBase;
        expertDebug.EntryCallBack = EntryCallBack;
        GetPE32DataExW(szFileName, (LPVOID)&PEStructure);
        if(PEStructure.Characteristics & 0x2000)
        {
            FileIsDll = true;
        }
        SetDebugLoopTimeOut(TimeOut);
        hSecondThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)DebugLoopInSecondThread, (LPVOID)FileIsDll, NULL, &ThreadId);
        WaitForSingleObject(hSecondThread, INFINITE);
        if(GetExitCodeThread(hSecondThread, &ExitCode))
        {
            if(ExitCode == -1)
            {
                ForceClose();
            }
        }
        RtlZeroMemory(&expertDebug, sizeof ExpertDebug);
        SetDebugLoopTimeOut(INFINITE);
    }
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
// Global.FindOEP.functions:
void GenericOEPVirtualProtectHit()
{

    PBreakPointDetail bpxList = (PBreakPointDetail)BreakPointBuffer;
    MEMORY_BASIC_INFORMATION MemInfo;
    DWORD MaximumBreakPoints = 0;
    DWORD NewProtect = 0;
    DWORD OldProtect = 0;

    while(MaximumBreakPoints < MAXIMUM_BREAKPOINTS)
    {
        bpxList = (PBreakPointDetail)((ULONG_PTR)bpxList + sizeof BreakPointDetail);
        if(bpxList->BreakPointType == UE_MEMORY && bpxList->BreakPointActive == UE_BPXACTIVE)
        {
            VirtualQueryEx(dbgProcessInformation.hProcess, (LPVOID)bpxList->BreakPointAddress, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
            OldProtect = MemInfo.Protect;
            if(!(OldProtect & PAGE_GUARD))
            {
                NewProtect = OldProtect ^ PAGE_GUARD;
                VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxList->BreakPointAddress, bpxList->BreakPointSize, NewProtect, &OldProtect);
            }
        }
        MaximumBreakPoints++;
    }
}
void GenericOEPTraceHit()
{

    char* szInstructionType;
    typedef void(TITCALL *fEPCallBack)();
    fEPCallBack myEPCallBack = (fEPCallBack)glbEntryTracerData.EPCallBack;
    LPDEBUG_EVENT myDbgEvent = (LPDEBUG_EVENT)GetDebugData();

    glbEntryTracerData.MemoryAccessedFrom = (ULONG_PTR)GetContextData(UE_CIP);
    glbEntryTracerData.MemoryAccessed = myDbgEvent->u.Exception.ExceptionRecord.ExceptionInformation[1];
    glbEntryTracerData.AccessType = myDbgEvent->u.Exception.ExceptionRecord.ExceptionInformation[0];
    szInstructionType = (char*)DisassembleEx(dbgProcessInformation.hProcess, (void*)glbEntryTracerData.MemoryAccessedFrom, true);
    StepInto(&GenericOEPTraceHited);
}
void GenericOEPTraceHited()
{

    int i;
    void* lpHashBuffer;
    bool FakeEPDetected = false;
    ULONG_PTR NumberOfBytesRW;
    LPDEBUG_EVENT myDbgEvent = (LPDEBUG_EVENT)GetDebugData();
    typedef void(TITCALL *fEPCallBack)();
    fEPCallBack myEPCallBack = (fEPCallBack)glbEntryTracerData.EPCallBack;
    PMEMORY_COMPARE_HANDLER myCmpHandler;
    ULONG_PTR memBpxAddress;
    ULONG_PTR memBpxSize;
    DWORD originalHash;
    DWORD currentHash;

    if(myDbgEvent->u.Exception.ExceptionRecord.ExceptionCode == STATUS_SINGLE_STEP)
    {
        if(glbEntryTracerData.MemoryAccessed >= glbEntryTracerData.LoadedImageBase && glbEntryTracerData.MemoryAccessed <= glbEntryTracerData.LoadedImageBase + glbEntryTracerData.SizeOfImage)
        {
            for(i = 0; i < glbEntryTracerData.SectionNumber; i++)
            {
                if(glbEntryTracerData.MemoryAccessed >= glbEntryTracerData.SectionData[i].SectionVirtualOffset + glbEntryTracerData.LoadedImageBase && glbEntryTracerData.MemoryAccessed < glbEntryTracerData.SectionData[i].SectionVirtualOffset + glbEntryTracerData.SectionData[i].SectionVirtualSize + glbEntryTracerData.LoadedImageBase)
                {
                    if(glbEntryTracerData.AccessType == 1)
                    {
                        glbEntryTracerData.SectionData[i].AccessedAlready = true;
                    }
                    if(glbEntryTracerData.MemoryAccessedFrom >= glbEntryTracerData.SectionData[i].SectionVirtualOffset + glbEntryTracerData.LoadedImageBase && glbEntryTracerData.MemoryAccessedFrom <= glbEntryTracerData.SectionData[i].SectionVirtualOffset + glbEntryTracerData.SectionData[i].SectionVirtualSize + glbEntryTracerData.LoadedImageBase)
                    {
                        if(i != glbEntryTracerData.OriginalEntryPointNum)
                        {
                            glbEntryTracerData.SectionData[i].AccessedAlready = true;
                        }
                        lpHashBuffer = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
                        memBpxAddress = (glbEntryTracerData.MemoryAccessed / 0x1000) * 0x1000;
                        memBpxSize = glbEntryTracerData.SectionData[i].SectionVirtualOffset + glbEntryTracerData.SectionData[i].SectionVirtualSize + glbEntryTracerData.LoadedImageBase - memBpxAddress;
                        if(memBpxSize > 0x1000)
                        {
                            memBpxSize = 0x1000;
                        }
                        if(ReadProcessMemory(dbgProcessInformation.hProcess, (void*)(memBpxAddress), lpHashBuffer, memBpxSize, &NumberOfBytesRW))
                        {
                            currentHash = EngineHashMemory((char*)lpHashBuffer, (DWORD)memBpxSize, NULL);
                            originalHash = EngineHashMemory((char*)((ULONG_PTR)glbEntryTracerData.SectionData[i].AllocatedSection + memBpxAddress - glbEntryTracerData.LoadedImageBase - glbEntryTracerData.SectionData[i].SectionVirtualOffset), (DWORD)memBpxSize, NULL);
                            if(ReadProcessMemory(dbgProcessInformation.hProcess, (void*)(glbEntryTracerData.CurrentIntructionPointer), lpHashBuffer, MAXIMUM_INSTRUCTION_SIZE, &NumberOfBytesRW))
                            {
                                myCmpHandler = (PMEMORY_COMPARE_HANDLER)(lpHashBuffer);
                                if(myCmpHandler->Array.bArrayEntry[0] == 0xC3) 		// RET
                                {
                                    FakeEPDetected = true;
                                }
                                else if(myCmpHandler->Array.bArrayEntry[0] == 0x33 && myCmpHandler->Array.bArrayEntry[1] == 0xC0 && myCmpHandler->Array.bArrayEntry[2] == 0xC3) 	// XOR EAX,EAX; RET
                                {
                                    FakeEPDetected = true;
                                }
                            }
                            VirtualFree(lpHashBuffer, NULL, MEM_RELEASE);
                            if(currentHash != originalHash && glbEntryTracerData.SectionData[i].AccessedAlready == true && i != glbEntryTracerData.OriginalEntryPointNum && FakeEPDetected == false)
                            {
                                __try
                                {
                                    if(glbEntryTracerData.EPCallBack != NULL)
                                    {
                                        glbEntryTracerData.CurrentIntructionPointer = (ULONG_PTR)GetContextData(UE_CIP);
                                        SetContextData(UE_CIP, glbEntryTracerData.MemoryAccessedFrom);
                                        DeleteAPIBreakPoint("kernel32.dll", "VirtualProtect", UE_APIEND);
                                        RemoveAllBreakPoints(UE_OPTION_REMOVEALL);
                                        myEPCallBack();
                                        SetContextData(UE_CIP, glbEntryTracerData.CurrentIntructionPointer);
                                    }
                                    else
                                    {
                                        StopDebug();
                                    }
                                }
                                __except(EXCEPTION_EXECUTE_HANDLER)
                                {
                                    StopDebug();
                                }
                            }
                        }
                    }
                    else
                    {
                        SetMemoryBPXEx((ULONG_PTR)(glbEntryTracerData.SectionData[i].SectionVirtualOffset + glbEntryTracerData.LoadedImageBase), glbEntryTracerData.SectionData[i].SectionVirtualSize, UE_MEMORY, false, &GenericOEPTraceHit);
                    }
                }
                else
                {
                    SetMemoryBPXEx((ULONG_PTR)(glbEntryTracerData.SectionData[i].SectionVirtualOffset + glbEntryTracerData.LoadedImageBase), glbEntryTracerData.SectionData[i].SectionVirtualSize, UE_MEMORY, false, &GenericOEPTraceHit);
                }
            }
        }
    }
    else
    {
        StopDebug();
    }
}
void GenericOEPLibraryDetailsHit()
{

    int i;
    bool memBreakPointSet = false;
    char szModuleName[2 * MAX_PATH] = {};
#if !defined(_WIN64)
    int inReg = UE_EAX;
#else
    int inReg = UE_RAX;
#endif

    if(GetModuleBaseNameA(dbgProcessInformation.hProcess, (HMODULE)GetContextData(inReg), szModuleName, sizeof szModuleName) > NULL)
    {
        if(lstrcmpiA(szModuleName, "kernel32.dll") != NULL)
        {
            if(glbEntryTracerData.FileIsDLL)
            {
                glbEntryTracerData.LoadedImageBase = (ULONG_PTR)GetDebuggedDLLBaseAddress();
            }
            else
            {
                glbEntryTracerData.LoadedImageBase = (ULONG_PTR)GetDebuggedFileBaseAddress();
            }
            for(i = 0; i < glbEntryTracerData.SectionNumber; i++)
            {
                if(glbEntryTracerData.SectionData[i].SectionAttributes & IMAGE_SCN_MEM_EXECUTE || glbEntryTracerData.SectionData[i].SectionAttributes & IMAGE_SCN_CNT_CODE)
                {
                    SetMemoryBPXEx((ULONG_PTR)(glbEntryTracerData.SectionData[i].SectionVirtualOffset + glbEntryTracerData.LoadedImageBase), glbEntryTracerData.SectionData[i].SectionVirtualSize, UE_MEMORY, false, &GenericOEPTraceHit);
                    memBreakPointSet = true;
                }
            }
            if(!memBreakPointSet)
            {
                StopDebug();
            }
            else
            {
                DeleteAPIBreakPoint("kernel32.dll", "GetModuleHandleW", UE_APIEND);
                DeleteAPIBreakPoint("kernel32.dll", "LoadLibraryExW", UE_APIEND);
            }
        }
    }
}
void GenericOEPTraceInit()
{

    int i;
    void* lpHashBuffer;
    ULONG_PTR NumberOfBytesRW;
    typedef void(TITCALL *fInitCallBack)();
    fInitCallBack myInitCallBack = (fInitCallBack)glbEntryTracerData.InitCallBack;

    if(glbEntryTracerData.FileIsDLL)
    {
        glbEntryTracerData.LoadedImageBase = (ULONG_PTR)GetDebuggedDLLBaseAddress();
    }
    else
    {
        glbEntryTracerData.LoadedImageBase = (ULONG_PTR)GetDebuggedFileBaseAddress();
    }
    for(i = 0; i < glbEntryTracerData.SectionNumber; i++)
    {
        lpHashBuffer = VirtualAlloc(NULL, glbEntryTracerData.SectionData[i].SectionVirtualSize, MEM_COMMIT, PAGE_READWRITE);
        if(lpHashBuffer != NULL)
        {
            if(ReadProcessMemory(dbgProcessInformation.hProcess, (void*)(glbEntryTracerData.SectionData[i].SectionVirtualOffset + glbEntryTracerData.LoadedImageBase), lpHashBuffer, glbEntryTracerData.SectionData[i].SectionVirtualSize, &NumberOfBytesRW))
            {
                glbEntryTracerData.SectionData[i].AllocatedSection = lpHashBuffer;
            }
        }
    }
    SetAPIBreakPoint("kernel32.dll", "VirtualProtect", UE_BREAKPOINT, UE_APIEND, &GenericOEPVirtualProtectHit);
    SetAPIBreakPoint("kernel32.dll", "GetModuleHandleW", UE_BREAKPOINT, UE_APIEND, &GenericOEPLibraryDetailsHit);
    SetAPIBreakPoint("kernel32.dll", "LoadLibraryExW", UE_BREAKPOINT, UE_APIEND, &GenericOEPLibraryDetailsHit);
    if(glbEntryTracerData.InitCallBack != NULL)
    {
        __try
        {
            myInitCallBack();
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            StopDebug();
        }
    }
}
bool GenericOEPFileInitW(wchar_t* szFileName, LPVOID TraceInitCallBack, LPVOID CallBack)
{

    int i;
#if defined(_WIN64)
    PE64Struct PEStruct = {};
#else
    PE32Struct PEStruct = {};
#endif
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;

    if(MapFileExW(szFileName, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        if(GetPE32DataFromMappedFileEx(FileMapVA, &PEStruct))
        {
            RtlZeroMemory(&glbEntryTracerData, sizeof GenericOEPTracerData);
            glbEntryTracerData.OriginalImageBase = PEStruct.ImageBase;
            glbEntryTracerData.OriginalEntryPoint = PEStruct.OriginalEntryPoint;
            glbEntryTracerData.SizeOfImage = PEStruct.NtSizeOfImage;
            glbEntryTracerData.SectionNumber = PEStruct.SectionNumber;
            glbEntryTracerData.FileIsDLL = IsFileDLL(NULL, FileMapVA);
            glbEntryTracerData.OriginalEntryPointNum = GetPE32SectionNumberFromVA(FileMapVA, glbEntryTracerData.OriginalImageBase + glbEntryTracerData.OriginalEntryPoint);
            for(i = 0; i < glbEntryTracerData.SectionNumber; i++)
            {
                glbEntryTracerData.SectionData[i].SectionVirtualOffset = (DWORD)GetPE32DataFromMappedFile(FileMapVA, i, UE_SECTIONVIRTUALOFFSET);
                glbEntryTracerData.SectionData[i].SectionVirtualSize = (DWORD)GetPE32DataFromMappedFile(FileMapVA, i, UE_SECTIONVIRTUALSIZE);
                if(glbEntryTracerData.SectionData[i].SectionVirtualSize % 0x1000 != 0)
                {
                    glbEntryTracerData.SectionData[i].SectionVirtualSize = ((glbEntryTracerData.SectionData[i].SectionVirtualSize / 0x1000) + 1) * 0x1000;
                }
                else
                {
                    glbEntryTracerData.SectionData[i].SectionVirtualSize = (glbEntryTracerData.SectionData[i].SectionVirtualSize / 0x1000) * 0x1000;
                }
                glbEntryTracerData.SectionData[i].SectionAttributes = (DWORD)GetPE32DataFromMappedFile(FileMapVA, i, UE_SECTIONFLAGS);
            }
            glbEntryTracerData.EPCallBack = CallBack;
            glbEntryTracerData.InitCallBack = TraceInitCallBack;
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            if(glbEntryTracerData.FileIsDLL)
            {
                return(false);
            }
            else
            {
                return(true);
            }
        }
        else
        {
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
        }
    }
    return(false);
}
// TitanEngine.FindOEP.functions:
__declspec(dllexport) void TITCALL FindOEPInit()
{
    RemoveAllBreakPoints(UE_OPTION_REMOVEALL);
}
__declspec(dllexport) bool TITCALL FindOEPGenerically(char* szFileName, LPVOID TraceInitCallBack, LPVOID CallBack)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        return(FindOEPGenericallyW(uniFileName, TraceInitCallBack, CallBack));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL FindOEPGenericallyW(wchar_t* szFileName, LPVOID TraceInitCallBack, LPVOID CallBack)
{

    int i;

    if(GenericOEPFileInitW(szFileName, TraceInitCallBack, CallBack))
    {
        InitDebugExW(szFileName, NULL, NULL, &GenericOEPTraceInit);
        DebugLoop();
        for(i = 0; i < glbEntryTracerData.SectionNumber; i++)
        {
            VirtualFree(glbEntryTracerData.SectionData[i].AllocatedSection, NULL, MEM_RELEASE);
        }
    }
    return(false);
}
// TitanEngine.Importer.functions:
__declspec(dllexport) void TITCALL ImporterAddNewDll(char* szDLLName, ULONG_PTR FirstThunk)
{
    wchar_t uniDLLName[MAX_PATH] = {};

    MultiByteToWideChar(CP_ACP, NULL, szDLLName, lstrlenA(szDLLName)+1, uniDLLName, sizeof(uniDLLName)/(sizeof(uniDLLName[0])));

    scylla_addModule(uniDLLName, FirstThunk);
}
__declspec(dllexport) void TITCALL ImporterAddNewAPI(char* szAPIName, ULONG_PTR ThunkValue)
{
    wchar_t uniAPIName[MAX_PATH] = {};

    MultiByteToWideChar(CP_ACP, NULL, szAPIName, lstrlenA(szAPIName)+1, uniAPIName, sizeof(uniAPIName)/(sizeof(uniAPIName[0])));

    scylla_addImport(uniAPIName, ThunkValue);
}
__declspec(dllexport) void TITCALL ImporterAddNewOrdinalAPI(ULONG_PTR OrdinalNumber, ULONG_PTR ThunkValue)
{

    if(OrdinalNumber & IMAGE_ORDINAL_FLAG)
    {
        OrdinalNumber = OrdinalNumber ^ IMAGE_ORDINAL_FLAG;
        ImporterAddNewAPI((char*)OrdinalNumber, ThunkValue);
    }
    else
    {
        ImporterAddNewAPI((char*)OrdinalNumber, ThunkValue);
    }
}
__declspec(dllexport) long TITCALL ImporterGetAddedDllCount()
{
    return scylla_getModuleCount();
}
__declspec(dllexport) long TITCALL ImporterGetAddedAPICount()
{
    return scylla_getImportCount();
}
__declspec(dllexport) bool TITCALL ImporterExportIAT(ULONG_PTR StorePlace, ULONG_PTR FileMapVA, HANDLE hFileMap)
{
    if(scylla_fixMappedDump(StorePlace, FileMapVA, hFileMap) != SCY_ERROR_SUCCESS)
    {
        return false;
    }

    return true;
}
__declspec(dllexport) long TITCALL ImporterEstimatedSize()
{
    return scylla_estimatedIATSize();
}
__declspec(dllexport) bool TITCALL ImporterExportIATEx(char* szDumpFileName, char* szExportFileName, char* szSectionName)
{

    wchar_t uniExportFileName[MAX_PATH] = {};
    wchar_t uniDumpFileName[MAX_PATH] = {};
    wchar_t uniSectionName[MAX_PATH] = {};

    if(szExportFileName != NULL && szDumpFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szExportFileName, lstrlenA(szExportFileName)+1, uniExportFileName, sizeof(uniExportFileName)/(sizeof(uniExportFileName[0])));
        MultiByteToWideChar(CP_ACP, NULL, szDumpFileName, lstrlenA(szDumpFileName)+1, uniDumpFileName, sizeof(uniDumpFileName)/(sizeof(uniDumpFileName[0])));
        MultiByteToWideChar(CP_ACP, NULL, szSectionName, lstrlenA(szSectionName)+1, uniSectionName, sizeof(uniSectionName)/(sizeof(uniSectionName[0])));
        return(ImporterExportIATExW(uniDumpFileName, uniExportFileName, uniSectionName));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL ImporterExportIATExW(wchar_t* szDumpFileName, wchar_t* szExportFileName, wchar_t* szSectionName)
{
    if(scylla_fixDump(szDumpFileName, szExportFileName, szSectionName) != SCY_ERROR_SUCCESS)
    {
        return false;
    }

    return true;
}
__declspec(dllexport) long long TITCALL ImporterFindAPIWriteLocation(char* szAPIName)
{
    return(scylla_findImportWriteLocation(szAPIName));
}
__declspec(dllexport) long long TITCALL ImporterFindOrdinalAPIWriteLocation(ULONG_PTR OrdinalNumber)
{
    return(scylla_findOrdinalImportWriteLocation(OrdinalNumber));
}
__declspec(dllexport) long long TITCALL ImporterFindAPIByWriteLocation(ULONG_PTR APIWriteLocation)
{
    return(scylla_findImportNameByWriteLocation(APIWriteLocation));
}
__declspec(dllexport) long long TITCALL ImporterFindDLLByWriteLocation(ULONG_PTR APIWriteLocation)
{
    return scylla_findModuleNameByWriteLocation(APIWriteLocation);
}
__declspec(dllexport) void* TITCALL ImporterGetDLLName(ULONG_PTR APIAddress)
{
    return((LPVOID)EngineGlobalAPIHandler(NULL, NULL, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_DLLNAME));
}
__declspec(dllexport) void* TITCALL ImporterGetAPIName(ULONG_PTR APIAddress)
{
    return((LPVOID)EngineGlobalAPIHandler(NULL, NULL, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_APINAME));
}
__declspec(dllexport) long long TITCALL ImporterGetAPIOrdinalNumber(ULONG_PTR APIAddress)
{
    return((long)EngineGlobalAPIHandler(NULL, NULL, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_API_ORDINAL_NUMBER));
}
__declspec(dllexport) void* TITCALL ImporterGetAPINameEx(ULONG_PTR APIAddress, ULONG_PTR DLLBasesList)
{
    return((LPVOID)EngineGlobalAPIHandler(NULL, DLLBasesList, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_APINAME));
}
__declspec(dllexport) long long TITCALL ImporterGetRemoteAPIAddress(HANDLE hProcess, ULONG_PTR APIAddress)
{
    return((ULONG_PTR)EngineGlobalAPIHandler(hProcess, NULL, APIAddress, NULL, UE_OPTION_IMPORTER_REALIGN_APIADDRESS));
}
__declspec(dllexport) long long TITCALL ImporterGetRemoteAPIAddressEx(char* szDLLName, char* szAPIName)
{

    int i = 0;
    int j = 0;
    char szAnsiLibraryName[MAX_PATH];
    PLIBRARY_ITEM_DATAW hListLibraryPtr = NULL;
    ULONG_PTR APIFoundAddress = 0;
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_EXPORT_DIRECTORY PEExports;
    PEXPORTED_DATA ExportedFunctions;
    PEXPORTED_DATA ExportedFunctionNames;
    PEXPORTED_DATA_WORD ExportedFunctionOrdinals;
    bool FileIs64 = false;

    hListLibraryPtr = (PLIBRARY_ITEM_DATAW)hListLibrary;
    if(hListLibraryPtr != NULL)
    {
        while(hListLibraryPtr->hFile != NULL)
        {
            WideCharToMultiByte(CP_ACP, NULL, hListLibraryPtr->szLibraryName, -1, szAnsiLibraryName, sizeof szAnsiLibraryName, NULL, NULL);
            if(lstrcmpiA(szAnsiLibraryName, szDLLName) == NULL)
            {
                __try
                {
                    DOSHeader = (PIMAGE_DOS_HEADER)hListLibraryPtr->hFileMappingView;
                    PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
                    PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
                    if(PEHeader32->OptionalHeader.Magic == 0x10B)
                    {
                        FileIs64 = false;
                    }
                    else if(PEHeader32->OptionalHeader.Magic == 0x20B)
                    {
                        FileIs64 = true;
                    }
                    else
                    {
                        return(NULL);
                    }
                    if(!FileIs64)
                    {
                        PEExports = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)ConvertVAtoFileOffsetEx((ULONG_PTR)hListLibraryPtr->hFileMappingView, GetFileSize(hListLibraryPtr->hFile, NULL), (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, true, true));
                        ExportedFunctions = (PEXPORTED_DATA)((ULONG_PTR)ConvertVAtoFileOffsetEx((ULONG_PTR)hListLibraryPtr->hFileMappingView, GetFileSize(hListLibraryPtr->hFile, NULL), (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase, PEExports->AddressOfFunctions, true, true));
                        ExportedFunctionNames = (PEXPORTED_DATA)((ULONG_PTR)ConvertVAtoFileOffsetEx((ULONG_PTR)hListLibraryPtr->hFileMappingView, GetFileSize(hListLibraryPtr->hFile, NULL), (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase, PEExports->AddressOfNames, true, true));
                        ExportedFunctionOrdinals = (PEXPORTED_DATA_WORD)((ULONG_PTR)ConvertVAtoFileOffsetEx((ULONG_PTR)hListLibraryPtr->hFileMappingView, GetFileSize(hListLibraryPtr->hFile, NULL), (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase, PEExports->AddressOfNameOrdinals, true, true));
                    }
                    else
                    {
                        PEExports = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)ConvertVAtoFileOffsetEx((ULONG_PTR)hListLibraryPtr->hFileMappingView, GetFileSize(hListLibraryPtr->hFile, NULL), (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, true, true));
                        ExportedFunctions = (PEXPORTED_DATA)((ULONG_PTR)ConvertVAtoFileOffsetEx((ULONG_PTR)hListLibraryPtr->hFileMappingView, GetFileSize(hListLibraryPtr->hFile, NULL), (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, PEExports->AddressOfFunctions, true, true));
                        ExportedFunctionNames = (PEXPORTED_DATA)((ULONG_PTR)ConvertVAtoFileOffsetEx((ULONG_PTR)hListLibraryPtr->hFileMappingView, GetFileSize(hListLibraryPtr->hFile, NULL), (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, PEExports->AddressOfNames, true, true));
                        ExportedFunctionOrdinals = (PEXPORTED_DATA_WORD)((ULONG_PTR)ConvertVAtoFileOffsetEx((ULONG_PTR)hListLibraryPtr->hFileMappingView, GetFileSize(hListLibraryPtr->hFile, NULL), (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, PEExports->AddressOfNameOrdinals, true, true));
                    }
                    for(j = 0; j <= (int)PEExports->NumberOfNames; j++)
                    {
                        if(!FileIs64)
                        {
                            if(lstrcmpiA((LPCSTR)szAPIName, (LPCSTR)((ULONG_PTR)ConvertVAtoFileOffsetEx((ULONG_PTR)hListLibraryPtr->hFileMappingView, GetFileSize(hListLibraryPtr->hFile, NULL), (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase, ExportedFunctionNames->ExportedItem, true, true))) == NULL)
                            {
                                ExportedFunctionOrdinals = (PEXPORTED_DATA_WORD)((ULONG_PTR)ExportedFunctionOrdinals + j * 2);
                                ExportedFunctions = (PEXPORTED_DATA)((ULONG_PTR)ExportedFunctions + (ExportedFunctionOrdinals->OrdinalNumber) * 4);
                                APIFoundAddress = ExportedFunctions->ExportedItem + (ULONG_PTR)hListLibraryPtr->BaseOfDll;
                                return((ULONG_PTR)APIFoundAddress);
                            }
                        }
                        else
                        {
                            if(lstrcmpiA((LPCSTR)szAPIName, (LPCSTR)((ULONG_PTR)ConvertVAtoFileOffsetEx((ULONG_PTR)hListLibraryPtr->hFileMappingView, GetFileSize(hListLibraryPtr->hFile, NULL), (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, ExportedFunctionNames->ExportedItem, true, true))) == NULL)
                            {
                                ExportedFunctionOrdinals = (PEXPORTED_DATA_WORD)((ULONG_PTR)ExportedFunctionOrdinals + j * 2);
                                ExportedFunctions = (PEXPORTED_DATA)((ULONG_PTR)ExportedFunctions + (ExportedFunctionOrdinals->OrdinalNumber) * 4);
                                APIFoundAddress = ExportedFunctions->ExportedItem + (ULONG_PTR)hListLibraryPtr->BaseOfDll;
                                return((ULONG_PTR)APIFoundAddress);
                            }
                        }
                        ExportedFunctionNames = (PEXPORTED_DATA)((ULONG_PTR)ExportedFunctionNames + 4);
                    }
                    return(NULL);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    return(NULL);
                }
            }
            hListLibraryPtr = (PLIBRARY_ITEM_DATAW)((ULONG_PTR)hListLibraryPtr + sizeof LIBRARY_ITEM_DATAW);
        }
    }
    return(NULL);
}
__declspec(dllexport) long long TITCALL ImporterGetLocalAPIAddress(HANDLE hProcess, ULONG_PTR APIAddress)
{
    return((ULONG_PTR)EngineGlobalAPIHandler(hProcess, NULL, APIAddress, NULL, UE_OPTION_IMPORTER_REALIGN_LOCAL_APIADDRESS));
}
__declspec(dllexport) void* TITCALL ImporterGetDLLNameFromDebugee(HANDLE hProcess, ULONG_PTR APIAddress)
{
    return((LPVOID)EngineGlobalAPIHandler(hProcess, NULL, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_DLLNAME));
}
__declspec(dllexport) void* TITCALL ImporterGetAPINameFromDebugee(HANDLE hProcess, ULONG_PTR APIAddress)
{
    return((LPVOID)EngineGlobalAPIHandler(hProcess, NULL, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_APINAME));
}
__declspec(dllexport) long long TITCALL ImporterGetAPIOrdinalNumberFromDebugee(HANDLE hProcess, ULONG_PTR APIAddress)
{
    return((long)EngineGlobalAPIHandler(hProcess, NULL, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_API_ORDINAL_NUMBER));
}
__declspec(dllexport) long TITCALL ImporterGetDLLIndexEx(ULONG_PTR APIAddress, ULONG_PTR DLLBasesList)
{
    return((DWORD)EngineGlobalAPIHandler(NULL, DLLBasesList, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_DLLINDEX));
}
__declspec(dllexport) long TITCALL ImporterGetDLLIndex(HANDLE hProcess, ULONG_PTR APIAddress, ULONG_PTR DLLBasesList)
{
    return((DWORD)EngineGlobalAPIHandler(hProcess, DLLBasesList, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_DLLINDEX));
}
__declspec(dllexport) long long TITCALL ImporterGetRemoteDLLBase(HANDLE hProcess, HMODULE LocalModuleBase)
{
    return((ULONG_PTR)EngineGlobalAPIHandler(hProcess, NULL, (ULONG_PTR)LocalModuleBase, NULL, UE_OPTION_IMPORTER_RETURN_DLLBASE));
}
__declspec(dllexport) long long TITCALL ImporterGetRemoteDLLBaseEx(HANDLE hProcess, char* szModuleName)
{

    int i = 1;
    DWORD Dummy = NULL;
    ULONG_PTR EnumeratedModules[0x2000];
    char RemoteDLLName[MAX_PATH];

    if(EnumProcessModules(hProcess, (HMODULE*)EnumeratedModules, 0x2000, &Dummy))
    {
        RtlZeroMemory(&RemoteDLLName, MAX_PATH);
        while(EnumeratedModules[i] != NULL)
        {
            if(GetModuleBaseNameA(hProcess, (HMODULE)EnumeratedModules[i], (LPSTR)RemoteDLLName, MAX_PATH) > NULL)
            {
                if(lstrcmpiA((LPCSTR)RemoteDLLName, (LPCSTR)szModuleName))
                {
                    return((ULONG_PTR)EnumeratedModules[i]);
                }
            }
            i++;
        }
    }
    return(NULL);
}

__declspec(dllexport) bool TITCALL ImporterIsForwardedAPI(HANDLE hProcess, ULONG_PTR APIAddress)
{
    if((ULONG_PTR)EngineGlobalAPIHandler(hProcess, NULL, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_FORWARDER_DLLINDEX) > NULL)
    {
        return(true);
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) void* TITCALL ImporterGetForwardedAPIName(HANDLE hProcess, ULONG_PTR APIAddress)
{
    return((LPVOID)EngineGlobalAPIHandler(hProcess, NULL, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_FORWARDER_APINAME));
}
__declspec(dllexport) void* TITCALL ImporterGetForwardedDLLName(HANDLE hProcess, ULONG_PTR APIAddress)
{
    return((LPVOID)EngineGlobalAPIHandler(hProcess, NULL, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_FORWARDER_DLLNAME));
}
__declspec(dllexport) long TITCALL ImporterGetForwardedDLLIndex(HANDLE hProcess, ULONG_PTR APIAddress, ULONG_PTR DLLBasesList)
{
    return((DWORD)EngineGlobalAPIHandler(hProcess, NULL, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_FORWARDER_DLLINDEX));
}
__declspec(dllexport) long long TITCALL ImporterGetForwardedAPIOrdinalNumber(HANDLE hProcess, ULONG_PTR APIAddress)
{
    return((DWORD)EngineGlobalAPIHandler(hProcess, NULL, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_FORWARDER_API_ORDINAL_NUMBER));
}
__declspec(dllexport) long long TITCALL ImporterGetNearestAPIAddress(HANDLE hProcess, ULONG_PTR APIAddress)
{
    return((ULONG_PTR)EngineGlobalAPIHandler(hProcess, NULL, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_NEAREST_APIADDRESS));
}
__declspec(dllexport) void* TITCALL ImporterGetNearestAPIName(HANDLE hProcess, ULONG_PTR APIAddress)
{
    return((LPVOID)EngineGlobalAPIHandler(hProcess, NULL, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_NEAREST_APINAME));
}
__declspec(dllexport) bool TITCALL ImporterCopyOriginalIAT(char* szOriginalFile, char* szDumpFile)
{

    wchar_t uniDumpFile[MAX_PATH] = {};
    wchar_t uniOriginalFile[MAX_PATH] = {};

    if(szOriginalFile != NULL && szDumpFile != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szDumpFile, lstrlenA(szDumpFile)+1, uniDumpFile, sizeof(uniDumpFile)/(sizeof(uniDumpFile[0])));
        MultiByteToWideChar(CP_ACP, NULL, szOriginalFile, lstrlenA(szOriginalFile)+1, uniOriginalFile, sizeof(uniOriginalFile)/(sizeof(uniOriginalFile[0])));
        return(ImporterCopyOriginalIATW(uniOriginalFile, uniDumpFile));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL ImporterCopyOriginalIATW(wchar_t* szOriginalFile, wchar_t* szDumpFile)
{

    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    BOOL FileIs64;
    HANDLE FileHandle=0;
    DWORD FileSize;
    HANDLE FileMap=0;
    ULONG_PTR FileMapVA;
    HANDLE FileHandle1=0;
    DWORD FileSize1;
    HANDLE FileMap1=0;
    ULONG_PTR FileMapVA1;
    ULONG_PTR IATPointer;
    ULONG_PTR IATWritePointer;
    ULONG_PTR IATCopyStart;
    DWORD IATSection;
    DWORD IATCopySize;
    DWORD IATHeaderData;

    if(MapFileExW(szOriginalFile, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        if(MapFileExW(szDumpFile, UE_ACCESS_ALL, &FileHandle1, &FileSize1, &FileMap1, &FileMapVA1, NULL))
        {
            DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
            if(EngineValidateHeader(FileMapVA, FileHandle, NULL, DOSHeader, true))
            {
                PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
                PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
                if(PEHeader32->OptionalHeader.Magic == 0x10B)
                {
                    FileIs64 = false;
                }
                else if(PEHeader32->OptionalHeader.Magic == 0x20B)
                {
                    FileIs64 = true;
                }
                else
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    UnMapFileEx(FileHandle1, FileSize1, FileMap1, FileMapVA1);
                    return(false);
                }
                if(!FileIs64)
                {
                    IATPointer = (ULONG_PTR)(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + PEHeader32->OptionalHeader.ImageBase);
                }
                else
                {
                    IATPointer = (ULONG_PTR)(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + PEHeader64->OptionalHeader.ImageBase);
                }
                IATSection = GetPE32SectionNumberFromVA(FileMapVA, IATPointer);
                IATPointer = (ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, IATPointer, true);
                if((int)IATSection >= NULL)
                {
                    IATWritePointer = (ULONG_PTR)GetPE32DataFromMappedFile(FileMapVA1, IATSection, UE_SECTIONRAWOFFSET) + FileMapVA1;
                    IATCopyStart = (ULONG_PTR)GetPE32DataFromMappedFile(FileMapVA, IATSection, UE_SECTIONRAWOFFSET) + FileMapVA;
                    IATCopySize = (DWORD)GetPE32DataFromMappedFile(FileMapVA1, IATSection, UE_SECTIONRAWSIZE);
                    __try
                    {
                        RtlMoveMemory((LPVOID)IATWritePointer, (LPVOID)IATCopyStart, IATCopySize);
                        IATHeaderData = (DWORD)GetPE32DataFromMappedFile(FileMapVA, NULL, UE_IMPORTTABLEADDRESS);
                        SetPE32DataForMappedFile(FileMapVA1, NULL, UE_IMPORTTABLEADDRESS, (ULONG_PTR)IATHeaderData);
                        IATHeaderData = (DWORD)GetPE32DataFromMappedFile(FileMapVA, NULL, UE_IMPORTTABLESIZE);
                        SetPE32DataForMappedFile(FileMapVA1, NULL, UE_IMPORTTABLESIZE, (ULONG_PTR)IATHeaderData);
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        UnMapFileEx(FileHandle1, FileSize1, FileMap1, FileMapVA1);
                        return(true);
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        UnMapFileEx(FileHandle1, FileSize1, FileMap1, FileMapVA1);
                        return(false);
                    }
                }
            }
            UnMapFileEx(FileHandle1, FileSize1, FileMap1, FileMapVA1);
        }
        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
    }

    return(false);
}
__declspec(dllexport) bool TITCALL ImporterLoadImportTable(char* szFileName)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        return(ImporterLoadImportTableW(uniFileName));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL ImporterLoadImportTableW(wchar_t* szFileName)
{
    //TODO scylla enable
    return false;
    /*
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_IMPORT_DESCRIPTOR ImportIID;
    PIMAGE_THUNK_DATA32 ThunkData32;
    PIMAGE_THUNK_DATA64 ThunkData64;
    ULONG_PTR CurrentThunk;
    BOOL FileIs64;
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;

    if(MapFileExW(szFileName, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
        if(EngineValidateHeader(FileMapVA, FileHandle, NULL, DOSHeader, true))
        {
            PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            if(PEHeader32->OptionalHeader.Magic == 0x10B)
            {
                FileIs64 = false;
            }
            else if(PEHeader32->OptionalHeader.Magic == 0x20B)
            {
                FileIs64 = true;
            }
            else
            {
                UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                return(false);
            }
            if(!FileIs64)
            {
                if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != NULL)
                {
                    ImporterInit(MAX_IMPORT_ALLOC, (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase);
                    ImportIID = (PIMAGE_IMPORT_DESCRIPTOR)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + PEHeader32->OptionalHeader.ImageBase), true);
                    __try
                    {
                        while(ImportIID->FirstThunk != NULL)
                        {
                            ImporterAddNewDll((char*)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((ULONG_PTR)ImportIID->Name + PEHeader32->OptionalHeader.ImageBase), true), NULL);
                            if(ImportIID->OriginalFirstThunk != NULL)
                            {
                                ThunkData32 = (PIMAGE_THUNK_DATA32)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((ULONG_PTR)ImportIID->OriginalFirstThunk + PEHeader32->OptionalHeader.ImageBase), true);
                                CurrentThunk = (ULONG_PTR)ImportIID->FirstThunk;
                            }
                            else
                            {
                                ThunkData32 = (PIMAGE_THUNK_DATA32)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((ULONG_PTR)ImportIID->FirstThunk + PEHeader32->OptionalHeader.ImageBase), true);
                                CurrentThunk = (ULONG_PTR)ImportIID->FirstThunk;
                            }
                            while(ThunkData32->u1.AddressOfData != NULL)
                            {
                                if(ThunkData32->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
                                {
                                    ImporterAddNewAPI((char*)(ThunkData32->u1.Ordinal ^ IMAGE_ORDINAL_FLAG32), (ULONG_PTR)CurrentThunk + PEHeader32->OptionalHeader.ImageBase);
                                }
                                else
                                {
                                    ImporterAddNewAPI((char*)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((ULONG_PTR)ThunkData32->u1.AddressOfData + 2 + PEHeader32->OptionalHeader.ImageBase), true), (ULONG_PTR)CurrentThunk + PEHeader32->OptionalHeader.ImageBase);
                                }
                                CurrentThunk = CurrentThunk + 4;
                                ThunkData32 = (PIMAGE_THUNK_DATA32)((ULONG_PTR)ThunkData32 + sizeof IMAGE_THUNK_DATA32);
                            }
                            ImportIID = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)ImportIID + sizeof IMAGE_IMPORT_DESCRIPTOR);
                        }
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(true);
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        ImporterCleanup();
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(false);
                    }
                }
            }
            else
            {
                if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != NULL)
                {
                    ImporterInit(MAX_IMPORT_ALLOC, (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase);
                    ImportIID = (PIMAGE_IMPORT_DESCRIPTOR)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + PEHeader64->OptionalHeader.ImageBase), true);
                    __try
                    {
                        while(ImportIID->FirstThunk != NULL)
                        {
                            ImporterAddNewDll((char*)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((ULONG_PTR)ImportIID->Name + PEHeader64->OptionalHeader.ImageBase), true), NULL);
                            if(ImportIID->OriginalFirstThunk != NULL)
                            {
                                ThunkData64 = (PIMAGE_THUNK_DATA64)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((ULONG_PTR)ImportIID->OriginalFirstThunk + PEHeader64->OptionalHeader.ImageBase), true);
                                CurrentThunk = (ULONG_PTR)ImportIID->OriginalFirstThunk;
                            }
                            else
                            {
                                ThunkData64 = (PIMAGE_THUNK_DATA64)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((ULONG_PTR)ImportIID->FirstThunk + PEHeader64->OptionalHeader.ImageBase), true);
                                CurrentThunk = (ULONG_PTR)ImportIID->FirstThunk;
                            }
                            while(ThunkData64->u1.AddressOfData != NULL)
                            {
                                if(ThunkData64->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                                {
                                    ImporterAddNewAPI((char*)(ThunkData64->u1.Ordinal ^ (ULONG_PTR)IMAGE_ORDINAL_FLAG64), (ULONG_PTR)CurrentThunk + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase);
                                }
                                else
                                {
                                    ImporterAddNewAPI((char*)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((ULONG_PTR)ThunkData64->u1.AddressOfData + 2 + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase), true), (ULONG_PTR)CurrentThunk + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase);
                                }
                                CurrentThunk = CurrentThunk + 8;
                                ThunkData64 = (PIMAGE_THUNK_DATA64)((ULONG_PTR)ThunkData64 + sizeof IMAGE_THUNK_DATA64);
                            }
                            ImportIID = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)ImportIID + sizeof IMAGE_IMPORT_DESCRIPTOR);
                        }
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(true);
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        ImporterCleanup();
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(false);
                    }
                }
            }
        }
        else
        {
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            return(false);
        }
    }
    else
    {
        return(false);
    }
    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
    return(false);
    */
}
__declspec(dllexport) bool TITCALL ImporterMoveOriginalIAT(char* szOriginalFile, char* szDumpFile, char* szSectionName)
{
    /*
    if(ImporterLoadImportTable(szOriginalFile))
    {
        return(ImporterExportIATEx(szDumpFile, szSectionName));
    }*/
    return(false);
}
__declspec(dllexport) bool TITCALL ImporterMoveOriginalIATW(wchar_t* szOriginalFile, wchar_t* szDumpFile, char* szSectionName)
{
    /*
    if(ImporterLoadImportTableW(szOriginalFile))
    {
        return(ImporterExportIATExW(szDumpFile, szSectionName));
    }*/
    return(false);
}
__declspec(dllexport) void TITCALL ImporterAutoSearchIAT(DWORD ProcessId, char* szFileName, ULONG_PTR SearchStart, LPVOID pIATStart, LPVOID pIATSize)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        return(ImporterAutoSearchIATW(ProcessId, uniFileName, SearchStart, pIATStart, pIATSize));
    }
}
__declspec(dllexport) void TITCALL ImporterAutoSearchIATW(DWORD ProcessId, wchar_t* szFileName, ULONG_PTR SearchStart, LPVOID pIATStart, LPVOID pIATSize)
{
    ULONG_PTR iatStart = NULL;
    DWORD iatSize = NULL;

    scylla_searchIAT(ProcessId, iatStart, iatSize, SearchStart, false);

    //we also try to automatically read imports so following call to ExportIAT has a chance
    if(iatStart != NULL && iatSize != NULL)
    {
        scylla_getImports(iatStart, iatSize, ProcessId);
    }

    RtlMoveMemory(pIATStart, &iatStart, sizeof ULONG_PTR);
    RtlMoveMemory(pIATSize, &iatSize, sizeof ULONG_PTR);

    return;
}
__declspec(dllexport) void TITCALL ImporterAutoSearchIATEx(DWORD ProcessId, ULONG_PTR ImageBase, ULONG_PTR SearchStart, LPVOID pIATStart, LPVOID pIATSize)
{

    wchar_t szTempName[MAX_PATH];
    wchar_t szTempFolder[MAX_PATH];

    RtlZeroMemory(&szTempName, sizeof szTempName);
    RtlZeroMemory(&szTempFolder, sizeof szTempFolder);
    if(GetTempPathW(MAX_PATH, szTempFolder) < MAX_PATH)
    {
        if(GetTempFileNameW(szTempFolder, L"DumpTemp", GetTickCount() + 102, szTempName))
        {
            HANDLE hProcess = OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION, FALSE, ProcessId);

            DumpProcessW(hProcess, (LPVOID)ImageBase, szTempName, NULL);
            ImporterAutoSearchIATW(ProcessId, szTempName, SearchStart, pIATStart, pIATSize);
            DeleteFileW(szTempName);
        }
    }
}
__declspec(dllexport) void TITCALL ImporterEnumAddedData(LPVOID EnumCallBack)
{
    return scylla_enumImportTree(EnumCallBack);
}
__declspec(dllexport) long TITCALL ImporterAutoFixIATEx(DWORD ProcessId, char* szDumpedFile, char* szSectionName, bool DumpRunningProcess, bool RealignFile, ULONG_PTR EntryPointAddress, ULONG_PTR ImageBase, ULONG_PTR SearchStart, bool TryAutoFix, bool FixEliminations, LPVOID UnknownPointerFixCallback)
{

    wchar_t uniDumpedFile[MAX_PATH] = {};
    wchar_t uniSectionName[MAX_PATH] = {};

    if(szDumpedFile != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szDumpedFile, lstrlenA(szDumpedFile)+1, uniDumpedFile, sizeof(uniDumpedFile)/(sizeof(uniDumpedFile[0])));
        MultiByteToWideChar(CP_ACP, NULL, szSectionName, lstrlenA(szSectionName)+1, uniSectionName, sizeof(uniSectionName)/(sizeof(uniSectionName[0])));
        return(ImporterAutoFixIATExW(ProcessId, uniDumpedFile, uniSectionName, DumpRunningProcess, RealignFile, EntryPointAddress, ImageBase, SearchStart, TryAutoFix, FixEliminations, UnknownPointerFixCallback));
    }
    else
    {
        return(NULL);	// Critical error! *just to be safe, but it should never happen!
    }
}
__declspec(dllexport) long TITCALL ImporterAutoFixIATExW(DWORD ProcessId, wchar_t* szDumpedFile, wchar_t* szSectionName, bool DumpRunningProcess, bool RealignFile, ULONG_PTR EntryPointAddress, ULONG_PTR ImageBase, ULONG_PTR SearchStart,  bool TryAutoFix, bool FixEliminations, LPVOID UnknownPointerFixCallback)
{
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    ULONG_PTR iatStart = NULL;
    DWORD iatSize = NULL;
    WCHAR IatFixFileName[MAX_PATH];
    WCHAR DumpFileName[MAX_PATH];

    lstrcpyW(DumpFileName, szDumpedFile);

    WCHAR* Extension = wcsrchr(DumpFileName, L'.');
    WCHAR Bak = *Extension;
    *Extension = 0;
    lstrcpyW(IatFixFileName, DumpFileName);
    *Extension = Bak;
    lstrcatW(IatFixFileName, L"_scy");
    lstrcatW(IatFixFileName, Extension);
    lstrcatW(DumpFileName, Extension);

    //do we need to dump first?
    if(DumpRunningProcess)
    {
        HANDLE hProcess = OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION, FALSE, ProcessId);

        if(!DumpProcessW(hProcess, (LPVOID)ImageBase, szDumpedFile, EntryPointAddress))
        {
            return(NULL);	// Critical error! *just to be safe, but it should never happen!
        }
    }

    //we need to fix iat, thats for sure
    int ret = scylla_searchIAT(ProcessId, iatStart, iatSize, SearchStart, false);

    if(ret != SCY_ERROR_SUCCESS)
    {
        if(ret == SCY_ERROR_PROCOPEN)
        {
            return (0x401); //error proc terminated
        }
        if(ret == SCY_ERROR_IATNOTFOUND || ret == SCY_ERROR_IATSEARCH)
        {
            return (0x405); //no API found
        }
    }

    scylla_getImports(iatStart, iatSize, ProcessId, UnknownPointerFixCallback);

    if(!scylla_importsValid())
    {
        return (0x405);
    }

    ret = scylla_fixDump(szDumpedFile, IatFixFileName, szSectionName);

    if(ret == SCY_ERROR_IATWRITE)
    {
        return (0x407);
    }

    //do we need to realign ?
    if(RealignFile)
    {
        if(MapFileExW(szDumpedFile, UE_ACCESS_ALL, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
        {
            FileSize = RealignPE(FileMapVA, FileSize, NULL);
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
        }
        else
        {
            return(0x406);	// Success, but realign failed!
        }
    }
    return(0x400);	// Success!
}
__declspec(dllexport) long TITCALL ImporterAutoFixIAT(DWORD ProcessId, char* szDumpedFile, ULONG_PTR SearchStart)
{
    return(ImporterAutoFixIATEx(ProcessId, szDumpedFile, ".RL!TEv2", false, false, NULL, NULL, SearchStart, false, false, NULL));
}
__declspec(dllexport) long TITCALL ImporterAutoFixIATW(DWORD ProcessId, wchar_t* szDumpedFile, ULONG_PTR SearchStart)
{
    return(ImporterAutoFixIATExW(ProcessId, szDumpedFile, L".RL!TEv2", false, false, NULL, NULL, SearchStart, false, false, NULL));
}
__declspec(dllexport) bool TITCALL ImporterDeleteAPI(DWORD_PTR apiAddr)
{
    return scylla_cutImport(apiAddr);
}
// Internal.Engine.Hook.functions:
bool ProcessHookScanAddNewHook(PHOOK_ENTRY HookDetails, void* ptrOriginalInstructions, PLIBRARY_ITEM_DATAW ModuleInformation, DWORD SizeOfImage)
{

    HOOK_ENTRY MyhookEntry = {};

    RtlMoveMemory(&MyhookEntry, HookDetails, sizeof HOOK_ENTRY);
    hookEntry.push_back(MyhookEntry);
    return(true);
}
// Global.Engine.Hook.functions:
__declspec(dllexport) bool TITCALL HooksSafeTransitionEx(LPVOID HookAddressArray, int NumberOfHooks, bool TransitionStart)
{

    int i;
    ULONG_PTR CurrentIP;
    ULONG_PTR HookAddress;
    PTHREAD_ITEM_DATA hListThreadPtr = (PTHREAD_ITEM_DATA)hListThread;
    PMEMORY_COMPARE_HANDLER myHookAddressArray;

    if(dbgProcessInformation.hProcess == NULL)
    {
        if(!TransitionStart || ThreaderImportRunningThreadData(GetCurrentProcessId()))
        {
            hListThreadPtr = (PTHREAD_ITEM_DATA)hListThread;
            if(hListThreadPtr != NULL)
            {
                while(hListThreadPtr->hThread != NULL)
                {
                    if(hListThreadPtr->hThread != INVALID_HANDLE_VALUE)
                    {
                        if(TransitionStart)
                        {
                            if(hListThreadPtr->dwThreadId != GetCurrentThreadId())
                            {
                                SuspendThread(hListThreadPtr->hThread);
                                CurrentIP = (ULONG_PTR)GetContextDataEx(hListThreadPtr->hThread, UE_CIP);
                                myHookAddressArray = (PMEMORY_COMPARE_HANDLER)HookAddressArray;
                                for(i = 0; i < NumberOfHooks; i++)
                                {
#if defined (_WIN64)
                                    HookAddress = (ULONG_PTR)myHookAddressArray->Array.qwArrayEntry[0];
                                    myHookAddressArray = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)myHookAddressArray + sizeof ULONG_PTR);
#else
                                    HookAddress = (ULONG_PTR)myHookAddressArray->Array.dwArrayEntry[0];
                                    myHookAddressArray = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)myHookAddressArray + sizeof ULONG_PTR);
#endif
                                    while(CurrentIP >= (ULONG_PTR)HookAddress && CurrentIP <= (ULONG_PTR)HookAddress + 5)
                                    {
                                        ResumeThread(hListThreadPtr->hThread);
                                        Sleep(5);
                                        SuspendThread(hListThreadPtr->hThread);
                                        CurrentIP = (ULONG_PTR)GetContextDataEx(hListThreadPtr->hThread, UE_CIP);
                                        i = 0;
                                    }
                                }
                            }
                        }
                        else
                        {
                            ResumeThread(hListThreadPtr->hThread);
                            EngineCloseHandle(hListThreadPtr->hThread);
                        }
                    }
                    hListThreadPtr = (PTHREAD_ITEM_DATA)((ULONG_PTR)hListThreadPtr + sizeof THREAD_ITEM_DATA);
                }
                if(!TransitionStart)
                {
                    VirtualFree(hListThread, NULL, MEM_RELEASE);
                    hListThread = NULL;
                }
                return(true);
            }
        }
        else
        {
            return(false);
        }
    }
    return(false);
}
__declspec(dllexport) bool TITCALL HooksSafeTransition(LPVOID HookAddress, bool TransitionStart)
{

    void* aHookAddress[1];
    aHookAddress[0] = HookAddress;

    return(HooksSafeTransitionEx(&aHookAddress[0], sizeof aHookAddress, TransitionStart));
}
__declspec(dllexport) bool TITCALL HooksIsAddressRedirected(LPVOID HookAddress)
{

    for(unsigned int i = 0; i < hookEntry.size(); i++)
    {
        if(hookEntry[i].HookAddress == HookAddress && hookEntry[i].IATHook == false && hookEntry[i].HookIsEnabled == true)
        {
            return(true);
        }
    }
    return(false);
}
__declspec(dllexport) void* TITCALL HooksGetTrampolineAddress(LPVOID HookAddress)
{

    for(unsigned int i = 0; i < hookEntry.size(); i++)
    {
        if(hookEntry[i].HookAddress == HookAddress)
        {
            return(hookEntry[i].PatchedEntry);
        }
    }
    return(NULL);
}
__declspec(dllexport) void* TITCALL HooksGetHookEntryDetails(LPVOID HookAddress)
{

    for(unsigned int i = 0; i < hookEntry.size(); i++)
    {
        if(hookEntry[i].HookAddress == HookAddress)
        {
            return(&hookEntry[i]);
        }
    }
    return(NULL);
}
__declspec(dllexport) bool TITCALL HooksInsertNewRedirection(LPVOID HookAddress, LPVOID RedirectTo, int HookType)
{

#if !defined(_WIN64)
    int j;
    unsigned int i;
#endif
    HOOK_ENTRY myHook = {};
    DWORD CalculatedRealingJump;
    ULONG_PTR x64CalculatedRealingJump;
    ULONG_PTR RealignAddressTarget;
    int ProcessedBufferSize = NULL;
    int CurrentInstructionSize = NULL;
    PMEMORY_COMPARE_HANDLER WriteMemory = (PMEMORY_COMPARE_HANDLER)CwpBuffPatchedEntry;
    PMEMORY_COMPARE_HANDLER CompareMemory;
#if !defined(_WIN64)
    PMEMORY_COMPARE_HANDLER RelocateMemory;
#endif
    void* cHookAddress = HookAddress;
    DWORD OldProtect = PAGE_READONLY;
    void* TempBuffPatchedEntry;
    bool returnData;

    x64CalculatedRealingJump = NULL;
    if(buffPatchedEntry == NULL || (ULONG_PTR)CwpBuffPatchedEntry - (ULONG_PTR)buffPatchedEntry + TEE_MAXIMUM_HOOK_SIZE > buffPatchedEntrySize)
    {
        buffPatchedEntrySize = buffPatchedEntrySize + 0x1000;
        CwpBuffPatchedEntry = (void*)((ULONG_PTR)CwpBuffPatchedEntry - (ULONG_PTR)buffPatchedEntry);
        TempBuffPatchedEntry = VirtualAlloc(NULL, buffPatchedEntrySize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if(TempBuffPatchedEntry != NULL)
        {
            if(hookEntry.size() > NULL)
            {
                RtlMoveMemory(TempBuffPatchedEntry, buffPatchedEntry, (ULONG_PTR)CwpBuffPatchedEntry);
            }
#if !defined(_WIN64)
            for(i = 0; i < hookEntry.size(); i++)
            {
                hookEntry[i].PatchedEntry = (void*)((ULONG_PTR)hookEntry[i].PatchedEntry - (ULONG_PTR)buffPatchedEntry + (ULONG_PTR)TempBuffPatchedEntry);
                CalculatedRealingJump = (DWORD)((ULONG_PTR)hookEntry[i].PatchedEntry - (ULONG_PTR)hookEntry[i].HookAddress - 5);
                RtlMoveMemory(&hookEntry[i].HookBytes[1], &CalculatedRealingJump, 4);
                if(hookEntry[i].RelocationCount > NULL)
                {
                    for(j = 0; j < hookEntry[i].RelocationCount; j++)
                    {
                        CompareMemory = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)buffPatchedEntry + hookEntry[i].RelocationInfo[j]);
                        RelocateMemory = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)TempBuffPatchedEntry + hookEntry[i].RelocationInfo[j]);
                        CurrentInstructionSize = StaticLengthDisassemble((void*)CompareMemory);
                        RealignAddressTarget = (ULONG_PTR)GetJumpDestination(GetCurrentProcess(), (ULONG_PTR)CompareMemory);
                        if(RealignAddressTarget != NULL)
                        {
                            if(CompareMemory->Array.bArrayEntry[0] == 0xE9 && CurrentInstructionSize == 5)
                            {
                                CalculatedRealingJump = (DWORD)((ULONG_PTR)RealignAddressTarget - (ULONG_PTR)RelocateMemory - CurrentInstructionSize);
                                RtlMoveMemory(&RelocateMemory->Array.bArrayEntry[1], &CalculatedRealingJump, sizeof CalculatedRealingJump);
                            }
                            else if(CompareMemory->Array.bArrayEntry[0] >= 0x70 && CompareMemory->Array.bArrayEntry[0] <= 0x7F && CurrentInstructionSize == 2)
                            {
                                CalculatedRealingJump = (DWORD)((ULONG_PTR)RealignAddressTarget - (ULONG_PTR)RelocateMemory - CurrentInstructionSize);
                                RtlMoveMemory(&RelocateMemory->Array.bArrayEntry[2], &CalculatedRealingJump, sizeof CalculatedRealingJump);
                            }
                            else if(CompareMemory->Array.bArrayEntry[0] == 0x0F && CompareMemory->Array.bArrayEntry[1] >= 0x80 && CompareMemory->Array.bArrayEntry[1] <= 0x8F && CurrentInstructionSize == 6)
                            {
                                CalculatedRealingJump = (DWORD)((ULONG_PTR)RealignAddressTarget - (ULONG_PTR)RelocateMemory - CurrentInstructionSize);
                                RtlMoveMemory(&RelocateMemory->Array.bArrayEntry[2], &CalculatedRealingJump, sizeof CalculatedRealingJump);
                            }
                            else if(CompareMemory->Array.bArrayEntry[0] == 0xE8 && CurrentInstructionSize == 5)
                            {
                                CalculatedRealingJump = (DWORD)((ULONG_PTR)RealignAddressTarget - (ULONG_PTR)RelocateMemory - CurrentInstructionSize);
                                RtlMoveMemory(&RelocateMemory->Array.bArrayEntry[1], &CalculatedRealingJump, sizeof CalculatedRealingJump);
                            }
                        }
                    }
                }
            }
#endif
            if(hookEntry.size() > NULL)
            {
                VirtualFree(buffPatchedEntry, NULL, MEM_RELEASE);
            }
            CwpBuffPatchedEntry = (void*)((ULONG_PTR)CwpBuffPatchedEntry + (ULONG_PTR)TempBuffPatchedEntry);
            WriteMemory = (PMEMORY_COMPARE_HANDLER)CwpBuffPatchedEntry;
            buffPatchedEntry = TempBuffPatchedEntry;
        }
    }
    while(ProcessedBufferSize < TEE_MAXIMUM_HOOK_INSERT_SIZE)
    {
        CompareMemory = (PMEMORY_COMPARE_HANDLER)cHookAddress;
        CurrentInstructionSize = StaticLengthDisassemble(cHookAddress);
        RealignAddressTarget = (ULONG_PTR)GetJumpDestination(GetCurrentProcess(), (ULONG_PTR)cHookAddress);
        if(RealignAddressTarget != NULL)
        {
            if(CompareMemory->Array.bArrayEntry[0] == 0xE9 && CurrentInstructionSize == 5)
            {
                if(cHookAddress == HookAddress)
                {
                    if(HooksIsAddressRedirected(HookAddress))
                    {
                        if(HooksRemoveRedirection(HookAddress, false))
                        {
                            returnData = HooksInsertNewRedirection(HookAddress, RedirectTo, HookType);
                            if(returnData)
                            {
                                return(true);
                            }
                            else
                            {
                                return(false);
                            }
                        }
                    }
                }
                CalculatedRealingJump = (DWORD)((ULONG_PTR)RealignAddressTarget - (ULONG_PTR)WriteMemory - CurrentInstructionSize);
                WriteMemory->Array.bArrayEntry[0] = 0xE9;
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[1], &CalculatedRealingJump, sizeof CalculatedRealingJump);
                myHook.RelocationInfo[myHook.RelocationCount] = (DWORD)((ULONG_PTR)WriteMemory - (ULONG_PTR)buffPatchedEntry);
                WriteMemory = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)WriteMemory + CurrentInstructionSize);
                myHook.RelocationCount++;
            }
            else if(CompareMemory->Array.bArrayEntry[0] == 0xEB && CurrentInstructionSize == 2)
            {
                CalculatedRealingJump = (DWORD)((ULONG_PTR)RealignAddressTarget - (ULONG_PTR)WriteMemory - 5);
                WriteMemory->Array.bArrayEntry[0] = 0xE9;
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[1], &CalculatedRealingJump, sizeof CalculatedRealingJump);
                myHook.RelocationInfo[myHook.RelocationCount] = (DWORD)((ULONG_PTR)WriteMemory - (ULONG_PTR)buffPatchedEntry);
                WriteMemory = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)WriteMemory + 5);
                myHook.RelocationCount++;
            }
            else if(CompareMemory->Array.bArrayEntry[0] >= 0x70 && CompareMemory->Array.bArrayEntry[0] <= 0x7F && CurrentInstructionSize == 2)
            {
#if !defined(_WIN64)
                CalculatedRealingJump = (DWORD)((ULONG_PTR)RealignAddressTarget - (ULONG_PTR)WriteMemory - 6);
                WriteMemory->Array.bArrayEntry[0] = 0x0F;
                WriteMemory->Array.bArrayEntry[1] = CompareMemory->Array.bArrayEntry[0] + 0x10;
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[2], &CalculatedRealingJump, sizeof CalculatedRealingJump);
                myHook.RelocationInfo[myHook.RelocationCount] = (DWORD)((ULONG_PTR)WriteMemory - (ULONG_PTR)buffPatchedEntry);
                WriteMemory = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)WriteMemory + 6);
                myHook.RelocationCount++;
#else
                x64CalculatedRealingJump = RealignAddressTarget;
                WriteMemory->Array.bArrayEntry[0] = CompareMemory->Array.bArrayEntry[0];
                WriteMemory->Array.bArrayEntry[1] = 0x02;
                WriteMemory->Array.bArrayEntry[2] = 0xEB;
                WriteMemory->Array.bArrayEntry[3] = 0x0E;
                WriteMemory->Array.bArrayEntry[4] = 0xFF;
                WriteMemory->Array.bArrayEntry[5] = 0x25;
                RtlZeroMemory(&WriteMemory->Array.bArrayEntry[6], 4);
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[10], &x64CalculatedRealingJump, sizeof x64CalculatedRealingJump);
                WriteMemory = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)WriteMemory + 18);
#endif
            }
            else if(CompareMemory->Array.bArrayEntry[0] == 0x0F && CompareMemory->Array.bArrayEntry[1] >= 0x80 && CompareMemory->Array.bArrayEntry[1] <= 0x8F && CurrentInstructionSize == 6)
            {
#if !defined(_WIN64)
                CalculatedRealingJump = (DWORD)((ULONG_PTR)RealignAddressTarget - (ULONG_PTR)WriteMemory - CurrentInstructionSize);
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[0], &CompareMemory->Array.bArrayEntry[0], 2);
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[2], &CalculatedRealingJump, sizeof CalculatedRealingJump);
                myHook.RelocationInfo[myHook.RelocationCount] = (DWORD)((ULONG_PTR)WriteMemory - (ULONG_PTR)buffPatchedEntry);
                WriteMemory = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)WriteMemory + CurrentInstructionSize);
                myHook.RelocationCount++;
#else
                x64CalculatedRealingJump = RealignAddressTarget;
                WriteMemory->Array.bArrayEntry[0] = CompareMemory->Array.bArrayEntry[0];
                WriteMemory->Array.bArrayEntry[1] = CompareMemory->Array.bArrayEntry[1];
                WriteMemory->Array.bArrayEntry[2] = 0x02;
                WriteMemory->Array.bArrayEntry[3] = 0x00;
                WriteMemory->Array.bArrayEntry[4] = 0x00;
                WriteMemory->Array.bArrayEntry[5] = 0x00;
                WriteMemory->Array.bArrayEntry[6] = 0xEB;
                WriteMemory->Array.bArrayEntry[7] = 0x0E;
                WriteMemory->Array.bArrayEntry[8] = 0xFF;
                WriteMemory->Array.bArrayEntry[9] = 0x25;
                RtlZeroMemory(&WriteMemory->Array.bArrayEntry[10], 4);
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[14], &x64CalculatedRealingJump, sizeof x64CalculatedRealingJump);
                WriteMemory = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)WriteMemory + 22);
#endif
            }
            else if(CompareMemory->Array.bArrayEntry[0] == 0xE8 && CurrentInstructionSize == 5)
            {
                CalculatedRealingJump = (DWORD)((ULONG_PTR)RealignAddressTarget - (ULONG_PTR)WriteMemory - CurrentInstructionSize);
                WriteMemory->Array.bArrayEntry[0] = 0xE8;
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[1], &CalculatedRealingJump, sizeof CalculatedRealingJump);
                myHook.RelocationInfo[myHook.RelocationCount] = (DWORD)((ULONG_PTR)WriteMemory - (ULONG_PTR)buffPatchedEntry);
                WriteMemory = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)WriteMemory + CurrentInstructionSize);
                myHook.RelocationCount++;
#if defined(_WIN64)
            }
            else if(CompareMemory->Array.bArrayEntry[0] == 0xFF && (CompareMemory->Array.bArrayEntry[1] == 0x15 || CompareMemory->Array.bArrayEntry[1] == 0x25) && CurrentInstructionSize == 6)
            {
                CalculatedRealingJump = (DWORD)((ULONG_PTR)RealignAddressTarget - (ULONG_PTR)WriteMemory - CurrentInstructionSize);
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[0], &CompareMemory->Array.bArrayEntry[0], 2);
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[2], &CalculatedRealingJump, sizeof CalculatedRealingJump);
                WriteMemory = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)WriteMemory + CurrentInstructionSize);
#endif
            }
            else
            {
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[0], cHookAddress, CurrentInstructionSize);
                WriteMemory = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)WriteMemory + CurrentInstructionSize);
            }
        }
        else
        {
            RtlMoveMemory(&WriteMemory->Array.bArrayEntry[0], cHookAddress, CurrentInstructionSize);
            WriteMemory = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)WriteMemory + CurrentInstructionSize);
        }
        cHookAddress = (void*)((ULONG_PTR)cHookAddress + CurrentInstructionSize);
        ProcessedBufferSize = ProcessedBufferSize + CurrentInstructionSize;
    }
    if(ProcessedBufferSize >= TEE_MAXIMUM_HOOK_INSERT_SIZE)
    {
        WriteMemory->Array.bArrayEntry[0] = 0xFF;
        WriteMemory->Array.bArrayEntry[1] = 0x25;
#if !defined(_WIN64)
        CalculatedRealingJump = (DWORD)((ULONG_PTR)WriteMemory + 6);
#else
        CalculatedRealingJump = NULL;
#endif
        RtlMoveMemory(&WriteMemory->Array.bArrayEntry[2], &CalculatedRealingJump, sizeof CalculatedRealingJump);
        RtlMoveMemory(&WriteMemory->Array.bArrayEntry[6], &cHookAddress, sizeof CalculatedRealingJump);
        WriteMemory = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)WriteMemory + 6 + sizeof ULONG_PTR);
        myHook.HookIsEnabled = true;
        myHook.HookType = (BYTE)HookType;
        myHook.HookAddress = HookAddress;
        myHook.RedirectionAddress = RedirectTo;
        myHook.PatchedEntry = CwpBuffPatchedEntry;
        myHook.HookSize = TEE_MAXIMUM_HOOK_SIZE;
        RtlMoveMemory(&myHook.OriginalBytes[0], HookAddress, TEE_MAXIMUM_HOOK_SIZE);
        CalculatedRealingJump = (DWORD)((ULONG_PTR)RedirectTo - (ULONG_PTR)HookAddress);
        CwpBuffPatchedEntry = (void*)((ULONG_PTR)WriteMemory);
        WriteMemory = (PMEMORY_COMPARE_HANDLER)HookAddress;
        if(HookType == TEE_HOOK_NRM_JUMP)
        {
#if !defined(_WIN64)
            CalculatedRealingJump = CalculatedRealingJump - 5;
            if(VirtualProtect(HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
            {
                WriteMemory->Array.bArrayEntry[0] = 0xE9;
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[1], &CalculatedRealingJump, sizeof CalculatedRealingJump);
                RtlMoveMemory(&myHook.HookBytes[0], HookAddress, TEE_MAXIMUM_HOOK_SIZE);
                VirtualProtect(HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                hookEntry.push_back(myHook);
                return(true);
            }
#else
            if(VirtualProtect(HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
            {
                WriteMemory->Array.bArrayEntry[0] = 0xFF;
                WriteMemory->Array.bArrayEntry[1] = 0x25;
                RtlZeroMemory(&WriteMemory->Array.bArrayEntry[2], 4);
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[6], &RedirectTo, sizeof RedirectTo);
                RtlMoveMemory(&myHook.HookBytes[0], HookAddress, TEE_MAXIMUM_HOOK_SIZE);
                VirtualProtect(HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                hookEntry.push_back(myHook);
                return(true);
            }
#endif
        }
        else if(HookType == TEE_HOOK_NRM_CALL)
        {
#if !defined(_WIN64)
            CalculatedRealingJump = CalculatedRealingJump - 5;
            if(VirtualProtect(HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
            {
                WriteMemory->Array.bArrayEntry[0] = 0xE8;
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[1], &CalculatedRealingJump, sizeof CalculatedRealingJump);
                RtlMoveMemory(&myHook.HookBytes[0], HookAddress, TEE_MAXIMUM_HOOK_SIZE);
                VirtualProtect(HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                hookEntry.push_back(myHook);
                return(true);
            }
#else
            if(VirtualProtect(HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
            {
                WriteMemory->Array.bArrayEntry[0] = 0xFF;
                WriteMemory->Array.bArrayEntry[1] = 0x15;
                RtlZeroMemory(&WriteMemory->Array.bArrayEntry[2], 4);
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[6], &RedirectTo, sizeof RedirectTo);
                RtlMoveMemory(&myHook.HookBytes[0], HookAddress, TEE_MAXIMUM_HOOK_SIZE);
                VirtualProtect(HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                hookEntry.push_back(myHook);
                return(true);
            }
#endif
        }
    }
    return(false);
}
__declspec(dllexport) bool TITCALL HooksInsertNewIATRedirectionEx(ULONG_PTR FileMapVA, ULONG_PTR LoadedModuleBase, char* szHookFunction, LPVOID RedirectTo)
{

    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_IMPORT_DESCRIPTOR ImportIID;
    PIMAGE_THUNK_DATA32 ThunkData32;
    PIMAGE_THUNK_DATA64 ThunkData64;
    DWORD OldProtect = PAGE_READONLY;
    ULONG_PTR CurrentThunk;
    HOOK_ENTRY myHook = {};
    BOOL FileIs64;

    if(FileMapVA != NULL && LoadedModuleBase != NULL)
    {
        myHook.IATHook = true;
        myHook.HookIsEnabled = true;
        myHook.HookType = TEE_HOOK_IAT;
        myHook.HookSize = sizeof ULONG_PTR;
        myHook.RedirectionAddress = RedirectTo;
        myHook.IATHookModuleBase = (void*)LoadedModuleBase;
        myHook.IATHookNameHash = EngineHashString(szHookFunction);
        DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
        if(EngineValidateHeader(FileMapVA, NULL, NULL, DOSHeader, true))
        {
            PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            if(PEHeader32->OptionalHeader.Magic == 0x10B)
            {
                FileIs64 = false;
            }
            else if(PEHeader32->OptionalHeader.Magic == 0x20B)
            {
                FileIs64 = true;
            }
            else
            {
                return(false);
            }
            if(!FileIs64)
            {
                if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != NULL)
                {
                    ImportIID = (PIMAGE_IMPORT_DESCRIPTOR)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + PEHeader32->OptionalHeader.ImageBase), true);
                    __try
                    {
                        while(ImportIID->FirstThunk != NULL)
                        {
                            if(ImportIID->OriginalFirstThunk != NULL)
                            {
                                ThunkData32 = (PIMAGE_THUNK_DATA32)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((ULONG_PTR)ImportIID->OriginalFirstThunk + PEHeader32->OptionalHeader.ImageBase), true);
                                CurrentThunk = (ULONG_PTR)ImportIID->FirstThunk;
                            }
                            else
                            {
                                ThunkData32 = (PIMAGE_THUNK_DATA32)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((ULONG_PTR)ImportIID->FirstThunk + PEHeader32->OptionalHeader.ImageBase), true);
                                CurrentThunk = (ULONG_PTR)ImportIID->FirstThunk;
                            }
                            while(ThunkData32->u1.AddressOfData != NULL)
                            {
                                if(!(ThunkData32->u1.Ordinal & IMAGE_ORDINAL_FLAG32))
                                {
                                    if(lstrcmpiA((char*)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((ULONG_PTR)ThunkData32->u1.AddressOfData + 2 + PEHeader32->OptionalHeader.ImageBase), true), szHookFunction) == NULL)
                                    {
                                        myHook.HookAddress = (void*)(CurrentThunk + LoadedModuleBase);
                                        if(VirtualProtect(myHook.HookAddress, myHook.HookSize, PAGE_EXECUTE_READWRITE, &OldProtect))
                                        {
                                            RtlMoveMemory(&myHook.OriginalBytes[0], myHook.HookAddress, myHook.HookSize);
                                            RtlMoveMemory(&myHook.HookBytes[0], &myHook.RedirectionAddress, myHook.HookSize);
                                            RtlMoveMemory(myHook.HookAddress, &myHook.RedirectionAddress, myHook.HookSize);
                                            VirtualProtect(myHook.HookAddress, myHook.HookSize, OldProtect, &OldProtect);
                                        }
                                        hookEntry.push_back(myHook);
                                    }
                                }
                                CurrentThunk = CurrentThunk + 4;
                                ThunkData32 = (PIMAGE_THUNK_DATA32)((ULONG_PTR)ThunkData32 + sizeof IMAGE_THUNK_DATA32);
                            }
                            ImportIID = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)ImportIID + sizeof IMAGE_IMPORT_DESCRIPTOR);
                        }
                        return(true);
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        return(false);
                    }
                }
            }
            else
            {
                if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != NULL)
                {
                    ImportIID = (PIMAGE_IMPORT_DESCRIPTOR)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + PEHeader64->OptionalHeader.ImageBase), true);
                    __try
                    {
                        while(ImportIID->FirstThunk != NULL)
                        {
                            if(ImportIID->OriginalFirstThunk != NULL)
                            {
                                ThunkData64 = (PIMAGE_THUNK_DATA64)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((ULONG_PTR)ImportIID->OriginalFirstThunk + PEHeader64->OptionalHeader.ImageBase), true);
                                CurrentThunk = (ULONG_PTR)ImportIID->OriginalFirstThunk;
                            }
                            else
                            {
                                ThunkData64 = (PIMAGE_THUNK_DATA64)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((ULONG_PTR)ImportIID->FirstThunk + PEHeader64->OptionalHeader.ImageBase), true);
                                CurrentThunk = (ULONG_PTR)ImportIID->FirstThunk;
                            }
                            while(ThunkData64->u1.AddressOfData != NULL)
                            {
                                if(!(ThunkData64->u1.Ordinal & IMAGE_ORDINAL_FLAG64))
                                {
                                    if(lstrcmpiA((char*)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((ULONG_PTR)ThunkData64->u1.AddressOfData + 2 + PEHeader64->OptionalHeader.ImageBase), true), szHookFunction) == NULL)
                                    {
                                        myHook.HookAddress = (void*)(CurrentThunk + LoadedModuleBase);
                                        if(VirtualProtect(myHook.HookAddress, myHook.HookSize, PAGE_EXECUTE_READWRITE, &OldProtect))
                                        {
                                            RtlMoveMemory(&myHook.OriginalBytes[0], myHook.HookAddress, myHook.HookSize);
                                            RtlMoveMemory(&myHook.HookBytes[0], &myHook.RedirectionAddress, myHook.HookSize);
                                            RtlMoveMemory(myHook.HookAddress, &myHook.RedirectionAddress, myHook.HookSize);
                                            VirtualProtect(myHook.HookAddress, myHook.HookSize, OldProtect, &OldProtect);
                                        }
                                        hookEntry.push_back(myHook);
                                    }
                                }
                                CurrentThunk = CurrentThunk + 8;
                                ThunkData64 = (PIMAGE_THUNK_DATA64)((ULONG_PTR)ThunkData64 + sizeof IMAGE_THUNK_DATA64);
                            }
                            ImportIID = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)ImportIID + sizeof IMAGE_IMPORT_DESCRIPTOR);
                        }
                        return(true);
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        return(false);
                    }
                }
            }
        }
        else
        {
            return(false);
        }
    }
    else
    {
        return(false);
    }
    return(false);
}
__declspec(dllexport) bool TITCALL HooksInsertNewIATRedirection(char* szModuleName, char* szHookFunction, LPVOID RedirectTo)
{

    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    DWORD NewSectionVO = NULL;
    DWORD NewSectionFO = NULL;
    HMODULE SelectedModule = NULL;

    SelectedModule = GetModuleHandleA(szModuleName);
    if(SelectedModule != NULL)
    {
        if(MapFileEx(szModuleName, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
        {
            if(HooksInsertNewIATRedirectionEx(FileMapVA, (ULONG_PTR)SelectedModule, szHookFunction, RedirectTo))
            {
                UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                return(true);
            }
            else
            {
                UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            }
        }
    }
    return(false);
}
__declspec(dllexport) bool TITCALL HooksRemoveRedirection(LPVOID HookAddress, bool RemoveAll)
{

    DWORD OldProtect = PAGE_READONLY;

    if(!RemoveAll)
    {
        for(unsigned int i = 0; i < hookEntry.size(); i++)
        {
            if(hookEntry[i].HookAddress == HookAddress && hookEntry[i].IATHook == false)
            {
                if(VirtualProtect(HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
                {
                    RtlMoveMemory(HookAddress, &hookEntry[i].OriginalBytes, hookEntry[i].HookSize);
                    VirtualProtect(HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                    hookEntry.erase(hookEntry.begin() + i);
                    return(true);
                }
            }
        }
        return(false);
    }
    else
    {
        for(unsigned int i = 0; i < hookEntry.size(); i++)
        {
            if(VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
            {
                RtlMoveMemory(hookEntry[i].HookAddress, &hookEntry[i].OriginalBytes, hookEntry[i].HookSize);
                VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
            }
        }
        hookEntry.clear();
        return(true);
    }
}
__declspec(dllexport) bool TITCALL HooksRemoveRedirectionsForModule(HMODULE ModuleBase)
{

    int j = NULL;
    unsigned int i = (unsigned int)hookEntry.size();
    DWORD OldProtect = PAGE_READONLY;
    MODULEINFO RemoteModuleInfo;

    if(GetModuleInformation(GetCurrentProcess(), ModuleBase, &RemoteModuleInfo, sizeof MODULEINFO))
    {
        while(i > NULL)
        {
            if((ULONG_PTR)hookEntry[i].HookAddress >= (ULONG_PTR)ModuleBase && (ULONG_PTR)hookEntry[i].HookAddress <= (ULONG_PTR)ModuleBase + RemoteModuleInfo.SizeOfImage)
            {
                if(VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
                {
                    RtlMoveMemory(hookEntry[i].HookAddress, &hookEntry[i].OriginalBytes, hookEntry[i].HookSize);
                    VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                    hookEntry.erase(hookEntry.begin() + i);
                    j++;
                }
            }
            i--;
        }
        if(j == NULL)
        {
            return(false);
        }
    }
    else
    {
        return(false);
    }
    return(true);
}
__declspec(dllexport) bool TITCALL HooksRemoveIATRedirection(char* szModuleName, char* szHookFunction, bool RemoveAll)
{

    unsigned int i = (unsigned int)hookEntry.size() - 1;
    DWORD OldProtect = PAGE_READONLY;
    HMODULE ModuleBase = GetModuleHandleA(szModuleName);
    DWORD FunctionNameHash = EngineHashString(szHookFunction);

    if(ModuleBase != NULL)
    {
        while(i > 0)
        {
            if((hookEntry[i].IATHookModuleBase == (void*)ModuleBase && RemoveAll == true) || (hookEntry[i].IATHookNameHash == FunctionNameHash && hookEntry[i].IATHook == true))
            {
                if(VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
                {
                    RtlMoveMemory(hookEntry[i].HookAddress, &hookEntry[i].OriginalBytes, hookEntry[i].HookSize);
                    VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                    hookEntry.erase(hookEntry.begin() + i);
                }
            }
            i--;
        }
    }
    return(false);
}
__declspec(dllexport) bool TITCALL HooksDisableRedirection(LPVOID HookAddress, bool DisableAll)
{

    DWORD OldProtect = PAGE_READONLY;

    if(!DisableAll)
    {
        for(unsigned int i = 0; i < hookEntry.size(); i++)
        {
            if(hookEntry[i].HookAddress == HookAddress && hookEntry[i].HookIsEnabled == true)
            {
                if(VirtualProtect(HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
                {
                    RtlMoveMemory(HookAddress, &hookEntry[i].OriginalBytes, hookEntry[i].HookSize);
                    VirtualProtect(HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                    hookEntry[i].HookIsEnabled = false;
                    return(true);
                }
            }
        }
        return(false);
    }
    else
    {
        for(unsigned int i = 0; i < hookEntry.size(); i++)
        {
            if(VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
            {
                RtlMoveMemory(hookEntry[i].HookAddress, &hookEntry[i].OriginalBytes, hookEntry[i].HookSize);
                VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                hookEntry[i].HookIsEnabled = false;
            }
        }
        return(true);
    }
}
__declspec(dllexport) bool TITCALL HooksDisableRedirectionsForModule(HMODULE ModuleBase)
{

    int j = NULL;
    unsigned int i = (unsigned int)hookEntry.size();
    DWORD OldProtect = PAGE_READONLY;
    MODULEINFO RemoteModuleInfo;

    if(GetModuleInformation(GetCurrentProcess(), ModuleBase, &RemoteModuleInfo, sizeof MODULEINFO))
    {
        while(i > NULL)
        {
            if((ULONG_PTR)hookEntry[i].HookAddress >= (ULONG_PTR)ModuleBase && (ULONG_PTR)hookEntry[i].HookAddress <= (ULONG_PTR)ModuleBase + RemoteModuleInfo.SizeOfImage)
            {
                if(VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
                {
                    RtlMoveMemory(hookEntry[i].HookAddress, &hookEntry[i].OriginalBytes, hookEntry[i].HookSize);
                    VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                    hookEntry[i].HookIsEnabled = false;
                    j++;
                }
            }
            i--;
        }
        if(j == NULL)
        {
            return(false);
        }
    }
    else
    {
        return(false);
    }
    return(true);
}
__declspec(dllexport) bool TITCALL HooksDisableIATRedirection(char* szModuleName, char* szHookFunction, bool DisableAll)
{

    unsigned int i = (unsigned int)hookEntry.size() - 1;
    DWORD OldProtect = PAGE_READONLY;
    HMODULE ModuleBase = GetModuleHandleA(szModuleName);
    DWORD FunctionNameHash = EngineHashString(szHookFunction);

    if(ModuleBase != NULL)
    {
        while(i > 0)
        {
            if((hookEntry[i].IATHookModuleBase == (void*)ModuleBase && DisableAll == true) || (hookEntry[i].IATHookNameHash == FunctionNameHash && hookEntry[i].IATHook == true))
            {
                if(hookEntry[i].HookIsEnabled)
                {
                    if(VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
                    {
                        RtlMoveMemory(hookEntry[i].HookAddress, &hookEntry[i].OriginalBytes, hookEntry[i].HookSize);
                        VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                        hookEntry[i].HookIsEnabled = false;
                    }
                }
            }
            i--;
        }
    }
    return(false);
}
__declspec(dllexport) bool TITCALL HooksEnableRedirection(LPVOID HookAddress, bool EnableAll)
{

    DWORD OldProtect = PAGE_READONLY;

    if(!EnableAll)
    {
        for(unsigned int i = 0; i < hookEntry.size(); i++)
        {
            if(hookEntry[i].HookAddress == HookAddress && hookEntry[i].HookIsEnabled == false)
            {
                if(VirtualProtect(HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
                {
                    RtlMoveMemory(HookAddress, &hookEntry[i].HookBytes, hookEntry[i].HookSize);
                    VirtualProtect(HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                    hookEntry[i].HookIsEnabled = true;
                    return(true);
                }
            }
        }
        return(false);
    }
    else
    {
        for(unsigned int i = 0; i < hookEntry.size(); i++)
        {
            if(VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
            {
                RtlMoveMemory(hookEntry[i].HookAddress, &hookEntry[i].HookBytes, hookEntry[i].HookSize);
                VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                hookEntry[i].HookIsEnabled = true;
            }
        }
        return(true);
    }
}
__declspec(dllexport) bool TITCALL HooksEnableRedirectionsForModule(HMODULE ModuleBase)
{

    int j = NULL;
    unsigned int i = (unsigned int)hookEntry.size();
    DWORD OldProtect = PAGE_READONLY;
    MODULEINFO RemoteModuleInfo;

    if(GetModuleInformation(GetCurrentProcess(), ModuleBase, &RemoteModuleInfo, sizeof MODULEINFO))
    {
        while(i > NULL)
        {
            if((ULONG_PTR)hookEntry[i].HookAddress >= (ULONG_PTR)ModuleBase && (ULONG_PTR)hookEntry[i].HookAddress <= (ULONG_PTR)ModuleBase + RemoteModuleInfo.SizeOfImage)
            {
                if(VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
                {
                    RtlMoveMemory(hookEntry[i].HookAddress, &hookEntry[i].HookBytes, hookEntry[i].HookSize);
                    VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                    hookEntry[i].HookIsEnabled = true;
                    j++;
                }
            }
            i--;
        }
        if(j == NULL)
        {
            return(false);
        }
    }
    else
    {
        return(false);
    }
    return(true);
}
__declspec(dllexport) bool TITCALL HooksEnableIATRedirection(char* szModuleName, char* szHookFunction, bool EnableAll)
{

    unsigned int i = (unsigned int)hookEntry.size() - 1;
    DWORD OldProtect = PAGE_READONLY;
    HMODULE ModuleBase = GetModuleHandleA(szModuleName);
    DWORD FunctionNameHash = EngineHashString(szHookFunction);

    if(ModuleBase != NULL)
    {
        while(i > 0)
        {
            if((hookEntry[i].IATHookModuleBase == (void*)ModuleBase && EnableAll == true) || (hookEntry[i].IATHookNameHash == FunctionNameHash && hookEntry[i].IATHook == true))
            {
                if(!hookEntry[i].HookIsEnabled)
                {
                    if(VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
                    {
                        RtlMoveMemory(hookEntry[i].HookAddress, &hookEntry[i].HookBytes, hookEntry[i].HookSize);
                        VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                        hookEntry[i].HookIsEnabled = true;
                    }
                }
            }
            i--;
        }
    }
    return(false);
}
__declspec(dllexport) void TITCALL HooksScanModuleMemory(HMODULE ModuleBase, LPVOID CallBack)
{

    unsigned int i;
    bool FileIs64 = false;
    bool FileError = false;
    void* pOriginalInstruction;
    bool ManuallyMapped = false;
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_EXPORT_DIRECTORY PEExports;
    HANDLE hProcess = GetCurrentProcess();
    LIBRARY_ITEM_DATA RemoteLibInfo = {};
    PLIBRARY_ITEM_DATA pRemoteLibInfo = (PLIBRARY_ITEM_DATA)LibrarianGetLibraryInfoEx((void*)ModuleBase);
    typedef bool(TITCALL *fEnumCallBack)(PHOOK_ENTRY HookDetails, void* ptrOriginalInstructions, PLIBRARY_ITEM_DATA ModuleInformation, DWORD SizeOfImage);
    fEnumCallBack myEnumCallBack = (fEnumCallBack)CallBack;
    BYTE CheckHookMemory[TEE_MAXIMUM_HOOK_SIZE];
    PMEMORY_COMPARE_HANDLER ExportedFunctions;
    PMEMORY_COMPARE_HANDLER FunctionMemory;
    ULONG_PTR lpNumberOfBytesWritten;
    HOOK_ENTRY MyhookEntry = {};
    ULONG_PTR HookDestination;
    MODULEINFO ModuleInfo;
    BYTE HookType = NULL;
    DWORD hSize;

    if(pRemoteLibInfo == NULL)
    {
        RemoteLibInfo.BaseOfDll = (void*)ModuleBase;
        GetModuleBaseNameA(hProcess, ModuleBase, &RemoteLibInfo.szLibraryName[0], MAX_PATH);
        GetModuleFileNameExA(hProcess, ModuleBase, &RemoteLibInfo.szLibraryPath[0], MAX_PATH);
        RemoteLibInfo.hFile = CreateFileA(RemoteLibInfo.szLibraryPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if(RemoteLibInfo.hFile != INVALID_HANDLE_VALUE)
        {
            RemoteLibInfo.hFileMapping = CreateFileMappingA(RemoteLibInfo.hFile, NULL, 2, NULL, GetFileSize(RemoteLibInfo.hFile, NULL), NULL);
            if(RemoteLibInfo.hFileMapping != NULL)
            {
                RemoteLibInfo.hFileMappingView = MapViewOfFile(RemoteLibInfo.hFileMapping, 4, NULL, NULL, NULL);
                if(RemoteLibInfo.hFileMappingView == NULL)
                {
                    CloseHandle(RemoteLibInfo.hFile);
                    CloseHandle(RemoteLibInfo.hFileMapping);
                    FileError = true;
                }
                else
                {
                    ManuallyMapped = true;
                }
            }
            else
            {
                CloseHandle(RemoteLibInfo.hFile);
                FileError = true;
            }
        }
        else
        {
            FileError = true;
        }
    }
    else
    {
        RtlMoveMemory(&RemoteLibInfo, pRemoteLibInfo, sizeof LIBRARY_ITEM_DATA);
    }
    if(!FileError)
    {
        hSize = GetFileSize(RemoteLibInfo.hFile, NULL);
        GetModuleInformation(hProcess, ModuleBase, &ModuleInfo, sizeof MODULEINFO);
        DOSHeader = (PIMAGE_DOS_HEADER)RemoteLibInfo.hFileMappingView;
        __try
        {
            PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            if(PEHeader32->OptionalHeader.Magic == 0x10B)
            {
                FileIs64 = false;
            }
            else if(PEHeader32->OptionalHeader.Magic == 0x20B)
            {
                FileIs64 = true;
            }
            else
            {
                FileError = true;
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            FileError = true;
        }
        if(!FileError)
        {
            FunctionMemory = (PMEMORY_COMPARE_HANDLER)&CheckHookMemory[0];
            if(!FileIs64)
            {
                __try
                {
                    if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != NULL)
                    {
                        PEExports = (PIMAGE_EXPORT_DIRECTORY)ConvertVAtoFileOffsetEx((ULONG_PTR)RemoteLibInfo.hFileMappingView, hSize, PEHeader32->OptionalHeader.ImageBase, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, true, true);
                        if(PEExports != NULL)
                        {
                            ExportedFunctions = (PMEMORY_COMPARE_HANDLER)(ConvertVAtoFileOffsetEx((ULONG_PTR)RemoteLibInfo.hFileMappingView, hSize, PEHeader32->OptionalHeader.ImageBase, PEExports->AddressOfFunctions, true, true));
                            for(i = 0; i < PEExports->NumberOfFunctions; i++)
                            {
                                if(ReadProcessMemory(hProcess, (void*)((ULONG_PTR)RemoteLibInfo.BaseOfDll + ExportedFunctions->Array.dwArrayEntry[i]), &CheckHookMemory[0], TEE_MAXIMUM_HOOK_SIZE, &lpNumberOfBytesWritten))
                                {
                                    if(FunctionMemory->Array.bArrayEntry[0] == 0xE9 || FunctionMemory->Array.bArrayEntry[0] == 0xE8)
                                    {
                                        HookDestination = (ULONG_PTR)GetJumpDestination(hProcess, (ULONG_PTR)RemoteLibInfo.BaseOfDll + ExportedFunctions->Array.dwArrayEntry[i]);
                                        if(HookDestination >= (ULONG_PTR)RemoteLibInfo.BaseOfDll && HookDestination <= (ULONG_PTR)RemoteLibInfo.BaseOfDll + (ULONG_PTR)ModuleInfo.SizeOfImage)
                                        {
                                            if(CallBack != NULL)
                                            {
                                                if(FunctionMemory->Array.bArrayEntry[0] == 0xE9)
                                                {
                                                    HookType = TEE_HOOK_NRM_JUMP;
                                                }
                                                else
                                                {
                                                    HookType = TEE_HOOK_NRM_CALL;
                                                }
                                                MyhookEntry.HookSize = 5;
                                                MyhookEntry.HookType = HookType;
                                                MyhookEntry.HookIsEnabled = true;
                                                MyhookEntry.RedirectionAddress = (void*)HookDestination;
                                                MyhookEntry.HookAddress = (void*)((ULONG_PTR)RemoteLibInfo.BaseOfDll + ExportedFunctions->Array.dwArrayEntry[i]);
                                                pOriginalInstruction = (void*)ConvertVAtoFileOffsetEx((ULONG_PTR)RemoteLibInfo.hFileMappingView, hSize, PEHeader32->OptionalHeader.ImageBase, ExportedFunctions->Array.dwArrayEntry[i], true, true);
                                                RtlZeroMemory(&MyhookEntry.HookBytes[0], TEE_MAXIMUM_HOOK_SIZE);
                                                RtlMoveMemory(&MyhookEntry.HookBytes[0], &CheckHookMemory[0], MyhookEntry.HookSize);
                                                RtlZeroMemory(&MyhookEntry.OriginalBytes[0], TEE_MAXIMUM_HOOK_SIZE);
                                                RtlMoveMemory(&MyhookEntry.OriginalBytes[0], pOriginalInstruction, MyhookEntry.HookSize);
                                                RelocaterRelocateMemoryBlock((ULONG_PTR)RemoteLibInfo.hFileMappingView, (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase + ExportedFunctions->Array.dwArrayEntry[i], &MyhookEntry.OriginalBytes[0], MyhookEntry.HookSize, (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase, (ULONG_PTR)RemoteLibInfo.BaseOfDll);
                                                if(!myEnumCallBack(&MyhookEntry, pOriginalInstruction, &RemoteLibInfo, ModuleInfo.SizeOfImage))
                                                {
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {

                }
            }
            else
            {
                __try
                {
                    if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != NULL)
                    {
                        PEExports = (PIMAGE_EXPORT_DIRECTORY)ConvertVAtoFileOffsetEx((ULONG_PTR)RemoteLibInfo.hFileMappingView, hSize, (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, true, true);
                        if(PEExports != NULL)
                        {
                            ExportedFunctions = (PMEMORY_COMPARE_HANDLER)(ConvertVAtoFileOffsetEx((ULONG_PTR)RemoteLibInfo.hFileMappingView, hSize, (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, PEExports->AddressOfFunctions, true, true));
                            for(i = 0; i < PEExports->NumberOfFunctions; i++)
                            {
                                if(ReadProcessMemory(hProcess, (void*)((ULONG_PTR)RemoteLibInfo.BaseOfDll + ExportedFunctions->Array.dwArrayEntry[i]), &CheckHookMemory[0], TEE_MAXIMUM_HOOK_SIZE, &lpNumberOfBytesWritten))
                                {
                                    if(FunctionMemory->Array.bArrayEntry[0] == 0xE9 || FunctionMemory->Array.bArrayEntry[0] == 0xE8)
                                    {
                                        HookDestination = (ULONG_PTR)GetJumpDestination(hProcess, (ULONG_PTR)RemoteLibInfo.BaseOfDll + ExportedFunctions->Array.dwArrayEntry[i]);
                                        if(HookDestination >= (ULONG_PTR)RemoteLibInfo.BaseOfDll && HookDestination <= (ULONG_PTR)RemoteLibInfo.BaseOfDll + (ULONG_PTR)ModuleInfo.SizeOfImage)
                                        {
                                            if(CallBack != NULL)
                                            {
                                                if(FunctionMemory->Array.bArrayEntry[0] == 0xE9)
                                                {
                                                    HookType = TEE_HOOK_NRM_JUMP;
                                                }
                                                else
                                                {
                                                    HookType = TEE_HOOK_NRM_CALL;
                                                }
                                                MyhookEntry.HookSize = 5;
                                                MyhookEntry.HookType = HookType;
                                                MyhookEntry.HookIsEnabled = true;
                                                MyhookEntry.RedirectionAddress = (void*)HookDestination;
                                                MyhookEntry.HookAddress = (void*)((ULONG_PTR)RemoteLibInfo.BaseOfDll + ExportedFunctions->Array.dwArrayEntry[i]);
                                                pOriginalInstruction = (void*)ConvertVAtoFileOffsetEx((ULONG_PTR)RemoteLibInfo.hFileMappingView, hSize, (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, ExportedFunctions->Array.dwArrayEntry[i], true, true);
                                                RtlZeroMemory(&MyhookEntry.HookBytes[0], TEE_MAXIMUM_HOOK_SIZE);
                                                RtlMoveMemory(&MyhookEntry.HookBytes[0], &CheckHookMemory[0], MyhookEntry.HookSize);
                                                RtlZeroMemory(&MyhookEntry.OriginalBytes[0], TEE_MAXIMUM_HOOK_SIZE);
                                                RtlMoveMemory(&MyhookEntry.OriginalBytes[0], pOriginalInstruction, MyhookEntry.HookSize);
                                                RelocaterRelocateMemoryBlock((ULONG_PTR)RemoteLibInfo.hFileMappingView, (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase + ExportedFunctions->Array.dwArrayEntry[i], &MyhookEntry.OriginalBytes[0], MyhookEntry.HookSize, (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, (ULONG_PTR)RemoteLibInfo.BaseOfDll);
                                                if(!myEnumCallBack(&MyhookEntry, pOriginalInstruction, &RemoteLibInfo, ModuleInfo.SizeOfImage))
                                                {
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {

                }
            }
        }
        if(ManuallyMapped)
        {
            if(UnmapViewOfFile(RemoteLibInfo.hFileMappingView))
            {
                CloseHandle(RemoteLibInfo.hFileMapping);
                CloseHandle(RemoteLibInfo.hFile);
            }
        }
    }
}
__declspec(dllexport) void TITCALL HooksScanEntireProcessMemory(LPVOID CallBack)
{

    unsigned int i;
    DWORD ModulesLoaded;
    HMODULE EnumeratedModules[1024];

    hookEntry.clear();
    if(EnumProcessModules(GetCurrentProcess(), &EnumeratedModules[0], sizeof EnumeratedModules, &ModulesLoaded))
    {
        ModulesLoaded = ModulesLoaded / sizeof HANDLE;
        for(i = 1; i < ModulesLoaded; i++)
        {
            HooksScanModuleMemory(EnumeratedModules[i], CallBack);
        }
    }
}
__declspec(dllexport) void TITCALL HooksScanEntireProcessMemoryEx()
{
    HooksScanEntireProcessMemory(&ProcessHookScanAddNewHook);
}
// Global.Engine.Tracer.functions:
long long EngineGlobalTracerHandler1(HANDLE hProcess, ULONG_PTR AddressToTrace, bool HashInstructions, DWORD InputNumberOfInstructions)
{

    SIZE_T memSize = 0;
    int NumberOfInstructions = 0;
    int LengthOfValidInstruction = 0;
    int CurrentNumberOfInstructions = 0;
    MEMORY_BASIC_INFORMATION MemInfo;
    LPVOID TraceMemory, cTraceMemory;
    ULONG_PTR ueNumberOfBytesRead = NULL;
    DWORD LastPushValue = NULL;
    ULONG_PTR TraceStartAddress;
    ULONG_PTR TraceTestAddress;
    ULONG_PTR TraceTestReadAddress;
    DWORD CurrentInstructionSize;
    PMEMORY_CMP_HANDLER CompareMemory;
    PMEMORY_COMPARE_HANDLER longCompareMemory;
    DWORD InstructionHash = NULL;
    bool FoundValidAPI = false;
    bool SkipThisInstruction = false;
    bool LoopCondition = true;
    bool SkipHashing = false;
    BYTE EmptyCall[5] = {0xE8, 0x00, 0x00, 0x00, 0x00};

    if(VirtualQueryEx(hProcess, (LPVOID)AddressToTrace, &MemInfo, sizeof MEMORY_BASIC_INFORMATION) != NULL)
    {
        if(MemInfo.RegionSize > NULL)
        {
            memSize = MemInfo.RegionSize;
            if(memSize > 0x4000)
            {
                memSize = 0x4000;
            }
            TraceMemory = VirtualAlloc(NULL, memSize, MEM_COMMIT, PAGE_READWRITE);
            cTraceMemory = TraceMemory;
            if(ReadProcessMemory(hProcess, (LPVOID)MemInfo.BaseAddress, TraceMemory, memSize, &ueNumberOfBytesRead))
            {
                TraceStartAddress = AddressToTrace - (ULONG_PTR)MemInfo.BaseAddress + (ULONG_PTR)TraceMemory;
                if(HashInstructions && InputNumberOfInstructions > NULL)
                {
                    LoopCondition = true;
                }
                else
                {
                    LoopCondition = false;
                }

                while(LoopCondition)
                {
                    SkipHashing = false;
                    SkipThisInstruction = false;
                    CompareMemory = (PMEMORY_CMP_HANDLER)TraceStartAddress;
                    CurrentInstructionSize = StaticLengthDisassemble((LPVOID)TraceStartAddress);
                    CurrentNumberOfInstructions++;
                    /*
                    	Long JUMP (0xE9)
                    */
                    if(HashInstructions == false && CompareMemory->DataByte[0] == 0xE9 && CurrentInstructionSize == 5)
                    {
                        TraceTestAddress = (ULONG_PTR)GetJumpDestination(NULL, TraceStartAddress) - (ULONG_PTR)TraceMemory + (ULONG_PTR)MemInfo.BaseAddress;
                        if(TraceTestAddress <= (ULONG_PTR)MemInfo.BaseAddress || TraceTestAddress >= (ULONG_PTR)MemInfo.BaseAddress + MemInfo.RegionSize)
                        {
                            if(LengthOfValidInstruction == NULL)
                            {
                                if(ImporterGetAPINameFromDebugee(hProcess, TraceTestAddress) != NULL)
                                {
                                    FoundValidAPI = true;
                                    break;
                                }
                            }
                            if(ImporterGetAPINameFromDebugee(hProcess, TraceTestAddress) != NULL)
                            {
                                FoundValidAPI = true;
                                break;
                            }
                            else
                            {
                                if(ImporterGetAPINameFromDebugee(hProcess, TraceTestAddress - LengthOfValidInstruction) != NULL)
                                {
                                    FoundValidAPI = true;
                                    TraceTestAddress = TraceTestAddress - LengthOfValidInstruction;
                                    break;
                                }
                            }
                        }
                        /*
                        	Near JUMP (0xFF25)
                        */
                    }
                    else if(HashInstructions == false && CompareMemory->DataByte[0] == 0xFF && CompareMemory->DataByte[1] == 0x25 && CurrentInstructionSize == 6)
                    {
                        TraceTestAddress = (ULONG_PTR)GetJumpDestination(NULL, TraceStartAddress);
                        if(ReadProcessMemory(hProcess, (LPVOID)TraceTestAddress, &TraceTestAddress, 4, &ueNumberOfBytesRead))
                        {
                            if(TraceTestAddress <= (ULONG_PTR)MemInfo.BaseAddress || TraceTestAddress >= (ULONG_PTR)MemInfo.BaseAddress + MemInfo.RegionSize)
                            {
                                if(LengthOfValidInstruction == NULL)
                                {
                                    if(ImporterGetAPINameFromDebugee(hProcess, TraceTestAddress) != NULL)
                                    {
                                        FoundValidAPI = true;
                                        break;
                                    }
                                }
                                if(ImporterGetAPINameFromDebugee(hProcess, TraceTestAddress) != NULL)
                                {
                                    FoundValidAPI = true;
                                    break;
                                }
                                else
                                {
                                    if(ImporterGetAPINameFromDebugee(hProcess, TraceTestAddress - LengthOfValidInstruction) != NULL)
                                    {
                                        FoundValidAPI = true;
                                        TraceTestAddress = TraceTestAddress - LengthOfValidInstruction;
                                        break;
                                    }
                                }
                            }
                        }
                        /*
                        	PUSH then RET (0x68 ???????? 0xC3)
                        */
                    }
                    else if(HashInstructions == false && CompareMemory->DataByte[0] == 0x68 && CompareMemory->DataByte[5] == 0xC3 && CurrentInstructionSize == 5)
                    {
                        longCompareMemory = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)CompareMemory + 1);
                        TraceTestAddress = (DWORD)(longCompareMemory->Array.dwArrayEntry[0]);
                        if(ReadProcessMemory(hProcess, (LPVOID)TraceTestAddress, &TraceTestReadAddress, 4, &ueNumberOfBytesRead))
                        {
                            if(TraceTestAddress <= (ULONG_PTR)MemInfo.BaseAddress || TraceTestAddress >= (ULONG_PTR)MemInfo.BaseAddress + MemInfo.RegionSize)
                            {
                                if(LengthOfValidInstruction == NULL)
                                {
                                    if(ImporterGetAPINameFromDebugee(hProcess, TraceTestAddress) != NULL)
                                    {
                                        FoundValidAPI = true;
                                        break;
                                    }
                                }
                                if(ImporterGetAPINameFromDebugee(hProcess, TraceTestAddress) != NULL)
                                {
                                    FoundValidAPI = true;
                                    break;
                                }
                                else
                                {
                                    if(ImporterGetAPINameFromDebugee(hProcess, TraceTestAddress - LengthOfValidInstruction) != NULL)
                                    {
                                        FoundValidAPI = true;
                                        TraceTestAddress = TraceTestAddress - LengthOfValidInstruction;
                                        break;
                                    }
                                }
                            }
                            else
                            {
                                TraceStartAddress = TraceStartAddress - (ULONG_PTR)MemInfo.BaseAddress + (ULONG_PTR)TraceMemory;
                            }
                        }
                        /*
                        	CALL (0xE8)
                        */
                    }
                    else if(HashInstructions == true && CompareMemory->DataByte[0] == 0xE8 && CurrentInstructionSize == 5)
                    {
                        SkipHashing = true;
                        InstructionHash = EngineHashMemory((char*)&EmptyCall, CurrentInstructionSize, InstructionHash);
                        /*
                        	PUSH (0x68)
                        */
                    }
                    else if(CompareMemory->DataByte[0] == 0x68 && CurrentInstructionSize == 5)
                    {
                        LastPushValue = (DWORD)(CompareMemory->DataByte[1] + CompareMemory->DataByte[2] * 0x1000 + CompareMemory->DataByte[3] * 0x100000 + CompareMemory->DataByte[4] * 0x10000000);
                        /*
                        	ADD BYTE PTR[AL],AL (0x00, 0x00) -> End of page!
                        */
                    }
                    else if(CompareMemory->DataByte[0] == 0x00 && CurrentInstructionSize == 2)
                    {
                        FoundValidAPI = false;
                        break;
                        /*
                        	RET (0xC3)
                        */
                    }
                    else if(CompareMemory->DataByte[0] == 0xC3 && CurrentInstructionSize == 1)
                    {
                        NumberOfInstructions++;
                        break;
                        /*
                        	RET (0xC2)
                        */
                    }
                    else if(CompareMemory->DataByte[0] == 0xC2 && CurrentInstructionSize == 3)
                    {
                        NumberOfInstructions++;
                        break;
                        /*
                        	Short JUMP (0xEB)
                        */
                    }
                    else if(CompareMemory->DataByte[0] == 0xEB && CurrentInstructionSize == 2)
                    {
                        TraceStartAddress = TraceStartAddress + CompareMemory->DataByte[1];
                        SkipThisInstruction = true;
                        /*
                        	CLC (0xF8)
                        */
                    }
                    else if(CompareMemory->DataByte[0] == 0xF8 && CurrentInstructionSize == 1)
                    {
                        SkipThisInstruction = true;
                        /*
                        	STC (0xF9)
                        */
                    }
                    else if(CompareMemory->DataByte[0] == 0xF9 && CurrentInstructionSize == 1)
                    {
                        SkipThisInstruction = true;
                        /*
                        	NOP (0x90)
                        */
                    }
                    else if(CompareMemory->DataByte[0] == 0x90 && CurrentInstructionSize == 1)
                    {
                        SkipThisInstruction = true;
                        /*
                        	FNOP (0xD9 0xD0)
                        */
                    }
                    else if(CompareMemory->DataByte[0] == 0xD9 && CompareMemory->DataByte[1] == 0xD0 && CurrentInstructionSize == 2)
                    {
                        SkipThisInstruction = true;
                        /*
                        	Multiple MOV
                        */
                    }
                    else if(CompareMemory->DataByte[0] >= 0x8A && CompareMemory->DataByte[0] <= 0x8B)
                    {
                        /*
                        	MOV EAX,EAX (0x8B 0xC8)
                        */
                        if(CompareMemory->DataByte[0] == 0x8B && CompareMemory->DataByte[1] == 0xC8 && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                            	MOV EBX,EBX (0x8B 0xC9)
                            */
                        else if(CompareMemory->DataByte[0] == 0x8B && CompareMemory->DataByte[1] == 0xC9 && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                        MOV ECX,ECX (0x8B 0xDB)
                        */
                        else if(CompareMemory->DataByte[0] == 0x8B && CompareMemory->DataByte[1] == 0xDB && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                           	MOV (0x8B 0xED)
                           */
                        else if(CompareMemory->DataByte[0] == 0x8B && CompareMemory->DataByte[1] == 0xED && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;

                        }
                        /*
                            	MOV (0x8B 0xF6)
                            */
                        else if(CompareMemory->DataByte[0] == 0x8B && CompareMemory->DataByte[1] == 0xF6 && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                        MOV (0x8B 0xE4)
                        */
                        else if(CompareMemory->DataByte[0] == 0x8B && CompareMemory->DataByte[1] == 0xE4 && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                        MOV EDX,EDX (0x8B 0xD2)
                        */
                        else if(CompareMemory->DataByte[0] == 0x8B && CompareMemory->DataByte[1] == 0xD2 && CurrentNumberOfInstructions != 1 && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                            	MOV EDI,EDI (0x8B 0xFF)
                            */
                        else if(CompareMemory->DataByte[0] == 0x8B && CompareMemory->DataByte[1] == 0xFF && CurrentNumberOfInstructions != 1 && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                            	MOV AL,AL (0x8A 0xC0)
                            */
                        else if(CompareMemory->DataByte[0] == 0x8A && CompareMemory->DataByte[1] == 0xC0 && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                            	MOV BL,BL (0x8A 0xDB)
                            */
                        else if(CompareMemory->DataByte[0] == 0x8A && CompareMemory->DataByte[1] == 0xDB && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                            	MOV CL,CL (0x8A 0xC9)
                            */
                        else if(CompareMemory->DataByte[0] == 0x8A && CompareMemory->DataByte[1] == 0xC9 && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                           	MOV (0x8A 0xD2)
                           */
                        else if(CompareMemory->DataByte[0] == 0x8A && CompareMemory->DataByte[1] == 0xD2 && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                            	MOV (0x8A 0xE4)
                            */
                        else if(CompareMemory->DataByte[0] == 0x8A && CompareMemory->DataByte[1] == 0xE4 && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                           	MOV (0x8A 0xED)
                           */
                        else if(CompareMemory->DataByte[0] == 0x8A && CompareMemory->DataByte[1] == 0xED && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                            	MOV (0x8A 0xFF)
                            */
                        else if(CompareMemory->DataByte[0] == 0x8A && CompareMemory->DataByte[1] == 0xFF && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                            	MOV (0x8A 0xF6)
                            */
                        else if(CompareMemory->DataByte[0] == 0x8A && CompareMemory->DataByte[1] == 0xF6 && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                           	MOV AX,AX (0x8B 0xC0)
                           */
                        else if(CompareMemory->DataByte[0] == 0x8B && CompareMemory->DataByte[1] == 0xC0 && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                           	MOV (0x8B 0xDB)
                           */
                        else if(CompareMemory->DataByte[0] == 0x8B && CompareMemory->DataByte[1] == 0xDB && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                            	MOV (0x8B 0xC9)
                            */
                        else if(CompareMemory->DataByte[0] == 0x8B && CompareMemory->DataByte[1] == 0xC9 && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                            	MOV (0x8B 0xF6)
                            */
                        else if(CompareMemory->DataByte[0] == 0x8B && CompareMemory->DataByte[1] == 0xF6 && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                           	MOV (0x8B 0xED)
                           */
                        else if(CompareMemory->DataByte[0] == 0x8B && CompareMemory->DataByte[1] == 0xED && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                    }
                    /*
                        	RDTSC (0x0F 0x31)
                        */
                    else if(CompareMemory->DataByte[0] == 0x0F && CompareMemory->DataByte[1] == 0x31 && CurrentInstructionSize == 2)
                    {
                        SkipThisInstruction = true;
                        /*
                        	CPUID (0x0F 0xA2)
                        */
                    }
                    else if(CompareMemory->DataByte[0] == 0x0F && CompareMemory->DataByte[1] == 0xA2 && CurrentInstructionSize == 2)
                    {
                        SkipThisInstruction = true;
                        /*
                        	XCHG EAX,EAX (0x87 0xC0)
                        */
                    }
                    else if(CompareMemory->DataByte[0] == 0x87 && CompareMemory->DataByte[1] == 0xC0 && CurrentInstructionSize == 2)
                    {
                        SkipThisInstruction = true;
                        /*
                        	SHL EAX,0 - SHL EDI,0 && SHR EAX,0 - SHR EDI,0
                        */
                    }
                    else if(CompareMemory->DataByte[0] == 0xC1 && CurrentInstructionSize == 3)
                    {
                        if(CompareMemory->DataByte[1] >= 0xE0 && CompareMemory->DataByte[1] <= 0xEF && CompareMemory->DataByte[2] == 0x00)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                        	ROR EAX,0 - ROR EDI,0 && ROL EAX,0 - ROL EDI,0
                        */
                    }
                    else if(CompareMemory->DataByte[0] == 0xC1 && CurrentInstructionSize == 3)
                    {
                        if(CompareMemory->DataByte[1] >= 0xC0 && CompareMemory->DataByte[1] <= 0xCF && CompareMemory->DataByte[2] == 0x00)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                        	LEA EAX,DWORD PTR[EAX] -> LEA EDI,DWORD PTR[EDI]
                        */
                    }
                    else if(CompareMemory->DataByte[0] == 0x8D && CurrentInstructionSize == 2)
                    {
                        if(CompareMemory->DataByte[1] == 0x00 || CompareMemory->DataByte[1] == 0x09 || CompareMemory->DataByte[1] == 0x1B || CompareMemory->DataByte[1] == 0x12)
                        {
                            SkipThisInstruction = true;
                        }
                        if(CompareMemory->DataByte[1] == 0x36 || CompareMemory->DataByte[1] == 0x3F)
                        {
                            SkipThisInstruction = true;
                        }
                        if(CompareMemory->DataByte[1] == 0x6D && CompareMemory->DataByte[2] == 0x00)
                        {
                            SkipThisInstruction = true;
                        }
                    }
                    if(!SkipThisInstruction)
                    {
                        if(HashInstructions == true && SkipHashing == false)
                        {
                            InstructionHash = EngineHashMemory((char*)TraceStartAddress, CurrentInstructionSize, InstructionHash);
                        }
                        LengthOfValidInstruction = LengthOfValidInstruction + CurrentInstructionSize;
                        NumberOfInstructions++;
                    }
                    if(HashInstructions)
                    {
                        InputNumberOfInstructions--;
                        if(InputNumberOfInstructions > NULL)
                        {
                            LoopCondition = true;
                        }
                        else
                        {
                            LoopCondition = false;
                        }
                    }
                    else
                    {
                        if(CurrentNumberOfInstructions < 1000 && FoundValidAPI == false)
                        {
                            LoopCondition = true;
                        }
                        else
                        {
                            LoopCondition = false;
                        }
                    }
                    TraceStartAddress = TraceStartAddress + CurrentInstructionSize;
                }
                VirtualFree(TraceMemory, NULL, MEM_RELEASE);
                if(!HashInstructions)
                {
                    if(FoundValidAPI == true)
                    {
                        return((ULONG_PTR)TraceTestAddress);
                    }
                    else if(CurrentNumberOfInstructions < 1000)
                    {
                        if(ImporterGetAPINameFromDebugee(hProcess, LastPushValue) != NULL)
                        {
                            return((ULONG_PTR)LastPushValue);
                        }
                        else if(ImporterGetAPINameFromDebugee(hProcess, LastPushValue - LengthOfValidInstruction) != NULL)
                        {
                            return((ULONG_PTR)(LastPushValue - LengthOfValidInstruction));
                        }
                        return((DWORD)NumberOfInstructions);
                    }
                }
                else
                {
                    return((DWORD)InstructionHash);
                }
            }
            else
            {
                VirtualFree(TraceMemory, NULL, MEM_RELEASE);
            }
        }
    }
    return(NULL);
}
// TitanEngine.Tracer.functions:
__declspec(dllexport) void TITCALL TracerInit()
{
    return;		// UE 1.5 compatibility mode
}
__declspec(dllexport) long long TITCALL TracerLevel1(HANDLE hProcess, ULONG_PTR AddressToTrace)
{
    return((ULONG_PTR)EngineGlobalTracerHandler1(hProcess, AddressToTrace, false, NULL));
}
__declspec(dllexport) long long TITCALL HashTracerLevel1(HANDLE hProcess, ULONG_PTR AddressToTrace, DWORD InputNumberOfInstructions)
{

    unsigned int i = 0;
    unsigned int j = 0;
    DWORD Dummy = NULL;
    MODULEINFO RemoteModuleInfo;
    ULONG_PTR EnumeratedModules[0x2000];
    ULONG_PTR LoadedModules[1000][4];
    char RemoteDLLName[MAX_PATH];
    HANDLE hLoadedModule = NULL;
    HANDLE ModuleHandle = NULL;
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_EXPORT_DIRECTORY PEExports;
    PEXPORTED_DATA ExportedFunctions;
    ULONG_PTR APIFoundAddress = NULL;
    bool ValidateHeader = false;
    bool FileIs64 = false;
    bool FoundAPI = false;
    DWORD CompareHash = NULL;
    DWORD TestHash = NULL;

    if(InputNumberOfInstructions > NULL)
    {
        CompareHash = (DWORD)EngineGlobalTracerHandler1(hProcess, AddressToTrace, true, InputNumberOfInstructions);
    }
    else
    {
        InputNumberOfInstructions = (DWORD)TracerLevel1(hProcess, AddressToTrace);
        if(InputNumberOfInstructions < 1000)
        {
            CompareHash = (DWORD)EngineGlobalTracerHandler1(hProcess, AddressToTrace, true, InputNumberOfInstructions);
        }
        else
        {
            return(NULL);
        }
    }
    RtlZeroMemory(&EnumeratedModules, 0x2000 * sizeof ULONG_PTR);
    RtlZeroMemory(&LoadedModules, 1000 * 4 * sizeof ULONG_PTR);
    if(hProcess == NULL)
    {
        if(dbgProcessInformation.hProcess == NULL)
        {
            hProcess = GetCurrentProcess();
        }
        else
        {
            hProcess = dbgProcessInformation.hProcess;
        }
    }
    if(EnumProcessModules(hProcess, (HMODULE*)EnumeratedModules, 0x2000, &Dummy))
    {
        i++;
        while(FoundAPI == false && EnumeratedModules[i] != NULL)
        {
            ValidateHeader = false;
            RtlZeroMemory(&RemoteDLLName, MAX_PATH);
            GetModuleFileNameExA(hProcess, (HMODULE)EnumeratedModules[i], (LPSTR)RemoteDLLName, MAX_PATH);
            if(GetModuleHandleA(RemoteDLLName) == NULL)
            {
                RtlZeroMemory(&RemoteDLLName, MAX_PATH);
                GetModuleBaseNameA(hProcess, (HMODULE)EnumeratedModules[i], (LPSTR)RemoteDLLName, MAX_PATH);
                if(GetModuleHandleA(RemoteDLLName) == NULL)
                {
                    if(engineAlowModuleLoading)
                    {
                        hLoadedModule = LoadLibraryA(RemoteDLLName);
                        if(hLoadedModule != NULL)
                        {
                            LoadedModules[i][0] = EnumeratedModules[i];
                            LoadedModules[i][1] = (ULONG_PTR)hLoadedModule;
                            LoadedModules[i][2] = 1;
                        }
                    }
                    else
                    {
                        hLoadedModule = (HANDLE)EngineSimulateDllLoader(hProcess, RemoteDLLName);
                        if(hLoadedModule != NULL)
                        {
                            LoadedModules[i][0] = EnumeratedModules[i];
                            LoadedModules[i][1] = (ULONG_PTR)hLoadedModule;
                            LoadedModules[i][2] = 1;
                            ValidateHeader = true;
                        }
                    }
                }
                else
                {
                    LoadedModules[i][0] = EnumeratedModules[i];
                    LoadedModules[i][1] = (ULONG_PTR)GetModuleHandleA(RemoteDLLName);
                    LoadedModules[i][2] = 0;
                }
            }
            else
            {
                LoadedModules[i][0] = EnumeratedModules[i];
                LoadedModules[i][1] = (ULONG_PTR)GetModuleHandleA(RemoteDLLName);
                LoadedModules[i][2] = 0;
            }

            if(!FoundAPI)
            {
                DOSHeader = (PIMAGE_DOS_HEADER)LoadedModules[i][1];
                RtlZeroMemory(&RemoteModuleInfo, sizeof MODULEINFO);
                GetModuleInformation(hProcess, (HMODULE)LoadedModules[i][1], &RemoteModuleInfo, sizeof MODULEINFO);
                if(ValidateHeader || EngineValidateHeader((ULONG_PTR)LoadedModules[i][1], hProcess, RemoteModuleInfo.lpBaseOfDll, DOSHeader, false))
                {
                    PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
                    PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
                    if(PEHeader32->OptionalHeader.Magic == 0x10B)
                    {
                        FileIs64 = false;
                    }
                    else if(PEHeader32->OptionalHeader.Magic == 0x20B)
                    {
                        FileIs64 = true;
                    }
                    else
                    {
                        return(NULL);
                    }
                    if(!FileIs64)
                    {
                        PEExports = (PIMAGE_EXPORT_DIRECTORY)(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + LoadedModules[i][1]);
                        ExportedFunctions = (PEXPORTED_DATA)(PEExports->AddressOfFunctions + LoadedModules[i][1]);
                    }
                    else
                    {
                        PEExports = (PIMAGE_EXPORT_DIRECTORY)(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + LoadedModules[i][1]);
                        ExportedFunctions = (PEXPORTED_DATA)(PEExports->AddressOfFunctions + LoadedModules[i][1]);
                    }
                    for(j = 0; j < PEExports->NumberOfFunctions; j++)
                    {
                        TestHash = (DWORD)EngineGlobalTracerHandler1(hProcess, (ULONG_PTR)(ExportedFunctions->ExportedItem + LoadedModules[i][1]), true, InputNumberOfInstructions);
                        if(TestHash == CompareHash)
                        {
                            APIFoundAddress = (ULONG_PTR)(ExportedFunctions->ExportedItem + LoadedModules[i][0]);
                            FoundAPI = true;
                        }
                        ExportedFunctions = (PEXPORTED_DATA)((ULONG_PTR)ExportedFunctions + 4);
                    }
                }
            }
            i++;
        }
        i = 1;
        while(EnumeratedModules[i] != NULL)
        {
            if(engineAlowModuleLoading)
            {
                if(LoadedModules[i][2] == 1)
                {
                    FreeLibrary((HMODULE)LoadedModules[i][1]);
                }
            }
            else
            {
                if(LoadedModules[i][2] == 1)
                {
                    VirtualFree((void*)LoadedModules[i][1], NULL, MEM_RELEASE);
                }
            }
            i++;
        }
    }
    return((ULONG_PTR)APIFoundAddress);
}
__declspec(dllexport) long TITCALL TracerDetectRedirection(HANDLE hProcess, ULONG_PTR AddressToTrace)
{

    int i,j;
    MEMORY_BASIC_INFORMATION MemInfo;
    DWORD KnownRedirectionIndex = NULL;
    ULONG_PTR ueNumberOfBytesRead = NULL;
    PMEMORY_CMP_HANDLER cMem;
    DWORD MemoryHash = NULL;
    DWORD MaximumReadSize = 0;
    DWORD TestAddressX86;
    LPVOID TraceMemory;
    bool HashCheck = false;

    VirtualQueryEx(hProcess, (LPVOID)AddressToTrace, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
    if(MemInfo.RegionSize > NULL)
    {
        MaximumReadSize = (DWORD)((ULONG_PTR)MemInfo.AllocationBase + MemInfo.RegionSize - AddressToTrace);
        if(MaximumReadSize > 0x1000)
        {
            MaximumReadSize = 0x1000;
            HashCheck = true;
        }
        else if(MaximumReadSize > 256)
        {
            HashCheck = true;
        }
        if(sizeof HANDLE == 4)
        {
            TraceMemory = VirtualAlloc(NULL, MaximumReadSize, MEM_COMMIT, PAGE_READWRITE);
            if(!TraceMemory)
            {
                return (NULL);
            }
            if(ReadProcessMemory(hProcess, (LPVOID)AddressToTrace, TraceMemory, MaximumReadSize, &ueNumberOfBytesRead))
            {
                cMem = (PMEMORY_CMP_HANDLER)TraceMemory;
                if(cMem->DataByte[0] == 0xEB && cMem->DataByte[1] == 0x01 && ((cMem->DataByte[3] >= 0x50 && cMem->DataByte[3] <= 0x5F) || cMem->DataByte[3] == 0x6A || cMem->DataByte[3] == 0x68))
                {
                    KnownRedirectionIndex = NULL;				// ; PeX 0.99 fail safe!
                }
                else if(cMem->DataByte[0] == 0x68 && cMem->DataByte[5] == 0x81 && cMem->DataByte[12] == 0xC3)
                {
                    KnownRedirectionIndex = 1;					//	; RLP 0.7.4 & CryptoPeProtector 0.9.x & ACProtect
                    /*	;$ ==>    >  68 904B4013     PUSH 13404B90
                    	;$+5      >  812C24 0A9E589B SUB DWORD PTR SS:[ESP],9B589E0A
                    	;$+C      >  C3              RET
                    	;$+D      >  68 E21554DF     PUSH DF5415E2
                    	;$+12     >  813424 B6DCB2A8 XOR DWORD PTR SS:[ESP],A8B2DCB6
                    	;$+19     >  C3              RET
                    	;$+1A     >  68 34B2C6B1     PUSH B1C6B234
                    	;$+1F     >  810424 4A2C21C6 ADD DWORD PTR SS:[ESP],C6212C4A
                    	;$+26     >  C3              RET */
                }
                else if(cMem->DataByte[0] == 0xFF && cMem->DataByte[1] == 0x25)
                {
                    KnownRedirectionIndex = 2;					//	; tELock 0.80 - 0.85
                    //	;$ ==>    >- FF25 48018E00   JMP NEAR DWORD PTR DS:[8E0148]
                }
                else if((cMem->DataByte[0] == 0xFF && cMem->DataByte[1] == 0x35) || (cMem->DataByte[1] == 0xFF && cMem->DataByte[2] == 0x35) && (cMem->DataByte[8] == 0xC3 || cMem->DataByte[9] == 0xC3))
                {
                    KnownRedirectionIndex = 3;					//	; tELock 0.90 - 0.95
                    /*	;$ ==>    >  FF35 AE018E00   PUSH DWORD PTR DS:[8E01AE]               ; kernel32.InitializeCriticalSection
                    	;$+6      >  A8 C3           TEST AL,0C3
                    	;$+8      >  C3              RET
                    	;$+9      >  F9              STC
                    	;$+A      >  FF35 B2018E00   PUSH DWORD PTR DS:[8E01B2]               ; kernel32.VirtualFree
                    	;$+10     >  80FA C3         CMP DL,0C3
                    	;$+13     >  C3              RET */
                }
                else if(cMem->DataByte[0] == 0xEB && cMem->DataByte[1] == 0x01 && cMem->DataByte[2] == 0xC9 && cMem->DataByte[3] == 0x60 && cMem->DataByte[4] == 0x0F && cMem->DataByte[5] == 0x31)
                {
                    KnownRedirectionIndex = 8;					//	; AlexProtector 1.x
                    /*	;$ ==>    > /EB 01           JMP SHORT 008413F9
                    	;$+2      > |C9              LEAVE
                    	;$+3      > \60              PUSHAD
                    	;$+4      >  0F31            RDTSC
                    	;$+6      >  EB 01           JMP SHORT 008413FF
                    	;$+8      >  C9              LEAVE
                    	;$+9      >  8BD8            MOV EBX,EAX
                    	;$+B      >  EB 01           JMP SHORT 00841404
                    	;...
                    	;$+33     >  68 E9B9D477     PUSH USER32.PostQuitMessage
                    	;$+38     >  EB 01           JMP SHORT 00841431
                    	;$+3A     >- E9 C3EB01E9     JMP E985FFF8 */
                }
                else if((cMem->DataByte[0] == 0x0B && cMem->DataByte[1] == 0xC5) || (cMem->DataByte[0] == 0x05 && cMem->DataByte[5] == 0xB8 && cMem->DataByte[10] == 0xEB && cMem->DataByte[11] == 0x02))
                {
                    KnownRedirectionIndex = 5;					//	; tELock 0.99 - 1.0 Private!
                    /*	;008E0122    05 F9DEBE71     ADD EAX,71BEDEF9
                    	;008E0127    B8 28018E00     MOV EAX,8E0128
                    	;008E012C    EB 02           JMP SHORT 008E0130
                    	;008E012E    CD 20           INT 20
                    	;008E0130    05 18000000     ADD EAX,18
                    	;008E0135    8B00            MOV EAX,DWORD PTR DS:[EAX]
                    	;008E0137    35 22018E00     XOR EAX,8E0122
                    	;008E013C    90              NOP
                    	;008E013D    90              NOP
                    	;008E013E    50              PUSH EAX
                    	;008E013F    C3              RET
                    	;
                    	;00850036    13C4            ADC EAX,ESP
                    	;00850038    E8 0A000000     CALL 00850047
                    	;0085003D    90              NOP
                    	;0085003E    1BC2            SBB EAX,EDX
                    	;00850040    E9 09000000     JMP 0085004E
                    	;00850045    1BC3            SBB EAX,EBX
                    	;00850047    83F8 74         CMP EAX,74
                    	;0085004A    C3              RET
                    	;0085004B    98              CWDE
                    	;0085004C    33C7            XOR EAX,EDI
                    	;0085004E    D6              SALC
                    	;0085004F    B8 50008500     MOV EAX,850050
                    	;00850054    EB 02           JMP SHORT 00850058
                    	;00850056    CD 20           INT 20
                    	;00850058    05 18000000     ADD EAX,18
                    	;0085005D    8B00            MOV EAX,DWORD PTR DS:[EAX]
                    	;0085005F    35 36008500     XOR EAX,850036
                    	;00850064    90              NOP
                    	;00850065    90              NOP
                    	;00850066    50              PUSH EAX
                    	;00850067    C3              RET */
                }
                else if((cMem->DataByte[0] == 0x13 && cMem->DataByte[1] == 0xC4 && cMem->DataByte[2] == 0xE8) || (cMem->DataByte[0] == 0x83 && cMem->DataByte[3] == 0xE8))
                {
                    KnownRedirectionIndex = 5;					//	; tELock 0.99 - 1.0 Private!
                }
                else if((cMem->DataByte[0] == 0xB8 || cMem->DataByte[0] == 0x1D || cMem->DataByte[0] == 0x0D || cMem->DataByte[0] == 0x2D) && cMem->DataByte[5] == 0xB8 && cMem->DataByte[10] == 0xEB && cMem->DataByte[11] == 0x02)
                {
                    KnownRedirectionIndex = 5;					//	; tELock 0.99 - 1.0 Private!
                    /*	;011F0000    B8 2107F205     MOV EAX,5F20721
                    	;011F0005    B8 06008D00     MOV EAX,8D0006
                    	;011F000A    EB 02           JMP SHORT 011F000E
                    	;011F000C    CD 20           INT 20
                    	;011F000E    05 18000000     ADD EAX,18
                    	;011F0013    8B00            MOV EAX,DWORD PTR DS:[EAX]
                    	;011F0015    35 00008D00     XOR EAX,8D0000
                    	;011F001A    90              NOP
                    	;011F001B    90              NOP
                    	;011F001C    50              PUSH EAX
                    	;011F001D    C3              RET
                    	;
                    	;01360000    1D A508F205     SBB EAX,5F208A5
                    	;01360005    B8 28008D00     MOV EAX,8D0028
                    	;0136000A    EB 02           JMP SHORT 0136000E
                    	;0136000C    CD 20           INT 20
                    	;0136000E    05 18000000     ADD EAX,18
                    	;01360013    8B00            MOV EAX,DWORD PTR DS:[EAX]
                    	;01360015    35 22008D00     XOR EAX,8D0022
                    	;0136001A    90              NOP
                    	;0136001B    90              NOP
                    	;0136001C    50              PUSH EAX
                    	;0136001D    C3              RET
                    	;
                    	;014B0000    0D F918F205     OR EAX,5F218F9
                    	;014B0005    B8 4A008D00     MOV EAX,8D004A
                    	;014B000A    EB 02           JMP SHORT 014B000E
                    	;014B000C    CD 20           INT 20
                    	;014B000E    05 18000000     ADD EAX,18
                    	;014B0013    8B00            MOV EAX,DWORD PTR DS:[EAX]
                    	;014B0015    35 44008D00     XOR EAX,8D0044
                    	;014B001A    90              NOP
                    	;014B001B    90              NOP
                    	;014B001C    50              PUSH EAX
                    	;014B001D    C3              RET
                    	;
                    	;01750000    2D 0B37F205     SUB EAX,5F2370B
                    	;01750005    B8 8E008D00     MOV EAX,8D008E
                    	;0175000A    EB 02           JMP SHORT 0175000E
                    	;0175000C    CD 20           INT 20
                    	;0175000E    05 18000000     ADD EAX,18
                    	;01750013    8B00            MOV EAX,DWORD PTR DS:[EAX]
                    	;01750015    35 88008D00     XOR EAX,8D0088
                    	;0175001A    90              NOP
                    	;0175001B    90              NOP
                    	;0175001C    50              PUSH EAX
                    	;0175001D    C3              RET
                    	;
                    	;019F0000    0BC4            OR EAX,ESP
                    	;019F0002    F9              STC
                    	;019F0003    E8 0B000000     CALL 019F0013
                    	;019F0008    90              NOP
                    	;019F0009    13C4            ADC EAX,ESP
                    	;019F000B    E9 0A000000     JMP 019F001A
                    	;019F0010    F9              STC
                    	;019F0011    13C3            ADC EAX,EBX
                    	;019F0013    98              CWDE
                    	;019F0014    03C2            ADD EAX,EDX
                    	;019F0016    C3              RET
                    	;
                    	;01B40000    48              DEC EAX
                    	;01B40001    E8 0D000000     CALL 01B40013
                    	;01B40006    03C5            ADD EAX,EBP
                    	;01B40008    FC              CLD
                    	;01B40009    E9 0A000000     JMP 01B40018
                    	;01B4000E    35 D82FF205     XOR EAX,5F22FD8
                    	;01B40013    C1C8 9A         ROR EAX,9A
                    	;01B40016    C3              RET */
                }
                else if((cMem->DataByte[0] == 0x0B && cMem->DataByte[1] == 0xC4 && cMem->DataByte[2] == 0xF9 && cMem->DataByte[3] == 0xE8) || (cMem->DataByte[0] == 0x48 && cMem->DataByte[1] == 0xE8))
                {
                    KnownRedirectionIndex = 5;					//	; tELock 0.99 - 1.0 Private!
                }
                else if((cMem->DataByte[0] == 0xB8 && cMem->DataByte[5] == 0xE8 && cMem->DataByte[10] == 0xF9 && cMem->DataByte[11] == 0xE9) && (cMem->DataByte[0] == 0xE8 && cMem->DataByte[1] == 0x0B && cMem->DataByte[10] == 0xE9 && cMem->DataByte[11] == 0x05 && cMem->DataByte[15] == 0x90 && cMem->DataByte[16] == 0xC3))
                {
                    KnownRedirectionIndex = 5;					//	; tELock 0.99 - 1.0 Private!
                    /*	;01C90000    B8 B853F205     MOV EAX,5F253B8
                    	;01C90005    E8 07000000     CALL 01C90011
                    	;01C9000A    F9              STC
                    	;01C9000B    E9 07000000     JMP 01C90017
                    	;01C90010    90              NOP
                    	;01C90011    23C3            AND EAX,EBX
                    	;01C90013    C3              RET
                    	;
                    	;00A40022    1BC2            SBB EAX,EDX
                    	;00A40024    E8 08000000     CALL 00A40031
                    	;00A40029    40              INC EAX
                    	;00A4002A    E9 09000000     JMP 00A40038
                    	;00A4002F    33C7            XOR EAX,EDI
                    	;00A40031    C1E8 92         SHR EAX,92
                    	;00A40034    C3              RET
                    	;00A40035    83E0 25         AND EAX,25
                    	;00A40038    25 E5AE65DD     AND EAX,DD65AEE5
                    	;00A4003D    B8 3E00A400     MOV EAX,0A4003E
                    	;00A40042    EB 02           JMP SHORT 00A40046
                    	;00A40044    CD 20           INT 20
                    	;00A40046    05 18000000     ADD EAX,18
                    	;00A4004B    8B00            MOV EAX,DWORD PTR DS:[EAX]
                    	;00A4004D    35 2200A400     XOR EAX,0A40022
                    	;00A40052    90              NOP
                    	;00A40053    90              NOP
                    	;00A40054    50              PUSH EAX
                    	;00A40055    C3              RET
                    	;
                    	;00A4005A    E8 0B000000     CALL 00A4006A
                    	;00A4005F    15 06F265DD     ADC EAX,DD65F206
                    	;00A40064    E9 05000000     JMP 00A4006E
                    	;00A40069    90              NOP
                    	;00A4006A    C3              RET
                    	;00A4006B    1BC5            SBB EAX,EBP
                    	;00A4006D    40              INC EAX
                    	;00A4006E    1BC0            SBB EAX,EAX
                    	;00A40070    F9              STC
                    	;00A40071    B8 7200A400     MOV EAX,0A40072
                    	;00A40076    EB 02           JMP SHORT 00A4007A
                    	;00A40078    CD 20           INT 20
                    	;00A4007A    05 18000000     ADD EAX,18
                    	;00A4007F    8B00            MOV EAX,DWORD PTR DS:[EAX]
                    	;00A40081    35 5A00A400     XOR EAX,0A4005A
                    	;00A40086    90              NOP
                    	;00A40087    90              NOP
                    	;00A40088    50              PUSH EAX
                    	;00A40089    C3              RET */
                }
                else if(cMem->DataByte[0] == 0x1B && cMem->DataByte[1] == 0xC2 && cMem->DataByte[2] == 0xE8 && cMem->DataByte[3] == 0x08 && cMem->DataByte[7] == 0x40 && cMem->DataByte[8] == 0xE9 && cMem->DataByte[9] == 0x09 && cMem->DataByte[10] == 0x00)
                {
                    KnownRedirectionIndex = 5;					//	; tELock 0.99 - 1.0 Private!
                }
                else if(cMem->DataByte[0] == 0x68 && cMem->DataByte[5] == 0xE9)
                {
                    RtlMoveMemory(&TestAddressX86, &cMem->DataByte[1], 4);
                    if(TestAddressX86 > AddressToTrace)
                    {
                        if(ImporterGetAPIName((ULONG_PTR)TestAddressX86) != NULL)
                        {
                            KnownRedirectionIndex = 6;			//	; ReCrypt 0.74
                            /*	;001739F1    68 E9D9D477     PUSH User32.EndDialog
                            	;001739F6  ^ E9 FDFEFFFF     JMP 001738F8 */
                        }
                    }
                }
                else if((cMem->DataByte[0] == 0xE8 && cMem->DataByte[5] == 0x58 && cMem->DataByte[6] == 0xEB && cMem->DataByte[7] == 0x01) || (cMem->DataByte[0] == 0xC8 && cMem->DataByte[4] == 0xE8 && cMem->DataByte[9] == 0x5B))
                {
                    KnownRedirectionIndex = 7;					//	; Orien 2.1x
                    /* ;GetCommandLineA
                    ;$ ==>    >/$  E8 00000000     CALL crackme_.0040DF8F
                    ;$+5      >|$  58              POP EAX
                    ;$+6      >|.  EB 01           JMP SHORT crackme_.0040DF93
                    ;$+8      >|   B8              DB B8
                    ;$+9      >|>  85DB            TEST EBX,EBX
                    ;$+B      >|.  2D 8F1F0000     SUB EAX,1F8F
                    ;$+10     >|.  EB 01           JMP SHORT crackme_.0040DF9D
                    ;$+12     >|   A8              DB A8
                    ;$+13     >|>  8D80 F0550000   LEA EAX,DWORD PTR DS:[EAX+55F0]
                    ;$+19     >\.  C3              RET
                    ;GetCommandLineW
                    ;$ ==>    > .  E8 00000000     CALL crackme_.0040DFA9
                    ;$+5      >/$  58              POP EAX
                    ;$+6      >|.  EB 01           JMP SHORT crackme_.0040DFAD
                    ;$+8      >|   B8              DB B8
                    ;$+9      >|>  85DB            TEST EBX,EBX
                    ;$+B      >|.  2D A91F0000     SUB EAX,1FA9
                    ;$+10     >|.  EB 01           JMP SHORT crackme_.0040DFB7
                    ;$+12     >|   A8              DB A8
                    ;$+13     >|>  8D80 F4560000   LEA EAX,DWORD PTR DS:[EAX+56F4]
                    ;$+19     >\.  C3              RET
                    ;ExitProcess
                    ;$ ==>    > $  C8 000000       ENTER 0,0
                    ;$+4      > .  E8 00000000     CALL crackme_.0040DF2A
                    ;$+9      > $  5B              POP EBX
                    ;$+A      > .  EB 01           JMP SHORT crackme_.0040DF2E
                    ;$+C      >    B8              DB B8
                    ;$+D      > >  85DB            TEST EBX,EBX
                    ;$+F      > .  81EB 2A1F0000   SUB EBX,1F2A
                    ;$+15     > .  EB 01           JMP SHORT crackme_.0040DF39
                    ;$+17     >    A8              DB A8
                    ;$+18     > >  8D83 4D310000   LEA EAX,DWORD PTR DS:[EBX+314D]
                    ;$+1E     > .  8038 00         CMP BYTE PTR DS:[EAX],0
                    ;$+21     > .  74 29           JE SHORT crackme_.0040DF6D
                    ;$+23     > .  EB 01           JMP SHORT crackme_.0040DF47
                    ;$+25     >    A8              DB A8
                    ;$+26     > >  8D93 55380000   LEA EDX,DWORD PTR DS:[EBX+3855]
                    ;$+2C     > .  E8 01000000     CALL crackme_.0040DF53
                    ;$+31     >    E9              DB E9
                    ;$+32     > $  83EC FC         SUB ESP,-4
                    ;$+35     > .  6A 00           PUSH 0
                    ;$+37     > .  52              PUSH EDX
                    ;$+38     > .  50              PUSH EAX
                    ;$+39     > .  6A 00           PUSH 0
                    ;$+3B     > .  E8 05000000     CALL crackme_.0040DF66
                    ;$+40     > .  EB 0A           JMP SHORT crackme_.0040DF6D
                    ;$+42     >    88              DB 88
                    ;$+43     >    FC              DB FC
                    ;$+44     >    B6              DB B6
                    ;$+45     > $  FFA3 FF3A0000   JMP NEAR DWORD PTR DS:[EBX+3AFF]
                    ;$+4B     >    CD              DB CD
                    ;$+4C     > >  E8 01000000     CALL crackme_.0040DF73
                    ;$+51     >    E9              DB E9
                    ;$+52     > $  83EC FC         SUB ESP,-4
                    ;$+55     > .  FF75 08         PUSH DWORD PTR SS:[EBP+8]
                    ;$+58     > .  E8 05000000     CALL crackme_.0040DF83
                    ;$+5D     > .  EB 0A           JMP SHORT crackme_.0040DF8A
                    ;$+5F     >    88              DB 88
                    ;$+60     >    FC              DB FC
                    ;$+61     >    B6              DB B6
                    ;$+62     > $  FFA3 BF3A0000   JMP NEAR DWORD PTR DS:[EBX+3ABF] */
                }
                else if((cMem->DataByte[0] == 0xEB && cMem->DataByte[1] == 0x01 && cMem->DataByte[2] == 0x66 && cMem->DataByte[3] == 0x1B) || (cMem->DataByte[0] == 0xEB && cMem->DataByte[1] == 0x02 && cMem->DataByte[2] == 0xCD && cMem->DataByte[3] == 0x20) || (cMem->DataByte[0] == 0xEB && cMem->DataByte[1] == 0x01 && cMem->DataByte[2] == 0xB8 && cMem->DataByte[3] == 0xEB))
                {
                    KnownRedirectionIndex = 4;					// ; tELock 0.96 - 0.98
                    /* ;(BYTE PTR[ESI] == 0EBh && (BYTE PTR[ESI+3] == 0EBh || BYTE PTR[ESI+2] == 0EBh))
                    ;017B0000    0BE4            OR ESP,ESP
                    ;017B0002    75 01           JNZ SHORT 017B0005
                    ;
                    ;15940000    85E4            TEST ESP,ESP
                    ;15940002    79 03           JNS SHORT 15940007
                    ;
                    ;008E0359    B8 8DE44500     MOV EAX,45E48D
                    ;008E035E    90              NOP
                    ;008E035F    FF30            PUSH DWORD PTR DS:[EAX]
                    ;008E0361    C3              RET
                    ;
                    ;008F0033    B8 AF008F00     MOV EAX,8F00AF
                    ;008F0038    40              INC EAX
                    ;008F0039    FF30            PUSH DWORD PTR DS:[EAX]
                    ;008F003B    C3              RET
                    ;
                    ;008E02F7    B8 20078E00     MOV EAX,8E0720
                    ;008E02FC    FF20            JMP NEAR DWORD PTR DS:[EAX] */
                }
                else if((cMem->DataByte[0] == 0xEB && cMem->DataByte[1] == 0x03 && cMem->DataByte[2] == 0xFF && cMem->DataByte[3] == 0xEB) || (cMem->DataByte[0] == 0xEB && cMem->DataByte[1] == 0x01 && cMem->DataByte[2] == 0xB8 && cMem->DataByte[3] == 0x05) || (cMem->DataByte[0] == 0xEB && cMem->DataByte[1] == 0x02 && cMem->DataByte[2] == 0xFF && cMem->DataByte[3] == 0x20))
                {
                    KnownRedirectionIndex = 4;					// ; tELock 0.96 - 0.98
                }
                else if((cMem->DataByte[0] == 0xF9 || cMem->DataByte[0] == 0xF8) || (cMem->DataByte[0] == 0x0B && cMem->DataByte[1] == 0xE4) || (cMem->DataByte[0] == 0x85 && cMem->DataByte[1] == 0xE4))
                {
                    KnownRedirectionIndex = 4;					// ; tELock 0.96 - 0.98
                }
                else if(cMem->DataByte[0] == 0xEB && (cMem->DataByte[1] > NULL && cMem->DataByte[1] < 4))
                {
                    i = 2;
                    j = 30;
                    while(j > NULL)
                    {
                        if(cMem->DataByte[i] == 0xB8 && (cMem->DataByte[i+5] == 0x40 || cMem->DataByte[i+5] == 0x90) && cMem->DataByte[i+6] == 0xFF && cMem->DataByte[i+7] == 0x30 && cMem->DataByte[i+8] == 0xC3)
                        {
                            KnownRedirectionIndex = 4;			// ; tELock 0.96 - 0.98
                            j = 1;
                        }
                        i++;
                        j--;
                    }
                }
                else if(HashCheck)
                {
                    if(cMem->DataByte[0] == 0x9C || cMem->DataByte[0] == 0xEB)
                    {
                        MemoryHash = EngineHashMemory((char*)TraceMemory, 192, MemoryHash);
                        if(MemoryHash == 0x5AF7E209 || MemoryHash == 0xEB480CAC || MemoryHash == 0x86218561 || MemoryHash == 0xCA9ABD85)
                        {
                            KnownRedirectionIndex = 9;			// ; SVKP 1.x
                        }
                        else if(MemoryHash == 0xF1F84A98 || MemoryHash == 0x91823290 || MemoryHash == 0xBEE6BAA0 || MemoryHash == 0x79603232)
                        {
                            KnownRedirectionIndex = 9;			// ; SVKP 1.x
                        }
                    }
                }
                VirtualFree(TraceMemory, NULL, MEM_RELEASE);
                return(KnownRedirectionIndex);
            }
            else
            {
                VirtualFree(TraceMemory, NULL, MEM_RELEASE);
            }
        }
    }
    return(NULL);
}
__declspec(dllexport) long long TITCALL TracerFixKnownRedirection(HANDLE hProcess, ULONG_PTR AddressToTrace, DWORD RedirectionId)
{

    int i = NULL;
    DWORD TestAddressX86;
    DWORD ReadAddressX86;
    DWORD MemoryHash = NULL;
    PMEMORY_CMP_HANDLER cMem;
    MEMORY_BASIC_INFORMATION MemInfo;
    ULONG_PTR ueNumberOfBytesRead = NULL;
    LPVOID TracerReadMemory = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    DWORD MaximumReadSize=0x1000;
    if(!TracerReadMemory)
        return (NULL);
    cMem = (PMEMORY_CMP_HANDLER)TracerReadMemory;

    VirtualQueryEx(hProcess, (LPVOID)AddressToTrace, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
    if(MemInfo.RegionSize > NULL)
    {
        MaximumReadSize = (DWORD)((ULONG_PTR)MemInfo.BaseAddress + MemInfo.RegionSize - AddressToTrace);
        if(MaximumReadSize > 0x1000)
        {
            MaximumReadSize = 0x1000;
        }
    }
    if(RedirectionId == NULL)
    {
        RedirectionId = (DWORD)TracerDetectRedirection(hProcess, AddressToTrace);
    }
    if(RedirectionId == 1) 												//	TracerFix_ACProtect
    {
        __try
        {
            if(ReadProcessMemory(hProcess, (LPVOID)AddressToTrace, TracerReadMemory, MaximumReadSize, &ueNumberOfBytesRead))
            {
                RtlMoveMemory(&TestAddressX86, &cMem->DataByte[1], 4);
                if(cMem->DataByte[5] == 0x81 && cMem->DataByte[6] == 0x2C)
                {
                    RtlMoveMemory(&ReadAddressX86, &cMem->DataByte[8], 4);
                    TestAddressX86 = TestAddressX86 - ReadAddressX86;
                }
                else if(cMem->DataByte[5] == 0x81 && cMem->DataByte[6] == 0x34)
                {
                    RtlMoveMemory(&ReadAddressX86, &cMem->DataByte[8], 4);
                    TestAddressX86 = TestAddressX86 ^ ReadAddressX86;
                }
                else if(cMem->DataByte[5] == 0x81 && cMem->DataByte[6] == 0x04)
                {
                    RtlMoveMemory(&ReadAddressX86, &cMem->DataByte[8], 4);
                    TestAddressX86 = TestAddressX86 + ReadAddressX86;
                }
                VirtualFree(TracerReadMemory, NULL, MEM_RELEASE);
                return((DWORD)TestAddressX86);
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            VirtualFree(TracerReadMemory, NULL, MEM_RELEASE);
            return(NULL);
        }
    }
    else if(RedirectionId == 2) 										//	TracerFix_tELock_varA
    {
        __try
        {
            if(ReadProcessMemory(hProcess, (LPVOID)AddressToTrace, TracerReadMemory, MaximumReadSize, &ueNumberOfBytesRead))
            {
                RtlMoveMemory(&TestAddressX86, &cMem->DataByte[2], 4);
                if(ReadProcessMemory(hProcess, (LPVOID)TestAddressX86, &TestAddressX86, 4, &ueNumberOfBytesRead))
                {
                    VirtualFree(TracerReadMemory, NULL, MEM_RELEASE);
                    return((DWORD)TestAddressX86);
                }
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            VirtualFree(TracerReadMemory, NULL, MEM_RELEASE);
            return(NULL);
        }
    }
    else if(RedirectionId == 3) 										//	TracerFix_tELock_varB
    {
        __try
        {
            if(ReadProcessMemory(hProcess, (LPVOID)AddressToTrace, TracerReadMemory, MaximumReadSize, &ueNumberOfBytesRead))
            {
                if(cMem->DataByte[0] == 0xFF && cMem->DataByte[1] == 0x35)
                {
                    RtlMoveMemory(&TestAddressX86, &cMem->DataByte[2], 4);
                }
                else
                {
                    RtlMoveMemory(&TestAddressX86, &cMem->DataByte[3], 4);
                }
                if(ReadProcessMemory(hProcess, (LPVOID)TestAddressX86, &TestAddressX86, 4, &ueNumberOfBytesRead))
                {
                    VirtualFree(TracerReadMemory, NULL, MEM_RELEASE);
                    return((DWORD)TestAddressX86);
                }
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            VirtualFree(TracerReadMemory, NULL, MEM_RELEASE);
            return(NULL);
        }
    }
    else if(RedirectionId == 4) 										//	TracerFix_tELock_varC
    {
        __try
        {
            if(ReadProcessMemory(hProcess, (LPVOID)AddressToTrace, TracerReadMemory, MaximumReadSize, &ueNumberOfBytesRead))
            {
                i = 100;
                if(cMem->DataByte[0] == 0xEB && (cMem->DataByte[1] > 0 && cMem->DataByte[1] < 4))
                {
                    cMem = (PMEMORY_CMP_HANDLER)((ULONG_PTR)cMem + cMem->DataByte[1] + 2);
                }
                while(i > NULL && (cMem->DataByte[0] != 0xFF && (cMem->DataByte[1] != 0x20 || cMem->DataByte[1] != 0x30)))
                {
                    cMem = (PMEMORY_CMP_HANDLER)((ULONG_PTR)cMem + 1);
                    i--;
                }
                if(i != NULL && cMem->DataByte[0] == 0xFF && cMem->DataByte[1] == 0x20)
                {
                    if(cMem->DataByte[2] != 0x90)
                    {
                        cMem = (PMEMORY_CMP_HANDLER)((ULONG_PTR)cMem + 1);
                        while(i > NULL && (cMem->DataByte[0] != 0xFF && (cMem->DataByte[1] != 0x20 || cMem->DataByte[1] != 0x30)))
                        {
                            cMem = (PMEMORY_CMP_HANDLER)((ULONG_PTR)cMem + 1);
                            i--;
                        }
                    }
                }
                if(i != NULL && cMem->DataByte[0] == 0xFF && cMem->DataByte[1] == 0x30)
                {
                    cMem = (PMEMORY_CMP_HANDLER)((ULONG_PTR)cMem - 6);
                    if(cMem->DataByte[0] == 0xB8)
                    {
                        RtlMoveMemory(&TestAddressX86, &cMem->DataByte[1], 4);
                        if(cMem->DataByte[5] == 0x40)
                        {
                            TestAddressX86++;
                        }
                    }
                    else
                    {
                        RtlMoveMemory(&TestAddressX86, &cMem->DataByte[2], 4);
                    }
                    if(ReadProcessMemory(hProcess, (LPVOID)TestAddressX86, &TestAddressX86, 4, &ueNumberOfBytesRead))
                    {
                        VirtualFree(TracerReadMemory, NULL, MEM_RELEASE);
                        return((DWORD)TestAddressX86);
                    }
                }
                else if(i != NULL && cMem->DataByte[0] == 0xFF && cMem->DataByte[1] == 0x20)
                {
                    cMem = (PMEMORY_CMP_HANDLER)((ULONG_PTR)cMem - 6);
                    RtlMoveMemory(&TestAddressX86, &cMem->DataByte[2], 4);
                    if(ReadProcessMemory(hProcess, (LPVOID)TestAddressX86, &TestAddressX86, 4, &ueNumberOfBytesRead))
                    {
                        VirtualFree(TracerReadMemory, NULL, MEM_RELEASE);
                        return((DWORD)TestAddressX86);
                    }
                }
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            VirtualFree(TracerReadMemory, NULL, MEM_RELEASE);
            return(NULL);
        }
    }
    else if(RedirectionId == 5) 										//	TracerFix_tELock_varD
    {
        __try
        {
            if(ReadProcessMemory(hProcess, (LPVOID)AddressToTrace, TracerReadMemory, MaximumReadSize, &ueNumberOfBytesRead))
            {
                i = 100;
                while(i > NULL && (cMem->DataByte[0] != 0x50 || cMem->DataByte[1] != 0xC3))
                {
                    cMem = (PMEMORY_CMP_HANDLER)((ULONG_PTR)cMem + 1);
                    i--;
                }
                if(i != NULL && cMem->DataByte[0] == 0x50 && cMem->DataByte[1] == 0xC3)
                {
                    cMem = (PMEMORY_CMP_HANDLER)((ULONG_PTR)cMem - 0x16);
                    RtlMoveMemory(&ReadAddressX86, &cMem->DataByte[0x10], 4);
                    RtlMoveMemory(&TestAddressX86, &cMem->DataByte[0], 4);
                    TestAddressX86 = TestAddressX86 + 0x18;
                    if(ReadProcessMemory(hProcess, (LPVOID)TestAddressX86, &TestAddressX86, 4, &ueNumberOfBytesRead))
                    {
                        TestAddressX86 = TestAddressX86 ^ ReadAddressX86;
                        VirtualFree(TracerReadMemory, NULL, MEM_RELEASE);
                        return((DWORD)TestAddressX86);
                    }
                }
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            VirtualFree(TracerReadMemory, NULL, MEM_RELEASE);
            return(NULL);
        }
    }
    else if(RedirectionId == 6) 										//	TracerFix_ReCrypt
    {
        __try
        {
            if(ReadProcessMemory(hProcess, (LPVOID)AddressToTrace, TracerReadMemory, MaximumReadSize, &ueNumberOfBytesRead))
            {
                RtlMoveMemory(&TestAddressX86, &cMem->DataByte[1], 4);
                VirtualFree(TracerReadMemory, NULL, MEM_RELEASE);
                return((DWORD)TestAddressX86);
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            VirtualFree(TracerReadMemory, NULL, MEM_RELEASE);
            return(NULL);
        }
    }
    else if(RedirectionId == 7) 										//	TracerFix_Orien
    {
        __try
        {
            if(ReadProcessMemory(hProcess, (LPVOID)AddressToTrace, TracerReadMemory, MaximumReadSize, &ueNumberOfBytesRead))
            {
                if(cMem->DataByte[0] == 0xE8)
                {
                    RtlMoveMemory(&ReadAddressX86, &cMem->DataByte[0x15], 4);
                    if(ReadAddressX86 == 0x55F0)
                    {
                        TestAddressX86 = (DWORD)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetCommandLineA"));
                    }
                    else
                    {
                        TestAddressX86 = (DWORD)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetCommandLineW"));
                    }
                    VirtualFree(TracerReadMemory, NULL, MEM_RELEASE);
                    return((DWORD)TestAddressX86);
                }
                else if(cMem->DataByte[0] == 0xC8)
                {
                    TestAddressX86 = (DWORD)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitProcess"));
                    VirtualFree(TracerReadMemory, NULL, MEM_RELEASE);
                    return((DWORD)TestAddressX86);
                }
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            VirtualFree(TracerReadMemory, NULL, MEM_RELEASE);
            return(NULL);
        }
    }
    else if(RedirectionId == 8) 										//	TracerFix_AlexProtector
    {
        __try
        {
            if(ReadProcessMemory(hProcess, (LPVOID)AddressToTrace, TracerReadMemory, MaximumReadSize, &ueNumberOfBytesRead))
            {
                cMem = (PMEMORY_CMP_HANDLER)((ULONG_PTR)cMem + 0x34);
                RtlMoveMemory(&TestAddressX86, &cMem->DataByte[0], 4);
                VirtualFree(TracerReadMemory, NULL, MEM_RELEASE);
                return((DWORD)TestAddressX86);
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            VirtualFree(TracerReadMemory, NULL, MEM_RELEASE);
            return(NULL);
        }
    }
    else if(RedirectionId == 9 && MaximumReadSize > 192) 				//	TracerFix_SVKP
    {
        __try
        {
            if(ReadProcessMemory(hProcess, (LPVOID)AddressToTrace, TracerReadMemory, MaximumReadSize, &ueNumberOfBytesRead))
            {
                if(cMem->DataByte[0] == 0x9C || cMem->DataByte[0] == 0xEB)
                {
                    MemoryHash = EngineHashMemory((char*)TracerReadMemory, 192, MemoryHash);
                    if(MemoryHash == 0x5AF7E209)
                    {
                        TestAddressX86 = (DWORD)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetCommandLineA"));
                    }
                    else if(MemoryHash == 0xEB480CAC)
                    {
                        TestAddressX86 = (DWORD)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitProcess"));
                    }
                    else if(MemoryHash == 0x86218561)
                    {
                        TestAddressX86 = (DWORD)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetCurrentProcess"));
                    }
                    else if(MemoryHash == 0xCA9ABD85)
                    {
                        TestAddressX86 = (DWORD)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetVersion"));
                    }
                    else if(MemoryHash == 0xF1F84A98)
                    {
                        TestAddressX86 = (DWORD)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetVersionExA"));
                    }
                    else if(MemoryHash == 0x91823290)
                    {
                        TestAddressX86 = (DWORD)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetModuleHandleA"));
                    }
                    else if(MemoryHash == 0xBEE6BAA0)
                    {
                        TestAddressX86 = (DWORD)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA"));
                    }
                    else if(MemoryHash == 0x79603232)
                    {
                        TestAddressX86 = (DWORD)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetModuleHandleA"));
                    }
                    VirtualFree(TracerReadMemory, NULL, MEM_RELEASE);
                    return((DWORD)TestAddressX86);
                }
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            VirtualFree(TracerReadMemory, NULL, MEM_RELEASE);
            return(NULL);
        }
    }
    VirtualFree(TracerReadMemory, NULL, MEM_RELEASE);
    return(NULL);
}
// TitanEngine.Exporter.functions:
__declspec(dllexport) void TITCALL ExporterCleanup()
{

    int i = NULL;

    for(i = 0; i < 1000; i++)
    {
        expExportAddress[i] = 0;
        expSortedNamePointers[i] = 0;
        expNamePointers[i] = 0;
        expNameHashes[i] = 0;
        expOrdinals[i] = 0;
    }
    //RtlZeroMemory(&szExportFileName, 512);
    RtlZeroMemory(&expExportData, sizeof IMAGE_EXPORT_DIRECTORY);
    VirtualFree(expTableData, NULL, MEM_RELEASE);
    expExportNumber = NULL;
    expTableData = NULL;
    expImageBase = NULL;
}
__declspec(dllexport) void TITCALL ExporterSetImageBase(ULONG_PTR ImageBase)
{
    expImageBase = ImageBase;
}
__declspec(dllexport) void TITCALL ExporterInit(DWORD MemorySize, ULONG_PTR ImageBase, DWORD ExportOrdinalBase, char* szExportModuleName)
{

    if(expTableData != NULL)
    {
        ExporterCleanup();
    }
    expExportData.Base = ExportOrdinalBase;
    expTableData = VirtualAlloc(NULL, MemorySize, MEM_COMMIT, PAGE_READWRITE);
    if(szExportModuleName != NULL)
    {
        RtlMoveMemory(expTableData, szExportModuleName, lstrlenA(szExportModuleName));
        expTableDataCWP = (LPVOID)((ULONG_PTR)expTableData + lstrlenA(szExportModuleName) + 2);
        expNamePresent = true;
    }
    else
    {
        expTableDataCWP = expTableData;
        expNamePresent = false;
    }
    expImageBase = ImageBase;
}
__declspec(dllexport) bool TITCALL ExporterAddNewExport(char* szExportName, DWORD ExportRelativeAddress)
{

    unsigned int i;
    DWORD NameHash;

    if(expTableDataCWP != NULL && szExportName != NULL)
    {
        NameHash = (DWORD)EngineHashString(szExportName);
        for(i = 0; i < expExportNumber; i++)
        {
            if(expNameHashes[i] == NameHash)
            {
                return(true);
            }
        }
        expExportAddress[expExportNumber] = ExportRelativeAddress;
        expNamePointers[expExportNumber] = (ULONG_PTR)expTableDataCWP;
        expNameHashes[expExportNumber] = (DWORD)EngineHashString(szExportName);
        expOrdinals[expExportNumber] = (WORD)(expExportNumber);
        RtlMoveMemory(expTableDataCWP, szExportName, lstrlenA(szExportName));
        expTableDataCWP = (LPVOID)((ULONG_PTR)expTableDataCWP + lstrlenA(szExportName) + 2);
        expExportNumber++;
        return(true);
    }
    return(false);
}
__declspec(dllexport) bool TITCALL ExporterAddNewOrdinalExport(DWORD OrdinalNumber, DWORD ExportRelativeAddress)
{

    unsigned int i = NULL;
    char szExportFunctionName[512];

    RtlZeroMemory(&szExportFunctionName, 512);
    if(expTableDataCWP != NULL)
    {
        if(expExportNumber == NULL)
        {
            expExportData.Base = OrdinalNumber;
            wsprintfA(szExportFunctionName, "Func%d", expExportNumber + 1);
            return(ExporterAddNewExport(szExportFunctionName, ExportRelativeAddress));
        }
        else
        {
            if(OrdinalNumber == expExportData.Base + expExportNumber - 1)
            {
                wsprintfA(szExportFunctionName, "Func%d", expExportNumber + 1);
                return(ExporterAddNewExport(szExportFunctionName, ExportRelativeAddress));
            }
            else if(OrdinalNumber > expExportData.Base + expExportNumber - 1)
            {
                for(i = expExportData.Base + expExportNumber - 1; i <= OrdinalNumber; i++)
                {
                    RtlZeroMemory(&szExportFunctionName, 512);
                    wsprintfA(szExportFunctionName, "Func%d", expExportNumber + 1);
                    ExporterAddNewExport(szExportFunctionName, ExportRelativeAddress);
                }
                return(true);
            }
            else
            {
                return(true);
            }
        }
    }
    return(false);
}
__declspec(dllexport) long TITCALL ExporterGetAddedExportCount()
{
    return(expExportNumber);
}
__declspec(dllexport) long TITCALL ExporterEstimatedSize()
{

    DWORD EstimatedSize = NULL;

    EstimatedSize = (DWORD)((ULONG_PTR)expTableDataCWP - (ULONG_PTR)expTableData);
    EstimatedSize = EstimatedSize + (expExportNumber * 12) + sizeof IMAGE_EXPORT_DIRECTORY;
    return(EstimatedSize);
}
__declspec(dllexport) bool TITCALL ExporterBuildExportTable(ULONG_PTR StorePlace, ULONG_PTR FileMapVA)
{

    unsigned int i = NULL;
    unsigned int j = NULL;
    LPVOID expBuildExportDataOld;
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    LPVOID expBuildExportData;
    LPVOID expBuildExportDataCWP;
    DWORD StorePlaceRVA = (DWORD)ConvertFileOffsetToVA(FileMapVA, StorePlace, false);
    ULONG_PTR TempULONG;
    DWORD TempDWORD;
    BOOL FileIs64 = false;

    if(expTableDataCWP != NULL)
    {
        expBuildExportData = VirtualAlloc(NULL, ExporterEstimatedSize(), MEM_COMMIT, PAGE_READWRITE);
        expBuildExportDataCWP = (LPVOID)((ULONG_PTR)expBuildExportData + sizeof IMAGE_EXPORT_DIRECTORY);

        expExportData.NumberOfNames = expExportNumber;
        expExportData.NumberOfFunctions = expExportNumber;
        for(i = 0; i < expExportNumber; i++)
        {
            for(j = 0; j < expExportNumber; j++)
            {
                if(lstrcmpiA((PCHAR)expNamePointers[i], (PCHAR)expNamePointers[j]) < NULL)
                {
                    TempULONG = expNamePointers[j];
                    expNamePointers[j] = expNamePointers[i];
                    expNamePointers[i] = TempULONG;
                    TempDWORD = expExportAddress[j];
                    expExportAddress[j] = expExportAddress[i];
                    expExportAddress[i] = TempDWORD;
                }
            }
        }

        if(expNamePresent)
        {
            expExportData.Name = StorePlaceRVA + (DWORD)((ULONG_PTR)expBuildExportDataCWP - (ULONG_PTR)expBuildExportData);
            RtlMoveMemory(expBuildExportDataCWP, (LPVOID)expTableData, lstrlenA((PCHAR)expTableData));
            expBuildExportDataCWP = (LPVOID)((ULONG_PTR)expBuildExportDataCWP + lstrlenA((PCHAR)expTableData) + 2);
        }
        for(i = 0; i < expExportNumber; i++)
        {
            RtlMoveMemory(expBuildExportDataCWP, (LPVOID)expNamePointers[i], lstrlenA((PCHAR)expNamePointers[i]));
            expBuildExportDataOld = expBuildExportDataCWP;
            expBuildExportDataCWP = (LPVOID)((ULONG_PTR)expBuildExportDataCWP + lstrlenA((PCHAR)expNamePointers[i]) + 2);
            expSortedNamePointers[i] = (DWORD)((ULONG_PTR)expBuildExportDataOld - (ULONG_PTR)expBuildExportData) + StorePlaceRVA;
        }
        expExportData.AddressOfFunctions = StorePlaceRVA + (DWORD)((ULONG_PTR)expBuildExportDataCWP - (ULONG_PTR)expBuildExportData);
        RtlMoveMemory(expBuildExportDataCWP, &expExportAddress, 4 * expExportNumber);
        expBuildExportDataCWP = (LPVOID)((ULONG_PTR)expBuildExportDataCWP + 4 * expExportNumber);
        expExportData.AddressOfNames = StorePlaceRVA + (DWORD)((ULONG_PTR)expBuildExportDataCWP - (ULONG_PTR)expBuildExportData);
        RtlMoveMemory(expBuildExportDataCWP, &expSortedNamePointers, 4 * expExportNumber);
        expBuildExportDataCWP = (LPVOID)((ULONG_PTR)expBuildExportDataCWP + 4 * expExportNumber);
        expExportData.AddressOfNameOrdinals = StorePlaceRVA + (DWORD)((ULONG_PTR)expBuildExportDataCWP - (ULONG_PTR)expBuildExportData);
        RtlMoveMemory(expBuildExportDataCWP, &expOrdinals, 2 * expExportNumber);
        expBuildExportDataCWP = (LPVOID)((ULONG_PTR)expBuildExportDataCWP + 2 * expExportNumber);
        RtlMoveMemory(expBuildExportData, &expExportData, sizeof IMAGE_EXPORT_DIRECTORY);
        __try
        {
            RtlMoveMemory((LPVOID)StorePlace, expBuildExportData, (DWORD)((ULONG_PTR)expBuildExportDataCWP - (ULONG_PTR)expBuildExportData));
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            VirtualFree(expBuildExportData, NULL, MEM_RELEASE);
            ExporterCleanup();
            return(false);
        }

        if(FileMapVA != NULL)
        {
            DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
            if(EngineValidateHeader(FileMapVA, NULL, NULL, DOSHeader, true))
            {
                PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
                PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
                if(PEHeader32->OptionalHeader.Magic == 0x10B)
                {
                    FileIs64 = false;
                }
                else if(PEHeader32->OptionalHeader.Magic == 0x20B)
                {
                    FileIs64 = true;
                }
                else
                {
                    return false;
                }
                if(!FileIs64)
                {
                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = (DWORD)StorePlaceRVA;
                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = (DWORD)((ULONG_PTR)expBuildExportDataCWP - (ULONG_PTR)expBuildExportData);
                }
                else
                {
                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = (DWORD)StorePlaceRVA;
                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = (DWORD)((ULONG_PTR)expBuildExportDataCWP - (ULONG_PTR)expBuildExportData);
                }
            }
        }
        VirtualFree(expBuildExportData, NULL, MEM_RELEASE);
        ExporterCleanup();
        return(true);
    }
    return(false);
}
__declspec(dllexport) bool TITCALL ExporterBuildExportTableEx(char* szExportFileName, char* szSectionName)
{

    wchar_t uniExportFileName[MAX_PATH] = {};

    if(szExportFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szExportFileName, lstrlenA(szExportFileName)+1, uniExportFileName, sizeof(uniExportFileName)/(sizeof(uniExportFileName[0])));
        return(ExporterBuildExportTableExW(uniExportFileName, szSectionName));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL ExporterBuildExportTableExW(wchar_t* szExportFileName, char* szSectionName)
{

    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    DWORD NewSectionVO = NULL;
    DWORD NewSectionFO = NULL;
    bool ReturnValue = false;

    if(ExporterGetAddedExportCount() > NULL)
    {
        NewSectionVO = AddNewSectionW(szExportFileName, szSectionName, ExporterEstimatedSize());
        if(MapFileExW(szExportFileName, UE_ACCESS_ALL, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
        {
            NewSectionFO = (DWORD)ConvertVAtoFileOffset(FileMapVA, NewSectionVO + (ULONG_PTR)GetPE32DataFromMappedFile(FileMapVA, NULL, UE_IMAGEBASE), true);
            ReturnValue = ExporterBuildExportTable(NewSectionFO, FileMapVA);
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            if(ReturnValue)
            {
                return(true);
            }
            else
            {
                return(false);
            }
        }
        else
        {
            return(false);
        }
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL ExporterLoadExportTable(char* szFileName)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        return(ExporterLoadExportTableW(uniFileName));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL ExporterLoadExportTableW(wchar_t* szFileName)
{

    unsigned int i = 0;
    unsigned int j = 0;
    unsigned int n = 0;
    unsigned int x = 0;
    bool ExportPresent = false;
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_EXPORT_DIRECTORY PEExports;
    PEXPORTED_DATA ExportedFunctions;
    PEXPORTED_DATA ExportedFunctionNames;
    PEXPORTED_DATA_WORD ExportedFunctionOrdinals;
    char* ExportName = NULL;
    BOOL FileIs64;
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;

    if(MapFileExW(szFileName, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
        if(EngineValidateHeader(FileMapVA, FileHandle, NULL, DOSHeader, true))
        {
            PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            if(PEHeader32->OptionalHeader.Magic == 0x10B)
            {
                FileIs64 = false;
            }
            else if(PEHeader32->OptionalHeader.Magic == 0x20B)
            {
                FileIs64 = true;
            }
            else
            {
                UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                return(false);
            }
            if(!FileIs64)
            {
                if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != NULL)
                {
                    PEExports = (PIMAGE_EXPORT_DIRECTORY)(ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + PEHeader32->OptionalHeader.ImageBase), true));
                    ExportedFunctions = (PEXPORTED_DATA)(ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)(PEExports->AddressOfFunctions + PEHeader32->OptionalHeader.ImageBase), true));
                    ExporterInit(50 * 1024, (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase, PEExports->Base, NULL);
                    ExportPresent = true;
                }
            }
            else
            {
                if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != NULL)
                {
                    PEExports = (PIMAGE_EXPORT_DIRECTORY)(ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + PEHeader64->OptionalHeader.ImageBase), true));
                    ExportedFunctions = (PEXPORTED_DATA)(ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)(PEExports->AddressOfFunctions + PEHeader64->OptionalHeader.ImageBase), true));
                    ExporterInit(50 * 1024, (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, PEExports->Base, NULL);
                    ExportPresent = true;
                }
            }
            if(ExportPresent)
            {
                for(n = 0; n <= PEExports->NumberOfNames; n++)
                {
                    ExportPresent = false;
                    x = n;
                    if(!FileIs64)
                    {
                        ExportedFunctionNames = (PEXPORTED_DATA)(ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)(PEExports->AddressOfNames + PEHeader32->OptionalHeader.ImageBase), true));
                        ExportedFunctionOrdinals = (PEXPORTED_DATA_WORD)(ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)(PEExports->AddressOfNameOrdinals + PEHeader32->OptionalHeader.ImageBase), true));
                    }
                    else
                    {
                        ExportedFunctionNames = (PEXPORTED_DATA)(ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)(PEExports->AddressOfNames + PEHeader64->OptionalHeader.ImageBase), true));
                        ExportedFunctionOrdinals = (PEXPORTED_DATA_WORD)(ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)(PEExports->AddressOfNameOrdinals + PEHeader64->OptionalHeader.ImageBase), true));
                    }
                    for(j = 0; j <= PEExports->NumberOfNames; j++)
                    {
                        if(ExportedFunctionOrdinals->OrdinalNumber != x)
                        {
                            ExportedFunctionOrdinals = (PEXPORTED_DATA_WORD)((ULONG_PTR)ExportedFunctionOrdinals + 2);
                        }
                        else
                        {
                            ExportPresent = true;
                            break;
                        }
                    }
                    if(ExportPresent)
                    {
                        ExportedFunctionNames = (PEXPORTED_DATA)((ULONG_PTR)ExportedFunctionNames + j * 4);
                        if(!FileIs64)
                        {
                            ExportName = (char*)(ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)(ExportedFunctionNames->ExportedItem + PEHeader32->OptionalHeader.ImageBase), true));
                        }
                        else
                        {
                            ExportName = (char*)(ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)(ExportedFunctionNames->ExportedItem + PEHeader64->OptionalHeader.ImageBase), true));
                        }
                        ExporterAddNewExport(ExportName, ExportedFunctions->ExportedItem);
                    }
                    ExportedFunctions = (PEXPORTED_DATA)((ULONG_PTR)ExportedFunctions + 4);
                }
                UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                return(true);
            }
            else
            {
                UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                return(false);
            }
        }
        else
        {
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            return(false);
        }
    }
    else
    {
        return(false);
    }
    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
    return(false);
}
// TitanEngine.Librarian.functions:
__declspec(dllexport) bool TITCALL LibrarianSetBreakPoint(char* szLibraryName, DWORD bpxType, bool SingleShoot, LPVOID bpxCallBack)
{

    int i = MAX_LIBRARY_BPX;
    PLIBRARY_BREAK_DATA ptrLibrarianData = (PLIBRARY_BREAK_DATA)LibrarianData;

    if(szLibraryName != NULL && ptrLibrarianData != NULL)
    {
        while(i > NULL && ptrLibrarianData->szLibraryName[0] != 0x00)
        {
            ptrLibrarianData = (PLIBRARY_BREAK_DATA)((ULONG_PTR)ptrLibrarianData + sizeof LIBRARY_BREAK_DATA);
            i--;
        }
        lstrcpyA(&ptrLibrarianData->szLibraryName[0], szLibraryName);
        ptrLibrarianData->bpxCallBack = bpxCallBack;
        ptrLibrarianData->bpxSingleShoot = SingleShoot;
        ptrLibrarianData->bpxType = bpxType;
        return(true);
    }
    return(false);
}
__declspec(dllexport) bool TITCALL LibrarianRemoveBreakPoint(char* szLibraryName, DWORD bpxType)
{

    int i = MAX_LIBRARY_BPX;
    PLIBRARY_BREAK_DATA ptrLibrarianData = (PLIBRARY_BREAK_DATA)LibrarianData;

    if(szLibraryName != NULL && ptrLibrarianData != NULL)
    {
        while(i > NULL)
        {
            if(ptrLibrarianData->szLibraryName[0] != 0x00)
            {
                if(lstrcmpiA(szLibraryName, ptrLibrarianData->szLibraryName) == NULL && (ptrLibrarianData->bpxType == bpxType || bpxType == UE_ON_LIB_ALL))
                {
                    RtlZeroMemory(ptrLibrarianData, sizeof LIBRARY_BREAK_DATA);
                }
            }
            ptrLibrarianData = (PLIBRARY_BREAK_DATA)((ULONG_PTR)ptrLibrarianData + sizeof LIBRARY_BREAK_DATA);
            i--;
        }
        return(true);
    }
    return(false);
}
__declspec(dllexport) void* TITCALL LibrarianGetLibraryInfo(char* szLibraryName)
{

    wchar_t uniLibraryName[MAX_PATH] = {};
    PLIBRARY_ITEM_DATAW LibInfo;

    if(szLibraryName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szLibraryName, lstrlenA(szLibraryName)+1, uniLibraryName, sizeof(uniLibraryName)/(sizeof(uniLibraryName[0])));
        LibInfo = (PLIBRARY_ITEM_DATAW)LibrarianGetLibraryInfoW(uniLibraryName);
        if(LibInfo != NULL)
        {
            RtlZeroMemory(&LibraryInfoData, sizeof LIBRARY_ITEM_DATA);
            LibraryInfoData.hFile = LibInfo->hFile;
            LibraryInfoData.BaseOfDll = LibInfo->BaseOfDll;
            LibraryInfoData.hFileMapping = LibInfo->hFileMapping;
            LibraryInfoData.hFileMappingView = LibInfo->hFileMappingView;
            WideCharToMultiByte(CP_ACP, NULL, LibInfo->szLibraryName, -1, &LibraryInfoData.szLibraryName[0], sizeof LibraryInfoData.szLibraryName, NULL, NULL);
            WideCharToMultiByte(CP_ACP, NULL, LibInfo->szLibraryPath, -1, &LibraryInfoData.szLibraryPath[0], sizeof LibraryInfoData.szLibraryPath, NULL, NULL);
            return((void*)&LibraryInfoData);
        }
        else
        {
            return(NULL);
        }
    }
    else
    {
        return(NULL);
    }
}
__declspec(dllexport) void* TITCALL LibrarianGetLibraryInfoW(wchar_t* szLibraryName)
{

    PLIBRARY_ITEM_DATAW hListLibraryPtr = NULL;

    if(hListLibrary != NULL)
    {
        hListLibraryPtr = (PLIBRARY_ITEM_DATAW)hListLibrary;
        while(hListLibraryPtr->hFile != NULL)
        {
            if(hListLibraryPtr->hFile != (HANDLE)-1)
            {
                if(lstrcmpiW(hListLibraryPtr->szLibraryName, szLibraryName) == NULL)
                {
                    return((void*)hListLibraryPtr);
                }
            }
            hListLibraryPtr = (PLIBRARY_ITEM_DATAW)((ULONG_PTR)hListLibraryPtr + sizeof LIBRARY_ITEM_DATAW);
        }
    }
    return(NULL);
}
__declspec(dllexport) void* TITCALL LibrarianGetLibraryInfoEx(void* BaseOfDll)
{

    PLIBRARY_ITEM_DATAW LibInfo;

    LibInfo = (PLIBRARY_ITEM_DATAW)LibrarianGetLibraryInfoExW(BaseOfDll);
    if(LibInfo != NULL)
    {
        RtlZeroMemory(&LibraryInfoData, sizeof LIBRARY_ITEM_DATA);
        LibraryInfoData.hFile = LibInfo->hFile;
        LibraryInfoData.BaseOfDll = LibInfo->BaseOfDll;
        LibraryInfoData.hFileMapping = LibInfo->hFileMapping;
        LibraryInfoData.hFileMappingView = LibInfo->hFileMappingView;
        WideCharToMultiByte(CP_ACP, NULL, LibInfo->szLibraryName, -1, &LibraryInfoData.szLibraryName[0], sizeof LibraryInfoData.szLibraryName, NULL, NULL);
        WideCharToMultiByte(CP_ACP, NULL, LibInfo->szLibraryPath, -1, &LibraryInfoData.szLibraryPath[0], sizeof LibraryInfoData.szLibraryPath, NULL, NULL);
        return((void*)&LibraryInfoData);
    }
    else
    {
        return(NULL);
    }
}
__declspec(dllexport) void* TITCALL LibrarianGetLibraryInfoExW(void* BaseOfDll)
{

    PLIBRARY_ITEM_DATAW hListLibraryPtr = NULL;

    if(hListLibrary != NULL)
    {
        hListLibraryPtr = (PLIBRARY_ITEM_DATAW)hListLibrary;
        while(hListLibraryPtr->hFile != NULL)
        {
            if(hListLibraryPtr->hFile != (HANDLE)-1)
            {
                if(hListLibraryPtr->BaseOfDll == BaseOfDll)
                {
                    return((void*)hListLibraryPtr);
                }
            }
            hListLibraryPtr = (PLIBRARY_ITEM_DATAW)((ULONG_PTR)hListLibraryPtr + sizeof LIBRARY_ITEM_DATAW);
        }
    }
    return(NULL);
}
__declspec(dllexport) void TITCALL LibrarianEnumLibraryInfo(void* EnumCallBack)
{

    PLIBRARY_ITEM_DATAW hListLibraryPtr = NULL;
    typedef void(TITCALL *fEnumCallBack)(LPVOID fLibraryDetail);
    fEnumCallBack myEnumCallBack = (fEnumCallBack)EnumCallBack;

    if(hListLibrary != NULL)
    {
        hListLibraryPtr = (PLIBRARY_ITEM_DATAW)hListLibrary;
        while(EnumCallBack != NULL && hListLibraryPtr->hFile != NULL)
        {
            if(hListLibraryPtr->hFile != (HANDLE)-1)
            {
                __try
                {
                    myEnumCallBack((void*)hListLibraryPtr);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    EnumCallBack = NULL;
                }
            }
            hListLibraryPtr = (PLIBRARY_ITEM_DATAW)((ULONG_PTR)hListLibraryPtr + sizeof LIBRARY_ITEM_DATAW);
        }
    }
}
__declspec(dllexport) void TITCALL LibrarianEnumLibraryInfoW(void* EnumCallBack)
{

    LIBRARY_ITEM_DATA myLibraryInfoData;
    PLIBRARY_ITEM_DATAW hListLibraryPtr = NULL;
    typedef void(TITCALL *fEnumCallBack)(LPVOID fLibraryDetail);
    fEnumCallBack myEnumCallBack = (fEnumCallBack)EnumCallBack;

    if(hListLibrary != NULL)
    {
        hListLibraryPtr = (PLIBRARY_ITEM_DATAW)hListLibrary;
        while(EnumCallBack != NULL && hListLibraryPtr->hFile != NULL)
        {
            if(hListLibraryPtr->hFile != (HANDLE)-1)
            {
                __try
                {
                    RtlZeroMemory(&myLibraryInfoData, sizeof LIBRARY_ITEM_DATA);
                    myLibraryInfoData.hFile = hListLibraryPtr->hFile;
                    myLibraryInfoData.BaseOfDll = hListLibraryPtr->BaseOfDll;
                    myLibraryInfoData.hFileMapping = hListLibraryPtr->hFileMapping;
                    myLibraryInfoData.hFileMappingView = hListLibraryPtr->hFileMappingView;
                    WideCharToMultiByte(CP_ACP, NULL, hListLibraryPtr->szLibraryName, -1, &myLibraryInfoData.szLibraryName[0], sizeof myLibraryInfoData.szLibraryName, NULL, NULL);
                    WideCharToMultiByte(CP_ACP, NULL, hListLibraryPtr->szLibraryPath, -1, &myLibraryInfoData.szLibraryPath[0], sizeof myLibraryInfoData.szLibraryPath, NULL, NULL);
                    myEnumCallBack((void*)&myLibraryInfoData);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    EnumCallBack = NULL;
                }
            }
            hListLibraryPtr = (PLIBRARY_ITEM_DATAW)((ULONG_PTR)hListLibraryPtr + sizeof LIBRARY_ITEM_DATAW);
        }
    }
}
// TitanEngine.Process.functions:
__declspec(dllexport) long TITCALL GetActiveProcessId(char* szImageName)
{

    wchar_t uniImageName[MAX_PATH] = {};

    if(szImageName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szImageName, lstrlenA(szImageName)+1, uniImageName, sizeof(uniImageName)/(sizeof(uniImageName[0])));
        return(GetActiveProcessIdW(uniImageName));
    }
    else
    {
        return(NULL);
    }
}
__declspec(dllexport) long TITCALL GetActiveProcessIdW(wchar_t* szImageName)
{

    int i;
    wchar_t* szTranslatedProcName;
    DWORD bProcessId[1024] = {};
    wchar_t szProcessPath[1024] = {};
    DWORD pProcessIdCount = NULL;
    HANDLE hProcess;

    if(EnumProcesses(bProcessId, sizeof bProcessId, &pProcessIdCount))
    {
        for(i = 0; i < (int)pProcessIdCount; i++)
        {
            if(bProcessId[i] != NULL)
            {
                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, bProcessId[i]);
                if(hProcess != NULL)
                {
                    if(GetProcessImageFileNameW(hProcess, szProcessPath, 1024) > NULL)
                    {
                        szTranslatedProcName = (wchar_t*)TranslateNativeNameW(szProcessPath);
                        lstrcpyW(szProcessPath, szTranslatedProcName);
                        VirtualFree((void*)szTranslatedProcName, NULL, MEM_RELEASE);
                        EngineCloseHandle(hProcess);
                        if(lstrcmpiW(szProcessPath, szImageName) == NULL)
                        {
                            return(bProcessId[i]);
                        }
                        else if(lstrcmpiW(EngineExtractFileNameW(szProcessPath), szImageName) == NULL)
                        {
                            return(bProcessId[i]);
                        }
                    }
                    else
                    {
                        EngineCloseHandle(hProcess);
                    }
                }
            }
        }
    }
    return(NULL);
}
__declspec(dllexport) void TITCALL EnumProcessesWithLibrary(char* szLibraryName, void* EnumFunction)
{

    int i;
    int j;
    typedef void(TITCALL *fEnumFunction)(DWORD ProcessId, HMODULE ModuleBaseAddress);
    fEnumFunction myEnumFunction = (fEnumFunction)EnumFunction;
    HMODULE EnumeratedModules[1024] = {};
    DWORD bProcessId[1024] = {};
    char szModuleName[1024] = {};
    DWORD pProcessIdCount = NULL;
    DWORD pModuleCount;
    HANDLE hProcess;

    if(EnumFunction != NULL)
    {
        if(EnumProcesses(bProcessId, sizeof bProcessId, &pProcessIdCount))
        {
            for(i = 0; i < (int)pProcessIdCount; i++)
            {
                if(bProcessId[i] != NULL)
                {
                    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, bProcessId[i]);
                    if(hProcess != NULL)
                    {
                        RtlZeroMemory(&EnumeratedModules[0], sizeof EnumeratedModules);
                        if(EnumProcessModules(hProcess, (HMODULE*)EnumeratedModules, sizeof EnumeratedModules, &pModuleCount))
                        {
                            for(j = 0; j < (int)pModuleCount; j++)
                            {
                                if(EnumeratedModules[j] != NULL)
                                {
                                    if(GetModuleBaseNameA(hProcess, EnumeratedModules[j], szModuleName, 1024) > NULL)
                                    {
                                        if(lstrcmpiA(szModuleName, szLibraryName) == NULL)
                                        {
                                            __try
                                            {
                                                myEnumFunction(bProcessId[i], EnumeratedModules[j]);
                                            }
                                            __except(EXCEPTION_EXECUTE_HANDLER)
                                            {
                                                EngineCloseHandle(hProcess);
                                                return;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        EngineCloseHandle(hProcess);
                    }
                }
            }
        }
    }
}
// TitanEngine.TLSFixer.functions:
__declspec(dllexport) bool TITCALL TLSBreakOnCallBack(LPVOID ArrayOfCallBacks, DWORD NumberOfCallBacks, LPVOID bpxCallBack)
{

    unsigned int i;
    LPVOID ReadArrayOfCallBacks = ArrayOfCallBacks;

    if(NumberOfCallBacks > NULL)
    {
        for(i = 0; i < NumberOfCallBacks; i++)
        {
            RtlMoveMemory(&tlsCallBackList[i], ReadArrayOfCallBacks, sizeof ULONG_PTR);
            ReadArrayOfCallBacks = (LPVOID)((ULONG_PTR)ReadArrayOfCallBacks + sizeof ULONG_PTR);
        }
        engineTLSBreakOnCallBackAddress = (ULONG_PTR)bpxCallBack;
        engineTLSBreakOnCallBack = true;
        return(true);
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL TLSGrabCallBackData(char* szFileName, LPVOID ArrayOfCallBacks, LPDWORD NumberOfCallBacks)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        return(TLSGrabCallBackDataW(uniFileName, ArrayOfCallBacks, NumberOfCallBacks));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL TLSGrabCallBackDataW(wchar_t* szFileName, LPVOID ArrayOfCallBacks, LPDWORD NumberOfCallBacks)
{

    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    BOOL FileIs64;
    PIMAGE_TLS_DIRECTORY32 TLSDirectoryX86;
    PIMAGE_TLS_DIRECTORY64 TLSDirectoryX64;
    ULONG_PTR TLSDirectoryAddress;
    ULONG_PTR TLSCallBackAddress;
    ULONG_PTR TLSCompareData = NULL;
    DWORD NumberOfTLSCallBacks = NULL;

    if(MapFileExW(szFileName, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
        if(EngineValidateHeader(FileMapVA, FileHandle, NULL, DOSHeader, true))
        {
            PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            if(PEHeader32->OptionalHeader.Magic == 0x10B)
            {
                FileIs64 = false;
            }
            else if(PEHeader32->OptionalHeader.Magic == 0x20B)
            {
                FileIs64 = true;
            }
            else
            {
                UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                return(false);
            }
            if(!FileIs64)
            {
                if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL)
                {
                    TLSDirectoryAddress = (ULONG_PTR)((ULONG_PTR)PEHeader32->OptionalHeader.ImageBase + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
                    TLSDirectoryX86 = (PIMAGE_TLS_DIRECTORY32)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryAddress, true);
                    if(TLSDirectoryX86->AddressOfCallBacks != NULL)
                    {
                        TLSCallBackAddress = (ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryX86->AddressOfCallBacks, true);
                        while(memcmp((LPVOID)TLSCallBackAddress, &TLSCompareData, sizeof ULONG_PTR) != NULL)
                        {
                            RtlMoveMemory(ArrayOfCallBacks, (LPVOID)TLSCallBackAddress, sizeof ULONG_PTR);
                            ArrayOfCallBacks = (LPVOID)((ULONG_PTR)ArrayOfCallBacks + sizeof ULONG_PTR);
                            TLSCallBackAddress = TLSCallBackAddress + sizeof ULONG_PTR;
                            NumberOfTLSCallBacks++;
                        }
                        *NumberOfCallBacks = NumberOfTLSCallBacks;
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(true);
                    }
                    else
                    {
                        *NumberOfCallBacks = NULL;
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(false);
                    }
                }
                else
                {
                    *NumberOfCallBacks = NULL;
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return(false);
                }
            }
            else
            {
                if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL)
                {
                    TLSDirectoryAddress = (ULONG_PTR)((ULONG_PTR)PEHeader64->OptionalHeader.ImageBase + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
                    TLSDirectoryX64 = (PIMAGE_TLS_DIRECTORY64)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryAddress, true);
                    if(TLSDirectoryX64->AddressOfCallBacks != NULL)
                    {
                        TLSCallBackAddress = (ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryX64->AddressOfCallBacks, true);
                        while(memcmp((LPVOID)TLSCallBackAddress, &TLSCompareData, sizeof ULONG_PTR) != NULL)
                        {
                            RtlMoveMemory(ArrayOfCallBacks, (LPVOID)TLSCallBackAddress, sizeof ULONG_PTR);
                            ArrayOfCallBacks = (LPVOID)((ULONG_PTR)ArrayOfCallBacks + sizeof ULONG_PTR);
                            TLSCallBackAddress = TLSCallBackAddress + sizeof ULONG_PTR;
                            NumberOfTLSCallBacks++;
                        }
                        *NumberOfCallBacks = NumberOfTLSCallBacks;
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(true);
                    }
                    else
                    {
                        *NumberOfCallBacks = NULL;
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(false);
                    }
                }
                else
                {
                    *NumberOfCallBacks = NULL;
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return(false);
                }
            }
        }
        else
        {
            *NumberOfCallBacks = NULL;
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            return(false);
        }
    }
    return(false);
}
__declspec(dllexport) bool TITCALL TLSBreakOnCallBackEx(char* szFileName, LPVOID bpxCallBack)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        return(TLSBreakOnCallBackExW(uniFileName, bpxCallBack));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL TLSBreakOnCallBackExW(wchar_t* szFileName, LPVOID bpxCallBack)
{

    ULONG_PTR TlsArrayOfCallBacks[100];
    DWORD TlsNumberOfCallBacks;

    RtlZeroMemory(&TlsArrayOfCallBacks, 100 * sizeof ULONG_PTR);
    if(szFileName != NULL)
    {
        if(TLSGrabCallBackDataW(szFileName, &TlsArrayOfCallBacks, &TlsNumberOfCallBacks))
        {
            TLSBreakOnCallBack(&TlsArrayOfCallBacks, TlsNumberOfCallBacks, bpxCallBack);
            return(true);
        }
        else
        {
            return(false);
        }
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL TLSRemoveCallback(char* szFileName)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        return(TLSRemoveCallbackW(uniFileName));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL TLSRemoveCallbackW(wchar_t* szFileName)
{

    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    BOOL FileIs64;
    PIMAGE_TLS_DIRECTORY32 TLSDirectoryX86;
    PIMAGE_TLS_DIRECTORY64 TLSDirectoryX64;
    ULONG_PTR TLSDirectoryAddress;

    if(MapFileExW(szFileName, UE_ACCESS_ALL, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
        if(EngineValidateHeader(FileMapVA, FileHandle, NULL, DOSHeader, true))
        {
            PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            if(PEHeader32->OptionalHeader.Magic == 0x10B)
            {
                FileIs64 = false;
            }
            else if(PEHeader32->OptionalHeader.Magic == 0x20B)
            {
                FileIs64 = true;
            }
            else
            {
                UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                return(false);
            }
            if(!FileIs64)
            {
                if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL)
                {
                    __try
                    {
                        TLSDirectoryAddress = (ULONG_PTR)((ULONG_PTR)PEHeader32->OptionalHeader.ImageBase + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
                        TLSDirectoryX86 = (PIMAGE_TLS_DIRECTORY32)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryAddress, true);
                        if(TLSDirectoryX86->AddressOfCallBacks != NULL)
                        {
                            TLSDirectoryX86->AddressOfCallBacks = NULL;
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return(true);
                        }
                        else
                        {
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return(false);
                        }
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(false);
                    }
                }
                else
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return(false);
                }
            }
            else
            {
                if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL)
                {
                    __try
                    {
                        TLSDirectoryAddress = (ULONG_PTR)((ULONG_PTR)PEHeader64->OptionalHeader.ImageBase + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
                        TLSDirectoryX64 = (PIMAGE_TLS_DIRECTORY64)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryAddress, true);
                        if(TLSDirectoryX64->AddressOfCallBacks != NULL)
                        {
                            TLSDirectoryX64->AddressOfCallBacks = NULL;
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return(true);
                        }
                        else
                        {
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return(false);
                        }
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(false);
                    }
                }
                else
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return(false);
                }
            }
        }
        else
        {
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            return(false);
        }
    }
    return(false);
}
__declspec(dllexport) bool TITCALL TLSRemoveTable(char* szFileName)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        return(TLSRemoveTableW(uniFileName));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL TLSRemoveTableW(wchar_t* szFileName)
{

    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    BOOL FileIs64;
    PIMAGE_TLS_DIRECTORY32 TLSDirectoryX86;
    PIMAGE_TLS_DIRECTORY64 TLSDirectoryX64;
    ULONG_PTR TLSDirectoryAddress;

    if(MapFileExW(szFileName, UE_ACCESS_ALL, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
        if(EngineValidateHeader(FileMapVA, FileHandle, NULL, DOSHeader, true))
        {
            PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            if(PEHeader32->OptionalHeader.Magic == 0x10B)
            {
                FileIs64 = false;
            }
            else if(PEHeader32->OptionalHeader.Magic == 0x20B)
            {
                FileIs64 = true;
            }
            else
            {
                UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                return(false);
            }
            if(!FileIs64)
            {
                if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL)
                {
                    __try
                    {
                        TLSDirectoryAddress = (ULONG_PTR)((ULONG_PTR)PEHeader32->OptionalHeader.ImageBase + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
                        TLSDirectoryX86 = (PIMAGE_TLS_DIRECTORY32)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryAddress, true);
                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = NULL;
                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = NULL;
                        RtlZeroMemory(TLSDirectoryX86, sizeof IMAGE_TLS_DIRECTORY32);
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(true);
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(false);
                    }
                }
                else
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return(false);
                }
            }
            else
            {
                if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL)
                {
                    __try
                    {
                        TLSDirectoryAddress = (ULONG_PTR)((ULONG_PTR)PEHeader64->OptionalHeader.ImageBase + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
                        TLSDirectoryX64 = (PIMAGE_TLS_DIRECTORY64)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryAddress, true);
                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = NULL;
                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = NULL;
                        RtlZeroMemory(TLSDirectoryX64, sizeof IMAGE_TLS_DIRECTORY64);
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(true);
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(false);
                    }
                }
                else
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return(false);
                }
            }
        }
        else
        {
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            return(false);
        }
    }
    return(false);
}
__declspec(dllexport) bool TITCALL TLSBackupData(char* szFileName)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        return(TLSBackupDataW(uniFileName));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL TLSBackupDataW(wchar_t* szFileName)
{

    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    BOOL FileIs64;
    PIMAGE_TLS_DIRECTORY32 TLSDirectoryX86;
    PIMAGE_TLS_DIRECTORY64 TLSDirectoryX64;
    ULONG_PTR TLSDirectoryAddress;
    ULONG_PTR TLSCallBackAddress;
    ULONG_PTR TLSCompareData = NULL;
    DWORD NumberOfTLSCallBacks = NULL;
    LPVOID ArrayOfCallBacks = &engineBackupArrayOfCallBacks;
    LPDWORD NumberOfCallBacks = &engineBackupNumberOfCallBacks;

    engineBackupTLSAddress = NULL;
    RtlZeroMemory(engineBackupArrayOfCallBacks, 0x1000);
    RtlZeroMemory(&engineBackupTLSDataX86, sizeof IMAGE_TLS_DIRECTORY32);
    RtlZeroMemory(&engineBackupTLSDataX64, sizeof IMAGE_TLS_DIRECTORY64);
    if(MapFileExW(szFileName, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
        if(EngineValidateHeader(FileMapVA, FileHandle, NULL, DOSHeader, true))
        {
            PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            if(PEHeader32->OptionalHeader.Magic == 0x10B)
            {
                FileIs64 = false;
            }
            else if(PEHeader32->OptionalHeader.Magic == 0x20B)
            {
                FileIs64 = true;
            }
            else
            {
                UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                return(false);
            }
            if(!FileIs64)
            {
                if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL)
                {
                    __try
                    {
                        engineBackupTLSx64 = false;
                        engineBackupTLSAddress = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
                        TLSDirectoryAddress = (ULONG_PTR)((ULONG_PTR)PEHeader32->OptionalHeader.ImageBase + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
                        TLSDirectoryX86 = (PIMAGE_TLS_DIRECTORY32)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryAddress, true);
                        RtlMoveMemory(&engineBackupTLSDataX86, (LPVOID)TLSDirectoryX86, sizeof IMAGE_TLS_DIRECTORY32);
                        if(TLSDirectoryX86->AddressOfCallBacks != NULL)
                        {
                            TLSCallBackAddress = (ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryX86->AddressOfCallBacks, true);
                            while(memcmp((LPVOID)TLSCallBackAddress, &TLSCompareData, sizeof ULONG_PTR) != NULL)
                            {
                                RtlMoveMemory(ArrayOfCallBacks, (LPVOID)TLSCallBackAddress, sizeof ULONG_PTR);
                                ArrayOfCallBacks = (LPVOID)((ULONG_PTR)ArrayOfCallBacks + sizeof ULONG_PTR);
                                TLSCallBackAddress = TLSCallBackAddress + sizeof ULONG_PTR;
                                NumberOfTLSCallBacks++;
                            }
                            *NumberOfCallBacks = NumberOfTLSCallBacks;
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return(true);
                        }
                        else
                        {
                            *NumberOfCallBacks = NULL;
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return(false);
                        }
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        *NumberOfCallBacks = NULL;
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(false);
                    }
                }
                else
                {
                    *NumberOfCallBacks = NULL;
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return(false);
                }
            }
            else
            {
                if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL)
                {
                    __try
                    {
                        engineBackupTLSx64 = true;
                        engineBackupTLSAddress = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
                        TLSDirectoryAddress = (ULONG_PTR)((ULONG_PTR)PEHeader64->OptionalHeader.ImageBase + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
                        TLSDirectoryX64 = (PIMAGE_TLS_DIRECTORY64)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryAddress, true);
                        RtlMoveMemory(&engineBackupTLSDataX64, (LPVOID)TLSDirectoryX64, sizeof IMAGE_TLS_DIRECTORY64);
                        if(TLSDirectoryX64->AddressOfCallBacks != NULL)
                        {
                            TLSCallBackAddress = (ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryX64->AddressOfCallBacks, true);
                            while(memcmp((LPVOID)TLSCallBackAddress, &TLSCompareData, sizeof ULONG_PTR) != NULL)
                            {
                                RtlMoveMemory(ArrayOfCallBacks, (LPVOID)TLSCallBackAddress, sizeof ULONG_PTR);
                                ArrayOfCallBacks = (LPVOID)((ULONG_PTR)ArrayOfCallBacks + sizeof ULONG_PTR);
                                TLSCallBackAddress = TLSCallBackAddress + sizeof ULONG_PTR;
                                NumberOfTLSCallBacks++;
                            }
                            *NumberOfCallBacks = NumberOfTLSCallBacks;
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return(true);
                        }
                        else
                        {
                            *NumberOfCallBacks = NULL;
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return(false);
                        }
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        *NumberOfCallBacks = NULL;
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(false);
                    }
                }
                else
                {
                    *NumberOfCallBacks = NULL;
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return(false);
                }
            }
        }
        else
        {
            *NumberOfCallBacks = NULL;
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            return(false);
        }
    }
    return(false);
}
__declspec(dllexport) bool TITCALL TLSRestoreData()
{

    ULONG_PTR ueNumberOfBytesRead = NULL;

    if(dbgProcessInformation.hProcess != NULL && engineBackupTLSAddress != NULL)
    {
        if(engineBackupTLSx64)
        {
            if(WriteProcessMemory(dbgProcessInformation.hProcess, (LPVOID)(engineBackupTLSAddress + GetDebuggedFileBaseAddress()), &engineBackupTLSDataX64, sizeof IMAGE_TLS_DIRECTORY64, &ueNumberOfBytesRead))
            {
                if(engineBackupTLSDataX64.AddressOfCallBacks != NULL && engineBackupNumberOfCallBacks != NULL)
                {
                    if(WriteProcessMemory(dbgProcessInformation.hProcess, (LPVOID)(engineBackupTLSDataX64.AddressOfCallBacks + GetDebuggedFileBaseAddress()), engineBackupArrayOfCallBacks, sizeof IMAGE_TLS_DIRECTORY64, &ueNumberOfBytesRead))
                    {
                        engineBackupTLSAddress = NULL;
                        return(true);
                    }
                }
                else
                {
                    engineBackupTLSAddress = NULL;
                    return(true);
                }
            }
        }
        else
        {
            if(WriteProcessMemory(dbgProcessInformation.hProcess, (LPVOID)(engineBackupTLSAddress + GetDebuggedFileBaseAddress()), &engineBackupTLSDataX86, sizeof IMAGE_TLS_DIRECTORY32, &ueNumberOfBytesRead))
            {
                if(engineBackupTLSDataX86.AddressOfCallBacks != NULL && engineBackupNumberOfCallBacks != NULL)
                {
                    if(WriteProcessMemory(dbgProcessInformation.hProcess, (LPVOID)(engineBackupTLSDataX86.AddressOfCallBacks + GetDebuggedFileBaseAddress()), engineBackupArrayOfCallBacks, sizeof IMAGE_TLS_DIRECTORY32, &ueNumberOfBytesRead))
                    {
                        engineBackupTLSAddress = NULL;
                        return(true);
                    }
                }
                else
                {
                    engineBackupTLSAddress = NULL;
                    return(true);
                }
            }
        }
    }
    return(false);
}
__declspec(dllexport) bool TITCALL TLSBuildNewTable(ULONG_PTR FileMapVA, ULONG_PTR StorePlace, ULONG_PTR StorePlaceRVA, LPVOID ArrayOfCallBacks, DWORD NumberOfCallBacks)
{

    BOOL FileIs64;
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_TLS_DIRECTORY32 TLSDirectoryX86;
    PIMAGE_TLS_DIRECTORY64 TLSDirectoryX64;
    ULONG_PTR TLSWriteData = StorePlaceRVA;

    if(FileMapVA != NULL)
    {
        DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
        if(EngineValidateHeader(FileMapVA, NULL, NULL, DOSHeader, true))
        {
            PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            if(PEHeader32->OptionalHeader.Magic == 0x10B)
            {
                FileIs64 = false;
            }
            else if(PEHeader32->OptionalHeader.Magic == 0x20B)
            {
                FileIs64 = true;
            }
            else
            {
                return(false);
            }
            if(!FileIs64)
            {
                __try
                {
                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = (DWORD)StorePlaceRVA;
                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = sizeof IMAGE_TLS_DIRECTORY32;
                    TLSDirectoryX86 = (PIMAGE_TLS_DIRECTORY32)StorePlace;
                    TLSDirectoryX86->StartAddressOfRawData = (DWORD)TLSWriteData;
                    TLSDirectoryX86->EndAddressOfRawData = (DWORD)TLSWriteData + 0x10;
                    TLSDirectoryX86->AddressOfIndex = (DWORD)TLSWriteData + 0x14;
                    TLSDirectoryX86->AddressOfCallBacks = (DWORD)TLSWriteData  + sizeof IMAGE_TLS_DIRECTORY32 + 8;
                    RtlMoveMemory((LPVOID)(StorePlace + sizeof IMAGE_TLS_DIRECTORY32 + 8), ArrayOfCallBacks, NumberOfCallBacks * 4);
                    return(true);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    return(false);
                }
            }
            else
            {
                __try
                {
                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = (DWORD)StorePlaceRVA;
                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = sizeof IMAGE_TLS_DIRECTORY64;
                    TLSDirectoryX64 = (PIMAGE_TLS_DIRECTORY64)StorePlace;
                    TLSDirectoryX64->StartAddressOfRawData = TLSWriteData;
                    TLSDirectoryX64->EndAddressOfRawData = TLSWriteData + 0x20;
                    TLSDirectoryX64->AddressOfIndex = TLSWriteData + 0x28;
                    TLSDirectoryX64->AddressOfCallBacks = TLSWriteData  + sizeof IMAGE_TLS_DIRECTORY64 + 12;
                    RtlMoveMemory((LPVOID)(StorePlace + sizeof IMAGE_TLS_DIRECTORY64 + 12), ArrayOfCallBacks, NumberOfCallBacks * 8);
                    return(true);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    return(false);
                }
            }
        }
        else
        {
            return(false);
        }
    }
    return(false);
}
__declspec(dllexport) bool TITCALL TLSBuildNewTableEx(char* szFileName, char* szSectionName, LPVOID ArrayOfCallBacks, DWORD NumberOfCallBacks)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        return(TLSBuildNewTableExW(uniFileName, szSectionName, ArrayOfCallBacks, NumberOfCallBacks));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL TLSBuildNewTableExW(wchar_t* szFileName, char* szSectionName, LPVOID ArrayOfCallBacks, DWORD NumberOfCallBacks)
{

    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    DWORD NewSectionVO = NULL;
    DWORD NewSectionFO = NULL;
    bool ReturnValue = false;
    ULONG_PTR tlsImageBase;

    tlsImageBase = (ULONG_PTR)GetPE32DataW(szFileName, NULL, UE_IMAGEBASE);
    NewSectionVO = AddNewSectionW(szFileName, szSectionName, sizeof IMAGE_TLS_DIRECTORY64 * 2);
    if(MapFileExW(szFileName, UE_ACCESS_ALL, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        NewSectionFO = (DWORD)ConvertVAtoFileOffset(FileMapVA, NewSectionVO + tlsImageBase, true);
        ReturnValue = TLSBuildNewTable(FileMapVA, NewSectionFO, NewSectionVO, ArrayOfCallBacks, NumberOfCallBacks);
        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
        if(ReturnValue)
        {
            return(true);
        }
        else
        {
            return(false);
        }
    }
    else
    {
        return(false);
    }
}
// TitanEngine.TranslateName.functions:
__declspec(dllexport) void* TITCALL TranslateNativeName(char* szNativeName)
{

    LPVOID TranslatedName = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    char szDeviceName[3] = "A:";
    char szDeviceCOMName[5] = "COM0";
    int CurrentDeviceLen;

    while(szDeviceName[0] <= 0x5A)
    {
        RtlZeroMemory(TranslatedName, 0x1000);
        if(QueryDosDeviceA(szDeviceName, (LPSTR)TranslatedName, 0x1000) > NULL)
        {
            CurrentDeviceLen = lstrlenA((LPSTR)TranslatedName);
            lstrcatA((LPSTR)TranslatedName, (LPCSTR)(szNativeName + CurrentDeviceLen));
            if(lstrcmpiA((LPCSTR)TranslatedName, szNativeName) == NULL)
            {
                RtlZeroMemory(TranslatedName, 0x1000);
                lstrcatA((LPSTR)TranslatedName, szDeviceName);
                lstrcatA((LPSTR)TranslatedName, (LPCSTR)(szNativeName + CurrentDeviceLen));
                return(TranslatedName);
            }
        }
        szDeviceName[0]++;
    }
    while(szDeviceCOMName[3] <= 0x39)
    {
        RtlZeroMemory(TranslatedName, 0x1000);
        if(QueryDosDeviceA(szDeviceCOMName, (LPSTR)TranslatedName, 0x1000) > NULL)
        {
            CurrentDeviceLen = lstrlenA((LPSTR)TranslatedName);
            lstrcatA((LPSTR)TranslatedName, (LPCSTR)(szNativeName + CurrentDeviceLen));
            if(lstrcmpiA((LPCSTR)TranslatedName, szNativeName) == NULL)
            {
                RtlZeroMemory(TranslatedName, 0x1000);
                lstrcatA((LPSTR)TranslatedName, szDeviceCOMName);
                lstrcatA((LPSTR)TranslatedName, (LPCSTR)(szNativeName + CurrentDeviceLen));
                return(TranslatedName);
            }
        }
        szDeviceCOMName[3]++;
    }
    VirtualFree(TranslatedName, NULL, MEM_RELEASE);
    return(NULL);
}
__declspec(dllexport) void* TITCALL TranslateNativeNameW(wchar_t* szNativeName)
{

    LPVOID TranslatedName = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    wchar_t szDeviceName[3] = L"A:";
    wchar_t szDeviceCOMName[5] = L"COM0";
    int CurrentDeviceLen;

    while(szDeviceName[0] <= 0x5A)
    {
        RtlZeroMemory(TranslatedName, 0x1000);
        if(QueryDosDeviceW(szDeviceName, (LPWSTR)TranslatedName, MAX_PATH * 2) > NULL)
        {
            CurrentDeviceLen = lstrlenW((LPWSTR)TranslatedName);
            lstrcatW((LPWSTR)TranslatedName, (LPCWSTR)(szNativeName + CurrentDeviceLen));
            if(lstrcmpiW((LPCWSTR)TranslatedName, szNativeName) == NULL)
            {
                RtlZeroMemory(TranslatedName, 0x1000);
                lstrcatW((LPWSTR)TranslatedName, szDeviceName);
                lstrcatW((LPWSTR)TranslatedName, (LPWSTR)(szNativeName + CurrentDeviceLen));
                return(TranslatedName);
            }
        }
        szDeviceName[0]++;
    }
    while(szDeviceCOMName[3] <= 0x39)
    {
        RtlZeroMemory(TranslatedName, 0x1000);
        if(QueryDosDeviceW(szDeviceCOMName, (LPWSTR)TranslatedName, MAX_PATH * 2) > NULL)
        {
            CurrentDeviceLen = lstrlenW((LPWSTR)TranslatedName);
            lstrcatW((LPWSTR)TranslatedName, (LPCWSTR)(szNativeName + CurrentDeviceLen));
            if(lstrcmpiW((LPCWSTR)TranslatedName, szNativeName) == NULL)
            {
                RtlZeroMemory(TranslatedName, 0x1000);
                lstrcatW((LPWSTR)TranslatedName, szDeviceCOMName);
                lstrcatW((LPWSTR)TranslatedName, (LPWSTR)(szNativeName + CurrentDeviceLen));
                return(TranslatedName);
            }
        }
        szDeviceCOMName[3]++;
    }
    VirtualFree(TranslatedName, NULL, MEM_RELEASE);
    return(NULL);
}
// TitanEngine.Handler.functions:
__declspec(dllexport) long TITCALL HandlerGetActiveHandleCount(DWORD ProcessId)
{

    int HandleCount = NULL;
    LPVOID QuerySystemBuffer;
    ULONG QuerySystemBufferSize = 0x2000;
    ULONG RequiredSize = NULL;
    ULONG TotalHandleCount = NULL;
#if !defined(_WIN64)
    typedef NTSTATUS(WINAPI *fZwQuerySystemInformation)(DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
    typedef NTSTATUS(WINAPI *fZwQueryObject)(HANDLE hObject, DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
#else
    typedef NTSTATUS(__fastcall *fZwQuerySystemInformation)(DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
    typedef NTSTATUS(__fastcall *fZwQueryObject)(HANDLE hObject, DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
#endif
    LPVOID ZwQuerySystemInformation = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"),"ZwQuerySystemInformation");
    LPVOID ZwQueryObject = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"),"ZwQueryObject");
    fZwQuerySystemInformation cZwQuerySystemInformation = (fZwQuerySystemInformation)(ZwQuerySystemInformation);
    fZwQueryObject cZwQueryObject = (fZwQueryObject)(ZwQueryObject);
    PNTDLL_QUERY_HANDLE_INFO HandleInfo;

    if(ZwQuerySystemInformation != NULL && ZwQueryObject != NULL)
    {
        QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
        while(cZwQuerySystemInformation(NTDLL_SystemHandleInfo, QuerySystemBuffer, QuerySystemBufferSize, &RequiredSize) == (NTSTATUS)0xC0000004L)
        {
            QuerySystemBufferSize = RequiredSize;
            VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
            QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
        }
        RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
        QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
        while(TotalHandleCount > NULL)
        {
            if(HandleInfo->ProcessId == ProcessId)
            {
                HandleCount++;
            }
            HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
            TotalHandleCount--;
        }
        VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
        return(HandleCount);
    }
    return(NULL);
}
__declspec(dllexport) bool TITCALL HandlerIsHandleOpen(DWORD ProcessId, HANDLE hHandle)
{

    bool HandleActive = false;
    LPVOID QuerySystemBuffer;
    ULONG QuerySystemBufferSize = 0x2000;
    ULONG RequiredSize = NULL;
    ULONG TotalHandleCount = NULL;
#if !defined(_WIN64)
    typedef NTSTATUS(WINAPI *fZwQuerySystemInformation)(DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
#else
    typedef NTSTATUS(__fastcall *fZwQuerySystemInformation)(DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
#endif
    LPVOID ZwQuerySystemInformation = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"),"ZwQuerySystemInformation");
    fZwQuerySystemInformation cZwQuerySystemInformation = (fZwQuerySystemInformation)(ZwQuerySystemInformation);
    PNTDLL_QUERY_HANDLE_INFO HandleInfo;

    if(ZwQuerySystemInformation != NULL)
    {
        QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
        while(cZwQuerySystemInformation(NTDLL_SystemHandleInfo, QuerySystemBuffer, QuerySystemBufferSize, &RequiredSize) == (NTSTATUS)0xC0000004L)
        {
            QuerySystemBufferSize = RequiredSize;
            VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
            QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
        }
        RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
        QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
        while(TotalHandleCount > NULL)
        {
            if(HandleInfo->ProcessId == ProcessId && (HANDLE)HandleInfo->hHandle == hHandle)
            {
                HandleActive = true;
                break;
            }
            HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
            TotalHandleCount--;
        }
        VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
        if(HandleActive)
        {
            return(true);
        }
    }
    return(false);
}
__declspec(dllexport) void* TITCALL HandlerGetHandleName(HANDLE hProcess, DWORD ProcessId, HANDLE hHandle, bool TranslateName)
{

    bool NameFound = false;
    HANDLE myHandle = NULL;
    LPVOID QuerySystemBuffer;
    ULONG QuerySystemBufferSize = 0x2000;
    ULONG RequiredSize = NULL;
    ULONG TotalHandleCount = NULL;
#if !defined(_WIN64)
    typedef NTSTATUS(WINAPI *fZwQuerySystemInformation)(DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
    typedef NTSTATUS(WINAPI *fZwQueryObject)(HANDLE hObject, DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
#else
    typedef NTSTATUS(__fastcall *fZwQuerySystemInformation)(DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
    typedef NTSTATUS(__fastcall *fZwQueryObject)(HANDLE hObject, DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
#endif
    LPVOID ZwQuerySystemInformation = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"),"ZwQuerySystemInformation");
    LPVOID ZwQueryObject = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"),"ZwQueryObject");
    fZwQuerySystemInformation cZwQuerySystemInformation = (fZwQuerySystemInformation)(ZwQuerySystemInformation);
    fZwQueryObject cZwQueryObject = (fZwQueryObject)(ZwQueryObject);
    PNTDLL_QUERY_HANDLE_INFO HandleInfo;
    PUBLIC_OBJECT_BASIC_INFORMATION ObjectBasicInfo;
    LPVOID ObjectNameInfo = VirtualAlloc(NULL, 0x2000, MEM_COMMIT, PAGE_READWRITE);
    PPUBLIC_OBJECT_NAME_INFORMATION pObjectNameInfo = (PPUBLIC_OBJECT_NAME_INFORMATION)ObjectNameInfo;
    LPVOID HandleFullName = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    LPVOID tmpHandleFullName = NULL;

    if(ZwQuerySystemInformation != NULL && ZwQueryObject != NULL)
    {
        QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
        while(cZwQuerySystemInformation(NTDLL_SystemHandleInfo, QuerySystemBuffer, QuerySystemBufferSize, &RequiredSize) == (NTSTATUS)0xC0000004L)
        {
            QuerySystemBufferSize = RequiredSize;
            VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
            QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
        }
        RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
        QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
        while(TotalHandleCount > NULL)
        {
            if(HandleInfo->ProcessId == ProcessId && (HANDLE)HandleInfo->hHandle == hHandle)
            {
                //if(!(HandleInfo->GrantedAccess & SYNCHRONIZE) || ((HandleInfo->GrantedAccess & SYNCHRONIZE) && ((WORD)HandleInfo->GrantedAccess != 0x19F9))){// && (WORD)HandleInfo->GrantedAccess != 0x89))){
                if(HandleInfo->GrantedAccess != 0x0012019F)
                {
                    if(DuplicateHandle(hProcess, hHandle, GetCurrentProcess(), &myHandle, NULL, false, DUPLICATE_SAME_ACCESS))
                    {
                        RtlZeroMemory(&ObjectBasicInfo, sizeof PUBLIC_OBJECT_BASIC_INFORMATION);
                        cZwQueryObject(myHandle, ObjectBasicInformation, &ObjectBasicInfo, sizeof PUBLIC_OBJECT_BASIC_INFORMATION, &RequiredSize);
                        cZwQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, 8, &RequiredSize);
                        cZwQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, RequiredSize, &RequiredSize);
                        RtlZeroMemory(HandleFullName, 0x1000);
                        if(pObjectNameInfo->Name.Length != NULL)
                        {
                            WideCharToMultiByte(CP_ACP, NULL, (LPCWSTR)pObjectNameInfo->Name.Buffer, -1, (LPSTR)HandleFullName, 0x1000, NULL, NULL);
                            NameFound = true;
                            if(TranslateName)
                            {
                                tmpHandleFullName = TranslateNativeName((char*)HandleFullName);
                                if(tmpHandleFullName != NULL)
                                {
                                    VirtualFree(HandleFullName, NULL, MEM_RELEASE);
                                    HandleFullName = tmpHandleFullName;
                                }
                            }
                        }
                        EngineCloseHandle(myHandle);
                        break;
                    }
                }
            }
            HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
            TotalHandleCount--;
        }
        VirtualFree(ObjectNameInfo, NULL, MEM_RELEASE);
        VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
        if(!NameFound)
        {
            VirtualFree(HandleFullName, NULL, MEM_RELEASE);
            return(NULL);
        }
        else
        {
            return(HandleFullName);
        }
    }
    VirtualFree(HandleFullName, NULL, MEM_RELEASE);
    VirtualFree(ObjectNameInfo, NULL, MEM_RELEASE);
    return(NULL);
}
__declspec(dllexport) void* TITCALL HandlerGetHandleNameW(HANDLE hProcess, DWORD ProcessId, HANDLE hHandle, bool TranslateName)
{

    bool NameFound = false;
    HANDLE myHandle = NULL;
    LPVOID QuerySystemBuffer;
    ULONG QuerySystemBufferSize = 0x2000;
    ULONG RequiredSize = NULL;
    ULONG TotalHandleCount = NULL;
#if !defined(_WIN64)
    typedef NTSTATUS(WINAPI *fZwQuerySystemInformation)(DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
    typedef NTSTATUS(WINAPI *fZwQueryObject)(HANDLE hObject, DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
#else
    typedef NTSTATUS(__fastcall *fZwQuerySystemInformation)(DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
    typedef NTSTATUS(__fastcall *fZwQueryObject)(HANDLE hObject, DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
#endif
    LPVOID ZwQuerySystemInformation = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"),"ZwQuerySystemInformation");
    LPVOID ZwQueryObject = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"),"ZwQueryObject");
    fZwQuerySystemInformation cZwQuerySystemInformation = (fZwQuerySystemInformation)(ZwQuerySystemInformation);
    fZwQueryObject cZwQueryObject = (fZwQueryObject)(ZwQueryObject);
    PNTDLL_QUERY_HANDLE_INFO HandleInfo;
    PUBLIC_OBJECT_BASIC_INFORMATION ObjectBasicInfo;
    LPVOID ObjectNameInfo = VirtualAlloc(NULL, 0x2000, MEM_COMMIT, PAGE_READWRITE);
    PPUBLIC_OBJECT_NAME_INFORMATION pObjectNameInfo = (PPUBLIC_OBJECT_NAME_INFORMATION)ObjectNameInfo;
    LPVOID HandleFullName = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    LPVOID tmpHandleFullName = NULL;

    if(ZwQuerySystemInformation != NULL && ZwQueryObject != NULL)
    {
        QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
        while(cZwQuerySystemInformation(NTDLL_SystemHandleInfo, QuerySystemBuffer, QuerySystemBufferSize, &RequiredSize) == (NTSTATUS)0xC0000004L)
        {
            QuerySystemBufferSize = RequiredSize;
            VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
            QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
        }
        RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
        QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
        while(TotalHandleCount > NULL)
        {
            if(HandleInfo->ProcessId == ProcessId && (HANDLE)HandleInfo->hHandle == hHandle)
            {
                //if(!(HandleInfo->GrantedAccess & SYNCHRONIZE) || ((HandleInfo->GrantedAccess & SYNCHRONIZE) && ((WORD)HandleInfo->GrantedAccess != 0x19F9))){// && (WORD)HandleInfo->GrantedAccess != 0x89))){
                if(HandleInfo->GrantedAccess != 0x0012019F)
                {
                    if(DuplicateHandle(hProcess, hHandle, GetCurrentProcess(), &myHandle, NULL, false, DUPLICATE_SAME_ACCESS))
                    {
                        RtlZeroMemory(&ObjectBasicInfo, sizeof PUBLIC_OBJECT_BASIC_INFORMATION);
                        cZwQueryObject(myHandle, ObjectBasicInformation, &ObjectBasicInfo, sizeof PUBLIC_OBJECT_BASIC_INFORMATION, &RequiredSize);
                        cZwQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, 8, &RequiredSize);
                        cZwQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, RequiredSize, &RequiredSize);
                        RtlZeroMemory(HandleFullName, 0x1000);
                        if(pObjectNameInfo->Name.Length != NULL)
                        {
                            //WideCharToMultiByte(CP_ACP, NULL, (LPCWSTR)pObjectNameInfo->Name.Buffer, -1, (LPSTR)HandleFullName, 0x1000, NULL, NULL);
                            NameFound = true;
                            lstrcpyW((wchar_t*)HandleFullName, (wchar_t*)pObjectNameInfo->Name.Buffer);
                            if(TranslateName)
                            {
                                tmpHandleFullName = TranslateNativeNameW((wchar_t*)HandleFullName);
                                if(tmpHandleFullName != NULL)
                                {
                                    VirtualFree(HandleFullName, NULL, MEM_RELEASE);
                                    HandleFullName = tmpHandleFullName;
                                }
                            }
                        }
                        EngineCloseHandle(myHandle);
                        break;
                    }
                }
            }
            HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
            TotalHandleCount--;
        }
        VirtualFree(ObjectNameInfo, NULL, MEM_RELEASE);
        VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
        if(!NameFound)
        {
            VirtualFree(HandleFullName, NULL, MEM_RELEASE);
            return(NULL);
        }
        else
        {
            return(HandleFullName);
        }
    }
    VirtualFree(HandleFullName, NULL, MEM_RELEASE);
    VirtualFree(ObjectNameInfo, NULL, MEM_RELEASE);
    return(NULL);
}
__declspec(dllexport) long TITCALL HandlerEnumerateOpenHandles(DWORD ProcessId, LPVOID HandleBuffer, DWORD MaxHandleCount)
{

    HANDLE myHandle = NULL;
    LPVOID QuerySystemBuffer;
    ULONG RequiredSize = NULL;
    ULONG TotalHandleCount = NULL;
    unsigned int HandleCount = NULL;
    ULONG QuerySystemBufferSize = 0x2000;
#if !defined(_WIN64)
    typedef NTSTATUS(WINAPI *fZwQuerySystemInformation)(DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
#else
    typedef NTSTATUS(__fastcall *fZwQuerySystemInformation)(DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
#endif
    LPVOID ZwQuerySystemInformation = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"),"ZwQuerySystemInformation");
    fZwQuerySystemInformation cZwQuerySystemInformation = (fZwQuerySystemInformation)(ZwQuerySystemInformation);
    PNTDLL_QUERY_HANDLE_INFO HandleInfo;

    if(ZwQuerySystemInformation != NULL)
    {
        QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
        while(cZwQuerySystemInformation(NTDLL_SystemHandleInfo, QuerySystemBuffer, QuerySystemBufferSize, &RequiredSize) == (NTSTATUS)0xC0000004L)
        {
            QuerySystemBufferSize = RequiredSize;
            VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
            QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
        }
        RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
        QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
        while(TotalHandleCount > NULL)
        {
            if(HandleInfo->ProcessId == ProcessId && HandleCount < MaxHandleCount)
            {
                myHandle = (HANDLE)HandleInfo->hHandle;
                RtlMoveMemory(HandleBuffer, &myHandle, sizeof HANDLE);
                HandleBuffer = (LPVOID)((ULONG_PTR)HandleBuffer + sizeof HANDLE);
                HandleCount++;
            }
            HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
            TotalHandleCount--;
        }
        VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
        return(HandleCount);
    }
    return(NULL);
}
__declspec(dllexport) long long TITCALL HandlerGetHandleDetails(HANDLE hProcess, DWORD ProcessId, HANDLE hHandle, DWORD InformationReturn)
{

    HANDLE myHandle = NULL;
    LPVOID QuerySystemBuffer;
    ULONG QuerySystemBufferSize = 0x2000;
    ULONG RequiredSize = NULL;
    ULONG TotalHandleCount = NULL;
#if !defined(_WIN64)
    typedef NTSTATUS(WINAPI *fZwQuerySystemInformation)(DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
    typedef NTSTATUS(WINAPI *fZwQueryObject)(HANDLE hObject, DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
#else
    typedef NTSTATUS(__fastcall *fZwQuerySystemInformation)(DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
    typedef NTSTATUS(__fastcall *fZwQueryObject)(HANDLE hObject, DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
#endif
    LPVOID ZwQuerySystemInformation = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"),"ZwQuerySystemInformation");
    LPVOID ZwQueryObject = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"),"ZwQueryObject");
    fZwQuerySystemInformation cZwQuerySystemInformation = (fZwQuerySystemInformation)(ZwQuerySystemInformation);
    fZwQueryObject cZwQueryObject = (fZwQueryObject)(ZwQueryObject);
    PNTDLL_QUERY_HANDLE_INFO HandleInfo;
    PUBLIC_OBJECT_BASIC_INFORMATION ObjectBasicInfo;
    LPVOID HandleFullData = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    LPVOID HandleNameData = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    PPUBLIC_OBJECT_TYPE_INFORMATION pObjectTypeInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)HandleFullData;
    bool DontFreeStringMemory = false;
    ULONG_PTR ReturnData = NULL;

    if(ZwQuerySystemInformation != NULL && ZwQueryObject != NULL)
    {
        QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
        while(cZwQuerySystemInformation(NTDLL_SystemHandleInfo, QuerySystemBuffer, QuerySystemBufferSize, &RequiredSize) == (NTSTATUS)0xC0000004L)
        {
            QuerySystemBufferSize = RequiredSize;
            VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
            QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
        }
        RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
        QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
        while(TotalHandleCount > NULL)
        {
            if(HandleInfo->ProcessId == ProcessId && (HANDLE)HandleInfo->hHandle == hHandle)
            {
                if(DuplicateHandle(hProcess, hHandle, GetCurrentProcess(), &myHandle, NULL, false, DUPLICATE_SAME_ACCESS))
                {
                    RtlZeroMemory(&ObjectBasicInfo, sizeof PUBLIC_OBJECT_BASIC_INFORMATION);
                    cZwQueryObject(myHandle, ObjectBasicInformation, &ObjectBasicInfo, sizeof PUBLIC_OBJECT_BASIC_INFORMATION, &RequiredSize);
                    if(InformationReturn == UE_OPTION_HANDLER_RETURN_HANDLECOUNT)
                    {
                        ReturnData = (ULONG_PTR)ObjectBasicInfo.HandleCount;
                    }
                    else if(InformationReturn == UE_OPTION_HANDLER_RETURN_ACCESS)
                    {
                        ReturnData = (ULONG_PTR)HandleInfo->GrantedAccess;
                    }
                    else if(InformationReturn == UE_OPTION_HANDLER_RETURN_FLAGS)
                    {
                        ReturnData = (ULONG_PTR)HandleInfo->Flags;
                    }
                    else if(InformationReturn == UE_OPTION_HANDLER_RETURN_TYPENAME)
                    {
                        //if(!(HandleInfo->GrantedAccess & SYNCHRONIZE) || ((HandleInfo->GrantedAccess & SYNCHRONIZE) && ((WORD)HandleInfo->GrantedAccess != 0x19F9))){// && (WORD)HandleInfo->GrantedAccess != 0x89))){
                        if(HandleInfo->GrantedAccess != 0x0012019F)
                        {
                            RtlZeroMemory(HandleFullData, 0x1000);
                            cZwQueryObject(myHandle, ObjectTypeInformation, HandleFullData, 8, &RequiredSize);
                            cZwQueryObject(myHandle, ObjectTypeInformation, HandleFullData, RequiredSize, &RequiredSize);
                            RtlZeroMemory(HandleNameData, 0x1000);
                            if(pObjectTypeInfo->TypeName.Length != NULL)
                            {
                                WideCharToMultiByte(CP_ACP, NULL, (LPCWSTR)pObjectTypeInfo->TypeName.Buffer, -1, (LPSTR)HandleNameData, 0x1000, NULL, NULL);
                                ReturnData = (ULONG_PTR)HandleNameData;
                                DontFreeStringMemory = true;
                            }
                        }
                    }
                    else if(InformationReturn == UE_OPTION_HANDLER_RETURN_TYPENAME_UNICODE)
                    {
                        //if(!(HandleInfo->GrantedAccess & SYNCHRONIZE) || ((HandleInfo->GrantedAccess & SYNCHRONIZE) && ((WORD)HandleInfo->GrantedAccess != 0x19F9))){// && (WORD)HandleInfo->GrantedAccess != 0x89))){
                        if(HandleInfo->GrantedAccess != 0x0012019F)
                        {
                            RtlZeroMemory(HandleFullData, 0x1000);
                            cZwQueryObject(myHandle, ObjectTypeInformation, HandleFullData, 8, &RequiredSize);
                            cZwQueryObject(myHandle, ObjectTypeInformation, HandleFullData, RequiredSize, &RequiredSize);
                            RtlZeroMemory(HandleNameData, 0x1000);
                            if(pObjectTypeInfo->TypeName.Length != NULL)
                            {
                                //WideCharToMultiByte(CP_ACP, NULL, (LPCWSTR)pObjectTypeInfo->TypeName.Buffer, -1, (LPSTR)HandleNameData, 0x1000, NULL, NULL);
                                lstrcpyW((wchar_t*)HandleNameData, (wchar_t*)pObjectTypeInfo->TypeName.Buffer);
                                ReturnData = (ULONG_PTR)HandleNameData;
                                DontFreeStringMemory = true;
                            }
                        }
                    }
                    EngineCloseHandle(myHandle);
                    break;
                }
            }
            HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
            TotalHandleCount--;
        }
        if(!DontFreeStringMemory)
        {
            VirtualFree(HandleNameData, NULL, MEM_RELEASE);
        }
        VirtualFree(HandleFullData, NULL, MEM_RELEASE);
        VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
        return(ReturnData);
    }
    if(!DontFreeStringMemory)
    {
        VirtualFree(HandleNameData, NULL, MEM_RELEASE);
    }
    VirtualFree(HandleFullData, NULL, MEM_RELEASE);
    return(NULL);
}
__declspec(dllexport) bool TITCALL HandlerCloseRemoteHandle(HANDLE hProcess, HANDLE hHandle)
{

    HANDLE myHandle;

    if(hProcess != NULL)
    {
        DuplicateHandle(hProcess, hHandle, GetCurrentProcess(), &myHandle, NULL, false, DUPLICATE_CLOSE_SOURCE);
        EngineCloseHandle(myHandle);
    }
    return(false);
}
__declspec(dllexport) long TITCALL HandlerEnumerateLockHandles(char* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated, LPVOID HandleDataBuffer, DWORD MaxHandleCount)
{

    wchar_t uniFileOrFolderName[MAX_PATH] = {};

    if(szFileOrFolderName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileOrFolderName, lstrlenA(szFileOrFolderName)+1, uniFileOrFolderName, sizeof(uniFileOrFolderName)/(sizeof(uniFileOrFolderName[0])));
        return(HandlerEnumerateLockHandlesW(uniFileOrFolderName, NameIsFolder, NameIsTranslated, HandleDataBuffer, MaxHandleCount));
    }
    else
    {
        return(NULL);
    }
}
__declspec(dllexport) long TITCALL HandlerEnumerateLockHandlesW(wchar_t* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated, LPVOID HandleDataBuffer, DWORD MaxHandleCount)
{

    int FoundHandles = NULL;
    HANDLE hProcess = NULL;
    HANDLE myHandle = NULL;
    HANDLE CopyHandle = NULL;
    LPVOID QuerySystemBuffer;
    ULONG QuerySystemBufferSize = 0x2000;
    ULONG RequiredSize = NULL;
    ULONG TotalHandleCount = NULL;
    DWORD LastProcessId = NULL;
#if !defined(_WIN64)
    typedef NTSTATUS(WINAPI *fZwQuerySystemInformation)(DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
    typedef NTSTATUS(WINAPI *fZwQueryObject)(HANDLE hObject, DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
#else
    typedef NTSTATUS(__fastcall *fZwQuerySystemInformation)(DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
    typedef NTSTATUS(__fastcall *fZwQueryObject)(HANDLE hObject, DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
#endif
    LPVOID ZwQuerySystemInformation = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"),"ZwQuerySystemInformation");
    LPVOID ZwQueryObject = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"),"ZwQueryObject");
    fZwQuerySystemInformation cZwQuerySystemInformation = (fZwQuerySystemInformation)(ZwQuerySystemInformation);
    fZwQueryObject cZwQueryObject = (fZwQueryObject)(ZwQueryObject);
    PNTDLL_QUERY_HANDLE_INFO HandleInfo;
    PUBLIC_OBJECT_BASIC_INFORMATION ObjectBasicInfo;
    LPVOID ObjectNameInfo = VirtualAlloc(NULL, 0x2000, MEM_COMMIT, PAGE_READWRITE);
    PPUBLIC_OBJECT_NAME_INFORMATION pObjectNameInfo = (PPUBLIC_OBJECT_NAME_INFORMATION)ObjectNameInfo;
    LPVOID HandleFullName = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    int LenFileOrFolderName = lstrlenW(szFileOrFolderName);
    LPVOID tmpHandleFullName = NULL;

    if(ZwQuerySystemInformation != NULL && ZwQueryObject != NULL)
    {
        QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
        while(cZwQuerySystemInformation(NTDLL_SystemHandleInfo, QuerySystemBuffer, QuerySystemBufferSize, &RequiredSize) == (NTSTATUS)0xC0000004L)
        {
            QuerySystemBufferSize = RequiredSize;
            VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
            QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
        }
        RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
        QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
        while(TotalHandleCount > NULL)
        {
            if(LastProcessId != HandleInfo->ProcessId)
            {
                if(hProcess != NULL)
                {
                    EngineCloseHandle(hProcess);
                }
                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, false, HandleInfo->ProcessId);
                LastProcessId = HandleInfo->ProcessId;
            }
            if(hProcess != NULL)
            {
                //if(!(HandleInfo->GrantedAccess & SYNCHRONIZE) || ((HandleInfo->GrantedAccess & SYNCHRONIZE) && ((WORD)HandleInfo->GrantedAccess != 0x19F9))){// && (WORD)HandleInfo->GrantedAccess != 0x89))){
                if(HandleInfo->GrantedAccess != 0x0012019F)
                {
                    if(DuplicateHandle(hProcess, (HANDLE)HandleInfo->hHandle, GetCurrentProcess(), &myHandle, NULL, false, DUPLICATE_SAME_ACCESS))
                    {
                        RtlZeroMemory(&ObjectBasicInfo, sizeof PUBLIC_OBJECT_BASIC_INFORMATION);
                        cZwQueryObject(myHandle, ObjectBasicInformation, &ObjectBasicInfo, sizeof PUBLIC_OBJECT_BASIC_INFORMATION, &RequiredSize);
                        cZwQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, 8, &RequiredSize);
                        cZwQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, RequiredSize, &RequiredSize);
                        RtlZeroMemory(HandleFullName, 0x1000);
                        if(pObjectNameInfo->Name.Length != NULL)
                        {
                            //WideCharToMultiByte(CP_ACP, NULL, (LPCWSTR)pObjectNameInfo->Name.Buffer, -1, (LPSTR)HandleFullName, 0x1000, NULL, NULL);
                            lstrcpyW((wchar_t*)HandleFullName, (wchar_t*)pObjectNameInfo->Name.Buffer);
                            if(NameIsTranslated)
                            {
                                tmpHandleFullName = TranslateNativeNameW((wchar_t*)HandleFullName);
                                if(tmpHandleFullName != NULL)
                                {
                                    VirtualFree(HandleFullName, NULL, MEM_RELEASE);
                                    HandleFullName = tmpHandleFullName;
                                }
                            }
                            if(NameIsFolder)
                            {
                                if(lstrlenW((LPCWSTR)HandleFullName) > LenFileOrFolderName)
                                {
                                    RtlZeroMemory((LPVOID)((ULONG_PTR)HandleFullName + LenFileOrFolderName * 2), 2);
                                }
                            }
                            if(lstrcmpiW((LPCWSTR)HandleFullName, szFileOrFolderName) == NULL && MaxHandleCount > NULL)
                            {
                                RtlMoveMemory(HandleDataBuffer, &HandleInfo->ProcessId, sizeof ULONG);
                                HandleDataBuffer = (LPVOID)((ULONG_PTR)HandleDataBuffer + sizeof ULONG);
                                CopyHandle = (HANDLE)HandleInfo->hHandle;
                                RtlMoveMemory(HandleDataBuffer, &CopyHandle, sizeof HANDLE);
                                HandleDataBuffer = (LPVOID)((ULONG_PTR)HandleDataBuffer + sizeof HANDLE);
                                FoundHandles++;
                                MaxHandleCount--;
                            }
                        }
                        EngineCloseHandle(myHandle);
                    }
                }
            }
            HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
            TotalHandleCount--;
        }
        VirtualFree(ObjectNameInfo, NULL, MEM_RELEASE);
        VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
        VirtualFree(HandleFullName, NULL, MEM_RELEASE);
        return(FoundHandles);
    }
    VirtualFree(ObjectNameInfo, NULL, MEM_RELEASE);
    VirtualFree(HandleFullName, NULL, MEM_RELEASE);
    return(NULL);
}
__declspec(dllexport) bool TITCALL HandlerCloseAllLockHandles(char* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated)
{

    wchar_t uniFileOrFolderName[MAX_PATH] = {};

    if(szFileOrFolderName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileOrFolderName, lstrlenA(szFileOrFolderName)+1, uniFileOrFolderName, sizeof(uniFileOrFolderName)/(sizeof(uniFileOrFolderName[0])));
        return(HandlerCloseAllLockHandlesW(uniFileOrFolderName, NameIsFolder, NameIsTranslated));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL HandlerCloseAllLockHandlesW(wchar_t* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated)
{

    bool AllHandled = true;
    HANDLE hProcess = NULL;
    HANDLE myHandle = NULL;
    HANDLE CopyHandle = NULL;
    LPVOID QuerySystemBuffer;
    ULONG QuerySystemBufferSize = 0x2000;
    ULONG RequiredSize = NULL;
    ULONG TotalHandleCount = NULL;
    DWORD LastProcessId = NULL;
#if !defined(_WIN64)
    typedef NTSTATUS(WINAPI *fZwQuerySystemInformation)(DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
    typedef NTSTATUS(WINAPI *fZwQueryObject)(HANDLE hObject, DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
#else
    typedef NTSTATUS(__fastcall *fZwQuerySystemInformation)(DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
    typedef NTSTATUS(__fastcall *fZwQueryObject)(HANDLE hObject, DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
#endif
    LPVOID ZwQuerySystemInformation = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"),"ZwQuerySystemInformation");
    LPVOID ZwQueryObject = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"),"ZwQueryObject");
    fZwQuerySystemInformation cZwQuerySystemInformation = (fZwQuerySystemInformation)(ZwQuerySystemInformation);
    fZwQueryObject cZwQueryObject = (fZwQueryObject)(ZwQueryObject);
    PNTDLL_QUERY_HANDLE_INFO HandleInfo;
    PUBLIC_OBJECT_BASIC_INFORMATION ObjectBasicInfo;
    LPVOID ObjectNameInfo = VirtualAlloc(NULL, 0x2000, MEM_COMMIT, PAGE_READWRITE);
    PPUBLIC_OBJECT_NAME_INFORMATION pObjectNameInfo = (PPUBLIC_OBJECT_NAME_INFORMATION)ObjectNameInfo;
    LPVOID HandleFullName = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    int LenFileOrFolderName = lstrlenW(szFileOrFolderName);
    LPVOID tmpHandleFullName = NULL;

    if(ZwQuerySystemInformation != NULL && ZwQueryObject != NULL)
    {
        QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
        while(cZwQuerySystemInformation(NTDLL_SystemHandleInfo, QuerySystemBuffer, QuerySystemBufferSize, &RequiredSize) == (NTSTATUS)0xC0000004L)
        {
            QuerySystemBufferSize = RequiredSize;
            VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
            QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
        }
        RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
        QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
        while(TotalHandleCount > NULL)
        {
            if(LastProcessId != HandleInfo->ProcessId)
            {
                if(hProcess != NULL)
                {
                    EngineCloseHandle(hProcess);
                }
                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, false, HandleInfo->ProcessId);
                LastProcessId = HandleInfo->ProcessId;
            }
            if(hProcess != NULL)
            {
                //if(!(HandleInfo->GrantedAccess & SYNCHRONIZE) || ((HandleInfo->GrantedAccess & SYNCHRONIZE) && ((WORD)HandleInfo->GrantedAccess != 0x19F9))){// && (WORD)HandleInfo->GrantedAccess != 0x89))){
                if(HandleInfo->GrantedAccess != 0x0012019F)
                {
                    if(DuplicateHandle(hProcess, (HANDLE)HandleInfo->hHandle, GetCurrentProcess(), &myHandle, NULL, false, DUPLICATE_SAME_ACCESS))
                    {
                        RtlZeroMemory(&ObjectBasicInfo, sizeof PUBLIC_OBJECT_BASIC_INFORMATION);
                        cZwQueryObject(myHandle, ObjectBasicInformation, &ObjectBasicInfo, sizeof PUBLIC_OBJECT_BASIC_INFORMATION, &RequiredSize);
                        cZwQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, 8, &RequiredSize);
                        cZwQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, RequiredSize, &RequiredSize);
                        RtlZeroMemory(HandleFullName, 0x1000);
                        if(pObjectNameInfo->Name.Length != NULL)
                        {
                            //WideCharToMultiByte(CP_ACP, NULL, (LPCWSTR)pObjectNameInfo->Name.Buffer, -1, (LPSTR)HandleFullName, 0x1000, NULL, NULL);
                            lstrcpyW((wchar_t*)HandleFullName, (wchar_t*)pObjectNameInfo->Name.Buffer);
                            if(NameIsTranslated)
                            {
                                tmpHandleFullName = TranslateNativeNameW((wchar_t*)HandleFullName);
                                if(tmpHandleFullName != NULL)
                                {
                                    VirtualFree(HandleFullName, NULL, MEM_RELEASE);
                                    HandleFullName = tmpHandleFullName;
                                }
                            }
                            if(NameIsFolder)
                            {
                                if(lstrlenW((LPCWSTR)HandleFullName) > LenFileOrFolderName)
                                {
                                    RtlZeroMemory((LPVOID)((ULONG_PTR)HandleFullName + LenFileOrFolderName * 2), 2);
                                }
                            }
                            if(lstrcmpiW((LPCWSTR)HandleFullName, szFileOrFolderName) == NULL)
                            {
                                if(!HandlerCloseRemoteHandle(hProcess, (HANDLE)HandleInfo->hHandle))
                                {
                                    AllHandled = false;
                                }
                            }
                        }
                        EngineCloseHandle(myHandle);
                    }
                }
            }
            HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
            TotalHandleCount--;
        }
        VirtualFree(ObjectNameInfo, NULL, MEM_RELEASE);
        VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
        VirtualFree(HandleFullName, NULL, MEM_RELEASE);
        if(AllHandled)
        {
            return(true);
        }
        else
        {
            return(false);
        }
    }
    VirtualFree(ObjectNameInfo, NULL, MEM_RELEASE);
    VirtualFree(HandleFullName, NULL, MEM_RELEASE);
    return(false);
}
__declspec(dllexport) bool TITCALL HandlerIsFileLocked(char* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated)
{

    wchar_t uniFileOrFolderName[MAX_PATH] = {};

    if(szFileOrFolderName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileOrFolderName, lstrlenA(szFileOrFolderName)+1, uniFileOrFolderName, sizeof(uniFileOrFolderName)/(sizeof(uniFileOrFolderName[0])));
        return(HandlerIsFileLockedW(uniFileOrFolderName, NameIsFolder, NameIsTranslated));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL HandlerIsFileLockedW(wchar_t* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated)
{

    HANDLE hProcess = NULL;
    HANDLE myHandle = NULL;
    HANDLE CopyHandle = NULL;
    LPVOID QuerySystemBuffer;
    ULONG QuerySystemBufferSize = 0x2000;
    ULONG RequiredSize = NULL;
    ULONG TotalHandleCount = NULL;
    DWORD LastProcessId = NULL;
#if !defined(_WIN64)
    typedef NTSTATUS(WINAPI *fZwQuerySystemInformation)(DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
    typedef NTSTATUS(WINAPI *fZwQueryObject)(HANDLE hObject, DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
#else
    typedef NTSTATUS(__fastcall *fZwQuerySystemInformation)(DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
    typedef NTSTATUS(__fastcall *fZwQueryObject)(HANDLE hObject, DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
#endif
    LPVOID ZwQuerySystemInformation = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"),"ZwQuerySystemInformation");
    LPVOID ZwQueryObject = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"),"ZwQueryObject");
    fZwQuerySystemInformation cZwQuerySystemInformation = (fZwQuerySystemInformation)(ZwQuerySystemInformation);
    fZwQueryObject cZwQueryObject = (fZwQueryObject)(ZwQueryObject);
    PNTDLL_QUERY_HANDLE_INFO HandleInfo;
    PUBLIC_OBJECT_BASIC_INFORMATION ObjectBasicInfo;
    LPVOID ObjectNameInfo = VirtualAlloc(NULL, 0x2000, MEM_COMMIT, PAGE_READWRITE);
    PPUBLIC_OBJECT_NAME_INFORMATION pObjectNameInfo = (PPUBLIC_OBJECT_NAME_INFORMATION)ObjectNameInfo;
    LPVOID HandleFullName = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    int LenFileOrFolderName = lstrlenW(szFileOrFolderName);
    LPVOID tmpHandleFullName = NULL;

    if(ZwQuerySystemInformation != NULL && ZwQueryObject != NULL)
    {
        QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
        while(cZwQuerySystemInformation(NTDLL_SystemHandleInfo, QuerySystemBuffer, QuerySystemBufferSize, &RequiredSize) == (NTSTATUS)0xC0000004L)
        {
            QuerySystemBufferSize = RequiredSize;
            VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
            QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
        }
        RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
        QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
        while(TotalHandleCount > NULL)
        {
            if(LastProcessId != HandleInfo->ProcessId)
            {
                if(hProcess != NULL)
                {
                    EngineCloseHandle(hProcess);
                }
                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, false, HandleInfo->ProcessId);
                LastProcessId = HandleInfo->ProcessId;
            }
            if(hProcess != NULL)
            {
                //if(!(HandleInfo->GrantedAccess & SYNCHRONIZE) || ((HandleInfo->GrantedAccess & SYNCHRONIZE) && ((WORD)HandleInfo->GrantedAccess != 0x19F9))){// && (WORD)HandleInfo->GrantedAccess != 0x89))){
                if(HandleInfo->GrantedAccess != 0x0012019F)
                {
                    if(DuplicateHandle(hProcess, (HANDLE)HandleInfo->hHandle, GetCurrentProcess(), &myHandle, NULL, false, DUPLICATE_SAME_ACCESS))
                    {
                        RtlZeroMemory(&ObjectBasicInfo, sizeof PUBLIC_OBJECT_BASIC_INFORMATION);
                        cZwQueryObject(myHandle, ObjectBasicInformation, &ObjectBasicInfo, sizeof PUBLIC_OBJECT_BASIC_INFORMATION, &RequiredSize);
                        cZwQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, 8, &RequiredSize);
                        cZwQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, RequiredSize, &RequiredSize);
                        RtlZeroMemory(HandleFullName, 0x1000);
                        if(pObjectNameInfo->Name.Length != NULL)
                        {
                            //WideCharToMultiByte(CP_ACP, NULL, (LPCWSTR)pObjectNameInfo->Name.Buffer, -1, (LPSTR)HandleFullName, 0x1000, NULL, NULL);
                            lstrcpyW((wchar_t*)HandleFullName, (wchar_t*)pObjectNameInfo->Name.Buffer);
                            if(NameIsTranslated)
                            {
                                tmpHandleFullName = TranslateNativeNameW((wchar_t*)HandleFullName);
                                if(tmpHandleFullName != NULL)
                                {
                                    VirtualFree(HandleFullName, NULL, MEM_RELEASE);
                                    HandleFullName = tmpHandleFullName;
                                }
                            }
                            if(NameIsFolder)
                            {
                                if(lstrlenW((LPCWSTR)HandleFullName) > LenFileOrFolderName)
                                {
                                    RtlZeroMemory((LPVOID)((ULONG_PTR)HandleFullName + LenFileOrFolderName * 2), 2);
                                }
                            }
                            if(lstrcmpiW((LPCWSTR)HandleFullName, szFileOrFolderName) == NULL)
                            {
                                VirtualFree(ObjectNameInfo, NULL, MEM_RELEASE);
                                VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
                                VirtualFree(HandleFullName, NULL, MEM_RELEASE);
                                EngineCloseHandle(myHandle);
                                return(true);
                            }
                        }
                        EngineCloseHandle(myHandle);
                    }
                }
            }
            HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
            TotalHandleCount--;
        }
        VirtualFree(ObjectNameInfo, NULL, MEM_RELEASE);
        VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
        VirtualFree(HandleFullName, NULL, MEM_RELEASE);
        return(false);
    }
    VirtualFree(ObjectNameInfo, NULL, MEM_RELEASE);
    VirtualFree(HandleFullName, NULL, MEM_RELEASE);
    return(false);
}
// TitanEngine.Handler[Mutex].functions:
__declspec(dllexport) long TITCALL HandlerEnumerateOpenMutexes(HANDLE hProcess, DWORD ProcessId, LPVOID HandleBuffer, DWORD MaxHandleCount)
{

    HANDLE myHandle = NULL;
    HANDLE copyHandle = NULL;
    LPVOID QuerySystemBuffer;
    ULONG RequiredSize = NULL;
    ULONG TotalHandleCount = NULL;
    unsigned int HandleCount = NULL;
    ULONG QuerySystemBufferSize = 0x2000;
#if !defined(_WIN64)
    typedef NTSTATUS(WINAPI *fZwQuerySystemInformation)(DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
    typedef NTSTATUS(WINAPI *fZwQueryObject)(HANDLE hObject, DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
#else
    typedef NTSTATUS(__fastcall *fZwQuerySystemInformation)(DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
    typedef NTSTATUS(__fastcall *fZwQueryObject)(HANDLE hObject, DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
#endif
    LPVOID ZwQuerySystemInformation = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"),"ZwQuerySystemInformation");
    LPVOID ZwQueryObject = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"),"ZwQueryObject");
    fZwQuerySystemInformation cZwQuerySystemInformation = (fZwQuerySystemInformation)(ZwQuerySystemInformation);
    fZwQueryObject cZwQueryObject = (fZwQueryObject)(ZwQueryObject);
    PNTDLL_QUERY_HANDLE_INFO HandleInfo;
    LPVOID HandleFullData = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    LPVOID HandleNameData = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    PPUBLIC_OBJECT_TYPE_INFORMATION pObjectTypeInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)HandleFullData;

    if(ZwQuerySystemInformation != NULL && ZwQueryObject != NULL)
    {
        QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
        while(cZwQuerySystemInformation(NTDLL_SystemHandleInfo, QuerySystemBuffer, QuerySystemBufferSize, &RequiredSize) == (NTSTATUS)0xC0000004L)
        {
            QuerySystemBufferSize = RequiredSize;
            VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
            QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
        }
        RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
        QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
        while(TotalHandleCount > NULL)
        {
            if(HandleInfo->ProcessId == ProcessId && HandleCount < MaxHandleCount)
            {
                //if(!(HandleInfo->GrantedAccess & SYNCHRONIZE) || ((HandleInfo->GrantedAccess & SYNCHRONIZE) && ((WORD)HandleInfo->GrantedAccess != 0x19F9))){// && (WORD)HandleInfo->GrantedAccess != 0x89))){
                if(HandleInfo->GrantedAccess != 0x0012019F)
                {
                    if(DuplicateHandle(hProcess, (HANDLE)HandleInfo->hHandle, GetCurrentProcess(), &myHandle, NULL, false, DUPLICATE_SAME_ACCESS))
                    {
                        RtlZeroMemory(HandleFullData, 0x1000);
                        cZwQueryObject(myHandle, ObjectTypeInformation, HandleFullData, 8, &RequiredSize);
                        cZwQueryObject(myHandle, ObjectTypeInformation, HandleFullData, RequiredSize, &RequiredSize);
                        RtlZeroMemory(HandleNameData, 0x1000);
                        if(pObjectTypeInfo->TypeName.Length != NULL)
                        {
                            WideCharToMultiByte(CP_ACP, NULL, (LPCWSTR)pObjectTypeInfo->TypeName.Buffer, -1, (LPSTR)HandleNameData, 0x1000, NULL, NULL);
                            if(lstrcmpiA((LPCSTR)HandleNameData, "Mutant") == NULL)
                            {
                                copyHandle = (HANDLE)HandleInfo->hHandle;
                                RtlMoveMemory(HandleBuffer, &copyHandle, sizeof HANDLE);
                                HandleBuffer = (LPVOID)((ULONG_PTR)HandleBuffer + sizeof HANDLE);
                                HandleCount++;
                            }
                        }
                        EngineCloseHandle(myHandle);
                    }
                }
            }
            HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
            TotalHandleCount--;
        }
        VirtualFree(HandleFullData, NULL, MEM_RELEASE);
        VirtualFree(HandleNameData, NULL, MEM_RELEASE);
        VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
        return(HandleCount);
    }
    VirtualFree(HandleFullData, NULL, MEM_RELEASE);
    VirtualFree(HandleNameData, NULL, MEM_RELEASE);
    return(NULL);
}
__declspec(dllexport) long long TITCALL HandlerGetOpenMutexHandle(HANDLE hProcess, DWORD ProcessId, char* szMutexString)
{

    wchar_t uniMutexString[MAX_PATH] = {};

    if(szMutexString != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szMutexString, lstrlenA(szMutexString)+1, uniMutexString, sizeof(uniMutexString)/(sizeof(uniMutexString[0])));
        return((ULONG_PTR)HandlerGetOpenMutexHandleW(hProcess, ProcessId, uniMutexString));
    }
    else
    {
        return(NULL);
    }
}
__declspec(dllexport) long long TITCALL HandlerGetOpenMutexHandleW(HANDLE hProcess, DWORD ProcessId, wchar_t* szMutexString)
{
    if(!szMutexString || lstrlenW(szMutexString)>=512)
        return 0;
    int i;
    HANDLE myHandle;
    LPVOID HandleBuffer = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    LPVOID cHandleBuffer = HandleBuffer;
    int OpenHandleCount = HandlerEnumerateOpenMutexes(hProcess, ProcessId, HandleBuffer, 0x1000 / sizeof HANDLE);
    wchar_t RealMutexName[512] = L"\\BaseNamedObjects\\";
    wchar_t* HandleName;

    if(OpenHandleCount > NULL)
    {
        lstrcatW(RealMutexName, szMutexString);
        for(i = 0; i < OpenHandleCount; i++)
        {
            RtlMoveMemory(&myHandle, cHandleBuffer, sizeof HANDLE);
            HandleName = (wchar_t*)HandlerGetHandleNameW(hProcess, ProcessId, myHandle, true);
            if(HandleName != NULL)
            {
                if(lstrcmpiW(HandleName, RealMutexName) == NULL)
                {
                    VirtualFree(HandleBuffer, NULL, MEM_RELEASE);
                    return((ULONG_PTR)myHandle);
                }
            }
            cHandleBuffer = (LPVOID)((ULONG_PTR)cHandleBuffer + sizeof HANDLE);
        }
    }
    VirtualFree(HandleBuffer, NULL, MEM_RELEASE);
    return(NULL);
}
__declspec(dllexport) long TITCALL HandlerGetProcessIdWhichCreatedMutex(char* szMutexString)
{

    wchar_t uniMutexString[MAX_PATH] = {};

    if(szMutexString != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szMutexString, lstrlenA(szMutexString)+1, uniMutexString, sizeof(uniMutexString)/(sizeof(uniMutexString[0])));
        return(HandlerGetProcessIdWhichCreatedMutexW(uniMutexString));
    }
    else
    {
        return(NULL);
    }
}
__declspec(dllexport) long TITCALL HandlerGetProcessIdWhichCreatedMutexW(wchar_t* szMutexString)
{
    if(!szMutexString || lstrlenW(szMutexString)>=512)
        return 0;
    HANDLE hProcess = NULL;
    DWORD ReturnData = NULL;
    HANDLE myHandle = NULL;
    LPVOID QuerySystemBuffer;
    ULONG RequiredSize = NULL;
    DWORD LastProcessId = NULL;
    ULONG TotalHandleCount = NULL;
    ULONG QuerySystemBufferSize = 0x2000;
#if !defined(_WIN64)
    typedef NTSTATUS(WINAPI *fZwQuerySystemInformation)(DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
    typedef NTSTATUS(WINAPI *fZwQueryObject)(HANDLE hObject, DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
#else
    typedef NTSTATUS(__fastcall *fZwQuerySystemInformation)(DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
    typedef NTSTATUS(__fastcall *fZwQueryObject)(HANDLE hObject, DWORD fInfoType, LPVOID fBuffer, ULONG fBufferSize, PULONG fRequiredSize);
#endif
    LPVOID ZwQuerySystemInformation = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"),"ZwQuerySystemInformation");
    LPVOID ZwQueryObject = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"),"ZwQueryObject");
    fZwQuerySystemInformation cZwQuerySystemInformation = (fZwQuerySystemInformation)(ZwQuerySystemInformation);
    fZwQueryObject cZwQueryObject = (fZwQueryObject)(ZwQueryObject);
    PNTDLL_QUERY_HANDLE_INFO HandleInfo;
    LPVOID HandleFullData = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    LPVOID HandleNameData = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    PPUBLIC_OBJECT_TYPE_INFORMATION pObjectTypeInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)HandleFullData;
    LPVOID ObjectNameInfo = VirtualAlloc(NULL, 0x2000, MEM_COMMIT, PAGE_READWRITE);
    PPUBLIC_OBJECT_NAME_INFORMATION pObjectNameInfo = (PPUBLIC_OBJECT_NAME_INFORMATION)ObjectNameInfo;
    wchar_t RealMutexName[512] = L"\\BaseNamedObjects\\";

    if(ZwQuerySystemInformation != NULL && ZwQueryObject != NULL)
    {
        lstrcatW(RealMutexName, szMutexString);
        QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
        while(cZwQuerySystemInformation(NTDLL_SystemHandleInfo, QuerySystemBuffer, QuerySystemBufferSize, &RequiredSize) == (NTSTATUS)0xC0000004L)
        {
            QuerySystemBufferSize = RequiredSize;
            VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
            QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
        }
        RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
        QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
        while(TotalHandleCount > NULL)
        {
            if(LastProcessId != HandleInfo->ProcessId)
            {
                if(hProcess != NULL)
                {
                    EngineCloseHandle(hProcess);
                }
                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, false, HandleInfo->ProcessId);
                LastProcessId = HandleInfo->ProcessId;
            }
            if(hProcess != NULL)
            {
                //if(!(HandleInfo->GrantedAccess & SYNCHRONIZE) || ((HandleInfo->GrantedAccess & SYNCHRONIZE) && ((WORD)HandleInfo->GrantedAccess != 0x19F9))){// && (WORD)HandleInfo->GrantedAccess != 0x89))){
                if(HandleInfo->GrantedAccess != 0x0012019F)
                {
                    if(DuplicateHandle(hProcess, (HANDLE)HandleInfo->hHandle, GetCurrentProcess(), &myHandle, NULL, false, DUPLICATE_SAME_ACCESS))
                    {
                        RtlZeroMemory(HandleFullData, 0x1000);
                        cZwQueryObject(myHandle, ObjectTypeInformation, HandleFullData, 8, &RequiredSize);
                        cZwQueryObject(myHandle, ObjectTypeInformation, HandleFullData, RequiredSize, &RequiredSize);
                        RtlZeroMemory(HandleNameData, 0x1000);
                        if(pObjectTypeInfo->TypeName.Length != NULL)
                        {
                            //WideCharToMultiByte(CP_ACP, NULL, (LPCWSTR)pObjectTypeInfo->TypeName.Buffer, -1, (LPSTR)HandleNameData, 0x1000, NULL, NULL);
                            lstrcpyW((wchar_t*)HandleNameData, (wchar_t*)pObjectNameInfo->Name.Buffer);
                            if(lstrcmpiW((LPCWSTR)HandleNameData, L"Mutant") == NULL)
                            {
                                cZwQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, 8, &RequiredSize);
                                cZwQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, RequiredSize, &RequiredSize);
                                RtlZeroMemory(HandleNameData, 0x1000);
                                if(pObjectNameInfo->Name.Length != NULL)
                                {
                                    RtlZeroMemory(HandleNameData, 0x1000);
                                    //WideCharToMultiByte(CP_ACP, NULL, (LPCWSTR)pObjectNameInfo->Name.Buffer, -1, (LPSTR)HandleNameData, 0x1000, NULL, NULL);
                                    lstrcpyW((wchar_t*)HandleNameData, (wchar_t*)pObjectNameInfo->Name.Buffer);
                                    if(lstrcmpiW((LPCWSTR)HandleNameData, RealMutexName) == NULL)
                                    {
                                        ReturnData = HandleInfo->ProcessId;
                                        break;
                                    }
                                }
                            }
                        }
                        EngineCloseHandle(myHandle);
                    }
                }
            }
            HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
            TotalHandleCount--;
        }
        VirtualFree(HandleFullData, NULL, MEM_RELEASE);
        VirtualFree(HandleNameData, NULL, MEM_RELEASE);
        VirtualFree(ObjectNameInfo, NULL, MEM_RELEASE);
        VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
        return(ReturnData);
    }
    VirtualFree(HandleFullData, NULL, MEM_RELEASE);
    VirtualFree(HandleNameData, NULL, MEM_RELEASE);
    VirtualFree(ObjectNameInfo, NULL, MEM_RELEASE);
    return(NULL);
}
// Global.Injector.functions: {DO NOT REORDER! USE ONLY IN RELEASE MODE!}
long injectedImpRec(LPVOID Parameter)
{

    HANDLE hFile;
    HANDLE hFileMap;
    PInjectImpRecCodeData APIData = (PInjectImpRecCodeData)Parameter;
    LPVOID szFileName = (LPVOID)((ULONG_PTR)Parameter + sizeof InjectImpRecCodeData);
    typedef ULONG_PTR(__cdecl *fTrace)(DWORD hFileMap, DWORD dwSizeMap, DWORD dwTimeOut, DWORD dwToTrace, DWORD dwExactCall);
    typedef HANDLE(WINAPI *fCreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
    typedef HANDLE(WINAPI *fCreateFileMappingA)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName);
    typedef BOOL(__cdecl *fCloseHandle)(HANDLE hHandle);
    fTrace cTrace = (fTrace)(APIData->fTrace);
    fCreateFileW cCreateFileW = (fCreateFileW)(APIData->fCreateFileA);
    fCloseHandle cCloseHandle = (fCloseHandle)(APIData->fCloseHandle);
    fCreateFileMappingA cCreateFileMappingA = (fCreateFileMappingA)(APIData->fCreateFileMappingA);

    hFile = cCreateFileW((LPCWSTR)szFileName, GENERIC_READ+GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile != INVALID_HANDLE_VALUE)
    {
        hFileMap = cCreateFileMappingA(hFile, NULL, 4, NULL, 0x100, NULL);
        cTrace((DWORD)hFileMap, 0x100, -1, (DWORD)APIData->AddressToTrace, NULL);
        cCloseHandle(hFile);
        return(1);
    }
    else
    {
        return(0);
    }
}
long injectedRemoteLoadLibrary(LPVOID Parameter)
{

    PInjectCodeData APIData = (PInjectCodeData)Parameter;
    Parameter = (LPVOID)((ULONG_PTR)Parameter + sizeof InjectCodeData);
#if !defined(_WIN64)
    typedef ULONG_PTR(WINAPI *fLoadLibraryW)(LPCWSTR fLibraryName);
    typedef ULONG_PTR(WINAPI *fVirtualFree)(LPVOID fMemBase, SIZE_T fMemSize, DWORD fFreeType);
#else
    typedef ULONG_PTR(__fastcall *fLoadLibraryW)(LPCWSTR fLibraryName);
    typedef ULONG_PTR(__fastcall *fVirtualFree)(LPVOID fMemBase, SIZE_T fMemSize, DWORD fFreeType);
#endif
    fLoadLibraryW cLoadLibraryW = (fLoadLibraryW)(APIData->fLoadLibrary);
    fVirtualFree cVirtualFree = (fVirtualFree)(APIData->fVirtualFree);
    long retValue = NULL;

    if(cLoadLibraryW((LPCWSTR)Parameter) != NULL)
    {
        retValue++;
    }
    cVirtualFree(Parameter, NULL, MEM_RELEASE);
    return(retValue);
}
long injectedRemoteFreeLibrary(LPVOID Parameter)
{

    PInjectCodeData APIData = (PInjectCodeData)Parameter;
#if !defined(_WIN64)
    typedef ULONG_PTR(WINAPI *fFreeLibrary)(HMODULE fLibBase);
    typedef ULONG_PTR(WINAPI *fVirtualFree)(LPVOID fMemBase, SIZE_T fMemSize, DWORD fFreeType);
#else
    typedef ULONG_PTR(__fastcall *fFreeLibrary)(HMODULE fLibBase);
    typedef ULONG_PTR(__fastcall *fVirtualFree)(LPVOID fMemBase, SIZE_T fMemSize, DWORD fFreeType);
#endif
    fFreeLibrary cFreeLibrary = (fFreeLibrary)(APIData->fFreeLibrary);
    fVirtualFree cVirtualFree = (fVirtualFree)(APIData->fVirtualFree);
    long retValue = NULL;

    if(cFreeLibrary(APIData->fFreeLibraryHandle))
    {
        retValue++;
    }
    cVirtualFree(Parameter, NULL, MEM_RELEASE);
    return(retValue);
}
long injectedRemoteFreeLibrarySimple(LPVOID Parameter)
{

    PInjectCodeData APIData = (PInjectCodeData)Parameter;
    LPVOID orgParameter = Parameter;
    Parameter = (LPVOID)((ULONG_PTR)Parameter + sizeof InjectCodeData);
#if !defined(_WIN64)
    typedef ULONG_PTR(WINAPI *fFreeLibrary)(HMODULE fLibBase);
    typedef HMODULE(WINAPI *fGetModuleHandleW)(LPCWSTR fLibraryName);
    typedef ULONG_PTR(WINAPI *fVirtualFree)(LPVOID fMemBase, SIZE_T fMemSize, DWORD fFreeType);
#else
    typedef ULONG_PTR(__fastcall *fFreeLibrary)(HMODULE fLibBase);
    typedef HMODULE(__fastcall *fGetModuleHandleW)(LPCWSTR fLibraryName);
    typedef ULONG_PTR(__fastcall *fVirtualFree)(LPVOID fMemBase, SIZE_T fMemSize, DWORD fFreeType);
#endif
    fGetModuleHandleW cGetModuleHandleW = (fGetModuleHandleW)(APIData->fGetModuleHandle);
    fFreeLibrary cFreeLibrary = (fFreeLibrary)(APIData->fFreeLibrary);
    fVirtualFree cVirtualFree = (fVirtualFree)(APIData->fVirtualFree);
    long retValue = NULL;
    HMODULE hModule;

    hModule = cGetModuleHandleW((LPCWSTR)Parameter);
    if(hModule != NULL)
    {
        if(cFreeLibrary(hModule))
        {
            retValue++;
        }
    }
    else
    {
        retValue++;
    }
    cVirtualFree(orgParameter, NULL, MEM_RELEASE);
    return(retValue);
}
long injectedExitProcess(LPVOID Parameter)
{

    PInjectCodeData APIData = (PInjectCodeData)Parameter;
#if !defined(_WIN64)
    typedef ULONG_PTR(WINAPI *fExitProcess)(DWORD fExitCode);
#else
    typedef ULONG_PTR(__fastcall *fExitProcess)(DWORD fExitCode);
#endif
    fExitProcess cExitProcess = (fExitProcess)(APIData->fExitProcess);
    long retValue = NULL;

    cExitProcess(APIData->fExitProcessCode);
    return(NULL);
}
void injectedTerminator()
{

    int i;

    for(i = 0; i < UE_MAX_RESERVED_MEMORY_LEFT; i++)
    {
        if(engineReservedMemoryLeft[i] != NULL)
        {
            VirtualFreeEx(engineReservedMemoryProcess, (LPVOID)engineReservedMemoryLeft[i], NULL, MEM_RELEASE);
            engineReservedMemoryLeft[i] = NULL;
        }
    }
}
// TitanEngine.Injector.functions:
__declspec(dllexport) bool TITCALL RemoteLoadLibrary(HANDLE hProcess, char* szLibraryFile, bool WaitForThreadExit)
{

    wchar_t uniLibraryFile[MAX_PATH] = {};

    if(szLibraryFile != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szLibraryFile, lstrlenA(szLibraryFile)+1, uniLibraryFile, sizeof(uniLibraryFile)/(sizeof(uniLibraryFile[0])));
        return(RemoteLoadLibraryW(hProcess, uniLibraryFile, WaitForThreadExit));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL RemoteLoadLibraryW(HANDLE hProcess, wchar_t* szLibraryFile, bool WaitForThreadExit)
{

    int i;
    InjectCodeData APIData;
    LPVOID remStringData;
    LPVOID remCodeData;
    ULONG_PTR remInjectSize = (ULONG_PTR)((ULONG_PTR)&injectedRemoteFreeLibrary - (ULONG_PTR)&injectedRemoteLoadLibrary);
#if !defined(_WIN64)
    typedef NTSTATUS(WINAPI *fZwSetInformationThread)(HANDLE fThreadHandle, DWORD fThreadInfoClass, LPVOID fBuffer, ULONG fBufferSize);
#else
    typedef NTSTATUS(__fastcall *fZwSetInformationThread)(HANDLE fThreadHandle, DWORD fThreadInfoClass, LPVOID fBuffer, ULONG fBufferSize);
#endif
    LPVOID ZwSetInformationThread = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"),"ZwSetInformationThread");
    fZwSetInformationThread cZwSetInformationThread = (fZwSetInformationThread)(ZwSetInformationThread);
    ULONG_PTR NumberOfBytesWritten;
    DWORD ThreadId;
    HANDLE hThread;
    DWORD ExitCode;

    if(hProcess != NULL)
    {
        RtlZeroMemory(&APIData, sizeof InjectCodeData);
        APIData.fLoadLibrary = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW"));
        APIData.fFreeLibrary = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeLibrary"));
        APIData.fGetModuleHandle = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetModuleHandleW"));
        APIData.fGetProcAddress = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress"));
        APIData.fVirtualFree = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualFree"));
        APIData.fExitProcess = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitProcess"));
        remCodeData = VirtualAllocEx(hProcess, NULL, remInjectSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        remStringData = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
        if(WriteProcessMemory(hProcess, (LPVOID)((ULONG_PTR)remStringData + sizeof InjectCodeData), (LPCVOID)szLibraryFile, lstrlenW(szLibraryFile) * 2, &NumberOfBytesWritten))
        {
            WriteProcessMemory(hProcess, remStringData, &APIData, sizeof InjectCodeData, &NumberOfBytesWritten);
            WriteProcessMemory(hProcess, remCodeData, (LPCVOID)&injectedRemoteLoadLibrary, remInjectSize, &NumberOfBytesWritten);
            if(WaitForThreadExit)
            {
                hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)remCodeData, remStringData, CREATE_SUSPENDED, &ThreadId);
                if(ZwSetInformationThread != NULL)
                {
                    cZwSetInformationThread(hThread, 0x11, NULL, NULL);
                }
                ResumeThread(hThread);
                WaitForSingleObject(hThread, INFINITE);
                VirtualFreeEx(hProcess, remCodeData, NULL, MEM_RELEASE);
                VirtualFreeEx(hProcess, remStringData, NULL, MEM_RELEASE);
                if(GetExitCodeThread(hThread, &ExitCode))
                {
                    if(ExitCode == NULL)
                    {
                        return(false);
                    }
                }
            }
            else
            {
                hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)remCodeData, remStringData, NULL, &ThreadId);
                for(i = 0; i < UE_MAX_RESERVED_MEMORY_LEFT; i++)
                {
                    if(engineReservedMemoryLeft[i] == NULL)
                    {
                        break;
                    }
                }
                engineReservedMemoryLeft[i] = (ULONG_PTR)remCodeData;
                engineReservedMemoryProcess = hProcess;
                ThreaderSetCallBackForNextExitThreadEvent((LPVOID)&injectedTerminator);
            }
            return(true);
        }
        else
        {
            VirtualFreeEx(hProcess, remCodeData, NULL, MEM_RELEASE);
            VirtualFreeEx(hProcess, remStringData, NULL, MEM_RELEASE);
        }
    }
    return(false);
}
__declspec(dllexport) bool TITCALL RemoteFreeLibrary(HANDLE hProcess, HMODULE hModule, char* szLibraryFile, bool WaitForThreadExit)
{

    wchar_t uniLibraryFile[MAX_PATH] = {};

    if(szLibraryFile != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szLibraryFile, lstrlenA(szLibraryFile)+1, uniLibraryFile, sizeof(uniLibraryFile)/(sizeof(uniLibraryFile[0])));
        return(RemoteFreeLibraryW(hProcess, hModule, uniLibraryFile, WaitForThreadExit));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL RemoteFreeLibraryW(HANDLE hProcess, HMODULE hModule, wchar_t* szLibraryFile, bool WaitForThreadExit)
{

    int i;
    InjectCodeData APIData;
    LPVOID remStringData;
    LPVOID remCodeData;
    ULONG_PTR remInjectSize1 = (ULONG_PTR)((ULONG_PTR)&injectedExitProcess - (ULONG_PTR)&injectedRemoteFreeLibrarySimple);
    ULONG_PTR remInjectSize2 = (ULONG_PTR)((ULONG_PTR)&injectedRemoteFreeLibrarySimple - (ULONG_PTR)&injectedRemoteFreeLibrary);
#if !defined(_WIN64)
    typedef NTSTATUS(WINAPI *fZwSetInformationThread)(HANDLE fThreadHandle, DWORD fThreadInfoClass, LPVOID fBuffer, ULONG fBufferSize);
#else
    typedef NTSTATUS(__fastcall *fZwSetInformationThread)(HANDLE fThreadHandle, DWORD fThreadInfoClass, LPVOID fBuffer, ULONG fBufferSize);
#endif
    LPVOID ZwSetInformationThread = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"),"ZwSetInformationThread");
    fZwSetInformationThread cZwSetInformationThread = (fZwSetInformationThread)(ZwSetInformationThread);
    ULONG_PTR NumberOfBytesWritten;
    DWORD ThreadId;
    HANDLE hThread;
    DWORD ExitCode;

    if(hProcess != NULL)
    {
        RtlZeroMemory(&APIData, sizeof InjectCodeData);
        APIData.fLoadLibrary = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW"));
        APIData.fFreeLibrary = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeLibrary"));
        APIData.fGetModuleHandle = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetModuleHandleW"));
        APIData.fGetProcAddress = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress"));
        APIData.fVirtualFree = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualFree"));
        APIData.fExitProcess = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitProcess"));
        APIData.fFreeLibraryHandle = hModule;
        remCodeData = VirtualAllocEx(hProcess, NULL, remInjectSize1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if(hModule == NULL)
        {
            remStringData = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
            if(WriteProcessMemory(hProcess, (LPVOID)((ULONG_PTR)remStringData + sizeof InjectCodeData), (LPCVOID)szLibraryFile, lstrlenW(szLibraryFile) * 2, &NumberOfBytesWritten))
            {
                WriteProcessMemory(hProcess, remStringData, &APIData, sizeof InjectCodeData, &NumberOfBytesWritten);
                WriteProcessMemory(hProcess, remCodeData, (LPCVOID)&injectedRemoteFreeLibrarySimple, remInjectSize1, &NumberOfBytesWritten);
                if(WaitForThreadExit)
                {
                    hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)remCodeData, remStringData, CREATE_SUSPENDED, &ThreadId);
                    if(ZwSetInformationThread != NULL)
                    {
                        cZwSetInformationThread(hThread, 0x11, NULL, NULL);
                    }
                    ResumeThread(hThread);
                    WaitForSingleObject(hThread, INFINITE);
                    VirtualFreeEx(hProcess, remCodeData, NULL, MEM_RELEASE);
                    VirtualFreeEx(hProcess, remStringData, NULL, MEM_RELEASE);
                    if(GetExitCodeThread(hThread, &ExitCode))
                    {
                        if(ExitCode == NULL)
                        {
                            return(false);
                        }
                    }
                }
                else
                {
                    hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)remCodeData, remStringData, NULL, &ThreadId);
                    for(i = 0; i < UE_MAX_RESERVED_MEMORY_LEFT; i++)
                    {
                        if(engineReservedMemoryLeft[i] == NULL)
                        {
                            break;
                        }
                    }
                    engineReservedMemoryLeft[i] = (ULONG_PTR)remCodeData;
                    engineReservedMemoryProcess = hProcess;
                    ThreaderSetCallBackForNextExitThreadEvent((LPVOID)&injectedTerminator);
                }
                return(true);
            }
            else
            {
                VirtualFreeEx(hProcess, remCodeData, NULL, MEM_RELEASE);
                VirtualFreeEx(hProcess, remStringData, NULL, MEM_RELEASE);
            }
        }
        else
        {
            remStringData = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
            if(WriteProcessMemory(hProcess, remStringData, &APIData, sizeof InjectCodeData, &NumberOfBytesWritten))
            {
                WriteProcessMemory(hProcess, remCodeData, (LPCVOID)&injectedRemoteFreeLibrary, remInjectSize2, &NumberOfBytesWritten);
                if(WaitForThreadExit)
                {
                    hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)remCodeData, remStringData, CREATE_SUSPENDED, &ThreadId);
                    if(ZwSetInformationThread != NULL)
                    {
                        cZwSetInformationThread(hThread, 0x11, NULL, NULL);
                    }
                    ResumeThread(hThread);
                    WaitForSingleObject(hThread, INFINITE);
                    VirtualFreeEx(hProcess, remCodeData, NULL, MEM_RELEASE);
                    if(GetExitCodeThread(hThread, &ExitCode))
                    {
                        if(ExitCode == NULL)
                        {
                            return(false);
                        }
                    }
                }
                else
                {
                    hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)remCodeData, remStringData, NULL, &ThreadId);
                    for(i = 0; i < UE_MAX_RESERVED_MEMORY_LEFT; i++)
                    {
                        if(engineReservedMemoryLeft[i] == NULL)
                        {
                            break;
                        }
                    }
                    engineReservedMemoryLeft[i] = (ULONG_PTR)remCodeData;
                    engineReservedMemoryProcess = hProcess;
                    ThreaderSetCallBackForNextExitThreadEvent((LPVOID)&injectedTerminator);
                }
                return(true);
            }
            else
            {
                VirtualFreeEx(hProcess, remCodeData, NULL, MEM_RELEASE);
                VirtualFreeEx(hProcess, remStringData, NULL, MEM_RELEASE);
            }
        }
    }
    return(false);
}
__declspec(dllexport) bool TITCALL RemoteExitProcess(HANDLE hProcess, DWORD ExitCode)
{

    InjectCodeData APIData;
    LPVOID remCodeData;
    LPVOID remStringData;
    ULONG_PTR remInjectSize = (ULONG_PTR)((ULONG_PTR)&injectedTerminator - (ULONG_PTR)&injectedExitProcess);
    ULONG_PTR NumberOfBytesWritten;
    DWORD ThreadId;
    HANDLE hThread;

    if(hProcess != NULL)
    {
        RtlZeroMemory(&APIData, sizeof InjectCodeData);
        APIData.fLoadLibrary = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"));
        APIData.fFreeLibrary = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeLibrary"));
        APIData.fGetModuleHandle = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetModuleHandleA"));
        APIData.fGetProcAddress = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress"));
        APIData.fVirtualFree = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualFree"));
        APIData.fExitProcess = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitProcess"));
        APIData.fExitProcessCode = ExitCode;
        remStringData = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
        remCodeData = VirtualAllocEx(hProcess, NULL, remInjectSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if(WriteProcessMemory(hProcess, remCodeData, (LPCVOID)&injectedExitProcess, remInjectSize, &NumberOfBytesWritten))
        {
            WriteProcessMemory(hProcess, remStringData, &APIData, sizeof InjectCodeData, &NumberOfBytesWritten);
            hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)remCodeData, remStringData, NULL, &ThreadId);
            VirtualFreeEx(hProcess, remCodeData, NULL, MEM_RELEASE);
            return(true);
        }
        else
        {
            VirtualFreeEx(hProcess, remCodeData, NULL, MEM_RELEASE);
            VirtualFreeEx(hProcess, remStringData, NULL, MEM_RELEASE);
        }
    }
    return(false);
}
// TitanEngine.Tracer.functions:
__declspec(dllexport) long TITCALL TracerFixRedirectionViaImpRecPlugin(HANDLE hProcess, char* szPluginName, ULONG_PTR AddressToTrace)
{

    int szLenght = NULL;
    HMODULE hImpRecModule = NULL;
    ULONG_PTR fImpRecTrace = NULL;
    PMEMORY_CMP_HANDLER cmpModuleName;
    ULONG_PTR remInjectSize = (ULONG_PTR)((ULONG_PTR)&injectedRemoteLoadLibrary - (ULONG_PTR)&injectedImpRec);
#if !defined(_WIN64)
    typedef NTSTATUS(WINAPI *fZwSetInformationThread)(HANDLE fThreadHandle, DWORD fThreadInfoClass, LPVOID fBuffer, ULONG fBufferSize);
#else
    typedef NTSTATUS(__fastcall *fZwSetInformationThread)(HANDLE fThreadHandle, DWORD fThreadInfoClass, LPVOID fBuffer, ULONG fBufferSize);
#endif
    LPVOID ZwSetInformationThread = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"),"ZwSetInformationThread");
    fZwSetInformationThread cZwSetInformationThread = (fZwSetInformationThread)(ZwSetInformationThread);
    LPVOID szModuleName = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    LPVOID szGarbageFile = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    LPVOID cModuleName = szModuleName;
    ULONG_PTR NumberOfBytesWritten;
    InjectImpRecCodeData APIData;
    DWORD TracedAddress = NULL;
    DWORD TraceAddress = NULL;
    LPVOID remStringData;
    LPVOID remCodeData;
    DWORD ThreadId;
    HANDLE hThread;
    DWORD ExitCode;
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;

    if(GetModuleFileNameA(engineHandle, (LPCH)szModuleName, 0x1000) > NULL)
    {
        cModuleName = (LPVOID)((ULONG_PTR)cModuleName + lstrlenA((LPCSTR)szModuleName));
        cmpModuleName = (PMEMORY_CMP_HANDLER)(cModuleName);
        while(cmpModuleName->DataByte[0] != 0x5C)
        {
            cmpModuleName = (PMEMORY_CMP_HANDLER)((ULONG_PTR)cmpModuleName - 1);
        }
        cmpModuleName = (PMEMORY_CMP_HANDLER)((ULONG_PTR)cmpModuleName + 1);
        cmpModuleName->DataByte[0] = 0x00;
        lstrcpyA((LPSTR)szGarbageFile, (LPCSTR)szModuleName);
        lstrcatA((LPSTR)szGarbageFile, "garbage\\ImpRec.txt");
        lstrcatA((LPSTR)szModuleName, "imports\\ImpRec\\");
        lstrcatA((LPSTR)szModuleName, szPluginName);
        if(ReadProcessMemory(hProcess, (LPVOID)AddressToTrace, &TraceAddress, 4, &NumberOfBytesWritten))
        {
            if(RemoteLoadLibrary(hProcess, (char*)szModuleName, true))
            {
                hImpRecModule = LoadLibraryA((char*)szModuleName);
                if(hImpRecModule != NULL)
                {
                    fImpRecTrace = (ULONG_PTR)GetProcAddress(hImpRecModule, "Trace");
                    if(fImpRecTrace != NULL)
                    {
                        fImpRecTrace = fImpRecTrace - (ULONG_PTR)hImpRecModule;
                        remCodeData = VirtualAllocEx(hProcess, NULL, remInjectSize, MEM_COMMIT, PAGE_READWRITE);
                        remStringData = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
                        RtlZeroMemory(&APIData, sizeof InjectImpRecCodeData);
                        APIData.fTrace = fImpRecTrace + (ULONG_PTR)ImporterGetRemoteDLLBase(hProcess, hImpRecModule);
                        APIData.AddressToTrace = (ULONG_PTR)TraceAddress;
                        APIData.fCreateFileA = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileA"));
                        APIData.fCreateFileMappingA = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileMappingA"));
                        APIData.fCloseHandle = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CloseHandle"));
                        if(WriteProcessMemory(hProcess, remCodeData, (LPCVOID)&injectedImpRec, remInjectSize, &NumberOfBytesWritten))
                        {
                            WriteProcessMemory(hProcess, remStringData, &APIData, sizeof InjectImpRecCodeData, &NumberOfBytesWritten);
                            WriteProcessMemory(hProcess, (LPVOID)((ULONG_PTR)remStringData + sizeof InjectImpRecCodeData), (LPCVOID)szGarbageFile, lstrlenA((LPSTR)szGarbageFile), &NumberOfBytesWritten);
                            hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)remCodeData, remStringData, CREATE_SUSPENDED, &ThreadId);
                            if(ZwSetInformationThread != NULL)
                            {
                                cZwSetInformationThread(hThread, 0x11, NULL, NULL);
                            }
                            ResumeThread(hThread);
                            WaitForSingleObject(hThread, INFINITE);
                            if(GetExitCodeThread(hThread, &ExitCode))
                            {
                                if(ExitCode != NULL)
                                {
                                    if(MapFileEx((char*)szGarbageFile, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
                                    {
                                        RtlMoveMemory(&TracedAddress, (LPVOID)FileMapVA, 4);
                                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                                    }
                                    if(!DeleteFileA((LPCSTR)szGarbageFile))
                                    {
                                        HandlerCloseAllLockHandles((char*)szGarbageFile, false, true);
                                        DeleteFileA((LPCSTR)szGarbageFile);
                                    }
                                }
                            }
                        }
                        RemoteFreeLibrary(hProcess, NULL, (char*)szModuleName, true);
                        VirtualFreeEx(hProcess, remCodeData, NULL, MEM_RELEASE);
                        VirtualFreeEx(hProcess, remStringData, NULL, MEM_RELEASE);
                    }
                    else
                    {
                        RemoteFreeLibrary(hProcess, NULL, (char*)szModuleName, true);
                    }
                    FreeLibrary(hImpRecModule);
                }
            }
        }
    }
    VirtualFree(szModuleName, NULL, MEM_RELEASE);
    VirtualFree(szGarbageFile, NULL, MEM_RELEASE);
    return(TracedAddress);
}
// TitanEngine.StaticUnpacker.functions:
__declspec(dllexport) bool TITCALL StaticFileLoad(char* szFileName, DWORD DesiredAccess, bool SimulateLoad, LPHANDLE FileHandle, LPDWORD LoadedSize, LPHANDLE FileMap, PULONG_PTR FileMapVA)
{

    if(!SimulateLoad)
    {
        if(MapFileEx(szFileName, DesiredAccess, FileHandle, LoadedSize, FileMap, FileMapVA, NULL))
        {
            return(true);
        }
    }
    else
    {
        *FileMapVA = (ULONG_PTR)ResourcerLoadFileForResourceUse(szFileName);
        if(*FileMapVA != NULL)
        {
            *LoadedSize = (DWORD)GetPE32DataFromMappedFile(*FileMapVA, NULL, UE_SIZEOFIMAGE);
            *FileHandle = NULL;
            *FileMap = NULL;
            return(true);
        }
    }
    return(false);
}
__declspec(dllexport) bool TITCALL StaticFileLoadW(wchar_t* szFileName, DWORD DesiredAccess, bool SimulateLoad, LPHANDLE FileHandle, LPDWORD LoadedSize, LPHANDLE FileMap, PULONG_PTR FileMapVA)
{

    if(!SimulateLoad)
    {
        if(MapFileExW(szFileName, DesiredAccess, FileHandle, LoadedSize, FileMap, FileMapVA, NULL))
        {
            return(true);
        }
    }
    else
    {
        *FileMapVA = (ULONG_PTR)ResourcerLoadFileForResourceUseW(szFileName);
        if(*FileMapVA != NULL)
        {
            *LoadedSize = (DWORD)GetPE32DataFromMappedFile(*FileMapVA, NULL, UE_SIZEOFIMAGE);
            *FileHandle = NULL;
            *FileMap = NULL;
            return(true);
        }
    }
    return(false);
}
__declspec(dllexport) bool TITCALL StaticFileUnload(char* szFileName, bool CommitChanges, HANDLE FileHandle, DWORD LoadedSize, HANDLE FileMap, ULONG_PTR FileMapVA)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        return(StaticFileUnloadW(uniFileName, CommitChanges, FileHandle, LoadedSize, FileMap, FileMapVA));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL StaticFileUnloadW(wchar_t* szFileName, bool CommitChanges, HANDLE FileHandle, DWORD LoadedSize, HANDLE FileMap, ULONG_PTR FileMapVA)
{

    DWORD PeHeaderSize;
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_SECTION_HEADER PESections;
    DWORD SectionNumber = 0;
    DWORD SectionRawOffset = 0;
    DWORD SectionRawSize = 0;
    BOOL FileIs64;
    HANDLE myFileHandle;
    DWORD myFileSize;
    HANDLE myFileMap;
    ULONG_PTR myFileMapVA;

    if(FileHandle != NULL && FileMap != NULL)
    {
        UnMapFileEx(FileHandle, LoadedSize, FileMap, FileMapVA);
        return(true);
    }
    else
    {
        if(!CommitChanges)
        {
            return(ResourcerFreeLoadedFile((LPVOID)FileMapVA));
        }
        else
        {
            if(MapFileExW(szFileName, UE_ACCESS_ALL, &myFileHandle, &myFileSize, &myFileMap, &myFileMapVA, NULL))
            {
                DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
                if(DOSHeader->e_lfanew < 0x1000 - 108)
                {
                    PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
                    PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
                    if(PEHeader32->OptionalHeader.Magic == 0x10B)
                    {
                        FileIs64 = false;
                    }
                    else if(PEHeader32->OptionalHeader.Magic == 0x20B)
                    {
                        FileIs64 = true;
                    }
                    else
                    {
                        ResourcerFreeLoadedFile((LPVOID)FileMapVA);
                        UnMapFileEx(myFileHandle, myFileSize, myFileMap, myFileMapVA);
                        return(false);
                    }
                    if(!FileIs64)
                    {
                        PeHeaderSize = PEHeader32->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_SECTION_HEADER) * PEHeader32->FileHeader.NumberOfSections;
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PEHeader32 + PEHeader32->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4);
                        SectionNumber = PEHeader32->FileHeader.NumberOfSections;
                        RtlMoveMemory((LPVOID)myFileMapVA, (LPVOID)FileMapVA, PeHeaderSize);
                        while(SectionNumber > 0)
                        {
                            RtlMoveMemory((LPVOID)((ULONG_PTR)myFileMapVA + PESections->PointerToRawData), (LPVOID)(FileMapVA + PESections->VirtualAddress), PESections->SizeOfRawData);
                            PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                            SectionNumber--;
                        }
                        ResourcerFreeLoadedFile((LPVOID)FileMapVA);
                        UnMapFileEx(myFileHandle, myFileSize, myFileMap, myFileMapVA);
                        return(true);
                    }
                    else
                    {
                        PeHeaderSize = PEHeader64->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_SECTION_HEADER) * PEHeader64->FileHeader.NumberOfSections;
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PEHeader64 + PEHeader64->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4);
                        SectionNumber = PEHeader64->FileHeader.NumberOfSections;
                        RtlMoveMemory((LPVOID)myFileMapVA, (LPVOID)FileMapVA, PeHeaderSize);
                        while(SectionNumber > 0)
                        {
                            RtlMoveMemory((LPVOID)((ULONG_PTR)myFileMapVA + PESections->PointerToRawData), (LPVOID)(FileMapVA + PESections->VirtualAddress), PESections->SizeOfRawData);
                            PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                            SectionNumber--;
                        }
                        ResourcerFreeLoadedFile((LPVOID)FileMapVA);
                        UnMapFileEx(myFileHandle, myFileSize, myFileMap, myFileMapVA);
                        return(true);
                    }
                }
                else
                {
                    ResourcerFreeLoadedFile((LPVOID)FileMapVA);
                    UnMapFileEx(myFileHandle, myFileSize, myFileMap, myFileMapVA);
                    return(false);
                }
            }
        }
    }
    return(false);
}
__declspec(dllexport) bool TITCALL StaticFileOpen(char* szFileName, DWORD DesiredAccess, LPHANDLE FileHandle, LPDWORD FileSizeLow, LPDWORD FileSizeHigh)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        return(StaticFileOpenW(uniFileName, DesiredAccess, FileHandle, FileSizeLow, FileSizeHigh));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL StaticFileOpenW(wchar_t* szFileName, DWORD DesiredAccess, LPHANDLE FileHandle, LPDWORD FileSizeLow, LPDWORD FileSizeHigh)
{

    __try
    {
        *FileHandle = CreateFileW(szFileName, DesiredAccess, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if(FileHandle != INVALID_HANDLE_VALUE)
        {
            *FileSizeLow = GetFileSize(*FileHandle, FileSizeHigh);
            return(true);
        }
        else
        {
            return(false);
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL StaticFileGetContent(HANDLE FileHandle, DWORD FilePositionLow, LPDWORD FilePositionHigh, void* Buffer, DWORD Size)
{

    DWORD rfNumberOfBytesRead;

    if(SetFilePointer(FileHandle, FilePositionLow, (PLONG)FilePositionHigh, FILE_BEGIN) != INVALID_SET_FILE_POINTER)
    {
        if(ReadFile(FileHandle, Buffer, Size, &rfNumberOfBytesRead, NULL))
        {
            if(rfNumberOfBytesRead == Size)
            {
                return(true);
            }
            else
            {
                RtlZeroMemory(Buffer, Size);
            }
        }
    }
    return(false);
}
__declspec(dllexport) void TITCALL StaticFileClose(HANDLE FileHandle)
{
    EngineCloseHandle(FileHandle);
}
__declspec(dllexport) void TITCALL StaticMemoryDecrypt(LPVOID MemoryStart, DWORD MemorySize, DWORD DecryptionType, DWORD DecryptionKeySize, ULONG_PTR DecryptionKey)
{
    DWORD LoopCount = NULL;
    BYTE DataByte = NULL;
    WORD DataWord = NULL;
    DWORD DataDword = NULL;
    ULONG_PTR DataQword = NULL;

    //ignore too big stuff
    if(DecryptionKeySize>sizeof(ULONG_PTR))
        return;

    if(MemoryStart != NULL && MemorySize > NULL)
    {
        LoopCount = MemorySize / DecryptionKeySize;
        while(LoopCount > NULL)
        {
            if(DecryptionType == UE_STATIC_DECRYPTOR_XOR)
            {
                if(DecryptionKeySize == UE_STATIC_KEY_SIZE_1)
                {
                    RtlMoveMemory(&DataByte, MemoryStart, UE_STATIC_KEY_SIZE_1);
                    DataByte = DataByte ^ (BYTE)DecryptionKey;
                    RtlMoveMemory(MemoryStart, &DataByte, UE_STATIC_KEY_SIZE_1);
                }
                else if(DecryptionKeySize == UE_STATIC_KEY_SIZE_2)
                {
                    RtlMoveMemory(&DataWord, MemoryStart, UE_STATIC_KEY_SIZE_2);
                    DataWord = DataWord ^ (WORD)DecryptionKey;
                    RtlMoveMemory(MemoryStart, &DataWord, UE_STATIC_KEY_SIZE_2);
                }
                else if(DecryptionKeySize == UE_STATIC_KEY_SIZE_4)
                {
                    RtlMoveMemory(&DataDword, MemoryStart, UE_STATIC_KEY_SIZE_4);
                    DataDword = DataDword ^ (DWORD)DecryptionKey;
                    RtlMoveMemory(MemoryStart, &DataDword, UE_STATIC_KEY_SIZE_4);
                }
                else if(DecryptionKeySize == UE_STATIC_KEY_SIZE_8)
                {
                    RtlMoveMemory(&DataQword, MemoryStart, UE_STATIC_KEY_SIZE_8);
                    DataQword = DataQword ^ (ULONG_PTR)DecryptionKey;
                    RtlMoveMemory(MemoryStart, &DataQword, UE_STATIC_KEY_SIZE_8);
                }
            }
            else if(DecryptionType == UE_STATIC_DECRYPTOR_SUB)
            {
                if(DecryptionKeySize == UE_STATIC_KEY_SIZE_1)
                {
                    RtlMoveMemory(&DataByte, MemoryStart, UE_STATIC_KEY_SIZE_1);
                    DataByte = DataByte - (BYTE)DecryptionKey;
                    RtlMoveMemory(MemoryStart, &DataByte, UE_STATIC_KEY_SIZE_1);
                }
                else if(DecryptionKeySize == UE_STATIC_KEY_SIZE_2)
                {
                    RtlMoveMemory(&DataWord, MemoryStart, UE_STATIC_KEY_SIZE_2);
                    DataWord = DataWord - (WORD)DecryptionKey;
                    RtlMoveMemory(MemoryStart, &DataWord, UE_STATIC_KEY_SIZE_2);
                }
                else if(DecryptionKeySize == UE_STATIC_KEY_SIZE_4)
                {
                    RtlMoveMemory(&DataDword, MemoryStart, UE_STATIC_KEY_SIZE_4);
                    DataDword = DataDword - (DWORD)DecryptionKey;
                    RtlMoveMemory(MemoryStart, &DataDword, UE_STATIC_KEY_SIZE_4);
                }
                else if(DecryptionKeySize == UE_STATIC_KEY_SIZE_8)
                {
                    RtlMoveMemory(&DataQword, MemoryStart, UE_STATIC_KEY_SIZE_8);
                    DataQword = DataQword - (ULONG_PTR)DecryptionKey;
                    RtlMoveMemory(MemoryStart, &DataQword, UE_STATIC_KEY_SIZE_8);
                }
            }
            else if(DecryptionType == UE_STATIC_DECRYPTOR_ADD)
            {
                if(DecryptionKeySize == UE_STATIC_KEY_SIZE_1)
                {
                    RtlMoveMemory(&DataByte, MemoryStart, UE_STATIC_KEY_SIZE_1);
                    DataByte = DataByte + (BYTE)DecryptionKey;
                    RtlMoveMemory(MemoryStart, &DataByte, UE_STATIC_KEY_SIZE_1);
                }
                else if(DecryptionKeySize == UE_STATIC_KEY_SIZE_2)
                {
                    RtlMoveMemory(&DataWord, MemoryStart, UE_STATIC_KEY_SIZE_2);
                    DataWord = DataWord + (WORD)DecryptionKey;
                    RtlMoveMemory(MemoryStart, &DataWord, UE_STATIC_KEY_SIZE_2);
                }
                else if(DecryptionKeySize == UE_STATIC_KEY_SIZE_4)
                {
                    RtlMoveMemory(&DataDword, MemoryStart, UE_STATIC_KEY_SIZE_4);
                    DataDword = DataDword + (DWORD)DecryptionKey;
                    RtlMoveMemory(MemoryStart, &DataDword, UE_STATIC_KEY_SIZE_4);
                }
                else if(DecryptionKeySize == UE_STATIC_KEY_SIZE_8)
                {
                    RtlMoveMemory(&DataQword, MemoryStart, UE_STATIC_KEY_SIZE_8);
                    DataQword = DataQword + (ULONG_PTR)DecryptionKey;
                    RtlMoveMemory(MemoryStart, &DataQword, UE_STATIC_KEY_SIZE_8);
                }
            }
            MemoryStart = (LPVOID)((ULONG_PTR)MemoryStart + DecryptionKeySize);
            LoopCount--;
        }
    }
}
__declspec(dllexport) void TITCALL StaticMemoryDecryptEx(LPVOID MemoryStart, DWORD MemorySize, DWORD DecryptionKeySize, void* DecryptionCallBack)
{

    DWORD LoopCount = NULL;
    typedef bool(TITCALL *fStaticCallBack)(void* sMemoryStart, int sKeySize);
    fStaticCallBack myStaticCallBack = (fStaticCallBack)DecryptionCallBack;

    if(MemoryStart != NULL && MemorySize > NULL)
    {
        LoopCount = MemorySize / DecryptionKeySize;
        while(LoopCount > NULL)
        {
            __try
            {
                if(!myStaticCallBack(MemoryStart, (int)DecryptionKeySize))
                {
                    break;
                }
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                break;
            }
            MemoryStart = (LPVOID)((ULONG_PTR)MemoryStart + DecryptionKeySize);
            LoopCount--;
        }
    }
}
__declspec(dllexport) void TITCALL StaticMemoryDecryptSpecial(LPVOID MemoryStart, DWORD MemorySize, DWORD DecryptionKeySize, DWORD SpecDecryptionType, void* DecryptionCallBack)
{

    DWORD LoopCount = NULL;
    typedef bool(TITCALL *fStaticCallBack)(void* sMemoryStart, int sKeySize);
    fStaticCallBack myStaticCallBack = (fStaticCallBack)DecryptionCallBack;

    if(MemoryStart != NULL && MemorySize > NULL)
    {
        if(SpecDecryptionType == UE_STATIC_DECRYPTOR_BACKWARD)
        {
            MemoryStart = (LPVOID)((ULONG_PTR)MemoryStart + MemorySize - DecryptionKeySize);
        }
        LoopCount = MemorySize / DecryptionKeySize;
        while(LoopCount > NULL)
        {
            __try
            {
                if(!myStaticCallBack(MemoryStart, (int)DecryptionKeySize))
                {
                    break;
                }
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                break;
            }
            if(SpecDecryptionType == UE_STATIC_DECRYPTOR_BACKWARD)
            {
                MemoryStart = (LPVOID)((ULONG_PTR)MemoryStart - DecryptionKeySize);
            }
            else
            {
                MemoryStart = (LPVOID)((ULONG_PTR)MemoryStart + DecryptionKeySize);
            }
            LoopCount--;
        }
    }
}
__declspec(dllexport) void TITCALL StaticSectionDecrypt(ULONG_PTR FileMapVA, DWORD SectionNumber, bool SimulateLoad, DWORD DecryptionType, DWORD DecryptionKeySize, ULONG_PTR DecryptionKey)
{

    if(!SimulateLoad)
    {
        StaticMemoryDecrypt((LPVOID)((ULONG_PTR)GetPE32DataFromMappedFile(FileMapVA, SectionNumber, UE_SECTIONRAWOFFSET) + FileMapVA), (DWORD)GetPE32DataFromMappedFile(FileMapVA, SectionNumber, UE_SECTIONRAWSIZE), DecryptionType, DecryptionKeySize, DecryptionKey);
    }
    else
    {
        StaticMemoryDecrypt((LPVOID)((ULONG_PTR)GetPE32DataFromMappedFile(FileMapVA, SectionNumber, UE_SECTIONVIRTUALOFFSET) + FileMapVA), (DWORD)GetPE32DataFromMappedFile(FileMapVA, SectionNumber, UE_SECTIONRAWSIZE), DecryptionType, DecryptionKeySize, DecryptionKey);
    }
}
__declspec(dllexport) bool TITCALL StaticMemoryDecompress(void* Source, DWORD SourceSize, void* Destination, DWORD DestinationSize, int Algorithm)
{
    if(!Source || !Destination)
        return false;
    ELzmaStatus lzStatus;
    CLzmaProps lzProps = {};
    ISzAlloc lzAlloc = {&LzmaAllocMem, &LzmaFreeMem};

    if(Algorithm == UE_STATIC_APLIB)
    {
#if !defined (_WIN64)
        if(aP_depack_asm_safe(Source, SourceSize, Destination, DestinationSize) != APLIB_ERROR)
        {
            return(true);
        }
        else if(aPsafe_depack(Source, SourceSize, Destination, DestinationSize) != APLIB_ERROR)
        {
            return(true);
        }
#endif
    }
    else if(Algorithm == UE_STATIC_LZMA)
    {
        if(LzmaDecode((unsigned char*)Destination, (size_t*)DestinationSize, (unsigned char*)Source, (size_t*)SourceSize, (unsigned char*)&lzProps, LZMA_PROPS_SIZE, LZMA_FINISH_ANY, &lzStatus, &lzAlloc) == SZ_OK)
        {
            return(true);
        }
    }
    return(false);
}
__declspec(dllexport) bool TITCALL StaticRawMemoryCopy(HANDLE hFile, ULONG_PTR FileMapVA, ULONG_PTR VitualAddressToCopy, DWORD Size, bool AddressIsRVA, char* szDumpFileName)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szDumpFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szDumpFileName, lstrlenA(szDumpFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        return(StaticRawMemoryCopyW(hFile, FileMapVA, VitualAddressToCopy, Size, AddressIsRVA, uniFileName));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL StaticRawMemoryCopyW(HANDLE hFile, ULONG_PTR FileMapVA, ULONG_PTR VitualAddressToCopy, DWORD Size, bool AddressIsRVA, wchar_t* szDumpFileName)
{

    DWORD SizeToRead;
    HANDLE hReadFile;
    HANDLE hWriteFile;
    LPVOID ueCopyBuffer;
    ULONG_PTR AddressToCopy;
    DWORD rfNumberOfBytesRead;

    if(FileMapVA != NULL)
    {
        if(DuplicateHandle(GetCurrentProcess(), hFile, GetCurrentProcess(), &hReadFile, NULL, false, DUPLICATE_SAME_ACCESS))
        {
            if(AddressIsRVA)
            {
                VitualAddressToCopy = VitualAddressToCopy + (ULONG_PTR)GetPE32DataFromMappedFile(FileMapVA, NULL, UE_IMAGEBASE);
                AddressToCopy = (ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, VitualAddressToCopy, false);
            }
            else
            {
                AddressToCopy = (ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, VitualAddressToCopy, false);
            }
            if(SetFilePointer(hReadFile, (long)AddressToCopy, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER)
            {
                ueCopyBuffer = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
                if(ueCopyBuffer != NULL)
                {
                    if(EngineCreatePathForFileW(szDumpFileName))
                    {
                        hWriteFile = CreateFileW(szDumpFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                        if(hWriteFile != INVALID_HANDLE_VALUE)
                        {
                            if(Size < 0x1000)
                            {
                                SizeToRead = Size;
                            }
                            else
                            {
                                SizeToRead = 0x1000;
                            }
                            while((int)Size > NULL)
                            {
                                if(ReadFile(hFile, ueCopyBuffer, SizeToRead, &rfNumberOfBytesRead, NULL) && rfNumberOfBytesRead == SizeToRead)
                                {
                                    WriteFile(hWriteFile, ueCopyBuffer, SizeToRead, &rfNumberOfBytesRead, NULL);
                                    if(Size > 0x1000)
                                    {
                                        Size = Size - 0x1000;
                                    }
                                    else if(SizeToRead != Size)
                                    {
                                        if(ReadFile(hFile, ueCopyBuffer, Size, &rfNumberOfBytesRead, NULL) && rfNumberOfBytesRead == SizeToRead)
                                        {
                                            WriteFile(hWriteFile, ueCopyBuffer, Size, &rfNumberOfBytesRead, NULL);
                                        }
                                        else
                                        {
                                            WriteFile(hWriteFile, ueCopyBuffer, rfNumberOfBytesRead, &rfNumberOfBytesRead, NULL);
                                        }
                                        SizeToRead = Size;
                                        Size = NULL;
                                    }
                                    else
                                    {
                                        SizeToRead = Size;
                                        Size = NULL;
                                    }
                                }
                                else
                                {
                                    WriteFile(hWriteFile, ueCopyBuffer, rfNumberOfBytesRead, &rfNumberOfBytesRead, NULL);
                                    Size = NULL;
                                }
                            }
                            EngineCloseHandle(hReadFile);
                            EngineCloseHandle(hWriteFile);
                            VirtualFree(ueCopyBuffer, NULL, MEM_RELEASE);
                            return(true);
                        }
                        else
                        {
                            VirtualFree(ueCopyBuffer, NULL, MEM_RELEASE);
                        }
                    }
                }
            }
            EngineCloseHandle(hReadFile);
        }
    }
    return(false);
}
__declspec(dllexport) bool TITCALL StaticRawMemoryCopyEx(HANDLE hFile, DWORD RawAddressToCopy, DWORD Size, char* szDumpFileName)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szDumpFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szDumpFileName, lstrlenA(szDumpFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        return(StaticRawMemoryCopyExW(hFile, RawAddressToCopy, Size, uniFileName));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL StaticRawMemoryCopyExW(HANDLE hFile, DWORD RawAddressToCopy, DWORD Size, wchar_t* szDumpFileName)
{

    DWORD SizeToRead;
    HANDLE hReadFile;
    HANDLE hWriteFile;
    LPVOID ueCopyBuffer;
    DWORD rfNumberOfBytesRead;

    if(DuplicateHandle(GetCurrentProcess(), hFile, GetCurrentProcess(), &hReadFile, NULL, false, DUPLICATE_SAME_ACCESS))
    {
        if(SetFilePointer(hReadFile, (long)(RawAddressToCopy), NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER)
        {
            ueCopyBuffer = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
            if(ueCopyBuffer != NULL)
            {
                if(EngineCreatePathForFileW(szDumpFileName))
                {
                    hWriteFile = CreateFileW(szDumpFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                    if(hWriteFile != INVALID_HANDLE_VALUE)
                    {
                        if(Size < 0x1000)
                        {
                            SizeToRead = Size;
                        }
                        else
                        {
                            SizeToRead = 0x1000;
                        }
                        while((int)Size > NULL)
                        {
                            if(ReadFile(hFile, ueCopyBuffer, SizeToRead, &rfNumberOfBytesRead, NULL) && rfNumberOfBytesRead == SizeToRead)
                            {
                                WriteFile(hWriteFile, ueCopyBuffer, SizeToRead, &rfNumberOfBytesRead, NULL);
                                if(Size > 0x1000)
                                {
                                    Size = Size - 0x1000;
                                }
                                else if(SizeToRead != Size)
                                {
                                    if(ReadFile(hFile, ueCopyBuffer, Size, &rfNumberOfBytesRead, NULL) && rfNumberOfBytesRead == SizeToRead)
                                    {
                                        WriteFile(hWriteFile, ueCopyBuffer, Size, &rfNumberOfBytesRead, NULL);
                                    }
                                    else
                                    {
                                        WriteFile(hWriteFile, ueCopyBuffer, rfNumberOfBytesRead, &rfNumberOfBytesRead, NULL);
                                    }
                                    SizeToRead = Size;
                                    Size = NULL;
                                }
                                else
                                {
                                    SizeToRead = Size;
                                    Size = NULL;
                                }
                            }
                            else
                            {
                                WriteFile(hWriteFile, ueCopyBuffer, rfNumberOfBytesRead, &rfNumberOfBytesRead, NULL);
                                Size = NULL;
                            }
                        }
                        EngineCloseHandle(hReadFile);
                        EngineCloseHandle(hWriteFile);
                        VirtualFree(ueCopyBuffer, NULL, MEM_RELEASE);
                        return(true);
                    }
                    else
                    {
                        VirtualFree(ueCopyBuffer, NULL, MEM_RELEASE);
                    }
                }
            }
        }
        EngineCloseHandle(hReadFile);
    }
    return(false);
}
__declspec(dllexport) bool TITCALL StaticRawMemoryCopyEx64(HANDLE hFile, DWORD64 RawAddressToCopy, DWORD64 Size, char* szDumpFileName)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szDumpFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szDumpFileName, lstrlenA(szDumpFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        return(StaticRawMemoryCopyEx64W(hFile, RawAddressToCopy, Size, uniFileName));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL StaticRawMemoryCopyEx64W(HANDLE hFile, DWORD64 RawAddressToCopy, DWORD64 Size, wchar_t* szDumpFileName)
{

    DWORD SizeToRead;
    HANDLE hReadFile;
    HANDLE hWriteFile;
    LPVOID ueCopyBuffer;
    DWORD rfNumberOfBytesRead;
    long FilePosLow;
    long FilePosHigh;

    if(DuplicateHandle(GetCurrentProcess(), hFile, GetCurrentProcess(), &hReadFile, NULL, false, DUPLICATE_SAME_ACCESS))
    {
        FilePosLow = (DWORD)RawAddressToCopy;
        RtlMoveMemory(&FilePosHigh, (void*)((ULONG_PTR)(&RawAddressToCopy) + 4), 4);
        if(SetFilePointer(hReadFile, FilePosLow, &FilePosHigh, FILE_BEGIN) != INVALID_SET_FILE_POINTER)
        {
            ueCopyBuffer = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
            if(ueCopyBuffer != NULL)
            {
                if(EngineCreatePathForFileW(szDumpFileName))
                {
                    hWriteFile = CreateFileW(szDumpFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                    if(hWriteFile != INVALID_HANDLE_VALUE)
                    {
                        if(Size < 0x1000)
                        {
                            SizeToRead = (DWORD)Size;
                        }
                        else
                        {
                            SizeToRead = 0x1000;
                        }
                        while(Size != NULL)
                        {
                            if(ReadFile(hFile, ueCopyBuffer, SizeToRead, &rfNumberOfBytesRead, NULL) && rfNumberOfBytesRead == SizeToRead)
                            {
                                WriteFile(hWriteFile, ueCopyBuffer, SizeToRead, &rfNumberOfBytesRead, NULL);
                                if(Size > 0x1000)
                                {
                                    Size = Size - 0x1000;
                                }
                                else if((DWORD64)SizeToRead != Size)
                                {
                                    if(ReadFile(hFile, ueCopyBuffer, (DWORD)Size, &rfNumberOfBytesRead, NULL) && rfNumberOfBytesRead == SizeToRead)
                                    {
                                        WriteFile(hWriteFile, ueCopyBuffer, (DWORD)Size, &rfNumberOfBytesRead, NULL);
                                    }
                                    else
                                    {
                                        WriteFile(hWriteFile, ueCopyBuffer, rfNumberOfBytesRead, &rfNumberOfBytesRead, NULL);
                                    }
                                    SizeToRead = (DWORD)Size;
                                    Size = NULL;
                                }
                                else
                                {
                                    SizeToRead = (DWORD)Size;
                                    Size = NULL;
                                }
                            }
                            else
                            {
                                WriteFile(hWriteFile, ueCopyBuffer, rfNumberOfBytesRead, &rfNumberOfBytesRead, NULL);
                                Size = NULL;
                            }
                        }
                        EngineCloseHandle(hReadFile);
                        EngineCloseHandle(hWriteFile);
                        VirtualFree(ueCopyBuffer, NULL, MEM_RELEASE);
                        return(true);
                    }
                    else
                    {
                        VirtualFree(ueCopyBuffer, NULL, MEM_RELEASE);
                    }
                }
            }
        }
        EngineCloseHandle(hReadFile);
    }
    return(false);
}
__declspec(dllexport) bool TITCALL StaticHashMemory(void* MemoryToHash, DWORD SizeOfMemory, void* HashDigest, bool OutputString, int Algorithm)
{

#define MD5LEN 16
#define SHA1LEN 20
#define HASH_MAX_LENGTH 20

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = NULL;
    DWORD rgbHash[HASH_MAX_LENGTH / 4];
    DWORD cbHash = 0;
    DWORD crc32 = -1;
    ALG_ID hashAlgo;

    if(Algorithm != UE_STATIC_HASH_CRC32)
    {
        if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, NULL))  //CRYPT_VERIFYCONTEXT
        {
            if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
            {
                return(false);
            }
        }
        if(Algorithm == UE_STATIC_HASH_MD5)
        {
            hashAlgo = CALG_MD5;
        }
        else
        {
            hashAlgo = CALG_SHA;
        }
        if(!CryptCreateHash(hProv, hashAlgo, NULL, NULL, &hHash))
        {
            CryptReleaseContext(hProv, NULL);
            return(false);
        }
        else
        {
            if(!CryptHashData(hHash, (const BYTE*)MemoryToHash, SizeOfMemory, NULL))
            {
                CryptReleaseContext(hProv, NULL);
                CryptDestroyHash(hHash);
                return(false);
            }
        }
        if(Algorithm == UE_STATIC_HASH_MD5)
        {
            cbHash = MD5LEN;
            if(!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)&rgbHash[0], &cbHash, NULL))
            {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, NULL);
                return(false);
            }
            else
            {
                rgbHash[0] = _byteswap_ulong(rgbHash[0]);
                rgbHash[1] = _byteswap_ulong(rgbHash[1]);
                rgbHash[2] = _byteswap_ulong(rgbHash[2]);
                rgbHash[3] = _byteswap_ulong(rgbHash[3]);
                __try
                {
                    if(OutputString)
                    {
                        wsprintfA((char*)HashDigest, "%08X%08X%08X%08X", rgbHash[0], rgbHash[1], rgbHash[2], rgbHash[3]);
                    }
                    else
                    {
                        RtlMoveMemory(HashDigest, &rgbHash[0], MD5LEN / 4);
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    CryptDestroyHash(hHash);
                    CryptReleaseContext(hProv, NULL);
                    return(false);
                }
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, NULL);
                return(true);
            }
        }
        else if(Algorithm == UE_STATIC_HASH_SHA1)
        {
            cbHash = SHA1LEN;
            if(!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)&rgbHash[0], &cbHash, NULL))
            {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, NULL);
                return(false);
            }
            else
            {
                rgbHash[0] = _byteswap_ulong(rgbHash[0]);
                rgbHash[1] = _byteswap_ulong(rgbHash[1]);
                rgbHash[2] = _byteswap_ulong(rgbHash[2]);
                rgbHash[3] = _byteswap_ulong(rgbHash[3]);
                rgbHash[4] = _byteswap_ulong(rgbHash[4]);
                __try
                {
                    if(OutputString)
                    {
                        wsprintfA((char*)HashDigest, "%08X%08X%08X%08X%08X", rgbHash[0], rgbHash[1], rgbHash[2], rgbHash[3], rgbHash[4]);
                    }
                    else
                    {
                        RtlMoveMemory(HashDigest, &rgbHash[0], SHA1LEN / 4);
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    CryptDestroyHash(hHash);
                    CryptReleaseContext(hProv, NULL);
                    return(false);
                }
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, NULL);
                return(true);
            }
        }
    }
    else
    {
        EngineCrc32PartialCRC(&crc32, (unsigned char*)MemoryToHash, (unsigned long)SizeOfMemory);
        crc32 = crc32 ^ 0xFFFFFFFF;
        if(OutputString)
        {
            wsprintfA((char*)HashDigest, "%08X", crc32);
        }
        else
        {
            RtlMoveMemory(HashDigest, &crc32, sizeof crc32);
        }
        return(true);
    }
    return(false);
}
__declspec(dllexport) bool TITCALL StaticHashFile(char* szFileName, char* HashDigest, bool OutputString, int Algorithm)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        return(StaticHashFileW(uniFileName, HashDigest, OutputString, Algorithm));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL StaticHashFileW(wchar_t* szFileName, char* HashDigest, bool OutputString, int Algorithm)
{

#define MD5LEN 16
#define SHA1LEN 20
#define HASH_MAX_LENGTH 20

    bool bResult = true;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = NULL;
    BYTE rgbFile[1024];
    DWORD cbRead = 0;
    DWORD rgbHash[HASH_MAX_LENGTH / 4];
    DWORD cbHash = 0;
    DWORD crc32 = -1;
    ALG_ID hashAlgo;

    hFile = CreateFileW(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if(hFile == INVALID_HANDLE_VALUE || HashDigest == NULL)
    {
        return(false);
    }
    if(Algorithm != UE_STATIC_HASH_CRC32)
    {
        if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, NULL))  //CRYPT_VERIFYCONTEXT
        {
            if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
            {
                CloseHandle(hFile);
                return(false);
            }
        }
        if(Algorithm == UE_STATIC_HASH_MD5)
        {
            hashAlgo = CALG_MD5;
        }
        else
        {
            hashAlgo = CALG_SHA;
        }
        if(!CryptCreateHash(hProv, hashAlgo, NULL, NULL, &hHash))
        {
            CloseHandle(hFile);
            CryptReleaseContext(hProv, NULL);
            return(false);
        }
        while(bResult)
        {
            if(!ReadFile(hFile, rgbFile, 1024, &cbRead, NULL))
            {
                bResult = false;
            }
            else if(cbRead == NULL)
            {
                break;
            }
            if(!CryptHashData(hHash, rgbFile, cbRead, NULL))
            {
                CryptReleaseContext(hProv, NULL);
                CryptDestroyHash(hHash);
                CloseHandle(hFile);
                return(false);
            }
        }
        if(!bResult)
        {
            CryptReleaseContext(hProv, NULL);
            CryptDestroyHash(hHash);
            CloseHandle(hFile);
            return(false);
        }
        if(Algorithm == UE_STATIC_HASH_MD5)
        {
            cbHash = MD5LEN;
            if(!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)&rgbHash[0], &cbHash, NULL))
            {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, NULL);
                CloseHandle(hFile);
                return(false);
            }
            else
            {
                rgbHash[0] = _byteswap_ulong(rgbHash[0]);
                rgbHash[1] = _byteswap_ulong(rgbHash[1]);
                rgbHash[2] = _byteswap_ulong(rgbHash[2]);
                rgbHash[3] = _byteswap_ulong(rgbHash[3]);
                __try
                {
                    if(OutputString)
                    {
                        wsprintfA(HashDigest, "%08X%08X%08X%08X", rgbHash[0], rgbHash[1], rgbHash[2], rgbHash[3]);
                    }
                    else
                    {
                        RtlMoveMemory(HashDigest, &rgbHash[0], MD5LEN / 4);
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    CryptDestroyHash(hHash);
                    CryptReleaseContext(hProv, NULL);
                    CloseHandle(hFile);
                    return(false);
                }
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, NULL);
                CloseHandle(hFile);
                return(true);
            }
        }
        else if(Algorithm == UE_STATIC_HASH_SHA1)
        {
            cbHash = SHA1LEN;
            if(!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)&rgbHash[0], &cbHash, NULL))
            {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, NULL);
                CloseHandle(hFile);
                return(false);
            }
            else
            {
                rgbHash[0] = _byteswap_ulong(rgbHash[0]);
                rgbHash[1] = _byteswap_ulong(rgbHash[1]);
                rgbHash[2] = _byteswap_ulong(rgbHash[2]);
                rgbHash[3] = _byteswap_ulong(rgbHash[3]);
                rgbHash[4] = _byteswap_ulong(rgbHash[4]);
                __try
                {
                    if(OutputString)
                    {
                        wsprintfA(HashDigest, "%08X%08X%08X%08X%08X", rgbHash[0], rgbHash[1], rgbHash[2], rgbHash[3], rgbHash[4]);
                    }
                    else
                    {
                        RtlMoveMemory(HashDigest, &rgbHash[0], SHA1LEN / 4);
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    CryptDestroyHash(hHash);
                    CryptReleaseContext(hProv, NULL);
                    CloseHandle(hFile);
                    return(false);
                }
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, NULL);
                CloseHandle(hFile);
                return(true);
            }
        }
    }
    else
    {
        while(bResult)
        {
            if(!ReadFile(hFile, rgbFile, 1024, &cbRead, NULL))
            {
                bResult = false;
            }
            else if(cbRead == NULL)
            {
                break;
            }
            EngineCrc32PartialCRC(&crc32, (unsigned char*)&rgbFile[0], cbRead);
        }
        crc32 = crc32 ^ 0xFFFFFFFF;
        if(OutputString)
        {
            wsprintfA(HashDigest, "%08X", crc32);
        }
        else
        {
            RtlMoveMemory(HashDigest, &crc32, sizeof crc32);
        }
        CloseHandle(hFile);
        return(true);
    }
    CloseHandle(hFile);
    return(false);
}
// TitanEngine.Engine.functions:
__declspec(dllexport) void TITCALL SetEngineVariable(DWORD VariableId, bool VariableSet)
{

    if(VariableId == UE_ENGINE_ALOW_MODULE_LOADING)
    {
        engineAlowModuleLoading = VariableSet;
    }
    else if(VariableId == UE_ENGINE_AUTOFIX_FORWARDERS)
    {
        engineCheckForwarders = VariableSet;
    }
    else if(VariableId == UE_ENGINE_PASS_ALL_EXCEPTIONS)
    {
        enginePassAllExceptions = VariableSet;
    }
    else if(VariableId == UE_ENGINE_NO_CONSOLE_WINDOW)
    {
        engineRemoveConsoleForDebugee = VariableSet;
    }
    else if(VariableId == UE_ENGINE_BACKUP_FOR_CRITICAL_FUNCTIONS)
    {
        engineBackupForCriticalFunctions = VariableSet;
    }
    else if(VariableId == UE_ENGINE_RESET_CUSTOM_HANDLER)
    {
        engineResetCustomHandler = VariableSet;
    }
    else if(VariableId == UE_ENGINE_CALL_PLUGIN_DEBUG_CALLBACK)
    {
        engineExecutePluginCallBack = VariableSet;
    }
}
// Global.Engine.Hook.functions:
void EngineFakeLoadLibraryReturn()
{

    ULONG_PTR ParameterData;
    LPDEBUG_EVENT currentDBGEvent;
    HANDLE currentProcess;

    currentDBGEvent = (LPDEBUG_EVENT)GetDebugData();
    currentProcess = dbgProcessInformation.hProcess;
    if(currentProcess != NULL)
    {
#if !defined(_WIN64)
        ParameterData = (ULONG_PTR)GetFunctionParameter(currentProcess, UE_FUNCTION_STDCALL_RET, 1, UE_PARAMETER_DWORD);
        if(ParameterData != NULL)
        {
            if(engineFakeDLLHandle != NULL)
            {
                SetContextData(UE_EAX, engineFakeDLLHandle);
            }
            else
            {
                SetContextData(UE_EAX, 0x10000000);
            }
        }
#else
        ParameterData = (ULONG_PTR)GetFunctionParameter(currentProcess, UE_FUNCTION_FASTCALL, 1, UE_PARAMETER_QWORD);
        if(ParameterData != NULL)
        {
            if(engineFakeDLLHandle != NULL)
            {
                SetContextData(UE_RAX, engineFakeDLLHandle);
            }
            else
            {
                SetContextData(UE_RAX, 0x10000000);
            }
        }
#endif
    }
}
void EngineFakeGetProcAddressReturn()
{

    ULONG_PTR ParameterData;
    LPDEBUG_EVENT currentDBGEvent;
    HANDLE currentProcess;

    currentDBGEvent = (LPDEBUG_EVENT)GetDebugData();
    currentProcess = dbgProcessInformation.hProcess;
    if(currentProcess != NULL)
    {
#if !defined(_WIN64)
        ParameterData = (ULONG_PTR)GetFunctionParameter(currentProcess, UE_FUNCTION_STDCALL_RET, 1, UE_PARAMETER_DWORD);
        if(ParameterData != NULL)
        {
            SetContextData(UE_EAX, (ULONG_PTR)ImporterGetRemoteAPIAddress(currentProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitProcess")));
        }
#else
        ParameterData = (ULONG_PTR)GetFunctionParameter(currentProcess, UE_FUNCTION_FASTCALL, 1, UE_PARAMETER_QWORD);
        if(ParameterData != NULL)
        {
            SetContextData(UE_RAX, (ULONG_PTR)ImporterGetRemoteAPIAddress(currentProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitProcess")));
        }
#endif
    }
}
// Global.TitanEngine.Engine.functions:
bool EngineGetFileDialog(char* GlobalBuffer)
{

    OPENFILENAMEA sOpenFileName;
    char szFilterString[] = "All Files \0*.*\0\0";
    char szDialogTitle[] = "TitanEngine2 from Reversing Labs";

    RtlZeroMemory(&sOpenFileName, sizeof(OPENFILENAMEA));
    sOpenFileName.lStructSize = sizeof(OPENFILENAMEA);
    sOpenFileName.lpstrFilter = &szFilterString[0];
    sOpenFileName.lpstrFile = &GlobalBuffer[0];
    sOpenFileName.nMaxFile = 1024;
    sOpenFileName.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_LONGNAMES | OFN_EXPLORER | OFN_HIDEREADONLY;
    sOpenFileName.lpstrTitle = &szDialogTitle[0];
    if(!GetOpenFileNameA(&sOpenFileName))
    {
        RtlZeroMemory(&GlobalBuffer[0], 1024);
        return(false);
    }
    else
    {
        return(true);
    }
}
long EngineWndProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{

    char szAboutTitle[] = "[ About ]";
    char szAboutText[] = "%s \r\n\r\n ReversingLabs - http://www.reversinglabs.com \r\n\r\n  Minimum engine version needed:\r\n- TitanEngine %i.%i.%i by RevLabs\r\n\r\nUnpacker coded by %s";
    typedef void(TITCALL *fStartUnpacking)(char* szInputFile, bool RealignFile, bool CopyOverlay);
    fStartUnpacking myStartUnpacking = (fStartUnpacking)EngineStartUnpackingCallBack;
    char GlobalBuffer[1024] = {};
    char AboutBuffer[1024] = {};
    bool bRealignFile = false;
    bool bCopyOverlay = false;

    if(uMsg == WM_INITDIALOG)
    {
        SendMessageA(hwndDlg, WM_SETTEXT, NULL, (LPARAM)&szWindowUnpackerTitle);
        SendMessageA(hwndDlg, WM_SETICON, NULL, (LPARAM)LoadIconA((HINSTANCE)engineHandle, MAKEINTRESOURCEA(IDI_ICON2)));
        SetDlgItemTextA(hwndDlg, IDD_UNPACKERTITLE, szWindowUnpackerLongTitle);
        SetDlgItemTextA(hwndDlg, IDC_FILENAME, "filename.exe");
        CheckDlgButton(hwndDlg, IDC_REALING, 1);
        EngineWindowHandle = hwndDlg;
    }
    else if(uMsg == WM_DROPFILES)
    {
        DragQueryFileA((HDROP)wParam, NULL, GlobalBuffer, 1024);
        SetDlgItemTextA(hwndDlg, IDC_FILENAME, GlobalBuffer);
    }
    else if(uMsg == WM_CLOSE)
    {
        EndDialog(hwndDlg, NULL);
    }
    else if(uMsg == WM_COMMAND)
    {
        if(wParam == IDC_UNPACK)
        {
            GetDlgItemTextA(hwndDlg, IDC_FILENAME, GlobalBuffer, 1024);
            if(!IsFileBeingDebugged() && EngineFileExists(GlobalBuffer))
            {
                EngineBoxHandle = GetDlgItem(hwndDlg, IDC_LISTBOX);
                SendMessageA(EngineBoxHandle, LB_RESETCONTENT, NULL, NULL);
                if(IsDlgButtonChecked(EngineWindowHandle, IDC_REALING))
                {
                    bRealignFile = true;
                }
                if(IsDlgButtonChecked(EngineWindowHandle, IDC_COPYOVERLAY))
                {
                    bCopyOverlay = true;
                }
                myStartUnpacking(GlobalBuffer, bRealignFile, bCopyOverlay);
            }
        }
        else if(wParam == IDC_BROWSE)
        {
            if(EngineGetFileDialog(GlobalBuffer))
            {
                SetDlgItemTextA(hwndDlg, IDC_FILENAME, GlobalBuffer);
            }
        }
        else if(wParam == IDC_ABOUT)
        {
            wsprintfA(AboutBuffer, szAboutText, szWindowUnpackerName, TE_VER_MAJOR, TE_VER_MIDDLE, TE_VER_MINOR, szWindowUnpackerAuthor);
            MessageBoxA(hwndDlg, AboutBuffer, szAboutTitle, MB_ICONASTERISK);
        }
        else if(wParam == IDC_EXIT)
        {
            EndDialog(hwndDlg, NULL);
        }
    }
    return(NULL);
}
// Global.Engine.Simplification.functions:
void EngineSimplifyLoadLibraryCallBack()
{

    ULONG_PTR iParameter1;
    char szLogBufferData[MAX_PATH] = {};
    char szReadStringData[MAX_PATH] = {};
    ULONG_PTR CurrentBreakAddress = (ULONG_PTR)GetContextData(UE_CIP);

    if(!EngineUnpackerFileImporterInit)
    {
        EngineUnpackerFileImporterInit = true;
        /* broken since scylla integration but we dont care
        if(EngineUnpackerFileStatus.FileIsDLL)
        {
            ImporterInit(50 * 1024, (ULONG_PTR)GetDebuggedDLLBaseAddress());
        }
        else
        {
            ImporterInit(50 * 1024, (ULONG_PTR)GetDebuggedFileBaseAddress());
        }*/
    }
    for(int i = 0; i < (int)EngineUnpackerBreakInfo.size(); i++)
    {
        if(EngineUnpackerBreakInfo[i].BreakPointAddress == CurrentBreakAddress)
        {
            iParameter1 = (ULONG_PTR)GetContextData((DWORD)EngineUnpackerBreakInfo[i].Parameter1);
            if(EngineUnpackerBreakInfo[i].SingleBreak)
            {
                EngineUnpackerBreakInfo.erase(EngineUnpackerBreakInfo.begin() + i);
            }
            if(GetRemoteString(pEngineUnpackerProcessHandle->hProcess, (void*)iParameter1, &szReadStringData[0], MAX_PATH))
            {
                ImporterAddNewDll(szReadStringData, (ULONG_PTR)GetContextData((DWORD)EngineUnpackerBreakInfo[i].Parameter2));
                if(EngineUnpackerOptionLogData)
                {
                    wsprintfA(szLogBufferData,"[x] LoadLibrary BPX -> %s",szReadStringData);
                    EngineAddUnpackerWindowLogMessage(szLogBufferData);
                }
            }
            break;
        }
    }
}
void EngineSimplifyGetProcAddressCallBack()
{

    ULONG_PTR iParameter1;
    char szLogBufferData[MAX_PATH] = {};
    char szReadStringData[MAX_PATH] = {};
    ULONG_PTR CurrentBreakAddress = (ULONG_PTR)GetContextData(UE_CIP);

    for(int i = 0; i < (int)EngineUnpackerBreakInfo.size(); i++)
    {
        if(EngineUnpackerBreakInfo[i].BreakPointAddress == CurrentBreakAddress)
        {
            iParameter1 = (ULONG_PTR)GetContextData((DWORD)EngineUnpackerBreakInfo[i].Parameter1);
            if(EngineUnpackerBreakInfo[i].SingleBreak)
            {
                EngineUnpackerBreakInfo.erase(EngineUnpackerBreakInfo.begin() + i);
            }
            if(EngineUnpackerFileStatus.FileIsDLL)
            {
                if(iParameter1 > (ULONG_PTR)GetDebuggedDLLBaseAddress())
                {
                    if(GetRemoteString(pEngineUnpackerProcessHandle->hProcess, (void*)iParameter1, &szReadStringData[0], MAX_PATH))
                    {
                        ImporterAddNewAPI(szReadStringData, (ULONG_PTR)GetContextData((DWORD)EngineUnpackerBreakInfo[i].Parameter2));
                        if(EngineUnpackerOptionLogData)
                        {
                            wsprintfA(szLogBufferData,"[x] GetProcAddress BPX -> %s",szReadStringData);
                            EngineAddUnpackerWindowLogMessage(szLogBufferData);
                        }
                    }
                }
                else
                {
                    ImporterAddNewOrdinalAPI(iParameter1, (ULONG_PTR)GetContextData((DWORD)EngineUnpackerBreakInfo[i].Parameter2));
                    if(EngineUnpackerOptionLogData)
                    {
                        wsprintfA(szLogBufferData,"[x] GetProcAddress BPX -> %08X",iParameter1);
                        EngineAddUnpackerWindowLogMessage(szLogBufferData);
                    }
                }
            }
            else
            {
                if(iParameter1 > (ULONG_PTR)GetDebuggedFileBaseAddress())
                {
                    if(GetRemoteString(pEngineUnpackerProcessHandle->hProcess, (void*)iParameter1, &szReadStringData[0], MAX_PATH))
                    {
                        ImporterAddNewAPI(szReadStringData, (ULONG_PTR)GetContextData((DWORD)EngineUnpackerBreakInfo[i].Parameter2));
                        if(EngineUnpackerOptionLogData)
                        {
                            wsprintfA(szLogBufferData,"[x] GetProcAddress BPX -> %s",szReadStringData);
                            EngineAddUnpackerWindowLogMessage(szLogBufferData);
                        }
                    }
                }
                else
                {
                    ImporterAddNewOrdinalAPI(iParameter1, (ULONG_PTR)GetContextData((DWORD)EngineUnpackerBreakInfo[i].Parameter2));
                    if(EngineUnpackerOptionLogData)
                    {
                        wsprintfA(szLogBufferData,"[x] GetProcAddress BPX -> %08X",iParameter1);
                        EngineAddUnpackerWindowLogMessage(szLogBufferData);
                    }
                }
            }
            break;
        }
    }
}
void EngineSimplifyMakeSnapshotCallBack()
{

    ULONG_PTR fdLoadedBase;
    wchar_t szTempName[MAX_PATH] = {};
    wchar_t szTempFolder[MAX_PATH] = {};
    ULONG_PTR CurrentBreakAddress = (ULONG_PTR)GetContextData(UE_CIP);

    if(EngineUnpackerFileStatus.FileIsDLL)
    {
        fdLoadedBase = (ULONG_PTR)GetDebuggedDLLBaseAddress();
    }
    else
    {
        fdLoadedBase = (ULONG_PTR)GetDebuggedFileBaseAddress();
    }
    for(int i = 0; i < (int)EngineUnpackerBreakInfo.size(); i++)
    {
        if(EngineUnpackerBreakInfo[i].BreakPointAddress == CurrentBreakAddress)
        {
            if(EngineUnpackerBreakInfo[i].SnapShotNumber == 1)
            {
                if(GetTempPathW(MAX_PATH, szTempFolder) < MAX_PATH)
                {
                    if(GetTempFileNameW(szTempFolder, L"OverlayTemp", GetTickCount() + 101, szTempName))
                    {
                        lstrcpyW(szEngineUnpackerSnapShot1, szTempName);
                        RelocaterMakeSnapshotW(pEngineUnpackerProcessHandle->hProcess, szEngineUnpackerSnapShot1, (void*)(EngineUnpackerBreakInfo[i].Parameter1 + fdLoadedBase), EngineUnpackerBreakInfo[i].Parameter2);
                    }
                }
            }
            else
            {
                if(GetTempPathW(MAX_PATH, szTempFolder) < MAX_PATH)
                {
                    if(GetTempFileNameW(szTempFolder, L"OverlayTemp", GetTickCount() + 201, szTempName))
                    {
                        lstrcpyW(szEngineUnpackerSnapShot2, szTempName);
                        RelocaterMakeSnapshotW(pEngineUnpackerProcessHandle->hProcess, szEngineUnpackerSnapShot2, (void*)(EngineUnpackerBreakInfo[i].Parameter1 + fdLoadedBase), EngineUnpackerBreakInfo[i].Parameter2);
                    }
                }
            }
            return;
        }
    }
}
void EngineSimplifyEntryPointCallBack()
{

    int i = 0;
    int j = 0;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    HANDLE FileHandle;
    long mImportTableOffset;
    long mRelocTableOffset;
    DWORD pOverlayStart;
    DWORD pOverlaySize;
    ULONG_PTR fdLoadedBase;
    char szLogBufferData[MAX_PATH] = {};
    wchar_t szTempFolder[MAX_PATH] = {};
    wchar_t szTempName[MAX_PATH] = {};

    __try
    {
        if(EngineUnpackerOptionUnpackedOEP == NULL)
        {
            EngineUnpackerOptionUnpackedOEP = (ULONG_PTR)GetContextData(UE_CIP);
        }
        if(EngineUnpackerOptionLogData)
        {
            wsprintfA(szLogBufferData,"[x] Entry Point at: %08X", EngineUnpackerOptionUnpackedOEP);
            EngineAddUnpackerWindowLogMessage(szLogBufferData);
        }
        if(EngineUnpackerFileStatus.FileIsDLL)
        {
            fdLoadedBase = (ULONG_PTR)GetDebuggedDLLBaseAddress();
            RelocaterInit(100 * 1024, (ULONG_PTR)GetPE32DataW(szEngineUnpackerInputFile, NULL, UE_IMAGEBASE), fdLoadedBase);
            for(i = 0; i < (int)EngineUnpackerBreakInfo.size(); i++)
            {
                if(EngineUnpackerBreakInfo[i].SnapShotNumber == 1)
                {
                    j = i;
                }
            }
            if(szEngineUnpackerSnapShot2[0] == 0x00)
            {
                if(GetTempPathW(MAX_PATH, szTempFolder) < MAX_PATH)
                {
                    if(GetTempFileNameW(szTempFolder, L"OverlayTemp", GetTickCount() + 301, szTempName))
                    {
                        lstrcpyW(szEngineUnpackerSnapShot2, szTempName);
                        RelocaterMakeSnapshotW(pEngineUnpackerProcessHandle->hProcess, szEngineUnpackerSnapShot2, (void*)(EngineUnpackerBreakInfo[j].Parameter1 + fdLoadedBase), EngineUnpackerBreakInfo[j].Parameter2);
                    }
                }
            }
            RelocaterCompareTwoSnapshotsW(pEngineUnpackerProcessHandle->hProcess, fdLoadedBase, (ULONG_PTR)GetPE32DataW(szEngineUnpackerInputFile, NULL, UE_SIZEOFIMAGE), szEngineUnpackerSnapShot1, szEngineUnpackerSnapShot2, EngineUnpackerBreakInfo[j].Parameter1 + fdLoadedBase);
            EngineUnpackerOptionRelocationFix = true;
        }
        else
        {
            fdLoadedBase = (ULONG_PTR)GetDebuggedFileBaseAddress();
        }
        if(PastePEHeaderW(pEngineUnpackerProcessHandle->hProcess, (void*)fdLoadedBase, szEngineUnpackerInputFile))
        {
            if(EngineUnpackerOptionLogData)
            {
                EngineAddUnpackerWindowLogMessage("[x] Paste PE header");
            }
        }
        DumpProcessW(pEngineUnpackerProcessHandle->hProcess, (void*)fdLoadedBase, szEngineUnpackerOutputFile, EngineUnpackerOptionUnpackedOEP);
        if(EngineUnpackerOptionLogData)
        {
            EngineAddUnpackerWindowLogMessage("[x] Process dumped!");
        }
        mImportTableOffset = AddNewSectionW(szEngineUnpackerOutputFile, ".TEv2", ImporterEstimatedSize() + 200) + (DWORD)fdLoadedBase;
        if(EngineUnpackerOptionRelocationFix)
        {
            if(EngineUnpackerFileStatus.FileIsDLL)
            {
                mRelocTableOffset = AddNewSectionW(szEngineUnpackerOutputFile, ".TEv2", RelocaterEstimatedSize() + 200);
            }
        }
        if(StaticFileLoadW(szEngineUnpackerOutputFile, UE_ACCESS_ALL, false, &FileHandle, &FileSize, &FileMap, &FileMapVA))
        {
            if(ImporterExportIAT((ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, mImportTableOffset, true), FileMapVA, FileHandle))
            {
                if(EngineUnpackerOptionLogData)
                {
                    EngineAddUnpackerWindowLogMessage("[x] IAT has been fixed!");
                }
            }
            if(EngineUnpackerOptionRelocationFix)
            {
                if(EngineUnpackerFileStatus.FileIsDLL)
                {
                    RelocaterExportRelocation((ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, mRelocTableOffset + fdLoadedBase, true), mRelocTableOffset, FileMapVA);
                    if(EngineUnpackerOptionLogData)
                    {
                        EngineAddUnpackerWindowLogMessage("[x] Exporting relocations!");
                    }
                }
            }
            if(EngineUnpackerOptionRealingFile)
            {
                FileSize = RealignPE(FileMapVA, FileSize, 2);
                if(EngineUnpackerOptionLogData)
                {
                    EngineAddUnpackerWindowLogMessage("[x] Realigning file!");
                }
            }
            StaticFileUnloadW(szEngineUnpackerOutputFile, false, FileHandle, FileSize, FileMap, FileMapVA);
            MakeAllSectionsRWEW(szEngineUnpackerOutputFile);
            if(EngineUnpackerFileStatus.FileIsDLL)
            {
                if(RelocaterChangeFileBaseW(szEngineUnpackerOutputFile, (ULONG_PTR)GetPE32DataW(szEngineUnpackerInputFile, NULL, UE_IMAGEBASE)))
                {
                    if(EngineUnpackerOptionLogData)
                    {
                        EngineAddUnpackerWindowLogMessage("[x] Rebase file image!");
                    }
                }
            }
            if(EngineUnpackerOptionMoveOverlay && FindOverlayW(szEngineUnpackerInputFile, &pOverlayStart, &pOverlaySize))
            {
                CopyOverlayW(szEngineUnpackerInputFile, szEngineUnpackerOutputFile);
                if(EngineUnpackerOptionLogData)
                {
                    EngineAddUnpackerWindowLogMessage("[x] Moving overlay to unpacked file!");
                }
            }
            StopDebug();
            if(EngineUnpackerOptionLogData)
            {
                EngineAddUnpackerWindowLogMessage("[Success] File has been unpacked!");
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        ForceClose();
        //broken since scylla integration but we dont care
        //ImporterCleanup();
        if(FileMapVA > NULL)
        {
            StaticFileUnloadW(szEngineUnpackerOutputFile, false, FileHandle, FileSize, FileMap, FileMapVA);
        }
        DeleteFileW(szEngineUnpackerOutputFile);
        if(EngineUnpackerOptionLogData)
        {
            EngineAddUnpackerWindowLogMessage("[Fatal Unpacking Error] Please mail file you tried to unpack to ReversingLabs Corporation!");
        }
    }
    if(EngineUnpackerOptionLogData)
    {
        EngineAddUnpackerWindowLogMessage("-> Unpack ended...");
    }
}
// TitanEngine.Engine.Simplification.functions:
__declspec(dllexport) void TITCALL EngineUnpackerInitialize(char* szFileName, char* szUnpackedFileName, bool DoLogData, bool DoRealignFile, bool DoMoveOverlay, void* EntryCallBack)
{

    wchar_t uniFileName[MAX_PATH] = {};
    wchar_t uniUnpackedFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        if(szUnpackedFileName == NULL)
        {
            return(EngineUnpackerInitializeW(uniFileName, NULL, DoLogData, DoRealignFile, DoMoveOverlay, EntryCallBack));
        }
        else
        {
            MultiByteToWideChar(CP_ACP, NULL, szUnpackedFileName, lstrlenA(szUnpackedFileName)+1, uniUnpackedFileName, sizeof(uniUnpackedFileName)/(sizeof(uniUnpackedFileName[0])));
            EngineUnpackerInitializeW(uniFileName, uniUnpackedFileName, DoLogData, DoRealignFile, DoMoveOverlay, EntryCallBack);
        }
    }
}
__declspec(dllexport) void TITCALL EngineUnpackerInitializeW(wchar_t* szFileName, wchar_t* szUnpackedFileName, bool DoLogData, bool DoRealignFile, bool DoMoveOverlay, void* EntryCallBack)
{

    int i,j;
    wchar_t TempBackBuffer[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        RtlZeroMemory(&szEngineUnpackerSnapShot1[0], MAX_PATH * 2);
        RtlZeroMemory(&szEngineUnpackerSnapShot2[0], MAX_PATH * 2);
        RtlZeroMemory(&EngineUnpackerFileStatus, sizeof FILE_STATUS_INFO);
        if(IsPE32FileValidExW(szFileName, UE_DEPTH_DEEP, &EngineUnpackerFileStatus))
        {
            if(!EngineUnpackerFileStatus.FileIsDLL)
            {
                pEngineUnpackerProcessHandle = (LPPROCESS_INFORMATION)InitDebugExW(szFileName, NULL, NULL, EntryCallBack);
            }
            else
            {
                pEngineUnpackerProcessHandle = (LPPROCESS_INFORMATION)InitDLLDebugW(szFileName, true, NULL, NULL, EntryCallBack);
            }
            if(pEngineUnpackerProcessHandle != NULL)
            {
                lstrcpyW(szEngineUnpackerInputFile, szFileName);
                if(szUnpackedFileName != NULL)
                {
                    lstrcpyW(szEngineUnpackerOutputFile, szUnpackedFileName);
                }
                else
                {
                    lstrcpyW(TempBackBuffer, szFileName);
                    i = lstrlenW(TempBackBuffer);
                    while(TempBackBuffer[i] != 0x2E)
                    {
                        i--;
                    }
                    TempBackBuffer[i] = 0x00;
                    j = i + 1;
                    wsprintfW(szEngineUnpackerOutputFile, L"%s.unpacked.%s", &TempBackBuffer[0], &TempBackBuffer[j]);
                }
                EngineUnpackerOptionRealingFile = DoRealignFile;
                EngineUnpackerOptionMoveOverlay = DoMoveOverlay;
                EngineUnpackerOptionRelocationFix = false;
                EngineUnpackerOptionLogData = DoLogData;
                EngineUnpackerOptionUnpackedOEP = NULL;
                EngineUnpackerFileImporterInit = false;
                if(EngineUnpackerOptionLogData)
                {
                    EngineAddUnpackerWindowLogMessage("-> Unpack started...");
                }
                EngineUnpackerBreakInfo.clear();
                DebugLoop();
            }
        }
    }
}
__declspec(dllexport) bool TITCALL EngineUnpackerSetBreakCondition(void* SearchStart, DWORD SearchSize, void* SearchPattern, DWORD PatternSize, DWORD PatternDelta, ULONG_PTR BreakType, bool SingleBreak, DWORD Parameter1, DWORD Parameter2)
{

    ULONG_PTR fPatternLocation;
    DWORD fBreakPointType = UE_BREAKPOINT;
    UnpackerInformation fUnpackerInformation = {};

    if((int)SearchStart == UE_UNPACKER_CONDITION_SEARCH_FROM_EP)
    {
        if(EngineUnpackerFileStatus.FileIsDLL)
        {
            SearchStart = (void*)((ULONG_PTR)GetPE32DataW(szEngineUnpackerInputFile, NULL, UE_OEP) + (ULONG_PTR)GetDebuggedDLLBaseAddress());
        }
        else
        {
            SearchStart = (void*)((ULONG_PTR)GetPE32DataW(szEngineUnpackerInputFile, NULL, UE_OEP) + (ULONG_PTR)GetDebuggedFileBaseAddress());
        }
    }
    if(SearchSize == NULL)
    {
        SearchSize = 0x1000;
    }
    fPatternLocation = (ULONG_PTR)FindEx(pEngineUnpackerProcessHandle->hProcess, SearchStart, SearchSize, SearchPattern, PatternSize, NULL);
    if(fPatternLocation != NULL)
    {
        if(SingleBreak)
        {
            fBreakPointType = UE_SINGLESHOOT;
        }
        fPatternLocation = fPatternLocation + (int)PatternDelta;
        fUnpackerInformation.Parameter1 = Parameter1;
        fUnpackerInformation.Parameter2 = Parameter2;
        fUnpackerInformation.SingleBreak = SingleBreak;
        fUnpackerInformation.BreakPointAddress = fPatternLocation;
        if(BreakType == UE_UNPACKER_CONDITION_LOADLIBRARY)
        {
            if(SetBPX(fPatternLocation, UE_BREAKPOINT, &EngineSimplifyLoadLibraryCallBack))
            {
                EngineUnpackerBreakInfo.push_back(fUnpackerInformation);
                return(true);
            }
        }
        else if(BreakType == UE_UNPACKER_CONDITION_GETPROCADDRESS)
        {
            if(SetBPX(fPatternLocation, UE_BREAKPOINT, &EngineSimplifyGetProcAddressCallBack))
            {
                EngineUnpackerBreakInfo.push_back(fUnpackerInformation);
                return(true);
            }
        }
        else if(BreakType == UE_UNPACKER_CONDITION_ENTRYPOINTBREAK)
        {
            if(SetBPX(fPatternLocation, UE_BREAKPOINT, &EngineSimplifyGetProcAddressCallBack))
            {
                EngineUnpackerBreakInfo.push_back(fUnpackerInformation);
                return(true);
            }
        }
        else if(BreakType == UE_UNPACKER_CONDITION_RELOCSNAPSHOT1)
        {
            if(SetBPX(fPatternLocation, UE_BREAKPOINT, &EngineSimplifyMakeSnapshotCallBack))
            {
                fUnpackerInformation.SnapShotNumber = 1;
                EngineUnpackerBreakInfo.push_back(fUnpackerInformation);
                return(true);
            }
        }
        else if(BreakType == UE_UNPACKER_CONDITION_RELOCSNAPSHOT2)
        {
            if(SetBPX(fPatternLocation, UE_BREAKPOINT, &EngineSimplifyMakeSnapshotCallBack))
            {
                fUnpackerInformation.SnapShotNumber = 2;
                EngineUnpackerBreakInfo.push_back(fUnpackerInformation);
                return(true);
            }
        }
        else
        {
            if(SetBPX(fPatternLocation, fBreakPointType, (void*)BreakType))
            {
                EngineUnpackerBreakInfo.push_back(fUnpackerInformation);
                return(true);
            }
        }
    }
    return(false);
}
__declspec(dllexport) void TITCALL EngineUnpackerSetEntryPointAddress(ULONG_PTR UnpackedEntryPointAddress)
{
    EngineUnpackerOptionUnpackedOEP = UnpackedEntryPointAddress;
}
__declspec(dllexport) void TITCALL EngineUnpackerFinalizeUnpacking()
{

    EngineSimplifyEntryPointCallBack();
    EmptyGarbage();
}
// TitanEngine.Engine.functions:
__declspec(dllexport) bool TITCALL EngineCreateMissingDependencies(char* szFileName, char* szOutputFolder, bool LogCreatedFiles)
{

    wchar_t uniFileName[MAX_PATH] = {};
    wchar_t uniOutputFolder[MAX_PATH] = {};

    if(szFileName != NULL && szOutputFolder != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        MultiByteToWideChar(CP_ACP, NULL, szOutputFolder, lstrlenA(szOutputFolder)+1, uniOutputFolder, sizeof(uniOutputFolder)/(sizeof(uniOutputFolder[0])));
        return(EngineCreateMissingDependenciesW(uniFileName, uniOutputFolder, LogCreatedFiles));
    }
    else
    {
        return(NULL);
    }
}
__declspec(dllexport) bool TITCALL EngineCreateMissingDependenciesW(wchar_t* szFileName, wchar_t* szOutputFolder, bool LogCreatedFiles)
{

    char* ImportDllName;
    wchar_t ImportDllNameW[512];
    wchar_t BuildExportName[512];
    PIMAGE_THUNK_DATA32 ImportThunkX86;
    PIMAGE_THUNK_DATA64 ImportThunkX64;
    PIMAGE_IMPORT_DESCRIPTOR ImportPointer;
    ULONG_PTR ImportTableAddress = NULL;
    ULONG_PTR ImportThunkName = NULL;
    DWORD ImportThunkAddress = NULL;
    ULONG_PTR ImageBase = NULL;
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    BOOL FileIs64;

    if(MapFileExW(szFileName, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
        if(DOSHeader->e_lfanew < 0x1000 - 108)
        {
            PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            if(PEHeader32->OptionalHeader.Magic == 0x10B)
            {
                FileIs64 = false;
            }
            else if(PEHeader32->OptionalHeader.Magic == 0x20B)
            {
                FileIs64 = true;
            }
            else
            {
                UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                return(false);
            }
            if(LogCreatedFiles)
            {
                if(engineDependencyFiles != NULL)
                {
                    VirtualFree(engineDependencyFiles, NULL, MEM_RELEASE);
                }
                engineDependencyFiles = VirtualAlloc(NULL, 20 * 1024, MEM_COMMIT, PAGE_READWRITE);
                engineDependencyFilesCWP = engineDependencyFiles;
            }
            if(!FileIs64)
            {
                ImageBase = (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase;
                ImportTableAddress = (ULONG_PTR)PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                ImportTableAddress = (ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, ImportTableAddress + ImageBase, true);
                ImportPointer = (PIMAGE_IMPORT_DESCRIPTOR)ImportTableAddress;
                while(ImportPointer->FirstThunk != NULL)
                {
                    ImportDllName = (PCHAR)((ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, ImportPointer->Name + ImageBase, true));
                    MultiByteToWideChar(CP_ACP, NULL, ImportDllName, lstrlenA(ImportDllName)+1, ImportDllNameW, sizeof(ImportDllNameW)/(sizeof(ImportDllNameW[0])));
                    if(!EngineIsDependencyPresentW(ImportDllNameW, szFileName, szOutputFolder))
                    {
                        RtlZeroMemory(&BuildExportName, 512);
                        lstrcatW(BuildExportName, szOutputFolder);
                        if(BuildExportName[lstrlenW(BuildExportName)-1] != 0x5C)
                        {
                            BuildExportName[lstrlenW(BuildExportName)] = 0x5C;
                        }
                        lstrcatW(BuildExportName, ImportDllNameW);
                        if(LogCreatedFiles)
                        {
                            RtlMoveMemory(engineDependencyFilesCWP, &BuildExportName, lstrlenW(BuildExportName) * 2);
                            engineDependencyFilesCWP = (LPVOID)((ULONG_PTR)engineDependencyFilesCWP + (lstrlenW(BuildExportName) * 2) + 2);
                        }
                        EngineExtractResource("MODULEx86", BuildExportName);
                        ExporterInit(20 * 1024, (ULONG_PTR)GetPE32DataW(BuildExportName, NULL, UE_IMAGEBASE), NULL, ImportDllName);
                        ImportThunkAddress = ImportPointer->FirstThunk;
                        if(ImportPointer->OriginalFirstThunk != NULL)
                        {
                            ImportThunkX86 = (PIMAGE_THUNK_DATA32)((ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, ImportPointer->OriginalFirstThunk + ImageBase, true));
                        }
                        else
                        {
                            ImportThunkX86 = (PIMAGE_THUNK_DATA32)((ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, ImportPointer->FirstThunk + ImageBase, true));
                        }
                        while(ImportThunkX86->u1.Function != NULL)
                        {
                            if(ImportThunkX86->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
                            {
                                ExporterAddNewOrdinalExport(ImportThunkX86->u1.Ordinal ^ IMAGE_ORDINAL_FLAG32, 0x1000);
                            }
                            else
                            {
                                ImportThunkName = (ULONG_PTR)(ConvertVAtoFileOffset(FileMapVA, ImportThunkX86->u1.AddressOfData + ImageBase, true) + 2);
                                ExporterAddNewExport((PCHAR)ImportThunkName, 0x1000);
                            }
                            ImportThunkX86 = (PIMAGE_THUNK_DATA32)((ULONG_PTR)ImportThunkX86 + 4);
                            ImportThunkAddress = ImportThunkAddress + 4;
                        }
                        ExporterBuildExportTableExW(BuildExportName, ".export");
                    }
                    ImportPointer = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)ImportPointer + sizeof IMAGE_IMPORT_DESCRIPTOR);
                }
            }
            else
            {
                ImageBase = (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase;
                ImportTableAddress = (ULONG_PTR)PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                ImportTableAddress = (ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, ImportTableAddress + ImageBase, true);
                ImportPointer = (PIMAGE_IMPORT_DESCRIPTOR)ImportTableAddress;
                while(ImportPointer->FirstThunk != NULL)
                {
                    ImportDllName = (PCHAR)((ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, ImportPointer->Name + ImageBase, true));
                    MultiByteToWideChar(CP_ACP, NULL, ImportDllName, lstrlenA(ImportDllName)+1, ImportDllNameW, sizeof(ImportDllNameW)/(sizeof(ImportDllNameW[0])));
                    if(!EngineIsDependencyPresentW(ImportDllNameW, szFileName, szOutputFolder))
                    {
                        RtlZeroMemory(&BuildExportName, 512);
                        lstrcatW(BuildExportName, szOutputFolder);
                        if(BuildExportName[lstrlenW(BuildExportName)-1] != 0x5C)
                        {
                            BuildExportName[lstrlenW(BuildExportName)] = 0x5C;
                        }
                        lstrcatW(BuildExportName, ImportDllNameW);
                        if(LogCreatedFiles)
                        {
                            RtlMoveMemory(engineDependencyFilesCWP, &BuildExportName, lstrlenW(BuildExportName) * 2);
                            engineDependencyFilesCWP = (LPVOID)((ULONG_PTR)engineDependencyFilesCWP + (lstrlenW(BuildExportName) * 2) + 2);
                        }
                        EngineExtractResource("MODULEx64", BuildExportName);
                        ExporterInit(20 * 1024, (ULONG_PTR)GetPE32DataW(BuildExportName, NULL, UE_IMAGEBASE), NULL, ImportDllName);
                        ImportThunkAddress = ImportPointer->FirstThunk;
                        if(ImportPointer->OriginalFirstThunk != NULL)
                        {
                            ImportThunkX64 = (PIMAGE_THUNK_DATA64)((ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, ImportPointer->OriginalFirstThunk + ImageBase, true));
                        }
                        else
                        {
                            ImportThunkX64 = (PIMAGE_THUNK_DATA64)((ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, ImportPointer->FirstThunk + ImageBase, true));
                        }
                        while(ImportThunkX64->u1.Function != NULL)
                        {
                            if(ImportThunkX64->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                            {
                                ExporterAddNewOrdinalExport((DWORD)(ImportThunkX64->u1.Ordinal ^ IMAGE_ORDINAL_FLAG64), 0x1000);
                            }
                            else
                            {
                                ImportThunkName = (ULONG_PTR)(ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)(ImportThunkX64->u1.AddressOfData + ImageBase), true) + 2);
                                ExporterAddNewExport((PCHAR)ImportThunkName, 0x1000);
                            }
                            ImportThunkX64 = (PIMAGE_THUNK_DATA64)((ULONG_PTR)ImportThunkX64 + 8);
                            ImportThunkAddress = ImportThunkAddress + 8;
                        }
                        ExporterBuildExportTableExW(BuildExportName, ".export");
                    }
                    ImportPointer = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)ImportPointer + sizeof IMAGE_IMPORT_DESCRIPTOR);
                }
            }
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            return(true);
        }
        else
        {
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            return(false);
        }
    }
    return(false);
}
__declspec(dllexport) bool TITCALL EngineFakeMissingDependencies(HANDLE hProcess)
{

    if(hProcess != NULL)
    {
        SetAPIBreakPoint("ntdll.dll", "LdrLoadDll", UE_BREAKPOINT, UE_APIEND, (LPVOID)&EngineFakeLoadLibraryReturn);
        SetAPIBreakPoint("ntdll.dll", "LdrGetProcedureAddress", UE_BREAKPOINT, UE_APIEND, (LPVOID)&EngineFakeGetProcAddressReturn);
    }
    return(false);
}
__declspec(dllexport) bool TITCALL EngineDeleteCreatedDependencies()
{

    wchar_t szTempName[MAX_PATH];
    wchar_t szTempFolder[MAX_PATH];

    if(engineDependencyFiles != NULL)
    {
        engineDependencyFilesCWP = engineDependencyFiles;
        while(*((char*)engineDependencyFilesCWP) != 0)
        {
            RtlZeroMemory(&szTempName, sizeof szTempName);
            RtlZeroMemory(&szTempFolder, sizeof szTempFolder);
            if(GetTempPathW(MAX_PATH, szTempFolder) < MAX_PATH)
            {
                if(GetTempFileNameW(szTempFolder, L"DeleteTempGenFile", GetTickCount(), szTempName))
                {
                    DeleteFileW(szTempName);
                    if(!MoveFileW((LPCWSTR)engineDependencyFilesCWP, szTempName))
                    {
                        DeleteFileW((LPCWSTR)engineDependencyFilesCWP);
                    }
                    else
                    {
                        DeleteFileW(szTempName);
                    }
                }
            }
            engineDependencyFilesCWP = (LPVOID)((ULONG_PTR)engineDependencyFilesCWP + (lstrlenW((PWCHAR)engineDependencyFilesCWP) * 2) + 2);
        }
        VirtualFree(engineDependencyFiles, NULL, MEM_RELEASE);
        engineDependencyFiles = NULL;
        engineDependencyFilesCWP = NULL;
        return(true);
    }
    return(false);
}

__declspec(dllexport) bool TITCALL EngineCreateUnpackerWindow(char* WindowUnpackerTitle, char* WindowUnpackerLongTitle, char* WindowUnpackerName, char* WindowUnpackerAuthor, void* StartUnpackingCallBack)
{
    if(!WindowUnpackerTitle || !WindowUnpackerLongTitle || !WindowUnpackerName || !WindowUnpackerAuthor || !StartUnpackingCallBack)
        return false;
    EngineStartUnpackingCallBack = StartUnpackingCallBack;
    lstrcpyA(szWindowUnpackerTitle, WindowUnpackerTitle);
    lstrcpyA(szWindowUnpackerLongTitle, WindowUnpackerLongTitle);
    lstrcpyA(szWindowUnpackerAuthor, WindowUnpackerAuthor);
    lstrcpyA(szWindowUnpackerName, WindowUnpackerName);
    if(DialogBoxParamA((HINSTANCE)engineHandle, MAKEINTRESOURCEA(IDD_MAINWINDOW), NULL, (DLGPROC)EngineWndProc, NULL) != -1)
    {
        return(true);
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) void TITCALL EngineAddUnpackerWindowLogMessage(char* szLogMessage)
{

    int cSelect;

    SendMessageA(EngineBoxHandle, LB_ADDSTRING, NULL, (LPARAM)szLogMessage);
    cSelect = (int)SendMessageA(EngineBoxHandle, LB_GETCOUNT, NULL, NULL);
    cSelect--;
    SendMessageA(EngineBoxHandle, LB_SETCURSEL, (WPARAM)cSelect, NULL);
}

// Global.Garbage.functions:
bool CreateGarbageItem(void* outGargabeItem, int MaxGargabeStringSize)
{

    bool Created = false;
    wchar_t szGarbageItem[512];
    wchar_t szGargabeItemBuff[128];

    while(!Created)
    {
        RtlZeroMemory(&szGarbageItem, sizeof szGarbageItem);
        RtlZeroMemory(&szGargabeItemBuff, sizeof szGargabeItemBuff);
        srand((unsigned int)time(NULL));
        wsprintfW(szGargabeItemBuff, L"Junk-%08x\\", (rand() % 128 + 1) * (rand() % 128 + 1) + (rand() % 1024 + 1));
        lstrcpyW(szGarbageItem, engineSzEngineGarbageFolder);
        lstrcatW(szGarbageItem, szGargabeItemBuff);
        if(EngineCreatePathForFileW(szGarbageItem))
        {
            Created = true;
        }
    }
    if(lstrlenW(szGarbageItem) * 2 >= MaxGargabeStringSize)
    {
        RtlMoveMemory(outGargabeItem, &szGarbageItem, MaxGargabeStringSize);
        return(false);
    }
    else
    {
        RtlMoveMemory(outGargabeItem, &szGarbageItem, lstrlenW(szGarbageItem) * 2);
        return(true);
    }
}
bool RemoveGarbageItem(wchar_t* szGarbageItem, bool RemoveFolder)
{

    wchar_t szFindSearchString[MAX_PATH];
    wchar_t szFoundFile[MAX_PATH];
    WIN32_FIND_DATAW FindData;
    bool QueryNextFile = true;
    HANDLE CurrentFile;

    if(szGarbageItem != NULL)
    {
        lstrcpyW(szFindSearchString, szGarbageItem);
        if(szFindSearchString[0] != NULL)
        {
            lstrcatW(szFindSearchString, L"\\*.*");
            CurrentFile = FindFirstFileW(szFindSearchString, &FindData);
            while(QueryNextFile == true && CurrentFile != INVALID_HANDLE_VALUE)
            {
                RtlZeroMemory(&szFoundFile, sizeof szFoundFile);
                lstrcpyW(szFoundFile, szGarbageItem);
                lstrcatW(szFoundFile, FindData.cFileName);
                if(FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                {
                    if(FindData.cFileName[0] != 0x2E)
                    {
                        lstrcatW(szFoundFile, L"\\");
                        RemoveGarbageItem(szFoundFile, true);
                    }
                }
                else
                {
                    if(!DeleteFileW(szFoundFile))
                    {
                        if(HandlerCloseAllLockHandlesW(szFoundFile, false, true))
                        {
                            DeleteFileW(szFoundFile);
                        }
                    }
                }
                if(!FindNextFileW(CurrentFile, &FindData))
                {
                    QueryNextFile = false;
                }
            }
            FindClose(CurrentFile);
            if(RemoveFolder)
            {
                if(lstrlenW(engineSzEngineGarbageFolder) < lstrlenW(szGarbageItem))
                {
                    if(!RemoveDirectoryW(szGarbageItem))
                    {
                        if(HandlerCloseAllLockHandlesW(szGarbageItem, true, true))
                        {
                            RemoveDirectoryW(szGarbageItem);
                        }
                    }
                }
            }
            return(true);
        }
        else
        {
            return(false);
        }
    }
    else
    {
        return(false);
    }
}
bool FillGarbageItem(wchar_t* szGarbageItem, wchar_t* szFileName, void* outGargabeItem, int MaxGargabeStringSize)
{
    if(!szGarbageItem || !szFileName || !outGargabeItem)
        return false;
    wchar_t szCopyFileName[512];
    wchar_t szGargabeItemBuff[128];

    lstrcpyW(szCopyFileName, szGarbageItem);
    if(szFileName != NULL)
    {
        lstrcatW(szCopyFileName, EngineExtractFileNameW(szFileName));
    }
    else
    {
        srand((unsigned int)time(NULL));
        wsprintfW(szGargabeItemBuff, L"Junk-Data-%08x.bin", (rand() % 128 + 1) * (rand() % 128 + 1) + (rand() % 1024 + 1));
        lstrcatW(szCopyFileName, szGargabeItemBuff);
    }
    if(lstrlenW(szCopyFileName) >= MaxGargabeStringSize)
    {
        RtlMoveMemory(outGargabeItem, &szCopyFileName, MaxGargabeStringSize);
        if(szFileName != NULL)
        {
            CopyFileW(szFileName, szCopyFileName, false);
        }
    }
    else
    {
        RtlMoveMemory(outGargabeItem, &szCopyFileName, lstrlenW(szCopyFileName) * 2);
        if(szFileName != NULL)
        {
            CopyFileW(szFileName, szCopyFileName, false);
        }
    }
    return(true);
}
void EmptyGarbage()
{
    RemoveGarbageItem(engineSzEngineGarbageFolder, false);
}

// Global.Engine.Entry:
bool APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{

    int i;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        engineHandle = hModule;
        if(sizeof HANDLE != 4)
        {
            engineCurrentPlatform = UE_PLATFORM_x64;
        }
        EngineInit();
        EmptyGarbage();
        for(i = 0; i < UE_MAX_RESERVED_MEMORY_LEFT; i++)
        {
            engineReservedMemoryLeft[i] = NULL;
        }
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        if(lpReserved != NULL)
        {
            ExtensionManagerPluginReleaseCallBack();
        }
        break;
    }
    return TRUE;
}
