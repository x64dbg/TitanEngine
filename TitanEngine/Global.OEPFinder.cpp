#include "stdafx.h"
#include "definitions.h"
#include "Global.OEPFinder.h"
#include "Global.Engine.h"
#include "Global.Breakpoints.h"
#include "Global.Debugger.h"
#include "Global.Mapping.h"
#include "Global.Handle.h"

GenericOEPTracerData glbEntryTracerData = {};

// Global.FindOEP.functions:
void GenericOEPVirtualProtectHit()
{
    MEMORY_BASIC_INFORMATION MemInfo;
    DWORD MaximumBreakPoints = 0;
    DWORD NewProtect = 0;
    DWORD OldProtect = 0;

    int bpcount = (int)BreakPointBuffer.size();
    for(int i = 0; i < bpcount; i++)
    {
        BreakPointDetail curDetail = BreakPointBuffer.at(i);
        if(curDetail.BreakPointType == UE_MEMORY && curDetail.BreakPointActive == UE_BPXACTIVE)
        {
            VirtualQueryEx(dbgProcessInformation.hProcess, (LPVOID)curDetail.BreakPointAddress, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
            OldProtect = MemInfo.Protect;
            if(!(OldProtect & PAGE_GUARD))
            {
                NewProtect = OldProtect ^ PAGE_GUARD;
                VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)curDetail.BreakPointAddress, curDetail.BreakPointSize, NewProtect, &OldProtect);
            }
        }
        MaximumBreakPoints++;
    }
}

void GenericOEPTraceHit()
{

    char* szInstructionType;
    typedef void(TITCALL * fEPCallBack)();
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
    //void* lpHashBuffer;
    char lpHashBuffer[0x1000] = {0};
    bool FakeEPDetected = false;
    ULONG_PTR NumberOfBytesRW;
    LPDEBUG_EVENT myDbgEvent = (LPDEBUG_EVENT)GetDebugData();
    typedef void(TITCALL * fEPCallBack)();
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
                        memBpxAddress = (glbEntryTracerData.MemoryAccessed / sizeof(lpHashBuffer)) * sizeof(lpHashBuffer);
                        memBpxSize = glbEntryTracerData.SectionData[i].SectionVirtualOffset + glbEntryTracerData.SectionData[i].SectionVirtualSize + glbEntryTracerData.LoadedImageBase - memBpxAddress;
                        if(memBpxSize > sizeof(lpHashBuffer))
                        {
                            memBpxSize = sizeof(lpHashBuffer);
                        }
                        if(ReadProcessMemory(dbgProcessInformation.hProcess, (void*)(memBpxAddress), lpHashBuffer, memBpxSize, &NumberOfBytesRW))
                        {
                            currentHash = EngineHashMemory((char*)lpHashBuffer, (DWORD)memBpxSize, NULL);
                            originalHash = EngineHashMemory((char*)((ULONG_PTR)glbEntryTracerData.SectionData[i].AllocatedSection + memBpxAddress - glbEntryTracerData.LoadedImageBase - glbEntryTracerData.SectionData[i].SectionVirtualOffset), (DWORD)memBpxSize, NULL);
                            if(ReadProcessMemory(dbgProcessInformation.hProcess, (void*)(glbEntryTracerData.CurrentIntructionPointer), lpHashBuffer, MAXIMUM_INSTRUCTION_SIZE, &NumberOfBytesRW))
                            {
                                myCmpHandler = (PMEMORY_COMPARE_HANDLER)(lpHashBuffer);
                                if(myCmpHandler->Array.bArrayEntry[0] == 0xC3)      // RET
                                {
                                    FakeEPDetected = true;
                                }
                                else if(myCmpHandler->Array.bArrayEntry[0] == 0x33 && myCmpHandler->Array.bArrayEntry[1] == 0xC0 && myCmpHandler->Array.bArrayEntry[2] == 0xC3)     // XOR EAX,EAX; RET
                                {
                                    FakeEPDetected = true;
                                }
                            }
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
    typedef void(TITCALL * fInitCallBack)();
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
                if(glbEntryTracerData.SectionData[i].SectionVirtualSize % 0x1000 != 0) //SectionAlignment, the default value is the page size for the system.
                {
                    glbEntryTracerData.SectionData[i].SectionVirtualSize = ((glbEntryTracerData.SectionData[i].SectionVirtualSize / 0x1000) + 1) * 0x1000;
                }
                glbEntryTracerData.SectionData[i].SectionAttributes = (DWORD)GetPE32DataFromMappedFile(FileMapVA, i, UE_SECTIONFLAGS);
            }
            glbEntryTracerData.EPCallBack = CallBack;
            glbEntryTracerData.InitCallBack = TraceInitCallBack;
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            if(glbEntryTracerData.FileIsDLL)
            {
                return false;
            }
            else
            {
                return true;
            }
        }
        else
        {
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
        }
    }
    return false;
}
