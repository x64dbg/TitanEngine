#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.Simplification.h"
#include "Global.Garbage.h"

// TitanEngine.Engine.Simplification.functions:
__declspec(dllexport) void TITCALL EngineUnpackerInitialize(char* szFileName, char* szUnpackedFileName, bool DoLogData, bool DoRealignFile, bool DoMoveOverlay, void* EntryCallBack)
{
    wchar_t uniFileName[MAX_PATH] = {};
    wchar_t uniUnpackedFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        if(szUnpackedFileName == NULL)
        {
            return EngineUnpackerInitializeW(uniFileName, NULL, DoLogData, DoRealignFile, DoMoveOverlay, EntryCallBack);
        }
        else
        {
            MultiByteToWideChar(CP_ACP, NULL, szUnpackedFileName, lstrlenA(szUnpackedFileName) + 1, uniUnpackedFileName, sizeof(uniUnpackedFileName) / (sizeof(uniUnpackedFileName[0])));
            EngineUnpackerInitializeW(uniFileName, uniUnpackedFileName, DoLogData, DoRealignFile, DoMoveOverlay, EntryCallBack);
        }
    }
}

__declspec(dllexport) void TITCALL EngineUnpackerInitializeW(wchar_t* szFileName, wchar_t* szUnpackedFileName, bool DoLogData, bool DoRealignFile, bool DoMoveOverlay, void* EntryCallBack)
{
    int i, j;
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
                return true;
            }
        }
        else if(BreakType == UE_UNPACKER_CONDITION_GETPROCADDRESS)
        {
            if(SetBPX(fPatternLocation, UE_BREAKPOINT, &EngineSimplifyGetProcAddressCallBack))
            {
                EngineUnpackerBreakInfo.push_back(fUnpackerInformation);
                return true;
            }
        }
        else if(BreakType == UE_UNPACKER_CONDITION_ENTRYPOINTBREAK)
        {
            if(SetBPX(fPatternLocation, UE_BREAKPOINT, &EngineSimplifyGetProcAddressCallBack))
            {
                EngineUnpackerBreakInfo.push_back(fUnpackerInformation);
                return true;
            }
        }
        else if(BreakType == UE_UNPACKER_CONDITION_RELOCSNAPSHOT1)
        {
            if(SetBPX(fPatternLocation, UE_BREAKPOINT, &EngineSimplifyMakeSnapshotCallBack))
            {
                fUnpackerInformation.SnapShotNumber = 1;
                EngineUnpackerBreakInfo.push_back(fUnpackerInformation);
                return true;
            }
        }
        else if(BreakType == UE_UNPACKER_CONDITION_RELOCSNAPSHOT2)
        {
            if(SetBPX(fPatternLocation, UE_BREAKPOINT, &EngineSimplifyMakeSnapshotCallBack))
            {
                fUnpackerInformation.SnapShotNumber = 2;
                EngineUnpackerBreakInfo.push_back(fUnpackerInformation);
                return true;
            }
        }
        else
        {
            if(SetBPX(fPatternLocation, fBreakPointType, (void*)BreakType))
            {
                EngineUnpackerBreakInfo.push_back(fUnpackerInformation);
                return true;
            }
        }
    }

    return false;
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
