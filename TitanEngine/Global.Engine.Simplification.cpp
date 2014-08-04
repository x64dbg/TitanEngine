#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.Simplification.h"
#include "Global.Debugger.h"

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
                    wsprintfA(szLogBufferData, "[x] LoadLibrary BPX -> %s", szReadStringData);
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
                            wsprintfA(szLogBufferData, "[x] GetProcAddress BPX -> %s", szReadStringData);
                            EngineAddUnpackerWindowLogMessage(szLogBufferData);
                        }
                    }
                }
                else
                {
                    ImporterAddNewOrdinalAPI(iParameter1, (ULONG_PTR)GetContextData((DWORD)EngineUnpackerBreakInfo[i].Parameter2));
                    if(EngineUnpackerOptionLogData)
                    {
                        wsprintfA(szLogBufferData, "[x] GetProcAddress BPX -> %08X", iParameter1);
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
                            wsprintfA(szLogBufferData, "[x] GetProcAddress BPX -> %s", szReadStringData);
                            EngineAddUnpackerWindowLogMessage(szLogBufferData);
                        }
                    }
                }
                else
                {
                    ImporterAddNewOrdinalAPI(iParameter1, (ULONG_PTR)GetContextData((DWORD)EngineUnpackerBreakInfo[i].Parameter2));
                    if(EngineUnpackerOptionLogData)
                    {
                        wsprintfA(szLogBufferData, "[x] GetProcAddress BPX -> %08X", iParameter1);
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
            wsprintfA(szLogBufferData, "[x] Entry Point at: %08X", EngineUnpackerOptionUnpackedOEP);
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