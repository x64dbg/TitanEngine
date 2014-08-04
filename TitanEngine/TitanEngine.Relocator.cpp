#include "stdafx.h"
#include "definitions.h"
#include "Global.Mapping.h"
#include "Global.Engine.h"
#include "Global.Garbage.h"

static LPVOID RelocationData = NULL;
LPVOID RelocationLastPage = NULL;
LPVOID RelocationStartPosition = NULL;
LPVOID RelocationWritePosition = NULL;
ULONG_PTR RelocationOldImageBase;
ULONG_PTR RelocationNewImageBase;

// TitanEngine.Relocater.functions:
__declspec(dllexport) void TITCALL RelocaterCleanup()
{

    if(RelocationData != NULL)
    {
        VirtualFree(RelocationData, NULL, MEM_RELEASE);
        RelocationLastPage = NULL;
        RelocationStartPosition = NULL;
        RelocationWritePosition = NULL;
        RelocationOldImageBase = NULL;
        RelocationNewImageBase = NULL;
    }
}

__declspec(dllexport) void TITCALL RelocaterInit(DWORD MemorySize, ULONG_PTR OldImageBase, ULONG_PTR NewImageBase)
{

    if(RelocationData != NULL)
    {
        VirtualFree(RelocationData, NULL, MEM_RELEASE);
    }
    RelocationData = VirtualAlloc(NULL, MemorySize, MEM_COMMIT, PAGE_READWRITE);
    RelocationLastPage = NULL;
    RelocationStartPosition = RelocationData;
    RelocationWritePosition = (LPVOID)((ULONG_PTR)RelocationData + 8);
    RelocationOldImageBase = OldImageBase;
    RelocationNewImageBase = NewImageBase;
}

__declspec(dllexport) void TITCALL RelocaterAddNewRelocation(HANDLE hProcess, ULONG_PTR RelocateAddress, DWORD RelocateState)
{

    MEMORY_BASIC_INFORMATION MemInfo;
    DWORD CompareDummy = NULL;
    DWORD CopyDummy = NULL;

    VirtualQueryEx(hProcess, (LPVOID)RelocateAddress, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
    if(MemInfo.BaseAddress != RelocationLastPage || RelocationLastPage == NULL)
    {
        RelocationLastPage = MemInfo.BaseAddress;
        if(memcmp(RelocationStartPosition, &CompareDummy, 4) == NULL)
        {
            CopyDummy = (DWORD)((ULONG_PTR)MemInfo.BaseAddress - (ULONG_PTR)RelocationNewImageBase);
            RtlMoveMemory(RelocationStartPosition, &CopyDummy, 4);
        }
        else
        {
            CopyDummy = (DWORD)((ULONG_PTR)RelocationWritePosition - (ULONG_PTR)RelocationStartPosition);
            if(CopyDummy % 4 == NULL)
            {
                RtlMoveMemory((LPVOID)((ULONG_PTR)RelocationStartPosition + 4), &CopyDummy, 4);
            }
            else
            {
                RelocationWritePosition = (LPVOID)((ULONG_PTR)RelocationWritePosition + 2);
                CopyDummy = (DWORD)((ULONG_PTR)RelocationWritePosition - (ULONG_PTR)RelocationStartPosition);
                if(CopyDummy % 4 == NULL)
                {
                    RtlMoveMemory((LPVOID)((ULONG_PTR)RelocationStartPosition + 4), &CopyDummy, 4);
                }
                else
                {
                    RelocationWritePosition = (LPVOID)((ULONG_PTR)RelocationWritePosition + 2);
                    CopyDummy = (DWORD)((ULONG_PTR)RelocationWritePosition - (ULONG_PTR)RelocationStartPosition);
                    RtlMoveMemory((LPVOID)((ULONG_PTR)RelocationStartPosition + 4), &CopyDummy, 4);
                }
            }
            RelocationStartPosition = RelocationWritePosition;
            CopyDummy = (DWORD)((ULONG_PTR)RelocationLastPage - (ULONG_PTR)RelocationNewImageBase);
            RtlMoveMemory(RelocationWritePosition, &CopyDummy, 4);
            RelocationWritePosition = (LPVOID)((ULONG_PTR)RelocationWritePosition + 8);
        }
    }
#if !defined(_WIN64)
    CopyDummy = (DWORD)((RelocateAddress - (ULONG_PTR)RelocationLastPage) ^ 0x3000);
#else
    CopyDummy = (DWORD)((RelocateAddress - (ULONG_PTR)RelocationLastPage) ^ 0x8000);
#endif
    RtlMoveMemory(RelocationWritePosition, &CopyDummy, 2);
    RelocationWritePosition = (LPVOID)((ULONG_PTR)RelocationWritePosition + 2);
}

__declspec(dllexport) long TITCALL RelocaterEstimatedSize()
{
    return((DWORD)((ULONG_PTR)RelocationWritePosition - (ULONG_PTR)RelocationData + 8));
}

__declspec(dllexport) bool TITCALL RelocaterExportRelocation(ULONG_PTR StorePlace, DWORD StorePlaceRVA, ULONG_PTR FileMapVA)
{

    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    BOOL FileIs64 = false;
    DWORD CopyDummy = NULL;

    __try
    {
        if((ULONG_PTR)RelocationStartPosition != -1)
        {
            CopyDummy = (DWORD)((ULONG_PTR)RelocationWritePosition - (ULONG_PTR)RelocationStartPosition);
            if(CopyDummy % 4 == NULL)
            {
                RtlMoveMemory((LPVOID)((ULONG_PTR)RelocationStartPosition + 4), &CopyDummy, 4);
            }
            else
            {
                RelocationWritePosition = (LPVOID)((ULONG_PTR)RelocationWritePosition + 2);
                CopyDummy = (DWORD)((ULONG_PTR)RelocationWritePosition - (ULONG_PTR)RelocationStartPosition);
                if(CopyDummy % 4 == NULL)
                {
                    RtlMoveMemory((LPVOID)((ULONG_PTR)RelocationStartPosition + 4), &CopyDummy, 4);
                }
                else
                {
                    RelocationWritePosition = (LPVOID)((ULONG_PTR)RelocationWritePosition + 2);
                    CopyDummy = (DWORD)((ULONG_PTR)RelocationWritePosition - (ULONG_PTR)RelocationStartPosition);
                    RtlMoveMemory((LPVOID)((ULONG_PTR)RelocationStartPosition + 4), &CopyDummy, 4);
                }
            }
        }
        RtlMoveMemory((LPVOID)StorePlace, RelocationData, (DWORD)((ULONG_PTR)RelocationWritePosition - (ULONG_PTR)RelocationData));
        VirtualFree(RelocationData, NULL, MEM_RELEASE);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }

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
            RelocationData = NULL;
            return false;
        }
        if(!FileIs64)
        {
            PEHeader32->OptionalHeader.ImageBase = (DWORD)RelocationNewImageBase;
            PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = StorePlaceRVA;
            PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = (DWORD)((ULONG_PTR)RelocationWritePosition - (ULONG_PTR)RelocationData);
        }
        else
        {
            PEHeader64->OptionalHeader.ImageBase = (ULONG_PTR)RelocationNewImageBase;
            PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = StorePlaceRVA;
            PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = (DWORD)((ULONG_PTR)RelocationWritePosition - (ULONG_PTR)RelocationData);
        }
        RelocationData = NULL;
        return true;
    }
    RelocationData = NULL;
    return false;
}

__declspec(dllexport) bool TITCALL RelocaterExportRelocationEx(char* szFileName, char* szSectionName)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        return(RelocaterExportRelocationExW(uniFileName, szSectionName));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL RelocaterExportRelocationExW(wchar_t* szFileName, char* szSectionName)
{

    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    DWORD NewSectionVO = NULL;
    DWORD NewSectionFO = NULL;
    bool ReturnValue = false;

    if(RelocaterEstimatedSize() > NULL)
    {
        NewSectionVO = AddNewSectionW(szFileName, szSectionName, RelocaterEstimatedSize());
        if(MapFileExW(szFileName, UE_ACCESS_ALL, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
        {
            NewSectionFO = (DWORD)ConvertVAtoFileOffset(FileMapVA, NewSectionVO + (ULONG_PTR)GetPE32DataFromMappedFile(FileMapVA, NULL, UE_IMAGEBASE), true);
            if(NewSectionFO)
                ReturnValue = RelocaterExportRelocation(NewSectionFO, NewSectionVO, FileMapVA);
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            if(ReturnValue)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        else
        {
            return false;
        }
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL RelocaterGrabRelocationTable(HANDLE hProcess, ULONG_PTR MemoryStart, DWORD MemorySize)
{

    MEMORY_BASIC_INFORMATION MemInfo;
    ULONG_PTR ueNumberOfBytesRead = NULL;
    DWORD OldProtect;

    if(RelocationData != NULL)
    {
        VirtualQueryEx(hProcess, (LPVOID)MemoryStart, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
        OldProtect = MemInfo.Protect;
        VirtualProtectEx(hProcess, (LPVOID)MemoryStart, MemorySize, PAGE_EXECUTE_READWRITE, &OldProtect);
        if(ReadProcessMemory(hProcess, (LPVOID)MemoryStart, RelocationData, MemorySize, &ueNumberOfBytesRead))
        {
            RelocationWritePosition = (LPVOID)((ULONG_PTR)RelocationData + MemorySize);
            RelocationStartPosition = (LPVOID)(-1);
            return true;
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL RelocaterGrabRelocationTableEx(HANDLE hProcess, ULONG_PTR MemoryStart, ULONG_PTR MemorySize, DWORD NtSizeOfImage)
{

    MEMORY_BASIC_INFORMATION MemInfo;
    LPVOID ReadMemoryStorage = NULL;
    LPVOID mReadMemoryStorage = NULL;
    ULONG_PTR ueNumberOfBytesRead = NULL;
    DWORD CompareDummy = NULL;
    DWORD RelocationBase = NULL;
    DWORD RelocationSize = NULL;
    DWORD OldProtect;
    DynBuf mem;

    if(RelocationData != NULL)
    {
        VirtualQueryEx(hProcess, (LPVOID)MemoryStart, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
        OldProtect = MemInfo.Protect;
        VirtualQueryEx(hProcess, (LPVOID)MemInfo.BaseAddress, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
        if(MemInfo.RegionSize < MemorySize || MemorySize == NULL)
        {
            MemorySize = MemInfo.RegionSize;
        }
        VirtualProtectEx(hProcess, (LPVOID)MemoryStart, MemorySize, PAGE_EXECUTE_READWRITE, &OldProtect);
        ReadMemoryStorage = mem.Allocate(MemorySize);
        mReadMemoryStorage = ReadMemoryStorage;
        if(ReadProcessMemory(hProcess, (LPVOID)MemoryStart, ReadMemoryStorage, MemorySize, &ueNumberOfBytesRead))
        {
            RtlMoveMemory(&RelocationBase, ReadMemoryStorage, 4);
            RtlMoveMemory(&RelocationSize, (LPVOID)((ULONG_PTR)ReadMemoryStorage + 4), 4);
            while(memcmp(ReadMemoryStorage, &CompareDummy, 4) != NULL && RelocationBase < NtSizeOfImage && RelocationSize < 0x2000)
            {
                ReadMemoryStorage = (LPVOID)((ULONG_PTR)ReadMemoryStorage + RelocationSize);
                RtlMoveMemory(&RelocationBase, ReadMemoryStorage, 4);
                RtlMoveMemory(&RelocationSize, (LPVOID)((ULONG_PTR)ReadMemoryStorage + 4), 4);
            }
            return(RelocaterGrabRelocationTable(hProcess, MemoryStart, (DWORD)((ULONG_PTR)ReadMemoryStorage - (ULONG_PTR)mReadMemoryStorage)));
        }
        else
        {
            return false;
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL RelocaterMakeSnapshot(HANDLE hProcess, char* szSaveFileName, LPVOID MemoryStart, ULONG_PTR MemorySize)
{
    return(DumpMemory(hProcess, MemoryStart, MemorySize, szSaveFileName));
}

__declspec(dllexport) bool TITCALL RelocaterMakeSnapshotW(HANDLE hProcess, wchar_t* szSaveFileName, LPVOID MemoryStart, ULONG_PTR MemorySize)
{
    return(DumpMemoryW(hProcess, MemoryStart, MemorySize, szSaveFileName));
}

__declspec(dllexport) bool TITCALL RelocaterCompareTwoSnapshots(HANDLE hProcess, ULONG_PTR LoadedImageBase, ULONG_PTR NtSizeOfImage, char* szDumpFile1, char* szDumpFile2, ULONG_PTR MemStart)
{

    wchar_t uniDumpFile1[MAX_PATH] = {};
    wchar_t uniDumpFile2[MAX_PATH] = {};

    if(szDumpFile1 != NULL && szDumpFile2 != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szDumpFile1, lstrlenA(szDumpFile1) + 1, uniDumpFile1, sizeof(uniDumpFile1) / (sizeof(uniDumpFile1[0])));
        MultiByteToWideChar(CP_ACP, NULL, szDumpFile2, lstrlenA(szDumpFile2) + 1, uniDumpFile2, sizeof(uniDumpFile2) / (sizeof(uniDumpFile2[0])));
        return(RelocaterCompareTwoSnapshotsW(hProcess, LoadedImageBase, NtSizeOfImage, uniDumpFile1, uniDumpFile2, MemStart));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL RelocaterCompareTwoSnapshotsW(HANDLE hProcess, ULONG_PTR LoadedImageBase, ULONG_PTR NtSizeOfImage, wchar_t* szDumpFile1, wchar_t* szDumpFile2, ULONG_PTR MemStart)
{

    int i = NULL;
    ULONG_PTR DeltaByte = NULL;
    int RelativeBase = NULL;
    ULONG_PTR ReadData = NULL;
    HANDLE FileHandle1;
    DWORD FileSize1;
    HANDLE FileMap1;
    ULONG_PTR FileMapVA1;
    HANDLE FileHandle2;
    DWORD FileSize2;
    HANDLE FileMap2;
    ULONG_PTR FileMapVA2;
    DWORD SearchSize;
    LPVOID Search1;
    LPVOID Search2;
    DWORD bkSearchSize;
    LPVOID bkSearch1;
    LPVOID bkSearch2;

    if(MapFileExW(szDumpFile1, UE_ACCESS_READ, &FileHandle1, &FileSize1, &FileMap1, &FileMapVA1, NULL))
    {
        if(MapFileExW(szDumpFile2, UE_ACCESS_READ, &FileHandle2, &FileSize2, &FileMap2, &FileMapVA2, NULL))
        {
            if(RelocationOldImageBase != NULL && RelocationNewImageBase != NULL && RelocationOldImageBase != RelocationNewImageBase)
            {
                __try
                {
                    if(RelocationOldImageBase > RelocationNewImageBase)
                    {
                        DeltaByte = (ULONG_PTR)((ULONG_PTR)RelocationOldImageBase - (ULONG_PTR)RelocationNewImageBase);
                    }
                    else
                    {
                        DeltaByte = (ULONG_PTR)((ULONG_PTR)RelocationNewImageBase - (ULONG_PTR)RelocationOldImageBase);
                    }
                    while((BYTE)DeltaByte == NULL)
                    {
                        DeltaByte = DeltaByte / 0x10;
                        i++;
                    }
                    DeltaByte = i - 1;
                    Search1 = (LPVOID)FileMapVA1;
                    Search2 = (LPVOID)FileMapVA2;
                    NtSizeOfImage = NtSizeOfImage + LoadedImageBase;
                    SearchSize = FileSize2;
                    SearchSize--;
                    while((int)SearchSize > NULL)
                    {
                        if(memcmp(Search1, Search2, 1) != 0)
                        {
                            i = sizeof HANDLE;
                            RelativeBase = NULL;
                            bkSearch1 = Search1;
                            bkSearch2 = Search2;
                            bkSearchSize = SearchSize;
                            if(Search1 >= (void*)((ULONG_PTR)FileMapVA1 + DeltaByte))
                            {
                                Search1 = (LPVOID)((ULONG_PTR)Search1 - DeltaByte);
                                Search2 = (LPVOID)((ULONG_PTR)Search2 - DeltaByte);
                                SearchSize = SearchSize + (DWORD)DeltaByte;
                            }
                            while(i > NULL && RelativeBase == NULL)
                            {
                                RtlMoveMemory(&ReadData, Search2, sizeof HANDLE);
                                if(ReadData >= LoadedImageBase && ReadData <= NtSizeOfImage)
                                {
                                    RelativeBase++;
                                }
                                else
                                {
                                    Search1 = (LPVOID)((ULONG_PTR)Search1 + 1);
                                    Search2 = (LPVOID)((ULONG_PTR)Search2 + 1);
                                    SearchSize = SearchSize - 1;
                                    i--;
                                }
                            }
                            if(RelativeBase == NULL)
                            {
                                Search1 = bkSearch1;
                                Search2 = bkSearch2;
                                SearchSize = bkSearchSize;
                            }
                            else
                            {
                                RelocaterAddNewRelocation(hProcess, MemStart + ((ULONG_PTR)Search2 - (ULONG_PTR)FileMapVA2), NULL);
                                Search1 = (LPVOID)((ULONG_PTR)Search1 + sizeof HANDLE - 1);
                                Search2 = (LPVOID)((ULONG_PTR)Search2 + sizeof HANDLE - 1);
                                SearchSize = SearchSize - sizeof HANDLE + 1;
                            }
                        }
                        Search1 = (LPVOID)((ULONG_PTR)Search1 + 1);
                        Search2 = (LPVOID)((ULONG_PTR)Search2 + 1);
                        SearchSize = SearchSize - 1;
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    RelocaterCleanup();
                    UnMapFileEx(FileHandle2, FileSize2, FileMap2, FileMapVA2);
                    UnMapFileEx(FileHandle1, FileSize1, FileMap1, FileMapVA1);
                    return false;
                }
            }
            UnMapFileEx(FileHandle2, FileSize2, FileMap2, FileMapVA2);
        }
        UnMapFileEx(FileHandle1, FileSize1, FileMap1, FileMapVA1);
        return true;
    }
    return false;
}

__declspec(dllexport) bool TITCALL RelocaterChangeFileBase(char* szFileName, ULONG_PTR NewImageBase)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        return(RelocaterChangeFileBaseW(uniFileName, NewImageBase));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL RelocaterChangeFileBaseW(wchar_t* szFileName, ULONG_PTR NewImageBase)
{

    DWORD RelocSize;
    ULONG_PTR RelocData;
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    BOOL FileIs64;
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    DWORD CompareDummy = NULL;
    DWORD RelocDelta = NULL;
    DWORD RelocDeltaSize = NULL;
    WORD RelocAddressData = NULL;
    ULONG_PTR RelocWriteAddress = NULL;
    ULONG_PTR RelocWriteData = NULL;
    DWORD64 RelocWriteData64 = NULL;
    wchar_t szBackupFile[MAX_PATH] = {};
    wchar_t szBackupItem[MAX_PATH] = {};

    if(engineBackupForCriticalFunctions && CreateGarbageItem(&szBackupItem, sizeof szBackupItem))
    {
        if(!FillGarbageItem(szBackupItem, szFileName, &szBackupFile, sizeof szBackupItem))
        {
            RtlZeroMemory(&szBackupItem, sizeof szBackupItem);
            lstrcpyW(szBackupFile, szFileName);
        }
    }
    else
    {
        RtlZeroMemory(&szBackupItem, sizeof szBackupItem);
        lstrcpyW(szBackupFile, szFileName);
    }
    if(MapFileExW(szBackupFile, UE_ACCESS_ALL, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
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
                RemoveGarbageItem(szBackupItem, true);
                return false;
            }
            if(!FileIs64)
            {
                if(PEHeader32->OptionalHeader.ImageBase == (DWORD)NewImageBase)
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    RemoveGarbageItem(szBackupItem, true);
                    return true;
                }
                RelocData = (ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + PEHeader32->OptionalHeader.ImageBase), true);
                RelocSize = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
            }
            else
            {
                if((ULONG_PTR)PEHeader64->OptionalHeader.ImageBase == NewImageBase)
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    RemoveGarbageItem(szBackupItem, true);
                    return true;
                }
                RelocData = (ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + PEHeader64->OptionalHeader.ImageBase), true);
                RelocSize = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
            }
            __try
            {
                while(memcmp((LPVOID)RelocData, &CompareDummy, 4))
                {
                    RtlMoveMemory(&RelocDelta, (LPVOID)RelocData, 4);
                    RtlMoveMemory(&RelocDeltaSize, (LPVOID)((ULONG_PTR)RelocData + 4), 4);
                    RelocDeltaSize = RelocDeltaSize - 8;
                    RelocData = RelocData + 8;
                    while(RelocDeltaSize > NULL)
                    {
                        RtlMoveMemory(&RelocAddressData, (LPVOID)RelocData, 2);
                        if(RelocAddressData != NULL)
                        {
                            if(RelocAddressData & 0x8000)
                            {
                                RelocAddressData = RelocAddressData ^ 0x8000;
                                RelocWriteAddress = (ULONG_PTR)(RelocAddressData + RelocDelta);
                                RelocWriteAddress = (ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((DWORD64)PEHeader64->OptionalHeader.ImageBase + RelocWriteAddress), true);
                                RtlMoveMemory(&RelocWriteData64, (LPVOID)RelocWriteAddress, 8);
                                RelocWriteData64 = RelocWriteData64 - (DWORD64)PEHeader64->OptionalHeader.ImageBase + (DWORD64)NewImageBase;
                                RtlMoveMemory((LPVOID)RelocWriteAddress, &RelocWriteData64, 8);
                            }
                            else if(RelocAddressData & 0x3000)
                            {
                                RelocAddressData = RelocAddressData ^ 0x3000;
                                RelocWriteAddress = (ULONG_PTR)(RelocAddressData + RelocDelta);
                                RelocWriteAddress = (ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, PEHeader32->OptionalHeader.ImageBase + RelocWriteAddress, true);
                                RtlMoveMemory(&RelocWriteData, (LPVOID)RelocWriteAddress, 4);
                                RelocWriteData = RelocWriteData - PEHeader32->OptionalHeader.ImageBase + NewImageBase;
                                RtlMoveMemory((LPVOID)RelocWriteAddress, &RelocWriteData, 4);
                            }
                        }
                        RelocDeltaSize = RelocDeltaSize - 2;
                        RelocData = RelocData + 2;
                    }
                }
                if(!FileIs64)
                {
                    PEHeader32->OptionalHeader.ImageBase = (DWORD)NewImageBase;
                }
                else
                {
                    PEHeader64->OptionalHeader.ImageBase = (ULONG_PTR)NewImageBase;
                }
                UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                if(szBackupItem[0] != NULL)
                {
                    if(CopyFileW(szBackupFile, szFileName, false))
                    {
                        RemoveGarbageItem(szBackupItem, true);
                        return true;
                    }
                    else
                    {
                        RemoveGarbageItem(szBackupItem, true);
                        return false;
                    }
                }
                else
                {
                    return true;
                }
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                RemoveGarbageItem(szBackupItem, true);
                return false;
            }
        }
        else
        {
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            RemoveGarbageItem(szBackupItem, true);
            return false;
        }
    }
    RemoveGarbageItem(szBackupItem, true);
    return false;
}

__declspec(dllexport) bool TITCALL RelocaterRelocateMemoryBlock(ULONG_PTR FileMapVA, ULONG_PTR MemoryLocation, void* RelocateMemory, DWORD RelocateMemorySize, ULONG_PTR CurrentLoadedBase, ULONG_PTR RelocateBase)
{

    BOOL FileIs64;
    DWORD RelocSize;
    ULONG_PTR RelocData;
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    DWORD CompareDummy = NULL;
    DWORD RelocDelta = NULL;
    DWORD RelocDeltaSize = NULL;
    WORD RelocAddressData = NULL;
    ULONG_PTR RelocWriteAddress = NULL;
    ULONG_PTR RelocWriteData = NULL;
    DWORD64 RelocWriteData64 = NULL;

    DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
    MemoryLocation = MemoryLocation - CurrentLoadedBase;
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
            if(PEHeader32->OptionalHeader.ImageBase == (DWORD)RelocateBase)
            {
                return true;
            }
            RelocData = (ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + PEHeader32->OptionalHeader.ImageBase), true);
            RelocSize = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        }
        else
        {
            if((ULONG_PTR)PEHeader64->OptionalHeader.ImageBase == RelocateBase)
            {
                return true;
            }
            RelocData = (ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + PEHeader64->OptionalHeader.ImageBase), true);
            RelocSize = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        }
        __try
        {
            while(memcmp((LPVOID)RelocData, &CompareDummy, 4))
            {
                RtlMoveMemory(&RelocDelta, (LPVOID)RelocData, 4);
                RtlMoveMemory(&RelocDeltaSize, (LPVOID)((ULONG_PTR)RelocData + 4), 4);
                RelocDeltaSize = RelocDeltaSize - 8;
                RelocData = RelocData + 8;
                while(RelocDeltaSize > NULL)
                {
                    RtlMoveMemory(&RelocAddressData, (LPVOID)RelocData, 2);
                    if(RelocAddressData != NULL)
                    {
                        if(RelocAddressData & 0x8000)
                        {
                            RelocAddressData = RelocAddressData ^ 0x8000;
                            if(RelocAddressData >= MemoryLocation && RelocAddressData < MemoryLocation + RelocateMemorySize)
                            {
                                RelocWriteAddress = (ULONG_PTR)(RelocAddressData + RelocDelta - MemoryLocation + (ULONG_PTR)RelocateMemory);
                                RtlMoveMemory(&RelocWriteData64, (LPVOID)RelocWriteAddress, 8);
                                RelocWriteData64 = RelocWriteData64 - (DWORD64)PEHeader64->OptionalHeader.ImageBase + (DWORD64)RelocateBase;
                                RtlMoveMemory((LPVOID)RelocWriteAddress, &RelocWriteData64, 8);
                            }
                        }
                        else if(RelocAddressData & 0x3000)
                        {
                            RelocAddressData = RelocAddressData ^ 0x3000;
                            if(RelocAddressData >= MemoryLocation && RelocAddressData < MemoryLocation + RelocateMemorySize)
                            {
                                RelocWriteAddress = (ULONG_PTR)(RelocAddressData + RelocDelta - MemoryLocation + (ULONG_PTR)RelocateMemory);
                                RtlMoveMemory(&RelocWriteData, (LPVOID)RelocWriteAddress, 4);
                                RelocWriteData = RelocWriteData - PEHeader32->OptionalHeader.ImageBase + RelocateBase;
                                RtlMoveMemory((LPVOID)RelocWriteAddress, &RelocWriteData, 4);
                            }
                        }
                    }
                    RelocDeltaSize = RelocDeltaSize - 2;
                    RelocData = RelocData + 2;
                }
            }
            return true;
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }
    else
    {
        return false;
    }
    return false;
}

__declspec(dllexport) bool TITCALL RelocaterWipeRelocationTable(char* szFileName)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        return(RelocaterWipeRelocationTableW(uniFileName));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL RelocaterWipeRelocationTableW(wchar_t* szFileName)
{

    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    DWORD WipeSectionNumber = NULL;
    ULONG_PTR Characteristics;
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
                return false;
            }
            if(!FileIs64)
            {
                if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != NULL)
                {
                    Characteristics = (ULONG_PTR)GetPE32DataFromMappedFile(FileMapVA, NULL, UE_CHARACTERISTICS) ^ 1;
                    SetPE32DataForMappedFile(FileMapVA, NULL, UE_CHARACTERISTICS, Characteristics);
                    WipeSectionNumber = GetPE32SectionNumberFromVA(FileMapVA, (ULONG_PTR)((ULONG_PTR)PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase));
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return(WipeSectionW(szFileName, (int)WipeSectionNumber, true));
                }
            }
            else
            {
                if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != NULL)
                {
                    Characteristics = (ULONG_PTR)GetPE32DataFromMappedFile(FileMapVA, NULL, UE_CHARACTERISTICS) ^ 1;
                    SetPE32DataForMappedFile(FileMapVA, NULL, UE_CHARACTERISTICS, Characteristics);
                    WipeSectionNumber = GetPE32SectionNumberFromVA(FileMapVA, (ULONG_PTR)((ULONG_PTR)PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase));
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return(WipeSectionW(szFileName, (int)WipeSectionNumber, true));
                }
            }
        }
    }
    return false;
}
