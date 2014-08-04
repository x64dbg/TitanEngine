#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.h"
#include "Global.Handle.h"
#include "Global.Mapping.h"
#include "Global.Garbage.h"

__declspec(dllexport) bool TITCALL ExtractSection(char* szFileName, char* szDumpFileName, DWORD SectionNumber)
{
    wchar_t uniFileName[MAX_PATH] = {};
    wchar_t uniDumpFileName[MAX_PATH] = {};

    if(szFileName != NULL && szDumpFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        MultiByteToWideChar(CP_ACP, NULL, szDumpFileName, lstrlenA(szDumpFileName) + 1, uniDumpFileName, sizeof(uniDumpFileName) / (sizeof(uniDumpFileName[0])));
        return(ExtractSectionW(uniFileName, uniDumpFileName, SectionNumber));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL ExtractSectionW(wchar_t* szFileName, wchar_t* szDumpFileName, DWORD SectionNumber)
{
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_SECTION_HEADER PESections;
    DWORD NumberOfBytesWritten;
    BOOL FileIs64;
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    HANDLE hFile;

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
                PESections = IMAGE_FIRST_SECTION(PEHeader32);
                if(SectionNumber <= PEHeader32->FileHeader.NumberOfSections)
                {
                    PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + SectionNumber * IMAGE_SIZEOF_SECTION_HEADER);
                    EngineCreatePathForFileW(szDumpFileName);
                    hFile = CreateFileW(szDumpFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                    if(hFile != INVALID_HANDLE_VALUE)
                    {
                        __try
                        {
                            WriteFile(hFile, (LPCVOID)(FileMapVA + PESections->PointerToRawData), PESections->SizeOfRawData, &NumberOfBytesWritten, NULL);
                            EngineCloseHandle(hFile);
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return true;
                        }
                        __except(EXCEPTION_EXECUTE_HANDLER)
                        {
                            EngineCloseHandle(hFile);
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            DeleteFileW(szDumpFileName);
                            return false;
                        }
                    }
                }
                UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                return false;
            }
            else
            {
                PESections = IMAGE_FIRST_SECTION(PEHeader64);
                if(SectionNumber <= PEHeader64->FileHeader.NumberOfSections)
                {
                    PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + SectionNumber * IMAGE_SIZEOF_SECTION_HEADER);
                    EngineCreatePathForFileW(szDumpFileName);
                    hFile = CreateFileW(szDumpFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                    if(hFile != INVALID_HANDLE_VALUE)
                    {
                        __try
                        {
                            WriteFile(hFile, (LPCVOID)(FileMapVA + PESections->PointerToRawData), PESections->SizeOfRawData, &NumberOfBytesWritten, NULL);
                            EngineCloseHandle(hFile);
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return true;
                        }
                        __except(EXCEPTION_EXECUTE_HANDLER)
                        {
                            EngineCloseHandle(hFile);
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            DeleteFileW(szDumpFileName);
                            return false;
                        }
                    }
                }
                UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                return false;
            }
        }
        else
        {
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            return false;
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL ResortFileSections(char* szFileName)
{
    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        return(ResortFileSectionsW(uniFileName));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL ResortFileSectionsW(wchar_t* szFileName)
{
    int i = 0;
    int j = 0;
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_SECTION_HEADER PESections;
    DWORD SectionNumber = 0;
    BOOL FileIs64;
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    wchar_t szBackupFile[MAX_PATH] = {};
    wchar_t szBackupItem[MAX_PATH] = {};
    ULONG_PTR fileSectionData[MAXIMUM_SECTION_NUMBER][3];
    ULONG_PTR fileSectionTemp;
    LPVOID sortedFileName;
    DynBuf sortedFileNameBuf;

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
                sortedFileName = sortedFileNameBuf.Allocate(FileSize);
                if(sortedFileName)
                {
                    RtlMoveMemory(sortedFileName, (LPVOID)FileMapVA, FileSize);
                    SectionNumber = PEHeader32->FileHeader.NumberOfSections;
                    PESections = IMAGE_FIRST_SECTION(PEHeader32);
                    while(SectionNumber > 0)
                    {
                        fileSectionData[i][0] = (ULONG_PTR)(PESections->PointerToRawData);
                        fileSectionData[i][1] = PESections->SizeOfRawData;
                        fileSectionData[i][2] = PEHeader32->FileHeader.NumberOfSections - SectionNumber;
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                        SectionNumber--;
                        i++;
                    }
                    for(j = 0; j < PEHeader32->FileHeader.NumberOfSections; j++)
                    {
                        for(i = 0; i < PEHeader32->FileHeader.NumberOfSections; i++)
                        {
                            if(fileSectionData[i][0] > fileSectionData[j][0])
                            {
                                fileSectionTemp = fileSectionData[j][0];
                                fileSectionData[j][0] = fileSectionData[i][0];
                                fileSectionData[i][0] = fileSectionTemp;
                                fileSectionTemp = fileSectionData[j][1];
                                fileSectionData[j][1] = fileSectionData[i][1];
                                fileSectionData[i][1] = fileSectionTemp;
                            }
                        }
                    }
                    for(i = 0; i < PEHeader32->FileHeader.NumberOfSections; i++)
                    {
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PEHeader32 - FileMapVA + (ULONG_PTR)sortedFileName + PEHeader32->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4);
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + fileSectionData[i][2] * IMAGE_SIZEOF_SECTION_HEADER);
                        RtlMoveMemory((LPVOID)((ULONG_PTR)sortedFileName + fileSectionData[i][0]), (LPVOID)((ULONG_PTR)FileMapVA + PESections->PointerToRawData), fileSectionData[i][1]);
                        PESections->PointerToRawData = (DWORD)fileSectionData[i][0];
                        PESections->SizeOfRawData = (DWORD)fileSectionData[i][1];
                    }
                    RtlMoveMemory((LPVOID)FileMapVA, sortedFileName, FileSize);
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
                else
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    RemoveGarbageItem(szBackupItem, true);
                    return false;
                }
            }
            else
            {
                sortedFileName = sortedFileNameBuf.Allocate(FileSize);
                if(sortedFileName)
                {
                    RtlMoveMemory(sortedFileName, (LPVOID)FileMapVA, FileSize);
                    SectionNumber = PEHeader64->FileHeader.NumberOfSections;
                    PESections = IMAGE_FIRST_SECTION(PEHeader64);
                    while(SectionNumber > 0)
                    {
                        fileSectionData[i][0] = (ULONG_PTR)(PESections->PointerToRawData);
                        fileSectionData[i][1] = PESections->SizeOfRawData;
                        fileSectionData[i][2] = PEHeader64->FileHeader.NumberOfSections - SectionNumber;
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                        SectionNumber--;
                        i++;
                    }
                    for(j = 0; j < PEHeader64->FileHeader.NumberOfSections; j++)
                    {
                        for(i = 0; i < PEHeader64->FileHeader.NumberOfSections; i++)
                        {
                            if(fileSectionData[i][0] > fileSectionData[j][0])
                            {
                                fileSectionTemp = fileSectionData[j][0];
                                fileSectionData[j][0] = fileSectionData[i][0];
                                fileSectionData[i][0] = fileSectionTemp;
                                fileSectionTemp = fileSectionData[j][1];
                                fileSectionData[j][1] = fileSectionData[i][1];
                                fileSectionData[i][1] = fileSectionTemp;
                            }
                        }
                    }
                    for(i = 0; i < PEHeader64->FileHeader.NumberOfSections; i++)
                    {
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PEHeader64 - FileMapVA + (ULONG_PTR)sortedFileName + PEHeader64->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4);
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + fileSectionData[i][2] * IMAGE_SIZEOF_SECTION_HEADER);
                        RtlMoveMemory((LPVOID)((ULONG_PTR)sortedFileName + fileSectionData[i][0]), (LPVOID)((ULONG_PTR)FileMapVA + PESections->PointerToRawData), fileSectionData[i][1]);
                        PESections->PointerToRawData = (DWORD)fileSectionData[i][0];
                        PESections->SizeOfRawData = (DWORD)fileSectionData[i][1];
                    }
                    RtlMoveMemory((LPVOID)FileMapVA, sortedFileName, FileSize);
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
                else
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    RemoveGarbageItem(szBackupItem, true);
                    return false;
                }
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

__declspec(dllexport) bool TITCALL MakeAllSectionsRWE(char* szFileName)
{
    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        return(MakeAllSectionsRWEW(uniFileName));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL MakeAllSectionsRWEW(wchar_t* szFileName)
{
    wchar_t szBackupFile[MAX_PATH] = {};
    wchar_t szBackupItem[MAX_PATH] = {};
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_SECTION_HEADER PESections;
    DWORD SectionNumber = 0;
    BOOL FileIs64;
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;

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
                PESections = IMAGE_FIRST_SECTION(PEHeader32);
                SectionNumber = PEHeader32->FileHeader.NumberOfSections;
                __try
                {
                    while(SectionNumber > 0)
                    {
                        PESections->Characteristics = 0xE0000020;
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                        SectionNumber--;
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
                    return true;
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
                PESections = IMAGE_FIRST_SECTION(PEHeader64);
                SectionNumber = PEHeader64->FileHeader.NumberOfSections;
                __try
                {
                    while(SectionNumber > 0)
                    {
                        PESections->Characteristics = 0xE0000020;
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                        SectionNumber--;
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
                    return true;
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    RemoveGarbageItem(szBackupItem, true);
                    return false;
                }
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

__declspec(dllexport) long TITCALL AddNewSectionEx(char* szFileName, char* szSectionName, DWORD SectionSize, DWORD SectionAttributes, LPVOID SectionContent, DWORD ContentSize)
{
    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        return(AddNewSectionExW(uniFileName, szSectionName, SectionSize, SectionAttributes, SectionContent, ContentSize));
    }
    else
    {
        return NULL;
    }
}

__declspec(dllexport) long TITCALL AddNewSectionExW(wchar_t* szFileName, char* szSectionName, DWORD SectionSize, DWORD SectionAttributes, LPVOID SectionContent, DWORD ContentSize)
{
    bool OverlayHasBeenRemoved = false;
    wchar_t szBackupOverlayFile[MAX_PATH] = {};
    wchar_t szBackupFile[MAX_PATH] = {};
    wchar_t szBackupItem[MAX_PATH] = {};
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_SECTION_HEADER PESections;
    DWORD SectionNameLength = 0;
    DWORD NewSectionVirtualOffset = 0;
    DWORD FileResizeValue = 0;
    DWORD LastSectionRawSize = 0;
    DWORD alignedSectionSize = 0;
    DWORD NtSizeOfImage = 0;
    DWORD SectionNumber = 0;
    DWORD SpaceLeft = 0;
    LPVOID NameOffset;
    BOOL FileIs64;
    HANDLE FileHandle;
    DWORD FileSize;
    DWORD OldFileSize = 0;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;

    if(ContentSize < SectionSize && ContentSize != 0)
    {
        ContentSize = SectionSize;
    }
    else if(ContentSize > SectionSize)
    {
        SectionSize = ContentSize;
    }

    if(engineBackupForCriticalFunctions && CreateGarbageItem(&szBackupItem, sizeof szBackupItem))
    {
        if(!FillGarbageItem(szBackupItem, szFileName, &szBackupFile, sizeof szBackupItem))
        {
            RtlZeroMemory(&szBackupItem, sizeof szBackupItem);
            lstrcpyW(szBackupFile, szFileName);
        }
        if(FindOverlayW(szBackupFile, NULL, NULL))
        {
            if(!FillGarbageItem(szBackupItem, NULL, &szBackupOverlayFile, sizeof szBackupItem))
            {
                RtlZeroMemory(&szBackupOverlayFile, sizeof szBackupOverlayFile);
            }
            else
            {
                if(ExtractOverlayW(szBackupFile, szBackupOverlayFile) && RemoveOverlayW(szBackupFile))
                {
                    OverlayHasBeenRemoved = true;
                }
            }
        }
    }
    else
    {
        RtlZeroMemory(&szBackupItem, sizeof szBackupItem);
        lstrcpyW(szBackupFile, szFileName);
    }
    if(MapFileExW(szBackupFile, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        OldFileSize = FileSize;
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
                return(0);
            }
            if(!FileIs64)
            {
                PESections = IMAGE_FIRST_SECTION(PEHeader32);
                SectionNumber = PEHeader32->FileHeader.NumberOfSections;
                __try
                {
                    alignedSectionSize = ((DWORD)SectionSize / PEHeader32->OptionalHeader.FileAlignment) * PEHeader32->OptionalHeader.FileAlignment;
                    if(alignedSectionSize < SectionSize)
                    {
                        SectionSize = alignedSectionSize + PEHeader32->OptionalHeader.FileAlignment;
                    }
                    else
                    {
                        SectionSize = alignedSectionSize;
                    }
                    SpaceLeft = PESections->PointerToRawData - (SectionNumber * IMAGE_SIZEOF_SECTION_HEADER) - DOSHeader->e_lfanew - sizeof IMAGE_NT_HEADERS32;
                    PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + (SectionNumber - 1) * IMAGE_SIZEOF_SECTION_HEADER);
                    LastSectionRawSize = (PESections->SizeOfRawData / PEHeader32->OptionalHeader.FileAlignment) * PEHeader32->OptionalHeader.FileAlignment;
                    if(LastSectionRawSize < PESections->SizeOfRawData)
                    {
                        LastSectionRawSize = LastSectionRawSize + PEHeader32->OptionalHeader.FileAlignment;
                    }
                    LastSectionRawSize = LastSectionRawSize - PESections->SizeOfRawData;
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    FileResizeValue = LastSectionRawSize + SectionSize;
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    RemoveGarbageItem(szBackupItem, true);
                    return(0);
                }
            }
            else
            {
                PESections = IMAGE_FIRST_SECTION(PEHeader64);
                SectionNumber = PEHeader64->FileHeader.NumberOfSections;
                __try
                {
                    alignedSectionSize = ((DWORD)SectionSize / PEHeader64->OptionalHeader.FileAlignment) * PEHeader64->OptionalHeader.FileAlignment;
                    if(alignedSectionSize < SectionSize)
                    {
                        SectionSize = alignedSectionSize + PEHeader64->OptionalHeader.FileAlignment;
                    }
                    else
                    {
                        SectionSize = alignedSectionSize;
                    }
                    SpaceLeft = PESections->PointerToRawData - (SectionNumber * IMAGE_SIZEOF_SECTION_HEADER) - DOSHeader->e_lfanew - sizeof IMAGE_NT_HEADERS64;
                    PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + (SectionNumber - 1) * IMAGE_SIZEOF_SECTION_HEADER);
                    LastSectionRawSize = (PESections->SizeOfRawData / PEHeader64->OptionalHeader.FileAlignment) * PEHeader64->OptionalHeader.FileAlignment;
                    if(LastSectionRawSize < PESections->SizeOfRawData)
                    {
                        LastSectionRawSize = LastSectionRawSize + PEHeader64->OptionalHeader.FileAlignment;
                    }
                    LastSectionRawSize = LastSectionRawSize - PESections->SizeOfRawData;
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    FileResizeValue = LastSectionRawSize + SectionSize;
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    RemoveGarbageItem(szBackupItem, true);
                    return(0);
                }
            }
        }
        else
        {
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            RemoveGarbageItem(szBackupItem, true);
            return(0);
        }
    }
    if(SpaceLeft > IMAGE_SIZEOF_SECTION_HEADER)
    {
        if(MapFileExW(szBackupFile, UE_ACCESS_ALL, &FileHandle, &FileSize, &FileMap, &FileMapVA, FileResizeValue))
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
                    return(0);
                }
                if(!FileIs64)
                {
                    __try
                    {
                        if(SectionSize == 0)
                        {
                            SectionSize = PEHeader32->OptionalHeader.FileAlignment;
                        }
                        alignedSectionSize = ((DWORD)SectionSize / PEHeader32->OptionalHeader.SectionAlignment) * PEHeader32->OptionalHeader.SectionAlignment;
                        if(alignedSectionSize < SectionSize)
                        {
                            alignedSectionSize = alignedSectionSize + PEHeader32->OptionalHeader.SectionAlignment;
                        }
                        PESections = IMAGE_FIRST_SECTION(PEHeader32);
                        SectionNumber = PEHeader32->FileHeader.NumberOfSections;
                        PEHeader32->FileHeader.NumberOfSections = PEHeader32->FileHeader.NumberOfSections + 1;
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + (SectionNumber - 1) * IMAGE_SIZEOF_SECTION_HEADER);
                        NewSectionVirtualOffset = PESections->VirtualAddress + (PESections->Misc.VirtualSize / PEHeader32->OptionalHeader.SectionAlignment) * PEHeader32->OptionalHeader.SectionAlignment;
                        if(NewSectionVirtualOffset < PESections->VirtualAddress + PESections->Misc.VirtualSize)
                        {
                            NewSectionVirtualOffset = NewSectionVirtualOffset + PEHeader32->OptionalHeader.SectionAlignment;
                        }
                        PESections->SizeOfRawData = PESections->SizeOfRawData + LastSectionRawSize;
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                        PEHeader32->OptionalHeader.SizeOfImage = NewSectionVirtualOffset + alignedSectionSize;
                        NameOffset = &PESections->Name;
                        if(lstrlenA(szSectionName) >= 8)
                        {
                            SectionNameLength = 8;
                        }
                        else
                        {
                            SectionNameLength = lstrlenA(szSectionName);
                        }
                        RtlMoveMemory(NameOffset, szSectionName, SectionNameLength);
                        if(SectionAttributes == 0)
                        {
                            PESections->Characteristics = 0xE0000020;
                        }
                        else
                        {
                            PESections->Characteristics = (DWORD)(SectionAttributes);
                        }
                        PESections->Misc.VirtualSize = alignedSectionSize;
                        PESections->SizeOfRawData = (DWORD)(SectionSize);
                        PESections->VirtualAddress = NewSectionVirtualOffset;
                        PESections->PointerToRawData = OldFileSize + LastSectionRawSize;
                        if(SectionContent != NULL)
                        {
                            RtlMoveMemory((LPVOID)(FileMapVA + OldFileSize), SectionContent, ContentSize);
                        }
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        if(szBackupItem[0] != NULL)
                        {
                            if(CopyFileW(szBackupFile, szFileName, false))
                            {
                                if(OverlayHasBeenRemoved && !AddOverlayW(szFileName, szBackupOverlayFile))
                                {
                                    RemoveGarbageItem(szBackupItem, true);
                                    return(0);
                                }
                                RemoveGarbageItem(szBackupItem, true);
                                return(NewSectionVirtualOffset);
                            }
                            else
                            {
                                RemoveGarbageItem(szBackupItem, true);
                                return(0);
                            }
                        }
                        else
                        {
                            return(NewSectionVirtualOffset);
                        }
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        RemoveGarbageItem(szBackupItem, true);
                        return(0);
                    }
                }
                else
                {
                    __try
                    {
                        if(SectionSize == 0)
                        {
                            SectionSize = PEHeader64->OptionalHeader.FileAlignment;
                        }
                        alignedSectionSize = ((DWORD)SectionSize / PEHeader64->OptionalHeader.SectionAlignment) * PEHeader64->OptionalHeader.SectionAlignment;
                        if(alignedSectionSize < SectionSize)
                        {
                            alignedSectionSize = alignedSectionSize + PEHeader64->OptionalHeader.SectionAlignment;
                        }
                        PESections = IMAGE_FIRST_SECTION(PEHeader64);
                        SectionNumber = PEHeader64->FileHeader.NumberOfSections;
                        PEHeader32->FileHeader.NumberOfSections = PEHeader32->FileHeader.NumberOfSections + 1;
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + (SectionNumber - 1) * IMAGE_SIZEOF_SECTION_HEADER);
                        NewSectionVirtualOffset = PESections->VirtualAddress + (PESections->Misc.VirtualSize / PEHeader64->OptionalHeader.SectionAlignment) * PEHeader64->OptionalHeader.SectionAlignment;
                        if(NewSectionVirtualOffset < PESections->VirtualAddress + PESections->Misc.VirtualSize)
                        {
                            NewSectionVirtualOffset = NewSectionVirtualOffset + PEHeader64->OptionalHeader.SectionAlignment;
                        }
                        PESections->SizeOfRawData = PESections->SizeOfRawData + LastSectionRawSize;
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                        PEHeader64->OptionalHeader.SizeOfImage = NewSectionVirtualOffset + alignedSectionSize;
                        NameOffset = &PESections->Name;
                        if(lstrlenA(szSectionName) >= 8)
                        {
                            SectionNameLength = 8;
                        }
                        else
                        {
                            SectionNameLength = lstrlenA(szSectionName);
                        }
                        RtlMoveMemory(NameOffset, szSectionName, SectionNameLength);
                        if(SectionAttributes == 0)
                        {
                            PESections->Characteristics = 0xE0000020;
                        }
                        else
                        {
                            PESections->Characteristics = (DWORD)(SectionAttributes);
                        }
                        PESections->Misc.VirtualSize = alignedSectionSize;
                        PESections->SizeOfRawData = (DWORD)(SectionSize);
                        PESections->VirtualAddress = NewSectionVirtualOffset;
                        PESections->PointerToRawData = OldFileSize + LastSectionRawSize;
                        if(SectionContent != NULL)
                        {
                            RtlMoveMemory((LPVOID)(FileMapVA + OldFileSize), SectionContent, ContentSize);
                        }
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        if(szBackupItem[0] != NULL)
                        {
                            if(CopyFileW(szBackupFile, szFileName, false))
                            {
                                if(OverlayHasBeenRemoved && !AddOverlayW(szFileName, szBackupOverlayFile))
                                {
                                    RemoveGarbageItem(szBackupItem, true);
                                    return(0);
                                }
                                RemoveGarbageItem(szBackupItem, true);
                                return(NewSectionVirtualOffset);
                            }
                            else
                            {
                                RemoveGarbageItem(szBackupItem, true);
                                return(0);
                            }
                        }
                        else
                        {
                            return(NewSectionVirtualOffset);
                        }
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        RemoveGarbageItem(szBackupItem, true);
                        return(0);
                    }
                }
            }
            else
            {
                UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                RemoveGarbageItem(szBackupItem, true);
                return(0);
            }
        }
    }
    RemoveGarbageItem(szBackupItem, true);
    return(0);
}

__declspec(dllexport) long TITCALL AddNewSection(char* szFileName, char* szSectionName, DWORD SectionSize)
{
    return AddNewSectionEx(szFileName, szSectionName, SectionSize, NULL, NULL, NULL);
}

__declspec(dllexport) long TITCALL AddNewSectionW(wchar_t* szFileName, char* szSectionName, DWORD SectionSize)
{
    return AddNewSectionExW(szFileName, szSectionName, SectionSize, NULL, NULL, NULL);
}

__declspec(dllexport) bool TITCALL ResizeLastSection(char* szFileName, DWORD NumberOfExpandBytes, bool AlignResizeData)
{
    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        return(ResizeLastSectionW(uniFileName, NumberOfExpandBytes, AlignResizeData));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL ResizeLastSectionW(wchar_t* szFileName, DWORD NumberOfExpandBytes, bool AlignResizeData)
{
    wchar_t szBackupFile[MAX_PATH] = {};
    wchar_t szBackupItem[MAX_PATH] = {};
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_SECTION_HEADER PESections;
    DWORD SectionNumber = 0;
    DWORD SectionRawSize = 0;
    BOOL FileIs64;
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;

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
    if(MapFileExW(szBackupFile, UE_ACCESS_ALL, &FileHandle, &FileSize, &FileMap, &FileMapVA, NumberOfExpandBytes))
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
                FileSize = FileSize - NumberOfExpandBytes;
                UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                RemoveGarbageItem(szBackupItem, true);
                return false;
            }
            if(!FileIs64)
            {
                PESections = IMAGE_FIRST_SECTION(PEHeader32);
                SectionNumber = PEHeader32->FileHeader.NumberOfSections;
                SectionNumber--;
                PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + SectionNumber * IMAGE_SIZEOF_SECTION_HEADER);
                __try
                {
                    if(AlignResizeData)
                    {
                        SectionRawSize = PESections->SizeOfRawData;
                        if((PESections->SizeOfRawData + NumberOfExpandBytes) % PEHeader32->OptionalHeader.FileAlignment == NULL)
                        {
                            PESections->SizeOfRawData = (((PESections->SizeOfRawData + NumberOfExpandBytes) / PEHeader32->OptionalHeader.FileAlignment)) * PEHeader32->OptionalHeader.FileAlignment;
                        }
                        else
                        {
                            PESections->SizeOfRawData = (((PESections->SizeOfRawData + NumberOfExpandBytes) / PEHeader32->OptionalHeader.FileAlignment) + 1) * PEHeader32->OptionalHeader.FileAlignment;
                        }
                        if(SectionRawSize > 0x7FFFFFFF)
                        {
                            SectionRawSize = NULL;
                        }
                        SectionRawSize = PESections->SizeOfRawData - SectionRawSize - NumberOfExpandBytes;
                        PEHeader32->OptionalHeader.SizeOfImage = PEHeader32->OptionalHeader.SizeOfImage - PESections->Misc.VirtualSize;
                        if((PESections->Misc.VirtualSize + NumberOfExpandBytes + SectionRawSize) % PEHeader32->OptionalHeader.SectionAlignment == NULL)
                        {
                            PESections->Misc.VirtualSize = (((PESections->Misc.VirtualSize + NumberOfExpandBytes + SectionRawSize) / PEHeader32->OptionalHeader.SectionAlignment)) * PEHeader32->OptionalHeader.SectionAlignment;
                        }
                        else
                        {
                            PESections->Misc.VirtualSize = (((PESections->Misc.VirtualSize + NumberOfExpandBytes + SectionRawSize) / PEHeader32->OptionalHeader.SectionAlignment) + 1) * PEHeader32->OptionalHeader.SectionAlignment;
                        }
                        PEHeader32->OptionalHeader.SizeOfImage = PEHeader32->OptionalHeader.SizeOfImage + PESections->Misc.VirtualSize;
                        if(SectionRawSize > NULL)
                        {
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            MapFileExW(szFileName, UE_ACCESS_ALL, &FileHandle, &FileSize, &FileMap, &FileMapVA, SectionRawSize);
                        }
                    }
                    else
                    {
                        PESections->SizeOfRawData = PESections->SizeOfRawData + NumberOfExpandBytes;
                    }
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    if(szBackupItem[0] != NULL)
                    {
                        RemoveGarbageItem(szBackupItem, true);
                        if(CopyFileW(szBackupFile, szFileName, false))
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
                PESections = IMAGE_FIRST_SECTION(PEHeader64);
                SectionNumber = PEHeader64->FileHeader.NumberOfSections;
                SectionNumber--;
                PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + SectionNumber * IMAGE_SIZEOF_SECTION_HEADER);
                __try
                {
                    if(AlignResizeData)
                    {
                        SectionRawSize = PESections->SizeOfRawData;
                        if((PESections->SizeOfRawData + NumberOfExpandBytes) % PEHeader64->OptionalHeader.FileAlignment == NULL)
                        {
                            PESections->SizeOfRawData = (((PESections->SizeOfRawData + NumberOfExpandBytes) / PEHeader64->OptionalHeader.FileAlignment)) * PEHeader64->OptionalHeader.FileAlignment;
                        }
                        else
                        {
                            PESections->SizeOfRawData = (((PESections->SizeOfRawData + NumberOfExpandBytes) / PEHeader64->OptionalHeader.FileAlignment) + 1) * PEHeader64->OptionalHeader.FileAlignment;
                        }
                        if(SectionRawSize > 0x7FFFFFFF)
                        {
                            SectionRawSize = NULL;
                        }
                        SectionRawSize = PESections->SizeOfRawData - SectionRawSize - NumberOfExpandBytes;
                        PEHeader64->OptionalHeader.SizeOfImage = PEHeader64->OptionalHeader.SizeOfImage - PESections->Misc.VirtualSize;
                        if((PESections->Misc.VirtualSize + NumberOfExpandBytes) % PEHeader64->OptionalHeader.SectionAlignment == NULL)
                        {
                            PESections->Misc.VirtualSize = (((PESections->Misc.VirtualSize + NumberOfExpandBytes + SectionRawSize) / PEHeader32->OptionalHeader.SectionAlignment)) * PEHeader64->OptionalHeader.SectionAlignment;
                        }
                        else
                        {
                            PESections->Misc.VirtualSize = (((PESections->Misc.VirtualSize + NumberOfExpandBytes + SectionRawSize) / PEHeader32->OptionalHeader.SectionAlignment) + 1) * PEHeader64->OptionalHeader.SectionAlignment;
                        }
                        PEHeader64->OptionalHeader.SizeOfImage = PEHeader64->OptionalHeader.SizeOfImage + PESections->Misc.VirtualSize;
                        if(SectionRawSize > NULL)
                        {
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            MapFileExW(szFileName, UE_ACCESS_ALL, &FileHandle, &FileSize, &FileMap, &FileMapVA, SectionRawSize);
                        }
                    }
                    else
                    {
                        PESections->SizeOfRawData = PESections->SizeOfRawData + NumberOfExpandBytes;
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
        }
        else
        {
            FileSize = FileSize - NumberOfExpandBytes;
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            RemoveGarbageItem(szBackupItem, true);
            return false;
        }
    }
    RemoveGarbageItem(szBackupItem, true);
    return false;
}

__declspec(dllexport) bool TITCALL DeleteLastSection(char* szFileName)
{
    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        return(DeleteLastSectionW(uniFileName));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL DeleteLastSectionW(wchar_t* szFileName)
{
    wchar_t szBackupFile[MAX_PATH] = {};
    wchar_t szBackupItem[MAX_PATH] = {};
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_SECTION_HEADER PESections;
    DWORD SectionNumber = 0;
    BOOL FileIs64;
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;

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
                PESections = IMAGE_FIRST_SECTION(PEHeader32);
                SectionNumber = PEHeader32->FileHeader.NumberOfSections;
                __try
                {
                    if(SectionNumber > 1)
                    {
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + (SectionNumber - 1) * IMAGE_SIZEOF_SECTION_HEADER);
                        PEHeader32->OptionalHeader.SizeOfImage = PEHeader32->OptionalHeader.SizeOfImage - PESections->Misc.VirtualSize;
                        FileSize = PESections->PointerToRawData;
                        RtlZeroMemory(PESections, IMAGE_SIZEOF_SECTION_HEADER);
                        PEHeader32->FileHeader.NumberOfSections--;
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
                    else
                    {
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        RemoveGarbageItem(szBackupItem, true);
                        return false;
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
                PESections = IMAGE_FIRST_SECTION(PEHeader64);
                SectionNumber = PEHeader64->FileHeader.NumberOfSections;
                __try
                {
                    if(SectionNumber > 1)
                    {
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + (SectionNumber - 1) * IMAGE_SIZEOF_SECTION_HEADER);
                        PEHeader64->OptionalHeader.SizeOfImage = PEHeader64->OptionalHeader.SizeOfImage - PESections->Misc.VirtualSize;
                        FileSize = PESections->PointerToRawData;
                        RtlZeroMemory(PESections, IMAGE_SIZEOF_SECTION_HEADER);
                        PEHeader64->FileHeader.NumberOfSections--;
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
                    else
                    {
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        RemoveGarbageItem(szBackupItem, true);
                        return false;
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    RemoveGarbageItem(szBackupItem, true);
                    return false;
                }
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

__declspec(dllexport) bool TITCALL DeleteLastSectionEx(char* szFileName, DWORD NumberOfSections)
{
    while(NumberOfSections > 0)
    {
        DeleteLastSection(szFileName);
        NumberOfSections--;
    }
    return true;
}

__declspec(dllexport) bool TITCALL DeleteLastSectionExW(wchar_t* szFileName, DWORD NumberOfSections)
{
    while(NumberOfSections > 0)
    {
        DeleteLastSectionW(szFileName);
        NumberOfSections--;
    }
    return true;
}

__declspec(dllexport) bool TITCALL WipeSection(char* szFileName, int WipeSectionNumber, bool RemovePhysically)
{
    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        return(WipeSectionW(uniFileName, WipeSectionNumber, RemovePhysically));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL WipeSectionW(wchar_t* szFileName, int WipeSectionNumber, bool RemovePhysically)
{
    wchar_t szBackupFile[MAX_PATH] = {};
    wchar_t szBackupItem[MAX_PATH] = {};
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_SECTION_HEADER PESections;
    DWORD NewVirtualSectionSize = 0;
    DWORD NewSectionRawPointer = 0;
    DWORD OldSectionDataRawPtr = 0;
    DWORD OldSectionDataPtr = 0;
    DWORD CurrentSectionPSize = 0;
    DWORD WipeSectionVirSize = 0;
    DWORD WipeSectionSize = 0;
    DWORD SectionDataPtr = 0;
    DWORD FileAlignment = 0;
    int SectionNumber = 0;
    BOOL FileIs64;
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;

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
            ULONG_PTR WipeRawSize = GetPE32DataFromMappedFile(FileMapVA, SectionNumber, UE_SECTIONRAWSIZE);
            if(!WipeRawSize)
                RemovePhysically = false;
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
                if(WipeSectionNumber != -1 && WipeSectionNumber <= PEHeader32->FileHeader.NumberOfSections)
                {
                    WipeSectionVirSize = (DWORD)GetPE32DataFromMappedFile(FileMapVA, WipeSectionNumber, UE_SECTIONVIRTUALSIZE);
                    WipeSectionSize = (DWORD)GetPE32DataFromMappedFile(FileMapVA, WipeSectionNumber, UE_SECTIONRAWSIZE);
                    PESections = IMAGE_FIRST_SECTION(PEHeader32);
                    FileAlignment = PEHeader32->OptionalHeader.FileAlignment;
                    __try
                    {
                        while(SectionNumber < PEHeader32->FileHeader.NumberOfSections)
                        {
                            if(SectionNumber == WipeSectionNumber - 1)
                            {
                                CurrentSectionPSize = PESections->SizeOfRawData;
                                if(CurrentSectionPSize % FileAlignment == NULL)
                                {
                                    CurrentSectionPSize = ((CurrentSectionPSize / FileAlignment)) * FileAlignment;
                                }
                                else
                                {
                                    CurrentSectionPSize = ((CurrentSectionPSize / FileAlignment) + 1) * FileAlignment;
                                }
                                PESections->SizeOfRawData = CurrentSectionPSize;
                                WipeSectionVirSize = WipeSectionVirSize + PESections->Misc.VirtualSize;
                                if(WipeSectionVirSize % PEHeader32->OptionalHeader.SectionAlignment == NULL)
                                {
                                    WipeSectionVirSize = ((WipeSectionVirSize / PEHeader32->OptionalHeader.SectionAlignment)) * PEHeader32->OptionalHeader.SectionAlignment;
                                }
                                else
                                {
                                    WipeSectionVirSize = ((WipeSectionVirSize / PEHeader32->OptionalHeader.SectionAlignment) + 1) * PEHeader32->OptionalHeader.SectionAlignment;
                                }
                                PESections->Misc.VirtualSize = WipeSectionVirSize;
                                CurrentSectionPSize = CurrentSectionPSize - PESections->SizeOfRawData;
                                WipeSectionSize = WipeSectionSize - CurrentSectionPSize;
                            }
                            else if(SectionNumber > WipeSectionNumber)
                            {
                                RtlMoveMemory((LPVOID)((ULONG_PTR)PESections - IMAGE_SIZEOF_SECTION_HEADER), (LPVOID)PESections, IMAGE_SIZEOF_SECTION_HEADER);
                            }
                            PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                            SectionNumber++;
                        }
                        RtlZeroMemory((LPVOID)PESections, IMAGE_SIZEOF_SECTION_HEADER);
                        PEHeader32->FileHeader.NumberOfSections--;
                        if(RemovePhysically)
                        {
                            FileSize = RealignPE(FileMapVA, FileSize, NULL);
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
            }
            else
            {
                if(WipeSectionNumber != -1 && WipeSectionNumber <= PEHeader64->FileHeader.NumberOfSections)
                {
                    WipeSectionVirSize = (DWORD)GetPE32DataFromMappedFile(FileMapVA, WipeSectionNumber, UE_SECTIONVIRTUALOFFSET);
                    WipeSectionVirSize = WipeSectionVirSize + (DWORD)GetPE32DataFromMappedFile(FileMapVA, WipeSectionNumber, UE_SECTIONVIRTUALSIZE);
                    if(WipeSectionVirSize % PEHeader32->OptionalHeader.SectionAlignment == NULL)
                    {
                        WipeSectionVirSize = ((WipeSectionVirSize / PEHeader32->OptionalHeader.SectionAlignment)) * PEHeader32->OptionalHeader.SectionAlignment;
                    }
                    else
                    {
                        WipeSectionVirSize = ((WipeSectionVirSize / PEHeader32->OptionalHeader.SectionAlignment) + 1) * PEHeader32->OptionalHeader.SectionAlignment;
                    }
                    WipeSectionSize = (DWORD)GetPE32DataFromMappedFile(FileMapVA, WipeSectionNumber, UE_SECTIONRAWSIZE);
                    PESections = IMAGE_FIRST_SECTION(PEHeader64);
                    FileAlignment = PEHeader64->OptionalHeader.FileAlignment;
                    __try
                    {
                        while(SectionNumber < PEHeader64->FileHeader.NumberOfSections)
                        {
                            if(SectionNumber == WipeSectionNumber - 1)
                            {
                                CurrentSectionPSize = PESections->SizeOfRawData;
                                if(CurrentSectionPSize % FileAlignment == NULL)
                                {
                                    CurrentSectionPSize = ((CurrentSectionPSize / FileAlignment)) * FileAlignment;
                                }
                                else
                                {
                                    CurrentSectionPSize = ((CurrentSectionPSize / FileAlignment) + 1) * FileAlignment;
                                }
                                PESections->SizeOfRawData = CurrentSectionPSize;
                                WipeSectionVirSize = WipeSectionVirSize + PESections->Misc.VirtualSize;
                                if(WipeSectionVirSize % PEHeader64->OptionalHeader.SectionAlignment == NULL)
                                {
                                    WipeSectionVirSize = ((WipeSectionVirSize / PEHeader64->OptionalHeader.SectionAlignment)) * PEHeader64->OptionalHeader.SectionAlignment;
                                }
                                else
                                {
                                    WipeSectionVirSize = ((WipeSectionVirSize / PEHeader64->OptionalHeader.SectionAlignment) + 1) * PEHeader64->OptionalHeader.SectionAlignment;
                                }
                                PESections->Misc.VirtualSize = WipeSectionVirSize;
                                CurrentSectionPSize = CurrentSectionPSize - PESections->SizeOfRawData;
                                WipeSectionSize = WipeSectionSize - CurrentSectionPSize;
                            }
                            else if(SectionNumber > WipeSectionNumber)
                            {
                                RtlMoveMemory((LPVOID)((ULONG_PTR)PESections - IMAGE_SIZEOF_SECTION_HEADER), (LPVOID)PESections, IMAGE_SIZEOF_SECTION_HEADER);
                            }
                            PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                            SectionNumber++;
                        }
                        RtlZeroMemory((LPVOID)PESections, IMAGE_SIZEOF_SECTION_HEADER);
                        PEHeader64->FileHeader.NumberOfSections--;
                        if(RemovePhysically)
                        {
                            FileSize = RealignPE(FileMapVA, FileSize, NULL);
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
            }
        }
        else
        {
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            RemoveGarbageItem(szBackupItem, true);
            return false;
        }
    }
    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
    RemoveGarbageItem(szBackupItem, true);
    return false;
}
