#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.h"
#include "Global.Mapping.h"
#include "Global.Garbage.h"

// TitanEngine.Realigner.functions:
__declspec(dllexport) bool TITCALL FixHeaderCheckSum(char* szFileName)
{
    wchar_t uniFileName[MAX_PATH] = {0};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, -1, uniFileName, _countof(uniFileName));
        return FixHeaderCheckSumW(uniFileName);
    }
    else
    {
        return 0;
    }
}

__declspec(dllexport) bool TITCALL FixHeaderCheckSumW(wchar_t* szFileName)
{
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    bool retVal = false;

    if(MapFileExW(szFileName, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, 0))
    {
        DWORD HeaderSum;
        DWORD CheckSum;
        if(CheckSumMappedFile((PVOID)FileMapVA, FileSize, &HeaderSum, &CheckSum))
        {
            retVal = SetPE32DataW(szFileName, NULL, UE_CHECKSUM, (ULONG_PTR)CheckSum);
        }
        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
    }
    return retVal;
}

__declspec(dllexport) long TITCALL RealignPE(ULONG_PTR FileMapVA, DWORD FileSize, DWORD RealingMode)
{

    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_SECTION_HEADER PESections;
    DWORD NewVirtualSectionSize = 0;
    DWORD NewSectionRawPointer = 0;
    DWORD OldSectionDataRawPtr = 0;
    DWORD OldSectionDataPtr = 0;
    DWORD SectionDataPtr = 0;
    DWORD SectionNumber = 0;
    DWORD CurrentSection = 0;
    DWORD FileAlignment = 0;
    BOOL FileIs64;

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
                return(-1);
            }
            if(!FileIs64)
            {
                PESections = IMAGE_FIRST_SECTION(PEHeader32);
                SectionNumber = PEHeader32->FileHeader.NumberOfSections;
                FileAlignment = PEHeader32->OptionalHeader.FileAlignment;
                if(FileAlignment == 0x1000)
                {
                    FileAlignment = 0x200;
                }
                __try
                {
                    PEHeader32->OptionalHeader.FileAlignment = FileAlignment;
                    while(SectionNumber > 0)
                    {
                        SectionDataPtr = PESections->PointerToRawData + PESections->SizeOfRawData;
                        if(PESections->SizeOfRawData > NULL)
                        {
                            SectionDataPtr--;
                            while(*(PUCHAR)(FileMapVA + SectionDataPtr) == 0x00 && SectionDataPtr > PESections->PointerToRawData)
                            {
                                SectionDataPtr--;
                            }
                        }
                        SectionDataPtr = SectionDataPtr - PESections->PointerToRawData;
                        OldSectionDataPtr = SectionDataPtr;
                        SectionDataPtr = (SectionDataPtr / FileAlignment) * FileAlignment;
                        if(SectionDataPtr < OldSectionDataPtr)
                        {
                            SectionDataPtr = SectionDataPtr + FileAlignment;
                        }
                        if(CurrentSection == NULL)
                        {
                            PEHeader32->OptionalHeader.SizeOfHeaders = PESections->PointerToRawData;
                            PEHeader32->OptionalHeader.SectionAlignment = PESections->VirtualAddress;
                            PESections->SizeOfRawData = SectionDataPtr;
                        }
                        else
                        {
                            OldSectionDataRawPtr = PESections->PointerToRawData;
                            PESections->SizeOfRawData = SectionDataPtr;
                            PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections - IMAGE_SIZEOF_SECTION_HEADER);
                            NewSectionRawPointer = PESections->PointerToRawData + PESections->SizeOfRawData;
                            PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                            PESections->PointerToRawData = NewSectionRawPointer;
                            RtlMoveMemory((LPVOID)((ULONG_PTR)FileMapVA + NewSectionRawPointer), (LPVOID)((ULONG_PTR)FileMapVA + OldSectionDataRawPtr), SectionDataPtr);
                        }
                        NewVirtualSectionSize = (PESections->Misc.VirtualSize / PEHeader32->OptionalHeader.SectionAlignment) * PEHeader32->OptionalHeader.SectionAlignment;
                        if(NewVirtualSectionSize < PESections->Misc.VirtualSize)
                        {
                            NewVirtualSectionSize = NewVirtualSectionSize + PEHeader32->OptionalHeader.SectionAlignment;
                        }
                        PESections->Misc.VirtualSize = NewVirtualSectionSize;
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                        CurrentSection++;
                        SectionNumber--;
                    }
                    PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections - IMAGE_SIZEOF_SECTION_HEADER);
                    return(PESections->PointerToRawData + PESections->SizeOfRawData);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    return(-1);
                }
            }
            else
            {
                PESections = IMAGE_FIRST_SECTION(PEHeader64);
                SectionNumber = PEHeader64->FileHeader.NumberOfSections;
                FileAlignment = PEHeader64->OptionalHeader.FileAlignment;
                if(FileAlignment == 0x1000)
                {
                    FileAlignment = 0x200;
                }
                __try
                {
                    PEHeader64->OptionalHeader.FileAlignment = FileAlignment;
                    while(SectionNumber > 0)
                    {
                        SectionDataPtr = PESections->PointerToRawData + PESections->SizeOfRawData;
                        if(PESections->SizeOfRawData > NULL)
                        {
                            SectionDataPtr--;
                            while(*(PUCHAR)(FileMapVA + SectionDataPtr) == 0x00 && SectionDataPtr > PESections->PointerToRawData)
                            {
                                SectionDataPtr--;
                            }
                        }
                        SectionDataPtr = SectionDataPtr - PESections->PointerToRawData;
                        OldSectionDataPtr = SectionDataPtr;
                        SectionDataPtr = (SectionDataPtr / FileAlignment) * FileAlignment;
                        if(SectionDataPtr < OldSectionDataPtr)
                        {
                            SectionDataPtr = SectionDataPtr + FileAlignment;
                        }
                        if(CurrentSection == NULL)
                        {
                            PEHeader64->OptionalHeader.SizeOfHeaders = PESections->PointerToRawData;
                            PEHeader64->OptionalHeader.SectionAlignment = PESections->VirtualAddress;
                            PESections->SizeOfRawData = SectionDataPtr;
                        }
                        else
                        {
                            OldSectionDataRawPtr = PESections->PointerToRawData;
                            PESections->SizeOfRawData = SectionDataPtr;
                            PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections - IMAGE_SIZEOF_SECTION_HEADER);
                            NewSectionRawPointer = PESections->PointerToRawData + PESections->SizeOfRawData;
                            PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                            PESections->PointerToRawData = NewSectionRawPointer;
                            RtlMoveMemory((LPVOID)((ULONG_PTR)FileMapVA + NewSectionRawPointer), (LPVOID)((ULONG_PTR)FileMapVA + OldSectionDataRawPtr), SectionDataPtr);
                        }
                        NewVirtualSectionSize = (PESections->Misc.VirtualSize / PEHeader64->OptionalHeader.SectionAlignment) * PEHeader64->OptionalHeader.SectionAlignment;
                        if(NewVirtualSectionSize < PESections->Misc.VirtualSize)
                        {
                            NewVirtualSectionSize = NewVirtualSectionSize + PEHeader64->OptionalHeader.SectionAlignment;
                        }
                        PESections->Misc.VirtualSize = NewVirtualSectionSize;
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                        CurrentSection++;
                        SectionNumber--;
                    }
                    PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections - IMAGE_SIZEOF_SECTION_HEADER);
                    return(PESections->PointerToRawData + PESections->SizeOfRawData);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    return(-1);
                }
            }
        }
        else
        {
            return(-1);
        }
    }
    return(-1);
}
__declspec(dllexport) long TITCALL RealignPEEx(char* szFileName, DWORD RealingFileSize, DWORD ForcedFileAlignment)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        return(RealignPEExW(uniFileName, RealingFileSize, ForcedFileAlignment));
    }
    else
    {
        return(-1);
    }
}
__declspec(dllexport) long TITCALL RealignPEExW(wchar_t* szFileName, DWORD RealingFileSize, DWORD ForcedFileAlignment)
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
    DWORD SectionDataPtr = 0;
    DWORD SectionNumber = 0;
    DWORD CurrentSection = 0;
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
                return(-1);
            }
            if(!FileIs64)
            {
                PESections = IMAGE_FIRST_SECTION(PEHeader32);
                SectionNumber = PEHeader32->FileHeader.NumberOfSections;
                if(ForcedFileAlignment == 0x0)
                {
                    ForcedFileAlignment = 0x200;
                }
                __try
                {
                    PEHeader32->OptionalHeader.FileAlignment = ForcedFileAlignment;
                    while(SectionNumber > 0)
                    {
                        SectionDataPtr = PESections->PointerToRawData + PESections->SizeOfRawData;
                        if(PESections->SizeOfRawData > NULL)
                        {
                            SectionDataPtr--;
                            while(*(PUCHAR)(FileMapVA + SectionDataPtr) == 0x00 && SectionDataPtr > PESections->PointerToRawData)
                            {
                                SectionDataPtr--;
                            }
                        }
                        SectionDataPtr = SectionDataPtr - PESections->PointerToRawData;
                        OldSectionDataPtr = SectionDataPtr;
                        SectionDataPtr = (SectionDataPtr / ForcedFileAlignment) * ForcedFileAlignment;
                        if(SectionDataPtr < OldSectionDataPtr)
                        {
                            SectionDataPtr = SectionDataPtr + ForcedFileAlignment;
                        }
                        if(CurrentSection == NULL)
                        {
                            PEHeader32->OptionalHeader.SizeOfHeaders = PESections->PointerToRawData;
                            PEHeader32->OptionalHeader.SectionAlignment = PESections->VirtualAddress;
                            PESections->SizeOfRawData = SectionDataPtr;
                        }
                        else
                        {
                            OldSectionDataRawPtr = PESections->PointerToRawData;
                            PESections->SizeOfRawData = SectionDataPtr;
                            PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections - IMAGE_SIZEOF_SECTION_HEADER);
                            NewSectionRawPointer = PESections->PointerToRawData + PESections->SizeOfRawData;
                            PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                            PESections->PointerToRawData = NewSectionRawPointer;
                            RtlMoveMemory((LPVOID)((ULONG_PTR)FileMapVA + NewSectionRawPointer), (LPVOID)((ULONG_PTR)FileMapVA + OldSectionDataRawPtr), SectionDataPtr);
                        }
                        NewVirtualSectionSize = (PESections->Misc.VirtualSize / PEHeader32->OptionalHeader.SectionAlignment) * PEHeader32->OptionalHeader.SectionAlignment;
                        if(NewVirtualSectionSize < PESections->Misc.VirtualSize)
                        {
                            NewVirtualSectionSize = NewVirtualSectionSize + PEHeader32->OptionalHeader.SectionAlignment;
                        }
                        PESections->Misc.VirtualSize = NewVirtualSectionSize;
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                        CurrentSection++;
                        SectionNumber--;
                    }
                    PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections - IMAGE_SIZEOF_SECTION_HEADER);
                    if(RealingFileSize == NULL)
                    {
                        FileSize = PESections->PointerToRawData + PESections->SizeOfRawData;
                    }
                    else
                    {
                        FileSize = RealingFileSize;
                    }
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    if(szBackupItem[0] != NULL)
                    {
                        if(CopyFileW(szBackupFile, szFileName, false))
                        {
                            RemoveGarbageItem(szBackupItem, true);
                            return(FileSize);
                        }
                        else
                        {
                            RemoveGarbageItem(szBackupItem, true);
                            return(-1);
                        }
                    }
                    else
                    {
                        return(FileSize);
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    RemoveGarbageItem(szBackupItem, true);
                    return(-1);
                }
            }
            else
            {
                PESections = IMAGE_FIRST_SECTION(PEHeader64);
                SectionNumber = PEHeader64->FileHeader.NumberOfSections;
                if(ForcedFileAlignment == 0x0)
                {
                    ForcedFileAlignment = 0x200;
                }
                __try
                {
                    PEHeader64->OptionalHeader.FileAlignment = ForcedFileAlignment;
                    while(SectionNumber > 0)
                    {
                        SectionDataPtr = PESections->PointerToRawData + PESections->SizeOfRawData;
                        if(PESections->SizeOfRawData > NULL)
                        {
                            SectionDataPtr--;
                            while(*(PUCHAR)(FileMapVA + SectionDataPtr) == 0x00 && SectionDataPtr > PESections->PointerToRawData)
                            {
                                SectionDataPtr--;
                            }
                        }
                        SectionDataPtr = SectionDataPtr - PESections->PointerToRawData;
                        OldSectionDataPtr = SectionDataPtr;
                        SectionDataPtr = (SectionDataPtr / ForcedFileAlignment) * ForcedFileAlignment;
                        if(SectionDataPtr < OldSectionDataPtr)
                        {
                            SectionDataPtr = SectionDataPtr + ForcedFileAlignment;
                        }
                        if(CurrentSection == NULL)
                        {
                            PEHeader64->OptionalHeader.SizeOfHeaders = PESections->PointerToRawData;
                            PEHeader64->OptionalHeader.SectionAlignment = PESections->VirtualAddress;
                            PESections->SizeOfRawData = SectionDataPtr;
                        }
                        else
                        {
                            OldSectionDataRawPtr = PESections->PointerToRawData;
                            PESections->SizeOfRawData = SectionDataPtr;
                            PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections - IMAGE_SIZEOF_SECTION_HEADER);
                            NewSectionRawPointer = PESections->PointerToRawData + PESections->SizeOfRawData;
                            PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                            PESections->PointerToRawData = NewSectionRawPointer;
                            RtlMoveMemory((LPVOID)((ULONG_PTR)FileMapVA + NewSectionRawPointer), (LPVOID)((ULONG_PTR)FileMapVA + OldSectionDataRawPtr), SectionDataPtr);
                        }
                        NewVirtualSectionSize = (PESections->Misc.VirtualSize / PEHeader64->OptionalHeader.SectionAlignment) * PEHeader64->OptionalHeader.SectionAlignment;
                        if(NewVirtualSectionSize < PESections->Misc.VirtualSize)
                        {
                            NewVirtualSectionSize = NewVirtualSectionSize + PEHeader64->OptionalHeader.SectionAlignment;
                        }
                        PESections->Misc.VirtualSize = NewVirtualSectionSize;
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                        CurrentSection++;
                        SectionNumber--;
                    }
                    PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections - IMAGE_SIZEOF_SECTION_HEADER);
                    if(RealingFileSize == NULL)
                    {
                        FileSize = PESections->PointerToRawData + PESections->SizeOfRawData;
                    }
                    else
                    {
                        FileSize = RealingFileSize;
                    }
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    if(szBackupItem[0] != NULL)
                    {
                        if(CopyFileW(szBackupFile, szFileName, false))
                        {
                            RemoveGarbageItem(szBackupItem, true);
                            return(FileSize);
                        }
                        else
                        {
                            RemoveGarbageItem(szBackupItem, true);
                            return(-1);
                        }
                    }
                    else
                    {
                        return(FileSize);
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    RemoveGarbageItem(szBackupItem, true);
                    return(-1);
                }
            }
        }
        else
        {
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            RemoveGarbageItem(szBackupItem, true);
            return(-1);
        }
    }
    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
    RemoveGarbageItem(szBackupItem, true);
    return(-1);
}
