#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.h"
#include "Global.Mapping.h"
#include "Global.Realigner.h"

__declspec(dllexport) bool TITCALL IsPE32FileValidEx(char* szFileName, DWORD CheckDepth, LPVOID FileStatusInfo)
{
    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        return(IsPE32FileValidExW(uniFileName, CheckDepth, FileStatusInfo));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL IsPE32FileValidExW(wchar_t* szFileName, DWORD CheckDepth, LPVOID FileStatusInfo)
{
    unsigned int i;
    ULONG_PTR ReadData = NULL;
    DWORD ReadSize = 0;
    WORD ReadDataWORD = 0;
    ULONG_PTR hSimulatedFileLoad;
    long SectionNumber = 0;
    DWORD SectionAttributes = 0;
    ULONG_PTR ConvertedAddress = NULL;
    DWORD CorrectedImageSize = 0;
    DWORD SectionVirtualSize = 0;
    DWORD SectionVirtualSizeFixed = 0;
    DWORD NumberOfSections = 0;
    FILE_STATUS_INFO myFileStatusInfo;
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_SECTION_HEADER PESections;
    PIMAGE_EXPORT_DIRECTORY PEExports;
    PIMAGE_TLS_DIRECTORY32 PETls32;
    PIMAGE_TLS_DIRECTORY64 PETls64;
    PIMAGE_IMPORT_DESCRIPTOR ImportIID;
    PIMAGE_BOUND_IMPORT_DESCRIPTOR BoundIID;
    PIMAGE_THUNK_DATA32 ThunkData32;
    PIMAGE_THUNK_DATA64 ThunkData64;
    bool hLoadedModuleSimulated = false;
    HMODULE hLoadedModule;
    ULONG_PTR ImportNamePtr;
    ULONG_PTR CurrentThunk;
    BOOL FileIsDLL = false;
    BOOL FileIs64;
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    WORD ResourceNamesTable[22] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16, 17, 18, 19, 20, 21, 22, 23, 24};

    RtlZeroMemory(&myFileStatusInfo, sizeof FILE_STATUS_INFO);
    if(MapFileExW(szFileName, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
        myFileStatusInfo.OveralEvaluation = UE_RESULT_FILE_OK;
        if(EngineValidateHeader(FileMapVA, FileHandle, NULL, DOSHeader, true))
        {
            PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            if(PEHeader32->Signature == 0x4550 && PEHeader32->OptionalHeader.Magic == 0x10B)
            {
                FileIs64 = false;
            }
            else if(PEHeader32->Signature == 0x4550 && PEHeader32->OptionalHeader.Magic == 0x20B)
            {
                FileIs64 = true;
                myFileStatusInfo.FileIs64Bit = true;
            }
            else
            {
                myFileStatusInfo.OveralEvaluation = UE_RESULT_FILE_INVALID_FORMAT;
                myFileStatusInfo.SignaturePE = UE_FIELD_BROKEN_NON_FIXABLE;
                if(FileStatusInfo != NULL)
                {
                    RtlMoveMemory(FileStatusInfo, &myFileStatusInfo, sizeof FILE_STATUS_INFO);
                }
                UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                return false;
            }
            if(!FileIs64)
            {
                /*
                    x86 Surface check
                */
                __try
                {
                    if(PEHeader32->OptionalHeader.SizeOfImage % PEHeader32->OptionalHeader.SectionAlignment == NULL)
                    {
                        CorrectedImageSize = ((PEHeader32->OptionalHeader.SizeOfImage / PEHeader32->OptionalHeader.SectionAlignment)) * PEHeader32->OptionalHeader.SectionAlignment;
                    }
                    else
                    {
                        CorrectedImageSize = ((PEHeader32->OptionalHeader.SizeOfImage / PEHeader32->OptionalHeader.SectionAlignment) + 1) * PEHeader32->OptionalHeader.SectionAlignment;
                    }
                    if(PEHeader32->OptionalHeader.SectionAlignment != NULL && PEHeader32->OptionalHeader.SectionAlignment >= PEHeader32->OptionalHeader.FileAlignment)
                    {
                        myFileStatusInfo.SectionAlignment = UE_FIELD_OK;
                        if(PEHeader32->OptionalHeader.SizeOfImage % PEHeader32->OptionalHeader.SectionAlignment == NULL)
                        {
                            myFileStatusInfo.SizeOfImage = UE_FIELD_OK;
                        }
                        else
                        {
                            if(CorrectedImageSize < PEHeader32->OptionalHeader.AddressOfEntryPoint)
                            {
                                myFileStatusInfo.SizeOfImage = UE_FIELD_BROKEN_NON_FIXABLE;
                            }
                            else
                            {
                                myFileStatusInfo.SizeOfImage = UE_FIELD_FIXABLE_NON_CRITICAL;
                            }
                        }
                    }
                    else
                    {
                        myFileStatusInfo.SectionAlignment = UE_FIELD_FIXABLE_CRITICAL;
                    }
                    SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.SectionAlignment, true);
                    if(PEHeader32->OptionalHeader.ImageBase % 0x1000 == NULL)
                    {
                        myFileStatusInfo.ImageBase = UE_FIELD_OK;
                    }
                    else
                    {
                        myFileStatusInfo.ImageBase = UE_FIELD_BROKEN_NON_FIXABLE;
                    }
                    SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.ImageBase, true);
                    if(PEHeader32->OptionalHeader.FileAlignment % 2 == NULL)
                    {
                        myFileStatusInfo.FileAlignment = UE_FIELD_OK;
                    }
                    else
                    {
                        myFileStatusInfo.FileAlignment = UE_FIELD_FIXABLE_CRITICAL;
                    }
                    SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.FileAlignment, false);
                    /*
                        Get the console flag
                    */
                    if(PEHeader32->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI)
                    {
                        myFileStatusInfo.FileIsConsole = true;
                    }
                    /*
                        Export and relocation checks [for DLL and EXE]
                    */
                    if(PEHeader32->FileHeader.Characteristics & 0x2000)
                    {
                        /*
                            Export table check
                        */
                        FileIsDLL = true;
                        myFileStatusInfo.FileIsDLL = true;
                        if(PEHeader32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT && PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != NULL)
                        {
                            if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress > CorrectedImageSize || PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size > CorrectedImageSize)
                            {
                                myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_FIXABLE;
                            }
                            else
                            {
                                ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + PEHeader32->OptionalHeader.ImageBase, false, true);
                                if(ConvertedAddress != NULL)
                                {
                                    if(EngineIsValidReadPtrEx((LPVOID)ConvertedAddress, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size))
                                    {
                                        PEExports = (PIMAGE_EXPORT_DIRECTORY)ConvertedAddress;
                                        if(PEExports->AddressOfFunctions > CorrectedImageSize || PEExports->AddressOfFunctions + 4 * PEExports->NumberOfFunctions > CorrectedImageSize)
                                        {
                                            myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_FIXABLE;
                                        }
                                        else if(PEExports->AddressOfNameOrdinals > CorrectedImageSize || PEExports->AddressOfNameOrdinals + 4 * PEExports->NumberOfNames > CorrectedImageSize)
                                        {
                                            myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_FIXABLE;
                                        }
                                        else if(PEExports->AddressOfNames > CorrectedImageSize || PEExports->AddressOfNames + 4 * PEExports->NumberOfNames > CorrectedImageSize)
                                        {
                                            myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_FIXABLE;
                                        }
                                        else if(PEExports->Name > CorrectedImageSize)
                                        {
                                            myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_FIXABLE;
                                        }
                                        else
                                        {
                                            if(CheckDepth == UE_DEPTH_DEEP)
                                            {
                                                ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEExports->AddressOfFunctions + PEHeader32->OptionalHeader.ImageBase, false, true);
                                                if(ConvertedAddress != NULL)
                                                {
                                                    for(i = 0; i < PEExports->NumberOfFunctions; i++)
                                                    {
                                                        RtlMoveMemory(&ReadData, (LPVOID)ConvertedAddress, 4);
                                                        if(ReadData > CorrectedImageSize || ReadData < PEHeader32->OptionalHeader.SectionAlignment)
                                                        {
                                                            myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_FIXABLE;
                                                            i = PEExports->NumberOfFunctions;
                                                        }
                                                        else
                                                        {
                                                            ConvertedAddress = ConvertedAddress + 4;
                                                        }
                                                    }
                                                }
                                                else
                                                {
                                                    myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_FIXABLE;
                                                }
                                                ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEExports->AddressOfNames + PEHeader32->OptionalHeader.ImageBase, false, true);
                                                if(ConvertedAddress != NULL)
                                                {
                                                    for(i = 0; i < PEExports->NumberOfNames; i++)
                                                    {
                                                        RtlMoveMemory(&ReadData, (LPVOID)ConvertedAddress, 4);
                                                        if(ReadData > CorrectedImageSize || ReadData < PEHeader32->OptionalHeader.SectionAlignment)
                                                        {
                                                            myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_FIXABLE;
                                                            i = PEExports->NumberOfNames;
                                                        }
                                                        else
                                                        {
                                                            ConvertedAddress = ConvertedAddress + 4;
                                                        }
                                                    }
                                                }
                                                else
                                                {
                                                    myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_FIXABLE;
                                                }
                                            }
                                        }
                                    }
                                    else
                                    {
                                        myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_FIXABLE;
                                    }
                                }
                                else
                                {
                                    myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_FIXABLE;
                                }
                            }
                            SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.ExportTable, true);
                        }
                        else
                        {
                            myFileStatusInfo.ExportTable = UE_FIELD_NOT_PRESET;
                        }
                        /*
                            Relocation table check
                        */
                        if(PEHeader32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC && PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != NULL)
                        {
                            if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress > CorrectedImageSize || PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > CorrectedImageSize)
                            {
                                myFileStatusInfo.RelocationTable = UE_FIELD_BROKEN_NON_FIXABLE;
                            }
                            else
                            {
                                ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + PEHeader32->OptionalHeader.ImageBase, false, true);
                                if(ConvertedAddress != NULL)
                                {
                                    if(EngineIsValidReadPtrEx((LPVOID)ConvertedAddress, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size))
                                    {
                                        RtlMoveMemory(&ReadData, (LPVOID)ConvertedAddress, 4);
                                        RtlMoveMemory(&ReadSize, (LPVOID)(ConvertedAddress + 4), 4);
                                        while(ReadData != NULL)
                                        {
                                            ReadSize = ReadSize - 8;
                                            ConvertedAddress = ConvertedAddress + 8;
                                            while(ReadSize > NULL)
                                            {
                                                RtlMoveMemory(&ReadDataWORD, (LPVOID)ConvertedAddress, 2);
                                                if(ReadDataWORD > 0xCFFF)
                                                {
                                                    myFileStatusInfo.RelocationTable = UE_FIELD_BROKEN_FIXABLE_FOR_STATIC_USE;
                                                }
                                                ConvertedAddress = ConvertedAddress + 2;
                                                ReadSize = ReadSize - 2;
                                            }
                                            RtlMoveMemory(&ReadData, (LPVOID)ConvertedAddress, 4);
                                            RtlMoveMemory(&ReadSize, (LPVOID)(ConvertedAddress + 4), 4);
                                        }
                                    }
                                    else
                                    {
                                        myFileStatusInfo.RelocationTable = UE_FIELD_BROKEN_FIXABLE_FOR_STATIC_USE;
                                    }
                                }
                                else
                                {
                                    myFileStatusInfo.RelocationTable = UE_FIELD_BROKEN_FIXABLE_FOR_STATIC_USE;
                                }
                            }
                            SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.RelocationTable, true);
                        }
                        else
                        {
                            myFileStatusInfo.RelocationTable = UE_FIELD_NOT_PRESET_WARNING;
                        }
                    }
                    else
                    {
                        /*
                            Export table check
                        */
                        if(PEHeader32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT && PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != NULL)
                        {
                            if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress > CorrectedImageSize || PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size > CorrectedImageSize)
                            {
                                myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_CRITICAL;
                            }
                            else
                            {
                                ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + PEHeader32->OptionalHeader.ImageBase, false, true);
                                if(ConvertedAddress != NULL)
                                {
                                    if(EngineIsValidReadPtrEx((LPVOID)ConvertedAddress, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size))
                                    {
                                        PEExports = (PIMAGE_EXPORT_DIRECTORY)ConvertedAddress;
                                        if(PEExports->AddressOfFunctions > CorrectedImageSize || PEExports->AddressOfFunctions + 4 * PEExports->NumberOfFunctions > CorrectedImageSize)
                                        {
                                            myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_CRITICAL;
                                        }
                                        else if(PEExports->AddressOfNameOrdinals > CorrectedImageSize || PEExports->AddressOfNameOrdinals + 4 * PEExports->NumberOfNames > CorrectedImageSize)
                                        {
                                            myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_CRITICAL;
                                        }
                                        else if(PEExports->AddressOfNames > CorrectedImageSize || PEExports->AddressOfNames + 4 * PEExports->NumberOfNames > CorrectedImageSize)
                                        {
                                            myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_CRITICAL;
                                        }
                                        else if(PEExports->Name > CorrectedImageSize)
                                        {
                                            myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_CRITICAL;
                                        }
                                    }
                                    else
                                    {
                                        myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_CRITICAL;
                                    }
                                }
                            }
                            SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.ExportTable, false);
                        }
                        else
                        {
                            myFileStatusInfo.ExportTable = UE_FIELD_NOT_PRESET;
                        }
                        /*
                            Relocation table check
                        */
                        if(PEHeader32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC && PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != NULL)
                        {
                            if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress > CorrectedImageSize || PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > CorrectedImageSize)
                            {
                                myFileStatusInfo.RelocationTable = UE_FIELD_BROKEN_NON_FIXABLE;
                            }
                            else
                            {
                                ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + PEHeader32->OptionalHeader.ImageBase, false, true);
                                if(ConvertedAddress == NULL || ConvertedAddress - FileMapVA > FileSize)
                                {
                                    myFileStatusInfo.RelocationTable = UE_FIELD_FIXABLE_NON_CRITICAL;
                                }
                            }
                            SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.RelocationTable, false);
                        }
                        else
                        {
                            myFileStatusInfo.RelocationTable = UE_FIELD_NOT_PRESET;
                        }
                    }
                    /*
                        Import table check
                    */
                    if(PEHeader32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT && PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != NULL)
                    {
                        if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress > CorrectedImageSize)
                        {
                            myFileStatusInfo.ImportTable = UE_FIELD_BROKEN_NON_FIXABLE;
                        }
                        else
                        {
                            ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + PEHeader32->OptionalHeader.ImageBase, false, true);
                            if(ConvertedAddress == NULL || ConvertedAddress - FileMapVA > FileSize)
                            {
                                myFileStatusInfo.ImportTable = UE_FIELD_BROKEN_NON_FIXABLE;
                            }
                            else
                            {
                                SectionNumber = GetPE32SectionNumberFromVA(FileMapVA, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + PEHeader32->OptionalHeader.ImageBase);
                                if(SectionNumber < 0x7FFFFFFF)
                                {
                                    SectionAttributes = (DWORD)GetPE32DataFromMappedFile(FileMapVA, SectionNumber, UE_SECTIONFLAGS);
                                    if(SectionAttributes & IMAGE_SCN_MEM_EXECUTE || SectionAttributes & IMAGE_SCN_CNT_CODE || SectionAttributes & IMAGE_SCN_MEM_WRITE || SectionAttributes & IMAGE_SCN_CNT_INITIALIZED_DATA)
                                    {
                                        myFileStatusInfo.ImportTableSection = UE_FIELD_OK;
                                    }
                                    else
                                    {
                                        myFileStatusInfo.ImportTableSection = UE_FIELD_FIXABLE_CRITICAL;
                                    }
                                    if(CheckDepth == UE_DEPTH_DEEP)
                                    {
                                        if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != NULL)
                                        {
                                            ImportIID = (PIMAGE_IMPORT_DESCRIPTOR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase, (ULONG_PTR)(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + PEHeader32->OptionalHeader.ImageBase), false, true);
                                            while(myFileStatusInfo.ImportTableData == UE_FIELD_OK && ImportIID->FirstThunk != NULL)
                                            {
                                                hLoadedModule = NULL;
                                                ImportNamePtr = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase, (ULONG_PTR)((ULONG_PTR)ImportIID->Name + PEHeader32->OptionalHeader.ImageBase), false, true);
                                                if(ImportNamePtr != NULL)
                                                {
                                                    if(!EngineIsDependencyPresent((char*)ImportNamePtr, NULL, NULL))
                                                    {
                                                        myFileStatusInfo.MissingDependencies = true;
                                                        hLoadedModuleSimulated = false;
                                                    }
                                                    else
                                                    {
                                                        hLoadedModuleSimulated = false;
                                                        hLoadedModule = GetModuleHandleA((char*)ImportNamePtr);
                                                        if(hLoadedModule == NULL)
                                                        {
                                                            hLoadedModule = (HMODULE)EngineSimulateDllLoader(GetCurrentProcess(), (char*)ImportNamePtr);
                                                            hLoadedModuleSimulated = true;
                                                        }
                                                    }
                                                }
                                                else
                                                {
                                                    myFileStatusInfo.ImportTableData = UE_FIELD_BROKEN_NON_FIXABLE;
                                                }
                                                if(ImportIID->OriginalFirstThunk != NULL)
                                                {
                                                    ThunkData32 = (PIMAGE_THUNK_DATA32)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase, (ULONG_PTR)((ULONG_PTR)ImportIID->OriginalFirstThunk + PEHeader32->OptionalHeader.ImageBase), false, true);
                                                    CurrentThunk = (ULONG_PTR)ImportIID->OriginalFirstThunk;
                                                }
                                                else
                                                {
                                                    ThunkData32 = (PIMAGE_THUNK_DATA32)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase, (ULONG_PTR)((ULONG_PTR)ImportIID->FirstThunk + PEHeader32->OptionalHeader.ImageBase), false, true);
                                                    CurrentThunk = (ULONG_PTR)ImportIID->FirstThunk;
                                                }
                                                if(ThunkData32 != NULL)
                                                {
                                                    while(myFileStatusInfo.ImportTableData == UE_FIELD_OK && ThunkData32->u1.AddressOfData != NULL)
                                                    {
                                                        if(ThunkData32->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
                                                        {
                                                            if((int)(ThunkData32->u1.Ordinal ^ IMAGE_ORDINAL_FLAG32) >= 0x10000)
                                                            {
                                                                myFileStatusInfo.ImportTableData = UE_FIELD_BROKEN_NON_FIXABLE;
                                                            }
                                                        }
                                                        else
                                                        {
                                                            ImportNamePtr = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase, (ULONG_PTR)((ULONG_PTR)ThunkData32->u1.AddressOfData + 2 + PEHeader32->OptionalHeader.ImageBase), false, true);
                                                            if(ImportNamePtr != NULL)
                                                            {
                                                                if(!EngineIsValidReadPtrEx((LPVOID)ImportNamePtr, 8))
                                                                {
                                                                    myFileStatusInfo.ImportTableData = UE_FIELD_BROKEN_NON_FIXABLE;
                                                                }
                                                                else
                                                                {
                                                                    if(hLoadedModule != NULL)
                                                                    {
                                                                        if(EngineGetProcAddress((ULONG_PTR)hLoadedModule, (char*)ImportNamePtr) == NULL)
                                                                        {
                                                                            myFileStatusInfo.MissingDeclaredAPIs = true;
                                                                            SetOverallFileStatus(&myFileStatusInfo, UE_FIELD_FIXABLE_CRITICAL, true);
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                            else
                                                            {
                                                                myFileStatusInfo.ImportTableData = UE_FIELD_BROKEN_NON_FIXABLE;
                                                            }
                                                        }
                                                        CurrentThunk = CurrentThunk + 4;
                                                        ThunkData32 = (PIMAGE_THUNK_DATA32)((ULONG_PTR)ThunkData32 + sizeof IMAGE_THUNK_DATA32);
                                                    }
                                                }
                                                else
                                                {
                                                    myFileStatusInfo.ImportTableData = UE_FIELD_BROKEN_NON_FIXABLE;
                                                }
                                                if(hLoadedModuleSimulated)
                                                {
                                                    VirtualFree((LPVOID)hLoadedModule, NULL, MEM_RELEASE);
                                                }
                                                ImportIID = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)ImportIID + sizeof IMAGE_IMPORT_DESCRIPTOR);
                                            }
                                        }
                                    }
                                }
                                else
                                {
                                    myFileStatusInfo.ImportTable = UE_FIELD_BROKEN_NON_FIXABLE;
                                }
                            }
                        }
                        SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.ImportTable, true);
                        SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.ImportTableData, true);
                        SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.ImportTableSection, true);
                    }
                    else
                    {
                        myFileStatusInfo.ImportTable = UE_FIELD_NOT_PRESET;
                    }
                    /*
                        TLS table check
                    */
                    if(PEHeader32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS && PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL)
                    {
                        if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress > CorrectedImageSize || PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size > CorrectedImageSize)
                        {
                            myFileStatusInfo.TLSTable = UE_FIELD_FIXABLE_CRITICAL;
                        }
                        else
                        {
                            ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress + PEHeader32->OptionalHeader.ImageBase, false, true);
                            if(ConvertedAddress == NULL || ConvertedAddress - FileMapVA > FileSize)
                            {
                                myFileStatusInfo.TLSTable = UE_FIELD_FIXABLE_CRITICAL;
                            }
                            else
                            {
                                PETls32 = (PIMAGE_TLS_DIRECTORY32)ConvertedAddress;
                                if(PETls32->StartAddressOfRawData != NULL && (PETls32->StartAddressOfRawData < PEHeader32->OptionalHeader.ImageBase || PETls32->StartAddressOfRawData > CorrectedImageSize + PEHeader32->OptionalHeader.ImageBase))
                                {
                                    myFileStatusInfo.TLSTable = UE_FIELD_FIXABLE_CRITICAL;
                                }
                                else if(PETls32->EndAddressOfRawData != NULL && (PETls32->EndAddressOfRawData < PEHeader32->OptionalHeader.ImageBase || PETls32->EndAddressOfRawData > CorrectedImageSize + PEHeader32->OptionalHeader.ImageBase))
                                {
                                    myFileStatusInfo.TLSTable = UE_FIELD_FIXABLE_CRITICAL;
                                }
                                else if(PETls32->AddressOfIndex != NULL && (PETls32->AddressOfIndex < PEHeader32->OptionalHeader.ImageBase || PETls32->AddressOfIndex > CorrectedImageSize + PEHeader32->OptionalHeader.ImageBase))
                                {
                                    myFileStatusInfo.TLSTable = UE_FIELD_FIXABLE_CRITICAL;
                                }
                                else if(PETls32->AddressOfCallBacks != NULL && (PETls32->AddressOfCallBacks < PEHeader32->OptionalHeader.ImageBase || PETls32->AddressOfCallBacks > CorrectedImageSize + PEHeader32->OptionalHeader.ImageBase))
                                {
                                    myFileStatusInfo.TLSTable = UE_FIELD_FIXABLE_CRITICAL;
                                }
                                if(PETls32->AddressOfCallBacks != NULL && CheckDepth == UE_DEPTH_DEEP)
                                {
                                    ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PETls32->AddressOfCallBacks + PEHeader32->OptionalHeader.ImageBase, false, true);
                                    if(ConvertedAddress != NULL)
                                    {
                                        while(ReadData != NULL)
                                        {
                                            RtlMoveMemory(&ReadData, (LPVOID)ConvertedAddress, 4);
                                            if(ReadData < PEHeader32->OptionalHeader.ImageBase || ReadData > CorrectedImageSize + PEHeader32->OptionalHeader.ImageBase)
                                            {
                                                myFileStatusInfo.TLSTable = UE_FIELD_FIXABLE_CRITICAL;
                                            }
                                            ConvertedAddress = ConvertedAddress + 4;
                                        }
                                    }
                                }
                            }
                        }
                        SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.TLSTable, false);
                    }
                    else
                    {
                        myFileStatusInfo.TLSTable = UE_FIELD_NOT_PRESET;
                    }
                    /*
                        Load config table check
                    */
                    if(PEHeader32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG && PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress != NULL)
                    {
                        if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress > CorrectedImageSize || PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size > CorrectedImageSize)
                        {
                            myFileStatusInfo.LoadConfigTable = UE_FIELD_FIXABLE_CRITICAL;
                        }
                        else
                        {
                            ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress + PEHeader32->OptionalHeader.ImageBase, false, true);
                            if(ConvertedAddress == NULL || ConvertedAddress - FileMapVA > FileSize)
                            {
                                myFileStatusInfo.LoadConfigTable = UE_FIELD_FIXABLE_CRITICAL;
                            }
                        }
                    }
                    else
                    {
                        myFileStatusInfo.LoadConfigTable = UE_FIELD_NOT_PRESET;
                    }
                    SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.LoadConfigTable, false);
                    /*
                        Bound import table check
                    */
                    if(PEHeader32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT && PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress != NULL)
                    {
                        if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress > CorrectedImageSize || PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size > CorrectedImageSize)
                        {
                            myFileStatusInfo.BoundImportTable = UE_FIELD_FIXABLE_CRITICAL;
                        }
                        else
                        {
                            ConvertedAddress = (ULONG_PTR)PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress + FileMapVA;
                            if(ConvertedAddress == NULL || ConvertedAddress - FileMapVA > FileSize)
                            {
                                myFileStatusInfo.BoundImportTable = UE_FIELD_FIXABLE_CRITICAL;
                            }
                            else
                            {
                                BoundIID = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)ConvertedAddress;
                                while(BoundIID->TimeDateStamp != NULL)
                                {
                                    if(BoundIID->OffsetModuleName > PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size)
                                    {
                                        myFileStatusInfo.BoundImportTable = UE_FIELD_FIXABLE_CRITICAL;
                                    }
                                    else if(!EngineIsPointedMemoryString(ConvertedAddress + BoundIID->OffsetModuleName))
                                    {
                                        myFileStatusInfo.BoundImportTable = UE_FIELD_FIXABLE_CRITICAL;
                                    }
                                    BoundIID = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((ULONG_PTR)BoundIID + sizeof IMAGE_BOUND_IMPORT_DESCRIPTOR);
                                }
                            }
                        }
                    }
                    else
                    {
                        myFileStatusInfo.BoundImportTable = UE_FIELD_NOT_PRESET;
                    }
                    SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.BoundImportTable, false);
                    /*
                        IAT check
                    */
                    if(PEHeader32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IAT && PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress != NULL)
                    {
                        if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress > CorrectedImageSize || PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size > CorrectedImageSize)
                        {
                            myFileStatusInfo.IATTable = UE_FIELD_FIXABLE_NON_CRITICAL;
                        }
                        else
                        {
                            ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress + PEHeader32->OptionalHeader.ImageBase, false, true);
                            if(ConvertedAddress == NULL || ConvertedAddress - FileMapVA > FileSize)
                            {
                                myFileStatusInfo.IATTable = UE_FIELD_FIXABLE_NON_CRITICAL;
                            }
                        }
                    }
                    else
                    {
                        myFileStatusInfo.IATTable = UE_FIELD_NOT_PRESET;
                    }
                    SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.IATTable, false);
                    /*
                        COM header check
                    */
                    if(PEHeader32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR && PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != NULL)
                    {
                        if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress > CorrectedImageSize || PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size > CorrectedImageSize)
                        {
                            myFileStatusInfo.COMHeaderTable = UE_FIELD_FIXABLE_NON_CRITICAL;
                        }
                        else
                        {
                            ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress + PEHeader32->OptionalHeader.ImageBase, false, true);
                            if(ConvertedAddress == NULL || ConvertedAddress - FileMapVA > FileSize)
                            {
                                myFileStatusInfo.COMHeaderTable = UE_FIELD_FIXABLE_NON_CRITICAL;
                            }
                        }
                    }
                    else
                    {
                        myFileStatusInfo.COMHeaderTable = UE_FIELD_NOT_PRESET;
                    }
                    SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.COMHeaderTable, false);
                    /*
                        Resource header check
                    */
                    if(PEHeader32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_RESOURCE && PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress != NULL)
                    {
                        if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress > CorrectedImageSize || PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size > CorrectedImageSize)
                        {
                            myFileStatusInfo.ResourceTable = UE_FIELD_FIXABLE_NON_CRITICAL;
                        }
                        else
                        {
                            ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress + PEHeader32->OptionalHeader.ImageBase, false, true);
                            if(ConvertedAddress == NULL || ConvertedAddress - FileMapVA > FileSize || ConvertedAddress - FileMapVA + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size > FileSize)
                            {
                                myFileStatusInfo.ResourceTable = UE_FIELD_BROKEN_BUT_CAN_BE_EMULATED;
                            }
                            if(CheckDepth == UE_DEPTH_DEEP)
                            {
                                hSimulatedFileLoad = (ULONG_PTR)EngineSimulateNtLoaderW(szFileName);
                                if(hSimulatedFileLoad != NULL)
                                {
                                    for(i = 0; i < 22; i++)
                                    {
                                        if(myFileStatusInfo.ResourceData == UE_FIELD_OK)
                                        {
                                            EnumResourceNamesA((HMODULE)hSimulatedFileLoad, MAKEINTRESOURCEA(ResourceNamesTable[i]), (ENUMRESNAMEPROCA)EngineValidateResource, (ULONG_PTR)&myFileStatusInfo.ResourceData);
                                        }
                                        else
                                        {
                                            i = 22;
                                        }
                                    }
                                    VirtualFree((LPVOID)hSimulatedFileLoad, NULL, MEM_RELEASE);
                                }
                            }
                        }
                        if(myFileStatusInfo.ResourceTable == UE_FIELD_BROKEN_BUT_CAN_BE_EMULATED && myFileStatusInfo.ResourceData == UE_FIELD_OK)
                        {
                            myFileStatusInfo.ResourceTable = UE_FIELD_OK;
                        }
                        SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.ResourceTable, true);
                    }
                    else
                    {
                        myFileStatusInfo.ResourceTable = UE_FIELD_NOT_PRESET;
                    }
                    /*
                        Section check
                    */
                    PESections = IMAGE_FIRST_SECTION(PEHeader32);
                    NumberOfSections = PEHeader32->FileHeader.NumberOfSections;
                    while(NumberOfSections > NULL)
                    {
                        SectionVirtualSize = PESections->VirtualAddress + PESections->Misc.VirtualSize;
                        if(PESections->Misc.VirtualSize % PEHeader32->OptionalHeader.SectionAlignment == NULL)
                        {
                            SectionVirtualSizeFixed = SectionVirtualSize;
                        }
                        else
                        {
                            SectionVirtualSizeFixed = PESections->VirtualAddress + (((PESections->Misc.VirtualSize / PEHeader32->OptionalHeader.SectionAlignment) + 1) * PEHeader32->OptionalHeader.SectionAlignment);
                        }
                        if(NumberOfSections > 1)
                        {
                            PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + sizeof IMAGE_SECTION_HEADER);
                            if(SectionVirtualSize > PESections->VirtualAddress || SectionVirtualSizeFixed > PESections->VirtualAddress)
                            {
                                myFileStatusInfo.SectionTable = UE_FIELD_FIXABLE_CRITICAL;
                            }
                        }
                        NumberOfSections--;
                    }
                    if(PESections->PointerToRawData + PESections->SizeOfRawData > FileSize && PESections->SizeOfRawData != NULL)
                    {
                        myFileStatusInfo.SectionTable = UE_FIELD_BROKEN_NON_FIXABLE;
                    }
                    SectionVirtualSizeFixed = SectionVirtualSizeFixed + 0xF000;
                    if(PEHeader32->OptionalHeader.SizeOfImage > SectionVirtualSizeFixed)
                    {
                        myFileStatusInfo.SizeOfImage = UE_FIELD_FIXABLE_CRITICAL;
                    }
                    SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.SizeOfImage, true);
                    SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.SectionTable, true);
                    /*
                        Entry point check
                    */
                    SectionNumber = GetPE32SectionNumberFromVA(FileMapVA, PEHeader32->OptionalHeader.AddressOfEntryPoint + PEHeader32->OptionalHeader.ImageBase);
                    if(SectionNumber != -1)
                    {
                        SectionAttributes = (DWORD)GetPE32DataFromMappedFile(FileMapVA, SectionNumber, UE_SECTIONFLAGS);
                        if(SectionAttributes & IMAGE_SCN_MEM_EXECUTE || SectionAttributes & IMAGE_SCN_CNT_CODE)
                        {
                            myFileStatusInfo.EntryPoint = UE_FIELD_OK;
                        }
                        else
                        {
                            myFileStatusInfo.EntryPoint = UE_FIELD_BROKEN_NON_CRITICAL;
                        }
                    }
                    ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader32->OptionalHeader.AddressOfEntryPoint + PEHeader32->OptionalHeader.ImageBase, false, true);
                    if(ConvertedAddress == NULL)
                    {
                        myFileStatusInfo.EntryPoint = UE_FIELD_BROKEN_NON_FIXABLE;
                    }
                    else
                    {
                        ReadData = NULL;
                        if(memcmp(&ReadData, (LPVOID)ConvertedAddress, 4) == NULL)
                        {
                            myFileStatusInfo.EntryPoint = UE_FIELD_BROKEN_NON_FIXABLE;
                        }
                    }
                    SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.EntryPoint, true);
                    /*
                        Return data
                    */
                    if(FileStatusInfo != NULL)
                    {
                        RtlMoveMemory(FileStatusInfo, &myFileStatusInfo, sizeof FILE_STATUS_INFO);
                    }
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    if(myFileStatusInfo.OveralEvaluation == UE_RESULT_FILE_OK)
                    {
                        return true;
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    myFileStatusInfo.EvaluationTerminatedByException = true;
                    myFileStatusInfo.OveralEvaluation = UE_RESULT_FILE_INVALID_FORMAT;
                    myFileStatusInfo.SignaturePE = UE_FIELD_BROKEN_NON_FIXABLE;
                    if(FileStatusInfo != NULL)
                    {
                        RtlMoveMemory(FileStatusInfo, &myFileStatusInfo, sizeof FILE_STATUS_INFO);
                    }
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return false;
                }
            }
            else
            {
                /*
                    x64 Surface check
                */
                __try
                {
                    if(PEHeader64->OptionalHeader.SizeOfImage % PEHeader64->OptionalHeader.SectionAlignment == NULL)
                    {
                        CorrectedImageSize = ((PEHeader64->OptionalHeader.SizeOfImage / PEHeader64->OptionalHeader.SectionAlignment)) * PEHeader64->OptionalHeader.SectionAlignment;
                    }
                    else
                    {
                        CorrectedImageSize = ((PEHeader64->OptionalHeader.SizeOfImage / PEHeader64->OptionalHeader.SectionAlignment) + 1) * PEHeader64->OptionalHeader.SectionAlignment;
                    }
                    if(PEHeader64->OptionalHeader.SectionAlignment != NULL && PEHeader64->OptionalHeader.SectionAlignment >= PEHeader64->OptionalHeader.FileAlignment)
                    {
                        myFileStatusInfo.SectionAlignment = UE_FIELD_OK;
                        if(PEHeader64->OptionalHeader.SizeOfImage % PEHeader64->OptionalHeader.SectionAlignment == NULL)
                        {
                            myFileStatusInfo.SizeOfImage = UE_FIELD_OK;
                        }
                        else
                        {
                            if(CorrectedImageSize < PEHeader64->OptionalHeader.AddressOfEntryPoint)
                            {
                                myFileStatusInfo.SizeOfImage = UE_FIELD_BROKEN_NON_FIXABLE;
                            }
                            else
                            {
                                myFileStatusInfo.SizeOfImage = UE_FIELD_FIXABLE_NON_CRITICAL;
                            }
                        }
                    }
                    else
                    {
                        myFileStatusInfo.SectionAlignment = UE_FIELD_FIXABLE_CRITICAL;
                    }
                    SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.SectionAlignment, true);
                    if((ULONG_PTR)PEHeader64->OptionalHeader.ImageBase % 0x1000 == NULL)
                    {
                        myFileStatusInfo.ImageBase = UE_FIELD_OK;
                    }
                    else
                    {
                        myFileStatusInfo.ImageBase = UE_FIELD_BROKEN_NON_FIXABLE;
                    }
                    SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.ImageBase, true);
                    if(PEHeader64->OptionalHeader.FileAlignment % 2 == NULL)
                    {
                        myFileStatusInfo.FileAlignment = UE_FIELD_OK;
                    }
                    else
                    {
                        myFileStatusInfo.FileAlignment = UE_FIELD_FIXABLE_CRITICAL;
                    }
                    SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.FileAlignment, false);
                    /*
                        Get the console flag
                    */
                    if(PEHeader64->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI)
                    {
                        myFileStatusInfo.FileIsConsole = true;
                    }
                    /*
                        Export and relocation checks [for DLL and EXE]
                    */
                    if(PEHeader64->FileHeader.Characteristics & 0x2000)
                    {
                        /*
                            Export table check
                        */
                        FileIsDLL = true;
                        myFileStatusInfo.FileIsDLL = true;
                        if(PEHeader64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT && PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != NULL)
                        {
                            if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress > CorrectedImageSize || PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size > CorrectedImageSize)
                            {
                                myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_FIXABLE;
                            }
                            else
                            {
                                ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, false, true);
                                if(ConvertedAddress != NULL)
                                {
                                    if(EngineIsValidReadPtrEx((LPVOID)ConvertedAddress, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size))
                                    {
                                        PEExports = (PIMAGE_EXPORT_DIRECTORY)ConvertedAddress;
                                        if(PEExports->AddressOfFunctions > CorrectedImageSize || PEExports->AddressOfFunctions + 4 * PEExports->NumberOfFunctions > CorrectedImageSize)
                                        {
                                            myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_FIXABLE;
                                        }
                                        else if(PEExports->AddressOfNameOrdinals > CorrectedImageSize || PEExports->AddressOfNameOrdinals + 4 * PEExports->NumberOfNames > CorrectedImageSize)
                                        {
                                            myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_FIXABLE;
                                        }
                                        else if(PEExports->AddressOfNames > CorrectedImageSize || PEExports->AddressOfNames + 4 * PEExports->NumberOfNames > CorrectedImageSize)
                                        {
                                            myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_FIXABLE;
                                        }
                                        else if(PEExports->Name > CorrectedImageSize)
                                        {
                                            myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_FIXABLE;
                                        }
                                        else
                                        {
                                            if(CheckDepth == UE_DEPTH_DEEP)
                                            {
                                                ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEExports->AddressOfFunctions + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, false, true);
                                                if(ConvertedAddress != NULL)
                                                {
                                                    for(i = 0; i < PEExports->NumberOfFunctions; i++)
                                                    {
                                                        RtlMoveMemory(&ReadData, (LPVOID)ConvertedAddress, 4);
                                                        if(ReadData > CorrectedImageSize || ReadData < PEHeader64->OptionalHeader.SectionAlignment)
                                                        {
                                                            myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_FIXABLE;
                                                            i = PEExports->NumberOfFunctions;
                                                        }
                                                        else
                                                        {
                                                            ConvertedAddress = ConvertedAddress + 4;
                                                        }
                                                    }
                                                }
                                                else
                                                {
                                                    myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_FIXABLE;
                                                }
                                                ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEExports->AddressOfNames + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, false, true);
                                                if(ConvertedAddress != NULL)
                                                {
                                                    for(i = 0; i < PEExports->NumberOfNames; i++)
                                                    {
                                                        RtlMoveMemory(&ReadData, (LPVOID)ConvertedAddress, 4);
                                                        if(ReadData > CorrectedImageSize || ReadData < PEHeader64->OptionalHeader.SectionAlignment)
                                                        {
                                                            myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_FIXABLE;
                                                            i = PEExports->NumberOfNames;
                                                        }
                                                        else
                                                        {
                                                            ConvertedAddress = ConvertedAddress + 4;
                                                        }
                                                    }
                                                }
                                                else
                                                {
                                                    myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_FIXABLE;
                                                }
                                            }
                                        }
                                    }
                                    else
                                    {
                                        myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_FIXABLE;
                                    }
                                }
                                else
                                {
                                    myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_FIXABLE;
                                }
                            }
                            SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.ExportTable, true);
                        }
                        else
                        {
                            myFileStatusInfo.ExportTable = UE_FIELD_NOT_PRESET;
                        }
                        /*
                            Relocation table check
                        */
                        if(PEHeader64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC && PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != NULL)
                        {
                            if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress > CorrectedImageSize || PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > CorrectedImageSize)
                            {
                                myFileStatusInfo.RelocationTable = UE_FIELD_BROKEN_NON_FIXABLE;
                            }
                            else
                            {
                                ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, false, true);
                                if(ConvertedAddress != NULL)
                                {
                                    if(EngineIsValidReadPtrEx((LPVOID)ConvertedAddress, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size))
                                    {
                                        RtlMoveMemory(&ReadData, (LPVOID)ConvertedAddress, 4);
                                        RtlMoveMemory(&ReadSize, (LPVOID)(ConvertedAddress + 4), 4);
                                        while(ReadData != NULL)
                                        {
                                            ReadSize = ReadSize - 8;
                                            ConvertedAddress = ConvertedAddress + 8;
                                            while(ReadSize > NULL)
                                            {
                                                RtlMoveMemory(&ReadDataWORD, (LPVOID)ConvertedAddress, 2);
                                                if(ReadDataWORD > 0xCFFF)
                                                {
                                                    myFileStatusInfo.RelocationTable = UE_FIELD_BROKEN_FIXABLE_FOR_STATIC_USE;
                                                }
                                                ConvertedAddress = ConvertedAddress + 2;
                                                ReadSize = ReadSize - 2;
                                            }
                                            RtlMoveMemory(&ReadData, (LPVOID)ConvertedAddress, 4);
                                            RtlMoveMemory(&ReadSize, (LPVOID)(ConvertedAddress + 4), 4);
                                        }
                                    }
                                    else
                                    {
                                        myFileStatusInfo.RelocationTable = UE_FIELD_BROKEN_FIXABLE_FOR_STATIC_USE;
                                    }
                                }
                                else
                                {
                                    myFileStatusInfo.RelocationTable = UE_FIELD_BROKEN_FIXABLE_FOR_STATIC_USE;
                                }
                            }
                            SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.RelocationTable, true);
                        }
                        else
                        {
                            myFileStatusInfo.RelocationTable = UE_FIELD_NOT_PRESET_WARNING;
                        }
                    }
                    else
                    {
                        /*
                            Export table check
                        */
                        if(PEHeader64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT && PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != NULL)
                        {
                            if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress > CorrectedImageSize || PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size > CorrectedImageSize)
                            {
                                myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_CRITICAL;
                            }
                            else
                            {
                                ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, false, true);
                                if(ConvertedAddress != NULL)
                                {
                                    if(EngineIsValidReadPtrEx((LPVOID)ConvertedAddress, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size))
                                    {
                                        PEExports = (PIMAGE_EXPORT_DIRECTORY)ConvertedAddress;
                                        if(PEExports->AddressOfFunctions > CorrectedImageSize || PEExports->AddressOfFunctions + 4 * PEExports->NumberOfFunctions > CorrectedImageSize)
                                        {
                                            myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_CRITICAL;
                                        }
                                        else if(PEExports->AddressOfNameOrdinals > CorrectedImageSize || PEExports->AddressOfNameOrdinals + 4 * PEExports->NumberOfNames > CorrectedImageSize)
                                        {
                                            myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_CRITICAL;
                                        }
                                        else if(PEExports->AddressOfNames > CorrectedImageSize || PEExports->AddressOfNames + 4 * PEExports->NumberOfNames > CorrectedImageSize)
                                        {
                                            myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_CRITICAL;
                                        }
                                        else if(PEExports->Name > CorrectedImageSize)
                                        {
                                            myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_CRITICAL;
                                        }
                                    }
                                    else
                                    {
                                        myFileStatusInfo.ExportTable = UE_FIELD_BROKEN_NON_CRITICAL;
                                    }
                                }
                            }
                            SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.ExportTable, false);
                        }
                        else
                        {
                            myFileStatusInfo.ExportTable = UE_FIELD_NOT_PRESET;
                        }
                        /*
                            Relocation table check
                        */
                        if(PEHeader64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC && PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != NULL)
                        {
                            if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress > CorrectedImageSize || PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > CorrectedImageSize)
                            {
                                myFileStatusInfo.RelocationTable = UE_FIELD_BROKEN_NON_FIXABLE;
                            }
                            else
                            {
                                ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, false, true);
                                if(ConvertedAddress == NULL || ConvertedAddress - FileMapVA > FileSize)
                                {
                                    myFileStatusInfo.RelocationTable = UE_FIELD_FIXABLE_NON_CRITICAL;
                                }
                            }
                            SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.RelocationTable, false);
                        }
                        else
                        {
                            myFileStatusInfo.RelocationTable = UE_FIELD_NOT_PRESET;
                        }
                    }
                    /*
                        Import table check
                    */
                    if(PEHeader64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT && PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != NULL)
                    {
                        if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress > CorrectedImageSize)
                        {
                            myFileStatusInfo.ImportTable = UE_FIELD_BROKEN_NON_FIXABLE;
                        }
                        else
                        {
                            ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, false, true);
                            if(ConvertedAddress == NULL || ConvertedAddress - FileMapVA > FileSize)
                            {
                                myFileStatusInfo.ImportTable = UE_FIELD_BROKEN_NON_FIXABLE;
                            }
                            else
                            {
                                SectionNumber = GetPE32SectionNumberFromVA(FileMapVA, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase);
                                if(SectionNumber >= NULL)
                                {
                                    SectionAttributes = (DWORD)GetPE32DataFromMappedFile(FileMapVA, SectionNumber, UE_SECTIONFLAGS);
                                    if(SectionAttributes & IMAGE_SCN_MEM_EXECUTE || SectionAttributes & IMAGE_SCN_CNT_CODE || SectionAttributes & IMAGE_SCN_MEM_WRITE || SectionAttributes & IMAGE_SCN_CNT_INITIALIZED_DATA)
                                    {
                                        myFileStatusInfo.ImportTableSection = UE_FIELD_OK;
                                    }
                                    else
                                    {
                                        myFileStatusInfo.ImportTableSection = UE_FIELD_FIXABLE_CRITICAL;
                                    }
                                    if(CheckDepth == UE_DEPTH_DEEP)
                                    {
                                        if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != NULL)
                                        {
                                            ImportIID = (PIMAGE_IMPORT_DESCRIPTOR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, (ULONG_PTR)(ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, (ULONG_PTR)(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase), false, true);
                                            while(myFileStatusInfo.ImportTableData == UE_FIELD_OK && ImportIID->FirstThunk != NULL)
                                            {
                                                hLoadedModule = NULL;
                                                ImportNamePtr = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, (ULONG_PTR)(ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, (ULONG_PTR)((ULONG_PTR)ImportIID->Name + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase), false, true);
                                                if(ImportNamePtr != NULL)
                                                {
                                                    if(!EngineIsDependencyPresent((char*)ImportNamePtr, NULL, NULL))
                                                    {
                                                        myFileStatusInfo.MissingDependencies = true;
                                                        hLoadedModuleSimulated = false;
                                                    }
                                                    else
                                                    {
                                                        hLoadedModuleSimulated = false;
                                                        hLoadedModule = GetModuleHandleA((char*)ImportNamePtr);
                                                        if(hLoadedModule == NULL)
                                                        {
                                                            hLoadedModule = (HMODULE)EngineSimulateDllLoader(GetCurrentProcess(), (char*)ImportNamePtr);
                                                            hLoadedModuleSimulated = true;
                                                        }
                                                    }
                                                }
                                                else
                                                {
                                                    myFileStatusInfo.ImportTableData = UE_FIELD_BROKEN_NON_FIXABLE;
                                                }
                                                if(ImportIID->OriginalFirstThunk != NULL)
                                                {
                                                    ThunkData64 = (PIMAGE_THUNK_DATA64)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, (ULONG_PTR)((ULONG_PTR)ImportIID->OriginalFirstThunk + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase), false, true);
                                                    CurrentThunk = (ULONG_PTR)ImportIID->OriginalFirstThunk;
                                                }
                                                else
                                                {
                                                    ThunkData32 = (PIMAGE_THUNK_DATA32)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase, (ULONG_PTR)((ULONG_PTR)ImportIID->FirstThunk + PEHeader32->OptionalHeader.ImageBase), false, true);
                                                    CurrentThunk = (ULONG_PTR)ImportIID->FirstThunk;
                                                }
                                                if(ThunkData64 != NULL)
                                                {
                                                    while(myFileStatusInfo.ImportTableData == UE_FIELD_OK && ThunkData64->u1.AddressOfData != NULL)
                                                    {
                                                        if(ThunkData64->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                                                        {
                                                            if((int)(ThunkData64->u1.Ordinal ^ IMAGE_ORDINAL_FLAG64) >= 0x10000)
                                                            {
                                                                myFileStatusInfo.ImportTableData = UE_FIELD_BROKEN_NON_FIXABLE;
                                                            }
                                                        }
                                                        else
                                                        {
                                                            ImportNamePtr = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, (ULONG_PTR)(ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, (ULONG_PTR)((ULONG_PTR)ThunkData64->u1.AddressOfData + 2 + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase), false, true);
                                                            if(ImportNamePtr != NULL)
                                                            {
                                                                if(!EngineIsValidReadPtrEx((LPVOID)ImportNamePtr, 8))
                                                                {
                                                                    myFileStatusInfo.ImportTableData = UE_FIELD_BROKEN_NON_FIXABLE;
                                                                }
                                                                else
                                                                {
                                                                    if(hLoadedModule != NULL)
                                                                    {
                                                                        if(EngineGetProcAddress((ULONG_PTR)hLoadedModule, (char*)ImportNamePtr) == NULL)
                                                                        {
                                                                            myFileStatusInfo.MissingDeclaredAPIs = true;
                                                                            SetOverallFileStatus(&myFileStatusInfo, UE_FIELD_FIXABLE_CRITICAL, true);
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                            else
                                                            {
                                                                myFileStatusInfo.ImportTableData = UE_FIELD_BROKEN_NON_FIXABLE;
                                                            }
                                                        }
                                                        CurrentThunk = CurrentThunk + 8;
                                                        ThunkData64 = (PIMAGE_THUNK_DATA64)((ULONG_PTR)ThunkData64 + sizeof IMAGE_THUNK_DATA64);
                                                    }
                                                }
                                                else
                                                {
                                                    myFileStatusInfo.ImportTableData = UE_FIELD_BROKEN_NON_FIXABLE;
                                                }
                                                if(hLoadedModuleSimulated)
                                                {
                                                    VirtualFree((LPVOID)hLoadedModule, NULL, MEM_RELEASE);
                                                }
                                                ImportIID = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)ImportIID + sizeof IMAGE_IMPORT_DESCRIPTOR);
                                            }
                                        }
                                    }
                                }
                                else
                                {
                                    myFileStatusInfo.ImportTable = UE_FIELD_BROKEN_NON_FIXABLE;
                                }
                            }
                        }
                        SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.ImportTable, true);
                        SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.ImportTableData, true);
                        SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.ImportTableSection, true);
                    }
                    else
                    {
                        myFileStatusInfo.ImportTable = UE_FIELD_NOT_PRESET;
                    }
                    /*
                        TLS table check
                    */
                    if(PEHeader64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS && PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL)
                    {
                        if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress > CorrectedImageSize || PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size > CorrectedImageSize)
                        {
                            myFileStatusInfo.TLSTable = UE_FIELD_FIXABLE_CRITICAL;
                        }
                        else
                        {
                            ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, false, true);
                            if(ConvertedAddress == NULL || ConvertedAddress - FileMapVA > FileSize)
                            {
                                myFileStatusInfo.TLSTable = UE_FIELD_FIXABLE_CRITICAL;
                            }
                            else
                            {
                                PETls64 = (PIMAGE_TLS_DIRECTORY64)ConvertedAddress;
                                if(PETls64->StartAddressOfRawData != NULL && (PETls64->StartAddressOfRawData < (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase || PETls64->StartAddressOfRawData > CorrectedImageSize + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase))
                                {
                                    myFileStatusInfo.TLSTable = UE_FIELD_FIXABLE_CRITICAL;
                                }
                                else if(PETls64->EndAddressOfRawData != NULL && (PETls64->EndAddressOfRawData < (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase || PETls64->EndAddressOfRawData > CorrectedImageSize + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase))
                                {
                                    myFileStatusInfo.TLSTable = UE_FIELD_FIXABLE_CRITICAL;
                                }
                                else if(PETls64->AddressOfIndex != NULL && (PETls64->AddressOfIndex < (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase || PETls64->AddressOfIndex > CorrectedImageSize + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase))
                                {
                                    myFileStatusInfo.TLSTable = UE_FIELD_FIXABLE_CRITICAL;
                                }
                                else if(PETls64->AddressOfCallBacks != NULL && (PETls64->AddressOfCallBacks < (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase || PETls64->AddressOfCallBacks > CorrectedImageSize + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase))
                                {
                                    myFileStatusInfo.TLSTable = UE_FIELD_FIXABLE_CRITICAL;
                                }
                                if(PETls64->AddressOfCallBacks != NULL && CheckDepth == UE_DEPTH_DEEP)
                                {
                                    ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, (ULONG_PTR)PETls64->AddressOfCallBacks + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, false, true);
                                    if(ConvertedAddress != NULL)
                                    {
                                        while(ReadData != NULL)
                                        {
                                            RtlMoveMemory(&ReadData, (LPVOID)ConvertedAddress, 8);
                                            if(ReadData < (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase || ReadData > CorrectedImageSize + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase)
                                            {
                                                myFileStatusInfo.TLSTable = UE_FIELD_FIXABLE_CRITICAL;
                                            }
                                            ConvertedAddress = ConvertedAddress + 8;
                                        }
                                    }
                                }
                            }
                        }
                        SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.TLSTable, false);
                    }
                    else
                    {
                        myFileStatusInfo.TLSTable = UE_FIELD_NOT_PRESET;
                    }
                    /*
                        Load config table check
                    */
                    if(PEHeader64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG && PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress != NULL)
                    {
                        if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress > CorrectedImageSize || PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size > CorrectedImageSize)
                        {
                            myFileStatusInfo.LoadConfigTable = UE_FIELD_FIXABLE_CRITICAL;
                        }
                        else
                        {
                            ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, false, true);
                            if(ConvertedAddress == NULL || ConvertedAddress - FileMapVA > FileSize)
                            {
                                myFileStatusInfo.LoadConfigTable = UE_FIELD_FIXABLE_CRITICAL;
                            }
                        }
                    }
                    else
                    {
                        myFileStatusInfo.LoadConfigTable = UE_FIELD_NOT_PRESET;
                    }
                    SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.LoadConfigTable, false);
                    /*
                        Bound import table check
                    */
                    if(PEHeader64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT && PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress != NULL)
                    {
                        if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress > CorrectedImageSize || PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size > CorrectedImageSize)
                        {
                            myFileStatusInfo.BoundImportTable = UE_FIELD_FIXABLE_CRITICAL;
                        }
                        else
                        {
                            ConvertedAddress = (ULONG_PTR)PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress + FileMapVA;
                            if(ConvertedAddress == NULL || ConvertedAddress - FileMapVA > FileSize)
                            {
                                myFileStatusInfo.BoundImportTable = UE_FIELD_FIXABLE_CRITICAL;
                            }
                            else
                            {
                                BoundIID = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)ConvertedAddress;
                                while(BoundIID->TimeDateStamp != NULL)
                                {
                                    if(BoundIID->OffsetModuleName > PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size)
                                    {
                                        myFileStatusInfo.BoundImportTable = UE_FIELD_FIXABLE_CRITICAL;
                                    }
                                    else if(!EngineIsPointedMemoryString(ConvertedAddress + BoundIID->OffsetModuleName))
                                    {
                                        myFileStatusInfo.BoundImportTable = UE_FIELD_FIXABLE_CRITICAL;
                                    }
                                    BoundIID = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((ULONG_PTR)BoundIID + sizeof IMAGE_BOUND_IMPORT_DESCRIPTOR);
                                }
                            }
                        }
                    }
                    else
                    {
                        myFileStatusInfo.BoundImportTable = UE_FIELD_NOT_PRESET;
                    }
                    SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.BoundImportTable, false);
                    /*
                        IAT check
                    */
                    if(PEHeader64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IAT && PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress != NULL)
                    {
                        if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress > CorrectedImageSize || PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size > CorrectedImageSize)
                        {
                            myFileStatusInfo.IATTable = UE_FIELD_FIXABLE_NON_CRITICAL;
                        }
                        else
                        {
                            ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, false, true);
                            if(ConvertedAddress == NULL || ConvertedAddress - FileMapVA > FileSize)
                            {
                                myFileStatusInfo.IATTable = UE_FIELD_FIXABLE_NON_CRITICAL;
                            }
                        }
                    }
                    else
                    {
                        myFileStatusInfo.IATTable = UE_FIELD_NOT_PRESET;
                    }
                    SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.IATTable, false);
                    /*
                        COM header check
                    */
                    if(PEHeader64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR && PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != NULL)
                    {
                        if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress > CorrectedImageSize || PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size > CorrectedImageSize)
                        {
                            myFileStatusInfo.COMHeaderTable = UE_FIELD_FIXABLE_NON_CRITICAL;
                        }
                        else
                        {
                            ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, false, true);
                            if(ConvertedAddress == NULL || ConvertedAddress - FileMapVA > FileSize)
                            {
                                myFileStatusInfo.COMHeaderTable = UE_FIELD_FIXABLE_NON_CRITICAL;
                            }
                        }
                    }
                    else
                    {
                        myFileStatusInfo.COMHeaderTable = UE_FIELD_NOT_PRESET;
                    }
                    SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.COMHeaderTable, false);
                    /*
                        Resource header check
                    */
                    if(PEHeader64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_RESOURCE && PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress != NULL)
                    {
                        if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress > CorrectedImageSize || PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size > CorrectedImageSize)
                        {
                            myFileStatusInfo.ResourceTable = UE_FIELD_FIXABLE_NON_CRITICAL;
                        }
                        else
                        {
                            ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, false, true);
                            if(ConvertedAddress == NULL || ConvertedAddress - FileMapVA > FileSize || ConvertedAddress - FileMapVA + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size > FileSize)
                            {
                                myFileStatusInfo.ResourceTable = UE_FIELD_BROKEN_BUT_CAN_BE_EMULATED;
                            }
                            if(CheckDepth == UE_DEPTH_DEEP)
                            {
                                hSimulatedFileLoad = (ULONG_PTR)EngineSimulateNtLoaderW(szFileName);
                                if(hSimulatedFileLoad != NULL)
                                {
                                    for(i = 0; i < 22; i++)
                                    {
                                        if(myFileStatusInfo.ResourceData == UE_FIELD_OK)
                                        {
                                            EnumResourceNamesA((HMODULE)hSimulatedFileLoad, MAKEINTRESOURCEA(ResourceNamesTable[i]), (ENUMRESNAMEPROCA)EngineValidateResource, (ULONG_PTR)&myFileStatusInfo.ResourceData);
                                        }
                                        else
                                        {
                                            i = 22;
                                        }
                                    }
                                    VirtualFree((LPVOID)hSimulatedFileLoad, NULL, MEM_RELEASE);
                                }
                            }
                        }
                        if(myFileStatusInfo.ResourceTable == UE_FIELD_BROKEN_BUT_CAN_BE_EMULATED && myFileStatusInfo.ResourceData == UE_FIELD_OK)
                        {
                            myFileStatusInfo.ResourceTable = UE_FIELD_OK;
                        }
                        SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.ResourceTable, true);
                    }
                    else
                    {
                        myFileStatusInfo.ResourceTable = UE_FIELD_NOT_PRESET;
                    }
                    /*
                        Section check
                    */
                    PESections = IMAGE_FIRST_SECTION(PEHeader64);
                    NumberOfSections = PEHeader64->FileHeader.NumberOfSections;
                    while(NumberOfSections > NULL)
                    {
                        SectionVirtualSize = PESections->VirtualAddress + PESections->Misc.VirtualSize;
                        if(PESections->Misc.VirtualSize % PEHeader64->OptionalHeader.SectionAlignment == NULL)
                        {
                            SectionVirtualSizeFixed = SectionVirtualSize;
                        }
                        else
                        {
                            SectionVirtualSizeFixed = PESections->VirtualAddress + (((PESections->Misc.VirtualSize / PEHeader64->OptionalHeader.SectionAlignment) + 1) * PEHeader64->OptionalHeader.SectionAlignment);
                        }
                        if(NumberOfSections > 1)
                        {
                            PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + sizeof IMAGE_SECTION_HEADER);
                            if(SectionVirtualSize > PESections->VirtualAddress || SectionVirtualSizeFixed > PESections->VirtualAddress)
                            {
                                myFileStatusInfo.SectionTable = UE_FIELD_FIXABLE_CRITICAL;
                            }
                        }
                        NumberOfSections--;
                    }
                    if(PESections->PointerToRawData + PESections->SizeOfRawData > FileSize && PESections->SizeOfRawData != NULL)
                    {
                        myFileStatusInfo.SectionTable = UE_FIELD_BROKEN_NON_FIXABLE;
                    }
                    SectionVirtualSizeFixed = SectionVirtualSizeFixed + 0xF000;
                    if(PEHeader64->OptionalHeader.SizeOfImage > SectionVirtualSizeFixed)
                    {
                        myFileStatusInfo.SizeOfImage = UE_FIELD_FIXABLE_CRITICAL;
                    }
                    SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.SizeOfImage, true);
                    SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.SectionTable, true);
                    /*
                        Entry point check
                    */
                    SectionNumber = GetPE32SectionNumberFromVA(FileMapVA, PEHeader64->OptionalHeader.AddressOfEntryPoint + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase);
                    if(SectionNumber != -1)
                    {
                        SectionAttributes = (DWORD)GetPE32DataFromMappedFile(FileMapVA, SectionNumber, UE_SECTIONFLAGS);
                        if(SectionAttributes & IMAGE_SCN_MEM_EXECUTE || SectionAttributes & IMAGE_SCN_CNT_CODE)
                        {
                            myFileStatusInfo.EntryPoint = UE_FIELD_OK;
                        }
                        else
                        {
                            myFileStatusInfo.EntryPoint = UE_FIELD_BROKEN_NON_CRITICAL;
                        }
                    }
                    ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader64->OptionalHeader.AddressOfEntryPoint + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, false, true);
                    if(ConvertedAddress == NULL)
                    {
                        myFileStatusInfo.EntryPoint = UE_FIELD_BROKEN_NON_FIXABLE;
                    }
                    else
                    {
                        ReadData = NULL;
                        if(memcmp(&ReadData, (LPVOID)ConvertedAddress, 4) == NULL)
                        {
                            myFileStatusInfo.EntryPoint = UE_FIELD_BROKEN_NON_FIXABLE;
                        }
                    }
                    SetOverallFileStatus(&myFileStatusInfo, myFileStatusInfo.EntryPoint, true);
                    /*
                        Return data
                    */
                    if(FileStatusInfo != NULL)
                    {
                        RtlMoveMemory(FileStatusInfo, &myFileStatusInfo, sizeof FILE_STATUS_INFO);
                    }
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    if(myFileStatusInfo.OveralEvaluation == UE_RESULT_FILE_OK)
                    {
                        return true;
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    myFileStatusInfo.EvaluationTerminatedByException = true;
                    myFileStatusInfo.OveralEvaluation = UE_RESULT_FILE_INVALID_FORMAT;
                    myFileStatusInfo.SignaturePE = UE_FIELD_BROKEN_NON_FIXABLE;
                    if(FileStatusInfo != NULL)
                    {
                        RtlMoveMemory(FileStatusInfo, &myFileStatusInfo, sizeof FILE_STATUS_INFO);
                    }
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return false;
                }
            }
        }
        else
        {
            myFileStatusInfo.OveralEvaluation = UE_RESULT_FILE_INVALID_FORMAT;
            myFileStatusInfo.SignatureMZ = UE_FIELD_BROKEN_NON_FIXABLE;
            if(FileStatusInfo != NULL)
            {
                RtlMoveMemory(FileStatusInfo, &myFileStatusInfo, sizeof FILE_STATUS_INFO);
            }
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            return false;
        }
    }
    if(FileStatusInfo != NULL)
    {
        RtlMoveMemory(FileStatusInfo, &myFileStatusInfo, sizeof FILE_STATUS_INFO);
    }
    return false;
}
__declspec(dllexport) bool TITCALL FixBrokenPE32FileEx(char* szFileName, LPVOID FileStatusInfo, LPVOID FileFixInfo)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        return(FixBrokenPE32FileExW(uniFileName, FileStatusInfo, FileFixInfo));
    }
    else
    {
        return false;
    }
}
__declspec(dllexport) bool TITCALL FixBrokenPE32FileExW(wchar_t* szFileName, LPVOID FileStatusInfo, LPVOID FileFixInfo)
{
    if(!FileFixInfo)
        return false;
    DWORD ReadData = NULL;
    DWORD ReadSize = NULL;
    WORD ReadDataWORD = NULL;
    ULONG_PTR ReadDataQWORD = NULL;
    DWORD OrdinalBase = NULL;
    DWORD OrdinalCount = NULL;
    long SectionNumber = NULL;
    DWORD SectionAttributes = NULL;
    ULONG_PTR ConvertedAddress = NULL;
    DWORD CorrectedImageSize = NULL;
    DWORD SectionVirtualSize = NULL;
    DWORD SectionVirtualSizeFixed = NULL;
    DWORD NumberOfSections = NULL;
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_SECTION_HEADER PESections;
    PIMAGE_EXPORT_DIRECTORY PEExports;
    PIMAGE_TLS_DIRECTORY32 PETls32;
    PIMAGE_TLS_DIRECTORY64 PETls64;
    PIMAGE_IMPORT_DESCRIPTOR ImportIID;
    PIMAGE_THUNK_DATA32 ThunkData32;
    PIMAGE_THUNK_DATA64 ThunkData64;
    PFILE_STATUS_INFO myFileStatusInfo = (PFILE_STATUS_INFO)FileStatusInfo;
    PFILE_FIX_INFO myFileFixInfo = (PFILE_FIX_INFO)FileFixInfo; //can bad point
    bool hLoadedModuleSimulated = false;
    HMODULE hLoadedModule;
    ULONG_PTR ImportNamePtr;
    ULONG_PTR CurrentThunk;
    BOOL FileIs64;
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    bool FileFixed = true;
    bool FeatureFixed = false;

    FILE_STATUS_INFO filestatusinfo; //for internal use

    if(myFileStatusInfo == NULL) //here check for myfilestrus..ah lol, youre right
    {
        myFileStatusInfo = &filestatusinfo;
        IsPE32FileValidExW(szFileName, UE_DEPTH_DEEP, myFileStatusInfo);
    }
    if(myFileFixInfo->FileFixPerformed == false && myFileStatusInfo->OveralEvaluation == UE_RESULT_FILE_INVALID_BUT_FIXABLE)
    {
        if(MapFileExW(szFileName, UE_ACCESS_ALL, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
        {
            myFileFixInfo->OveralEvaluation = UE_RESULT_FILE_INVALID_AND_NON_FIXABLE;
            DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
            if(EngineValidateHeader(FileMapVA, FileHandle, NULL, DOSHeader, true))
            {
                PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
                PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
                if(PEHeader32->Signature == 0x4550 && PEHeader32->OptionalHeader.Magic == 0x10B)
                {
                    FileIs64 = false;
                }
                else if(PEHeader32->Signature == 0x4550 && PEHeader32->OptionalHeader.Magic == 0x20B)
                {
                    FileIs64 = true;
                }
                else
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return false;
                }
                if(myFileStatusInfo->SignatureMZ != UE_FIELD_OK)
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return false;
                }
                else if(myFileStatusInfo->SignaturePE != UE_FIELD_OK)
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return false;
                }
                else if(myFileStatusInfo->SectionAlignment != UE_FIELD_OK)
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return false;
                }
                else if(myFileStatusInfo->FileAlignment != UE_FIELD_OK)
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return false;
                }
                else if(myFileStatusInfo->ImportTable != UE_FIELD_OK)
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return false;
                }
                else if(myFileStatusInfo->ImportTableData != UE_FIELD_OK)
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return false;
                }
                if(!FileIs64)
                {
                    /*
                        x86 Surface check
                    */
                    __try
                    {
                        if(PEHeader32->OptionalHeader.SizeOfImage % PEHeader32->OptionalHeader.SectionAlignment == NULL)
                        {
                            CorrectedImageSize = (PEHeader32->OptionalHeader.SizeOfImage / PEHeader32->OptionalHeader.SectionAlignment) * PEHeader32->OptionalHeader.SectionAlignment;
                        }
                        else
                        {
                            CorrectedImageSize = ((PEHeader32->OptionalHeader.SizeOfImage / PEHeader32->OptionalHeader.SectionAlignment) + 1) * PEHeader32->OptionalHeader.SectionAlignment;
                        }
                        /*
                            Fixing import table
                        */
                        if(myFileStatusInfo->MissingDeclaredAPIs)
                        {
                            ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + PEHeader32->OptionalHeader.ImageBase, false, true);
                            SectionNumber = GetPE32SectionNumberFromVA(FileMapVA, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + PEHeader32->OptionalHeader.ImageBase);
                            if(SectionNumber >= NULL)
                            {
                                SectionAttributes = (DWORD)GetPE32DataFromMappedFile(FileMapVA, SectionNumber, UE_SECTIONFLAGS);
                                if(SectionAttributes & IMAGE_SCN_MEM_EXECUTE || SectionAttributes & IMAGE_SCN_CNT_CODE || SectionAttributes & IMAGE_SCN_MEM_WRITE || SectionAttributes & IMAGE_SCN_CNT_INITIALIZED_DATA)
                                {
                                    // Should not execute!
                                }
                                else
                                {
                                    if(!SetPE32DataForMappedFile(FileMapVA, SectionAttributes, UE_SECTIONFLAGS, 0xE0000020))
                                    {
                                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                                        return false;
                                    }
                                }
                                if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != NULL)
                                {
                                    ImportIID = (PIMAGE_IMPORT_DESCRIPTOR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase, (ULONG_PTR)(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + PEHeader32->OptionalHeader.ImageBase), false, true);
                                    while(ImportIID->FirstThunk != NULL)
                                    {
                                        hLoadedModule = NULL;
                                        ImportNamePtr = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase, (ULONG_PTR)((ULONG_PTR)ImportIID->Name + PEHeader32->OptionalHeader.ImageBase), false, true);
                                        if(ImportNamePtr != NULL)
                                        {
                                            if(!EngineIsDependencyPresent((char*)ImportNamePtr, NULL, NULL))
                                            {
                                                hLoadedModuleSimulated = false;
                                            }
                                            else
                                            {
                                                hLoadedModuleSimulated = false;
                                                hLoadedModule = GetModuleHandleA((char*)ImportNamePtr);
                                                if(hLoadedModule == NULL)
                                                {
                                                    hLoadedModule = (HMODULE)EngineSimulateDllLoader(GetCurrentProcess(), (char*)ImportNamePtr);
                                                    hLoadedModuleSimulated = true;
                                                }
                                            }
                                        }
                                        if(ImportIID->OriginalFirstThunk != NULL)
                                        {
                                            ThunkData32 = (PIMAGE_THUNK_DATA32)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase, (ULONG_PTR)((ULONG_PTR)ImportIID->OriginalFirstThunk + PEHeader32->OptionalHeader.ImageBase), false, true);
                                            CurrentThunk = (ULONG_PTR)ImportIID->OriginalFirstThunk;
                                        }
                                        else
                                        {
                                            ThunkData32 = (PIMAGE_THUNK_DATA32)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase, (ULONG_PTR)((ULONG_PTR)ImportIID->FirstThunk + PEHeader32->OptionalHeader.ImageBase), false, true);
                                            CurrentThunk = (ULONG_PTR)ImportIID->FirstThunk;
                                        }
                                        if(ThunkData32 != NULL)
                                        {
                                            while(ThunkData32->u1.AddressOfData != NULL)
                                            {
                                                if(ThunkData32->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
                                                {
                                                    if((int)(ThunkData32->u1.Ordinal ^ IMAGE_ORDINAL_FLAG32) >= 0x10000)
                                                    {
                                                        FileFixed = false;
                                                    }
                                                }
                                                else
                                                {
                                                    ImportNamePtr = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase, (ULONG_PTR)((ULONG_PTR)ThunkData32->u1.AddressOfData + 2 + PEHeader32->OptionalHeader.ImageBase), false, true);
                                                    if(ImportNamePtr != NULL)
                                                    {
                                                        if(EngineIsValidReadPtrEx((LPVOID)ImportNamePtr, 8))
                                                        {
                                                            if(hLoadedModule != NULL)
                                                            {
                                                                if(EngineGetProcAddress((ULONG_PTR)hLoadedModule, (char*)ImportNamePtr) == NULL)
                                                                {
                                                                    OrdinalBase = NULL;
                                                                    OrdinalCount = NULL;
                                                                    if(EngineGetLibraryOrdinalData((ULONG_PTR)hLoadedModule, &OrdinalBase, &OrdinalCount))
                                                                    {
                                                                        if(OrdinalBase != NULL && OrdinalCount != NULL)
                                                                        {
                                                                            ThunkData32->u1.Ordinal = (OrdinalBase + 1) ^ IMAGE_ORDINAL_FLAG32;
                                                                        }
                                                                        else
                                                                        {
                                                                            FileFixed = false;
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                CurrentThunk = CurrentThunk + 4;
                                                ThunkData32 = (PIMAGE_THUNK_DATA32)((ULONG_PTR)ThunkData32 + sizeof IMAGE_THUNK_DATA32);
                                            }
                                        }
                                        if(hLoadedModuleSimulated)
                                        {
                                            VirtualFree((LPVOID)hLoadedModule, NULL, MEM_RELEASE);
                                        }
                                        ImportIID = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)ImportIID + sizeof IMAGE_IMPORT_DESCRIPTOR);
                                    }
                                }
                            }
                        }
                        /*
                            Fixing Export table
                        */
                        if(myFileStatusInfo->ExportTable == UE_FIELD_NOT_PRESET_WARNING)
                        {
                            FileFixed = false;
                        }
                        else if(myFileFixInfo->DontFixExports == false && myFileStatusInfo->ExportTable != UE_FIELD_OK && myFileStatusInfo->ExportTable != UE_FIELD_NOT_PRESET)
                        {
                            if(PEHeader32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT && PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != NULL)
                            {
                                if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress > CorrectedImageSize || PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size > CorrectedImageSize)
                                {
                                    myFileFixInfo->StrippedExports = true;
                                    myFileFixInfo->OriginalExportTableAddress = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                                    myFileFixInfo->OriginalExportTableSize = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
                                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = NULL;
                                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = NULL;
                                }
                                else
                                {
                                    FeatureFixed = true;
                                    ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + PEHeader32->OptionalHeader.ImageBase, false, true);
                                    if(ConvertedAddress != NULL)
                                    {
                                        if(EngineIsValidReadPtrEx((LPVOID)ConvertedAddress, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size))
                                        {
                                            PEExports = (PIMAGE_EXPORT_DIRECTORY)ConvertedAddress;
                                            if(PEExports->AddressOfFunctions > CorrectedImageSize || PEExports->AddressOfFunctions + 4 * PEExports->NumberOfFunctions > CorrectedImageSize)
                                            {
                                                FeatureFixed = false;
                                            }
                                            else if(PEExports->AddressOfNameOrdinals > CorrectedImageSize || PEExports->AddressOfNameOrdinals + 4 * PEExports->NumberOfNames > CorrectedImageSize)
                                            {
                                                FeatureFixed = false;
                                            }
                                            else if(PEExports->AddressOfNames > CorrectedImageSize || PEExports->AddressOfNames + 4 * PEExports->NumberOfNames > CorrectedImageSize)
                                            {
                                                FeatureFixed = false;
                                            }
                                            else if(PEExports->Name > CorrectedImageSize)
                                            {
                                                FeatureFixed = false;
                                            }
                                            if(!FeatureFixed)
                                            {
                                                myFileFixInfo->StrippedExports = true;
                                                myFileFixInfo->OriginalExportTableAddress = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                                                myFileFixInfo->OriginalExportTableSize = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
                                                PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = NULL;
                                                PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = NULL;
                                            }
                                        }
                                        else
                                        {
                                            myFileFixInfo->StrippedExports = true;
                                            myFileFixInfo->OriginalExportTableAddress = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                                            myFileFixInfo->OriginalExportTableSize = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
                                            PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = NULL;
                                            PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = NULL;
                                        }
                                    }
                                }
                            }
                        }
                        /*
                            Fixing Relocation table
                        */
                        if(myFileStatusInfo->FileIsDLL == true && myFileStatusInfo->RelocationTable == UE_FIELD_BROKEN_NON_FIXABLE)
                        {
                            FileFixed = false;
                        }
                        else if(myFileFixInfo->DontFixRelocations == false && myFileStatusInfo->RelocationTable != UE_FIELD_OK)
                        {
                            if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress > CorrectedImageSize || PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > CorrectedImageSize)
                            {
                                if(myFileStatusInfo->FileIsDLL)
                                {
                                    FileFixed = false;
                                }
                                else
                                {
                                    myFileFixInfo->StrippedRelocation = true;
                                    myFileFixInfo->OriginalRelocationTableAddress = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                                    myFileFixInfo->OriginalRelocationTableSize = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = NULL;
                                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = NULL;
                                }
                            }
                            else
                            {
                                ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + PEHeader32->OptionalHeader.ImageBase, false, true);
                                if(ConvertedAddress != NULL)
                                {
                                    if(EngineIsValidReadPtrEx((LPVOID)ConvertedAddress, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size))
                                    {
                                        RtlMoveMemory(&ReadData, (LPVOID)ConvertedAddress, 4);
                                        RtlMoveMemory(&ReadSize, (LPVOID)(ConvertedAddress + 4), 4);
                                        while(ReadData != NULL)
                                        {
                                            ReadSize = ReadSize - 8;
                                            ConvertedAddress = ConvertedAddress + 8;
                                            while(ReadSize > NULL)
                                            {
                                                RtlMoveMemory(&ReadDataWORD, (LPVOID)ConvertedAddress, 2);
                                                if(ReadDataWORD > 0xCFFF)
                                                {
                                                    RtlZeroMemory((LPVOID)ConvertedAddress, 2);
                                                }
                                                ConvertedAddress = ConvertedAddress + 2;
                                                ReadSize = ReadSize - 2;
                                            }
                                            RtlMoveMemory(&ReadData, (LPVOID)ConvertedAddress, 4);
                                            RtlMoveMemory(&ReadSize, (LPVOID)(ConvertedAddress + 4), 4);
                                        }
                                    }
                                    else
                                    {
                                        if(myFileStatusInfo->FileIsDLL)
                                        {
                                            FileFixed = false;
                                        }
                                        else
                                        {
                                            myFileFixInfo->StrippedRelocation = true;
                                            myFileFixInfo->OriginalRelocationTableAddress = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                                            myFileFixInfo->OriginalRelocationTableSize = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                                            PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = NULL;
                                            PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = NULL;
                                        }
                                    }
                                }
                                else
                                {
                                    if(myFileStatusInfo->FileIsDLL)
                                    {
                                        FileFixed = false;
                                    }
                                    else
                                    {
                                        myFileFixInfo->StrippedRelocation = true;
                                        myFileFixInfo->OriginalRelocationTableAddress = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                                        myFileFixInfo->OriginalRelocationTableSize = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = NULL;
                                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = NULL;
                                    }
                                }
                            }
                        }
                        else if(myFileStatusInfo->RelocationTable == UE_FIELD_OK)
                        {
                            // Filter case!
                        }
                        else
                        {
                            FileFixed = false;
                        }
                        /*
                            Fixing Resource table
                        */
                        if(myFileFixInfo->DontFixResources == false && myFileStatusInfo->ResourceData != UE_FIELD_OK && myFileStatusInfo->ResourceData != UE_FIELD_NOT_PRESET)
                        {
                            myFileFixInfo->StrippedResources = true;
                            myFileFixInfo->OriginalResourceTableAddress = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
                            myFileFixInfo->OriginalResourceTableSize = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
                            PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = NULL;
                            PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = NULL;
                        }
                        else if(myFileFixInfo->DontFixResources == false && myFileStatusInfo->ResourceTable != UE_FIELD_OK && myFileStatusInfo->ResourceTable != UE_FIELD_NOT_PRESET)
                        {
                            if(PEHeader32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_RESOURCE && PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress != NULL)
                            {
                                if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress > CorrectedImageSize || PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size > CorrectedImageSize)
                                {
                                    myFileFixInfo->StrippedResources = true;
                                    myFileFixInfo->OriginalResourceTableAddress = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
                                    myFileFixInfo->OriginalResourceTableSize = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
                                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = NULL;
                                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = NULL;
                                }
                                else
                                {
                                    ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress + PEHeader32->OptionalHeader.ImageBase, false, true);
                                    if(ConvertedAddress == NULL || ConvertedAddress - FileMapVA > FileSize || ConvertedAddress - FileMapVA + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size > FileSize)
                                    {
                                        myFileFixInfo->StrippedResources = true;
                                        myFileFixInfo->OriginalResourceTableAddress = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
                                        myFileFixInfo->OriginalResourceTableSize = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
                                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = NULL;
                                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = NULL;
                                    }
                                }
                            }
                        }
                        /*
                            Fixing TLS table
                        */
                        if(myFileFixInfo->DontFixTLS == false && myFileStatusInfo->TLSTable != UE_FIELD_OK && myFileStatusInfo->TLSTable != UE_FIELD_NOT_PRESET)
                        {
                            if(PEHeader32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS && PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL)
                            {
                                if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress > CorrectedImageSize || PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size > CorrectedImageSize)
                                {
                                    myFileFixInfo->StrippedTLS = true;
                                    myFileFixInfo->OriginalTLSTableAddress = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
                                    myFileFixInfo->OriginalTLSTableSize = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
                                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = NULL;
                                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = NULL;
                                }
                                else
                                {
                                    ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress + PEHeader32->OptionalHeader.ImageBase, false, true);
                                    if(ConvertedAddress == NULL || ConvertedAddress - FileMapVA > FileSize)
                                    {
                                        myFileFixInfo->StrippedTLS = true;
                                        myFileFixInfo->OriginalTLSTableAddress = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
                                        myFileFixInfo->OriginalTLSTableSize = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
                                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = NULL;
                                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = NULL;
                                    }
                                    else
                                    {
                                        FeatureFixed = true;
                                        PETls32 = (PIMAGE_TLS_DIRECTORY32)ConvertedAddress;
                                        if(PETls32->StartAddressOfRawData != NULL && (PETls32->StartAddressOfRawData < PEHeader32->OptionalHeader.ImageBase || PETls32->StartAddressOfRawData > CorrectedImageSize + PEHeader32->OptionalHeader.ImageBase))
                                        {
                                            FeatureFixed = false;
                                        }
                                        else if(PETls32->EndAddressOfRawData != NULL && (PETls32->EndAddressOfRawData < PEHeader32->OptionalHeader.ImageBase || PETls32->EndAddressOfRawData > CorrectedImageSize + PEHeader32->OptionalHeader.ImageBase))
                                        {
                                            FeatureFixed = false;
                                        }
                                        else if(PETls32->AddressOfIndex != NULL && (PETls32->AddressOfIndex < PEHeader32->OptionalHeader.ImageBase || PETls32->AddressOfIndex > CorrectedImageSize + PEHeader32->OptionalHeader.ImageBase))
                                        {
                                            FeatureFixed = false;
                                        }
                                        else if(PETls32->AddressOfCallBacks != NULL && (PETls32->AddressOfCallBacks < PEHeader32->OptionalHeader.ImageBase || PETls32->AddressOfCallBacks > CorrectedImageSize + PEHeader32->OptionalHeader.ImageBase))
                                        {
                                            FeatureFixed = false;
                                        }
                                        if(!FeatureFixed)
                                        {
                                            myFileFixInfo->StrippedTLS = true;
                                            myFileFixInfo->OriginalTLSTableAddress = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
                                            myFileFixInfo->OriginalTLSTableSize = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
                                            PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = NULL;
                                            PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = NULL;
                                        }
                                        else
                                        {
                                            if(PETls32->AddressOfCallBacks != NULL)
                                            {
                                                ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PETls32->AddressOfCallBacks + PEHeader32->OptionalHeader.ImageBase, false, true);
                                                if(ConvertedAddress != NULL)
                                                {
                                                    while(ReadData != NULL)
                                                    {
                                                        RtlMoveMemory(&ReadData, (LPVOID)ConvertedAddress, 4);
                                                        if(ReadData < PEHeader32->OptionalHeader.ImageBase || ReadData > CorrectedImageSize + PEHeader32->OptionalHeader.ImageBase)
                                                        {
                                                            RtlZeroMemory((LPVOID)ConvertedAddress, 4);
                                                        }
                                                        ConvertedAddress = ConvertedAddress + 4;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        /*
                            Fix Load config table
                        */
                        if(myFileFixInfo->DontFixLoadConfig == false && myFileStatusInfo->LoadConfigTable != UE_FIELD_OK && myFileStatusInfo->LoadConfigTable != UE_FIELD_NOT_PRESET)
                        {
                            if(PEHeader32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG && PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress != NULL)
                            {
                                if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress > CorrectedImageSize || PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size > CorrectedImageSize)
                                {
                                    myFileFixInfo->StrippedLoadConfig = true;
                                    myFileFixInfo->OriginalLoadConfigTableAddress = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
                                    myFileFixInfo->OriginalLoadConfigTableSize = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size;
                                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = NULL;
                                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = NULL;
                                }
                                else
                                {
                                    ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress + PEHeader32->OptionalHeader.ImageBase, false, true);
                                    if(ConvertedAddress == NULL || ConvertedAddress - FileMapVA > FileSize)
                                    {
                                        myFileFixInfo->StrippedLoadConfig = true;
                                        myFileFixInfo->OriginalLoadConfigTableAddress = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
                                        myFileFixInfo->OriginalLoadConfigTableSize = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size;
                                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = NULL;
                                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = NULL;
                                    }
                                }
                            }
                        }
                        /*
                            Fix Bound import table
                        */
                        if(myFileFixInfo->DontFixBoundImports == false && myFileStatusInfo->BoundImportTable != UE_FIELD_OK && myFileStatusInfo->BoundImportTable != UE_FIELD_NOT_PRESET)
                        {
                            if(PEHeader32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT && PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress != NULL)
                            {
                                if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress > CorrectedImageSize || PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size > CorrectedImageSize)
                                {
                                    myFileFixInfo->StrippedBoundImports = true;
                                    myFileFixInfo->OriginalBoundImportTableAddress = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress;
                                    myFileFixInfo->OriginalBoundImportTableSize = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size;
                                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = NULL;
                                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = NULL;
                                }
                                else
                                {
                                    ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress + PEHeader32->OptionalHeader.ImageBase, false, true);
                                    if(ConvertedAddress == NULL || ConvertedAddress - FileMapVA > FileSize)
                                    {
                                        myFileFixInfo->StrippedBoundImports = true;
                                        myFileFixInfo->OriginalBoundImportTableAddress = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress;
                                        myFileFixInfo->OriginalBoundImportTableSize = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size;
                                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = NULL;
                                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = NULL;
                                    }
                                }
                            }
                        }
                        /*
                            Fix IAT
                        */
                        if(myFileFixInfo->DontFixIAT == false && myFileStatusInfo->IATTable != UE_FIELD_OK && myFileStatusInfo->IATTable != UE_FIELD_NOT_PRESET)
                        {
                            if(PEHeader32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IAT && PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress != NULL)
                            {
                                if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress > CorrectedImageSize || PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size > CorrectedImageSize)
                                {
                                    myFileFixInfo->StrippedIAT = true;
                                    myFileFixInfo->OriginalImportAddressTableAddress = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
                                    myFileFixInfo->OriginalImportAddressTableSize = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
                                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = NULL;
                                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = NULL;
                                }
                                else
                                {
                                    ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress + PEHeader32->OptionalHeader.ImageBase, false, true);
                                    if(ConvertedAddress == NULL || ConvertedAddress - FileMapVA > FileSize)
                                    {
                                        myFileFixInfo->StrippedIAT = true;
                                        myFileFixInfo->OriginalImportAddressTableAddress = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
                                        myFileFixInfo->OriginalImportAddressTableSize = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
                                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = NULL;
                                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = NULL;
                                    }
                                }
                            }
                        }
                        /*
                            Fix COM header
                        */
                        if(myFileFixInfo->DontFixCOM == false && myFileStatusInfo->COMHeaderTable != UE_FIELD_OK && myFileStatusInfo->COMHeaderTable != UE_FIELD_NOT_PRESET)
                        {
                            if(PEHeader32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR && PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != NULL)
                            {
                                if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress > CorrectedImageSize || PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size > CorrectedImageSize)
                                {
                                    myFileFixInfo->StrippedCOM = true;
                                    myFileFixInfo->OriginalCOMTableAddress = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
                                    myFileFixInfo->OriginalCOMTableSize = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size;
                                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress = NULL;
                                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size = NULL;
                                }
                                else
                                {
                                    ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress + PEHeader32->OptionalHeader.ImageBase, false, true);
                                    if(ConvertedAddress == NULL || ConvertedAddress - FileMapVA > FileSize)
                                    {
                                        myFileFixInfo->StrippedCOM = true;
                                        myFileFixInfo->OriginalCOMTableAddress = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
                                        myFileFixInfo->OriginalCOMTableSize = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size;
                                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress = NULL;
                                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size = NULL;
                                    }
                                }
                            }
                        }
                        /*
                            Fix sections and SizeOfImage
                        */
                        if(myFileStatusInfo->SectionTable != UE_FIELD_OK || myFileStatusInfo->SizeOfImage != UE_FIELD_OK)
                        {
                            PESections = IMAGE_FIRST_SECTION(PEHeader32);
                            NumberOfSections = PEHeader32->FileHeader.NumberOfSections;
                            while(NumberOfSections > NULL)
                            {
                                SectionVirtualSize = PESections->VirtualAddress + PESections->Misc.VirtualSize;
                                if(PESections->Misc.VirtualSize % PEHeader32->OptionalHeader.SectionAlignment == NULL)
                                {
                                    SectionVirtualSizeFixed = SectionVirtualSize;
                                }
                                else
                                {
                                    SectionVirtualSizeFixed = PESections->VirtualAddress + (((PESections->Misc.VirtualSize / PEHeader32->OptionalHeader.SectionAlignment) + 1) * PEHeader32->OptionalHeader.SectionAlignment);
                                }
                                if(NumberOfSections > 1)
                                {
                                    PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + sizeof IMAGE_SECTION_HEADER);
                                    if(SectionVirtualSize > PESections->VirtualAddress || SectionVirtualSizeFixed > PESections->VirtualAddress)
                                    {
                                        PESections->Misc.VirtualSize = SectionVirtualSizeFixed;
                                    }
                                }
                                NumberOfSections--;
                            }
                            if(PESections->PointerToRawData + PESections->SizeOfRawData > FileSize && PESections->SizeOfRawData != NULL)
                            {
                                PESections->SizeOfRawData = FileSize - PESections->PointerToRawData;
                            }
                            if(myFileStatusInfo->SizeOfImage != UE_FIELD_OK)
                            {
                                SectionVirtualSizeFixed = SectionVirtualSizeFixed + 0xF000;
                                if(PEHeader32->OptionalHeader.SizeOfImage > SectionVirtualSizeFixed)
                                {
                                    PEHeader32->OptionalHeader.SizeOfImage = SectionVirtualSizeFixed - 0xF000;
                                }
                            }
                        }
                        /*
                            Entry point check
                        */
                        if(myFileStatusInfo->EntryPoint != UE_FIELD_OK)
                        {
                            SectionNumber = GetPE32SectionNumberFromVA(FileMapVA, PEHeader32->OptionalHeader.AddressOfEntryPoint + (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase);
                            if(SectionNumber != -1)
                            {
                                SectionAttributes = (DWORD)GetPE32DataFromMappedFile(FileMapVA, SectionNumber, UE_SECTIONFLAGS);
                                if(SectionAttributes & IMAGE_SCN_MEM_EXECUTE || SectionAttributes & IMAGE_SCN_CNT_CODE)
                                {
                                    // Should never execute
                                }
                                else
                                {
                                    if(!SetPE32DataForMappedFile(FileMapVA, SectionNumber, UE_SECTIONFLAGS, 0xE0000020))
                                    {
                                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                                        return false;
                                    }
                                }
                            }
                        }
                        /*
                            Fix end
                        */
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        if(FileFixed)
                        {
                            myFileFixInfo->OveralEvaluation = UE_RESULT_FILE_OK;
                            myFileFixInfo->FileFixPerformed = FileFixed;
                        }
                        return true;
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        myFileFixInfo->FixingTerminatedByException = true;
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return false;
                    }
                }
                else
                {
                    /*
                        x64 Surface check
                    */
                    __try
                    {
                        if(PEHeader64->OptionalHeader.SizeOfImage % PEHeader64->OptionalHeader.SectionAlignment == NULL)
                        {
                            CorrectedImageSize = (PEHeader64->OptionalHeader.SizeOfImage / PEHeader64->OptionalHeader.SectionAlignment) * PEHeader64->OptionalHeader.SectionAlignment;
                        }
                        else
                        {
                            CorrectedImageSize = ((PEHeader64->OptionalHeader.SizeOfImage / PEHeader64->OptionalHeader.SectionAlignment) + 1) * PEHeader64->OptionalHeader.SectionAlignment;
                        }
                        /*
                            Fixing import table
                        */
                        if(myFileStatusInfo->MissingDeclaredAPIs)
                        {
                            ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, false, true);
                            SectionNumber = GetPE32SectionNumberFromVA(FileMapVA, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase);
                            if(SectionNumber >= NULL)
                            {
                                SectionAttributes = (DWORD)GetPE32DataFromMappedFile(FileMapVA, SectionNumber, UE_SECTIONFLAGS);
                                if(SectionAttributes & IMAGE_SCN_MEM_EXECUTE || SectionAttributes & IMAGE_SCN_CNT_CODE || SectionAttributes & IMAGE_SCN_MEM_WRITE || SectionAttributes & IMAGE_SCN_CNT_INITIALIZED_DATA)
                                {
                                    // Should not execute!
                                }
                                else
                                {
                                    if(!SetPE32DataForMappedFile(FileMapVA, SectionAttributes, UE_SECTIONFLAGS, 0xE0000020))
                                    {
                                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                                        return false;
                                    }
                                }
                                if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != NULL)
                                {
                                    ImportIID = (PIMAGE_IMPORT_DESCRIPTOR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, (ULONG_PTR)(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase), false, true);
                                    while(ImportIID->FirstThunk != NULL)
                                    {
                                        hLoadedModule = NULL;
                                        ImportNamePtr = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, (ULONG_PTR)((ULONG_PTR)ImportIID->Name + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase), false, true);
                                        if(ImportNamePtr != NULL)
                                        {
                                            if(!EngineIsDependencyPresent((char*)ImportNamePtr, NULL, NULL))
                                            {
                                                hLoadedModuleSimulated = false;
                                            }
                                            else
                                            {
                                                hLoadedModuleSimulated = false;
                                                hLoadedModule = GetModuleHandleA((char*)ImportNamePtr);
                                                if(hLoadedModule == NULL)
                                                {
                                                    hLoadedModule = (HMODULE)EngineSimulateDllLoader(GetCurrentProcess(), (char*)ImportNamePtr);
                                                    hLoadedModuleSimulated = true;
                                                }
                                            }
                                        }
                                        if(ImportIID->OriginalFirstThunk != NULL)
                                        {
                                            ThunkData64 = (PIMAGE_THUNK_DATA64)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, (ULONG_PTR)((ULONG_PTR)ImportIID->OriginalFirstThunk + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase), false, true);
                                            CurrentThunk = (ULONG_PTR)ImportIID->OriginalFirstThunk;
                                        }
                                        else
                                        {
                                            ThunkData32 = (PIMAGE_THUNK_DATA32)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase, (ULONG_PTR)((ULONG_PTR)ImportIID->FirstThunk + PEHeader32->OptionalHeader.ImageBase), false, true);
                                            CurrentThunk = (ULONG_PTR)ImportIID->FirstThunk;
                                        }
                                        if(ThunkData64 != NULL)
                                        {
                                            while(ThunkData64->u1.AddressOfData != NULL)
                                            {
                                                if(ThunkData64->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                                                {
                                                    if((int)(ThunkData64->u1.Ordinal ^ IMAGE_ORDINAL_FLAG64) >= 0x10000)
                                                    {
                                                        FileFixed = false;
                                                    }
                                                }
                                                else
                                                {
                                                    ImportNamePtr = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, (ULONG_PTR)((ULONG_PTR)ThunkData64->u1.AddressOfData + 2 + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase), false, true);
                                                    if(ImportNamePtr != NULL)
                                                    {
                                                        if(EngineIsValidReadPtrEx((LPVOID)ImportNamePtr, 8))
                                                        {
                                                            if(hLoadedModule != NULL)
                                                            {
                                                                if(EngineGetProcAddress((ULONG_PTR)hLoadedModule, (char*)ImportNamePtr) == NULL)
                                                                {
                                                                    OrdinalBase = NULL;
                                                                    OrdinalCount = NULL;
                                                                    if(EngineGetLibraryOrdinalData((ULONG_PTR)hLoadedModule, &OrdinalBase, &OrdinalCount))
                                                                    {
                                                                        if(OrdinalBase != NULL && OrdinalCount != NULL)
                                                                        {
                                                                            ThunkData64->u1.Ordinal = (OrdinalBase + 1) ^ IMAGE_ORDINAL_FLAG64;
                                                                        }
                                                                        else
                                                                        {
                                                                            FileFixed = false;
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                CurrentThunk = CurrentThunk + 8;
                                                ThunkData64 = (PIMAGE_THUNK_DATA64)((ULONG_PTR)ThunkData64 + sizeof IMAGE_THUNK_DATA64);
                                            }
                                        }
                                        if(hLoadedModuleSimulated)
                                        {
                                            VirtualFree((LPVOID)hLoadedModule, NULL, MEM_RELEASE);
                                        }
                                        ImportIID = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)ImportIID + sizeof IMAGE_IMPORT_DESCRIPTOR);
                                    }
                                }
                            }
                        }
                        /*
                            Fixing Export table
                        */
                        if(myFileStatusInfo->ExportTable == UE_FIELD_NOT_PRESET_WARNING)
                        {
                            FileFixed = false;
                        }
                        else if(myFileFixInfo->DontFixExports == false && myFileStatusInfo->ExportTable != UE_FIELD_OK && myFileStatusInfo->ExportTable != UE_FIELD_NOT_PRESET)
                        {
                            if(PEHeader64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT && PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != NULL)
                            {
                                if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress > CorrectedImageSize || PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size > CorrectedImageSize)
                                {
                                    myFileFixInfo->StrippedExports = true;
                                    myFileFixInfo->OriginalExportTableAddress = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                                    myFileFixInfo->OriginalExportTableSize = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
                                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = NULL;
                                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = NULL;
                                }
                                else
                                {
                                    FeatureFixed = true;
                                    ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, false, true);
                                    if(ConvertedAddress != NULL)
                                    {
                                        if(EngineIsValidReadPtrEx((LPVOID)ConvertedAddress, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size))
                                        {
                                            PEExports = (PIMAGE_EXPORT_DIRECTORY)ConvertedAddress;
                                            if(PEExports->AddressOfFunctions > CorrectedImageSize || PEExports->AddressOfFunctions + 4 * PEExports->NumberOfFunctions > CorrectedImageSize)
                                            {
                                                FeatureFixed = false;
                                            }
                                            else if(PEExports->AddressOfNameOrdinals > CorrectedImageSize || PEExports->AddressOfNameOrdinals + 4 * PEExports->NumberOfNames > CorrectedImageSize)
                                            {
                                                FeatureFixed = false;
                                            }
                                            else if(PEExports->AddressOfNames > CorrectedImageSize || PEExports->AddressOfNames + 4 * PEExports->NumberOfNames > CorrectedImageSize)
                                            {
                                                FeatureFixed = false;
                                            }
                                            else if(PEExports->Name > CorrectedImageSize)
                                            {
                                                FeatureFixed = false;
                                            }
                                            if(!FeatureFixed)
                                            {
                                                myFileFixInfo->StrippedExports = true;
                                                myFileFixInfo->OriginalExportTableAddress = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                                                myFileFixInfo->OriginalExportTableSize = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
                                                PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = NULL;
                                                PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = NULL;
                                            }
                                        }
                                        else
                                        {
                                            myFileFixInfo->StrippedExports = true;
                                            myFileFixInfo->OriginalExportTableAddress = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                                            myFileFixInfo->OriginalExportTableSize = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
                                            PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = NULL;
                                            PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = NULL;
                                        }
                                    }
                                }
                            }
                        }
                        /*
                            Fixing Relocation table
                        */
                        if(myFileStatusInfo->FileIsDLL == true && myFileStatusInfo->RelocationTable == UE_FIELD_BROKEN_NON_FIXABLE)
                        {
                            FileFixed = false;
                        }
                        else if(myFileFixInfo->DontFixRelocations == false && myFileStatusInfo->RelocationTable != UE_FIELD_OK)
                        {
                            if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress > CorrectedImageSize || PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > CorrectedImageSize)
                            {
                                if(myFileStatusInfo->FileIsDLL)
                                {
                                    FileFixed = false;
                                }
                                else
                                {
                                    myFileFixInfo->StrippedRelocation = true;
                                    myFileFixInfo->OriginalRelocationTableAddress = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                                    myFileFixInfo->OriginalRelocationTableSize = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = NULL;
                                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = NULL;
                                }
                            }
                            else
                            {
                                ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, false, true);
                                if(ConvertedAddress != NULL)
                                {
                                    if(EngineIsValidReadPtrEx((LPVOID)ConvertedAddress, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size))
                                    {
                                        RtlMoveMemory(&ReadData, (LPVOID)ConvertedAddress, 4);
                                        RtlMoveMemory(&ReadSize, (LPVOID)(ConvertedAddress + 4), 4);
                                        while(ReadData != NULL)
                                        {
                                            ReadSize = ReadSize - 8;
                                            ConvertedAddress = ConvertedAddress + 8;
                                            while(ReadSize > NULL)
                                            {
                                                RtlMoveMemory(&ReadDataWORD, (LPVOID)ConvertedAddress, 2);
                                                if(ReadDataWORD > 0xCFFF)
                                                {
                                                    RtlZeroMemory((LPVOID)ConvertedAddress, 2);
                                                }
                                                ConvertedAddress = ConvertedAddress + 2;
                                                ReadSize = ReadSize - 2;
                                            }
                                            RtlMoveMemory(&ReadData, (LPVOID)ConvertedAddress, 4);
                                            RtlMoveMemory(&ReadSize, (LPVOID)(ConvertedAddress + 4), 4);
                                        }
                                    }
                                    else
                                    {
                                        if(myFileStatusInfo->FileIsDLL)
                                        {
                                            FileFixed = false;
                                        }
                                        else
                                        {
                                            myFileFixInfo->StrippedRelocation = true;
                                            myFileFixInfo->OriginalRelocationTableAddress = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                                            myFileFixInfo->OriginalRelocationTableSize = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                                            PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = NULL;
                                            PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = NULL;
                                        }
                                    }
                                }
                                else
                                {
                                    if(myFileStatusInfo->FileIsDLL)
                                    {
                                        FileFixed = false;
                                    }
                                    else
                                    {
                                        myFileFixInfo->StrippedRelocation = true;
                                        myFileFixInfo->OriginalRelocationTableAddress = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                                        myFileFixInfo->OriginalRelocationTableSize = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = NULL;
                                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = NULL;
                                    }
                                }
                            }
                        }
                        else if(myFileStatusInfo->RelocationTable == UE_FIELD_OK)
                        {
                            // Filter case!
                        }
                        else
                        {
                            FileFixed = false;
                        }
                        /*
                            Fixing Resource table
                        */
                        if(myFileFixInfo->DontFixResources == false && myFileStatusInfo->ResourceData != UE_FIELD_OK && myFileStatusInfo->ResourceData != UE_FIELD_NOT_PRESET)
                        {
                            myFileFixInfo->StrippedResources = true;
                            myFileFixInfo->OriginalResourceTableAddress = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
                            myFileFixInfo->OriginalResourceTableSize = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
                            PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = NULL;
                            PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = NULL;
                        }
                        else if(myFileFixInfo->DontFixResources == false && myFileStatusInfo->ResourceTable != UE_FIELD_OK && myFileStatusInfo->ResourceTable != UE_FIELD_NOT_PRESET)
                        {
                            if(PEHeader64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_RESOURCE && PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress != NULL)
                            {
                                if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress > CorrectedImageSize || PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size > CorrectedImageSize)
                                {
                                    myFileFixInfo->StrippedResources = true;
                                    myFileFixInfo->OriginalResourceTableAddress = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
                                    myFileFixInfo->OriginalResourceTableSize = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
                                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = NULL;
                                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = NULL;
                                }
                                else
                                {
                                    ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, false, true);
                                    if(ConvertedAddress == NULL || ConvertedAddress - FileMapVA > FileSize || ConvertedAddress - FileMapVA + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size > FileSize)
                                    {
                                        myFileFixInfo->StrippedResources = true;
                                        myFileFixInfo->OriginalResourceTableAddress = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
                                        myFileFixInfo->OriginalResourceTableSize = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
                                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = NULL;
                                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = NULL;
                                    }
                                }
                            }
                        }
                        /*
                            Fixing TLS table
                        */
                        if(myFileFixInfo->DontFixTLS == false && myFileStatusInfo->TLSTable != UE_FIELD_OK && myFileStatusInfo->TLSTable != UE_FIELD_NOT_PRESET)
                        {
                            if(PEHeader64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS && PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL)
                            {
                                if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress > CorrectedImageSize || PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size > CorrectedImageSize)
                                {
                                    myFileFixInfo->StrippedTLS = true;
                                    myFileFixInfo->OriginalTLSTableAddress = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
                                    myFileFixInfo->OriginalTLSTableSize = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
                                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = NULL;
                                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = NULL;
                                }
                                else
                                {
                                    ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, false, true);
                                    if(ConvertedAddress == NULL || ConvertedAddress - FileMapVA > FileSize)
                                    {
                                        myFileFixInfo->StrippedTLS = true;
                                        myFileFixInfo->OriginalTLSTableAddress = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
                                        myFileFixInfo->OriginalTLSTableSize = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
                                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = NULL;
                                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = NULL;
                                    }
                                    else
                                    {
                                        FeatureFixed = true;
                                        PETls64 = (PIMAGE_TLS_DIRECTORY64)ConvertedAddress;
                                        if(PETls64->StartAddressOfRawData != NULL && (PETls64->StartAddressOfRawData < (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase || PETls64->StartAddressOfRawData > CorrectedImageSize + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase))
                                        {
                                            FeatureFixed = false;
                                        }
                                        else if(PETls64->EndAddressOfRawData != NULL && (PETls64->EndAddressOfRawData < (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase || PETls64->EndAddressOfRawData > CorrectedImageSize + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase))
                                        {
                                            FeatureFixed = false;
                                        }
                                        else if(PETls64->AddressOfIndex != NULL && (PETls64->AddressOfIndex < (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase || PETls64->AddressOfIndex > CorrectedImageSize + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase))
                                        {
                                            FeatureFixed = false;
                                        }
                                        else if(PETls64->AddressOfCallBacks != NULL && (PETls64->AddressOfCallBacks < (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase || PETls64->AddressOfCallBacks > CorrectedImageSize + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase))
                                        {
                                            FeatureFixed = false;
                                        }
                                        if(!FeatureFixed)
                                        {
                                            myFileFixInfo->StrippedTLS = true;
                                            myFileFixInfo->OriginalTLSTableAddress = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
                                            myFileFixInfo->OriginalTLSTableSize = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
                                            PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = NULL;
                                            PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = NULL;
                                        }
                                        else
                                        {
                                            if(PETls64->AddressOfCallBacks != NULL)
                                            {
                                                ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, (ULONG_PTR)PETls64->AddressOfCallBacks + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, false, true);
                                                if(ConvertedAddress != NULL)
                                                {
                                                    while(ReadData != NULL)
                                                    {
                                                        RtlMoveMemory(&ReadDataQWORD, (LPVOID)ConvertedAddress, 8);
                                                        if(ReadDataQWORD < (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase || ReadDataQWORD > CorrectedImageSize + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase)
                                                        {
                                                            RtlZeroMemory((LPVOID)ConvertedAddress, 8);
                                                        }
                                                        ConvertedAddress = ConvertedAddress + 8;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        /*
                            Fix Load config table
                        */
                        if(myFileFixInfo->DontFixLoadConfig == false && myFileStatusInfo->LoadConfigTable != UE_FIELD_OK && myFileStatusInfo->LoadConfigTable != UE_FIELD_NOT_PRESET)
                        {
                            if(PEHeader64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG && PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress != NULL)
                            {
                                if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress > CorrectedImageSize || PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size > CorrectedImageSize)
                                {
                                    myFileFixInfo->StrippedLoadConfig = true;
                                    myFileFixInfo->OriginalLoadConfigTableAddress = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
                                    myFileFixInfo->OriginalLoadConfigTableSize = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size;
                                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = NULL;
                                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = NULL;
                                }
                                else
                                {
                                    ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, false, true);
                                    if(ConvertedAddress == NULL || ConvertedAddress - FileMapVA > FileSize)
                                    {
                                        myFileFixInfo->StrippedLoadConfig = true;
                                        myFileFixInfo->OriginalLoadConfigTableAddress = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
                                        myFileFixInfo->OriginalLoadConfigTableSize = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size;
                                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = NULL;
                                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = NULL;
                                    }
                                }
                            }
                        }
                        /*
                            Fix Bound import table
                        */
                        if(myFileFixInfo->DontFixBoundImports == false && myFileStatusInfo->BoundImportTable != UE_FIELD_OK && myFileStatusInfo->BoundImportTable != UE_FIELD_NOT_PRESET)
                        {
                            if(PEHeader64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT && PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress != NULL)
                            {
                                if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress > CorrectedImageSize || PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size > CorrectedImageSize)
                                {
                                    myFileFixInfo->StrippedBoundImports = true;
                                    myFileFixInfo->OriginalBoundImportTableAddress = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress;
                                    myFileFixInfo->OriginalBoundImportTableSize = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size;
                                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = NULL;
                                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = NULL;
                                }
                                else
                                {
                                    ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, false, true);
                                    if(ConvertedAddress == NULL || ConvertedAddress - FileMapVA > FileSize)
                                    {
                                        myFileFixInfo->StrippedBoundImports = true;
                                        myFileFixInfo->OriginalBoundImportTableAddress = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress;
                                        myFileFixInfo->OriginalBoundImportTableSize = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size;
                                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = NULL;
                                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = NULL;
                                    }
                                }
                            }
                        }
                        /*
                            Fix IAT
                        */
                        if(myFileFixInfo->DontFixIAT == false && myFileStatusInfo->IATTable != UE_FIELD_OK && myFileStatusInfo->IATTable != UE_FIELD_NOT_PRESET)
                        {
                            if(PEHeader64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IAT && PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress != NULL)
                            {
                                if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress > CorrectedImageSize || PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size > CorrectedImageSize)
                                {
                                    myFileFixInfo->StrippedIAT = true;
                                    myFileFixInfo->OriginalImportAddressTableAddress = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
                                    myFileFixInfo->OriginalImportAddressTableSize = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
                                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = NULL;
                                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = NULL;
                                }
                                else
                                {
                                    ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, false, true);
                                    if(ConvertedAddress == NULL || ConvertedAddress - FileMapVA > FileSize)
                                    {
                                        myFileFixInfo->StrippedIAT = true;
                                        myFileFixInfo->OriginalImportAddressTableAddress = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
                                        myFileFixInfo->OriginalImportAddressTableSize = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
                                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = NULL;
                                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = NULL;
                                    }
                                }
                            }
                        }
                        /*
                            Fix COM header
                        */
                        if(myFileFixInfo->DontFixCOM == false && myFileStatusInfo->COMHeaderTable != UE_FIELD_OK && myFileStatusInfo->COMHeaderTable != UE_FIELD_NOT_PRESET)
                        {
                            if(PEHeader64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR && PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != NULL)
                            {
                                if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress > CorrectedImageSize || PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size > CorrectedImageSize)
                                {
                                    myFileFixInfo->StrippedCOM = true;
                                    myFileFixInfo->OriginalCOMTableAddress = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
                                    myFileFixInfo->OriginalCOMTableSize = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size;
                                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress = NULL;
                                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size = NULL;
                                }
                                else
                                {
                                    ConvertedAddress = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, NULL, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, false, true);
                                    if(ConvertedAddress == NULL || ConvertedAddress - FileMapVA > FileSize)
                                    {
                                        myFileFixInfo->StrippedCOM = true;
                                        myFileFixInfo->OriginalCOMTableAddress = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
                                        myFileFixInfo->OriginalCOMTableSize = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size;
                                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress = NULL;
                                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size = NULL;
                                    }
                                }
                            }
                        }
                        /*
                            Fix sections and SizeOfImage
                        */
                        if(myFileStatusInfo->SectionTable != UE_FIELD_OK || myFileStatusInfo->SizeOfImage != UE_FIELD_OK)
                        {
                            PESections = IMAGE_FIRST_SECTION(PEHeader64);
                            NumberOfSections = PEHeader64->FileHeader.NumberOfSections;
                            while(NumberOfSections > NULL)
                            {
                                SectionVirtualSize = PESections->VirtualAddress + PESections->Misc.VirtualSize;
                                if(PESections->Misc.VirtualSize % PEHeader64->OptionalHeader.SectionAlignment == NULL)
                                {
                                    SectionVirtualSizeFixed = SectionVirtualSize;
                                }
                                else
                                {
                                    SectionVirtualSizeFixed = PESections->VirtualAddress + (((PESections->Misc.VirtualSize / PEHeader64->OptionalHeader.SectionAlignment) + 1) * PEHeader64->OptionalHeader.SectionAlignment);
                                }
                                if(NumberOfSections > 1)
                                {
                                    PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + sizeof IMAGE_SECTION_HEADER);
                                    if(SectionVirtualSize > PESections->VirtualAddress || SectionVirtualSizeFixed > PESections->VirtualAddress)
                                    {
                                        PESections->Misc.VirtualSize = SectionVirtualSizeFixed;
                                    }
                                }
                                NumberOfSections--;
                            }
                            if(PESections->PointerToRawData + PESections->SizeOfRawData > FileSize && PESections->SizeOfRawData != NULL)
                            {
                                PESections->SizeOfRawData = FileSize - PESections->PointerToRawData;
                            }
                            if(myFileStatusInfo->SizeOfImage != UE_FIELD_OK)
                            {
                                SectionVirtualSizeFixed = SectionVirtualSizeFixed + 0xF000;
                                if(PEHeader64->OptionalHeader.SizeOfImage > SectionVirtualSizeFixed)
                                {
                                    PEHeader64->OptionalHeader.SizeOfImage = SectionVirtualSizeFixed - 0xF000;
                                }
                            }
                        }
                        /*
                            Entry point check
                        */
                        if(myFileStatusInfo->EntryPoint != UE_FIELD_OK)
                        {
                            SectionNumber = GetPE32SectionNumberFromVA(FileMapVA, PEHeader64->OptionalHeader.AddressOfEntryPoint + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase);
                            if(SectionNumber != -1)
                            {
                                SectionAttributes = (DWORD)GetPE32DataFromMappedFile(FileMapVA, SectionNumber, UE_SECTIONFLAGS);
                                if(SectionAttributes & IMAGE_SCN_MEM_EXECUTE || SectionAttributes & IMAGE_SCN_CNT_CODE)
                                {
                                    // Should never execute
                                }
                                else
                                {
                                    if(!SetPE32DataForMappedFile(FileMapVA, SectionNumber, UE_SECTIONFLAGS, 0xE0000020))
                                    {
                                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                                        return false;
                                    }
                                }
                            }
                        }
                        /*
                            Fix end
                        */
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        if(FileFixed)
                        {
                            myFileFixInfo->OveralEvaluation = UE_RESULT_FILE_OK;
                            myFileFixInfo->FileFixPerformed = FileFixed;
                        }
                        return true;
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        myFileFixInfo->FixingTerminatedByException = true;
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return false;
                    }
                }
            }
            else
            {
                UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                return false;
            }
        }
    }
    else if(myFileFixInfo->FileFixPerformed)
    {
        if(MapFileExW(szFileName, UE_ACCESS_ALL, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
        {
            DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
            if(EngineValidateHeader(FileMapVA, FileHandle, NULL, DOSHeader, true))
            {
                PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
                PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
                if(PEHeader32->Signature == 0x4550 && PEHeader32->OptionalHeader.Magic == 0x10B)
                {
                    FileIs64 = false;
                }
                else if(PEHeader32->Signature == 0x4550 && PEHeader32->OptionalHeader.Magic == 0x20B)
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
                    if(myFileFixInfo->StrippedRelocation)
                    {
                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = myFileFixInfo->OriginalRelocationTableAddress;
                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = myFileFixInfo->OriginalRelocationTableSize;
                    }
                    if(myFileFixInfo->StrippedExports)
                    {
                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = myFileFixInfo->OriginalExportTableAddress;
                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = myFileFixInfo->OriginalExportTableSize;
                    }
                    if(myFileFixInfo->StrippedResources)
                    {
                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = myFileFixInfo->OriginalResourceTableAddress;
                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = myFileFixInfo->OriginalResourceTableSize;
                    }
                    if(myFileFixInfo->StrippedTLS)
                    {
                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = myFileFixInfo->OriginalTLSTableAddress;
                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = myFileFixInfo->OriginalTLSTableSize;
                    }
                    if(myFileFixInfo->StrippedLoadConfig)
                    {
                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = myFileFixInfo->OriginalLoadConfigTableAddress;
                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = myFileFixInfo->OriginalLoadConfigTableSize;
                    }
                    if(myFileFixInfo->StrippedBoundImports)
                    {
                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = myFileFixInfo->OriginalBoundImportTableAddress;
                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = myFileFixInfo->OriginalBoundImportTableSize;
                    }
                    if(myFileFixInfo->StrippedIAT)
                    {
                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = myFileFixInfo->OriginalImportAddressTableAddress;
                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = myFileFixInfo->OriginalImportAddressTableSize;
                    }
                    if(myFileFixInfo->StrippedCOM)
                    {
                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress = myFileFixInfo->OriginalCOMTableAddress;
                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size = myFileFixInfo->OriginalCOMTableSize;
                    }
                }
                else
                {
                    if(myFileFixInfo->StrippedRelocation)
                    {
                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = myFileFixInfo->OriginalRelocationTableAddress;
                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = myFileFixInfo->OriginalRelocationTableSize;
                    }
                    if(myFileFixInfo->StrippedExports)
                    {
                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = myFileFixInfo->OriginalExportTableAddress;
                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = myFileFixInfo->OriginalExportTableSize;
                    }
                    if(myFileFixInfo->StrippedResources)
                    {
                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = myFileFixInfo->OriginalResourceTableAddress;
                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = myFileFixInfo->OriginalResourceTableSize;
                    }
                    if(myFileFixInfo->StrippedTLS)
                    {
                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = myFileFixInfo->OriginalTLSTableAddress;
                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = myFileFixInfo->OriginalTLSTableSize;
                    }
                    if(myFileFixInfo->StrippedLoadConfig)
                    {
                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = myFileFixInfo->OriginalLoadConfigTableAddress;
                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = myFileFixInfo->OriginalLoadConfigTableSize;
                    }
                    if(myFileFixInfo->StrippedBoundImports)
                    {
                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = myFileFixInfo->OriginalBoundImportTableAddress;
                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = myFileFixInfo->OriginalBoundImportTableSize;
                    }
                    if(myFileFixInfo->StrippedIAT)
                    {
                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = myFileFixInfo->OriginalImportAddressTableAddress;
                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = myFileFixInfo->OriginalImportAddressTableSize;
                    }
                    if(myFileFixInfo->StrippedCOM)
                    {
                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress = myFileFixInfo->OriginalCOMTableAddress;
                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size = myFileFixInfo->OriginalCOMTableSize;
                    }
                }
                UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                return true;
            }
        }
    }
    return false;
}
