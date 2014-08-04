#include "stdafx.h"
#include "definitions.h"
#include "Global.Mapping.h"
#include "Global.Engine.h"

static LPVOID expTableData = NULL;
static LPVOID expTableDataCWP = NULL;
static ULONG_PTR expImageBase = 0;
static DWORD expExportNumber = 0;
static bool expNamePresent = false;
static DWORD expExportAddress[1000];
static DWORD expSortedNamePointers[1000];
static ULONG_PTR expNamePointers[1000];
static DWORD expNameHashes[1000];
static WORD expOrdinals[1000];
static IMAGE_EXPORT_DIRECTORY expExportData;

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
                return true;
            }
        }
        expExportAddress[expExportNumber] = ExportRelativeAddress;
        expNamePointers[expExportNumber] = (ULONG_PTR)expTableDataCWP;
        expNameHashes[expExportNumber] = (DWORD)EngineHashString(szExportName);
        expOrdinals[expExportNumber] = (WORD)(expExportNumber);
        RtlMoveMemory(expTableDataCWP, szExportName, lstrlenA(szExportName));
        expTableDataCWP = (LPVOID)((ULONG_PTR)expTableDataCWP + lstrlenA(szExportName) + 2);
        expExportNumber++;
        return true;
    }
    return false;
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
                return true;
            }
            else
            {
                return true;
            }
        }
    }
    return false;
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
    DynBuf expBuildExportDyn;
    LPVOID expBuildExportDataCWP;
    DWORD StorePlaceRVA = (DWORD)ConvertFileOffsetToVA(FileMapVA, StorePlace, false);
    ULONG_PTR TempULONG;
    DWORD TempDWORD;
    BOOL FileIs64 = false;

    if(expTableDataCWP != NULL)
    {
        expBuildExportData = expBuildExportDyn.Allocate(ExporterEstimatedSize());
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

        RtlMoveMemory((LPVOID)StorePlace, expBuildExportData, (DWORD)((ULONG_PTR)expBuildExportDataCWP - (ULONG_PTR)expBuildExportData));

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
        ExporterCleanup();
        return true;
    }
    return false;
}
__declspec(dllexport) bool TITCALL ExporterBuildExportTableEx(char* szExportFileName, char* szSectionName)
{

    wchar_t uniExportFileName[MAX_PATH] = {};

    if(szExportFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szExportFileName, lstrlenA(szExportFileName) + 1, uniExportFileName, sizeof(uniExportFileName) / (sizeof(uniExportFileName[0])));
        return(ExporterBuildExportTableExW(uniExportFileName, szSectionName));
    }
    else
    {
        return false;
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
            if(NewSectionFO)
                ReturnValue = ExporterBuildExportTable(NewSectionFO, FileMapVA);
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
__declspec(dllexport) bool TITCALL ExporterLoadExportTable(char* szFileName)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        return(ExporterLoadExportTableW(uniFileName));
    }
    else
    {
        return false;
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
                return false;
            }
            if(!FileIs64)
            {
                if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != NULL)
                {
                    PEExports = (PIMAGE_EXPORT_DIRECTORY)(ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + PEHeader32->OptionalHeader.ImageBase), true));
                    if(PEExports)
                    {
                        ExportedFunctions = (PEXPORTED_DATA)(ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)(PEExports->AddressOfFunctions + PEHeader32->OptionalHeader.ImageBase), true));
                        if(ExportedFunctions)
                        {
                            ExporterInit(50 * 1024, (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase, PEExports->Base, NULL);
                            ExportPresent = true;
                        }
                    }
                }
            }
            else
            {
                if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != NULL)
                {
                    PEExports = (PIMAGE_EXPORT_DIRECTORY)(ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + PEHeader64->OptionalHeader.ImageBase), true));
                    if(PEExports)
                    {
                        ExportedFunctions = (PEXPORTED_DATA)(ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)(PEExports->AddressOfFunctions + PEHeader64->OptionalHeader.ImageBase), true));
                        if(ExportedFunctions)
                        {
                            ExporterInit(50 * 1024, (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, PEExports->Base, NULL);
                            ExportPresent = true;
                        }
                    }
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
                    if(ExportedFunctionNames && ExportedFunctionOrdinals)
                    {
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
                            if(ExportName)
                                ExporterAddNewExport(ExportName, ExportedFunctions->ExportedItem);
                        }
                        ExportedFunctions = (PEXPORTED_DATA)((ULONG_PTR)ExportedFunctions + 4);
                    }
                }
                UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                return true;
            }
            else
            {
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
    else
    {
        return false;
    }
    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
    return false;
}
