#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.h"
#include "Global.Mapping.h"

__declspec(dllexport) ULONG_PTR TITCALL GetPE32DataFromMappedFile(ULONG_PTR FileMapVA, DWORD WhichSection, DWORD WhichData)
{

    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_SECTION_HEADER PESections;
    DWORD SectionNumber = 0;
    BOOL FileIs64;
    static char sectionName[9] = "";

    if(FileMapVA != NULL)
    {
        DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
        if(EngineValidateHeader(FileMapVA, NULL, NULL, DOSHeader, true))
        {
            PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            if(PEHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            {
                FileIs64 = false;
            }
            else if(PEHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            {
                FileIs64 = true;
            }
            else
            {
                return(0);
            }
            if(!FileIs64)
            {
                PESections = IMAGE_FIRST_SECTION(PEHeader32);
                SectionNumber = PEHeader32->FileHeader.NumberOfSections;
                if(WhichData < UE_SECTIONNAME)
                {
                    if(WhichData == UE_PE_OFFSET)
                    {
                        return(DOSHeader->e_lfanew);
                    }
                    else if(WhichData == UE_IMAGEBASE)
                    {
                        return(PEHeader32->OptionalHeader.ImageBase);
                    }
                    else if(WhichData == UE_OEP)
                    {
                        return(PEHeader32->OptionalHeader.AddressOfEntryPoint);
                    }
                    else if(WhichData == UE_BASEOFCODE)
                    {
                        return(PEHeader32->OptionalHeader.BaseOfCode);
                    }
                    else if(WhichData == UE_BASEOFDATA)
                    {
                        return(PEHeader32->OptionalHeader.BaseOfData);
                    }
                    else if(WhichData == UE_SIZEOFIMAGE)
                    {
                        return(PEHeader32->OptionalHeader.SizeOfImage);
                    }
                    else if(WhichData == UE_SIZEOFHEADERS)
                    {
                        return(PEHeader32->OptionalHeader.SizeOfHeaders);
                    }
                    else if(WhichData == UE_SIZEOFOPTIONALHEADER)
                    {
                        return(PEHeader32->FileHeader.SizeOfOptionalHeader);
                    }
                    else if(WhichData == UE_SECTIONALIGNMENT)
                    {
                        return(PEHeader32->OptionalHeader.SectionAlignment);
                    }
                    else if(WhichData == UE_IMPORTTABLEADDRESS)
                    {
                        return(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
                    }
                    else if(WhichData == UE_IMPORTTABLESIZE)
                    {
                        return(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
                    }
                    else if(WhichData == UE_RESOURCETABLEADDRESS)
                    {
                        return(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
                    }
                    else if(WhichData == UE_RESOURCETABLESIZE)
                    {
                        return(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size);
                    }
                    else if(WhichData == UE_EXPORTTABLEADDRESS)
                    {
                        return(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                    }
                    else if(WhichData == UE_EXPORTTABLESIZE)
                    {
                        return(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
                    }
                    else if(WhichData == UE_TLSTABLEADDRESS)
                    {
                        return(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
                    }
                    else if(WhichData == UE_TLSTABLESIZE)
                    {
                        return(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size);
                    }
                    else if(WhichData == UE_RELOCATIONTABLEADDRESS)
                    {
                        return(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
                    }
                    else if(WhichData == UE_RELOCATIONTABLESIZE)
                    {
                        return(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
                    }
                    else if(WhichData == UE_TIMEDATESTAMP)
                    {
                        return(PEHeader32->FileHeader.TimeDateStamp);
                    }
                    else if(WhichData == UE_SECTIONNUMBER)
                    {
                        return(PEHeader32->FileHeader.NumberOfSections);
                    }
                    else if(WhichData == UE_CHECKSUM)
                    {
                        return(PEHeader32->OptionalHeader.CheckSum);
                    }
                    else if(WhichData == UE_SUBSYSTEM)
                    {
                        return(PEHeader32->OptionalHeader.Subsystem);
                    }
                    else if(WhichData == UE_CHARACTERISTICS)
                    {
                        return(PEHeader32->FileHeader.Characteristics);
                    }
                    else if(WhichData == UE_NUMBEROFRVAANDSIZES)
                    {
                        return(PEHeader32->OptionalHeader.NumberOfRvaAndSizes);
                    }
                    else if(WhichData == UE_DLLCHARACTERISTICS)
                    {
                        return(PEHeader32->OptionalHeader.DllCharacteristics);
                    }
                    else
                    {
                        return(0);
                    }
                }
                else
                {
                    if(SectionNumber >= WhichSection)
                    {
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + WhichSection * IMAGE_SIZEOF_SECTION_HEADER);
                        if(WhichData == UE_SECTIONNAME)
                        {
                            memcpy(sectionName, PESections->Name, 8);
                            return (ULONG_PTR)sectionName;
                        }
                        else if(WhichData == UE_SECTIONVIRTUALOFFSET)
                        {
                            return(PESections->VirtualAddress);
                        }
                        else if(WhichData == UE_SECTIONVIRTUALSIZE)
                        {
                            return(PESections->Misc.VirtualSize);
                        }
                        else if(WhichData == UE_SECTIONRAWOFFSET)
                        {
                            return(PESections->PointerToRawData);
                        }
                        else if(WhichData == UE_SECTIONRAWSIZE)
                        {
                            return(PESections->SizeOfRawData);
                        }
                        else if(WhichData == UE_SECTIONFLAGS)
                        {
                            return(PESections->Characteristics);
                        }
                        else
                        {
                            return(0);
                        }
                    }
                }
                return(0);
            }
            else
            {
                PESections = IMAGE_FIRST_SECTION(PEHeader64);
                SectionNumber = PEHeader64->FileHeader.NumberOfSections;
                if(WhichData < UE_SECTIONNAME)
                {
                    if(WhichData == UE_PE_OFFSET)
                    {
                        return(DOSHeader->e_lfanew);
                    }
                    else if(WhichData == UE_IMAGEBASE)
                    {
                        return (ULONG_PTR)(PEHeader64->OptionalHeader.ImageBase);
                    }
                    else if(WhichData == UE_OEP)
                    {
                        return(PEHeader64->OptionalHeader.AddressOfEntryPoint);
                    }
                    else if(WhichData == UE_BASEOFCODE)
                    {
                        return(PEHeader64->OptionalHeader.BaseOfCode);
                    }
                    /* non-existent in IMAGE_OPTIONAL_HEADER64
                    else if(WhichData == UE_BASEOFDATA)
                    {
                        return(PEHeader64->OptionalHeader.BaseOfData);
                    }*/
                    else if(WhichData == UE_SIZEOFIMAGE)
                    {
                        return(PEHeader64->OptionalHeader.SizeOfImage);
                    }
                    else if(WhichData == UE_SIZEOFHEADERS)
                    {
                        return(PEHeader64->OptionalHeader.SizeOfHeaders);
                    }
                    else if(WhichData == UE_SIZEOFOPTIONALHEADER)
                    {
                        return(PEHeader64->FileHeader.SizeOfOptionalHeader);
                    }
                    else if(WhichData == UE_SECTIONALIGNMENT)
                    {
                        return(PEHeader64->OptionalHeader.SectionAlignment);
                    }
                    else if(WhichData == UE_IMPORTTABLEADDRESS)
                    {
                        return(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
                    }
                    else if(WhichData == UE_IMPORTTABLESIZE)
                    {
                        return(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
                    }
                    else if(WhichData == UE_RESOURCETABLEADDRESS)
                    {
                        return(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
                    }
                    else if(WhichData == UE_RESOURCETABLESIZE)
                    {
                        return(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size);
                    }
                    else if(WhichData == UE_EXPORTTABLEADDRESS)
                    {
                        return(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                    }
                    else if(WhichData == UE_EXPORTTABLESIZE)
                    {
                        return(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
                    }
                    else if(WhichData == UE_TLSTABLEADDRESS)
                    {
                        return(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
                    }
                    else if(WhichData == UE_TLSTABLESIZE)
                    {
                        return(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size);
                    }
                    else if(WhichData == UE_RELOCATIONTABLEADDRESS)
                    {
                        return(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
                    }
                    else if(WhichData == UE_RELOCATIONTABLESIZE)
                    {
                        return(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
                    }
                    else if(WhichData == UE_TIMEDATESTAMP)
                    {
                        return(PEHeader64->FileHeader.TimeDateStamp);
                    }
                    else if(WhichData == UE_SECTIONNUMBER)
                    {
                        return(PEHeader64->FileHeader.NumberOfSections);
                    }
                    else if(WhichData == UE_CHECKSUM)
                    {
                        return(PEHeader64->OptionalHeader.CheckSum);
                    }
                    else if(WhichData == UE_SUBSYSTEM)
                    {
                        return(PEHeader64->OptionalHeader.Subsystem);
                    }
                    else if(WhichData == UE_CHARACTERISTICS)
                    {
                        return(PEHeader64->FileHeader.Characteristics);
                    }
                    else if(WhichData == UE_NUMBEROFRVAANDSIZES)
                    {
                        return(PEHeader64->OptionalHeader.NumberOfRvaAndSizes);
                    }
                    else if(WhichData == UE_DLLCHARACTERISTICS)
                    {
                        return(PEHeader64->OptionalHeader.DllCharacteristics);
                    }
                    else
                    {
                        return(0);
                    }
                }
                else
                {
                    if(SectionNumber >= WhichSection)
                    {
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + WhichSection * IMAGE_SIZEOF_SECTION_HEADER);
                        if(WhichData == UE_SECTIONNAME)
                        {
                            memcpy(sectionName, PESections->Name, 8);
                            return (ULONG_PTR)sectionName;
                        }
                        else if(WhichData == UE_SECTIONVIRTUALOFFSET)
                        {
                            return(PESections->VirtualAddress);
                        }
                        else if(WhichData == UE_SECTIONVIRTUALSIZE)
                        {
                            return(PESections->Misc.VirtualSize);
                        }
                        else if(WhichData == UE_SECTIONRAWOFFSET)
                        {
                            return(PESections->PointerToRawData);
                        }
                        else if(WhichData == UE_SECTIONRAWSIZE)
                        {
                            return(PESections->SizeOfRawData);
                        }
                        else if(WhichData == UE_SECTIONFLAGS)
                        {
                            return(PESections->Characteristics);
                        }
                        else
                        {
                            return(0);
                        }
                    }
                }
                return(0);
            }
        }
        else
        {
            return(0);
        }
    }
    return(0);
}
__declspec(dllexport) ULONG_PTR TITCALL GetPE32Data(char* szFileName, DWORD WhichSection, DWORD WhichData)
{

    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    ULONG_PTR ReturnValue = 0;

    if(MapFileEx(szFileName, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        ReturnValue = GetPE32DataFromMappedFile(FileMapVA, WhichSection, WhichData);
        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
        return(ReturnValue);
    }
    else
    {
        return(0);
    }
}
__declspec(dllexport) ULONG_PTR TITCALL GetPE32DataW(const wchar_t* szFileName, DWORD WhichSection, DWORD WhichData)
{

    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    ULONG_PTR ReturnValue = 0;

    if(MapFileExW(szFileName, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        ReturnValue = GetPE32DataFromMappedFile(FileMapVA, WhichSection, WhichData);
        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
        return(ReturnValue);
    }
    else
    {
        return(0);
    }
}
__declspec(dllexport) bool TITCALL GetPE32DataFromMappedFileEx(ULONG_PTR FileMapVA, LPVOID DataStorage)
{

    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    BOOL FileIs64;
    PPE32Struct PE32Structure = (PPE32Struct)DataStorage;
    PPE64Struct PE64Structure = (PPE64Struct)DataStorage;

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
                PE32Structure->PE32Offset = DOSHeader->e_lfanew;
                PE32Structure->ImageBase = PEHeader32->OptionalHeader.ImageBase;
                PE32Structure->OriginalEntryPoint = PEHeader32->OptionalHeader.AddressOfEntryPoint;
                PE32Structure->BaseOfCode = PEHeader32->OptionalHeader.BaseOfCode;
                PE32Structure->BaseOfData = PEHeader32->OptionalHeader.BaseOfData;
                PE32Structure->NtSizeOfImage = PEHeader32->OptionalHeader.SizeOfImage;
                PE32Structure->NtSizeOfHeaders = PEHeader32->OptionalHeader.SizeOfHeaders;
                PE32Structure->SizeOfOptionalHeaders = PEHeader32->FileHeader.SizeOfOptionalHeader;
                PE32Structure->FileAlignment = PEHeader32->OptionalHeader.FileAlignment;
                PE32Structure->SectionAligment = PEHeader32->OptionalHeader.SectionAlignment;
                PE32Structure->ImportTableAddress = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                PE32Structure->ImportTableSize = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
                PE32Structure->ResourceTableAddress = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
                PE32Structure->ResourceTableSize = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
                PE32Structure->ExportTableAddress = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                PE32Structure->ExportTableSize = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
                PE32Structure->TLSTableAddress = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
                PE32Structure->TLSTableSize = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
                PE32Structure->RelocationTableAddress = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                PE32Structure->RelocationTableSize = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                PE32Structure->TimeDateStamp = PEHeader32->FileHeader.TimeDateStamp;
                PE32Structure->SectionNumber = PEHeader32->FileHeader.NumberOfSections;
                PE32Structure->CheckSum = PEHeader32->OptionalHeader.CheckSum;
                PE32Structure->SubSystem = PEHeader32->OptionalHeader.Subsystem;
                PE32Structure->Characteristics = PEHeader32->FileHeader.Characteristics;
                PE32Structure->NumberOfRvaAndSizes = PEHeader32->OptionalHeader.NumberOfRvaAndSizes;
                return true;
            }
            else
            {
                PE64Structure->PE64Offset = DOSHeader->e_lfanew;
                PE64Structure->ImageBase = PEHeader64->OptionalHeader.ImageBase;
                PE64Structure->OriginalEntryPoint = PEHeader64->OptionalHeader.AddressOfEntryPoint;
                PE64Structure->BaseOfCode = PEHeader32->OptionalHeader.BaseOfCode;
                PE64Structure->BaseOfData = PEHeader32->OptionalHeader.BaseOfData;
                PE64Structure->NtSizeOfImage = PEHeader64->OptionalHeader.SizeOfImage;
                PE64Structure->NtSizeOfHeaders = PEHeader64->OptionalHeader.SizeOfHeaders;
                PE64Structure->SizeOfOptionalHeaders = PEHeader64->FileHeader.SizeOfOptionalHeader;
                PE64Structure->FileAlignment = PEHeader64->OptionalHeader.FileAlignment;
                PE64Structure->SectionAligment = PEHeader64->OptionalHeader.SectionAlignment;
                PE64Structure->ImportTableAddress = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                PE64Structure->ImportTableSize = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
                PE64Structure->ResourceTableAddress = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
                PE64Structure->ResourceTableSize = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
                PE64Structure->ExportTableAddress = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                PE64Structure->ExportTableSize = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
                PE64Structure->TLSTableAddress = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
                PE64Structure->TLSTableSize = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
                PE64Structure->RelocationTableAddress = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                PE64Structure->RelocationTableSize = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                PE64Structure->TimeDateStamp = PEHeader64->FileHeader.TimeDateStamp;
                PE64Structure->SectionNumber = PEHeader64->FileHeader.NumberOfSections;
                PE64Structure->CheckSum = PEHeader64->OptionalHeader.CheckSum;
                PE64Structure->SubSystem = PEHeader64->OptionalHeader.Subsystem;
                PE64Structure->Characteristics = PEHeader64->FileHeader.Characteristics;
                PE64Structure->NumberOfRvaAndSizes = PEHeader64->OptionalHeader.NumberOfRvaAndSizes;
                return true;
            }
        }
        else
        {
            return false;
        }
    }
    return false;
}
__declspec(dllexport) bool TITCALL GetPE32DataEx(char* szFileName, LPVOID DataStorage)
{

    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    ULONG_PTR ReturnValue = 0;

    if(MapFileEx(szFileName, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        ReturnValue = GetPE32DataFromMappedFileEx(FileMapVA, DataStorage);
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
__declspec(dllexport) bool TITCALL GetPE32DataExW(wchar_t* szFileName, LPVOID DataStorage)
{

    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    ULONG_PTR ReturnValue = 0;

    if(MapFileExW(szFileName, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        ReturnValue = GetPE32DataFromMappedFileEx(FileMapVA, DataStorage);
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
__declspec(dllexport) bool TITCALL SetPE32DataForMappedFile(ULONG_PTR FileMapVA, DWORD WhichSection, DWORD WhichData, ULONG_PTR NewDataValue)
{

    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_SECTION_HEADER PESections;
    DWORD SectionNumber = 0;
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
                return false;
            }
            if(!FileIs64)
            {
                PESections = IMAGE_FIRST_SECTION(PEHeader32);
                SectionNumber = PEHeader32->FileHeader.NumberOfSections;
                __try
                {
                    if(WhichData < UE_SECTIONNAME)
                    {
                        if(WhichData == UE_PE_OFFSET)
                        {
                            DOSHeader->e_lfanew = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_IMAGEBASE)
                        {
                            PEHeader32->OptionalHeader.ImageBase = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_OEP)
                        {
                            PEHeader32->OptionalHeader.AddressOfEntryPoint = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_BASEOFCODE)
                        {
                            PEHeader32->OptionalHeader.BaseOfCode = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_BASEOFDATA)
                        {
                            PEHeader32->OptionalHeader.BaseOfData = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_SIZEOFIMAGE)
                        {
                            PEHeader32->OptionalHeader.SizeOfImage = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_SIZEOFHEADERS)
                        {
                            PEHeader32->OptionalHeader.SizeOfHeaders = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_SIZEOFOPTIONALHEADER)
                        {
                            PEHeader32->FileHeader.SizeOfOptionalHeader = (WORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_SECTIONALIGNMENT)
                        {
                            PEHeader32->OptionalHeader.SectionAlignment = (WORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_IMPORTTABLEADDRESS)
                        {
                            PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_IMPORTTABLESIZE)
                        {
                            PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_RESOURCETABLEADDRESS)
                        {
                            PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_RESOURCETABLESIZE)
                        {
                            PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_EXPORTTABLEADDRESS)
                        {
                            PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_EXPORTTABLESIZE)
                        {
                            PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_TLSTABLEADDRESS)
                        {
                            PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_TLSTABLESIZE)
                        {
                            PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_RELOCATIONTABLEADDRESS)
                        {
                            PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_RELOCATIONTABLESIZE)
                        {
                            PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_TIMEDATESTAMP)
                        {
                            PEHeader32->FileHeader.TimeDateStamp = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_SECTIONNUMBER)
                        {
                            PEHeader32->FileHeader.NumberOfSections = (WORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_CHECKSUM)
                        {
                            PEHeader32->OptionalHeader.CheckSum = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_SUBSYSTEM)
                        {
                            PEHeader32->OptionalHeader.Subsystem = (WORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_CHARACTERISTICS)
                        {
                            PEHeader32->FileHeader.Characteristics = (WORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_NUMBEROFRVAANDSIZES)
                        {
                            PEHeader32->OptionalHeader.NumberOfRvaAndSizes = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_DLLCHARACTERISTICS)
                        {
                            PEHeader32->OptionalHeader.DllCharacteristics = (WORD)NewDataValue;
                            return true;
                        }
                        else
                        {
                            return false;
                        }
                    }
                    else
                    {
                        if(WhichSection <= SectionNumber)
                        {
                            PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + WhichSection * IMAGE_SIZEOF_SECTION_HEADER);
                            if(WhichData == UE_SECTIONNAME)
                            {
                                memcpy(PESections->Name, (void*)NewDataValue, 8);
                                return true;
                            }
                            else if(WhichData == UE_SECTIONVIRTUALOFFSET)
                            {
                                PESections->VirtualAddress = (DWORD)NewDataValue;
                                return true;
                            }
                            else if(WhichData == UE_SECTIONVIRTUALSIZE)
                            {
                                PESections->Misc.VirtualSize = (DWORD)NewDataValue;
                                return true;
                            }
                            else if(WhichData == UE_SECTIONRAWOFFSET)
                            {
                                PESections->PointerToRawData = (DWORD)NewDataValue;
                                return true;
                            }
                            else if(WhichData == UE_SECTIONRAWSIZE)
                            {
                                PESections->SizeOfRawData = (DWORD)NewDataValue;
                                return true;
                            }
                            else if(WhichData == UE_SECTIONFLAGS)
                            {
                                PESections->Characteristics = (DWORD)NewDataValue;
                                return true;
                            }
                            else
                            {
                                return false;
                            }
                        }
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    return false;
                }
                return false;
            }
            else
            {
                PESections = IMAGE_FIRST_SECTION(PEHeader64);
                SectionNumber = PEHeader64->FileHeader.NumberOfSections;
                __try
                {
                    if(WhichData < UE_SECTIONNAME)
                    {
                        if(WhichData == UE_PE_OFFSET)
                        {
                            DOSHeader->e_lfanew = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_IMAGEBASE)
                        {
                            PEHeader64->OptionalHeader.ImageBase = NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_OEP)
                        {
                            PEHeader64->OptionalHeader.AddressOfEntryPoint = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_BASEOFCODE)
                        {
                            PEHeader64->OptionalHeader.BaseOfCode = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_BASEOFDATA)
                        {
                            //non-existant in IMAGE_OPTIONAL_HEADER64
                            return false;
                        }
                        else if(WhichData == UE_SIZEOFIMAGE)
                        {
                            PEHeader64->OptionalHeader.SizeOfImage = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_SIZEOFHEADERS)
                        {
                            PEHeader64->OptionalHeader.SizeOfHeaders = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_SIZEOFOPTIONALHEADER)
                        {
                            PEHeader64->FileHeader.SizeOfOptionalHeader = (WORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_SECTIONALIGNMENT)
                        {
                            PEHeader64->OptionalHeader.SectionAlignment = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_IMPORTTABLEADDRESS)
                        {
                            PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_IMPORTTABLESIZE)
                        {
                            PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_RESOURCETABLEADDRESS)
                        {
                            PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_RESOURCETABLESIZE)
                        {
                            PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_EXPORTTABLEADDRESS)
                        {
                            PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_EXPORTTABLESIZE)
                        {
                            PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_TLSTABLEADDRESS)
                        {
                            PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_TLSTABLESIZE)
                        {
                            PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_RELOCATIONTABLEADDRESS)
                        {
                            PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_RELOCATIONTABLESIZE)
                        {
                            PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_TIMEDATESTAMP)
                        {
                            PEHeader64->FileHeader.TimeDateStamp = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_SECTIONNUMBER)
                        {
                            PEHeader64->FileHeader.NumberOfSections = (WORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_CHECKSUM)
                        {
                            PEHeader64->OptionalHeader.CheckSum = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_SUBSYSTEM)
                        {
                            PEHeader64->OptionalHeader.Subsystem = (WORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_CHARACTERISTICS)
                        {
                            PEHeader64->FileHeader.Characteristics = (WORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_NUMBEROFRVAANDSIZES)
                        {
                            PEHeader64->OptionalHeader.NumberOfRvaAndSizes = (DWORD)NewDataValue;
                            return true;
                        }
                        else if(WhichData == UE_DLLCHARACTERISTICS)
                        {
                            PEHeader64->OptionalHeader.DllCharacteristics = (WORD)NewDataValue;
                            return true;
                        }
                        else
                        {
                            return(0);
                        }
                    }
                    else
                    {
                        if(WhichSection <= SectionNumber)
                        {
                            PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + WhichSection * IMAGE_SIZEOF_SECTION_HEADER);
                            if(WhichData == UE_SECTIONNAME)
                            {
                                return false;
                            }
                            else if(WhichData == UE_SECTIONVIRTUALOFFSET)
                            {
                                PESections->VirtualAddress = (DWORD)NewDataValue;
                                return true;
                            }
                            else if(WhichData == UE_SECTIONVIRTUALSIZE)
                            {
                                PESections->Misc.VirtualSize = (DWORD)NewDataValue;
                                return true;
                            }
                            else if(WhichData == UE_SECTIONRAWOFFSET)
                            {
                                PESections->PointerToRawData = (DWORD)NewDataValue;
                                return true;
                            }
                            else if(WhichData == UE_SECTIONRAWSIZE)
                            {
                                PESections->SizeOfRawData = (DWORD)NewDataValue;
                                return true;
                            }
                            else if(WhichData == UE_SECTIONFLAGS)
                            {
                                PESections->Characteristics = (DWORD)NewDataValue;
                                return true;
                            }
                            else
                            {
                                return false;
                            }
                        }
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    return false;
                }
                return false;
            }
        }
        else
        {
            return false;
        }
    }
    return false;
}
__declspec(dllexport) bool TITCALL SetPE32Data(char* szFileName, DWORD WhichSection, DWORD WhichData, ULONG_PTR NewDataValue)
{

    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    ULONG_PTR ReturnValue = 0;

    if(MapFileEx(szFileName, UE_ACCESS_ALL, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        ReturnValue = SetPE32DataForMappedFile(FileMapVA, WhichSection, WhichData, NewDataValue);
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
__declspec(dllexport) bool TITCALL SetPE32DataW(wchar_t* szFileName, DWORD WhichSection, DWORD WhichData, ULONG_PTR NewDataValue)
{

    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    ULONG_PTR ReturnValue = 0;

    if(MapFileExW(szFileName, UE_ACCESS_ALL, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        ReturnValue = SetPE32DataForMappedFile(FileMapVA, WhichSection, WhichData, NewDataValue);
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
__declspec(dllexport) bool TITCALL SetPE32DataForMappedFileEx(ULONG_PTR FileMapVA, LPVOID DataStorage)
{

    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    BOOL FileIs64;
    PPE32Struct PE32Structure = (PPE32Struct)DataStorage;
    PPE64Struct PE64Structure = (PPE64Struct)DataStorage;

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
                __try
                {
                    DOSHeader->e_lfanew = PE32Structure->PE32Offset;
                    PEHeader32->OptionalHeader.ImageBase = PE32Structure->ImageBase;
                    PEHeader32->OptionalHeader.AddressOfEntryPoint = PE32Structure->OriginalEntryPoint;
                    PEHeader32->OptionalHeader.BaseOfCode = PE32Structure->BaseOfCode;
                    PEHeader32->OptionalHeader.BaseOfData = PE32Structure->BaseOfData;
                    PEHeader32->OptionalHeader.SizeOfImage = PE32Structure->NtSizeOfImage;
                    PEHeader32->OptionalHeader.SizeOfHeaders = PE32Structure->NtSizeOfHeaders;
                    PEHeader32->FileHeader.SizeOfOptionalHeader = PE32Structure->SizeOfOptionalHeaders;
                    PEHeader32->OptionalHeader.FileAlignment = PE32Structure->FileAlignment;
                    PEHeader32->OptionalHeader.SectionAlignment = PE32Structure->SectionAligment;
                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = PE32Structure->ImportTableAddress;
                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = PE32Structure->ImportTableSize;
                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = PE32Structure->ResourceTableAddress;
                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = PE32Structure->ResourceTableSize;
                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = PE32Structure->ExportTableAddress;
                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = PE32Structure->ExportTableSize;
                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = PE32Structure->TLSTableAddress;
                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = PE32Structure->TLSTableSize;
                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = PE32Structure->RelocationTableAddress;
                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = PE32Structure->RelocationTableSize;
                    PEHeader32->FileHeader.TimeDateStamp = PE32Structure->TimeDateStamp;
                    PEHeader32->FileHeader.NumberOfSections = PE32Structure->SectionNumber;
                    PEHeader32->OptionalHeader.CheckSum = PE32Structure->CheckSum;
                    PEHeader32->OptionalHeader.Subsystem = PE32Structure->SubSystem;
                    PEHeader32->FileHeader.Characteristics = PE32Structure->Characteristics;
                    PEHeader32->OptionalHeader.NumberOfRvaAndSizes = PE32Structure->NumberOfRvaAndSizes;
                    return true;
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    return false;
                }
            }
            else
            {
                __try
                {
                    DOSHeader->e_lfanew = PE64Structure->PE64Offset;
                    PEHeader64->OptionalHeader.ImageBase = PE64Structure->ImageBase;
                    PEHeader64->OptionalHeader.AddressOfEntryPoint = PE64Structure->OriginalEntryPoint;
                    PEHeader64->OptionalHeader.BaseOfCode = PE64Structure->BaseOfCode;
                    PEHeader64->OptionalHeader.SizeOfImage = PE64Structure->NtSizeOfImage;
                    PEHeader64->OptionalHeader.SizeOfHeaders = PE64Structure->NtSizeOfHeaders;
                    PEHeader64->FileHeader.SizeOfOptionalHeader = PE64Structure->SizeOfOptionalHeaders;
                    PEHeader64->OptionalHeader.FileAlignment = PE64Structure->FileAlignment;
                    PEHeader64->OptionalHeader.SectionAlignment = PE64Structure->SectionAligment;
                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = PE64Structure->ImportTableAddress;
                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = PE64Structure->ImportTableSize;
                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = PE64Structure->ResourceTableAddress;
                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = PE64Structure->ResourceTableSize;
                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = PE64Structure->ExportTableAddress;
                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = PE64Structure->ExportTableSize;
                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = PE64Structure->TLSTableAddress;
                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = PE64Structure->TLSTableSize;
                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = PE64Structure->RelocationTableAddress;
                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = PE64Structure->RelocationTableSize;
                    PEHeader64->FileHeader.TimeDateStamp = PE64Structure->TimeDateStamp;
                    PEHeader64->FileHeader.NumberOfSections = PE64Structure->SectionNumber;
                    PEHeader64->OptionalHeader.CheckSum = PE64Structure->CheckSum;
                    PEHeader64->OptionalHeader.Subsystem = PE64Structure->SubSystem;
                    PEHeader64->FileHeader.Characteristics = PE64Structure->Characteristics;
                    PEHeader64->OptionalHeader.NumberOfRvaAndSizes = PE64Structure->NumberOfRvaAndSizes;
                    return true;
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    return false;
                }
            }
        }
        else
        {
            return false;
        }
    }
    return false;
}
__declspec(dllexport) bool TITCALL SetPE32DataEx(char* szFileName, LPVOID DataStorage)
{

    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    ULONG_PTR ReturnValue = 0;

    if(MapFileEx(szFileName, UE_ACCESS_ALL, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        ReturnValue = SetPE32DataForMappedFileEx(FileMapVA, DataStorage);
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
__declspec(dllexport) bool TITCALL SetPE32DataExW(wchar_t* szFileName, LPVOID DataStorage)
{

    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    ULONG_PTR ReturnValue = 0;

    if(MapFileExW(szFileName, UE_ACCESS_ALL, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        ReturnValue = SetPE32DataForMappedFileEx(FileMapVA, DataStorage);
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

__declspec(dllexport) bool TITCALL IsFileDLL(char* szFileName, ULONG_PTR FileMapVA)
{

    if(szFileName != NULL)
    {
        if((DWORD)GetPE32Data(szFileName, NULL, UE_CHARACTERISTICS) & 0x2000)
        {
            return true;
        }
    }
    else if(FileMapVA != NULL)
    {
        if((DWORD)GetPE32DataFromMappedFile(FileMapVA, NULL, UE_CHARACTERISTICS) & 0x2000)
        {
            return true;
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL IsFileDLLW(wchar_t* szFileName, ULONG_PTR FileMapVA)
{

    if(szFileName != NULL)
    {
        if((DWORD)GetPE32DataW(szFileName, NULL, UE_CHARACTERISTICS) & 0x2000)
        {
            return true;
        }
    }
    else if(FileMapVA != NULL)
    {
        if((DWORD)GetPE32DataFromMappedFile(FileMapVA, NULL, UE_CHARACTERISTICS) & 0x2000)
        {
            return true;
        }
    }
    return false;
}
