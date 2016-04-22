#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.h"

__declspec(dllexport) long TITCALL GetPE32SectionNumberFromVA(ULONG_PTR FileMapVA, ULONG_PTR AddressToConvert)
{
    if(!FileMapVA)
        return -2;

    PIMAGE_DOS_HEADER DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
    if(EngineValidateHeader(FileMapVA, NULL, NULL, DOSHeader, true))
    {
        PIMAGE_NT_HEADERS32 PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
        PIMAGE_NT_HEADERS64 PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
        BOOL FileIs64;
        if(PEHeader32->OptionalHeader.Magic == 0x10B)
            FileIs64 = false;
        else if(PEHeader32->OptionalHeader.Magic == 0x20B)
            FileIs64 = true;
        else
            return -2;

        if(!FileIs64) //x86
        {
            __try
            {
                ULONG_PTR ConvertAddress = AddressToConvert - PEHeader32->OptionalHeader.ImageBase;
                PIMAGE_SECTION_HEADER PESections = IMAGE_FIRST_SECTION(PEHeader32);
                DWORD SectionNumber = PEHeader32->FileHeader.NumberOfSections;
                DWORD FoundInSection = -1;
                while(SectionNumber > 0)
                {
                    if(PESections->VirtualAddress <= ConvertAddress && ConvertAddress < PESections->VirtualAddress + max(PESections->Misc.VirtualSize, PESections->SizeOfRawData))
                    {
                        FoundInSection = PEHeader32->FileHeader.NumberOfSections - SectionNumber;
                    }
                    PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                    SectionNumber--;
                }
                return FoundInSection;
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                return -2;
            }
        }
        else //x64
        {
            __try
            {
                ULONG_PTR ConvertAddress = AddressToConvert - (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase;
                PIMAGE_SECTION_HEADER PESections = IMAGE_FIRST_SECTION(PEHeader64);
                DWORD SectionNumber = PEHeader64->FileHeader.NumberOfSections;
                DWORD FoundInSection = -1;
                while(SectionNumber > 0)
                {
                    if(PESections->VirtualAddress <= ConvertAddress && ConvertAddress < PESections->VirtualAddress + max(PESections->Misc.VirtualSize, PESections->SizeOfRawData))
                    {
                        FoundInSection = PEHeader64->FileHeader.NumberOfSections - SectionNumber;
                    }
                    PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                    SectionNumber--;
                }
                return FoundInSection;
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                return -2;
            }
        }
    }
    return -2;
}
__declspec(dllexport) ULONG_PTR TITCALL ConvertVAtoFileOffset(ULONG_PTR FileMapVA, ULONG_PTR AddressToConvert, bool ReturnType)
{
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_SECTION_HEADER PESections;
    DWORD SectionNumber = 0;
    ULONG_PTR ConvertedAddress = 0;
    ULONG_PTR ConvertAddress = 0;
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
                return(0);
            }
            if(!FileIs64)
            {
                ConvertAddress = (DWORD)((DWORD)AddressToConvert - PEHeader32->OptionalHeader.ImageBase);
                if(ConvertAddress < PEHeader32->OptionalHeader.SectionAlignment)
                {
                    ConvertedAddress = ConvertAddress;
                }
                PESections = IMAGE_FIRST_SECTION(PEHeader32);
                SectionNumber = PEHeader32->FileHeader.NumberOfSections;
                __try
                {
                    while(SectionNumber > 0)
                    {
                        if(PESections->VirtualAddress <= ConvertAddress && ConvertAddress < PESections->VirtualAddress + max(PESections->Misc.VirtualSize, PESections->SizeOfRawData))
                        {
                            if(ConvertAddress - PESections->VirtualAddress <= PESections->SizeOfRawData)
                            {
                                ConvertedAddress = PESections->PointerToRawData + (ConvertAddress - PESections->VirtualAddress);
                            }
                        }
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                        SectionNumber--;
                    }
                    if(ReturnType)
                    {
                        if(ConvertedAddress != NULL)
                        {
                            ConvertedAddress += FileMapVA;
                        }
                        else if(ConvertAddress == NULL)
                        {
                            ConvertedAddress = FileMapVA;
                        }
                    }
                    return ConvertedAddress;
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    return(0);
                }
            }
            else
            {
                ConvertAddress = (DWORD)(AddressToConvert - PEHeader64->OptionalHeader.ImageBase);
                if(ConvertAddress < PEHeader64->OptionalHeader.SectionAlignment)
                {
                    ConvertedAddress = ConvertAddress;
                }
                PESections = IMAGE_FIRST_SECTION(PEHeader64);
                SectionNumber = PEHeader64->FileHeader.NumberOfSections;
                __try
                {
                    while(SectionNumber > 0)
                    {
                        if(PESections->VirtualAddress <= ConvertAddress && ConvertAddress < PESections->VirtualAddress + max(PESections->Misc.VirtualSize, PESections->SizeOfRawData))
                        {
                            if(ConvertAddress - PESections->VirtualAddress <= PESections->SizeOfRawData)
                            {
                                ConvertedAddress = PESections->PointerToRawData + (ConvertAddress - PESections->VirtualAddress);
                            }
                        }
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                        SectionNumber--;
                    }
                    if(ReturnType)
                    {
                        if(ConvertedAddress != NULL)
                        {
                            ConvertedAddress += FileMapVA;
                        }
                        else if(ConvertAddress == NULL)
                        {
                            ConvertedAddress = FileMapVA;
                        }
                    }
                    return(ConvertedAddress);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    return(0);
                }
            }
        }
        else
        {
            return(0);
        }
    }
    return(0);
}
__declspec(dllexport) ULONG_PTR TITCALL ConvertVAtoFileOffsetEx(ULONG_PTR FileMapVA, DWORD FileSize, ULONG_PTR ImageBase, ULONG_PTR AddressToConvert, bool AddressIsRVA, bool ReturnType)
{

    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_SECTION_HEADER PESections;
    DWORD SectionNumber = 0;
    ULONG_PTR ConvertedAddress = 0;
    ULONG_PTR ConvertAddress = 0;
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
                return(0);
            }
            if(!FileIs64)
            {
                if(!AddressIsRVA)
                {
                    if(ImageBase == NULL)
                    {
                        ConvertAddress = (DWORD)((DWORD)AddressToConvert - PEHeader32->OptionalHeader.ImageBase);
                    }
                    else
                    {
                        ConvertAddress = (DWORD)((DWORD)AddressToConvert - ImageBase);
                    }
                }
                else
                {
                    ConvertAddress = (DWORD)AddressToConvert;
                }
                if(ConvertAddress < PEHeader32->OptionalHeader.SectionAlignment)
                {
                    ConvertedAddress = ConvertAddress;
                }
                PESections = IMAGE_FIRST_SECTION(PEHeader32);
                SectionNumber = PEHeader32->FileHeader.NumberOfSections;
                __try
                {
                    while(SectionNumber > 0)
                    {
                        if(PESections->VirtualAddress <= ConvertAddress && ConvertAddress < PESections->VirtualAddress + max(PESections->Misc.VirtualSize, PESections->SizeOfRawData))
                        {
                            if(ConvertAddress - PESections->VirtualAddress <= PESections->SizeOfRawData)
                            {
                                ConvertedAddress = PESections->PointerToRawData + (ConvertAddress - PESections->VirtualAddress);
                            }
                        }
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                        SectionNumber--;
                    }
                    if(ReturnType)
                    {
                        if(ConvertedAddress != NULL)
                        {
                            ConvertedAddress = ConvertedAddress + FileMapVA;
                        }
                    }
                    if(ReturnType)
                    {
                        if(ConvertedAddress >= FileMapVA && ConvertedAddress <= FileMapVA + FileSize)
                        {
                            return((ULONG_PTR)ConvertedAddress);
                        }
                        else
                        {
                            return(NULL);
                        }
                    }
                    else
                    {
                        if(ConvertedAddress > NULL && ConvertedAddress <= FileSize)
                        {
                            return((ULONG_PTR)ConvertedAddress);
                        }
                        else
                        {
                            return(NULL);
                        }
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    return(NULL);
                }
            }
            else
            {
                if(!AddressIsRVA)
                {
                    if(ImageBase == NULL)
                    {
                        ConvertAddress = (DWORD)(AddressToConvert - PEHeader64->OptionalHeader.ImageBase);
                    }
                    else
                    {
                        ConvertAddress = (DWORD)(AddressToConvert - ImageBase);
                    }
                }
                else
                {
                    ConvertAddress = (DWORD)AddressToConvert;
                }
                if(ConvertAddress < PEHeader64->OptionalHeader.SectionAlignment)
                {
                    ConvertedAddress = ConvertAddress;
                }
                PESections = IMAGE_FIRST_SECTION(PEHeader64);
                SectionNumber = PEHeader64->FileHeader.NumberOfSections;
                __try
                {
                    while(SectionNumber > 0)
                    {
                        if(PESections->VirtualAddress <= ConvertAddress && ConvertAddress < PESections->VirtualAddress + max(PESections->Misc.VirtualSize, PESections->SizeOfRawData))
                        {
                            if(ConvertAddress - PESections->VirtualAddress <= PESections->SizeOfRawData)
                            {
                                ConvertedAddress = PESections->PointerToRawData + (ConvertAddress - PESections->VirtualAddress);
                            }
                        }
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                        SectionNumber--;
                    }
                    if(ReturnType)
                    {
                        if(ConvertedAddress != NULL)
                        {
                            ConvertedAddress = ConvertedAddress + FileMapVA;
                        }
                    }
                    if(ReturnType)
                    {
                        if(ConvertedAddress >= FileMapVA && ConvertedAddress <= FileMapVA + FileSize)
                        {
                            return((ULONG_PTR)ConvertedAddress);
                        }
                        else
                        {
                            return(NULL);
                        }
                    }
                    else
                    {
                        if(ConvertedAddress > NULL && ConvertedAddress <= FileSize)
                        {
                            return((ULONG_PTR)ConvertedAddress);
                        }
                        else
                        {
                            return(NULL);
                        }
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    return(NULL);
                }
            }
        }
        else
        {
            return(0);
        }
    }
    return(0);
}
__declspec(dllexport) ULONG_PTR TITCALL ConvertFileOffsetToVA(ULONG_PTR FileMapVA, ULONG_PTR AddressToConvert, bool ReturnType)
{

    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_SECTION_HEADER PESections;
    DWORD SectionNumber = 0;
    ULONG_PTR ConvertedAddress = 0;
    ULONG_PTR ConvertAddress = 0;
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
                return(0);
            }
            if(!FileIs64)
            {
                ConvertAddress = (DWORD)((DWORD)AddressToConvert - FileMapVA);
                if(ConvertAddress < PEHeader32->OptionalHeader.FileAlignment)
                {
                    ConvertedAddress = ConvertAddress;
                }
                PESections = IMAGE_FIRST_SECTION(PEHeader32);
                SectionNumber = PEHeader32->FileHeader.NumberOfSections;
                __try
                {
                    while(SectionNumber > 0)
                    {
                        if(PESections->PointerToRawData <= ConvertAddress && ConvertAddress <= PESections->PointerToRawData + PESections->SizeOfRawData)
                        {
                            ConvertedAddress = PESections->VirtualAddress + (ConvertAddress - PESections->PointerToRawData);
                        }
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                        SectionNumber--;
                    }
                    if(ReturnType)
                    {
                        if(ConvertedAddress != NULL)
                        {
                            ConvertedAddress = ConvertedAddress + PEHeader32->OptionalHeader.ImageBase;
                        }
                    }
                    else if(ConvertAddress == NULL)
                    {
                        ConvertedAddress = PEHeader32->OptionalHeader.ImageBase;
                    }
                    return(ConvertedAddress);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    return(0);
                }
            }
            else
            {
                ConvertAddress = (DWORD)(AddressToConvert - FileMapVA);
                if(ConvertAddress < PEHeader64->OptionalHeader.FileAlignment)
                {
                    ConvertedAddress = ConvertAddress;
                }
                PESections = IMAGE_FIRST_SECTION(PEHeader64);
                SectionNumber = PEHeader64->FileHeader.NumberOfSections;
                __try
                {
                    while(SectionNumber > 0)
                    {
                        if(PESections->PointerToRawData <= ConvertAddress && ConvertAddress <= PESections->PointerToRawData + PESections->SizeOfRawData)
                        {
                            ConvertedAddress = PESections->VirtualAddress + (ConvertAddress - PESections->PointerToRawData);
                        }
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                        SectionNumber--;
                    }
                    if(ReturnType)
                    {
                        if(ConvertedAddress != NULL)
                        {
                            ConvertedAddress = ConvertedAddress + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase;
                        }
                    }
                    else if(ConvertAddress == NULL)
                    {
                        ConvertedAddress = (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase;
                    }
                    return(ConvertedAddress);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    return(0);
                }
            }
        }
        else
        {
            return(0);
        }
    }
    return(0);
}
__declspec(dllexport) ULONG_PTR TITCALL ConvertFileOffsetToVAEx(ULONG_PTR FileMapVA, DWORD FileSize, ULONG_PTR ImageBase, ULONG_PTR AddressToConvert, bool ReturnType)
{

    ULONG_PTR ConvertedAddress = NULL;
    DWORD cnvSectionAlignment = NULL;
    ULONG_PTR cnvImageBase = NULL;
    DWORD cnvSizeOfImage = NULL;

    if(FileMapVA != NULL)
    {
        if(ImageBase == NULL)
        {
            cnvImageBase = (ULONG_PTR)GetPE32DataFromMappedFile(FileMapVA, NULL, UE_IMAGEBASE);
        }
        else
        {
            cnvImageBase = ImageBase;
        }
        cnvSizeOfImage = (DWORD)GetPE32DataFromMappedFile(FileMapVA, NULL, UE_SIZEOFIMAGE);
        cnvSectionAlignment = (DWORD)GetPE32DataFromMappedFile(FileMapVA, NULL, UE_SECTIONALIGNMENT);
        ConvertedAddress = (ULONG_PTR)ConvertFileOffsetToVA(FileMapVA, AddressToConvert, ReturnType);
        if(ReturnType)
        {
            if(ConvertedAddress >= cnvImageBase + cnvSectionAlignment && ConvertedAddress <= cnvImageBase + cnvSizeOfImage)
            {
                return((ULONG_PTR)ConvertedAddress);
            }
            else
            {
                return(NULL);
            }
        }
        else
        {
            if(ConvertedAddress >= cnvSectionAlignment && ConvertedAddress <= cnvSizeOfImage)
            {
                return((ULONG_PTR)ConvertedAddress);
            }
            else
            {
                return(NULL);
            }
        }
    }
    return(NULL);
}
