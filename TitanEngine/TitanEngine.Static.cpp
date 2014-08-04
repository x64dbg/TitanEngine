#include "stdafx.h"
#include "definitions.h"
#include "Global.Mapping.h"
#include "Global.Handle.h"
#include "Global.Engine.h"
#include "Global.Engine.Hash.h"

// TitanEngine.StaticUnpacker.functions:
__declspec(dllexport) bool TITCALL StaticFileLoad(char* szFileName, DWORD DesiredAccess, bool SimulateLoad, LPHANDLE FileHandle, LPDWORD LoadedSize, LPHANDLE FileMap, PULONG_PTR FileMapVA)
{
    if(!SimulateLoad)
    {
        if(MapFileEx(szFileName, DesiredAccess, FileHandle, LoadedSize, FileMap, FileMapVA, NULL))
        {
            return true;
        }
    }
    else
    {
        *FileMapVA = (ULONG_PTR)ResourcerLoadFileForResourceUse(szFileName);
        if(*FileMapVA != NULL)
        {
            *LoadedSize = (DWORD)GetPE32DataFromMappedFile(*FileMapVA, NULL, UE_SIZEOFIMAGE);
            *FileHandle = NULL;
            *FileMap = NULL;

            return true;
        }
    }

    return false;
}

__declspec(dllexport) bool TITCALL StaticFileLoadW(wchar_t* szFileName, DWORD DesiredAccess, bool SimulateLoad, LPHANDLE FileHandle, LPDWORD LoadedSize, LPHANDLE FileMap, PULONG_PTR FileMapVA)
{
    if(!SimulateLoad)
    {
        if(MapFileExW(szFileName, DesiredAccess, FileHandle, LoadedSize, FileMap, FileMapVA, NULL))
        {
            return true;
        }
    }
    else
    {
        *FileMapVA = (ULONG_PTR)ResourcerLoadFileForResourceUseW(szFileName);
        if(*FileMapVA != NULL)
        {
            *LoadedSize = (DWORD)GetPE32DataFromMappedFile(*FileMapVA, NULL, UE_SIZEOFIMAGE);
            *FileHandle = NULL;
            *FileMap = NULL;

            return true;
        }
    }

    return false;
}

__declspec(dllexport) bool TITCALL StaticFileUnload(char* szFileName, bool CommitChanges, HANDLE FileHandle, DWORD LoadedSize, HANDLE FileMap, ULONG_PTR FileMapVA)
{
    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        return(StaticFileUnloadW(uniFileName, CommitChanges, FileHandle, LoadedSize, FileMap, FileMapVA));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL StaticFileUnloadW(wchar_t* szFileName, bool CommitChanges, HANDLE FileHandle, DWORD LoadedSize, HANDLE FileMap, ULONG_PTR FileMapVA)
{
    DWORD PeHeaderSize;
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_SECTION_HEADER PESections;
    DWORD SectionNumber = 0;
    DWORD SectionRawOffset = 0;
    DWORD SectionRawSize = 0;
    BOOL FileIs64;
    HANDLE myFileHandle;
    DWORD myFileSize;
    HANDLE myFileMap;
    ULONG_PTR myFileMapVA;

    if(FileHandle != NULL && FileMap != NULL)
    {
        UnMapFileEx(FileHandle, LoadedSize, FileMap, FileMapVA);

        return true;
    }
    else
    {
        if(!CommitChanges)
        {
            return ResourcerFreeLoadedFile((LPVOID)FileMapVA);
        }
        else
        {
            if(MapFileExW(szFileName, UE_ACCESS_ALL, &myFileHandle, &myFileSize, &myFileMap, &myFileMapVA, NULL))
            {
                DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
                if(DOSHeader->e_lfanew < 0x1000 - 108)
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
                        ResourcerFreeLoadedFile((LPVOID)FileMapVA);
                        UnMapFileEx(myFileHandle, myFileSize, myFileMap, myFileMapVA);

                        return false;
                    }

                    if(!FileIs64)
                    {
                        PeHeaderSize = PEHeader32->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_SECTION_HEADER) * PEHeader32->FileHeader.NumberOfSections;
                        PESections = IMAGE_FIRST_SECTION(PEHeader32);
                        SectionNumber = PEHeader32->FileHeader.NumberOfSections;
                        RtlMoveMemory((LPVOID)myFileMapVA, (LPVOID)FileMapVA, PeHeaderSize);

                        while(SectionNumber > 0)
                        {
                            RtlMoveMemory((LPVOID)((ULONG_PTR)myFileMapVA + PESections->PointerToRawData), (LPVOID)(FileMapVA + PESections->VirtualAddress), PESections->SizeOfRawData);
                            PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                            SectionNumber--;
                        }

                        ResourcerFreeLoadedFile((LPVOID)FileMapVA);
                        UnMapFileEx(myFileHandle, myFileSize, myFileMap, myFileMapVA);

                        return true;
                    }
                    else
                    {
                        PeHeaderSize = PEHeader64->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_SECTION_HEADER) * PEHeader64->FileHeader.NumberOfSections;
                        PESections = IMAGE_FIRST_SECTION(PEHeader64);
                        SectionNumber = PEHeader64->FileHeader.NumberOfSections;
                        RtlMoveMemory((LPVOID)myFileMapVA, (LPVOID)FileMapVA, PeHeaderSize);

                        while(SectionNumber > 0)
                        {
                            RtlMoveMemory((LPVOID)((ULONG_PTR)myFileMapVA + PESections->PointerToRawData), (LPVOID)(FileMapVA + PESections->VirtualAddress), PESections->SizeOfRawData);
                            PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                            SectionNumber--;
                        }
                        ResourcerFreeLoadedFile((LPVOID)FileMapVA);
                        UnMapFileEx(myFileHandle, myFileSize, myFileMap, myFileMapVA);

                        return true;
                    }
                }
                else
                {
                    ResourcerFreeLoadedFile((LPVOID)FileMapVA);
                    UnMapFileEx(myFileHandle, myFileSize, myFileMap, myFileMapVA);

                    return false;
                }
            }
        }
    }

    return false;
}

__declspec(dllexport) bool TITCALL StaticFileOpen(char* szFileName, DWORD DesiredAccess, LPHANDLE FileHandle, LPDWORD FileSizeLow, LPDWORD FileSizeHigh)
{
    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));

        return StaticFileOpenW(uniFileName, DesiredAccess, FileHandle, FileSizeLow, FileSizeHigh);
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL StaticFileOpenW(wchar_t* szFileName, DWORD DesiredAccess, LPHANDLE FileHandle, LPDWORD FileSizeLow, LPDWORD FileSizeHigh)
{
    __try
    {
        *FileHandle = CreateFileW(szFileName, DesiredAccess, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if(FileHandle != INVALID_HANDLE_VALUE)
        {
            *FileSizeLow = GetFileSize(*FileHandle, FileSizeHigh);

            return true;
        }
        else
        {
            return false;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL StaticFileGetContent(HANDLE FileHandle, DWORD FilePositionLow, LPDWORD FilePositionHigh, void* Buffer, DWORD Size)
{
    DWORD rfNumberOfBytesRead;

    if(SetFilePointer(FileHandle, FilePositionLow, (PLONG)FilePositionHigh, FILE_BEGIN) != INVALID_SET_FILE_POINTER)
    {
        if(ReadFile(FileHandle, Buffer, Size, &rfNumberOfBytesRead, NULL))
        {
            if(rfNumberOfBytesRead == Size)
            {
                return true;
            }
            else
            {
                RtlZeroMemory(Buffer, Size);
            }
        }
    }

    return false;
}

__declspec(dllexport) void TITCALL StaticFileClose(HANDLE FileHandle)
{
    EngineCloseHandle(FileHandle);
}

__declspec(dllexport) void TITCALL StaticMemoryDecrypt(LPVOID MemoryStart, DWORD MemorySize, DWORD DecryptionType, DWORD DecryptionKeySize, ULONG_PTR DecryptionKey)
{
    DWORD LoopCount = NULL;
    BYTE DataByte = NULL;
    WORD DataWord = NULL;
    DWORD DataDword = NULL;
    ULONG64 DataQword = NULL;

    //ignore too big stuff
    if(DecryptionKeySize > sizeof(ULONG_PTR))
        return;

    if(MemoryStart != NULL && MemorySize > NULL)
    {
        LoopCount = MemorySize / DecryptionKeySize;
        while(LoopCount > NULL)
        {
            if(DecryptionType == UE_STATIC_DECRYPTOR_XOR)
            {
                if(DecryptionKeySize == UE_STATIC_KEY_SIZE_1)
                {
                    RtlMoveMemory(&DataByte, MemoryStart, UE_STATIC_KEY_SIZE_1);
                    DataByte = DataByte ^ (BYTE)DecryptionKey;
                    RtlMoveMemory(MemoryStart, &DataByte, UE_STATIC_KEY_SIZE_1);
                }
                else if(DecryptionKeySize == UE_STATIC_KEY_SIZE_2)
                {
                    RtlMoveMemory(&DataWord, MemoryStart, UE_STATIC_KEY_SIZE_2);
                    DataWord = DataWord ^ (WORD)DecryptionKey;
                    RtlMoveMemory(MemoryStart, &DataWord, UE_STATIC_KEY_SIZE_2);
                }
                else if(DecryptionKeySize == UE_STATIC_KEY_SIZE_4)
                {
                    RtlMoveMemory(&DataDword, MemoryStart, UE_STATIC_KEY_SIZE_4);
                    DataDword = DataDword ^ (DWORD)DecryptionKey;
                    RtlMoveMemory(MemoryStart, &DataDword, UE_STATIC_KEY_SIZE_4);
                }
                else if(DecryptionKeySize == UE_STATIC_KEY_SIZE_8)
                {
                    RtlMoveMemory(&DataQword, MemoryStart, UE_STATIC_KEY_SIZE_8);
                    DataQword = DataQword ^ (ULONG_PTR)DecryptionKey;
                    RtlMoveMemory(MemoryStart, &DataQword, UE_STATIC_KEY_SIZE_8);
                }
            }
            else if(DecryptionType == UE_STATIC_DECRYPTOR_SUB)
            {
                if(DecryptionKeySize == UE_STATIC_KEY_SIZE_1)
                {
                    RtlMoveMemory(&DataByte, MemoryStart, UE_STATIC_KEY_SIZE_1);
                    DataByte = DataByte - (BYTE)DecryptionKey;
                    RtlMoveMemory(MemoryStart, &DataByte, UE_STATIC_KEY_SIZE_1);
                }
                else if(DecryptionKeySize == UE_STATIC_KEY_SIZE_2)
                {
                    RtlMoveMemory(&DataWord, MemoryStart, UE_STATIC_KEY_SIZE_2);
                    DataWord = DataWord - (WORD)DecryptionKey;
                    RtlMoveMemory(MemoryStart, &DataWord, UE_STATIC_KEY_SIZE_2);
                }
                else if(DecryptionKeySize == UE_STATIC_KEY_SIZE_4)
                {
                    RtlMoveMemory(&DataDword, MemoryStart, UE_STATIC_KEY_SIZE_4);
                    DataDword = DataDword - (DWORD)DecryptionKey;
                    RtlMoveMemory(MemoryStart, &DataDword, UE_STATIC_KEY_SIZE_4);
                }
                else if(DecryptionKeySize == UE_STATIC_KEY_SIZE_8)
                {
                    RtlMoveMemory(&DataQword, MemoryStart, UE_STATIC_KEY_SIZE_8);
                    DataQword = DataQword - (ULONG_PTR)DecryptionKey;
                    RtlMoveMemory(MemoryStart, &DataQword, UE_STATIC_KEY_SIZE_8);
                }
            }
            else if(DecryptionType == UE_STATIC_DECRYPTOR_ADD)
            {
                if(DecryptionKeySize == UE_STATIC_KEY_SIZE_1)
                {
                    RtlMoveMemory(&DataByte, MemoryStart, UE_STATIC_KEY_SIZE_1);
                    DataByte = DataByte + (BYTE)DecryptionKey;
                    RtlMoveMemory(MemoryStart, &DataByte, UE_STATIC_KEY_SIZE_1);
                }
                else if(DecryptionKeySize == UE_STATIC_KEY_SIZE_2)
                {
                    RtlMoveMemory(&DataWord, MemoryStart, UE_STATIC_KEY_SIZE_2);
                    DataWord = DataWord + (WORD)DecryptionKey;
                    RtlMoveMemory(MemoryStart, &DataWord, UE_STATIC_KEY_SIZE_2);
                }
                else if(DecryptionKeySize == UE_STATIC_KEY_SIZE_4)
                {
                    RtlMoveMemory(&DataDword, MemoryStart, UE_STATIC_KEY_SIZE_4);
                    DataDword = DataDword + (DWORD)DecryptionKey;
                    RtlMoveMemory(MemoryStart, &DataDword, UE_STATIC_KEY_SIZE_4);
                }
                else if(DecryptionKeySize == UE_STATIC_KEY_SIZE_8)
                {
                    RtlMoveMemory(&DataQword, MemoryStart, UE_STATIC_KEY_SIZE_8);
                    DataQword = DataQword + (ULONG_PTR)DecryptionKey;
                    RtlMoveMemory(MemoryStart, &DataQword, UE_STATIC_KEY_SIZE_8);
                }
            }
            MemoryStart = (LPVOID)((ULONG_PTR)MemoryStart + DecryptionKeySize);
            LoopCount--;
        }
    }
}

__declspec(dllexport) void TITCALL StaticMemoryDecryptEx(LPVOID MemoryStart, DWORD MemorySize, DWORD DecryptionKeySize, void* DecryptionCallBack)
{
    DWORD LoopCount = NULL;
    typedef bool(TITCALL * fStaticCallBack)(void* sMemoryStart, int sKeySize);
    fStaticCallBack myStaticCallBack = (fStaticCallBack)DecryptionCallBack;

    if(MemoryStart != NULL && MemorySize > NULL)
    {
        LoopCount = MemorySize / DecryptionKeySize;
        while(LoopCount > NULL)
        {
            __try
            {
                if(!myStaticCallBack(MemoryStart, (int)DecryptionKeySize))
                {
                    break;
                }
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                break;
            }
            MemoryStart = (LPVOID)((ULONG_PTR)MemoryStart + DecryptionKeySize);
            LoopCount--;
        }
    }
}

__declspec(dllexport) void TITCALL StaticMemoryDecryptSpecial(LPVOID MemoryStart, DWORD MemorySize, DWORD DecryptionKeySize, DWORD SpecDecryptionType, void* DecryptionCallBack)
{
    DWORD LoopCount = NULL;
    typedef bool(TITCALL * fStaticCallBack)(void* sMemoryStart, int sKeySize);
    fStaticCallBack myStaticCallBack = (fStaticCallBack)DecryptionCallBack;

    if(MemoryStart != NULL && MemorySize > NULL)
    {
        if(SpecDecryptionType == UE_STATIC_DECRYPTOR_BACKWARD)
        {
            MemoryStart = (LPVOID)((ULONG_PTR)MemoryStart + MemorySize - DecryptionKeySize);
        }
        LoopCount = MemorySize / DecryptionKeySize;
        while(LoopCount > NULL)
        {
            __try
            {
                if(!myStaticCallBack(MemoryStart, (int)DecryptionKeySize))
                {
                    break;
                }
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                break;
            }

            if(SpecDecryptionType == UE_STATIC_DECRYPTOR_BACKWARD)
            {
                MemoryStart = (LPVOID)((ULONG_PTR)MemoryStart - DecryptionKeySize);
            }
            else
            {
                MemoryStart = (LPVOID)((ULONG_PTR)MemoryStart + DecryptionKeySize);
            }

            LoopCount--;
        }
    }
}

__declspec(dllexport) void TITCALL StaticSectionDecrypt(ULONG_PTR FileMapVA, DWORD SectionNumber, bool SimulateLoad, DWORD DecryptionType, DWORD DecryptionKeySize, ULONG_PTR DecryptionKey)
{
    if(!SimulateLoad)
    {
        StaticMemoryDecrypt((LPVOID)((ULONG_PTR)GetPE32DataFromMappedFile(FileMapVA, SectionNumber, UE_SECTIONRAWOFFSET) + FileMapVA), (DWORD)GetPE32DataFromMappedFile(FileMapVA, SectionNumber, UE_SECTIONRAWSIZE), DecryptionType, DecryptionKeySize, DecryptionKey);
    }
    else
    {
        StaticMemoryDecrypt((LPVOID)((ULONG_PTR)GetPE32DataFromMappedFile(FileMapVA, SectionNumber, UE_SECTIONVIRTUALOFFSET) + FileMapVA), (DWORD)GetPE32DataFromMappedFile(FileMapVA, SectionNumber, UE_SECTIONRAWSIZE), DecryptionType, DecryptionKeySize, DecryptionKey);
    }
}

__declspec(dllexport) bool TITCALL StaticMemoryDecompress(void* Source, DWORD SourceSize, void* Destination, DWORD DestinationSize, int Algorithm)
{
    if(!Source || !Destination)
        return false;
    ELzmaStatus lzStatus;
    CLzmaProps lzProps = {};
    ISzAlloc lzAlloc = {&LzmaAllocMem, &LzmaFreeMem};

    if(Algorithm == UE_STATIC_APLIB)
    {
        if(aP_depack_asm_safe(Source, SourceSize, Destination, DestinationSize) != APLIB_ERROR)
        {
            return true;
        }
        else if(aPsafe_depack(Source, SourceSize, Destination, DestinationSize) != APLIB_ERROR)
        {
            return true;
        }
    }
    else if(Algorithm == UE_STATIC_LZMA)
    {
        if(LzmaDecode((unsigned char*)Destination, (size_t*)DestinationSize, (unsigned char*)Source, (size_t*)SourceSize, (unsigned char*)&lzProps, LZMA_PROPS_SIZE, LZMA_FINISH_ANY, &lzStatus, &lzAlloc) == SZ_OK)
        {
            return true;
        }
    }

    return false;
}

__declspec(dllexport) bool TITCALL StaticRawMemoryCopy(HANDLE hFile, ULONG_PTR FileMapVA, ULONG_PTR VitualAddressToCopy, DWORD Size, bool AddressIsRVA, char* szDumpFileName)
{
    wchar_t uniFileName[MAX_PATH] = {};

    if(szDumpFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szDumpFileName, lstrlenA(szDumpFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        return(StaticRawMemoryCopyW(hFile, FileMapVA, VitualAddressToCopy, Size, AddressIsRVA, uniFileName));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL StaticRawMemoryCopyW(HANDLE hFile, ULONG_PTR FileMapVA, ULONG_PTR VitualAddressToCopy, DWORD Size, bool AddressIsRVA, wchar_t* szDumpFileName)
{
    DWORD SizeToRead;
    HANDLE hReadFile;
    HANDLE hWriteFile;
    //LPVOID ueCopyBuf;
    char ueCopyBuffer[0x1000] = {0};
    ULONG_PTR AddressToCopy;
    DWORD rfNumberOfBytesRead;

    if(FileMapVA != NULL)
    {
        if(DuplicateHandle(GetCurrentProcess(), hFile, GetCurrentProcess(), &hReadFile, NULL, false, DUPLICATE_SAME_ACCESS))
        {
            if(AddressIsRVA)
            {
                VitualAddressToCopy = VitualAddressToCopy + (ULONG_PTR)GetPE32DataFromMappedFile(FileMapVA, NULL, UE_IMAGEBASE);
                AddressToCopy = (ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, VitualAddressToCopy, false);
            }
            else
            {
                AddressToCopy = (ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, VitualAddressToCopy, false);
            }

            if(SetFilePointer(hReadFile, (long)AddressToCopy, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER)
            {
                EngineCreatePathForFileW(szDumpFileName);
                hWriteFile = CreateFileW(szDumpFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if(hWriteFile != INVALID_HANDLE_VALUE)
                {
                    if(Size < sizeof(ueCopyBuffer))
                    {
                        SizeToRead = Size;
                    }
                    else
                    {
                        SizeToRead = sizeof(ueCopyBuffer);
                    }
                    while((int)Size > NULL)
                    {
                        if(ReadFile(hFile, ueCopyBuffer, SizeToRead, &rfNumberOfBytesRead, NULL) && rfNumberOfBytesRead == SizeToRead)
                        {
                            WriteFile(hWriteFile, ueCopyBuffer, SizeToRead, &rfNumberOfBytesRead, NULL);
                            if(Size > sizeof(ueCopyBuffer))
                            {
                                Size = Size - sizeof(ueCopyBuffer);
                            }
                            else if(SizeToRead != Size)
                            {
                                if(ReadFile(hFile, ueCopyBuffer, Size, &rfNumberOfBytesRead, NULL) && rfNumberOfBytesRead == SizeToRead)
                                {
                                    WriteFile(hWriteFile, ueCopyBuffer, Size, &rfNumberOfBytesRead, NULL);
                                }
                                else
                                {
                                    WriteFile(hWriteFile, ueCopyBuffer, rfNumberOfBytesRead, &rfNumberOfBytesRead, NULL);
                                }
                                SizeToRead = Size;
                                Size = NULL;
                            }
                            else
                            {
                                SizeToRead = Size;
                                Size = NULL;
                            }
                        }
                        else
                        {
                            WriteFile(hWriteFile, ueCopyBuffer, rfNumberOfBytesRead, &rfNumberOfBytesRead, NULL);
                            Size = NULL;
                        }
                    }

                    EngineCloseHandle(hReadFile);
                    EngineCloseHandle(hWriteFile);

                    return true;
                }
            }
            EngineCloseHandle(hReadFile);
        }
    }

    return false;
}

__declspec(dllexport) bool TITCALL StaticRawMemoryCopyEx(HANDLE hFile, DWORD RawAddressToCopy, DWORD Size, char* szDumpFileName)
{
    wchar_t uniFileName[MAX_PATH] = {};

    if(szDumpFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szDumpFileName, lstrlenA(szDumpFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        return(StaticRawMemoryCopyExW(hFile, RawAddressToCopy, Size, uniFileName));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL StaticRawMemoryCopyExW(HANDLE hFile, DWORD RawAddressToCopy, DWORD Size, wchar_t* szDumpFileName)
{
    DWORD SizeToRead;
    HANDLE hReadFile;
    HANDLE hWriteFile;
    char ueCopyBuffer[0x1000] = {0};
    DWORD rfNumberOfBytesRead;

    if(DuplicateHandle(GetCurrentProcess(), hFile, GetCurrentProcess(), &hReadFile, NULL, false, DUPLICATE_SAME_ACCESS))
    {
        if(SetFilePointer(hReadFile, (long)(RawAddressToCopy), NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER)
        {
            EngineCreatePathForFileW(szDumpFileName);
            hWriteFile = CreateFileW(szDumpFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if(hWriteFile != INVALID_HANDLE_VALUE)
            {
                if(Size < sizeof(ueCopyBuffer))
                {
                    SizeToRead = Size;
                }
                else
                {
                    SizeToRead = sizeof(ueCopyBuffer);
                }
                while((int)Size > 0)
                {
                    if(ReadFile(hFile, ueCopyBuffer, SizeToRead, &rfNumberOfBytesRead, NULL) && rfNumberOfBytesRead == SizeToRead)
                    {
                        WriteFile(hWriteFile, ueCopyBuffer, SizeToRead, &rfNumberOfBytesRead, NULL);
                        if(Size > sizeof(ueCopyBuffer))
                        {
                            Size = Size - sizeof(ueCopyBuffer);
                        }
                        else if(SizeToRead != Size)
                        {
                            if(ReadFile(hFile, ueCopyBuffer, Size, &rfNumberOfBytesRead, NULL) && rfNumberOfBytesRead == SizeToRead)
                            {
                                WriteFile(hWriteFile, ueCopyBuffer, Size, &rfNumberOfBytesRead, NULL);
                            }
                            else
                            {
                                WriteFile(hWriteFile, ueCopyBuffer, rfNumberOfBytesRead, &rfNumberOfBytesRead, NULL);
                            }
                            SizeToRead = Size;
                            Size = 0;
                        }
                        else
                        {
                            SizeToRead = Size;
                            Size = 0;
                        }
                    }
                    else
                    {
                        WriteFile(hWriteFile, ueCopyBuffer, rfNumberOfBytesRead, &rfNumberOfBytesRead, NULL);
                        Size = 0;
                    }
                }

                EngineCloseHandle(hReadFile);
                EngineCloseHandle(hWriteFile);

                return true;
            }
        }

        EngineCloseHandle(hReadFile);
    }

    return false;
}

__declspec(dllexport) bool TITCALL StaticRawMemoryCopyEx64(HANDLE hFile, DWORD64 RawAddressToCopy, DWORD64 Size, char* szDumpFileName)
{
    wchar_t uniFileName[MAX_PATH] = {};

    if(szDumpFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szDumpFileName, lstrlenA(szDumpFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));

        return StaticRawMemoryCopyEx64W(hFile, RawAddressToCopy, Size, uniFileName);
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL StaticRawMemoryCopyEx64W(HANDLE hFile, DWORD64 RawAddressToCopy, DWORD64 Size, wchar_t* szDumpFileName)
{
    DWORD SizeToRead;
    HANDLE hReadFile;
    HANDLE hWriteFile;
    char ueCopyBuffer[0x1000] = {0};
    DWORD rfNumberOfBytesRead;
    long FilePosLow;
    long FilePosHigh;

    if(DuplicateHandle(GetCurrentProcess(), hFile, GetCurrentProcess(), &hReadFile, NULL, false, DUPLICATE_SAME_ACCESS))
    {
        FilePosLow = (DWORD)RawAddressToCopy;
        RtlMoveMemory(&FilePosHigh, (void*)((ULONG_PTR)(&RawAddressToCopy) + 4), 4);
        if(SetFilePointer(hReadFile, FilePosLow, &FilePosHigh, FILE_BEGIN) != INVALID_SET_FILE_POINTER)
        {
            EngineCreatePathForFileW(szDumpFileName);
            hWriteFile = CreateFileW(szDumpFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if(hWriteFile != INVALID_HANDLE_VALUE)
            {
                if(Size < 0x1000)
                {
                    SizeToRead = (DWORD)Size;
                }
                else
                {
                    SizeToRead = 0x1000;
                }
                while(Size != NULL)
                {
                    if(ReadFile(hFile, ueCopyBuffer, SizeToRead, &rfNumberOfBytesRead, NULL) && rfNumberOfBytesRead == SizeToRead)
                    {
                        WriteFile(hWriteFile, ueCopyBuffer, SizeToRead, &rfNumberOfBytesRead, NULL);
                        if(Size > 0x1000)
                        {
                            Size = Size - 0x1000;
                        }
                        else if((DWORD64)SizeToRead != Size)
                        {
                            if(ReadFile(hFile, ueCopyBuffer, (DWORD)Size, &rfNumberOfBytesRead, NULL) && rfNumberOfBytesRead == SizeToRead)
                            {
                                WriteFile(hWriteFile, ueCopyBuffer, (DWORD)Size, &rfNumberOfBytesRead, NULL);
                            }
                            else
                            {
                                WriteFile(hWriteFile, ueCopyBuffer, rfNumberOfBytesRead, &rfNumberOfBytesRead, NULL);
                            }

                            SizeToRead = (DWORD)Size;
                            Size = NULL;
                        }
                        else
                        {
                            SizeToRead = (DWORD)Size;
                            Size = NULL;
                        }
                    }
                    else
                    {
                        WriteFile(hWriteFile, ueCopyBuffer, rfNumberOfBytesRead, &rfNumberOfBytesRead, NULL);
                        Size = NULL;
                    }
                }

                EngineCloseHandle(hReadFile);
                EngineCloseHandle(hWriteFile);

                return true;
            }
        }
    }

    EngineCloseHandle(hReadFile);

    return false;
}

__declspec(dllexport) bool TITCALL StaticHashMemory(void* MemoryToHash, DWORD SizeOfMemory, void* HashDigest, bool OutputString, int Algorithm)
{
#define MD5LEN 16
#define SHA1LEN 20
#define HASH_MAX_LENGTH 20

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = NULL;
    DWORD rgbHash[HASH_MAX_LENGTH / 4];
    DWORD cbHash = 0;
    DWORD crc32 = -1;
    ALG_ID hashAlgo;

    if(Algorithm != UE_STATIC_HASH_CRC32)
    {
        if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, NULL))  //CRYPT_VERIFYCONTEXT
        {
            if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
            {
                return false;
            }
        }
        if(Algorithm == UE_STATIC_HASH_MD5)
        {
            hashAlgo = CALG_MD5;
        }
        else
        {
            hashAlgo = CALG_SHA;
        }
        if(!CryptCreateHash(hProv, hashAlgo, NULL, NULL, &hHash))
        {
            CryptReleaseContext(hProv, NULL);

            return false;
        }
        else
        {
            if(!CryptHashData(hHash, (const BYTE*)MemoryToHash, SizeOfMemory, NULL))
            {
                CryptReleaseContext(hProv, NULL);
                CryptDestroyHash(hHash);

                return false;
            }
        }
        if(Algorithm == UE_STATIC_HASH_MD5)
        {
            cbHash = MD5LEN;
            if(!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)&rgbHash[0], &cbHash, NULL))
            {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, NULL);

                return false;
            }
            else
            {
                rgbHash[0] = _byteswap_ulong(rgbHash[0]);
                rgbHash[1] = _byteswap_ulong(rgbHash[1]);
                rgbHash[2] = _byteswap_ulong(rgbHash[2]);
                rgbHash[3] = _byteswap_ulong(rgbHash[3]);

                __try
                {
                    if(OutputString)
                    {
                        wsprintfA((char*)HashDigest, "%08X%08X%08X%08X", rgbHash[0], rgbHash[1], rgbHash[2], rgbHash[3]);
                    }
                    else
                    {
                        RtlMoveMemory(HashDigest, &rgbHash[0], MD5LEN / 4);
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    CryptDestroyHash(hHash);
                    CryptReleaseContext(hProv, NULL);

                    return false;
                }

                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, NULL);

                return true;
            }
        }
        else if(Algorithm == UE_STATIC_HASH_SHA1)
        {
            cbHash = SHA1LEN;
            if(!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)&rgbHash[0], &cbHash, NULL))
            {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, NULL);

                return false;
            }
            else
            {
                rgbHash[0] = _byteswap_ulong(rgbHash[0]);
                rgbHash[1] = _byteswap_ulong(rgbHash[1]);
                rgbHash[2] = _byteswap_ulong(rgbHash[2]);
                rgbHash[3] = _byteswap_ulong(rgbHash[3]);
                rgbHash[4] = _byteswap_ulong(rgbHash[4]);
                __try
                {
                    if(OutputString)
                    {
                        wsprintfA((char*)HashDigest, "%08X%08X%08X%08X%08X", rgbHash[0], rgbHash[1], rgbHash[2], rgbHash[3], rgbHash[4]);
                    }
                    else
                    {
                        RtlMoveMemory(HashDigest, &rgbHash[0], SHA1LEN / 4);
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    CryptDestroyHash(hHash);
                    CryptReleaseContext(hProv, NULL);

                    return false;
                }

                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, NULL);

                return true;
            }
        }
    }
    else
    {
        EngineCrc32PartialCRC(&crc32, (unsigned char*)MemoryToHash, (unsigned long)SizeOfMemory);
        crc32 = crc32 ^ 0xFFFFFFFF;
        if(OutputString)
        {
            wsprintfA((char*)HashDigest, "%08X", crc32);
        }
        else
        {
            RtlMoveMemory(HashDigest, &crc32, sizeof crc32);
        }

        return true;
    }

    return false;
}

__declspec(dllexport) bool TITCALL StaticHashFile(char* szFileName, char* HashDigest, bool OutputString, int Algorithm)
{
    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));

        return StaticHashFileW(uniFileName, HashDigest, OutputString, Algorithm);
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL StaticHashFileW(wchar_t* szFileName, char* HashDigest, bool OutputString, int Algorithm)
{
#define MD5LEN 16
#define SHA1LEN 20
#define HASH_MAX_LENGTH 20

    bool bResult = true;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = NULL;
    BYTE rgbFile[1024];
    DWORD cbRead = 0;
    DWORD rgbHash[HASH_MAX_LENGTH / 4];
    DWORD cbHash = 0;
    DWORD crc32 = -1;
    ALG_ID hashAlgo;

    hFile = CreateFileW(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if(hFile == INVALID_HANDLE_VALUE || HashDigest == NULL)
    {
        return false;
    }
    if(Algorithm != UE_STATIC_HASH_CRC32)
    {
        if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, NULL))  //CRYPT_VERIFYCONTEXT
        {
            if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
            {
                CloseHandle(hFile);

                return false;
            }
        }
        if(Algorithm == UE_STATIC_HASH_MD5)
        {
            hashAlgo = CALG_MD5;
        }
        else
        {
            hashAlgo = CALG_SHA;
        }
        if(!CryptCreateHash(hProv, hashAlgo, NULL, NULL, &hHash))
        {
            CloseHandle(hFile);
            CryptReleaseContext(hProv, NULL);

            return false;
        }
        while(bResult)
        {
            if(!ReadFile(hFile, rgbFile, 1024, &cbRead, NULL))
            {
                bResult = false;
            }
            else if(cbRead == NULL)
            {
                break;
            }
            if(!CryptHashData(hHash, rgbFile, cbRead, NULL))
            {
                CryptReleaseContext(hProv, NULL);
                CryptDestroyHash(hHash);
                CloseHandle(hFile);

                return false;
            }
        }
        if(!bResult)
        {
            CryptReleaseContext(hProv, NULL);
            CryptDestroyHash(hHash);
            CloseHandle(hFile);

            return false;
        }
        if(Algorithm == UE_STATIC_HASH_MD5)
        {
            cbHash = MD5LEN;
            if(!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)&rgbHash[0], &cbHash, NULL))
            {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, NULL);
                CloseHandle(hFile);

                return false;
            }
            else
            {
                rgbHash[0] = _byteswap_ulong(rgbHash[0]);
                rgbHash[1] = _byteswap_ulong(rgbHash[1]);
                rgbHash[2] = _byteswap_ulong(rgbHash[2]);
                rgbHash[3] = _byteswap_ulong(rgbHash[3]);

                __try
                {
                    if(OutputString)
                    {
                        wsprintfA(HashDigest, "%08X%08X%08X%08X", rgbHash[0], rgbHash[1], rgbHash[2], rgbHash[3]);
                    }
                    else
                    {
                        RtlMoveMemory(HashDigest, &rgbHash[0], MD5LEN / 4);
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    CryptDestroyHash(hHash);
                    CryptReleaseContext(hProv, NULL);
                    CloseHandle(hFile);

                    return false;
                }
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, NULL);
                CloseHandle(hFile);

                return true;
            }
        }
        else if(Algorithm == UE_STATIC_HASH_SHA1)
        {
            cbHash = SHA1LEN;
            if(!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)&rgbHash[0], &cbHash, NULL))
            {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, NULL);
                CloseHandle(hFile);

                return false;
            }
            else
            {
                rgbHash[0] = _byteswap_ulong(rgbHash[0]);
                rgbHash[1] = _byteswap_ulong(rgbHash[1]);
                rgbHash[2] = _byteswap_ulong(rgbHash[2]);
                rgbHash[3] = _byteswap_ulong(rgbHash[3]);
                rgbHash[4] = _byteswap_ulong(rgbHash[4]);

                __try
                {
                    if(OutputString)
                    {
                        wsprintfA(HashDigest, "%08X%08X%08X%08X%08X", rgbHash[0], rgbHash[1], rgbHash[2], rgbHash[3], rgbHash[4]);
                    }
                    else
                    {
                        RtlMoveMemory(HashDigest, &rgbHash[0], SHA1LEN / 4);
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    CryptDestroyHash(hHash);
                    CryptReleaseContext(hProv, NULL);
                    CloseHandle(hFile);

                    return false;
                }
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, NULL);
                CloseHandle(hFile);

                return true;
            }
        }
    }
    else
    {
        while(bResult)
        {
            if(!ReadFile(hFile, rgbFile, 1024, &cbRead, NULL))
            {
                bResult = false;
            }
            else if(cbRead == NULL)
            {
                break;
            }

            EngineCrc32PartialCRC(&crc32, (unsigned char*)&rgbFile[0], cbRead);
        }
        crc32 = crc32 ^ 0xFFFFFFFF;
        if(OutputString)
        {
            wsprintfA(HashDigest, "%08X", crc32);
        }
        else
        {
            RtlMoveMemory(HashDigest, &crc32, sizeof crc32);
        }

        CloseHandle(hFile);

        return true;
    }

    CloseHandle(hFile);

    return false;
}