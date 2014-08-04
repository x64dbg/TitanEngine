#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.h"
#include "Global.Handle.h"

//TitanEngine.Dumper.functions:
__declspec(dllexport) bool TITCALL DumpProcess(HANDLE hProcess, LPVOID ImageBase, char* szDumpFileName, ULONG_PTR EntryPoint)
{
    wchar_t uniDumpFileName[MAX_PATH] = {0};
    if(szDumpFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szDumpFileName, -1, uniDumpFileName, _countof(uniDumpFileName));
        return DumpProcessW(hProcess, ImageBase, uniDumpFileName, EntryPoint);
    }
    return false;
}

__declspec(dllexport) bool TITCALL DumpProcessW(HANDLE hProcess, LPVOID ImageBase, wchar_t* szDumpFileName, ULONG_PTR EntryPoint)
{
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_DOS_HEADER DOSFixHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_NT_HEADERS32 PEFixHeader32;
    PIMAGE_NT_HEADERS64 PEFixHeader64;
    PIMAGE_SECTION_HEADER PEFixSection;
    ULONG_PTR ueNumberOfBytesRead = 0;
    DWORD uedNumberOfBytesRead = 0;
    DWORD SizeOfImageDump = 0;
    int NumberOfSections = 0;
    BOOL FileIs64 = false;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD RealignedVirtualSize = 0;
    ULONG_PTR ProcReadBase = 0;
    LPVOID ReadBase = ImageBase;
    SIZE_T CalculatedHeaderSize = NULL;
    SIZE_T AlignedHeaderSize = NULL;
    DynBuf ueReadBuf, ueCopyBuf;
    LPVOID ueReadBuffer = ueReadBuf.Allocate(0x2000);
    LPVOID ueCopyBuffer = ueCopyBuf.Allocate(0x2000);

    if(ReadProcessMemory(hProcess, ImageBase, ueReadBuffer, 0x1000, &ueNumberOfBytesRead))
    {
        //ReadProcessMemory
        DOSHeader = (PIMAGE_DOS_HEADER)ueReadBuffer;
        PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);

        if((DOSHeader->e_lfanew > 0x500) || (DOSHeader->e_magic != IMAGE_DOS_SIGNATURE) || (PEHeader32->Signature != IMAGE_NT_SIGNATURE))
        {
            return false;
        }

        CalculatedHeaderSize = DOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + (sizeof(IMAGE_SECTION_HEADER) * PEHeader32->FileHeader.NumberOfSections);

        if(CalculatedHeaderSize > 0x1000)
        {
            if(CalculatedHeaderSize % 0x1000 != NULL)
            {
                AlignedHeaderSize = ((CalculatedHeaderSize / 0x1000) + 1) * 0x1000;
            }
            else
            {
                AlignedHeaderSize = CalculatedHeaderSize;
            }
            ueReadBuffer = ueReadBuf.Allocate(AlignedHeaderSize);
            ueCopyBuffer = ueCopyBuf.Allocate(AlignedHeaderSize);
            if(!ReadProcessMemory(hProcess, ImageBase, ueReadBuffer, AlignedHeaderSize, &ueNumberOfBytesRead))
            {
                return false;
            }
            else
            {
                DOSHeader = (PIMAGE_DOS_HEADER)ueReadBuffer;
            }
        }
        else
        {
            CalculatedHeaderSize = 0x1000;
            AlignedHeaderSize = 0x1000;
        }
        if(EngineValidateHeader((ULONG_PTR)ueReadBuffer, hProcess, ImageBase, DOSHeader, false))
        {
            //EngineValidateHeader
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
                return false;
            }
            if(!FileIs64)
            {
                //PE32 Handler
                NumberOfSections = PEHeader32->FileHeader.NumberOfSections;
                NumberOfSections++;
                if(PEHeader32->OptionalHeader.SizeOfImage % PEHeader32->OptionalHeader.SectionAlignment == NULL)
                {
                    SizeOfImageDump = ((PEHeader32->OptionalHeader.SizeOfImage / PEHeader32->OptionalHeader.SectionAlignment)) * PEHeader32->OptionalHeader.SectionAlignment;
                }
                else
                {
                    SizeOfImageDump = ((PEHeader32->OptionalHeader.SizeOfImage / PEHeader32->OptionalHeader.SectionAlignment) + 1) * PEHeader32->OptionalHeader.SectionAlignment;
                }
                SizeOfImageDump = SizeOfImageDump - (DWORD)AlignedHeaderSize;
                EngineCreatePathForFileW(szDumpFileName);
                hFile = CreateFileW(szDumpFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if(hFile != INVALID_HANDLE_VALUE)
                {
                    if(ReadProcessMemory(hProcess, ImageBase, ueCopyBuffer, AlignedHeaderSize, &ueNumberOfBytesRead))
                    {
                        if(ueCopyBuffer)
                        {
                            DOSFixHeader = (PIMAGE_DOS_HEADER)ueCopyBuffer;
                            PEFixHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSFixHeader + DOSFixHeader->e_lfanew);
                            PEFixSection = IMAGE_FIRST_SECTION(PEFixHeader32);
                            if(PEFixHeader32->OptionalHeader.FileAlignment > 0x200)
                            {
                                PEFixHeader32->OptionalHeader.FileAlignment = PEHeader32->OptionalHeader.SectionAlignment;
                            }
                            PEFixHeader32->OptionalHeader.AddressOfEntryPoint = (DWORD)(EntryPoint - (ULONG_PTR)ImageBase);
                            PEFixHeader32->OptionalHeader.ImageBase = (DWORD)((ULONG_PTR)ImageBase);
                            for(int i = NumberOfSections; i >= 1; i--)
                            {
                                PEFixSection->PointerToRawData = PEFixSection->VirtualAddress;
                                RealignedVirtualSize = (PEFixSection->Misc.VirtualSize / PEHeader32->OptionalHeader.SectionAlignment) * PEHeader32->OptionalHeader.SectionAlignment;
                                if(RealignedVirtualSize < PEFixSection->Misc.VirtualSize)
                                {
                                    RealignedVirtualSize = RealignedVirtualSize + PEHeader32->OptionalHeader.SectionAlignment;
                                }
                                PEFixSection->SizeOfRawData = RealignedVirtualSize;
                                PEFixSection->Misc.VirtualSize = RealignedVirtualSize;
                                PEFixSection = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PEFixSection + IMAGE_SIZEOF_SECTION_HEADER);
                            }
                            WriteFile(hFile, ueCopyBuffer, (DWORD)AlignedHeaderSize, &uedNumberOfBytesRead, NULL);
                            ReadBase = (LPVOID)((ULONG_PTR)ReadBase + AlignedHeaderSize - TITANENGINE_PAGESIZE);
                            while(SizeOfImageDump > NULL)
                            {
                                ProcReadBase = (ULONG_PTR)ReadBase + TITANENGINE_PAGESIZE;
                                ReadBase = (LPVOID)ProcReadBase;
                                if(SizeOfImageDump >= TITANENGINE_PAGESIZE)
                                {
                                    RtlZeroMemory(ueCopyBuffer, AlignedHeaderSize);

                                    MemoryReadSafe(hProcess, ReadBase, ueCopyBuffer, TITANENGINE_PAGESIZE, &ueNumberOfBytesRead);

                                    WriteFile(hFile, ueCopyBuffer, TITANENGINE_PAGESIZE, &uedNumberOfBytesRead, NULL);
                                    SizeOfImageDump = SizeOfImageDump - TITANENGINE_PAGESIZE;
                                }
                                else
                                {
                                    RtlZeroMemory(ueCopyBuffer, AlignedHeaderSize);

                                    MemoryReadSafe(hProcess, ReadBase, ueCopyBuffer, SizeOfImageDump, &ueNumberOfBytesRead);

                                    WriteFile(hFile, ueCopyBuffer, SizeOfImageDump, &uedNumberOfBytesRead, NULL);
                                    SizeOfImageDump = NULL;
                                }
                            }
                            EngineCloseHandle(hFile);
                            return true;
                        }
                    }
                }
            }//PE32 Handler
            else
            {
                //PE64 Handler
                NumberOfSections = PEHeader64->FileHeader.NumberOfSections;
                NumberOfSections++;
                if(PEHeader64->OptionalHeader.SizeOfImage % PEHeader64->OptionalHeader.SectionAlignment == NULL)
                {
                    SizeOfImageDump = ((PEHeader64->OptionalHeader.SizeOfImage / PEHeader64->OptionalHeader.SectionAlignment)) * PEHeader64->OptionalHeader.SectionAlignment;
                }
                else
                {
                    SizeOfImageDump = ((PEHeader64->OptionalHeader.SizeOfImage / PEHeader64->OptionalHeader.SectionAlignment) + 1) * PEHeader64->OptionalHeader.SectionAlignment;
                }
                SizeOfImageDump = SizeOfImageDump - (DWORD)AlignedHeaderSize;
                EngineCreatePathForFileW(szDumpFileName);
                hFile = CreateFileW(szDumpFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if(hFile != INVALID_HANDLE_VALUE)
                {
                    if(ReadProcessMemory(hProcess, ImageBase, ueCopyBuffer, AlignedHeaderSize, &ueNumberOfBytesRead))
                    {
                        if(ueCopyBuffer)
                        {
                            DOSFixHeader = (PIMAGE_DOS_HEADER)ueCopyBuffer;
                            PEFixHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSFixHeader + DOSFixHeader->e_lfanew);
                            PEFixSection = IMAGE_FIRST_SECTION(PEFixHeader64);
                            if(PEFixHeader64->OptionalHeader.FileAlignment > 0x200)
                            {
                                PEFixHeader64->OptionalHeader.FileAlignment = PEHeader64->OptionalHeader.SectionAlignment;
                            }
                            PEFixHeader64->OptionalHeader.AddressOfEntryPoint = (DWORD)(EntryPoint - (ULONG_PTR)ImageBase);
                            PEFixHeader64->OptionalHeader.ImageBase = (DWORD64)((ULONG_PTR)ImageBase);
                            for(int i = NumberOfSections; i >= 1; i--)
                            {
                                PEFixSection->PointerToRawData = PEFixSection->VirtualAddress;
                                RealignedVirtualSize = (PEFixSection->Misc.VirtualSize / PEHeader64->OptionalHeader.SectionAlignment) * PEHeader64->OptionalHeader.SectionAlignment;
                                if(RealignedVirtualSize < PEFixSection->Misc.VirtualSize)
                                {
                                    RealignedVirtualSize = RealignedVirtualSize + PEHeader64->OptionalHeader.SectionAlignment;
                                }
                                PEFixSection->SizeOfRawData = RealignedVirtualSize;
                                PEFixSection->Misc.VirtualSize = RealignedVirtualSize;
                                PEFixSection = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PEFixSection + IMAGE_SIZEOF_SECTION_HEADER);
                            }
                            WriteFile(hFile, ueCopyBuffer, (DWORD)AlignedHeaderSize, &uedNumberOfBytesRead, NULL);
                            ReadBase = (LPVOID)((ULONG_PTR)ReadBase + (DWORD)AlignedHeaderSize - TITANENGINE_PAGESIZE);
                            while(SizeOfImageDump > NULL)
                            {
                                ProcReadBase = (ULONG_PTR)ReadBase + TITANENGINE_PAGESIZE;
                                ReadBase = (LPVOID)ProcReadBase;
                                if(SizeOfImageDump >= TITANENGINE_PAGESIZE)
                                {
                                    RtlZeroMemory(ueCopyBuffer, AlignedHeaderSize);

                                    MemoryReadSafe(hProcess, ReadBase, ueCopyBuffer, TITANENGINE_PAGESIZE, &ueNumberOfBytesRead);

                                    WriteFile(hFile, ueCopyBuffer, TITANENGINE_PAGESIZE, &uedNumberOfBytesRead, NULL);
                                    SizeOfImageDump = SizeOfImageDump - TITANENGINE_PAGESIZE;
                                }
                                else
                                {
                                    RtlZeroMemory(ueCopyBuffer, AlignedHeaderSize);

                                    MemoryReadSafe(hProcess, ReadBase, ueCopyBuffer, SizeOfImageDump, &ueNumberOfBytesRead);

                                    WriteFile(hFile, ueCopyBuffer, SizeOfImageDump, &uedNumberOfBytesRead, NULL);
                                    SizeOfImageDump = NULL;
                                }
                            }
                            EngineCloseHandle(hFile);
                            return true;
                        }
                    }
                }
            }//PE64 Handler
        }//EngineValidateHeader
    }//ReadProcessMemory

    if(hFile != INVALID_HANDLE_VALUE)
    {
        EngineCloseHandle(hFile);
    }

    return false;
}

__declspec(dllexport) bool TITCALL DumpProcessEx(DWORD ProcessId, LPVOID ImageBase, char* szDumpFileName, ULONG_PTR EntryPoint)
{
    wchar_t uniDumpFileName[MAX_PATH] = {0};

    if(szDumpFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szDumpFileName, -1, uniDumpFileName, _countof(uniDumpFileName));
        return(DumpProcessExW(ProcessId, ImageBase, uniDumpFileName, EntryPoint));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL DumpProcessExW(DWORD ProcessId, LPVOID ImageBase, wchar_t* szDumpFileName, ULONG_PTR EntryPoint)
{
    HANDLE hProcess = 0;
    bool ReturnValue = false;

    hProcess = EngineOpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    if(hProcess)
    {
        ReturnValue = DumpProcessW(hProcess, ImageBase, szDumpFileName, EntryPoint);
        EngineCloseHandle(hProcess);
        return ReturnValue;
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL DumpMemory(HANDLE hProcess, LPVOID MemoryStart, ULONG_PTR MemorySize, char* szDumpFileName)
{
    wchar_t uniDumpFileName[MAX_PATH] = {0};

    if(szDumpFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szDumpFileName, -1, uniDumpFileName, _countof(uniDumpFileName));
        return(DumpMemoryW(hProcess, MemoryStart, MemorySize, uniDumpFileName));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL DumpMemoryW(HANDLE hProcess, LPVOID MemoryStart, ULONG_PTR MemorySize, wchar_t* szDumpFileName)
{
    ULONG_PTR ueNumberOfBytesRead = 0;
    DWORD uedNumberOfBytesRead = 0;
    HANDLE hFile = 0;
    LPVOID ReadBase = MemoryStart;
    ULONG_PTR ProcReadBase = (ULONG_PTR)ReadBase;
    char ueCopyBuffer[0x2000] = {0};

    EngineCreatePathForFileW(szDumpFileName);
    hFile = CreateFileW(szDumpFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile != INVALID_HANDLE_VALUE)
    {
        while(MemorySize > NULL)
        {
            ReadBase = (LPVOID)ProcReadBase;
            if(MemorySize >= 0x1000)
            {
                RtlZeroMemory(ueCopyBuffer, 0x2000);

                MemoryReadSafe(hProcess, ReadBase, ueCopyBuffer, 0x1000, &ueNumberOfBytesRead);

                WriteFile(hFile, ueCopyBuffer, 0x1000, &uedNumberOfBytesRead, NULL);
                MemorySize = MemorySize - 0x1000;
            }
            else
            {
                RtlZeroMemory(ueCopyBuffer, 0x2000);

                MemoryReadSafe(hProcess, ReadBase, ueCopyBuffer, MemorySize, &ueNumberOfBytesRead);

                WriteFile(hFile, ueCopyBuffer, (DWORD)MemorySize, &uedNumberOfBytesRead, NULL);
                MemorySize = NULL;
            }
            ProcReadBase = (ULONG_PTR)ReadBase + 0x1000;
        }
        EngineCloseHandle(hFile);
        return true;
    }
    return false;
}

__declspec(dllexport) bool TITCALL DumpMemoryEx(DWORD ProcessId, LPVOID MemoryStart, ULONG_PTR MemorySize, char* szDumpFileName)
{
    wchar_t uniDumpFileName[MAX_PATH] = {0};

    if(szDumpFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szDumpFileName, -1, uniDumpFileName, _countof(uniDumpFileName));
        return(DumpMemoryExW(ProcessId, MemoryStart, MemorySize, uniDumpFileName));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL DumpMemoryExW(DWORD ProcessId, LPVOID MemoryStart, ULONG_PTR MemorySize, wchar_t* szDumpFileName)
{
    HANDLE hProcess = 0;
    bool ReturnValue = false;

    hProcess = EngineOpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    if(hProcess)
    {
        ReturnValue = DumpMemoryW(hProcess, MemoryStart, MemorySize, szDumpFileName);
        EngineCloseHandle(hProcess);
        return ReturnValue;
    }

    return false;
}

__declspec(dllexport) bool TITCALL DumpRegions(HANDLE hProcess, char* szDumpFolder, bool DumpAboveImageBaseOnly)
{
    wchar_t uniDumpFolder[MAX_PATH] = {0};

    if(szDumpFolder != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szDumpFolder, -1, uniDumpFolder, _countof(uniDumpFolder));
        return(DumpRegionsW(hProcess, uniDumpFolder, DumpAboveImageBaseOnly));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL DumpRegionsW(HANDLE hProcess, wchar_t* szDumpFolder, bool DumpAboveImageBaseOnly)
{
    int i;
    DWORD cbNeeded = NULL;
    wchar_t szDumpName[MAX_PATH];
    wchar_t szDumpFileName[MAX_PATH];
    MEMORY_BASIC_INFORMATION MemInfo;
    ULONG_PTR DumpAddress = NULL;
    HMODULE EnumeratedModules[1024] = {0};
    bool AddressIsModuleBase = false;

    if(hProcess != NULL)
    {
        if(!EnumProcessModules(hProcess, EnumeratedModules, sizeof(EnumeratedModules), &cbNeeded))
        {
            return false;
        }

        while(VirtualQueryEx(hProcess, (LPVOID)DumpAddress, &MemInfo, sizeof MEMORY_BASIC_INFORMATION) != NULL)
        {
            AddressIsModuleBase = false;
            for(i = 0; i < (int)(cbNeeded / sizeof(HMODULE)); i++)
            {
                if(EnumeratedModules[i] == (HMODULE)MemInfo.AllocationBase)
                {
                    AddressIsModuleBase = true;
                    i = 1024;
                }
                else if(EnumeratedModules[i] == 0)
                {
                    i = 1024;
                }
            }
            if(!(MemInfo.Protect & PAGE_NOACCESS) && AddressIsModuleBase == false)
            {
                if(DumpAboveImageBaseOnly == false || (DumpAboveImageBaseOnly == true && EnumeratedModules[0] < (HMODULE)MemInfo.BaseAddress))
                {
                    RtlZeroMemory(&szDumpName, MAX_PATH);
                    RtlZeroMemory(&szDumpFileName, MAX_PATH);
                    lstrcpyW(szDumpFileName, szDumpFolder);
                    if(szDumpFileName[lstrlenW(szDumpFileName) - 1] != L'\\')
                    {
                        szDumpFileName[lstrlenW(szDumpFileName)] = L'\\';
                    }
                    wsprintfW(szDumpName, L"Dump-%x_%x.dmp", (ULONG_PTR)MemInfo.BaseAddress, (ULONG_PTR)MemInfo.RegionSize);
                    lstrcatW(szDumpFileName, szDumpName);
                    DumpMemoryW(hProcess, (LPVOID)MemInfo.BaseAddress, (ULONG_PTR)MemInfo.RegionSize, szDumpFileName);
                }
            }
            DumpAddress = DumpAddress + (ULONG_PTR)MemInfo.RegionSize;
        }
        return true;
    }
    return false;
}

__declspec(dllexport) bool TITCALL DumpRegionsEx(DWORD ProcessId, char* szDumpFolder, bool DumpAboveImageBaseOnly)
{
    wchar_t uniDumpFolder[MAX_PATH] = {0};

    if(szDumpFolder != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szDumpFolder, -1, uniDumpFolder, _countof(uniDumpFolder));
        return(DumpRegionsExW(ProcessId, uniDumpFolder, DumpAboveImageBaseOnly));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL DumpRegionsExW(DWORD ProcessId, wchar_t* szDumpFolder, bool DumpAboveImageBaseOnly)
{
    HANDLE hProcess = 0;
    bool ReturnValue = false;

    hProcess = EngineOpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    if(hProcess)
    {
        ReturnValue = DumpRegionsW(hProcess, szDumpFolder, DumpAboveImageBaseOnly);
        EngineCloseHandle(hProcess);
        return ReturnValue;
    }

    return false;
}

__declspec(dllexport) bool TITCALL DumpModule(HANDLE hProcess, LPVOID ModuleBase, char* szDumpFileName)
{
    wchar_t uniDumpFileName[MAX_PATH] = {0};

    if(szDumpFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szDumpFileName, -1, uniDumpFileName, _countof(uniDumpFileName));
        return(DumpModuleW(hProcess, ModuleBase, uniDumpFileName));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL DumpModuleW(HANDLE hProcess, LPVOID ModuleBase, wchar_t* szDumpFileName)
{

    int i;
    DWORD cbNeeded = NULL;
    MODULEINFO RemoteModuleInfo;
    HMODULE EnumeratedModules[1024] = {0};

    if(EnumProcessModules(hProcess, EnumeratedModules, sizeof(EnumeratedModules), &cbNeeded))
    {
        for(i = 0; i < (int)(cbNeeded / sizeof(HMODULE)); i++)
        {
            if(EnumeratedModules[i] == (HMODULE)ModuleBase)
            {
                if(GetModuleInformation(hProcess, (HMODULE)EnumeratedModules[i], &RemoteModuleInfo, sizeof(MODULEINFO)))
                {
                    return(DumpMemoryW(hProcess, (LPVOID)EnumeratedModules[i], RemoteModuleInfo.SizeOfImage, szDumpFileName));
                }
            }
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL DumpModuleEx(DWORD ProcessId, LPVOID ModuleBase, char* szDumpFileName)
{
    wchar_t uniDumpFileName[MAX_PATH] = {0};

    if(szDumpFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szDumpFileName, -1, uniDumpFileName, _countof(uniDumpFileName));
        return(DumpModuleExW(ProcessId, ModuleBase, uniDumpFileName));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL DumpModuleExW(DWORD ProcessId, LPVOID ModuleBase, wchar_t* szDumpFileName)
{

    HANDLE hProcess = 0;
    bool ReturnValue = false;

    hProcess = EngineOpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    if(hProcess) //If the function fails, the return value is NULL. To get extended error information, call GetLastError.
    {
        ReturnValue = DumpModuleW(hProcess, ModuleBase, szDumpFileName);
        EngineCloseHandle(hProcess);
        return ReturnValue;
    }

    return false;
}
