#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.h"
#include "Global.Handle.h"
#include "Global.Mapping.h"
#include <psapi.h>

HARDWARE_DATA DebugRegister[4] = {};
PROCESS_INFORMATION dbgProcessInformation = {};
char engineExtractedFolderName[512];
char engineFoundDLLName[512];
char engineFoundAPIName[512];
char engineExtractedFileName[512];
wchar_t engineExtractedFileNameW[512];
std::vector<PluginInformation> Plugin;
HMODULE engineHandle;
bool engineCheckForwarders = true;
bool engineAlowModuleLoading = false;
bool engineCreatePathForFiles = true; // hardcoded

// Global.Engine.functions:
void EngineExecutePluginReleaseCallBack()
{
    typedef void(TITCALL *fPluginReleaseExec)();
    fPluginReleaseExec myPluginReleaseExec;

    for(unsigned int i = 0; i < Plugin.size(); i++)
    {
        __try
        {
            if(Plugin.at(i).TitanReleasePlugin != NULL)
            {
                myPluginReleaseExec = (fPluginReleaseExec)Plugin[i].TitanReleasePlugin;
                myPluginReleaseExec();
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {

        }
    }
}

void EngineExecutePluginResetCallBack()
{

    typedef void(TITCALL *fPluginResetExec)();
    fPluginResetExec myPluginResetExec;

    for(unsigned int i = 0; i < Plugin.size(); i++)
    {
        __try
        {
            if(Plugin.at(i).TitanResetPlugin != NULL)
            {
                myPluginResetExec = (fPluginResetExec)Plugin[i].TitanResetPlugin;
                myPluginResetExec();
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {

        }
    }
}

void EngineExecutePluginDebugCallBack(LPDEBUG_EVENT debugEvent, int CallReason)
{
    typedef void(TITCALL *fPluginDebugExec)(LPDEBUG_EVENT debugEvent, int CallReason);
    fPluginDebugExec myPluginDebugExec;

    for(unsigned int i = 0; i < Plugin.size(); i++)
    {
        __try
        {
            if(!Plugin.at(i).PluginDisabled)
            {
                if(Plugin.at(i).TitanDebuggingCallBack != NULL)
                {
                    myPluginDebugExec = (fPluginDebugExec)Plugin[i].TitanDebuggingCallBack;
                    myPluginDebugExec(debugEvent, CallReason);
                }
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {

        }
    }
}

bool EngineIsThereFreeHardwareBreakSlot(LPDWORD FreeRegister)
{

    if(DebugRegister[0].DrxEnabled == false)
    {
        if(FreeRegister != NULL)
        {
            *FreeRegister = UE_DR0;
        }
        return(true);
    }
    else if(DebugRegister[1].DrxEnabled == false)
    {
        if(FreeRegister != NULL)
        {
            *FreeRegister = UE_DR1;
        }
        return(true);
    }
    else if(DebugRegister[2].DrxEnabled == false)
    {
        if(FreeRegister != NULL)
        {
            *FreeRegister = UE_DR2;
        }
        return(true);
    }
    else if(DebugRegister[3].DrxEnabled == false)
    {
        if(FreeRegister != NULL)
        {
            *FreeRegister = UE_DR3;
        }
        return(true);
    }
    return(false);
}

bool EngineFileExists(char* szFileName)
{

    HANDLE hFile = CreateFileA(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if(hFile != INVALID_HANDLE_VALUE)
    {
        EngineCloseHandle(hFile);
        return(true);
    }
    else
    {
        return(false);
    }
}

char* EngineExtractPath(char* szFileName)
{
    int i;

    RtlZeroMemory(&engineExtractedFolderName, sizeof(engineExtractedFolderName));
    lstrcpyA(engineExtractedFolderName, szFileName);
    i = lstrlenA(engineExtractedFolderName);
    while(i > 0 && engineExtractedFolderName[i] != 0x5C)
    {
        engineExtractedFolderName[i] = 0x00;
        i--;
    }
    return(engineExtractedFolderName);
}

char* EngineExtractFileName(char* szFileName)
{

    int i;
    int j;
    int x = 0;

    i = lstrlenA(szFileName);
    RtlZeroMemory(&engineExtractedFileName, sizeof(engineExtractedFileName));
    while(i > 0 && szFileName[i] != 0x5C)
    {
        i--;
    }
    if(szFileName[i] == 0x5C)
    {
        for(j = i + 1; j <= lstrlenA(szFileName); j++)
        {
            engineExtractedFileName[x] = szFileName[j];
            x++;
        }
    }
    else
    {
        return(szFileName);
    }
    return(engineExtractedFileName);
}

bool EngineCreatePathForFile(char* szFileName)
{

    int i,j;
    char szFolderName[2 * MAX_PATH] = {};
    char szCreateFolder[2 * MAX_PATH] = {};

    if(engineCreatePathForFiles)
    {
        i = lstrlenA(szFileName);
        while(szFileName[i] != '\\' && i > NULL)
        {
            i--;
        }
        if(i != NULL)
        {
            RtlMoveMemory(szFolderName, szFileName, i + 1);
            if(!CreateDirectoryA(szFolderName, NULL))
            {
                if(GetLastError() != ERROR_ALREADY_EXISTS)
                {
                    j = lstrlenA(szFolderName);
                    for(i = 4; i < j; i++)
                    {
                        if(szFileName[i] == '\\')
                        {
                            RtlZeroMemory(szCreateFolder, 2 * MAX_PATH);
                            RtlCopyMemory(szCreateFolder, szFileName, i + 1);
                            CreateDirectoryA(szCreateFolder, NULL);
                        }
                    }
                }
            }
        }
    }
    return(true);
}

bool EngineCreatePathForFileW(wchar_t* szFileName)
{

    int i,j;
    wchar_t szFolderName[MAX_PATH] = {};
    wchar_t szCreateFolder[MAX_PATH] = {};

    if(engineCreatePathForFiles)
    {
        i = lstrlenW(szFileName);
        while(szFileName[i] != '\\' && i > 0)
        {
            i--;
        }
        if(i != 0)
        {
            RtlCopyMemory(szFolderName, szFileName, (i * 2) + 2);
            if(!CreateDirectoryW(szFolderName, NULL))
            {
                if(GetLastError() != ERROR_ALREADY_EXISTS)
                {
                    j = lstrlenW(szFolderName);
                    for(i = 4; i < j; i++)
                    {
                        if(szFileName[i] == '\\')
                        {
                            RtlZeroMemory(szCreateFolder, 2 * MAX_PATH);
                            RtlCopyMemory(szCreateFolder, szFileName, (i * 2) + 1);
                            CreateDirectoryW(szCreateFolder, NULL);
                        }
                    }
                }
            }
        }
    }
    return(true);
}

wchar_t* EngineExtractFileNameW(wchar_t* szFileName)
{

    int i;
    int j;
    int x = 0;

    i = lstrlenW(szFileName);
    RtlZeroMemory(&engineExtractedFileNameW, sizeof engineExtractedFileNameW);
    while(i > 0 && szFileName[i] != 0x5C)
    {
        i--;
    }
    if(szFileName[i] == 0x5C)
    {
        int len=lstrlenW(szFileName);
        for(j = i + 1; j <= len; j++)
        {
            engineExtractedFileNameW[x] = szFileName[j];
            x++;
        }
    }
    else
    {
        return(szFileName);
    }
    return(engineExtractedFileNameW);
}

bool EngineIsPointedMemoryString(ULONG_PTR PossibleStringPtr)
{

    bool StringIsValid = true;
    unsigned int i = 512;
    MEMORY_BASIC_INFORMATION MemInfo = {0};
    DWORD MaxDisassmSize = 512;
    BYTE TestChar;

    VirtualQueryEx(GetCurrentProcess(), (LPVOID)PossibleStringPtr, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
    if(MemInfo.State == MEM_COMMIT)
    {
        if((ULONG_PTR)MemInfo.BaseAddress + (ULONG_PTR)MemInfo.RegionSize - PossibleStringPtr <= 512)
        {
            MaxDisassmSize = (DWORD)((ULONG_PTR)MemInfo.BaseAddress + (ULONG_PTR)MemInfo.RegionSize - PossibleStringPtr - 1);
            VirtualQueryEx(GetCurrentProcess(), (LPVOID)(PossibleStringPtr + (ULONG_PTR)MemInfo.RegionSize), &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
            if(MemInfo.State != MEM_COMMIT)
            {
                i = MaxDisassmSize;
            }
            else
            {
                MaxDisassmSize = 512;
            }
        }
        else
        {
            MaxDisassmSize = 512;
        }

        TestChar = *((BYTE*)PossibleStringPtr);
        while(i > NULL && StringIsValid == true && TestChar != 0x00)
        {
            TestChar = *((BYTE*)PossibleStringPtr);

            if(TestChar < 32 || TestChar > 126)
            {
                if(TestChar != 0x00)
                {
                    StringIsValid = false;
                }
            }
            PossibleStringPtr++;
            i--;
        }
        if(StringIsValid == true && MaxDisassmSize - i > 4)
        {
            return(true);
        }
    }
    return(false);
}

int EnginePointedMemoryStringLength(ULONG_PTR PossibleStringPtr)
{

    bool StringIsValid = true;
    unsigned int i = 512;
    MEMORY_BASIC_INFORMATION MemInfo;
    DWORD MaxDisassmSize = 512;
    BYTE TestChar;

    VirtualQueryEx(GetCurrentProcess(), (LPVOID)PossibleStringPtr, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
    if(MemInfo.State == MEM_COMMIT)
    {
        if((ULONG_PTR)MemInfo.BaseAddress + (ULONG_PTR)MemInfo.RegionSize - PossibleStringPtr <= 512)
        {
            MaxDisassmSize = (DWORD)((ULONG_PTR)MemInfo.BaseAddress + (ULONG_PTR)MemInfo.RegionSize - PossibleStringPtr - 1);
            VirtualQueryEx(GetCurrentProcess(), (LPVOID)(PossibleStringPtr + (ULONG_PTR)MemInfo.RegionSize), &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
            if(MemInfo.State != MEM_COMMIT)
            {
                i = MaxDisassmSize;
            }
        }

        TestChar = *((BYTE*)PossibleStringPtr);
        while(i > NULL && StringIsValid == true && TestChar != 0x00)
        {
            TestChar = *((BYTE*)PossibleStringPtr);

            if(TestChar < 32 || TestChar > 126)
            {
                if(TestChar != 0x00)
                {
                    StringIsValid = false;
                }
            }
            PossibleStringPtr++;
            i--;
        }
        if(StringIsValid == true && 512 - i > 4)
        {
            i = 512 - i;
            return(i);
        }
    }
    return(NULL);
}

bool EngineCompareResourceString(wchar_t* String1, wchar_t* String2)
{

    PMEMORY_COMPARE_HANDLER memData = (PMEMORY_COMPARE_HANDLER)String1;
    wchar_t StringCmp[MAX_PATH] = {};

    String1 = (wchar_t*)((ULONG_PTR)String1 + 2);
    RtlMoveMemory(&StringCmp[0], &String1[0], memData->Array.wArrayEntry[0] * 2);
    if(lstrcmpiW(StringCmp, String2) == NULL)
    {
        return(true);
    }
    return(false);
}

long long EngineEstimateNewSectionRVA(ULONG_PTR FileMapVA)
{

    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_SECTION_HEADER PESections;
    DWORD NewSectionVirtualOffset = 0;
    DWORD SectionNumber = 0;
    BOOL FileIs64;

    if(FileMapVA != NULL)
    {
        DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
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
            PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PEHeader32 + PEHeader32->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4);
            SectionNumber = PEHeader32->FileHeader.NumberOfSections;
            __try
            {
                PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + (SectionNumber - 1) * IMAGE_SIZEOF_SECTION_HEADER);
                NewSectionVirtualOffset = PESections->VirtualAddress + (PESections->Misc.VirtualSize / PEHeader32->OptionalHeader.SectionAlignment) * PEHeader32->OptionalHeader.SectionAlignment;
                if(NewSectionVirtualOffset < PESections->VirtualAddress + PESections->Misc.VirtualSize)
                {
                    NewSectionVirtualOffset = NewSectionVirtualOffset + PEHeader32->OptionalHeader.SectionAlignment;
                }
                return((ULONG_PTR)(NewSectionVirtualOffset + PEHeader32->OptionalHeader.ImageBase));
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                return(0);
            }
        }
        else
        {
            PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PEHeader64 + PEHeader64->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4);
            SectionNumber = PEHeader64->FileHeader.NumberOfSections;
            __try
            {
                PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + (SectionNumber - 1) * IMAGE_SIZEOF_SECTION_HEADER);
                NewSectionVirtualOffset = PESections->VirtualAddress + (PESections->Misc.VirtualSize / PEHeader64->OptionalHeader.SectionAlignment) * PEHeader64->OptionalHeader.SectionAlignment;
                if(NewSectionVirtualOffset < PESections->VirtualAddress + PESections->Misc.VirtualSize)
                {
                    NewSectionVirtualOffset = NewSectionVirtualOffset + PEHeader32->OptionalHeader.SectionAlignment;
                }
                return((ULONG_PTR)(NewSectionVirtualOffset + PEHeader64->OptionalHeader.ImageBase));
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                return(0);
            }
        }
    }
    return(0);
}

bool EngineExtractForwarderData(ULONG_PTR PossibleStringPtr, LPVOID szFwdDLLName, LPVOID szFwdAPIName)
{

    __try
    {
        LPVOID lpPossibleStringPtr = (LPVOID)PossibleStringPtr;
        BYTE TestChar;

        TestChar = *((BYTE*)PossibleStringPtr);

        while(TestChar != 0x2E && TestChar != 0x00)
        {
            TestChar = *((BYTE*)PossibleStringPtr);
            PossibleStringPtr++;
        }
        if(TestChar == 0x00)
        {
            return(false);
        }
        PossibleStringPtr--;
        RtlCopyMemory(szFwdDLLName, lpPossibleStringPtr, PossibleStringPtr - (ULONG_PTR)lpPossibleStringPtr);
        lstrcatA((LPSTR)szFwdDLLName, ".dll");
        lpPossibleStringPtr = (LPVOID)(PossibleStringPtr + 1);
        TestChar = *((BYTE*)PossibleStringPtr);

        if(TestChar == 0x23)
        {
            lpPossibleStringPtr = (LPVOID)(PossibleStringPtr + 1);
        }
        while(TestChar != 0x00)
        {
            TestChar = *((BYTE*)PossibleStringPtr);
            PossibleStringPtr++;
        }
        RtlCopyMemory(szFwdAPIName, lpPossibleStringPtr, PossibleStringPtr - (ULONG_PTR)lpPossibleStringPtr);
        return(true);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return(false);
    }
}

bool EngineGrabDataFromMappedFile(HANDLE hFile, ULONG_PTR FileMapVA, ULONG_PTR FileOffset, DWORD CopySize, LPVOID CopyToMemory)
{
    DWORD rfNumberOfBytesRead = NULL;

    RtlZeroMemory(CopyToMemory, CopySize);
    SetFilePointer(hFile, (DWORD)(FileOffset - FileMapVA), NULL, FILE_BEGIN);
    return !!ReadFile(hFile, CopyToMemory, CopySize, &rfNumberOfBytesRead, NULL);
}

bool EngineExtractResource(char* szResourceName, wchar_t* szExtractedFileName)
{

    HRSRC hResource;
    HGLOBAL hResourceGlobal;
    DWORD ResourceSize;
    LPVOID ResourceData;
    DWORD NumberOfBytesWritten;
    HANDLE hFile;

    hResource = FindResourceA(engineHandle, (LPCSTR)szResourceName, "BINARY");
    if(hResource != NULL)
    {
        hResourceGlobal = LoadResource(engineHandle, hResource);
        if(hResourceGlobal != NULL)
        {
            ResourceSize = SizeofResource(engineHandle, hResource);
            ResourceData = LockResource(hResourceGlobal);
            if(EngineCreatePathForFileW(szExtractedFileName))
            {
                hFile = CreateFileW(szExtractedFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if(hFile != INVALID_HANDLE_VALUE)
                {
                    WriteFile(hFile, ResourceData, ResourceSize, &NumberOfBytesWritten, NULL);
                    EngineCloseHandle(hFile);
                }
                else
                {
                    return(false);
                }
            }
        }
        return(true);
    }
    return(false);
}

bool EngineIsDependencyPresent(char* szFileName, char* szDependencyForFile, char* szPresentInFolder)
{
    int i,j;
    HANDLE hFile;
    char szTryFileName[512] = {0};

    if(szPresentInFolder != NULL && szFileName != NULL)
    {
        lstrcpyA(szTryFileName, szPresentInFolder);
        if(szTryFileName[lstrlenA(szTryFileName)-1] != 0x5C)
        {
            szTryFileName[lstrlenA(szTryFileName)] = 0x5C;
        }
        lstrcatA(szTryFileName, szFileName);
        hFile = CreateFileA(szTryFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if(hFile != INVALID_HANDLE_VALUE)
        {
            EngineCloseHandle(hFile);
            return(true);
        }
    }

    if(szFileName != NULL)
    {
        hFile = CreateFileA(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if(hFile != INVALID_HANDLE_VALUE)
        {
            EngineCloseHandle(hFile);
            return(true);
        }
        if(GetSystemDirectoryA(szTryFileName, 512) > NULL)
        {
            lstrcatA(szTryFileName, "\\");
            lstrcatA(szTryFileName, szFileName);
            hFile = CreateFileA(szTryFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if(hFile != INVALID_HANDLE_VALUE)
            {
                EngineCloseHandle(hFile);
                return(true);
            }
        }
        if(GetWindowsDirectoryA(szTryFileName, 512) > NULL)
        {
            lstrcatA(szTryFileName, "\\");
            lstrcatA(szTryFileName, szFileName);
            hFile = CreateFileA(szTryFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if(hFile != INVALID_HANDLE_VALUE)
            {
                EngineCloseHandle(hFile);
                return(true);
            }
        }
        if(szDependencyForFile != NULL)
        {
            RtlZeroMemory(&szTryFileName, 512);
            i = lstrlenA(szDependencyForFile);
            while(i > 0 && szDependencyForFile[i] != 0x5C)
            {
                i--;
            }
            for(j = 0; j <= i; j++)
            {
                szTryFileName[j] = szDependencyForFile[j];
            }
            lstrcatA(szTryFileName, szFileName);
            hFile = CreateFileA(szTryFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if(hFile != INVALID_HANDLE_VALUE)
            {
                EngineCloseHandle(hFile);
                return(true);
            }
        }
    }
    return(false);
}

bool EngineIsDependencyPresentW(wchar_t* szFileName, wchar_t* szDependencyForFile, wchar_t* szPresentInFolder)
{

    int i,j;
    HANDLE hFile;
    wchar_t szTryFileName[512] = {0};

    if(szPresentInFolder != NULL)
    {
        lstrcpyW(szTryFileName, szPresentInFolder);
        if(szTryFileName[lstrlenW(szTryFileName)-1] != 0x5C)
        {
            szTryFileName[lstrlenW(szTryFileName)] = 0x5C;
        }
        lstrcatW(szTryFileName, szFileName);
        hFile = CreateFileW(szTryFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if(hFile != INVALID_HANDLE_VALUE)
        {
            EngineCloseHandle(hFile);
            return(true);
        }
    }
    if(szFileName != NULL)
    {
        hFile = CreateFileW(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if(hFile != INVALID_HANDLE_VALUE)
        {
            EngineCloseHandle(hFile);
            return(true);
        }
        if(GetSystemDirectoryW(szTryFileName, 512) > NULL)
        {
            lstrcatW(szTryFileName, L"\\");
            lstrcatW(szTryFileName, szFileName);
            hFile = CreateFileW(szTryFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if(hFile != INVALID_HANDLE_VALUE)
            {
                EngineCloseHandle(hFile);
                return(true);
            }
        }

        if(GetWindowsDirectoryW(szTryFileName, 512) > NULL)
        {
            lstrcatW(szTryFileName, L"\\");
            lstrcatW(szTryFileName, szFileName);
            hFile = CreateFileW(szTryFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if(hFile != INVALID_HANDLE_VALUE)
            {
                EngineCloseHandle(hFile);
                return(true);
            }
        }

        if(szDependencyForFile != NULL)
        {
            i = lstrlenW(szDependencyForFile);
            while(i > 0 && szDependencyForFile[i] != 0x5C)
            {
                i--;
            }
            for(j = 0; j <= i; j++)
            {
                szTryFileName[j] = szDependencyForFile[j];
            }
            lstrcatW(szTryFileName, szFileName);
            hFile = CreateFileW(szTryFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if(hFile != INVALID_HANDLE_VALUE)
            {
                EngineCloseHandle(hFile);
                return(true);
            }
        }
    }
    return(false);
}

bool EngineGetDependencyLocation(char* szFileName, char* szDependencyForFile, void* szLocationOfTheFile, int MaxStringSize)
{

    int i,j;
    HANDLE hFile;
    char szTryFileName[512] = {0};

    if(szFileName != NULL)
    {
        hFile = CreateFileA(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if(hFile != INVALID_HANDLE_VALUE)
        {
            RtlZeroMemory(szLocationOfTheFile, MaxStringSize);
            if(lstrlenA(szFileName) <= MaxStringSize)
            {
                RtlCopyMemory(szLocationOfTheFile, szFileName, lstrlenA(szFileName));
            }
            EngineCloseHandle(hFile);
            return(true);
        }
        if(GetSystemDirectoryA(szTryFileName, 512) > NULL)
        {
            lstrcatA(szTryFileName, "\\");
            lstrcatA(szTryFileName, szFileName);
            hFile = CreateFileA(szTryFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if(hFile != INVALID_HANDLE_VALUE)
            {
                RtlZeroMemory(szLocationOfTheFile, MaxStringSize);
                if(lstrlenA(szTryFileName) <= MaxStringSize)
                {
                    RtlCopyMemory(szLocationOfTheFile, &szTryFileName, lstrlenA(szTryFileName));
                }
                EngineCloseHandle(hFile);
                return(true);
            }
        }
        if(GetWindowsDirectoryA(szTryFileName, 512) > NULL)
        {
            lstrcatA(szTryFileName, "\\");
            lstrcatA(szTryFileName, szFileName);
            hFile = CreateFileA(szTryFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if(hFile != INVALID_HANDLE_VALUE)
            {
                RtlZeroMemory(szLocationOfTheFile, MaxStringSize);
                if(lstrlenA(szTryFileName) <= MaxStringSize)
                {
                    RtlCopyMemory(szLocationOfTheFile, &szTryFileName, lstrlenA(szTryFileName));
                }
                EngineCloseHandle(hFile);
                return(true);
            }
        }
        if(szDependencyForFile != NULL)
        {
            RtlZeroMemory(&szTryFileName, 512);
            i = lstrlenA(szDependencyForFile);
            while(i > 0 && szDependencyForFile[i] != 0x5C)
            {
                i--;
            }
            for(j = 0; j <= i; j++)
            {
                szTryFileName[j] = szDependencyForFile[j];
            }
            lstrcatA(szTryFileName, szFileName);
            hFile = CreateFileA(szTryFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if(hFile != INVALID_HANDLE_VALUE)
            {
                RtlZeroMemory(szLocationOfTheFile, MaxStringSize);
                if(lstrlenA(szTryFileName) <= MaxStringSize)
                {
                    RtlCopyMemory(szLocationOfTheFile, &szTryFileName, lstrlenA(szTryFileName));
                }
                EngineCloseHandle(hFile);
                return(true);
            }
        }
    }
    return(false);
}

long EngineHashString(char* szStringToHash)
{

    int i = NULL;
    DWORD HashValue = NULL;

    if(szStringToHash != NULL)
    {
        for(i = 0; i < lstrlenA(szStringToHash); i++)
        {
            HashValue = (((HashValue << 7) | (HashValue >> (32 - 7))) ^ szStringToHash[i]);
        }
    }
    return(HashValue);
}

long EngineHashMemory(char* MemoryAddress, int MemorySize, DWORD InitialHashValue)
{

    int i = NULL;
    DWORD HashValue = InitialHashValue;

    for(i = 0; i < MemorySize; i++)
    {
        if(MemoryAddress[i] != NULL)
        {
            HashValue = (((HashValue << 7) | (HashValue >> (32 - 7))) ^ MemoryAddress[i]);
        }
    }
    return(HashValue);
}

bool EngineIsBadReadPtrEx(LPVOID DataPointer, DWORD DataSize)
{

    MEMORY_BASIC_INFORMATION MemInfo = {0};

    while(DataSize > NULL)
    {
        VirtualQuery(DataPointer, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
        if(MemInfo.AllocationProtect == MEM_FREE || MemInfo.AllocationProtect == MEM_PRIVATE)
        {
            return(false);
        }
        DataPointer = (LPVOID)((ULONG_PTR)DataPointer + MemInfo.RegionSize);
        if(MemInfo.RegionSize > DataSize)
        {
            DataSize = NULL;
        }
        else
        {
            DataSize = DataSize - (DWORD)MemInfo.RegionSize;
        }
    }
    return(true);
}

bool EngineValidateResource(HMODULE hModule, LPCTSTR lpszType, LPTSTR lpszName, LONG_PTR lParam)
{

    HRSRC hResource;
    HGLOBAL hResourceGlobal;
    DWORD ResourceSize;
    LPVOID ResourceData;
    BYTE ReturnData = UE_FIELD_FIXABLE_CRITICAL;

    hResource = FindResourceA(hModule, (LPCSTR)lpszName, (LPCSTR)lpszType);
    if(hResource != NULL)
    {
        hResourceGlobal = LoadResource(hModule, hResource);
        if(hResourceGlobal != NULL)
        {
            ResourceSize = SizeofResource(hModule, hResource);
            ResourceData = LockResource(hResourceGlobal);
            if(ResourceData != NULL)
            {
                if(!EngineIsBadReadPtrEx(ResourceData, ResourceSize))
                {
                    *((LONG*)lParam) = ReturnData;
                    return(false);
                }
            }
            else
            {
                *((LONG*)lParam) = ReturnData;
                return(false);
            }
        }
        return(true);
    }

    *((LONG*)lParam) = ReturnData;
    return(false);
}

bool EngineValidateHeader(ULONG_PTR FileMapVA, HANDLE hFileProc, LPVOID ImageBase, PIMAGE_DOS_HEADER DOSHeader, bool IsFile)
{

    MODULEINFO ModuleInfo;
    DWORD MemorySize = NULL;
    PIMAGE_NT_HEADERS32 PEHeader32;
    IMAGE_NT_HEADERS32 RemotePEHeader32;
    MEMORY_BASIC_INFORMATION MemoryInfo= {0};
    ULONG_PTR NumberOfBytesRW = NULL;

    if(IsFile)
    {
        if(hFileProc == NULL)
        {
            VirtualQueryEx(GetCurrentProcess(), (LPVOID)FileMapVA, &MemoryInfo, sizeof MEMORY_BASIC_INFORMATION);
            VirtualQueryEx(GetCurrentProcess(), MemoryInfo.AllocationBase, &MemoryInfo, sizeof MEMORY_BASIC_INFORMATION);
            MemorySize = (DWORD)((ULONG_PTR)MemoryInfo.AllocationBase + (ULONG_PTR)MemoryInfo.RegionSize - (ULONG_PTR)FileMapVA);
        }
        else
        {
            MemorySize = GetFileSize(hFileProc, NULL);
        }
        __try
        {
            if(DOSHeader->e_magic == 0x5A4D)
            {
                if(DOSHeader->e_lfanew + sizeof IMAGE_DOS_HEADER + sizeof(IMAGE_NT_HEADERS64) < MemorySize)
                {
                    PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
                    if(PEHeader32->Signature != 0x4550)
                    {
                        return(false);
                    }
                    else
                    {
                        return(true);
                    }
                }
                else
                {
                    return(false);
                }
            }
            else
            {
                return(false);
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            return(false);
        }
    }
    else
    {
        RtlZeroMemory(&ModuleInfo, sizeof MODULEINFO);
        GetModuleInformation(hFileProc, (HMODULE)ImageBase, &ModuleInfo, sizeof MODULEINFO);
        __try
        {
            if(DOSHeader->e_magic == 0x5A4D)
            {
                if(DOSHeader->e_lfanew + sizeof IMAGE_DOS_HEADER + sizeof(IMAGE_NT_HEADERS64) < ModuleInfo.SizeOfImage)
                {
                    if(ReadProcessMemory(hFileProc, (LPVOID)((ULONG_PTR)ImageBase + DOSHeader->e_lfanew), &RemotePEHeader32, sizeof IMAGE_NT_HEADERS32, &NumberOfBytesRW))
                    {
                        PEHeader32 = (PIMAGE_NT_HEADERS32)(&RemotePEHeader32);
                        if(PEHeader32->Signature != 0x4550)
                        {
                            return(false);
                        }
                        else
                        {
                            return(true);
                        }
                    }
                    else
                    {
                        return(false);
                    }
                }
                else
                {
                    return(false);
                }
            }
            else
            {
                return(false);
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            return(false);
        }
    }
}

long long EngineSimulateNtLoaderW(wchar_t* szFileName)
{

    DWORD PeHeaderSize;
    LPVOID AllocatedFile;
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_SECTION_HEADER PESections;
    DWORD SectionNumber = 0;
    DWORD SectionRawOffset = 0;
    DWORD SectionRawSize = 0;
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
                return(NULL);
            }
            if(!FileIs64)
            {
                AllocatedFile = VirtualAlloc(NULL, PEHeader32->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
                __try
                {
                    PeHeaderSize = DOSHeader->e_lfanew + PEHeader32->FileHeader.SizeOfOptionalHeader + (sizeof(IMAGE_SECTION_HEADER) * PEHeader32->FileHeader.NumberOfSections) + sizeof(IMAGE_FILE_HEADER) + 4;
                    PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PEHeader32 + PEHeader32->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4);
                    SectionNumber = PEHeader32->FileHeader.NumberOfSections;
                    RtlCopyMemory(AllocatedFile, (LPVOID)FileMapVA, PeHeaderSize);
                    while(SectionNumber > 0)
                    {
                        RtlCopyMemory((LPVOID)((ULONG_PTR)AllocatedFile + PESections->VirtualAddress), (LPVOID)(FileMapVA + PESections->PointerToRawData), PESections->SizeOfRawData);
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                        SectionNumber--;
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    VirtualFree(AllocatedFile, NULL, MEM_RELEASE);
                    AllocatedFile = NULL;
                }
                UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                return((ULONG_PTR)AllocatedFile);
            }
            else
            {
                AllocatedFile = VirtualAlloc(NULL, PEHeader64->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
                __try
                {
                    PeHeaderSize = DOSHeader->e_lfanew + PEHeader64->FileHeader.SizeOfOptionalHeader + (sizeof(IMAGE_SECTION_HEADER) * PEHeader64->FileHeader.NumberOfSections) + sizeof(IMAGE_FILE_HEADER) + 4;
                    PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PEHeader64 + PEHeader64->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4);
                    SectionNumber = PEHeader64->FileHeader.NumberOfSections;
                    RtlCopyMemory(AllocatedFile, (LPVOID)FileMapVA, PeHeaderSize);
                    while(SectionNumber > 0)
                    {
                        RtlCopyMemory((LPVOID)((ULONG_PTR)AllocatedFile + PESections->VirtualAddress), (LPVOID)(FileMapVA + PESections->PointerToRawData), PESections->SizeOfRawData);
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                        SectionNumber--;
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    VirtualFree(AllocatedFile, NULL, MEM_RELEASE);
                    AllocatedFile = NULL;
                }
                UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                return((ULONG_PTR)AllocatedFile);
            }
        }
        else
        {
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            return(NULL);
        }
    }
    return(NULL);
}

long long EngineSimulateNtLoader(char* szFileName)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        return(EngineSimulateNtLoaderW(uniFileName));
    }
    else
    {
        return(NULL);
    }
}

long long EngineSimulateDllLoader(HANDLE hProcess, char* szFileName)
{

    int n;
    BOOL FileIs64;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    HANDLE FileHandle;
    LPVOID DLLMemory = NULL;
    DWORD ExportDelta = NULL;
    DWORD PEHeaderSize = NULL;
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_EXPORT_DIRECTORY PEExports;
    PEXPORTED_DATA ExportedFunctionNames;
    ULONG_PTR ConvertedExport = NULL;
    char szFileRemoteProc[1024]= {0};
    char szDLLFileLocation[512]= {0};
    char* szTranslatedProcName=0;

    GetProcessImageFileNameA(hProcess, szFileRemoteProc, sizeof(szFileRemoteProc));
    szTranslatedProcName = (char*)TranslateNativeName(szFileRemoteProc);
    if(EngineIsDependencyPresent(szFileName, NULL, NULL))
    {
        if(EngineGetDependencyLocation(szFileName, szTranslatedProcName, &szDLLFileLocation, sizeof(szDLLFileLocation)))
        {
            VirtualFree((void*)szTranslatedProcName, NULL, MEM_RELEASE);
            if(MapFileEx(szDLLFileLocation, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
            {
                DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
                if(EngineValidateHeader(FileMapVA, FileHandle, NULL, DOSHeader, true))
                {
                    PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
                    PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
                    if(PEHeader32->OptionalHeader.Magic == 0x10B)
                    {
                        PEHeaderSize = PEHeader32->FileHeader.NumberOfSections * IMAGE_SIZEOF_SECTION_HEADER + PEHeader32->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4;
                        FileIs64 = false;
                    }
                    else if(PEHeader32->OptionalHeader.Magic == 0x20B)
                    {
                        PEHeaderSize = PEHeader64->FileHeader.NumberOfSections * IMAGE_SIZEOF_SECTION_HEADER + PEHeader64->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4;
                        FileIs64 = true;
                    }
                    else
                    {
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(NULL);
                    }
                    if(!FileIs64)
                    {
                        if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != NULL)
                        {
                            DLLMemory = VirtualAlloc(NULL, DOSHeader->e_lfanew + PEHeaderSize + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size + 0x1000, MEM_COMMIT, PAGE_READWRITE);
                            if(DLLMemory != NULL)
                            {
                                __try
                                {
                                    if((DOSHeader->e_lfanew + PEHeaderSize) % 0x1000 != 0)
                                    {
                                        ExportDelta = (((DOSHeader->e_lfanew + PEHeaderSize) / 0x1000) + 1) * 0x1000;
                                    }
                                    else
                                    {
                                        ExportDelta = ((DOSHeader->e_lfanew + PEHeaderSize) / 0x1000) * 0x1000;
                                    }
                                    ConvertedExport = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, PEHeader32->OptionalHeader.ImageBase, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, true, true);
                                    if(ConvertedExport != NULL)
                                    {
                                        PEExports = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)DLLMemory + ExportDelta);
                                        RtlCopyMemory(DLLMemory, (LPVOID)FileMapVA, PEHeaderSize + DOSHeader->e_lfanew);
                                        RtlCopyMemory((LPVOID)((ULONG_PTR)DLLMemory + ExportDelta), (LPVOID)ConvertedExport, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
                                        PEExports->AddressOfFunctions = PEExports->AddressOfFunctions - PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + ExportDelta;
                                        PEExports->AddressOfNameOrdinals = PEExports->AddressOfNameOrdinals - PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + ExportDelta;
                                        PEExports->AddressOfNames = PEExports->AddressOfNames - PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + ExportDelta;
                                        PEExports->Name = PEExports->Name - PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + ExportDelta;
                                        ExportedFunctionNames = (PEXPORTED_DATA)(PEExports->AddressOfNames + (ULONG_PTR)DLLMemory);
                                        for(n = 0; n < (int)PEExports->NumberOfNames; n++)
                                        {
                                            ExportedFunctionNames->ExportedItem = ExportedFunctionNames->ExportedItem - PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + ExportDelta;
                                            ExportedFunctionNames = (PEXPORTED_DATA)((ULONG_PTR)ExportedFunctionNames + 4);
                                        }
                                        DOSHeader = (PIMAGE_DOS_HEADER)DLLMemory;
                                        PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
                                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = ExportDelta;
                                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                                        return((ULONG_PTR)DLLMemory);
                                    }
                                    else
                                    {
                                        VirtualFree(DLLMemory, NULL, MEM_RELEASE);
                                    }
                                }
                                __except(EXCEPTION_EXECUTE_HANDLER)
                                {
                                    VirtualFree(DLLMemory, NULL, MEM_RELEASE);
                                }
                            }
                        }
                    }
                    else
                    {
                        if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != NULL)
                        {
                            DLLMemory = VirtualAlloc(NULL, DOSHeader->e_lfanew + PEHeaderSize + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size + 0x1000, MEM_COMMIT, PAGE_READWRITE);
                            if(DLLMemory != NULL)
                            {
                                __try
                                {
                                    if((DOSHeader->e_lfanew + PEHeaderSize) % 0x1000 != 0)
                                    {
                                        ExportDelta = (((DOSHeader->e_lfanew + PEHeaderSize) % 0x1000) + 1) * 0x1000;
                                    }
                                    else
                                    {
                                        ExportDelta = ((DOSHeader->e_lfanew + PEHeaderSize) % 0x1000) * 0x1000;
                                    }
                                    ConvertedExport = (ULONG_PTR)ConvertVAtoFileOffsetEx(FileMapVA, FileSize, (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, true, true);
                                    if(ConvertedExport != NULL)
                                    {
                                        PEExports = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)DLLMemory + ExportDelta);
                                        RtlCopyMemory(DLLMemory, (LPVOID)FileMapVA, PEHeaderSize + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
                                        RtlCopyMemory((LPVOID)((ULONG_PTR)DLLMemory + ExportDelta), (LPVOID)ConvertedExport, PEHeaderSize + DOSHeader->e_lfanew);
                                        PEExports->AddressOfFunctions = PEExports->AddressOfFunctions - PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + ExportDelta;
                                        PEExports->AddressOfNameOrdinals = PEExports->AddressOfNameOrdinals - PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + ExportDelta;
                                        PEExports->AddressOfNames = PEExports->AddressOfNames - PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + ExportDelta;
                                        PEExports->Name = PEExports->Name - PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + ExportDelta;
                                        ExportedFunctionNames = (PEXPORTED_DATA)(PEExports->AddressOfNames + (ULONG_PTR)DLLMemory);
                                        for(n = 0; n < (int)PEExports->NumberOfNames; n++)
                                        {
                                            ExportedFunctionNames->ExportedItem = ExportedFunctionNames->ExportedItem - PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + ExportDelta;
                                            ExportedFunctionNames = (PEXPORTED_DATA)((ULONG_PTR)ExportedFunctionNames + 4);
                                        }
                                        DOSHeader = (PIMAGE_DOS_HEADER)DLLMemory;
                                        PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
                                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = ExportDelta;
                                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                                        return((ULONG_PTR)DLLMemory);
                                    }
                                    else
                                    {
                                        VirtualFree(DLLMemory, NULL, MEM_RELEASE);
                                    }
                                }
                                __except(EXCEPTION_EXECUTE_HANDLER)
                                {
                                    VirtualFree(DLLMemory, NULL, MEM_RELEASE);
                                }
                            }
                        }
                    }
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                }
            }
        }
    }
    VirtualFree((void*)szTranslatedProcName, NULL, MEM_RELEASE);
    return(NULL);
}

long long EngineGetProcAddress(ULONG_PTR ModuleBase, char* szAPIName)
{

    int i = 0;
    int j = 0;
    ULONG_PTR APIFoundAddress = 0;
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_EXPORT_DIRECTORY PEExports;
    PEXPORTED_DATA ExportedFunctions;
    PEXPORTED_DATA ExportedFunctionNames;
    PEXPORTED_DATA_WORD ExportedFunctionOrdinals;
    char szModuleName[MAX_PATH] = {};
    bool FileIs64 = false;

    if(GetModuleFileNameA((HMODULE)ModuleBase, szModuleName, MAX_PATH) == NULL)
    {
        __try
        {
            DOSHeader = (PIMAGE_DOS_HEADER)ModuleBase;
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
                return(NULL);
            }
            if(!FileIs64)
            {
                PEExports = (PIMAGE_EXPORT_DIRECTORY)(ModuleBase + (ULONG_PTR)PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                ExportedFunctions = (PEXPORTED_DATA)(ModuleBase + (ULONG_PTR)PEExports->AddressOfFunctions);
                ExportedFunctionNames = (PEXPORTED_DATA)(ModuleBase + (ULONG_PTR)PEExports->AddressOfNames);
                ExportedFunctionOrdinals = (PEXPORTED_DATA_WORD)(ModuleBase + (ULONG_PTR)PEExports->AddressOfNameOrdinals);
            }
            else
            {
                PEExports = (PIMAGE_EXPORT_DIRECTORY)(ModuleBase + (ULONG_PTR)PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                ExportedFunctions = (PEXPORTED_DATA)(ModuleBase + (ULONG_PTR)PEExports->AddressOfFunctions);
                ExportedFunctionNames = (PEXPORTED_DATA)(ModuleBase + (ULONG_PTR)PEExports->AddressOfNames);
                ExportedFunctionOrdinals = (PEXPORTED_DATA_WORD)(ModuleBase + (ULONG_PTR)PEExports->AddressOfNameOrdinals);
            }
            for(j = 0; j < (int)PEExports->NumberOfNames; j++)
            {
                if(lstrcmpiA((LPCSTR)szAPIName, (LPCSTR)(ModuleBase + (ULONG_PTR)ExportedFunctionNames->ExportedItem)) == NULL)
                {
                    ExportedFunctionOrdinals = (PEXPORTED_DATA_WORD)((ULONG_PTR)ExportedFunctionOrdinals + j * 2);
                    ExportedFunctions = (PEXPORTED_DATA)((ULONG_PTR)ExportedFunctions + (ExportedFunctionOrdinals->OrdinalNumber) * 4);
                    APIFoundAddress = ExportedFunctions->ExportedItem + (ULONG_PTR)ModuleBase;
                    return((ULONG_PTR)APIFoundAddress);
                }
                ExportedFunctionNames = (PEXPORTED_DATA)((ULONG_PTR)ExportedFunctionNames + 4);
            }
            return(NULL);
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            return(NULL);
        }
    }
    else
    {
        return((ULONG_PTR)GetProcAddress((HMODULE)ModuleBase, szAPIName));
    }
}

bool EngineGetLibraryOrdinalData(ULONG_PTR ModuleBase, LPDWORD ptrOrdinalBase, LPDWORD ptrOrdinalCount)
{

    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_EXPORT_DIRECTORY PEExports;
    bool FileIs64 = false;

    __try
    {
        DOSHeader = (PIMAGE_DOS_HEADER)ModuleBase;
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
            return(false);
        }
        if(!FileIs64)
        {
            PEExports = (PIMAGE_EXPORT_DIRECTORY)(ModuleBase + (ULONG_PTR)PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
            *ptrOrdinalBase = PEExports->Base;
            *ptrOrdinalCount = PEExports->NumberOfNames;
        }
        else
        {
            PEExports = (PIMAGE_EXPORT_DIRECTORY)(ModuleBase + (ULONG_PTR)PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
            *ptrOrdinalBase = PEExports->Base;
            *ptrOrdinalCount = PEExports->NumberOfNames;
        }
        return(true);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return(false);
    }
    return(false);
}

long long EngineGlobalAPIHandler(HANDLE handleProcess, ULONG_PTR EnumedModulesBases, ULONG_PTR APIAddress, char* szAPIName, DWORD ReturnType)
{

    unsigned int i = 0;
    unsigned int j = 0;
    unsigned int n = 0;
    unsigned int x = 0;
    unsigned int y = 0;
    unsigned int z = 0;
    DWORD Dummy = NULL;
    HANDLE hProcess = NULL;
    ULONG_PTR EnumeratedModules[0x2000];
    ULONG_PTR LoadedModules[1000][4];
    char RemoteDLLName[MAX_PATH]= {0};
    char FullRemoteDLLName[MAX_PATH]= {0};
    char szWindowsSideBySide[MAX_PATH]= {0};
    char szWindowsSideBySideCmp[MAX_PATH]= {0};
    char szWindowsKernelBase[MAX_PATH]= {0};
    HANDLE hLoadedModule = NULL;
    HANDLE ModuleHandle = NULL;
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_EXPORT_DIRECTORY PEExports;
    PEXPORTED_DATA ExportedFunctions;
    PEXPORTED_DATA ExportedFunctionNames;
    PEXPORTED_DATA_WORD ExportedFunctionOrdinals;
    ULONG_PTR APIFoundAddress = NULL;
    MODULEINFO RemoteModuleInfo;
    bool ValidateHeader = false;
    bool FileIs64 = false;
    bool APINameFound = false;
    bool SkipModule = false;
    unsigned int FoundIndex = 0;
    unsigned int FoundOrdinalNumber = 0;
    ULONG_PTR FileMapVA;
    char szFwdDLLName[512] = {0};
    char szFwdAPIName[512] = {0};
    ULONG_PTR RealignedAPIAddress;
    ULONG_PTR ForwarderData = NULL;
    unsigned int ClosestAPI = 0x1000;
    int Vista64UserForwarderFix = 0;
    unsigned int Windows7KernelBase = 0xFFFFFFFF;

    RtlZeroMemory(&engineFoundDLLName, sizeof(szFwdDLLName));
    RtlZeroMemory(&EnumeratedModules, 0x2000 * sizeof ULONG_PTR);
    RtlZeroMemory(&LoadedModules, 1000 * 4 * sizeof ULONG_PTR);
    GetWindowsDirectoryA(szWindowsSideBySide, MAX_PATH);
    lstrcpyA(szWindowsKernelBase, szWindowsSideBySide);
    lstrcatA(szWindowsSideBySide, "\\WinSxS");
    if(EnumedModulesBases != NULL)
    {
        RtlMoveMemory(&EnumeratedModules, (LPVOID)EnumedModulesBases, 0x1000);
        i--;
    }
    if(handleProcess == NULL)
    {
        if(dbgProcessInformation.hProcess == NULL)
        {
            hProcess = GetCurrentProcess();
        }
        else
        {
            hProcess = dbgProcessInformation.hProcess;
        }
    }
    else
    {
        hProcess = handleProcess;
    }
    if(EnumedModulesBases != NULL || EnumProcessModules(hProcess, (HMODULE*)EnumeratedModules, 0x2000, &Dummy))
    {
        i++;
        z = i;
        y = i;
        while(EnumeratedModules[y] != NULL)
        {
            // Vista x64 fix
            if(Vista64UserForwarderFix == NULL)
            {
                GetModuleBaseNameA(hProcess, (HMODULE)EnumeratedModules[y], (LPSTR)RemoteDLLName, MAX_PATH);
                if(!lstrcmpiA(RemoteDLLName, "user32.dll"))
                    Vista64UserForwarderFix = y;
                //NOTE: this code is used to ignore all APIs inside kernelbase.dll
                else if(!lstrcmpiA(RemoteDLLName, "kernelbase.dll"))
                {
                    GetModuleFileNameExA(hProcess, (HMODULE)EnumeratedModules[y], (LPSTR)RemoteDLLName, MAX_PATH);
                    RemoteDLLName[lstrlenA(szWindowsKernelBase)] = 0x00;
                    if(lstrcmpiA(RemoteDLLName, szWindowsKernelBase) == NULL)
                    {
                        Windows7KernelBase = y;
                    }
                }
            }
            y++;
        }
        while(APINameFound == false && EnumeratedModules[i] != NULL)
        {
            //NOTE: un-comment when kernelbase should be ignored
            /*if(i == Windows7KernelBase)
            {
                i++;
                if(EnumeratedModules[i] == NULL)
                {
                    break;
                }
            }*/
            ValidateHeader = false;
            RtlZeroMemory(&RemoteDLLName, MAX_PATH);
            GetModuleFileNameExA(hProcess, (HMODULE)EnumeratedModules[i], (LPSTR)RemoteDLLName, MAX_PATH);
            lstrcpyA(FullRemoteDLLName, RemoteDLLName);
            RtlZeroMemory(&szWindowsSideBySideCmp, MAX_PATH);
            RtlCopyMemory(&szWindowsSideBySideCmp, FullRemoteDLLName, lstrlenA(szWindowsSideBySide));
            if(GetModuleHandleA(RemoteDLLName) == NULL)
            {
                RtlZeroMemory(&RemoteDLLName, MAX_PATH);
                GetModuleBaseNameA(hProcess, (HMODULE)EnumeratedModules[i], (LPSTR)RemoteDLLName, MAX_PATH);
                if(GetModuleHandleA(RemoteDLLName) == NULL || lstrcmpiA(szWindowsSideBySideCmp, szWindowsSideBySide) == NULL)
                {
                    if(engineAlowModuleLoading)
                    {
                        hLoadedModule = LoadLibraryA(FullRemoteDLLName);
                        if(hLoadedModule != NULL)
                        {
                            LoadedModules[i][0] = EnumeratedModules[i];
                            LoadedModules[i][1] = (ULONG_PTR)hLoadedModule;
                            LoadedModules[i][2] = 1;
                        }
                    }
                    else
                    {
                        hLoadedModule = (HANDLE)EngineSimulateDllLoader(hProcess, FullRemoteDLLName);
                        if(hLoadedModule != NULL)
                        {
                            LoadedModules[i][0] = EnumeratedModules[i];
                            LoadedModules[i][1] = (ULONG_PTR)hLoadedModule;
                            LoadedModules[i][2] = 1;
                            ValidateHeader = true;
                        }
                    }
                }
                else
                {
                    LoadedModules[i][0] = EnumeratedModules[i];
                    LoadedModules[i][1] = (ULONG_PTR)GetModuleHandleA(RemoteDLLName);
                    LoadedModules[i][2] = 0;
                }
            }
            else
            {
                LoadedModules[i][0] = EnumeratedModules[i];
                LoadedModules[i][1] = (ULONG_PTR)GetModuleHandleA(RemoteDLLName);
                LoadedModules[i][2] = 0;
            }


            if(ReturnType != UE_OPTION_IMPORTER_RETURN_FORWARDER_DLLNAME && ReturnType != UE_OPTION_IMPORTER_RETURN_FORWARDER_DLLINDEX && ReturnType != UE_OPTION_IMPORTER_RETURN_FORWARDER_APINAME)
            {
                if(szAPIName == NULL && ReturnType == UE_OPTION_IMPORTER_REALIGN_APIADDRESS)
                {
                    RtlZeroMemory(&RemoteModuleInfo, sizeof MODULEINFO);
                    //GetModuleInformation(GetCurrentProcess(), (HMODULE)LoadedModules[i][1], &RemoteModuleInfo, sizeof MODULEINFO);
                    GetModuleInformation(hProcess, (HMODULE)LoadedModules[i][0], &RemoteModuleInfo, sizeof MODULEINFO);
                    if(APIAddress >= LoadedModules[i][1] && APIAddress <= LoadedModules[i][1] + RemoteModuleInfo.SizeOfImage)
                    {
                        GetModuleBaseNameA(hProcess, (HMODULE)LoadedModules[i][0], (LPSTR)engineFoundDLLName, 512);
                        APIFoundAddress = (ULONG_PTR)(APIAddress - LoadedModules[i][1] + LoadedModules[i][0]);
                        APINameFound = true;
                        FoundIndex = i;
                        break;
                    }
                }
                else if(szAPIName == NULL && ReturnType == UE_OPTION_IMPORTER_REALIGN_LOCAL_APIADDRESS)
                {
                    RtlZeroMemory(&RemoteModuleInfo, sizeof MODULEINFO);
                    GetModuleInformation(hProcess, (HMODULE)LoadedModules[i][0], &RemoteModuleInfo, sizeof MODULEINFO);
                    if(APIAddress >= LoadedModules[i][0] && APIAddress <= LoadedModules[i][0] + RemoteModuleInfo.SizeOfImage)
                    {
                        GetModuleBaseNameA(hProcess, (HMODULE)LoadedModules[i][0], (LPSTR)engineFoundDLLName, 512);
                        APIFoundAddress = (ULONG_PTR)(APIAddress - LoadedModules[i][0] + LoadedModules[i][1]);
                        APINameFound = true;
                        FoundIndex = i;
                        break;
                    }
                }
                else if(szAPIName == NULL && ReturnType == UE_OPTION_IMPORTER_RETURN_DLLBASE)
                {
                    if(APIAddress == LoadedModules[i][1])
                    {
                        APIFoundAddress = LoadedModules[i][0];
                        APINameFound = true;
                        FoundIndex = i;
                        break;
                    }
                }
                else if(ReturnType == UE_OPTION_IMPORTER_RETURN_NEAREST_APIADDRESS || ReturnType == UE_OPTION_IMPORTER_RETURN_NEAREST_APINAME)
                {
                    RtlZeroMemory(&RemoteModuleInfo, sizeof MODULEINFO);
                    GetModuleInformation(hProcess, (HMODULE)LoadedModules[i][0], &RemoteModuleInfo, sizeof MODULEINFO);
                    if(APIAddress >= LoadedModules[i][0] && APIAddress <= LoadedModules[i][0] + RemoteModuleInfo.SizeOfImage)
                    {
                        DOSHeader = (PIMAGE_DOS_HEADER)LoadedModules[i][1];
                        if(ValidateHeader || EngineValidateHeader((ULONG_PTR)LoadedModules[i][1], GetCurrentProcess(), RemoteModuleInfo.lpBaseOfDll, DOSHeader, false))
                        {
                            __try
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
                                    return(NULL);
                                }
                                if(!FileIs64)
                                {
                                    PEExports = (PIMAGE_EXPORT_DIRECTORY)(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + LoadedModules[i][1]);
                                    ExportedFunctions = (PEXPORTED_DATA)(PEExports->AddressOfFunctions + LoadedModules[i][1]);
                                }
                                else
                                {
                                    PEExports = (PIMAGE_EXPORT_DIRECTORY)(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + LoadedModules[i][1]);
                                    ExportedFunctions = (PEXPORTED_DATA)(PEExports->AddressOfFunctions + LoadedModules[i][1]);
                                }
                                for(n = 0; n < PEExports->NumberOfFunctions; n++)  //NumberOfNames
                                {
                                    if(APIAddress - (ExportedFunctions->ExportedItem + LoadedModules[i][0]) < ClosestAPI)
                                    {
                                        ClosestAPI = (unsigned int)(APIAddress - (ExportedFunctions->ExportedItem + LoadedModules[i][0]));
                                        ExportedFunctionNames = (PEXPORTED_DATA)(PEExports->AddressOfNames + LoadedModules[i][1]);
                                        ExportedFunctionOrdinals = (PEXPORTED_DATA_WORD)(PEExports->AddressOfNameOrdinals + LoadedModules[i][1]);
                                        GetModuleBaseNameA(hProcess, (HMODULE)LoadedModules[i][0], (LPSTR)engineFoundDLLName, 512);
                                        RtlZeroMemory(&engineFoundAPIName, sizeof(engineFoundAPIName));
                                        x = n;
                                        FoundOrdinalNumber = (unsigned int)PEExports->Base;
                                        for(j = 0; j < PEExports->NumberOfNames; j++)
                                        {
                                            if(ExportedFunctionOrdinals->OrdinalNumber != x)
                                            {
                                                ExportedFunctionOrdinals = (PEXPORTED_DATA_WORD)((ULONG_PTR)ExportedFunctionOrdinals + 2);
                                            }
                                            else
                                            {
                                                FoundOrdinalNumber = FoundOrdinalNumber + (unsigned int)ExportedFunctionOrdinals->OrdinalNumber;
                                                break;
                                            }
                                        }
                                        ExportedFunctionNames = (PEXPORTED_DATA)((ULONG_PTR)ExportedFunctionNames + j * 4);
                                        if(EngineIsPointedMemoryString((ULONG_PTR)(ExportedFunctionNames->ExportedItem + LoadedModules[i][1])))
                                        {
                                            lstrcpyA((LPSTR)engineFoundAPIName, (LPCSTR)(ExportedFunctionNames->ExportedItem + LoadedModules[i][1]));
                                        }
                                        APIFoundAddress = ExportedFunctions->ExportedItem + LoadedModules[i][0];
                                        APINameFound = true;
                                        FoundIndex = i;
                                    }
                                    ExportedFunctions = (PEXPORTED_DATA)((ULONG_PTR)ExportedFunctions + 4);
                                }
                            }
                            __except(EXCEPTION_EXECUTE_HANDLER)
                            {
                                ClosestAPI = 0x1000;
                                APINameFound = false;
                            }
                        }
                    }
                }

                if((ReturnType == UE_OPTION_IMPORTER_RETURN_API_ORDINAL_NUMBER || (ReturnType > UE_OPTION_IMPORTER_REALIGN_APIADDRESS && ReturnType < UE_OPTION_IMPORTER_RETURN_FORWARDER_DLLNAME)) && ReturnType != UE_OPTION_IMPORTER_RETURN_DLLBASE && LoadedModules[i][1] != NULL)
                {
                    RtlZeroMemory(&RemoteModuleInfo, sizeof MODULEINFO);
                    DOSHeader = (PIMAGE_DOS_HEADER)LoadedModules[i][1];
                    //GetModuleInformation(GetCurrentProcess(), (HMODULE)LoadedModules[i][1], &RemoteModuleInfo, sizeof MODULEINFO);
                    GetModuleInformation(hProcess, (HMODULE)LoadedModules[i][0], &RemoteModuleInfo, sizeof MODULEINFO);
                    if(APIAddress >= LoadedModules[i][0] && APIAddress <= LoadedModules[i][0] + RemoteModuleInfo.SizeOfImage)
                    {
                        if(ValidateHeader || EngineValidateHeader((ULONG_PTR)LoadedModules[i][1], GetCurrentProcess(), RemoteModuleInfo.lpBaseOfDll, DOSHeader, false))
                        {
                            __try
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
                                    return(NULL);
                                }
                                if(!FileIs64)
                                {
                                    PEExports = (PIMAGE_EXPORT_DIRECTORY)(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + LoadedModules[i][1]);
                                    ExportedFunctions = (PEXPORTED_DATA)(PEExports->AddressOfFunctions + LoadedModules[i][1]);
                                    ExportedFunctionNames = (PEXPORTED_DATA)(PEExports->AddressOfNames + LoadedModules[i][1]);
                                    ExportedFunctionOrdinals = (PEXPORTED_DATA_WORD)(PEExports->AddressOfNameOrdinals + LoadedModules[i][1]);
                                }
                                else
                                {
                                    PEExports = (PIMAGE_EXPORT_DIRECTORY)(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + LoadedModules[i][1]);
                                    ExportedFunctions = (PEXPORTED_DATA)(PEExports->AddressOfFunctions + LoadedModules[i][1]);
                                    ExportedFunctionNames = (PEXPORTED_DATA)(PEExports->AddressOfNames + LoadedModules[i][1]);
                                    ExportedFunctionOrdinals = (PEXPORTED_DATA_WORD)(PEExports->AddressOfNameOrdinals + LoadedModules[i][1]);
                                }
                                if(ReturnType == UE_OPTION_IMPORTER_RETURN_APINAME || ReturnType == UE_OPTION_IMPORTER_RETURN_DLLNAME || ReturnType == UE_OPTION_IMPORTER_RETURN_DLLINDEX || ReturnType == UE_OPTION_IMPORTER_RETURN_API_ORDINAL_NUMBER)
                                {
                                    for(j = 0; j < PEExports->NumberOfFunctions; j++)  //NumberOfNames
                                    {
                                        if(ExportedFunctions->ExportedItem + LoadedModules[i][0] == APIAddress)
                                        {
                                            GetModuleBaseNameA(hProcess, (HMODULE)LoadedModules[i][0], (LPSTR)engineFoundDLLName, 512);
                                            RtlZeroMemory(&engineFoundAPIName, sizeof(engineFoundAPIName));
                                            x = j;
                                            FoundOrdinalNumber = (unsigned int)PEExports->Base;
                                            for(j = 0; j < PEExports->NumberOfNames; j++)
                                            {
                                                if(ExportedFunctionOrdinals->OrdinalNumber != x)
                                                {
                                                    ExportedFunctionOrdinals = (PEXPORTED_DATA_WORD)((ULONG_PTR)ExportedFunctionOrdinals + 2);
                                                }
                                                else
                                                {
                                                    FoundOrdinalNumber = FoundOrdinalNumber + (unsigned int)ExportedFunctionOrdinals->OrdinalNumber;
                                                    break;
                                                }
                                            }
                                            ExportedFunctionNames = (PEXPORTED_DATA)((ULONG_PTR)ExportedFunctionNames + j * 4);
                                            if(EngineIsPointedMemoryString((ULONG_PTR)(ExportedFunctionNames->ExportedItem + LoadedModules[i][1])))
                                            {
                                                lstrcpyA((LPSTR)engineFoundAPIName, (LPCSTR)(ExportedFunctionNames->ExportedItem + LoadedModules[i][1]));
                                            }
                                            APINameFound = true;
                                            FoundIndex = i;
                                            break;
                                        }
                                        ExportedFunctions = (PEXPORTED_DATA)((ULONG_PTR)ExportedFunctions + 4);
                                    }
                                }
                                else if(ReturnType == UE_OPTION_IMPORTER_RETURN_APIADDRESS)
                                {
                                    for(j = 0; j < PEExports->NumberOfFunctions; j++)  //NumberOfNames
                                    {
                                        if(lstrcmpiA((LPCSTR)szAPIName, (LPCSTR)(ExportedFunctionNames->ExportedItem + LoadedModules[i][1])) == NULL)
                                        {
                                            ExportedFunctionOrdinals = (PEXPORTED_DATA_WORD)((ULONG_PTR)ExportedFunctionOrdinals + j * 2);
                                            ExportedFunctions = (PEXPORTED_DATA)((ULONG_PTR)ExportedFunctions + (ExportedFunctionOrdinals->OrdinalNumber) * 4);
                                            GetModuleBaseNameA(hProcess, (HMODULE)LoadedModules[i][0], (LPSTR)engineFoundDLLName, 512);
                                            RtlZeroMemory(&engineFoundAPIName, sizeof(engineFoundAPIName));
                                            ExportedFunctions = (PEXPORTED_DATA)((ULONG_PTR)ExportedFunctions + (j + PEExports->Base) * 4);
                                            APIFoundAddress = ExportedFunctions->ExportedItem + LoadedModules[i][0];
                                            APINameFound = true;
                                            FoundIndex = i;
                                            break;
                                        }
                                        ExportedFunctionNames = (PEXPORTED_DATA)((ULONG_PTR)ExportedFunctionNames + 4);
                                    }
                                }
                            }
                            __except(EXCEPTION_EXECUTE_HANDLER)
                            {
                                RtlZeroMemory(&engineFoundAPIName, sizeof(engineFoundAPIName));
                                APINameFound = false;
                            }
                        }
                    }
                }
            }
            i++;
        }

        if(ReturnType == UE_OPTION_IMPORTER_RETURN_FORWARDER_DLLNAME || ReturnType == UE_OPTION_IMPORTER_RETURN_FORWARDER_APINAME || ReturnType == UE_OPTION_IMPORTER_RETURN_FORWARDER_DLLINDEX || ReturnType == UE_OPTION_IMPORTER_RETURN_FORWARDER_API_ORDINAL_NUMBER)
        {
            RealignedAPIAddress = (ULONG_PTR)EngineGlobalAPIHandler(hProcess, NULL, APIAddress, NULL, UE_OPTION_IMPORTER_REALIGN_APIADDRESS);
            if(z <= 1)
            {
                z = 2;
            }
            for(i = y; i >= z; i--)
            {
                FileMapVA = LoadedModules[i][1];
                if(FileMapVA != NULL)
                {
                    DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
                    RtlZeroMemory(&RemoteModuleInfo, sizeof MODULEINFO);
                    //GetModuleInformation(GetCurrentProcess(), (HMODULE)LoadedModules[i][1], &RemoteModuleInfo, sizeof MODULEINFO);
                    GetModuleInformation(hProcess, (HMODULE)LoadedModules[i][0], &RemoteModuleInfo, sizeof MODULEINFO);
                    if(ValidateHeader || EngineValidateHeader((ULONG_PTR)LoadedModules[i][1], GetCurrentProcess(), RemoteModuleInfo.lpBaseOfDll, DOSHeader, false))
                    {
                        __try
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
                                SkipModule = true;
                            }
                            if(!SkipModule)
                            {
                                if(!FileIs64)
                                {
                                    PEExports = (PIMAGE_EXPORT_DIRECTORY)(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + LoadedModules[i][1]);
                                    ExportedFunctionNames = (PEXPORTED_DATA)(PEExports->AddressOfNames + LoadedModules[i][1]);
                                    ExportedFunctions = (PEXPORTED_DATA)(PEExports->AddressOfFunctions + LoadedModules[i][1]);
                                    ExportedFunctionOrdinals = (PEXPORTED_DATA_WORD)(PEExports->AddressOfNameOrdinals + LoadedModules[i][1]);
                                }
                                else
                                {
                                    PEExports = (PIMAGE_EXPORT_DIRECTORY)(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + LoadedModules[i][1]);
                                    ExportedFunctionNames = (PEXPORTED_DATA)(PEExports->AddressOfNames + LoadedModules[i][1]);
                                    ExportedFunctions = (PEXPORTED_DATA)(PEExports->AddressOfFunctions + LoadedModules[i][1]);
                                    ExportedFunctionOrdinals = (PEXPORTED_DATA_WORD)(PEExports->AddressOfNameOrdinals + LoadedModules[i][1]);
                                }
                                for(j = 0; j < PEExports->NumberOfFunctions; j++)
                                {
                                    if(EngineIsPointedMemoryString((ULONG_PTR)ExportedFunctions->ExportedItem + LoadedModules[i][1]))
                                    {
                                        RtlZeroMemory(&szFwdAPIName, 512);
                                        RtlZeroMemory(&szFwdDLLName, 512);
                                        if(EngineExtractForwarderData((ULONG_PTR)ExportedFunctions->ExportedItem + LoadedModules[i][1], &szFwdDLLName, &szFwdAPIName))
                                        {
                                            if((ULONG_PTR)GetProcAddress(GetModuleHandleA(szFwdDLLName), szFwdAPIName) == RealignedAPIAddress)
                                            {
                                                GetModuleBaseNameA(hProcess, (HMODULE)LoadedModules[i][0], (LPSTR)engineFoundDLLName, 512);
                                                RtlZeroMemory(&engineFoundAPIName, 512);
                                                x = j;
                                                FoundOrdinalNumber = (unsigned int)PEExports->Base;
                                                for(j = 0; j < PEExports->NumberOfNames; j++)
                                                {
                                                    if(ExportedFunctionOrdinals->OrdinalNumber != x)
                                                    {
                                                        ExportedFunctionOrdinals = (PEXPORTED_DATA_WORD)((ULONG_PTR)ExportedFunctionOrdinals + 2);
                                                    }
                                                    else
                                                    {
                                                        FoundOrdinalNumber = FoundOrdinalNumber + (unsigned int)ExportedFunctionOrdinals->OrdinalNumber;
                                                        break;
                                                    }
                                                }
                                                ExportedFunctionNames = (PEXPORTED_DATA)((ULONG_PTR)ExportedFunctionNames + j * 4);
                                                if(EngineIsPointedMemoryString((ULONG_PTR)(ExportedFunctionNames->ExportedItem + LoadedModules[i][1])))
                                                {
                                                    lstrcpyA((LPSTR)engineFoundAPIName, (LPCSTR)(ExportedFunctionNames->ExportedItem + LoadedModules[i][1]));
                                                }
                                                APINameFound = true;
                                                FoundIndex = i;
                                                break;
                                            }
                                        }
                                    }
                                    ExportedFunctions = (PEXPORTED_DATA)((ULONG_PTR)ExportedFunctions + 4);
                                }
                            }
                        }
                        __except(EXCEPTION_EXECUTE_HANDLER)
                        {
                            RtlZeroMemory(&szFwdAPIName, 512);
                            RtlZeroMemory(&szFwdDLLName, 512);
                            APINameFound = false;
                        }
                    }
                }
                if(APINameFound)
                {
                    break;
                }
            }
        }
        i = 1;
        while(EnumeratedModules[i] != NULL)
        {
            if(engineAlowModuleLoading)
            {
                if(LoadedModules[i][2] == 1)
                {
                    FreeLibrary((HMODULE)LoadedModules[i][1]);
                }
            }
            else
            {
                if(LoadedModules[i][2] == 1)
                {
                    VirtualFree((void*)LoadedModules[i][1], NULL, MEM_RELEASE);
                }
            }
            i++;
        }
        if(APINameFound)
        {
            //
            // Vista/w7 x64 fix
            //
            if(lstrcmpiA(engineFoundAPIName, "NtdllDefWindowProc_A") == NULL)
            {
                lstrcpyA(engineFoundAPIName, "DefWindowProcA");
                lstrcpyA(engineFoundDLLName, "user32.dll");
                FoundIndex = Vista64UserForwarderFix;
            }
            else if(lstrcmpiA(engineFoundAPIName, "NtdllDefWindowProc_W") == NULL)
            {
                lstrcpyA(engineFoundAPIName, "DefWindowProcW");
                lstrcpyA(engineFoundDLLName, "user32.dll");
                FoundIndex = Vista64UserForwarderFix;
            }
            else if(lstrcmpiA(engineFoundAPIName, "NtdllDialogWndProc_A") == NULL)
            {
                lstrcpyA(engineFoundAPIName, "DefDlgProcA");
                lstrcpyA(engineFoundDLLName, "user32.dll");
                FoundIndex = Vista64UserForwarderFix;
            }
            else if(lstrcmpiA(engineFoundAPIName, "NtdllDialogWndProc_W") == NULL)
            {
                lstrcpyA(engineFoundAPIName, "DefDlgProcW");
                lstrcpyA(engineFoundDLLName, "user32.dll");
                FoundIndex = Vista64UserForwarderFix;
            }
            if(ReturnType == UE_OPTION_IMPORTER_RETURN_APINAME || ReturnType == UE_OPTION_IMPORTER_RETURN_FORWARDER_APINAME)
            {
                if(ReturnType == UE_OPTION_IMPORTER_RETURN_APINAME && engineCheckForwarders == true)
                {
                    if(engineAlowModuleLoading == true || (engineAlowModuleLoading == false && LoadedModules[FoundIndex][2] != 1))
                    {
                        if(lstrcmpiA(engineFoundDLLName, "ntdll.dll") == NULL)
                        {
                            ForwarderData = (ULONG_PTR)EngineGlobalAPIHandler(handleProcess, EnumedModulesBases, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_FORWARDER_APINAME);
                        }
                        else
                        {
                            ForwarderData = NULL;
                        }
                        if(ForwarderData != NULL)
                        {
                            return(ForwarderData);
                        }
                        else
                        {
                            if(engineFoundAPIName[0] != 0x00)
                            {
                                return((ULONG_PTR)engineFoundAPIName);
                            }
                            else
                            {
                                return(NULL);
                            }
                        }
                    }
                    else
                    {
                        if(engineFoundAPIName[0] != 0x00)
                        {
                            return((ULONG_PTR)engineFoundAPIName);
                        }
                        else
                        {
                            return(NULL);
                        }
                    }
                }
                else
                {
                    if(engineFoundAPIName[0] != 0x00)
                    {
                        return((ULONG_PTR)engineFoundAPIName);
                    }
                    else
                    {
                        return(NULL);
                    }
                }
            }
            else if(ReturnType == UE_OPTION_IMPORTER_RETURN_APIADDRESS)
            {
                return(APIFoundAddress);
            }
            else if(ReturnType == UE_OPTION_IMPORTER_RETURN_API_ORDINAL_NUMBER || ReturnType == UE_OPTION_IMPORTER_RETURN_FORWARDER_API_ORDINAL_NUMBER)
            {
                return((ULONG_PTR)FoundOrdinalNumber);
            }
            else if(ReturnType == UE_OPTION_IMPORTER_RETURN_DLLNAME || ReturnType == UE_OPTION_IMPORTER_RETURN_FORWARDER_DLLNAME)
            {
                if(ReturnType == UE_OPTION_IMPORTER_RETURN_DLLNAME && engineCheckForwarders == true)
                {
                    if(engineAlowModuleLoading == true || (engineAlowModuleLoading == false && LoadedModules[FoundIndex][2] != 1))
                    {
                        if(lstrcmpiA(engineFoundDLLName, "ntdll.dll") == NULL)
                        {
                            ForwarderData = (ULONG_PTR)EngineGlobalAPIHandler(handleProcess, EnumedModulesBases, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_FORWARDER_DLLNAME);
                        }
                        else
                        {
                            ForwarderData = NULL;
                        }
                        if(ForwarderData != NULL)
                        {
                            return(ForwarderData);
                        }
                        else
                        {
                            if(engineFoundDLLName[0] != 0x00)
                            {
                                return((ULONG_PTR)engineFoundDLLName);
                            }
                            else
                            {
                                return(NULL);
                            }
                        }
                    }
                    else
                    {
                        if(engineFoundDLLName[0] != 0x00)
                        {
                            return((ULONG_PTR)engineFoundDLLName);
                        }
                        else
                        {
                            return(NULL);
                        }
                    }
                }
                else
                {
                    if(engineFoundDLLName[0] != 0x00)
                    {
                        return((ULONG_PTR)engineFoundDLLName);
                    }
                    else
                    {
                        return(NULL);
                    }
                }
            }
            else if(ReturnType == UE_OPTION_IMPORTER_RETURN_DLLINDEX || ReturnType == UE_OPTION_IMPORTER_RETURN_FORWARDER_DLLINDEX)
            {
                if(ReturnType == UE_OPTION_IMPORTER_RETURN_DLLINDEX && engineCheckForwarders == true)
                {
                    if(engineAlowModuleLoading == true || (engineAlowModuleLoading == false && LoadedModules[FoundIndex][2] != 1))
                    {
                        if(lstrcmpiA(engineFoundDLLName, "ntdll.dll") == NULL)
                        {
                            ForwarderData = (ULONG_PTR)EngineGlobalAPIHandler(handleProcess, EnumedModulesBases, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_FORWARDER_DLLINDEX);
                        }
                        else
                        {
                            ForwarderData = NULL;
                        }
                        if(ForwarderData != NULL)
                        {
                            return(ForwarderData);
                        }
                        else
                        {
                            return(FoundIndex);
                        }
                    }
                    else
                    {
                        return(FoundIndex);
                    }
                }
                else
                {
                    return(FoundIndex);
                }
            }
            else if(ReturnType == UE_OPTION_IMPORTER_RETURN_DLLBASE)
            {
                return(APIFoundAddress);
            }
            else if(ReturnType == UE_OPTION_IMPORTER_RETURN_NEAREST_APIADDRESS)
            {
                return(APIFoundAddress);
            }
            else if(ReturnType == UE_OPTION_IMPORTER_RETURN_NEAREST_APINAME)
            {
                if(engineCheckForwarders)
                {
                    if(engineAlowModuleLoading == true || (engineAlowModuleLoading == false && LoadedModules[FoundIndex][2] != 1))
                    {
                        if(lstrcmpiA(engineFoundDLLName, "ntdll.dll") == NULL)
                        {
                            ForwarderData = (ULONG_PTR)EngineGlobalAPIHandler(handleProcess, EnumedModulesBases, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_FORWARDER_APINAME);
                        }
                        else
                        {
                            ForwarderData = NULL;
                        }
                        if(ForwarderData != NULL)
                        {
                            return(ForwarderData);
                        }
                        else
                        {
                            if(engineFoundAPIName[0] != 0x00)
                            {
                                return((ULONG_PTR)engineFoundAPIName);
                            }
                            else
                            {
                                return(NULL);
                            }
                        }
                    }
                    else
                    {
                        if(engineFoundAPIName[0] != 0x00)
                        {
                            return((ULONG_PTR)engineFoundAPIName);
                        }
                        else
                        {
                            return(NULL);
                        }
                    }
                }
                else
                {
                    if(engineFoundAPIName[0] != 0x00)
                    {
                        return((ULONG_PTR)engineFoundAPIName);
                    }
                    else
                    {
                        return(NULL);
                    }
                }
            }
            else
            {
                return(APIFoundAddress);
            }
        }
        else
        {
            if(ReturnType == UE_OPTION_IMPORTER_RETURN_API_ORDINAL_NUMBER || ReturnType == UE_OPTION_IMPORTER_RETURN_FORWARDER_API_ORDINAL_NUMBER)
            {
                return((ULONG_PTR)-1);
            }
            else
            {
                return(NULL);
            }
        }
    }
    else
    {
        return(NULL);
    }
    return(NULL);
}