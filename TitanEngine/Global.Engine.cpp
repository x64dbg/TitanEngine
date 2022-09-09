#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.h"
#include "Global.Handle.h"
#include "Global.Mapping.h"
#include "Global.Engine.Extension.h"
#include "Global.Engine.Hash.h"
#include "Global.Debugger.h"

bool engineCheckForwarders = true;
bool engineAlowModuleLoading = false;
bool engineCreatePathForFiles = true; // hardcoded
bool engineBackupForCriticalFunctions = true;
bool engineResumeProcessIfNoThreadIsActive = false;
bool engineResetCustomHandler = true;
bool engineRemoveConsoleForDebugee = false;
bool enginePassAllExceptions = true;
bool engineExecutePluginCallBack = true;
bool engineAutoHideFromDebugger = false; // hardcoded
bool engineEnableDebugPrivilege = false;
bool engineSafeAttach = false;
bool engineMembpAlt = false;
bool engineDisableAslr = false;
bool engineSafeStep = true;

char engineFoundDLLName[512] = {0};
char engineFoundAPIName[512] = {0};
wchar_t engineExtractedFileNameW[512] = {0};
wchar_t engineSzEngineFile[MAX_PATH] = {0};
wchar_t engineSzEngineFolder[MAX_PATH] = {0};
HMODULE engineHandle;
LPVOID engineExitThreadOneShootCallBack = NULL;
LPVOID engineDependencyFiles;
LPVOID engineDependencyFilesCWP;
void* EngineStartUnpackingCallBack;

// Global.Engine.functions:
void EngineInit()
{
    int i;
    if(GetModuleFileNameW(engineHandle, engineSzEngineFile, _countof(engineSzEngineFile)) > NULL)
    {
        lstrcpyW(engineSzEngineFolder, engineSzEngineFile);
        i = lstrlenW(engineSzEngineFolder);
        while(engineSzEngineFolder[i] != L'\\' && i)
            i--;
        if(i)
        {
            engineSzEngineFolder[i] = L'\0';
            lstrcpyW(engineSzEngineGarbageFolder, engineSzEngineFolder);
            lstrcatW(engineSzEngineGarbageFolder, L"\\garbage\\");
            CreateDirectoryW(engineSzEngineGarbageFolder, 0);
        }
        EngineInitPlugins(engineSzEngineFolder);
    }
    HashInit();
}

bool EngineIsThereFreeHardwareBreakSlot(LPDWORD FreeRegister)
{
    if(DebugRegister[0].DrxEnabled == false)
    {
        if(FreeRegister != NULL)
        {
            *FreeRegister = UE_DR0;
        }
        return true;
    }
    else if(DebugRegister[1].DrxEnabled == false)
    {
        if(FreeRegister != NULL)
        {
            *FreeRegister = UE_DR1;
        }
        return true;
    }
    else if(DebugRegister[2].DrxEnabled == false)
    {
        if(FreeRegister != NULL)
        {
            *FreeRegister = UE_DR2;
        }
        return true;
    }
    else if(DebugRegister[3].DrxEnabled == false)
    {
        if(FreeRegister != NULL)
        {
            *FreeRegister = UE_DR3;
        }
        return true;
    }
    return false;
}

bool EngineFileExists(char* szFileName)
{

    HANDLE hFile = CreateFileA(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if(hFile != INVALID_HANDLE_VALUE)
    {
        EngineCloseHandle(hFile);
        return true;
    }
    else
    {
        return false;
    }
}

void EngineCreatePathForFile(char* szFileName)
{
    int len = lstrlenA(szFileName);
    while(szFileName[len] != '\\' && len)
        len--;
    char szFolderName[MAX_PATH] = "";
    lstrcpyA(szFolderName, szFileName);
    if(len)
        szFolderName[len + 1] = '\0';
    else //just a filename
        return;
    lstrcatA(szFolderName, "\\");
    len = lstrlenA(szFolderName);
    char szCreateFolder[MAX_PATH] = "";
    for(int i = 3; i < len; i++)
    {
        if(szFolderName[i] == '\\')
        {
            lstrcpyA(szCreateFolder, szFolderName);
            szCreateFolder[i] = '\0';
            CreateDirectoryA(szCreateFolder, 0);
        }
    }
}

void EngineCreatePathForFileW(wchar_t* szFileName)
{
    int len = lstrlenW(szFileName);
    while(szFileName[len] != L'\\' && len)
        len--;
    wchar_t szFolderName[MAX_PATH] = L"";
    lstrcpyW(szFolderName, szFileName);
    if(len)
        szFolderName[len + 1] = L'\0';
    else //just a filename
        return;
    len = lstrlenW(szFolderName);
    wchar_t szCreateFolder[MAX_PATH] = L"";
    for(int i = 3; i < len; i++)
    {
        if(szFolderName[i] == '\\')
        {
            lstrcpyW(szCreateFolder, szFolderName);
            szCreateFolder[i] = '\0';
            CreateDirectoryW(szCreateFolder, 0);
        }
    }
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
        int len = lstrlenW(szFileName);
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

            if(TestChar < ' ' || TestChar > '~') //is inside the lower-ascii range
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
            return true;
        }
    }
    return false;
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
        return true;
    }
    return false;
}

ULONG_PTR EngineEstimateNewSectionRVA(ULONG_PTR FileMapVA)
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
            PESections = IMAGE_FIRST_SECTION(PEHeader32);
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
            PESections = IMAGE_FIRST_SECTION(PEHeader64);
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
            return false;
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
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
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
            EngineCreatePathForFileW(szExtractedFileName);
            hFile = CreateFileW(szExtractedFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if(hFile != INVALID_HANDLE_VALUE)
            {
                if(WriteFile(hFile, ResourceData, ResourceSize, &NumberOfBytesWritten, NULL))
                {
                    EngineCloseHandle(hFile);
                    return true;
                }
                EngineCloseHandle(hFile);
            }
        }
    }
    return false;
}

bool EngineIsDependencyPresent(char* szFileName, char* szDependencyForFile, char* szPresentInFolder)
{
    int i, j;
    HANDLE hFile;
    char szTryFileName[512] = {0};

    if(szPresentInFolder != NULL && szFileName != NULL)
    {
        lstrcpyA(szTryFileName, szPresentInFolder);
        if(szTryFileName[lstrlenA(szTryFileName) - 1] != 0x5C)
        {
            szTryFileName[lstrlenA(szTryFileName)] = 0x5C;
        }
        lstrcatA(szTryFileName, szFileName);
        hFile = CreateFileA(szTryFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if(hFile != INVALID_HANDLE_VALUE)
        {
            EngineCloseHandle(hFile);
            return true;
        }
    }

    if(szFileName != NULL)
    {
        hFile = CreateFileA(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if(hFile != INVALID_HANDLE_VALUE)
        {
            EngineCloseHandle(hFile);
            return true;
        }
        if(GetSystemDirectoryA(szTryFileName, 512) > NULL)
        {
            lstrcatA(szTryFileName, "\\");
            lstrcatA(szTryFileName, szFileName);
            hFile = CreateFileA(szTryFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if(hFile != INVALID_HANDLE_VALUE)
            {
                EngineCloseHandle(hFile);
                return true;
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
                return true;
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
                return true;
            }
        }
    }
    return false;
}

bool EngineIsDependencyPresentW(wchar_t* szFileName, wchar_t* szDependencyForFile, wchar_t* szPresentInFolder)
{

    int i, j;
    HANDLE hFile;
    wchar_t szTryFileName[512] = {0};

    if(szPresentInFolder != NULL)
    {
        lstrcpyW(szTryFileName, szPresentInFolder);
        if(szTryFileName[lstrlenW(szTryFileName) - 1] != 0x5C)
        {
            szTryFileName[lstrlenW(szTryFileName)] = 0x5C;
        }
        lstrcatW(szTryFileName, szFileName);
        hFile = CreateFileW(szTryFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if(hFile != INVALID_HANDLE_VALUE)
        {
            EngineCloseHandle(hFile);
            return true;
        }
    }
    if(szFileName != NULL)
    {
        hFile = CreateFileW(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if(hFile != INVALID_HANDLE_VALUE)
        {
            EngineCloseHandle(hFile);
            return true;
        }
        if(GetSystemDirectoryW(szTryFileName, 512) > NULL)
        {
            lstrcatW(szTryFileName, L"\\");
            lstrcatW(szTryFileName, szFileName);
            hFile = CreateFileW(szTryFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if(hFile != INVALID_HANDLE_VALUE)
            {
                EngineCloseHandle(hFile);
                return true;
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
                return true;
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
                return true;
            }
        }
    }
    return false;
}

bool EngineGetDependencyLocation(char* szFileName, char* szDependencyForFile, void* szLocationOfTheFile, int MaxStringSize)
{
    wchar_t uniFileName[MAX_PATH] = {0};
    wchar_t uniDependencyForFile[MAX_PATH] = {0};
    wchar_t* uniLocationOfTheFile = (WCHAR*)malloc(sizeof(WCHAR) * MaxStringSize);

    MultiByteToWideChar(CP_ACP, NULL, szFileName, -1, uniFileName, _countof(uniFileName));
    MultiByteToWideChar(CP_ACP, NULL, szDependencyForFile, -1, uniDependencyForFile, _countof(uniDependencyForFile));
    if(EngineGetDependencyLocationW(uniFileName, uniDependencyForFile, uniLocationOfTheFile, MaxStringSize))
    {
        bool retVal = (WideCharToMultiByte(CP_ACP, NULL, uniLocationOfTheFile, -1, (char*)szLocationOfTheFile, MaxStringSize, NULL, NULL) != 0);
        free(uniLocationOfTheFile);
        return retVal;
    }

    return false;
}

bool EngineGetDependencyLocationW(wchar_t* szFileName, wchar_t* szDependencyForFile, void* szLocationOfTheFile, int MaxStringSize)
{

    int i, j;
    HANDLE hFile;
    wchar_t szTryFileName[512] = {0};

    if(szFileName != NULL)
    {
        RtlZeroMemory(szLocationOfTheFile, MaxStringSize * sizeof(WCHAR));

        hFile = CreateFileW(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if(hFile != INVALID_HANDLE_VALUE)
        {
            if((int)wcslen(szFileName) <= MaxStringSize)
            {
                RtlCopyMemory(szLocationOfTheFile, szFileName, wcslen(szFileName) * sizeof(WCHAR));
            }
            EngineCloseHandle(hFile);
            return true;
        }
        if(GetSystemDirectoryW(szTryFileName, _countof(szTryFileName)) > NULL)
        {
            wcscat(szTryFileName, L"\\");
            wcscat(szTryFileName, szFileName);
            hFile = CreateFileW(szTryFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if(hFile != INVALID_HANDLE_VALUE)
            {
                if((int)wcslen(szTryFileName) <= MaxStringSize)
                {
                    RtlCopyMemory(szLocationOfTheFile, &szTryFileName, wcslen(szTryFileName) * sizeof(WCHAR));
                }
                EngineCloseHandle(hFile);
                return true;
            }
        }
        if(GetWindowsDirectoryW(szTryFileName, _countof(szTryFileName)) > NULL)
        {
            wcscat(szTryFileName, L"\\");
            wcscat(szTryFileName, szFileName);
            hFile = CreateFileW(szTryFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if(hFile != INVALID_HANDLE_VALUE)
            {
                if((int)wcslen(szTryFileName) <= MaxStringSize)
                {
                    RtlCopyMemory(szLocationOfTheFile, &szTryFileName, wcslen(szTryFileName) * sizeof(WCHAR));
                }
                EngineCloseHandle(hFile);
                return true;
            }
        }
        if(szDependencyForFile != NULL)
        {
            RtlZeroMemory(szTryFileName, sizeof(szTryFileName));
            i = (int)wcslen(szDependencyForFile);
            while(i > 0 && szDependencyForFile[i] != L'\\')
            {
                i--;
            }
            for(j = 0; j <= i; j++)
            {
                szTryFileName[j] = szDependencyForFile[j];
            }
            wcscat(szTryFileName, szFileName);
            hFile = CreateFileW(szTryFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if(hFile != INVALID_HANDLE_VALUE)
            {
                if((int)wcslen(szTryFileName) <= MaxStringSize)
                {
                    RtlCopyMemory(szLocationOfTheFile, &szTryFileName, wcslen(szTryFileName) * sizeof(WCHAR));
                }
                EngineCloseHandle(hFile);
                return true;
            }
        }
    }
    return false;
}

long EngineHashString(char* szStringToHash)
{

    int i = NULL;
    DWORD HashValue = NULL;

    if(szStringToHash != NULL)
    {
        const int strl = lstrlenA(szStringToHash);
        for(i = 0; i < strl; i++)
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

bool EngineIsValidReadPtrEx(LPVOID DataPointer, DWORD DataSize)
{

    MEMORY_BASIC_INFORMATION MemInfo = {0};

    while(DataSize > NULL)
    {
        VirtualQuery(DataPointer, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
        if(MemInfo.AllocationProtect == MEM_FREE || MemInfo.AllocationProtect == MEM_PRIVATE)
        {
            return false;
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
    return true;
}

bool EngineValidateResource(HMODULE hModule, LPCTSTR lpszType, LPTSTR lpszName, LONG_PTR lParam)
{
    HRSRC hResource;
    HGLOBAL hResourceGlobal;
    DWORD ResourceSize;
    LPVOID ResourceData;
    BYTE ReturnData = UE_FIELD_FIXABLE_CRITICAL;

    hResource = FindResourceA(hModule, (LPCSTR)lpszName, (LPCSTR)lpszType);
    if(hResource != NULL) //FindResourceA didn't fail
    {
        hResourceGlobal = LoadResource(hModule, hResource);
        if(hResourceGlobal != NULL) //LoadResource didn't fail
        {
            ResourceSize = SizeofResource(hModule, hResource);
            ResourceData = LockResource(hResourceGlobal);
            if(ResourceData != NULL) //LockResource didn't fail
            {
                if(EngineIsValidReadPtrEx(ResourceData, ResourceSize)) //ResourceData is a valid read pointer
                {
                    return true;
                }
            }
        }
    }
    *((LONG*)lParam) = ReturnData;
    return false;
}

bool EngineValidateHeader(ULONG_PTR FileMapVA, HANDLE hFileProc, LPVOID ImageBase, PIMAGE_DOS_HEADER DOSHeader, bool IsFile)
{
    MODULEINFO ModuleInfo;
    DWORD PESize, MaxPESize;
    PIMAGE_NT_HEADERS PEHeader;
    IMAGE_NT_HEADERS RemotePEHeader;
    ULONG_PTR NumberOfBytesRW = NULL;

    if(IsFile)
    {
        if(hFileProc == NULL)
        {
            PESize = 0;
            MaxPESize = ULONG_MAX;
        }
        else
        {
            PESize = GetFileSize(hFileProc, NULL);
            MaxPESize = PESize;
        }
        __try
        {
            if(DOSHeader->e_magic == IMAGE_DOS_SIGNATURE)
            {
                DWORD LfaNew = DOSHeader->e_lfanew;
                if((PESize == 0 || (LfaNew < PESize && LfaNew + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) < PESize)) &&
                        MaxPESize != 0 &&
                        LfaNew < (MaxPESize - sizeof(IMAGE_NT_SIGNATURE) - sizeof(IMAGE_FILE_HEADER)))
                {
                    PEHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)DOSHeader + LfaNew);
                    return PEHeader->Signature == IMAGE_NT_SIGNATURE;
                }
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }
    else
    {
        RtlZeroMemory(&ModuleInfo, sizeof MODULEINFO);
        GetModuleInformation(hFileProc, (HMODULE)ImageBase, &ModuleInfo, sizeof(MODULEINFO));
        PESize = ModuleInfo.SizeOfImage;
        __try
        {
            if(DOSHeader->e_magic == IMAGE_DOS_SIGNATURE)
            {
                DWORD LfaNew = DOSHeader->e_lfanew;
                if((LfaNew < PESize && LfaNew + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) < PESize) &&
                        LfaNew < (PESize - sizeof(IMAGE_NT_SIGNATURE) - sizeof(IMAGE_FILE_HEADER)))
                {
                    if(ReadProcessMemory(hFileProc, (LPVOID)((ULONG_PTR)ImageBase + LfaNew), &RemotePEHeader, sizeof(IMAGE_NT_HEADERS), &NumberOfBytesRW))
                    {
                        PEHeader = (PIMAGE_NT_HEADERS)&RemotePEHeader;
                        return PEHeader->Signature == IMAGE_NT_SIGNATURE;
                    }
                }
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }
    return false;
}

ULONG_PTR EngineSimulateNtLoaderW(wchar_t* szFileName)
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
                    PESections = IMAGE_FIRST_SECTION(PEHeader32);
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
                    PESections = IMAGE_FIRST_SECTION(PEHeader64);
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

ULONG_PTR EngineSimulateNtLoader(char* szFileName)
{
    wchar_t uniFileName[MAX_PATH] = {0};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, -1, uniFileName, _countof(uniFileName));
        return(EngineSimulateNtLoaderW(uniFileName));
    }
    else
    {
        return(NULL);
    }
}

ULONG_PTR EngineSimulateDllLoader(HANDLE hProcess, char* szFileName)
{
    WCHAR uniFileName[MAX_PATH] = {0};

    if(hProcess && szFileName)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, -1, uniFileName, _countof(uniFileName));
        return EngineSimulateDllLoaderW(hProcess, uniFileName);
    }

    return 0;
}

ULONG_PTR EngineSimulateDllLoaderW(HANDLE hProcess, wchar_t* szFileName)
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
    WCHAR szFileRemoteProc[1024] = {0};
    WCHAR szDLLFileLocation[512] = {0};
    WCHAR* szTranslatedProcName = 0;

    GetProcessImageFileNameW(hProcess, szFileRemoteProc, _countof(szFileRemoteProc));

    szTranslatedProcName = (WCHAR*)TranslateNativeNameW(szFileRemoteProc);
    if(EngineIsDependencyPresentW(szFileName, NULL, NULL))
    {
        if(EngineGetDependencyLocationW(szFileName, szTranslatedProcName, &szDLLFileLocation, _countof(szDLLFileLocation)))
        {
            VirtualFree((void*)szTranslatedProcName, NULL, MEM_RELEASE);
            if(MapFileExW(szDLLFileLocation, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
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
                                    if((DOSHeader->e_lfanew + PEHeaderSize) % 0x1000 != 0) //SectionAlignment, the default value is the page size for the system.
                                    {
                                        ExportDelta = (((DOSHeader->e_lfanew + PEHeaderSize) / 0x1000) + 1) * 0x1000;
                                    }
                                    else
                                    {
                                        ExportDelta = (DOSHeader->e_lfanew + PEHeaderSize); //multiple of 0x1000
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
                                    if((DOSHeader->e_lfanew + PEHeaderSize) % 0x1000 != 0) //SectionAlignment, the default value is the page size for the system.
                                    {
                                        ExportDelta = (((DOSHeader->e_lfanew + PEHeaderSize) / 0x1000) + 1) * 0x1000;
                                    }
                                    else
                                    {
                                        ExportDelta = (DOSHeader->e_lfanew + PEHeaderSize); //multiple of 0x1000
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

ULONG_PTR EngineGetProcAddress(ULONG_PTR ModuleBase, char* szAPIName)
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
    bool FileIs64 = false;

    APIFoundAddress = (ULONG_PTR)GetProcAddress((HMODULE)ModuleBase, szAPIName);

    if(APIFoundAddress == 0)
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
        return APIFoundAddress;
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
            return false;
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
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
    return false;
}

ULONG_PTR EngineGlobalAPIHandler(HANDLE handleProcess, ULONG_PTR EnumedModulesBases, ULONG_PTR APIAddress, const char* szAPIName, DWORD ReturnType)
{

    unsigned int i = 0;
    unsigned int j = 0;
    unsigned int n = 0;
    unsigned int x = 0;
    unsigned int y = 0;
    unsigned int z = 0;
    DWORD Dummy = NULL;
    HANDLE hProcess = NULL;
    ULONG_PTR EnumeratedModules[0x1000] = {0};
    ULONG_PTR LoadedModules[1000][4] = {0};
    char RemoteDLLName[MAX_PATH] = {0};
    char FullRemoteDLLName[MAX_PATH] = {0};
    char szWindowsSideBySide[MAX_PATH] = {0};
    char szWindowsSideBySideCmp[MAX_PATH] = {0};
    char szWindowsKernelBase[MAX_PATH] = {0};
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

    GetWindowsDirectoryA(szWindowsSideBySide, MAX_PATH);
    lstrcpyA(szWindowsKernelBase, szWindowsSideBySide);
    lstrcatA(szWindowsSideBySide, "\\WinSxS");
    if(EnumedModulesBases != NULL)
    {
        RtlMoveMemory(EnumeratedModules, (LPVOID)EnumedModulesBases, 0x1000);
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
    if(EnumedModulesBases != NULL || EnumProcessModules(hProcess, (HMODULE*)EnumeratedModules, sizeof(EnumeratedModules), &Dummy))
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
                return((ULONG_PTR) - 1);
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

DWORD EngineSetDebugPrivilege(HANDLE hProcess, bool bEnablePrivilege)
{
    HANDLE TokenHandle;
    NTSTATUS Status = NtOpenProcessToken(hProcess,
                                         TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                                         &TokenHandle);
    if(!NT_SUCCESS(Status))
        return RtlNtStatusToDosError(Status);

    LUID LuidPrivilege;
    LuidPrivilege.LowPart = SE_DEBUG_PRIVILEGE;
    LuidPrivilege.HighPart = 0;

    TOKEN_PRIVILEGES Privileges;
    Privileges.PrivilegeCount = 1;
    Privileges.Privileges[0].Luid = LuidPrivilege;
    Privileges.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;

    ULONG ReturnLength;
    Status = NtAdjustPrivilegesToken(TokenHandle,
                                     FALSE,
                                     &Privileges,
                                     sizeof(Privileges),
                                     nullptr,
                                     &ReturnLength);
    NtClose(TokenHandle);

    // Map the success code NOT_ALL_ASSIGNED to an appropriate error
    // since we're only trying to adjust one privilege.
    if(Status == STATUS_NOT_ALL_ASSIGNED)
        Status = STATUS_PRIVILEGE_NOT_HELD;

    return NT_SUCCESS(Status) ? ERROR_SUCCESS : RtlNtStatusToDosError(Status);
}

HANDLE EngineOpenProcess(DWORD dwDesiredAccess, bool bInheritHandle, DWORD dwProcessId)
{
    return OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}

HANDLE EngineOpenThread(DWORD dwDesiredAccess, bool bInheritHandle, DWORD dwThreadId)
{
    return OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId);
}
