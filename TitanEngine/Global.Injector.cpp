#include "stdafx.h"
#include "definitions.h"
#include "Global.Injector.h"

HANDLE engineReservedMemoryProcess = NULL;
ULONG_PTR engineReservedMemoryLeft[UE_MAX_RESERVED_MEMORY_LEFT];

long injectedRemoteLoadLibrary(LPVOID Parameter)
{
    PInjectCodeData APIData = (PInjectCodeData)Parameter;
    Parameter = (LPVOID)((ULONG_PTR)Parameter + sizeof InjectCodeData);
#if !defined(_WIN64)
    typedef ULONG_PTR(WINAPI * fLoadLibraryW)(LPCWSTR fLibraryName);
    typedef ULONG_PTR(WINAPI * fVirtualFree)(LPVOID fMemBase, SIZE_T fMemSize, DWORD fFreeType);
#else
    typedef ULONG_PTR(__fastcall * fLoadLibraryW)(LPCWSTR fLibraryName);
    typedef ULONG_PTR(__fastcall * fVirtualFree)(LPVOID fMemBase, SIZE_T fMemSize, DWORD fFreeType);
#endif
    fLoadLibraryW cLoadLibraryW = (fLoadLibraryW)(APIData->fLoadLibrary);
    fVirtualFree cVirtualFree = (fVirtualFree)(APIData->fVirtualFree);
    long retValue = NULL;

    if(cLoadLibraryW((LPCWSTR)Parameter) != NULL)
    {
        retValue++;
    }
    cVirtualFree(Parameter, NULL, MEM_RELEASE);
    return(retValue);
}

long injectedRemoteFreeLibrary(LPVOID Parameter)
{

    PInjectCodeData APIData = (PInjectCodeData)Parameter;
#if !defined(_WIN64)
    typedef ULONG_PTR(WINAPI * fFreeLibrary)(HMODULE fLibBase);
    typedef ULONG_PTR(WINAPI * fVirtualFree)(LPVOID fMemBase, SIZE_T fMemSize, DWORD fFreeType);
#else
    typedef ULONG_PTR(__fastcall * fFreeLibrary)(HMODULE fLibBase);
    typedef ULONG_PTR(__fastcall * fVirtualFree)(LPVOID fMemBase, SIZE_T fMemSize, DWORD fFreeType);
#endif
    fFreeLibrary cFreeLibrary = (fFreeLibrary)(APIData->fFreeLibrary);
    fVirtualFree cVirtualFree = (fVirtualFree)(APIData->fVirtualFree);
    long retValue = NULL;

    if(cFreeLibrary(APIData->fFreeLibraryHandle))
    {
        retValue++;
    }
    cVirtualFree(Parameter, NULL, MEM_RELEASE);
    return(retValue);
}

long injectedRemoteFreeLibrarySimple(LPVOID Parameter)
{

    PInjectCodeData APIData = (PInjectCodeData)Parameter;
    LPVOID orgParameter = Parameter;
    Parameter = (LPVOID)((ULONG_PTR)Parameter + sizeof InjectCodeData);
#if !defined(_WIN64)
    typedef ULONG_PTR(WINAPI * fFreeLibrary)(HMODULE fLibBase);
    typedef HMODULE(WINAPI * fGetModuleHandleW)(LPCWSTR fLibraryName);
    typedef ULONG_PTR(WINAPI * fVirtualFree)(LPVOID fMemBase, SIZE_T fMemSize, DWORD fFreeType);
#else
    typedef ULONG_PTR(__fastcall * fFreeLibrary)(HMODULE fLibBase);
    typedef HMODULE(__fastcall * fGetModuleHandleW)(LPCWSTR fLibraryName);
    typedef ULONG_PTR(__fastcall * fVirtualFree)(LPVOID fMemBase, SIZE_T fMemSize, DWORD fFreeType);
#endif
    fGetModuleHandleW cGetModuleHandleW = (fGetModuleHandleW)(APIData->fGetModuleHandle);
    fFreeLibrary cFreeLibrary = (fFreeLibrary)(APIData->fFreeLibrary);
    fVirtualFree cVirtualFree = (fVirtualFree)(APIData->fVirtualFree);
    long retValue = NULL;
    HMODULE hModule;

    hModule = cGetModuleHandleW((LPCWSTR)Parameter);
    if(hModule != NULL)
    {
        if(cFreeLibrary(hModule))
        {
            retValue++;
        }
    }
    else
    {
        retValue++;
    }
    cVirtualFree(orgParameter, NULL, MEM_RELEASE);
    return(retValue);
}

long injectedExitProcess(LPVOID Parameter)
{

    PInjectCodeData APIData = (PInjectCodeData)Parameter;
#if !defined(_WIN64)
    typedef ULONG_PTR(WINAPI * fExitProcess)(DWORD fExitCode);
#else
    typedef ULONG_PTR(__fastcall * fExitProcess)(DWORD fExitCode);
#endif
    fExitProcess cExitProcess = (fExitProcess)(APIData->fExitProcess);
    long retValue = NULL;

    cExitProcess(APIData->fExitProcessCode);
    return(NULL);
}

void injectedTerminator()
{

    int i;

    for(i = 0; i < UE_MAX_RESERVED_MEMORY_LEFT; i++)
    {
        if(engineReservedMemoryLeft[i] != NULL)
        {
            VirtualFreeEx(engineReservedMemoryProcess, (LPVOID)engineReservedMemoryLeft[i], NULL, MEM_RELEASE);
            engineReservedMemoryLeft[i] = NULL;
        }
    }
}

// Global.Injector.functions: {DO NOT REORDER! USE ONLY IN RELEASE MODE!}
long injectedImpRec(LPVOID Parameter)
{
    HANDLE hFile;
    HANDLE hFileMap;
    PInjectImpRecCodeData APIData = (PInjectImpRecCodeData)Parameter;
    LPVOID szFileName = (LPVOID)((ULONG_PTR)Parameter + sizeof InjectImpRecCodeData);
    typedef ULONG_PTR(__cdecl * fTrace)(DWORD hFileMap, DWORD dwSizeMap, DWORD dwTimeOut, DWORD dwToTrace, DWORD dwExactCall);
    typedef HANDLE(WINAPI * fCreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
    typedef HANDLE(WINAPI * fCreateFileMappingA)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName);
    typedef BOOL(__cdecl * fCloseHandle)(HANDLE hHandle);
    fTrace cTrace = (fTrace)(APIData->fTrace);
    fCreateFileW cCreateFileW = (fCreateFileW)(APIData->fCreateFileA);
    fCloseHandle cCloseHandle = (fCloseHandle)(APIData->fCloseHandle);
    fCreateFileMappingA cCreateFileMappingA = (fCreateFileMappingA)(APIData->fCreateFileMappingA);

    hFile = cCreateFileW((LPCWSTR)szFileName, GENERIC_READ + GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile != INVALID_HANDLE_VALUE)
    {
        hFileMap = cCreateFileMappingA(hFile, NULL, 4, NULL, 0x100, NULL);
        cTrace((DWORD)hFileMap, 0x100, -1, (DWORD)APIData->AddressToTrace, NULL);
        cCloseHandle(hFile);
        return(1);
    }
    else
    {
        return(0);
    }
}