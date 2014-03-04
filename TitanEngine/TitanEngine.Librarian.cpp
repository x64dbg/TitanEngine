#include "stdafx.h"
#include "definitions.h"
#include "Global.Librarian.h"

// TitanEngine.Librarian.functions:
__declspec(dllexport) bool TITCALL LibrarianSetBreakPoint(char* szLibraryName, DWORD bpxType, bool SingleShoot, LPVOID bpxCallBack)
{

    int i = MAX_LIBRARY_BPX;
    PLIBRARY_BREAK_DATA ptrLibrarianData = (PLIBRARY_BREAK_DATA)LibrarianData;

    if(szLibraryName != NULL && ptrLibrarianData != NULL)
    {
        while(i > NULL && ptrLibrarianData->szLibraryName[0] != 0x00)
        {
            ptrLibrarianData = (PLIBRARY_BREAK_DATA)((ULONG_PTR)ptrLibrarianData + sizeof LIBRARY_BREAK_DATA);
            i--;
        }
        lstrcpyA(&ptrLibrarianData->szLibraryName[0], szLibraryName);
        ptrLibrarianData->bpxCallBack = bpxCallBack;
        ptrLibrarianData->bpxSingleShoot = SingleShoot;
        ptrLibrarianData->bpxType = bpxType;
        return true;
    }
    return false;
}

__declspec(dllexport) bool TITCALL LibrarianRemoveBreakPoint(char* szLibraryName, DWORD bpxType)
{

    int i = MAX_LIBRARY_BPX;
    PLIBRARY_BREAK_DATA ptrLibrarianData = (PLIBRARY_BREAK_DATA)LibrarianData;

    if(szLibraryName != NULL && ptrLibrarianData != NULL)
    {
        while(i > NULL)
        {
            if(ptrLibrarianData->szLibraryName[0] != 0x00)
            {
                if(lstrcmpiA(szLibraryName, ptrLibrarianData->szLibraryName) == NULL && (ptrLibrarianData->bpxType == bpxType || bpxType == UE_ON_LIB_ALL))
                {
                    RtlZeroMemory(ptrLibrarianData, sizeof LIBRARY_BREAK_DATA);
                }
            }
            ptrLibrarianData = (PLIBRARY_BREAK_DATA)((ULONG_PTR)ptrLibrarianData + sizeof LIBRARY_BREAK_DATA);
            i--;
        }
        return true;
    }
    return false;
}

__declspec(dllexport) void* TITCALL LibrarianGetLibraryInfo(char* szLibraryName)
{

    wchar_t uniLibraryName[MAX_PATH] = {};
    PLIBRARY_ITEM_DATAW LibInfo;

    if(szLibraryName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szLibraryName, lstrlenA(szLibraryName)+1, uniLibraryName, sizeof(uniLibraryName)/(sizeof(uniLibraryName[0])));
        LibInfo = (PLIBRARY_ITEM_DATAW)LibrarianGetLibraryInfoW(uniLibraryName);
        if(LibInfo != NULL)
        {
            RtlZeroMemory(&LibraryInfoData, sizeof LIBRARY_ITEM_DATA);
            LibraryInfoData.hFile = LibInfo->hFile;
            LibraryInfoData.BaseOfDll = LibInfo->BaseOfDll;
            LibraryInfoData.hFileMapping = LibInfo->hFileMapping;
            LibraryInfoData.hFileMappingView = LibInfo->hFileMappingView;
            WideCharToMultiByte(CP_ACP, NULL, LibInfo->szLibraryName, -1, &LibraryInfoData.szLibraryName[0], sizeof LibraryInfoData.szLibraryName, NULL, NULL);
            WideCharToMultiByte(CP_ACP, NULL, LibInfo->szLibraryPath, -1, &LibraryInfoData.szLibraryPath[0], sizeof LibraryInfoData.szLibraryPath, NULL, NULL);
            return((void*)&LibraryInfoData);
        }
        else
        {
            return(NULL);
        }
    }
    else
    {
        return(NULL);
    }
}

__declspec(dllexport) void* TITCALL LibrarianGetLibraryInfoW(wchar_t* szLibraryName)
{

    PLIBRARY_ITEM_DATAW hListLibraryPtr = NULL;

    if(hListLibrary != NULL)
    {
        hListLibraryPtr = (PLIBRARY_ITEM_DATAW)hListLibrary;
        while(hListLibraryPtr->hFile != NULL)
        {
            if(hListLibraryPtr->hFile != (HANDLE)-1)
            {
                if(lstrcmpiW(hListLibraryPtr->szLibraryName, szLibraryName) == NULL)
                {
                    return((void*)hListLibraryPtr);
                }
            }
            hListLibraryPtr = (PLIBRARY_ITEM_DATAW)((ULONG_PTR)hListLibraryPtr + sizeof LIBRARY_ITEM_DATAW);
        }
    }
    return(NULL);
}

__declspec(dllexport) void* TITCALL LibrarianGetLibraryInfoEx(void* BaseOfDll)
{

    PLIBRARY_ITEM_DATAW LibInfo;

    LibInfo = (PLIBRARY_ITEM_DATAW)LibrarianGetLibraryInfoExW(BaseOfDll);
    if(LibInfo != NULL)
    {
        RtlZeroMemory(&LibraryInfoData, sizeof LIBRARY_ITEM_DATA);
        LibraryInfoData.hFile = LibInfo->hFile;
        LibraryInfoData.BaseOfDll = LibInfo->BaseOfDll;
        LibraryInfoData.hFileMapping = LibInfo->hFileMapping;
        LibraryInfoData.hFileMappingView = LibInfo->hFileMappingView;
        WideCharToMultiByte(CP_ACP, NULL, LibInfo->szLibraryName, -1, &LibraryInfoData.szLibraryName[0], sizeof LibraryInfoData.szLibraryName, NULL, NULL);
        WideCharToMultiByte(CP_ACP, NULL, LibInfo->szLibraryPath, -1, &LibraryInfoData.szLibraryPath[0], sizeof LibraryInfoData.szLibraryPath, NULL, NULL);
        return((void*)&LibraryInfoData);
    }
    else
    {
        return(NULL);
    }
}

__declspec(dllexport) void* TITCALL LibrarianGetLibraryInfoExW(void* BaseOfDll)
{

    PLIBRARY_ITEM_DATAW hListLibraryPtr = NULL;

    if(hListLibrary != NULL)
    {
        hListLibraryPtr = (PLIBRARY_ITEM_DATAW)hListLibrary;
        while(hListLibraryPtr->hFile != NULL)
        {
            if(hListLibraryPtr->hFile != (HANDLE)-1)
            {
                if(hListLibraryPtr->BaseOfDll == BaseOfDll)
                {
                    return((void*)hListLibraryPtr);
                }
            }
            hListLibraryPtr = (PLIBRARY_ITEM_DATAW)((ULONG_PTR)hListLibraryPtr + sizeof LIBRARY_ITEM_DATAW);
        }
    }
    return(NULL);
}

__declspec(dllexport) void TITCALL LibrarianEnumLibraryInfo(void* EnumCallBack)
{

    PLIBRARY_ITEM_DATAW hListLibraryPtr = NULL;
    typedef void(TITCALL *fEnumCallBack)(LPVOID fLibraryDetail);
    fEnumCallBack myEnumCallBack = (fEnumCallBack)EnumCallBack;

    if(hListLibrary != NULL)
    {
        hListLibraryPtr = (PLIBRARY_ITEM_DATAW)hListLibrary;
        while(EnumCallBack != NULL && hListLibraryPtr->hFile != NULL)
        {
            if(hListLibraryPtr->hFile != (HANDLE)-1)
            {
                __try
                {
                    myEnumCallBack((void*)hListLibraryPtr);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    EnumCallBack = NULL;
                }
            }
            hListLibraryPtr = (PLIBRARY_ITEM_DATAW)((ULONG_PTR)hListLibraryPtr + sizeof LIBRARY_ITEM_DATAW);
        }
    }
}

__declspec(dllexport) void TITCALL LibrarianEnumLibraryInfoW(void* EnumCallBack)
{

    LIBRARY_ITEM_DATA myLibraryInfoData;
    PLIBRARY_ITEM_DATAW hListLibraryPtr = NULL;
    typedef void(TITCALL *fEnumCallBack)(LPVOID fLibraryDetail);
    fEnumCallBack myEnumCallBack = (fEnumCallBack)EnumCallBack;

    if(hListLibrary != NULL)
    {
        hListLibraryPtr = (PLIBRARY_ITEM_DATAW)hListLibrary;
        while(EnumCallBack != NULL && hListLibraryPtr->hFile != NULL)
        {
            if(hListLibraryPtr->hFile != (HANDLE)-1)
            {
                __try
                {
                    RtlZeroMemory(&myLibraryInfoData, sizeof LIBRARY_ITEM_DATA);
                    myLibraryInfoData.hFile = hListLibraryPtr->hFile;
                    myLibraryInfoData.BaseOfDll = hListLibraryPtr->BaseOfDll;
                    myLibraryInfoData.hFileMapping = hListLibraryPtr->hFileMapping;
                    myLibraryInfoData.hFileMappingView = hListLibraryPtr->hFileMappingView;
                    WideCharToMultiByte(CP_ACP, NULL, hListLibraryPtr->szLibraryName, -1, &myLibraryInfoData.szLibraryName[0], sizeof myLibraryInfoData.szLibraryName, NULL, NULL);
                    WideCharToMultiByte(CP_ACP, NULL, hListLibraryPtr->szLibraryPath, -1, &myLibraryInfoData.szLibraryPath[0], sizeof myLibraryInfoData.szLibraryPath, NULL, NULL);
                    myEnumCallBack((void*)&myLibraryInfoData);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    EnumCallBack = NULL;
                }
            }
            hListLibraryPtr = (PLIBRARY_ITEM_DATAW)((ULONG_PTR)hListLibraryPtr + sizeof LIBRARY_ITEM_DATAW);
        }
    }
}
