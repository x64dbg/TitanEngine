#include "stdafx.h"
#include "definitions.h"
#include "Global.Librarian.h"

static LIBRARY_ITEM_DATA LibraryInfoData = {};

// TitanEngine.Librarian.functions:
__declspec(dllexport) bool TITCALL LibrarianSetBreakPoint(char* szLibraryName, DWORD bpxType, bool SingleShoot, LPVOID bpxCallBack)
{
    LIBRARY_BREAK_DATA NewLibrarianData;
    memset(&NewLibrarianData, 0, sizeof(LIBRARY_BREAK_DATA));
    lstrcpyA(NewLibrarianData.szLibraryName, szLibraryName);
    NewLibrarianData.bpxCallBack = bpxCallBack;
    NewLibrarianData.bpxSingleShoot = SingleShoot;
    NewLibrarianData.bpxType = bpxType;
    LibrarianData.push_back(NewLibrarianData);

    return true;
}

__declspec(dllexport) bool TITCALL LibrarianRemoveBreakPoint(char* szLibraryName, DWORD bpxType)
{
    for(int i = (int)LibrarianData.size() - 1; i >= 0; i--)
    {
        if(!_stricmp(szLibraryName, LibrarianData.at(i).szLibraryName) && (LibrarianData.at(i).bpxType == bpxType || bpxType == UE_ON_LIB_ALL))
        {
            LibrarianData.erase(LibrarianData.begin() + i);
        }
    }

    return true;
}

__declspec(dllexport) void* TITCALL LibrarianGetLibraryInfo(char* szLibraryName)
{
    if(!szLibraryName)
        return NULL;

    wchar_t uniLibraryName[MAX_PATH] = {};
    PLIBRARY_ITEM_DATAW LibInfo;
    MultiByteToWideChar(CP_ACP, NULL, szLibraryName, lstrlenA(szLibraryName) + 1, uniLibraryName, sizeof(uniLibraryName) / (sizeof(uniLibraryName[0])));
    LibInfo = (PLIBRARY_ITEM_DATAW)LibrarianGetLibraryInfoW(uniLibraryName);
    if(LibInfo)
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

    return NULL;
}

__declspec(dllexport) void* TITCALL LibrarianGetLibraryInfoW(wchar_t* szLibraryName)
{
    static LIBRARY_ITEM_DATAW LibraryInfo;
    memset(&LibraryInfo, 0, sizeof(LIBRARY_ITEM_DATAW));

    for(unsigned int i = 0; i < hListLibrary.size(); i++)
    {
        if(hListLibrary.at(i).hFile != INVALID_HANDLE_VALUE && !lstrcmpiW(hListLibrary.at(i).szLibraryName, szLibraryName))
        {
            memcpy(&LibraryInfo, &hListLibrary.at(i), sizeof(LIBRARY_ITEM_DATAW));
            return &LibraryInfo;
        }
    }

    return NULL;
}

__declspec(dllexport) void* TITCALL LibrarianGetLibraryInfoEx(void* BaseOfDll)
{
    PLIBRARY_ITEM_DATAW LibInfo;
    LibInfo = (PLIBRARY_ITEM_DATAW)LibrarianGetLibraryInfoExW(BaseOfDll);
    if(LibInfo)
    {
        RtlZeroMemory(&LibraryInfoData, sizeof LIBRARY_ITEM_DATA);
        LibraryInfoData.hFile = LibInfo->hFile;
        LibraryInfoData.BaseOfDll = LibInfo->BaseOfDll;
        LibraryInfoData.hFileMapping = LibInfo->hFileMapping;
        LibraryInfoData.hFileMappingView = LibInfo->hFileMappingView;
        WideCharToMultiByte(CP_ACP, NULL, LibInfo->szLibraryName, -1, &LibraryInfoData.szLibraryName[0], sizeof LibraryInfoData.szLibraryName, NULL, NULL);
        WideCharToMultiByte(CP_ACP, NULL, LibInfo->szLibraryPath, -1, &LibraryInfoData.szLibraryPath[0], sizeof LibraryInfoData.szLibraryPath, NULL, NULL);

        return (void*)&LibraryInfoData;
    }

    return NULL;
}

__declspec(dllexport) void* TITCALL LibrarianGetLibraryInfoExW(void* BaseOfDll)
{
    static LIBRARY_ITEM_DATAW LibraryData;
    memset(&LibraryData, 0, sizeof(LIBRARY_ITEM_DATAW));

    for(unsigned int i = 0; i < hListLibrary.size(); i++)
    {
        if(hListLibrary.at(i).hFile != INVALID_HANDLE_VALUE && hListLibrary.at(i).BaseOfDll == BaseOfDll)
        {
            memcpy(&LibraryData, &hListLibrary.at(i), sizeof(LIBRARY_ITEM_DATAW));

            return &LibraryData;
        }
    }

    return NULL;
}

__declspec(dllexport) void TITCALL LibrarianEnumLibraryInfo(void* EnumCallBack)
{
    if(!EnumCallBack)
        return;

    typedef void(TITCALL * fEnumCallBack)(LPVOID fLibraryDetail);
    fEnumCallBack myEnumCallBack = (fEnumCallBack)EnumCallBack;

    for(unsigned int i = 0; i < hListLibrary.size(); i++)
    {
        if(hListLibrary.at(i).hFile != INVALID_HANDLE_VALUE)
        {
            __try
            {
                LIBRARY_ITEM_DATA myLibraryInfoData;
                memset(&myLibraryInfoData, 0, sizeof(LIBRARY_ITEM_DATA));
                myLibraryInfoData.hFile = hListLibrary.at(i).hFile;
                myLibraryInfoData.BaseOfDll = hListLibrary.at(i).BaseOfDll;
                myLibraryInfoData.hFileMapping = hListLibrary.at(i).hFileMapping;
                myLibraryInfoData.hFileMappingView = hListLibrary.at(i).hFileMappingView;
                WideCharToMultiByte(CP_ACP, NULL, hListLibrary.at(i).szLibraryName, -1, &myLibraryInfoData.szLibraryName[0], sizeof(myLibraryInfoData.szLibraryName), NULL, NULL);
                WideCharToMultiByte(CP_ACP, NULL, hListLibrary.at(i).szLibraryPath, -1, &myLibraryInfoData.szLibraryPath[0], sizeof(myLibraryInfoData.szLibraryPath), NULL, NULL);
                myEnumCallBack(&myLibraryInfoData);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                break;
            }
        }
    }
}

__declspec(dllexport) void TITCALL LibrarianEnumLibraryInfoW(void* EnumCallBack)
{
    if(!EnumCallBack)
        return;

    typedef void(TITCALL * fEnumCallBack)(LPVOID fLibraryDetail);
    fEnumCallBack myEnumCallBack = (fEnumCallBack)EnumCallBack;

    for(unsigned int i = 0; i < hListLibrary.size(); i++)
    {
        if(hListLibrary.at(i).hFile != INVALID_HANDLE_VALUE)
        {
            __try
            {
                myEnumCallBack(&hListLibrary.at(i));
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                break;
            }
        }
    }
}
