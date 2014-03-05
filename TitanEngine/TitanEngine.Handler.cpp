#include "stdafx.h"
#include "definitions.h"
#include "Global.Handle.h"

// TitanEngine.Handler.functions:
__declspec(dllexport) long TITCALL HandlerGetActiveHandleCount(DWORD ProcessId)
{

    int HandleCount = NULL;
    LPVOID QuerySystemBuffer;
    ULONG QuerySystemBufferSize = 0x2000;
    ULONG RequiredSize = NULL;
    ULONG TotalHandleCount = NULL;

    PNTDLL_QUERY_HANDLE_INFO HandleInfo;

    QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
    while(NtQuerySystemInformation(SystemHandleInformation, QuerySystemBuffer, QuerySystemBufferSize, &RequiredSize) == (NTSTATUS)0xC0000004L)
    {
        QuerySystemBufferSize = RequiredSize;
        VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
        QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
    }
    RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
    QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
    HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
    while(TotalHandleCount > NULL)
    {
        if(HandleInfo->ProcessId == ProcessId)
        {
            HandleCount++;
        }
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
        TotalHandleCount--;
    }
    VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
    return(HandleCount);

    return(NULL);
}
__declspec(dllexport) bool TITCALL HandlerIsHandleOpen(DWORD ProcessId, HANDLE hHandle)
{
    bool HandleActive = false;
    LPVOID QuerySystemBuffer;
    ULONG QuerySystemBufferSize = 0x2000;
    ULONG RequiredSize = NULL;
    ULONG TotalHandleCount = NULL;
    PNTDLL_QUERY_HANDLE_INFO HandleInfo;

    QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
    while(NtQuerySystemInformation(SystemHandleInformation, QuerySystemBuffer, QuerySystemBufferSize, &RequiredSize) == (NTSTATUS)0xC0000004L)
    {
        QuerySystemBufferSize = RequiredSize;
        VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
        QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
    }
    RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
    QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
    HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
    while(TotalHandleCount > NULL)
    {
        if(HandleInfo->ProcessId == ProcessId && (HANDLE)HandleInfo->hHandle == hHandle)
        {
            HandleActive = true;
            break;
        }
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
        TotalHandleCount--;
    }
    VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
    if(HandleActive)
    {
        return true;
    }

    return false;
}
__declspec(dllexport) void* TITCALL HandlerGetHandleName(HANDLE hProcess, DWORD ProcessId, HANDLE hHandle, bool TranslateName)
{

    bool NameFound = false;
    HANDLE myHandle = NULL;
    LPVOID QuerySystemBuffer;
    ULONG QuerySystemBufferSize = 0x2000;
    ULONG RequiredSize = NULL;
    ULONG TotalHandleCount = NULL;
    PNTDLL_QUERY_HANDLE_INFO HandleInfo;
    PUBLIC_OBJECT_BASIC_INFORMATION ObjectBasicInfo;
    LPVOID ObjectNameInfo = VirtualAlloc(NULL, 0x2000, MEM_COMMIT, PAGE_READWRITE);
    PPUBLIC_OBJECT_NAME_INFORMATION pObjectNameInfo = (PPUBLIC_OBJECT_NAME_INFORMATION)ObjectNameInfo;
    LPVOID HandleFullName = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    LPVOID tmpHandleFullName = NULL;


    QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
    while(NtQuerySystemInformation(SystemHandleInformation, QuerySystemBuffer, QuerySystemBufferSize, &RequiredSize) == (NTSTATUS)0xC0000004L)
    {
        QuerySystemBufferSize = RequiredSize;
        VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
        QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
    }
    RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
    QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
    HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
    while(TotalHandleCount > NULL)
    {
        if(HandleInfo->ProcessId == ProcessId && (HANDLE)HandleInfo->hHandle == hHandle)
        {
            //if(!(HandleInfo->GrantedAccess & SYNCHRONIZE) || ((HandleInfo->GrantedAccess & SYNCHRONIZE) && ((WORD)HandleInfo->GrantedAccess != 0x19F9))){// && (WORD)HandleInfo->GrantedAccess != 0x89))){
            if(HandleInfo->GrantedAccess != 0x0012019F)
            {
                if(DuplicateHandle(hProcess, hHandle, GetCurrentProcess(), &myHandle, NULL, false, DUPLICATE_SAME_ACCESS))
                {
                    RtlZeroMemory(&ObjectBasicInfo, sizeof PUBLIC_OBJECT_BASIC_INFORMATION);
                    NtQueryObject(myHandle, ObjectBasicInformation, &ObjectBasicInfo, sizeof PUBLIC_OBJECT_BASIC_INFORMATION, &RequiredSize);
                    NtQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, 8, &RequiredSize);
                    NtQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, RequiredSize, &RequiredSize);
                    RtlZeroMemory(HandleFullName, 0x1000);
                    if(pObjectNameInfo->Name.Length != NULL)
                    {
                        WideCharToMultiByte(CP_ACP, NULL, (LPCWSTR)pObjectNameInfo->Name.Buffer, -1, (LPSTR)HandleFullName, 0x1000, NULL, NULL);
                        NameFound = true;
                        if(TranslateName)
                        {
                            tmpHandleFullName = TranslateNativeName((char*)HandleFullName);
                            if(tmpHandleFullName != NULL)
                            {
                                VirtualFree(HandleFullName, NULL, MEM_RELEASE);
                                HandleFullName = tmpHandleFullName;
                            }
                        }
                    }
                    EngineCloseHandle(myHandle);
                    break;
                }
            }
        }
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
        TotalHandleCount--;
    }
    VirtualFree(ObjectNameInfo, NULL, MEM_RELEASE);
    VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
    if(!NameFound)
    {
        VirtualFree(HandleFullName, NULL, MEM_RELEASE);
        return(NULL);
    }
    else
    {
        return(HandleFullName);
    }

    VirtualFree(HandleFullName, NULL, MEM_RELEASE);
    VirtualFree(ObjectNameInfo, NULL, MEM_RELEASE);
    return(NULL);
}
__declspec(dllexport) void* TITCALL HandlerGetHandleNameW(HANDLE hProcess, DWORD ProcessId, HANDLE hHandle, bool TranslateName)
{

    bool NameFound = false;
    HANDLE myHandle = NULL;
    LPVOID QuerySystemBuffer;
    ULONG QuerySystemBufferSize = 0x2000;
    ULONG RequiredSize = NULL;
    ULONG TotalHandleCount = NULL;
    PNTDLL_QUERY_HANDLE_INFO HandleInfo;
    PUBLIC_OBJECT_BASIC_INFORMATION ObjectBasicInfo;
    LPVOID ObjectNameInfo = VirtualAlloc(NULL, 0x2000, MEM_COMMIT, PAGE_READWRITE);
    PPUBLIC_OBJECT_NAME_INFORMATION pObjectNameInfo = (PPUBLIC_OBJECT_NAME_INFORMATION)ObjectNameInfo;
    LPVOID HandleFullName = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    LPVOID tmpHandleFullName = NULL;


    QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
    while(NtQuerySystemInformation(SystemHandleInformation, QuerySystemBuffer, QuerySystemBufferSize, &RequiredSize) == (NTSTATUS)0xC0000004L)
    {
        QuerySystemBufferSize = RequiredSize;
        VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
        QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
    }
    RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
    QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
    HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
    while(TotalHandleCount > NULL)
    {
        if(HandleInfo->ProcessId == ProcessId && (HANDLE)HandleInfo->hHandle == hHandle)
        {
            //if(!(HandleInfo->GrantedAccess & SYNCHRONIZE) || ((HandleInfo->GrantedAccess & SYNCHRONIZE) && ((WORD)HandleInfo->GrantedAccess != 0x19F9))){// && (WORD)HandleInfo->GrantedAccess != 0x89))){
            if(HandleInfo->GrantedAccess != 0x0012019F)
            {
                if(DuplicateHandle(hProcess, hHandle, GetCurrentProcess(), &myHandle, NULL, false, DUPLICATE_SAME_ACCESS))
                {
                    RtlZeroMemory(&ObjectBasicInfo, sizeof PUBLIC_OBJECT_BASIC_INFORMATION);
                    NtQueryObject(myHandle, ObjectBasicInformation, &ObjectBasicInfo, sizeof PUBLIC_OBJECT_BASIC_INFORMATION, &RequiredSize);
                    NtQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, 8, &RequiredSize);
                    NtQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, RequiredSize, &RequiredSize);
                    RtlZeroMemory(HandleFullName, 0x1000);
                    if(pObjectNameInfo->Name.Length != NULL)
                    {
                        //WideCharToMultiByte(CP_ACP, NULL, (LPCWSTR)pObjectNameInfo->Name.Buffer, -1, (LPSTR)HandleFullName, 0x1000, NULL, NULL);
                        NameFound = true;
                        lstrcpyW((wchar_t*)HandleFullName, (wchar_t*)pObjectNameInfo->Name.Buffer);
                        if(TranslateName)
                        {
                            tmpHandleFullName = TranslateNativeNameW((wchar_t*)HandleFullName);
                            if(tmpHandleFullName != NULL)
                            {
                                VirtualFree(HandleFullName, NULL, MEM_RELEASE);
                                HandleFullName = tmpHandleFullName;
                            }
                        }
                    }
                    EngineCloseHandle(myHandle);
                    break;
                }
            }
        }
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
        TotalHandleCount--;
    }
    VirtualFree(ObjectNameInfo, NULL, MEM_RELEASE);
    VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
    if(!NameFound)
    {
        VirtualFree(HandleFullName, NULL, MEM_RELEASE);
        return(NULL);
    }
    else
    {
        return(HandleFullName);
    }

    VirtualFree(HandleFullName, NULL, MEM_RELEASE);
    VirtualFree(ObjectNameInfo, NULL, MEM_RELEASE);
    return(NULL);
}
__declspec(dllexport) long TITCALL HandlerEnumerateOpenHandles(DWORD ProcessId, LPVOID HandleBuffer, DWORD MaxHandleCount)
{

    HANDLE myHandle = NULL;
    LPVOID QuerySystemBuffer;
    ULONG RequiredSize = NULL;
    ULONG TotalHandleCount = NULL;
    unsigned int HandleCount = NULL;
    ULONG QuerySystemBufferSize = 0x2000;
    PNTDLL_QUERY_HANDLE_INFO HandleInfo;


    QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
    while(NtQuerySystemInformation(SystemHandleInformation, QuerySystemBuffer, QuerySystemBufferSize, &RequiredSize) == (NTSTATUS)0xC0000004L)
    {
        QuerySystemBufferSize = RequiredSize;
        VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
        QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
    }
    RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
    QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
    HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
    while(TotalHandleCount > NULL)
    {
        if(HandleInfo->ProcessId == ProcessId && HandleCount < MaxHandleCount)
        {
            myHandle = (HANDLE)HandleInfo->hHandle;
            RtlMoveMemory(HandleBuffer, &myHandle, sizeof HANDLE);
            HandleBuffer = (LPVOID)((ULONG_PTR)HandleBuffer + sizeof HANDLE);
            HandleCount++;
        }
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
        TotalHandleCount--;
    }
    VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
    return(HandleCount);

    return(NULL);
}
__declspec(dllexport) long long TITCALL HandlerGetHandleDetails(HANDLE hProcess, DWORD ProcessId, HANDLE hHandle, DWORD InformationReturn)
{

    HANDLE myHandle = NULL;
    LPVOID QuerySystemBuffer;
    ULONG QuerySystemBufferSize = 0x2000;
    ULONG RequiredSize = NULL;
    ULONG TotalHandleCount = NULL;
    PNTDLL_QUERY_HANDLE_INFO HandleInfo;
    PUBLIC_OBJECT_BASIC_INFORMATION ObjectBasicInfo;
    LPVOID HandleFullData = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    LPVOID HandleNameData = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    PPUBLIC_OBJECT_TYPE_INFORMATION pObjectTypeInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)HandleFullData;
    bool DontFreeStringMemory = false;
    ULONG_PTR ReturnData = NULL;


    QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
    while(NtQuerySystemInformation(SystemHandleInformation, QuerySystemBuffer, QuerySystemBufferSize, &RequiredSize) == (NTSTATUS)0xC0000004L)
    {
        QuerySystemBufferSize = RequiredSize;
        VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
        QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
    }
    RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
    QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
    HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
    while(TotalHandleCount > NULL)
    {
        if(HandleInfo->ProcessId == ProcessId && (HANDLE)HandleInfo->hHandle == hHandle)
        {
            if(DuplicateHandle(hProcess, hHandle, GetCurrentProcess(), &myHandle, NULL, false, DUPLICATE_SAME_ACCESS))
            {
                RtlZeroMemory(&ObjectBasicInfo, sizeof PUBLIC_OBJECT_BASIC_INFORMATION);
                NtQueryObject(myHandle, ObjectBasicInformation, &ObjectBasicInfo, sizeof PUBLIC_OBJECT_BASIC_INFORMATION, &RequiredSize);
                if(InformationReturn == UE_OPTION_HANDLER_RETURN_HANDLECOUNT)
                {
                    ReturnData = (ULONG_PTR)ObjectBasicInfo.HandleCount;
                }
                else if(InformationReturn == UE_OPTION_HANDLER_RETURN_ACCESS)
                {
                    ReturnData = (ULONG_PTR)HandleInfo->GrantedAccess;
                }
                else if(InformationReturn == UE_OPTION_HANDLER_RETURN_FLAGS)
                {
                    ReturnData = (ULONG_PTR)HandleInfo->Flags;
                }
                else if(InformationReturn == UE_OPTION_HANDLER_RETURN_TYPENAME)
                {
                    //if(!(HandleInfo->GrantedAccess & SYNCHRONIZE) || ((HandleInfo->GrantedAccess & SYNCHRONIZE) && ((WORD)HandleInfo->GrantedAccess != 0x19F9))){// && (WORD)HandleInfo->GrantedAccess != 0x89))){
                    if(HandleInfo->GrantedAccess != 0x0012019F)
                    {
                        RtlZeroMemory(HandleFullData, 0x1000);
                        NtQueryObject(myHandle, ObjectTypeInformation, HandleFullData, 8, &RequiredSize);
                        NtQueryObject(myHandle, ObjectTypeInformation, HandleFullData, RequiredSize, &RequiredSize);
                        RtlZeroMemory(HandleNameData, 0x1000);
                        if(pObjectTypeInfo->TypeName.Length != NULL)
                        {
                            WideCharToMultiByte(CP_ACP, NULL, (LPCWSTR)pObjectTypeInfo->TypeName.Buffer, -1, (LPSTR)HandleNameData, 0x1000, NULL, NULL);
                            ReturnData = (ULONG_PTR)HandleNameData;
                            DontFreeStringMemory = true;
                        }
                    }
                }
                else if(InformationReturn == UE_OPTION_HANDLER_RETURN_TYPENAME_UNICODE)
                {
                    //if(!(HandleInfo->GrantedAccess & SYNCHRONIZE) || ((HandleInfo->GrantedAccess & SYNCHRONIZE) && ((WORD)HandleInfo->GrantedAccess != 0x19F9))){// && (WORD)HandleInfo->GrantedAccess != 0x89))){
                    if(HandleInfo->GrantedAccess != 0x0012019F)
                    {
                        RtlZeroMemory(HandleFullData, 0x1000);
                        NtQueryObject(myHandle, ObjectTypeInformation, HandleFullData, 8, &RequiredSize);
                        NtQueryObject(myHandle, ObjectTypeInformation, HandleFullData, RequiredSize, &RequiredSize);
                        RtlZeroMemory(HandleNameData, 0x1000);
                        if(pObjectTypeInfo->TypeName.Length != NULL)
                        {
                            //WideCharToMultiByte(CP_ACP, NULL, (LPCWSTR)pObjectTypeInfo->TypeName.Buffer, -1, (LPSTR)HandleNameData, 0x1000, NULL, NULL);
                            lstrcpyW((wchar_t*)HandleNameData, (wchar_t*)pObjectTypeInfo->TypeName.Buffer);
                            ReturnData = (ULONG_PTR)HandleNameData;
                            DontFreeStringMemory = true;
                        }
                    }
                }
                EngineCloseHandle(myHandle);
                break;
            }
        }
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
        TotalHandleCount--;
    }
    if(!DontFreeStringMemory)
    {
        VirtualFree(HandleNameData, NULL, MEM_RELEASE);
    }
    VirtualFree(HandleFullData, NULL, MEM_RELEASE);
    VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
    return(ReturnData);

    if(!DontFreeStringMemory)
    {
        VirtualFree(HandleNameData, NULL, MEM_RELEASE);
    }
    VirtualFree(HandleFullData, NULL, MEM_RELEASE);
    return(NULL);
}
__declspec(dllexport) bool TITCALL HandlerCloseRemoteHandle(HANDLE hProcess, HANDLE hHandle)
{

    HANDLE myHandle;

    if(hProcess != NULL)
    {
        DuplicateHandle(hProcess, hHandle, GetCurrentProcess(), &myHandle, NULL, false, DUPLICATE_CLOSE_SOURCE);
        EngineCloseHandle(myHandle);
    }
    return false;
}
__declspec(dllexport) long TITCALL HandlerEnumerateLockHandles(char* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated, LPVOID HandleDataBuffer, DWORD MaxHandleCount)
{

    wchar_t uniFileOrFolderName[MAX_PATH] = {};

    if(szFileOrFolderName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileOrFolderName, lstrlenA(szFileOrFolderName)+1, uniFileOrFolderName, sizeof(uniFileOrFolderName)/(sizeof(uniFileOrFolderName[0])));
        return(HandlerEnumerateLockHandlesW(uniFileOrFolderName, NameIsFolder, NameIsTranslated, HandleDataBuffer, MaxHandleCount));
    }
    else
    {
        return(NULL);
    }
}
__declspec(dllexport) long TITCALL HandlerEnumerateLockHandlesW(wchar_t* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated, LPVOID HandleDataBuffer, DWORD MaxHandleCount)
{

    int FoundHandles = NULL;
    HANDLE hProcess = NULL;
    HANDLE myHandle = NULL;
    HANDLE CopyHandle = NULL;
    LPVOID QuerySystemBuffer;
    ULONG QuerySystemBufferSize = 0x2000;
    ULONG RequiredSize = NULL;
    ULONG TotalHandleCount = NULL;
    DWORD LastProcessId = NULL;


    PNTDLL_QUERY_HANDLE_INFO HandleInfo;
    PUBLIC_OBJECT_BASIC_INFORMATION ObjectBasicInfo;
    LPVOID ObjectNameInfo = VirtualAlloc(NULL, 0x2000, MEM_COMMIT, PAGE_READWRITE);
    PPUBLIC_OBJECT_NAME_INFORMATION pObjectNameInfo = (PPUBLIC_OBJECT_NAME_INFORMATION)ObjectNameInfo;
    LPVOID HandleFullName = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    int LenFileOrFolderName = lstrlenW(szFileOrFolderName);
    LPVOID tmpHandleFullName = NULL;


    QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
    while(NtQuerySystemInformation(SystemHandleInformation, QuerySystemBuffer, QuerySystemBufferSize, &RequiredSize) == (NTSTATUS)0xC0000004L)
    {
        QuerySystemBufferSize = RequiredSize;
        VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
        QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
    }
    RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
    QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
    HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
    while(TotalHandleCount > NULL)
    {
        if(LastProcessId != HandleInfo->ProcessId)
        {
            if(hProcess != NULL)
            {
                EngineCloseHandle(hProcess);
            }
            hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, false, HandleInfo->ProcessId);
            LastProcessId = HandleInfo->ProcessId;
        }
        if(hProcess != NULL)
        {
            //if(!(HandleInfo->GrantedAccess & SYNCHRONIZE) || ((HandleInfo->GrantedAccess & SYNCHRONIZE) && ((WORD)HandleInfo->GrantedAccess != 0x19F9))){// && (WORD)HandleInfo->GrantedAccess != 0x89))){
            if(HandleInfo->GrantedAccess != 0x0012019F)
            {
                if(DuplicateHandle(hProcess, (HANDLE)HandleInfo->hHandle, GetCurrentProcess(), &myHandle, NULL, false, DUPLICATE_SAME_ACCESS))
                {
                    RtlZeroMemory(&ObjectBasicInfo, sizeof PUBLIC_OBJECT_BASIC_INFORMATION);
                    NtQueryObject(myHandle, ObjectBasicInformation, &ObjectBasicInfo, sizeof PUBLIC_OBJECT_BASIC_INFORMATION, &RequiredSize);
                    NtQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, 8, &RequiredSize);
                    NtQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, RequiredSize, &RequiredSize);
                    RtlZeroMemory(HandleFullName, 0x1000);
                    if(pObjectNameInfo->Name.Length != NULL)
                    {
                        //WideCharToMultiByte(CP_ACP, NULL, (LPCWSTR)pObjectNameInfo->Name.Buffer, -1, (LPSTR)HandleFullName, 0x1000, NULL, NULL);
                        lstrcpyW((wchar_t*)HandleFullName, (wchar_t*)pObjectNameInfo->Name.Buffer);
                        if(NameIsTranslated)
                        {
                            tmpHandleFullName = TranslateNativeNameW((wchar_t*)HandleFullName);
                            if(tmpHandleFullName != NULL)
                            {
                                VirtualFree(HandleFullName, NULL, MEM_RELEASE);
                                HandleFullName = tmpHandleFullName;
                            }
                        }
                        if(NameIsFolder)
                        {
                            if(lstrlenW((LPCWSTR)HandleFullName) > LenFileOrFolderName)
                            {
                                RtlZeroMemory((LPVOID)((ULONG_PTR)HandleFullName + LenFileOrFolderName * 2), 2);
                            }
                        }
                        if(lstrcmpiW((LPCWSTR)HandleFullName, szFileOrFolderName) == NULL && MaxHandleCount > NULL)
                        {
                            RtlMoveMemory(HandleDataBuffer, &HandleInfo->ProcessId, sizeof ULONG);
                            HandleDataBuffer = (LPVOID)((ULONG_PTR)HandleDataBuffer + sizeof ULONG);
                            CopyHandle = (HANDLE)HandleInfo->hHandle;
                            RtlMoveMemory(HandleDataBuffer, &CopyHandle, sizeof HANDLE);
                            HandleDataBuffer = (LPVOID)((ULONG_PTR)HandleDataBuffer + sizeof HANDLE);
                            FoundHandles++;
                            MaxHandleCount--;
                        }
                    }
                    EngineCloseHandle(myHandle);
                }
            }
        }
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
        TotalHandleCount--;
    }
    VirtualFree(ObjectNameInfo, NULL, MEM_RELEASE);
    VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
    VirtualFree(HandleFullName, NULL, MEM_RELEASE);
    return(FoundHandles);
}
__declspec(dllexport) bool TITCALL HandlerCloseAllLockHandles(char* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated)
{

    wchar_t uniFileOrFolderName[MAX_PATH] = {};

    if(szFileOrFolderName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileOrFolderName, lstrlenA(szFileOrFolderName)+1, uniFileOrFolderName, sizeof(uniFileOrFolderName)/(sizeof(uniFileOrFolderName[0])));
        return(HandlerCloseAllLockHandlesW(uniFileOrFolderName, NameIsFolder, NameIsTranslated));
    }
    else
    {
        return false;
    }
}
__declspec(dllexport) bool TITCALL HandlerCloseAllLockHandlesW(wchar_t* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated)
{

    bool AllHandled = true;
    HANDLE hProcess = NULL;
    HANDLE myHandle = NULL;
    HANDLE CopyHandle = NULL;
    LPVOID QuerySystemBuffer;
    ULONG QuerySystemBufferSize = 0x2000;
    ULONG RequiredSize = NULL;
    ULONG TotalHandleCount = NULL;
    DWORD LastProcessId = NULL;
    PNTDLL_QUERY_HANDLE_INFO HandleInfo;
    PUBLIC_OBJECT_BASIC_INFORMATION ObjectBasicInfo;
    LPVOID ObjectNameInfo = VirtualAlloc(NULL, 0x2000, MEM_COMMIT, PAGE_READWRITE);
    PPUBLIC_OBJECT_NAME_INFORMATION pObjectNameInfo = (PPUBLIC_OBJECT_NAME_INFORMATION)ObjectNameInfo;
    LPVOID HandleFullName = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    int LenFileOrFolderName = lstrlenW(szFileOrFolderName);
    LPVOID tmpHandleFullName = NULL;


    QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
    while(NtQuerySystemInformation(SystemHandleInformation, QuerySystemBuffer, QuerySystemBufferSize, &RequiredSize) == (NTSTATUS)0xC0000004L)
    {
        QuerySystemBufferSize = RequiredSize;
        VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
        QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
    }
    RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
    QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
    HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
    while(TotalHandleCount > NULL)
    {
        if(LastProcessId != HandleInfo->ProcessId)
        {
            if(hProcess != NULL)
            {
                EngineCloseHandle(hProcess);
            }
            hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, false, HandleInfo->ProcessId);
            LastProcessId = HandleInfo->ProcessId;
        }
        if(hProcess != NULL)
        {
            //if(!(HandleInfo->GrantedAccess & SYNCHRONIZE) || ((HandleInfo->GrantedAccess & SYNCHRONIZE) && ((WORD)HandleInfo->GrantedAccess != 0x19F9))){// && (WORD)HandleInfo->GrantedAccess != 0x89))){
            if(HandleInfo->GrantedAccess != 0x0012019F)
            {
                if(DuplicateHandle(hProcess, (HANDLE)HandleInfo->hHandle, GetCurrentProcess(), &myHandle, NULL, false, DUPLICATE_SAME_ACCESS))
                {
                    RtlZeroMemory(&ObjectBasicInfo, sizeof PUBLIC_OBJECT_BASIC_INFORMATION);
                    NtQueryObject(myHandle, ObjectBasicInformation, &ObjectBasicInfo, sizeof PUBLIC_OBJECT_BASIC_INFORMATION, &RequiredSize);
                    NtQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, 8, &RequiredSize);
                    NtQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, RequiredSize, &RequiredSize);
                    RtlZeroMemory(HandleFullName, 0x1000);
                    if(pObjectNameInfo->Name.Length != NULL)
                    {
                        //WideCharToMultiByte(CP_ACP, NULL, (LPCWSTR)pObjectNameInfo->Name.Buffer, -1, (LPSTR)HandleFullName, 0x1000, NULL, NULL);
                        lstrcpyW((wchar_t*)HandleFullName, (wchar_t*)pObjectNameInfo->Name.Buffer);
                        if(NameIsTranslated)
                        {
                            tmpHandleFullName = TranslateNativeNameW((wchar_t*)HandleFullName);
                            if(tmpHandleFullName != NULL)
                            {
                                VirtualFree(HandleFullName, NULL, MEM_RELEASE);
                                HandleFullName = tmpHandleFullName;
                            }
                        }
                        if(NameIsFolder)
                        {
                            if(lstrlenW((LPCWSTR)HandleFullName) > LenFileOrFolderName)
                            {
                                RtlZeroMemory((LPVOID)((ULONG_PTR)HandleFullName + LenFileOrFolderName * 2), 2);
                            }
                        }
                        if(lstrcmpiW((LPCWSTR)HandleFullName, szFileOrFolderName) == NULL)
                        {
                            if(!HandlerCloseRemoteHandle(hProcess, (HANDLE)HandleInfo->hHandle))
                            {
                                AllHandled = false;
                            }
                        }
                    }
                    EngineCloseHandle(myHandle);
                }
            }
        }
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
        TotalHandleCount--;
    }
    VirtualFree(ObjectNameInfo, NULL, MEM_RELEASE);
    VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
    VirtualFree(HandleFullName, NULL, MEM_RELEASE);
    if(AllHandled)
    {
        return true;
    }
    else
    {
        return false;
    }

}
__declspec(dllexport) bool TITCALL HandlerIsFileLocked(char* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated)
{

    wchar_t uniFileOrFolderName[MAX_PATH] = {};

    if(szFileOrFolderName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileOrFolderName, lstrlenA(szFileOrFolderName)+1, uniFileOrFolderName, sizeof(uniFileOrFolderName)/(sizeof(uniFileOrFolderName[0])));
        return(HandlerIsFileLockedW(uniFileOrFolderName, NameIsFolder, NameIsTranslated));
    }
    else
    {
        return false;
    }
}
__declspec(dllexport) bool TITCALL HandlerIsFileLockedW(wchar_t* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated)
{

    HANDLE hProcess = NULL;
    HANDLE myHandle = NULL;
    HANDLE CopyHandle = NULL;
    LPVOID QuerySystemBuffer;
    ULONG QuerySystemBufferSize = 0x2000;
    ULONG RequiredSize = NULL;
    ULONG TotalHandleCount = NULL;
    DWORD LastProcessId = NULL;

    PNTDLL_QUERY_HANDLE_INFO HandleInfo;
    PUBLIC_OBJECT_BASIC_INFORMATION ObjectBasicInfo;
    LPVOID ObjectNameInfo = VirtualAlloc(NULL, 0x2000, MEM_COMMIT, PAGE_READWRITE);
    PPUBLIC_OBJECT_NAME_INFORMATION pObjectNameInfo = (PPUBLIC_OBJECT_NAME_INFORMATION)ObjectNameInfo;
    LPVOID HandleFullName = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    int LenFileOrFolderName = lstrlenW(szFileOrFolderName);
    LPVOID tmpHandleFullName = NULL;

    QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
    while(NtQuerySystemInformation(SystemHandleInformation, QuerySystemBuffer, QuerySystemBufferSize, &RequiredSize) == (NTSTATUS)0xC0000004L)
    {
        QuerySystemBufferSize = RequiredSize;
        VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
        QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
    }
    RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
    QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
    HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
    while(TotalHandleCount > NULL)
    {
        if(LastProcessId != HandleInfo->ProcessId)
        {
            if(hProcess != NULL)
            {
                EngineCloseHandle(hProcess);
            }
            hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, false, HandleInfo->ProcessId);
            LastProcessId = HandleInfo->ProcessId;
        }
        if(hProcess != NULL)
        {
            //if(!(HandleInfo->GrantedAccess & SYNCHRONIZE) || ((HandleInfo->GrantedAccess & SYNCHRONIZE) && ((WORD)HandleInfo->GrantedAccess != 0x19F9))){// && (WORD)HandleInfo->GrantedAccess != 0x89))){
            if(HandleInfo->GrantedAccess != 0x0012019F)
            {
                if(DuplicateHandle(hProcess, (HANDLE)HandleInfo->hHandle, GetCurrentProcess(), &myHandle, NULL, false, DUPLICATE_SAME_ACCESS))
                {
                    RtlZeroMemory(&ObjectBasicInfo, sizeof PUBLIC_OBJECT_BASIC_INFORMATION);
                    NtQueryObject(myHandle, ObjectBasicInformation, &ObjectBasicInfo, sizeof PUBLIC_OBJECT_BASIC_INFORMATION, &RequiredSize);
                    NtQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, 8, &RequiredSize);
                    NtQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, RequiredSize, &RequiredSize);
                    RtlZeroMemory(HandleFullName, 0x1000);
                    if(pObjectNameInfo->Name.Length != NULL)
                    {
                        //WideCharToMultiByte(CP_ACP, NULL, (LPCWSTR)pObjectNameInfo->Name.Buffer, -1, (LPSTR)HandleFullName, 0x1000, NULL, NULL);
                        lstrcpyW((wchar_t*)HandleFullName, (wchar_t*)pObjectNameInfo->Name.Buffer);
                        if(NameIsTranslated)
                        {
                            tmpHandleFullName = TranslateNativeNameW((wchar_t*)HandleFullName);
                            if(tmpHandleFullName != NULL)
                            {
                                VirtualFree(HandleFullName, NULL, MEM_RELEASE);
                                HandleFullName = tmpHandleFullName;
                            }
                        }
                        if(NameIsFolder)
                        {
                            if(lstrlenW((LPCWSTR)HandleFullName) > LenFileOrFolderName)
                            {
                                RtlZeroMemory((LPVOID)((ULONG_PTR)HandleFullName + LenFileOrFolderName * 2), 2);
                            }
                        }
                        if(lstrcmpiW((LPCWSTR)HandleFullName, szFileOrFolderName) == NULL)
                        {
                            VirtualFree(ObjectNameInfo, NULL, MEM_RELEASE);
                            VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
                            VirtualFree(HandleFullName, NULL, MEM_RELEASE);
                            EngineCloseHandle(myHandle);
                            return true;
                        }
                    }
                    EngineCloseHandle(myHandle);
                }
            }
        }
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
        TotalHandleCount--;
    }
    VirtualFree(ObjectNameInfo, NULL, MEM_RELEASE);
    VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
    VirtualFree(HandleFullName, NULL, MEM_RELEASE);
    return false;

}
// TitanEngine.Handler[Mutex].functions:
__declspec(dllexport) long TITCALL HandlerEnumerateOpenMutexes(HANDLE hProcess, DWORD ProcessId, LPVOID HandleBuffer, DWORD MaxHandleCount)
{

    HANDLE myHandle = NULL;
    HANDLE copyHandle = NULL;
    LPVOID QuerySystemBuffer;
    ULONG RequiredSize = NULL;
    ULONG TotalHandleCount = NULL;
    unsigned int HandleCount = NULL;
    ULONG QuerySystemBufferSize = 0x2000;

    PNTDLL_QUERY_HANDLE_INFO HandleInfo;
    LPVOID HandleFullData = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    LPVOID HandleNameData = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    PPUBLIC_OBJECT_TYPE_INFORMATION pObjectTypeInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)HandleFullData;


    QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
    while(NtQuerySystemInformation(SystemHandleInformation, QuerySystemBuffer, QuerySystemBufferSize, &RequiredSize) == (NTSTATUS)0xC0000004L)
    {
        QuerySystemBufferSize = RequiredSize;
        VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
        QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
    }
    RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
    QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
    HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
    while(TotalHandleCount > NULL)
    {
        if(HandleInfo->ProcessId == ProcessId && HandleCount < MaxHandleCount)
        {
            //if(!(HandleInfo->GrantedAccess & SYNCHRONIZE) || ((HandleInfo->GrantedAccess & SYNCHRONIZE) && ((WORD)HandleInfo->GrantedAccess != 0x19F9))){// && (WORD)HandleInfo->GrantedAccess != 0x89))){
            if(HandleInfo->GrantedAccess != 0x0012019F)
            {
                if(DuplicateHandle(hProcess, (HANDLE)HandleInfo->hHandle, GetCurrentProcess(), &myHandle, NULL, false, DUPLICATE_SAME_ACCESS))
                {
                    RtlZeroMemory(HandleFullData, 0x1000);
                    NtQueryObject(myHandle, ObjectTypeInformation, HandleFullData, 8, &RequiredSize);
                    NtQueryObject(myHandle, ObjectTypeInformation, HandleFullData, RequiredSize, &RequiredSize);
                    RtlZeroMemory(HandleNameData, 0x1000);
                    if(pObjectTypeInfo->TypeName.Length != NULL)
                    {
                        WideCharToMultiByte(CP_ACP, NULL, (LPCWSTR)pObjectTypeInfo->TypeName.Buffer, -1, (LPSTR)HandleNameData, 0x1000, NULL, NULL);
                        if(lstrcmpiA((LPCSTR)HandleNameData, "Mutant") == NULL)
                        {
                            copyHandle = (HANDLE)HandleInfo->hHandle;
                            RtlMoveMemory(HandleBuffer, &copyHandle, sizeof HANDLE);
                            HandleBuffer = (LPVOID)((ULONG_PTR)HandleBuffer + sizeof HANDLE);
                            HandleCount++;
                        }
                    }
                    EngineCloseHandle(myHandle);
                }
            }
        }
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
        TotalHandleCount--;
    }
    VirtualFree(HandleFullData, NULL, MEM_RELEASE);
    VirtualFree(HandleNameData, NULL, MEM_RELEASE);
    VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
    return(HandleCount);

}
__declspec(dllexport) long long TITCALL HandlerGetOpenMutexHandle(HANDLE hProcess, DWORD ProcessId, char* szMutexString)
{

    wchar_t uniMutexString[MAX_PATH] = {};

    if(szMutexString != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szMutexString, lstrlenA(szMutexString)+1, uniMutexString, sizeof(uniMutexString)/(sizeof(uniMutexString[0])));
        return((ULONG_PTR)HandlerGetOpenMutexHandleW(hProcess, ProcessId, uniMutexString));
    }
    else
    {
        return(NULL);
    }
}
__declspec(dllexport) long long TITCALL HandlerGetOpenMutexHandleW(HANDLE hProcess, DWORD ProcessId, wchar_t* szMutexString)
{
    if(!szMutexString || lstrlenW(szMutexString)>=512)
        return 0;
    int i;
    HANDLE myHandle;
    LPVOID HandleBuffer = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    LPVOID cHandleBuffer = HandleBuffer;
    int OpenHandleCount = HandlerEnumerateOpenMutexes(hProcess, ProcessId, HandleBuffer, 0x1000 / sizeof HANDLE);
    wchar_t RealMutexName[512] = L"\\BaseNamedObjects\\";
    wchar_t* HandleName;

    if(OpenHandleCount > NULL)
    {
        lstrcatW(RealMutexName, szMutexString);
        for(i = 0; i < OpenHandleCount; i++)
        {
            RtlMoveMemory(&myHandle, cHandleBuffer, sizeof HANDLE);
            HandleName = (wchar_t*)HandlerGetHandleNameW(hProcess, ProcessId, myHandle, true);
            if(HandleName != NULL)
            {
                if(lstrcmpiW(HandleName, RealMutexName) == NULL)
                {
                    VirtualFree(HandleBuffer, NULL, MEM_RELEASE);
                    return((ULONG_PTR)myHandle);
                }
            }
            cHandleBuffer = (LPVOID)((ULONG_PTR)cHandleBuffer + sizeof HANDLE);
        }
    }
    VirtualFree(HandleBuffer, NULL, MEM_RELEASE);
    return(NULL);
}
__declspec(dllexport) long TITCALL HandlerGetProcessIdWhichCreatedMutex(char* szMutexString)
{

    wchar_t uniMutexString[MAX_PATH] = {};

    if(szMutexString != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szMutexString, lstrlenA(szMutexString)+1, uniMutexString, sizeof(uniMutexString)/(sizeof(uniMutexString[0])));
        return(HandlerGetProcessIdWhichCreatedMutexW(uniMutexString));
    }
    else
    {
        return(NULL);
    }
}
__declspec(dllexport) long TITCALL HandlerGetProcessIdWhichCreatedMutexW(wchar_t* szMutexString)
{
    if(!szMutexString || lstrlenW(szMutexString)>=512)
        return 0;
    HANDLE hProcess = NULL;
    DWORD ReturnData = NULL;
    HANDLE myHandle = NULL;
    LPVOID QuerySystemBuffer;
    ULONG RequiredSize = NULL;
    DWORD LastProcessId = NULL;
    ULONG TotalHandleCount = NULL;
    ULONG QuerySystemBufferSize = 0x2000;
    PNTDLL_QUERY_HANDLE_INFO HandleInfo;
    LPVOID HandleFullData = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    LPVOID HandleNameData = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    PPUBLIC_OBJECT_TYPE_INFORMATION pObjectTypeInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)HandleFullData;
    LPVOID ObjectNameInfo = VirtualAlloc(NULL, 0x2000, MEM_COMMIT, PAGE_READWRITE);
    PPUBLIC_OBJECT_NAME_INFORMATION pObjectNameInfo = (PPUBLIC_OBJECT_NAME_INFORMATION)ObjectNameInfo;
    wchar_t RealMutexName[512] = L"\\BaseNamedObjects\\";


    lstrcatW(RealMutexName, szMutexString);
    QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
    while(NtQuerySystemInformation(SystemHandleInformation, QuerySystemBuffer, QuerySystemBufferSize, &RequiredSize) == (NTSTATUS)0xC0000004L)
    {
        QuerySystemBufferSize = RequiredSize;
        VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
        QuerySystemBuffer = VirtualAlloc(NULL, QuerySystemBufferSize, MEM_COMMIT, PAGE_READWRITE);
    }
    RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
    QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
    HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
    while(TotalHandleCount > NULL)
    {
        if(LastProcessId != HandleInfo->ProcessId)
        {
            if(hProcess != NULL)
            {
                EngineCloseHandle(hProcess);
            }
            hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, false, HandleInfo->ProcessId);
            LastProcessId = HandleInfo->ProcessId;
        }
        if(hProcess != NULL)
        {
            //if(!(HandleInfo->GrantedAccess & SYNCHRONIZE) || ((HandleInfo->GrantedAccess & SYNCHRONIZE) && ((WORD)HandleInfo->GrantedAccess != 0x19F9))){// && (WORD)HandleInfo->GrantedAccess != 0x89))){
            if(HandleInfo->GrantedAccess != 0x0012019F)
            {
                if(DuplicateHandle(hProcess, (HANDLE)HandleInfo->hHandle, GetCurrentProcess(), &myHandle, NULL, false, DUPLICATE_SAME_ACCESS))
                {
                    RtlZeroMemory(HandleFullData, 0x1000);
                    NtQueryObject(myHandle, ObjectTypeInformation, HandleFullData, 8, &RequiredSize);
                    NtQueryObject(myHandle, ObjectTypeInformation, HandleFullData, RequiredSize, &RequiredSize);
                    RtlZeroMemory(HandleNameData, 0x1000);
                    if(pObjectTypeInfo->TypeName.Length != NULL)
                    {
                        //WideCharToMultiByte(CP_ACP, NULL, (LPCWSTR)pObjectTypeInfo->TypeName.Buffer, -1, (LPSTR)HandleNameData, 0x1000, NULL, NULL);
                        lstrcpyW((wchar_t*)HandleNameData, (wchar_t*)pObjectNameInfo->Name.Buffer);
                        if(lstrcmpiW((LPCWSTR)HandleNameData, L"Mutant") == NULL)
                        {
                            NtQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, 8, &RequiredSize);
                            NtQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, RequiredSize, &RequiredSize);
                            RtlZeroMemory(HandleNameData, 0x1000);
                            if(pObjectNameInfo->Name.Length != NULL)
                            {
                                RtlZeroMemory(HandleNameData, 0x1000);
                                //WideCharToMultiByte(CP_ACP, NULL, (LPCWSTR)pObjectNameInfo->Name.Buffer, -1, (LPSTR)HandleNameData, 0x1000, NULL, NULL);
                                lstrcpyW((wchar_t*)HandleNameData, (wchar_t*)pObjectNameInfo->Name.Buffer);
                                if(lstrcmpiW((LPCWSTR)HandleNameData, RealMutexName) == NULL)
                                {
                                    ReturnData = HandleInfo->ProcessId;
                                    break;
                                }
                            }
                        }
                    }
                    EngineCloseHandle(myHandle);
                }
            }
        }
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
        TotalHandleCount--;
    }
    VirtualFree(HandleFullData, NULL, MEM_RELEASE);
    VirtualFree(HandleNameData, NULL, MEM_RELEASE);
    VirtualFree(ObjectNameInfo, NULL, MEM_RELEASE);
    VirtualFree(QuerySystemBuffer, NULL, MEM_RELEASE);
    return(ReturnData);

}
