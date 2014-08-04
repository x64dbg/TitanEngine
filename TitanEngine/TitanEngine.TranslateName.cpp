#include "stdafx.h"
#include "definitions.h"

// TitanEngine.TranslateName.functions:
__declspec(dllexport) void* TITCALL TranslateNativeName(char* szNativeName)
{
    void* TranslatedName = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE); //pointer is returned
    char szDeviceName[3] = "A:";
    char szDeviceCOMName[5] = "COM0";
    int CurrentDeviceLen;

    while(szDeviceName[0] <= 0x5A)
    {
        RtlZeroMemory(TranslatedName, 0x1000);
        if(QueryDosDeviceA(szDeviceName, (LPSTR)TranslatedName, 0x1000) > NULL)
        {
            CurrentDeviceLen = lstrlenA((LPSTR)TranslatedName);
            lstrcatA((LPSTR)TranslatedName, (LPCSTR)(szNativeName + CurrentDeviceLen));
            if(lstrcmpiA((LPCSTR)TranslatedName, szNativeName) == NULL)
            {
                RtlZeroMemory(TranslatedName, 0x1000);
                lstrcatA((LPSTR)TranslatedName, szDeviceName);
                lstrcatA((LPSTR)TranslatedName, (LPCSTR)(szNativeName + CurrentDeviceLen));
                return(TranslatedName);
            }
        }
        szDeviceName[0]++;
    }

    while(szDeviceCOMName[3] <= 0x39)
    {
        RtlZeroMemory(TranslatedName, 0x1000);
        if(QueryDosDeviceA(szDeviceCOMName, (LPSTR)TranslatedName, 0x1000) > NULL)
        {
            CurrentDeviceLen = lstrlenA((LPSTR)TranslatedName);
            lstrcatA((LPSTR)TranslatedName, (LPCSTR)(szNativeName + CurrentDeviceLen));
            if(lstrcmpiA((LPCSTR)TranslatedName, szNativeName) == NULL)
            {
                RtlZeroMemory(TranslatedName, 0x1000);
                lstrcatA((LPSTR)TranslatedName, szDeviceCOMName);
                lstrcatA((LPSTR)TranslatedName, (LPCSTR)(szNativeName + CurrentDeviceLen));
                return(TranslatedName);
            }
        }
        szDeviceCOMName[3]++;
    }

    VirtualFree(TranslatedName, NULL, MEM_RELEASE);

    return NULL;
}

__declspec(dllexport) void* TITCALL TranslateNativeNameW(wchar_t* szNativeName)
{
    void* TranslatedName = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE); //pointer is returned
    wchar_t szDeviceName[3] = L"A:";
    wchar_t szDeviceCOMName[5] = L"COM0";
    int CurrentDeviceLen;

    while(szDeviceName[0] <= 0x5A)
    {
        RtlZeroMemory(TranslatedName, 0x1000);
        if(QueryDosDeviceW(szDeviceName, (LPWSTR)TranslatedName, MAX_PATH * 2) > NULL)
        {
            CurrentDeviceLen = lstrlenW((LPWSTR)TranslatedName);
            lstrcatW((LPWSTR)TranslatedName, (LPCWSTR)(szNativeName + CurrentDeviceLen));
            if(lstrcmpiW((LPCWSTR)TranslatedName, szNativeName) == NULL)
            {
                RtlZeroMemory(TranslatedName, 0x1000);
                lstrcatW((LPWSTR)TranslatedName, szDeviceName);
                lstrcatW((LPWSTR)TranslatedName, (LPWSTR)(szNativeName + CurrentDeviceLen));
                return(TranslatedName);
            }
        }
        szDeviceName[0]++;
    }

    while(szDeviceCOMName[3] <= 0x39)
    {
        RtlZeroMemory(TranslatedName, 0x1000);
        if(QueryDosDeviceW(szDeviceCOMName, (LPWSTR)TranslatedName, MAX_PATH * 2) > NULL)
        {
            CurrentDeviceLen = lstrlenW((LPWSTR)TranslatedName);
            lstrcatW((LPWSTR)TranslatedName, (LPCWSTR)(szNativeName + CurrentDeviceLen));
            if(lstrcmpiW((LPCWSTR)TranslatedName, szNativeName) == NULL)
            {
                RtlZeroMemory(TranslatedName, 0x1000);
                lstrcatW((LPWSTR)TranslatedName, szDeviceCOMName);
                lstrcatW((LPWSTR)TranslatedName, (LPWSTR)(szNativeName + CurrentDeviceLen));
                return(TranslatedName);
            }
        }
        szDeviceCOMName[3]++;
    }

    VirtualFree(TranslatedName, NULL, MEM_RELEASE);

    return NULL;
}