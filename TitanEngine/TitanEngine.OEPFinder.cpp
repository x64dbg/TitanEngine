#include "stdafx.h"
#include "definitions.h"
#include "Global.OEPFinder.h"

// TitanEngine.FindOEP.functions:
__declspec(dllexport) void TITCALL FindOEPInit()
{
    RemoveAllBreakPoints(UE_OPTION_REMOVEALL);
}
__declspec(dllexport) bool TITCALL FindOEPGenerically(char* szFileName, LPVOID TraceInitCallBack, LPVOID CallBack)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        return(FindOEPGenericallyW(uniFileName, TraceInitCallBack, CallBack));
    }
    else
    {
        return false;
    }
}
__declspec(dllexport) bool TITCALL FindOEPGenericallyW(wchar_t* szFileName, LPVOID TraceInitCallBack, LPVOID CallBack)
{

    int i;

    if(GenericOEPFileInitW(szFileName, TraceInitCallBack, CallBack))
    {
        InitDebugExW(szFileName, NULL, NULL, &GenericOEPTraceInit);
        DebugLoop();
        for(i = 0; i < glbEntryTracerData.SectionNumber; i++)
        {
            VirtualFree(glbEntryTracerData.SectionData[i].AllocatedSection, NULL, MEM_RELEASE);
        }
    }
    return false;
}
