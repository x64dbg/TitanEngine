#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.Extension.h"


static std::vector<PluginInformation> Plugin;

// Global.Engine.Extension.Functions:
void ExtensionManagerPluginReleaseCallBack()
{
    for(unsigned int i = 0; i < Plugin.size(); i++)
    {
        __try
        {
            if(Plugin.at(i).TitanReleasePlugin != NULL)
            {
                Plugin.at(i).TitanReleasePlugin();
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {

        }
    }
}

void ExtensionManagerPluginResetCallBack()
{
    for(unsigned int i = 0; i < Plugin.size(); i++)
    {
        __try
        {
            if(Plugin.at(i).TitanResetPlugin != NULL)
            {
                Plugin.at(i).TitanResetPlugin();
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {

        }
    }
}

void ExtensionManagerPluginDebugCallBack(LPDEBUG_EVENT debugEvent, int CallReason)
{
    for(unsigned int i = 0; i < Plugin.size(); i++)
    {
        __try
        {
            if(!Plugin.at(i).PluginDisabled)
            {
                if(Plugin.at(i).TitanDebuggingCallBack != NULL)
                {
                    Plugin.at(i).TitanDebuggingCallBack(debugEvent, CallReason);
                }
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {

        }
    }
}

void EngineInitPlugins(wchar_t* szEngineFolder)
{
    bool MoreFiles = true;
    bool NameHasBeenRegistered = false;
    PluginInformation myPluginInfo = {};
#if defined (_WIN64)
    wchar_t* szPluginFolder = L"\\plugins\\x64\\";
#else
    wchar_t* szPluginFolder = L"\\plugins\\x86\\";
#endif
    wchar_t szPluginSearchString[MAX_PATH] = {};
    wchar_t szPluginFullPath[MAX_PATH] = {};
    fPluginRegister myPluginRegister;
    WIN32_FIND_DATAW FindData;
    HANDLE CurrentFile;

    lstrcpyW(szPluginSearchString, szEngineFolder);
    lstrcatW(szPluginSearchString, szPluginFolder);
    lstrcatW(szPluginSearchString, L"*.dll");
    CurrentFile = FindFirstFileW(szPluginSearchString, &FindData);
    while(MoreFiles)
    {
        lstrcpyW(szPluginFullPath, szEngineFolder);
        lstrcatW(szPluginFullPath, szPluginFolder);
        lstrcatW(szPluginFullPath, FindData.cFileName);
        RtlZeroMemory(&myPluginInfo, sizeof PluginInformation);
        myPluginInfo.PluginBaseAddress = LoadLibraryW(szPluginFullPath);
        if(myPluginInfo.PluginBaseAddress != NULL)
        {
            myPluginInfo.TitanResetPlugin = (fPluginResetExec)GetProcAddress(myPluginInfo.PluginBaseAddress, "TitanResetPlugin");
            myPluginInfo.TitanReleasePlugin = (fPluginReleaseExec)GetProcAddress(myPluginInfo.PluginBaseAddress, "TitanReleasePlugin");
            myPluginInfo.TitanRegisterPlugin = (fPluginRegister)GetProcAddress(myPluginInfo.PluginBaseAddress, "TitanRegisterPlugin");
            myPluginInfo.TitanDebuggingCallBack = (fPluginDebugExec)GetProcAddress(myPluginInfo.PluginBaseAddress, "TitanDebuggingCallBack");
            myPluginRegister = myPluginInfo.TitanRegisterPlugin;
            if(myPluginRegister != NULL)
            {
                __try
                {
                    if(myPluginRegister((char*)&myPluginInfo.PluginName[0], &myPluginInfo.PluginMajorVersion, &myPluginInfo.PluginMinorVersion))
                    {
                        if(lstrlenA(myPluginInfo.PluginName) <= 64)
                        {
                            NameHasBeenRegistered = false;
                            for(unsigned int i = 0; i < Plugin.size(); i++)
                            {
                                if(lstrcmpiA(Plugin.at(i).PluginName, myPluginInfo.PluginName) == NULL)
                                {
                                    NameHasBeenRegistered = true;
                                }
                            }
                            if(!NameHasBeenRegistered)
                            {
                                Plugin.push_back(myPluginInfo);
                            }
                            else
                            {
                                FreeLibrary(myPluginInfo.PluginBaseAddress);
                            }
                        }
                        else
                        {
                            FreeLibrary(myPluginInfo.PluginBaseAddress);
                        }
                    }
                    else
                    {
                        FreeLibrary(myPluginInfo.PluginBaseAddress);
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    FreeLibrary(myPluginInfo.PluginBaseAddress);
                }
            }
        }
        if(!FindNextFileW(CurrentFile, &FindData))
        {
            MoreFiles = false;
        }
    }
    FindClose(CurrentFile);
}

__declspec(dllexport) bool TITCALL ExtensionManagerIsPluginLoaded(char* szPluginName)
{

    for(unsigned int i = 0; i < Plugin.size(); i++)
    {
        if(lstrcmpiA(Plugin.at(i).PluginName, szPluginName) == NULL)
        {
            return true;
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL ExtensionManagerIsPluginEnabled(char* szPluginName)
{
    for(unsigned int i = 0; i < Plugin.size(); i++)
    {
        if(lstrcmpiA(Plugin.at(i).PluginName, szPluginName) == NULL)
        {
            if(!Plugin.at(i).PluginDisabled)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL ExtensionManagerDisableAllPlugins()
{
    for(unsigned int i = 0; i < Plugin.size(); i++)
    {
        Plugin.at(i).PluginDisabled = true;
    }
    return true;
}

__declspec(dllexport) bool TITCALL ExtensionManagerDisablePlugin(char* szPluginName)
{
    for(unsigned int i = 0; i < Plugin.size(); i++)
    {
        if(lstrcmpiA(Plugin.at(i).PluginName, szPluginName) == NULL)
        {
            Plugin.at(i).PluginDisabled = true;
            return true;
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL ExtensionManagerEnableAllPlugins()
{
    for(unsigned int i = 0; i < Plugin.size(); i++)
    {
        Plugin.at(i).PluginDisabled = false;
    }
    return true;
}

__declspec(dllexport) bool TITCALL ExtensionManagerEnablePlugin(char* szPluginName)
{
    for(unsigned int i = 0; i < Plugin.size(); i++)
    {
        if(lstrcmpiA(Plugin.at(i).PluginName, szPluginName) == NULL)
        {
            Plugin.at(i).PluginDisabled = false;
            return true;
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL ExtensionManagerUnloadAllPlugins()
{
    for(unsigned int i = 0; i < Plugin.size(); i++)
    {
        if(FreeLibrary(Plugin.at(i).PluginBaseAddress))
        {
            Plugin.erase(Plugin.begin() + i);
        }
    }
    return true;
}

__declspec(dllexport) bool TITCALL ExtensionManagerUnloadPlugin(char* szPluginName)
{
    fPluginReleaseExec myPluginReleaseExec;

    for(unsigned int i = 0; i < Plugin.size(); i++)
    {
        if(lstrcmpiA(Plugin.at(i).PluginName, szPluginName) == NULL)
        {
            __try
            {
                if(Plugin.at(i).TitanReleasePlugin != NULL)
                {
                    myPluginReleaseExec = (fPluginReleaseExec)Plugin.at(i).TitanReleasePlugin;
                    myPluginReleaseExec();
                    if(FreeLibrary(Plugin.at(i).PluginBaseAddress))
                    {
                        Plugin.erase(Plugin.begin() + i);
                        return true;
                    }
                }
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                if(FreeLibrary(Plugin.at(i).PluginBaseAddress))
                {
                    Plugin.erase(Plugin.begin() + i);
                    return true;
                }
            }
        }
    }
    return false;
}

__declspec(dllexport) void* TITCALL ExtensionManagerGetPluginInfo(char* szPluginName)
{
    for(unsigned int i = 0; i < Plugin.size(); i++)
    {
        if(lstrcmpiA(Plugin.at(i).PluginName, szPluginName) == NULL)
        {
            return(&Plugin.at(i));
        }
    }
    return(NULL);
}
