#ifndef _GLOBAL_ENGINE_EXTENSION_H
#define _GLOBAL_ENGINE_EXTENSION_H

#include "definitions.h"

#define PLUGCALL TITCALL

//typedefs
typedef void(PLUGCALL* fPluginDebugExec)(LPDEBUG_EVENT debugEvent, int CallReason);
typedef bool(PLUGCALL* fPluginRegister)(char* szPluginName, LPDWORD titanPluginMajorVersion, LPDWORD titanPluginMinorVersion);
typedef void(PLUGCALL* fPluginReleaseExec)();
typedef void(PLUGCALL* fPluginResetExec)();

//structs
typedef struct
{
    char PluginName[64];
    DWORD PluginMajorVersion;
    DWORD PluginMinorVersion;
    HMODULE PluginBaseAddress;
    fPluginDebugExec TitanDebuggingCallBack;
    fPluginRegister TitanRegisterPlugin;
    fPluginReleaseExec TitanReleasePlugin;
    fPluginResetExec TitanResetPlugin;
    bool PluginDisabled;
} PluginInformation, *PPluginInformation;

//functions
void ExtensionManagerPluginReleaseCallBack();
void ExtensionManagerPluginResetCallBack();
void ExtensionManagerPluginDebugCallBack(LPDEBUG_EVENT debugEvent, int CallReason);
void EngineInitPlugins(wchar_t* szEngineFolder);

#endif //_GLOBAL_ENGINE_EXTENSION_H