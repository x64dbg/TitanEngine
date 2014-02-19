#ifndef _GLOBAL_ENGINE_EXTENSION_H
#define _GLOBAL_ENGINE_EXTENSION_H

void ExtensionManagerPluginReleaseCallBack();
void ExtensionManagerPluginResetCallBack();
void ExtensionManagerPluginDebugCallBack(LPDEBUG_EVENT debugEvent, int CallReason);
void EngineInitPlugins(wchar_t* szEngineFolder);

#endif //_GLOBAL_ENGINE_EXTENSION_H