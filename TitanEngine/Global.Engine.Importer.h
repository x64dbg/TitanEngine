#ifndef _GLOBAL_ENGINE_IMPORTER_H
#define _GLOBAL_ENGINE_IMPORTER_H

//EngineGetProcAddressRemote
ULONG_PTR EngineGetProcAddressRemote(const char * szDLLName, const char* szAPIName);
ULONG_PTR EngineGetProcAddressRemote(HANDLE hProcess, const char * szDLLName, const char* szAPIName);
ULONG_PTR EngineGetProcAddressRemote(const WCHAR * szDLLName, const char* szAPIName);
ULONG_PTR EngineGetProcAddressRemote(HANDLE hProcess, const WCHAR * szDLLName, const char* szAPIName);

#endif //_GLOBAL_ENGINE_IMPORTER_H