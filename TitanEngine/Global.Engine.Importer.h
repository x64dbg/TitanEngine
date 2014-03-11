#ifndef _GLOBAL_ENGINE_IMPORTER_H
#define _GLOBAL_ENGINE_IMPORTER_H

//EngineGetProcAddressRemote
ULONG_PTR EngineGetProcAddressRemote(HANDLE hProcess, const wchar_t* szDLLName, const char* szAPIName);
ULONG_PTR EngineGetProcAddressRemote(HANDLE hProcess, const char* szDLLName, const char* szAPIName);
ULONG_PTR EngineGetModuleBaseRemote(HANDLE hProcess, ULONG_PTR APIAddress);
ULONG_PTR EngineGetModuleBaseRemote(HANDLE hProcess, const wchar_t* szDLLName);
ULONG_PTR EngineGetModuleBaseRemote(HANDLE hProcess, const char* szDLLName);
ULONG_PTR EngineGetAPIAddressRemote(HANDLE hProcess, ULONG_PTR APIAddress);
ULONG_PTR EngineGetAPIAddressLocal(HANDLE hProcess, ULONG_PTR APIAddress);

#endif //_GLOBAL_ENGINE_IMPORTER_H