#ifndef _GLOBAL_ENGINE_H
#define _GLOBAL_ENGINE_H

#include <vector>

//Global.Engine.Variables
extern HMODULE engineHandle;
extern wchar_t engineSzEngineGarbageFolder[MAX_PATH];
extern LPVOID engineExitThreadOneShootCallBack;
extern LPVOID engineDependencyFiles;
extern LPVOID engineDependencyFilesCWP;
extern void* EngineStartUnpackingCallBack;

extern bool engineAlowModuleLoading;
extern bool engineCheckForwarders;
extern bool engineBackupForCriticalFunctions;
extern bool engineResumeProcessIfNoThreadIsActive;
extern bool engineResetCustomHandler;
extern bool engineRemoveConsoleForDebugee;
extern bool enginePassAllExceptions;
extern bool engineExecutePluginCallBack;
extern bool engineAutoHideFromDebugger;
extern bool engineEnableDebugPrivilege;

//Global.Engine.Functions
void EngineInit();
bool EngineIsThereFreeHardwareBreakSlot(LPDWORD FreeRegister);
bool EngineFileExists(char* szFileName);
void EngineCreatePathForFile(char* szFileName);
void EngineCreatePathForFileW(wchar_t* szFileName);
wchar_t* EngineExtractFileNameW(wchar_t* szFileName);
bool EngineIsPointedMemoryString(ULONG_PTR PossibleStringPtr);
int EnginePointedMemoryStringLength(ULONG_PTR PossibleStringPtr);
bool EngineCompareResourceString(wchar_t* String1, wchar_t* String2);
ULONG_PTR EngineEstimateNewSectionRVA(ULONG_PTR FileMapVA);
bool EngineExtractForwarderData(ULONG_PTR PossibleStringPtr, LPVOID szFwdDLLName, LPVOID szFwdAPIName);
bool EngineGrabDataFromMappedFile(HANDLE hFile, ULONG_PTR FileMapVA, ULONG_PTR FileOffset, DWORD CopySize, LPVOID CopyToMemory);
bool EngineExtractResource(char* szResourceName, wchar_t* szExtractedFileName);
bool EngineIsDependencyPresent(char* szFileName, char* szDependencyForFile, char* szPresentInFolder);
bool EngineIsDependencyPresentW(wchar_t* szFileName, wchar_t* szDependencyForFile, wchar_t* szPresentInFolder);
bool EngineGetDependencyLocation(char* szFileName, char* szDependencyForFile, void* szLocationOfTheFile, int MaxStringSize);
bool EngineGetDependencyLocationW(wchar_t* szFileName, wchar_t* szDependencyForFile, void* szLocationOfTheFile, int MaxStringSize);
long EngineHashString(char* szStringToHash);
long EngineHashMemory(char* MemoryAddress, int MemorySize, DWORD InitialHashValue);
bool EngineIsValidReadPtrEx(LPVOID DataPointer, DWORD DataSize);
bool EngineValidateResource(HMODULE hModule, LPCTSTR lpszType, LPTSTR lpszName, LONG_PTR lParam);
bool EngineValidateHeader(ULONG_PTR FileMapVA, HANDLE hFileProc, LPVOID ImageBase, PIMAGE_DOS_HEADER DOSHeader, bool IsFile);
ULONG_PTR EngineSimulateNtLoaderW(wchar_t* szFileName);
ULONG_PTR EngineSimulateNtLoader(char* szFileName);
ULONG_PTR EngineSimulateDllLoader(HANDLE hProcess, char* szFileName);
ULONG_PTR EngineSimulateDllLoaderW(HANDLE hProcess, wchar_t* szFileName);
ULONG_PTR EngineGetProcAddress(ULONG_PTR ModuleBase, char* szAPIName);
bool EngineGetLibraryOrdinalData(ULONG_PTR ModuleBase, LPDWORD ptrOrdinalBase, LPDWORD ptrOrdinalCount);
ULONG_PTR EngineGlobalAPIHandler(HANDLE handleProcess, ULONG_PTR EnumedModulesBases, ULONG_PTR APIAddress, const char* szAPIName, DWORD ReturnType);
DWORD EngineSetDebugPrivilege(HANDLE hProcess, bool bEnablePrivilege);
HANDLE EngineOpenProcess(DWORD dwDesiredAccess, bool bInheritHandle, DWORD dwProcessId);
HANDLE EngineOpenThread(DWORD dwDesiredAccess, bool bInheritHandle, DWORD dwThreadId);

#endif //_GLOBAL_ENGINE_H