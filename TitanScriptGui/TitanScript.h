#ifndef TITANSCRIPT_H
#define TITANSCRIPT_H

#if _MSC_VER > 1000
//#pragma once
#endif

#include <windows.h>

enum eLogType {TS_LOG_NORMAL, TS_LOG_ERROR, TS_LOG_COMMAND, TS_LOG_DEBUG};
typedef void(*fLogCallback)(const char* szString, eLogType Type);

typedef bool (*tScripterLoadFileA)(const char*);
typedef bool (*tScripterLoadFileW)(const wchar_t*);
typedef bool (*tScripterLoadBuffer)(const char*);
typedef bool (*tScripterResume)();
typedef bool (*tScripterPause)();
typedef bool (*tScripterAutoDebugA)(const char*);
typedef bool (*tScripterAutoDebugW)(const wchar_t*);
typedef void (*tScripterSetLogCallback)(fLogCallback Callback);
typedef bool (*tScripterExecuteWithTitanMistA)(const char*, const char*);

// use like this: tScripterResume foo = GetTSFunctionPointer(Resume);
#define GetTSFunctionPointer(x) ((tScripter ## x)GetProcAddress(GetModuleHandleA("TitanScript"), "Scripter" #x))

#endif /*TITANSCRIPT_H*/
