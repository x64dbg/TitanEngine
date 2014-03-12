#ifndef TITANSCRIPT_CPP
#define TITANSCRIPT_CPP

#if _MSC_VER > 1000
	#pragma once
#endif

namespace TS
{

namespace TSH
{
	#ifdef TITANSCRIPT_H
		#undef TITANSCRIPT_H
	#endif

	#include "TitanScript.h"
}

typedef TSH::eLogType eLogType;

class ScripterX
{
protected:

	static TSH::tScripterLoadBuffer pLoadBuffer;
	static TSH::tScripterResume pResume;
	static TSH::tScripterPause pPause;
	static TSH::tScripterSetLogCallback pSetLogCallback;

	typedef TSH::fLogCallback fLogCallback;

	//static bool Loaded;

	static bool LoadBuffer(const char* szScript)
	{
		return pLoadBuffer ? pLoadBuffer(szScript) : false;
	}
	static bool Resume()
	{
		return pResume ? pResume() : false;
	}
	static bool Pause()
	{
		return pPause ? pPause() : false;
	}
	static void SetLogCallback(fLogCallback Callback)
	{
		if(pSetLogCallback) pSetLogCallback(Callback);
	}
};

class ScripterA
{
private:

	static TSH::tScripterLoadFileA pLoadFile;
	static TSH::tScripterAutoDebugA pAutoDebug;

public:

	//static bool Loaded;

	static bool LoadFile(const char* szFileName)
	{
		return pLoadFile ? pLoadFile(szFileName) : false;
	}
	bool AutoDebug(const char* Debuggee)
	{
		return pAutoDebug ? pAutoDebug(Debuggee) : false;
	}
};

class ScripterW
{
private:

	static TSH::tScripterLoadFileW pLoadFile;
	static TSH::tScripterAutoDebugW pAutoDebug;

public:

	//static bool Loaded;

	static bool LoadFile(const wchar_t* szFileName)
	{
		return pLoadFile ? pLoadFile(szFileName) : false;
	}
	bool AutoDebug(const wchar_t* Debuggee)
	{
		return pAutoDebug ? pAutoDebug(Debuggee) : false;
	}
};

class Scripter : ScripterX, ScripterA, ScripterW
{
public:

	using ScripterX::fLogCallback;

	using ScripterA::LoadFile;
	using ScripterW::LoadFile;
	using ScripterX::LoadBuffer;
	using ScripterX::Resume;
	using ScripterX::Pause;
	using ScripterA::AutoDebug;
	using ScripterW::AutoDebug;
	using ScripterX::SetLogCallback;
};

TSH::tScripterLoadFileA ScripterA::pLoadFile = GetTSFunctionPointer(LoadFileA);
TSH::tScripterLoadFileW ScripterW::pLoadFile = GetTSFunctionPointer(LoadFileW);
TSH::tScripterLoadBuffer ScripterX::pLoadBuffer = GetTSFunctionPointer(LoadBuffer);
TSH::tScripterResume ScripterX::pResume = GetTSFunctionPointer(Resume);
TSH::tScripterPause ScripterX::pPause = GetTSFunctionPointer(Pause);
TSH::tScripterAutoDebugA ScripterA::pAutoDebug = GetTSFunctionPointer(AutoDebugA);
TSH::tScripterAutoDebugW ScripterW::pAutoDebug = GetTSFunctionPointer(AutoDebugW);
TSH::tScripterSetLogCallback ScripterX::pSetLogCallback = GetTSFunctionPointer(SetLogCallback);

} /* namespace TS */

#endif /*TITANSCRIPT_CPP*/
