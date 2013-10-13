#ifndef TITANENGINE_CPP
#define TITANENGINE_CPP

#if _MSC_VER > 1000
    #pragma once
#endif

namespace TE
{

#include <windows.h>

namespace UE
{
	#ifdef TITANENGINE
		#undef TITANENGINE
	#endif

	#include "TitanEngine.h"
}

// ----

enum eHideLevel : DWORD
{
	UE_HIDE_PEBONLY = UE::UE_HIDE_PEBONLY,
	UE_HIDE_BASIC = UE::UE_HIDE_BASIC
};

enum ePluginCallReason : int
{
	UE_PLUGIN_CALL_REASON_PREDEBUG = UE::UE_PLUGIN_CALL_REASON_PREDEBUG,
	UE_PLUGIN_CALL_REASON_EXCEPTION = UE::UE_PLUGIN_CALL_REASON_EXCEPTION,
	UE_PLUGIN_CALL_REASON_POSTDEBUG = UE::UE_PLUGIN_CALL_REASON_POSTDEBUG
};

enum eHookType : int
{
	TEE_HOOK_NRM_JUMP = UE::TEE_HOOK_NRM_JUMP,
	TEE_HOOK_NRM_CALL = UE::TEE_HOOK_NRM_CALL,
	TEE_HOOK_IAT = UE::TEE_HOOK_IAT
};

enum eEngineVariable : DWORD
{
	UE_ENGINE_ALOW_MODULE_LOADING = UE::UE_ENGINE_ALOW_MODULE_LOADING,
	UE_ENGINE_AUTOFIX_FORWARDERS = UE::UE_ENGINE_AUTOFIX_FORWARDERS,
	UE_ENGINE_PASS_ALL_EXCEPTIONS = UE::UE_ENGINE_PASS_ALL_EXCEPTIONS,
	UE_ENGINE_NO_CONSOLE_WINDOW = UE::UE_ENGINE_NO_CONSOLE_WINDOW,
	UE_ENGINE_BACKUP_FOR_CRITICAL_FUNCTIONS = UE::UE_ENGINE_BACKUP_FOR_CRITICAL_FUNCTIONS,
	UE_ENGINE_CALL_PLUGIN_CALLBACK = UE::UE_ENGINE_CALL_PLUGIN_CALLBACK,
	UE_ENGINE_RESET_CUSTOM_HANDLER = UE::UE_ENGINE_RESET_CUSTOM_HANDLER,
	UE_ENGINE_CALL_PLUGIN_DEBUG_CALLBACK = UE::UE_ENGINE_CALL_PLUGIN_DEBUG_CALLBACK
};

enum eBPRemoveOption : DWORD
{
	UE_OPTION_REMOVEALL = UE::UE_OPTION_REMOVEALL,
	UE_OPTION_DISABLEALL = UE::UE_OPTION_DISABLEALL,
	UE_OPTION_REMOVEALLDISABLED = UE::UE_OPTION_REMOVEALLDISABLED,
	UE_OPTION_REMOVEALLENABLED = UE::UE_OPTION_REMOVEALLENABLED
};

enum eAccess : DWORD
{
	UE_ACCESS_READ = UE::UE_ACCESS_READ,
	UE_ACCESS_WRITE = UE::UE_ACCESS_WRITE,
	UE_ACCESS_ALL = UE::UE_ACCESS_ALL
};

enum eDecryptionType : DWORD
{
	UE_STATIC_DECRYPTOR_XOR = UE::UE_STATIC_DECRYPTOR_XOR,
	UE_STATIC_DECRYPTOR_SUB = UE::UE_STATIC_DECRYPTOR_SUB,
	UE_STATIC_DECRYPTOR_ADD = UE::UE_STATIC_DECRYPTOR_ADD
};

enum eDecryptionDirection : DWORD
{
	UE_STATIC_DECRYPTOR_FOREWARD = UE::UE_STATIC_DECRYPTOR_FOREWARD,
	UE_STATIC_DECRYPTOR_BACKWARD = UE::UE_STATIC_DECRYPTOR_BACKWARD
};

enum eDecryptionKeySize : DWORD
{
	UE_STATIC_KEY_SIZE_1 = UE::UE_STATIC_KEY_SIZE_1,
	UE_STATIC_KEY_SIZE_2 = UE::UE_STATIC_KEY_SIZE_2,
	UE_STATIC_KEY_SIZE_4 = UE::UE_STATIC_KEY_SIZE_4,
	UE_STATIC_KEY_SIZE_8 = UE::UE_STATIC_KEY_SIZE_8
};

enum eCompressionAlgorithm : int
{
	UE_STATIC_APLIB = UE::UE_STATIC_APLIB,
	UE_STATIC_APLIB_DEPACK = UE::UE_STATIC_APLIB_DEPACK,
	UE_STATIC_LZMA = UE::UE_STATIC_LZMA
};

enum eHashAlgorithm : int
{
	UE_STATIC_HASH_MD5 = UE::UE_STATIC_HASH_MD5,
	UE_STATIC_HASH_SHA1 = UE::UE_STATIC_HASH_SHA1,
	UE_STATIC_HASH_CRC32 = UE::UE_STATIC_HASH_CRC32
};

const DWORD UE_RESOURCE_LANGUAGE_ANY = UE::UE_RESOURCE_LANGUAGE_ANY;

enum ePE32Data : DWORD
{
	UE_PE_OFFSET = UE::UE_PE_OFFSET,
	UE_IMAGEBASE = UE::UE_IMAGEBASE,
	UE_OEP = UE::UE_OEP,
	UE_SIZEOFIMAGE = UE::UE_SIZEOFIMAGE,
	UE_SIZEOFHEADERS = UE::UE_SIZEOFHEADERS,
	UE_SIZEOFOPTIONALHEADER = UE::UE_SIZEOFOPTIONALHEADER,
	UE_SECTIONALIGNMENT = UE::UE_SECTIONALIGNMENT,
	UE_IMPORTTABLEADDRESS = UE::UE_IMPORTTABLEADDRESS,
	UE_IMPORTTABLESIZE = UE::UE_IMPORTTABLESIZE,
	UE_RESOURCETABLEADDRESS = UE::UE_RESOURCETABLEADDRESS,
	UE_RESOURCETABLESIZE = UE::UE_RESOURCETABLESIZE,
	UE_EXPORTTABLEADDRESS = UE::UE_EXPORTTABLEADDRESS,
	UE_EXPORTTABLESIZE = UE::UE_EXPORTTABLESIZE,
	UE_TLSTABLEADDRESS = UE::UE_TLSTABLEADDRESS,
	UE_TLSTABLESIZE = UE::UE_TLSTABLESIZE,
	UE_RELOCATIONTABLEADDRESS = UE::UE_RELOCATIONTABLEADDRESS,
	UE_RELOCATIONTABLESIZE = UE::UE_RELOCATIONTABLESIZE,
	UE_TIMEDATESTAMP = UE::UE_TIMEDATESTAMP,
	UE_SECTIONNUMBER = UE::UE_SECTIONNUMBER,
	UE_CHECKSUM = UE::UE_CHECKSUM,
	UE_SUBSYSTEM = UE::UE_SUBSYSTEM,
	UE_CHARACTERISTICS = UE::UE_CHARACTERISTICS,
	UE_NUMBEROFRVAANDSIZES = UE::UE_NUMBEROFRVAANDSIZES,
	UE_SECTIONNAME = UE::UE_SECTIONNAME,
	UE_SECTIONVIRTUALOFFSET = UE::UE_SECTIONVIRTUALOFFSET,
	UE_SECTIONVIRTUALSIZE = UE::UE_SECTIONVIRTUALSIZE,
	UE_SECTIONRAWOFFSET = UE::UE_SECTIONRAWOFFSET,
	UE_SECTIONRAWSIZE = UE::UE_SECTIONRAWSIZE,
	UE_SECTIONFLAGS = UE::UE_SECTIONFLAGS
};

enum eCustomException : DWORD
{
	UE_CH_BREAKPOINT = UE::UE_CH_BREAKPOINT,
	UE_CH_SINGLESTEP = UE::UE_CH_SINGLESTEP,
	UE_CH_ACCESSVIOLATION = UE::UE_CH_ACCESSVIOLATION,
	UE_CH_ILLEGALINSTRUCTION = UE::UE_CH_ILLEGALINSTRUCTION,
	UE_CH_NONCONTINUABLEEXCEPTION = UE::UE_CH_NONCONTINUABLEEXCEPTION,
	UE_CH_ARRAYBOUNDSEXCEPTION = UE::UE_CH_ARRAYBOUNDSEXCEPTION,
	UE_CH_FLOATDENORMALOPERAND = UE::UE_CH_FLOATDENORMALOPERAND,
	UE_CH_FLOATDEVIDEBYZERO = UE::UE_CH_FLOATDEVIDEBYZERO,
	UE_CH_INTEGERDEVIDEBYZERO = UE::UE_CH_INTEGERDEVIDEBYZERO,
	UE_CH_INTEGEROVERFLOW = UE::UE_CH_INTEGEROVERFLOW,
	UE_CH_PRIVILEGEDINSTRUCTION = UE::UE_CH_PRIVILEGEDINSTRUCTION,
	UE_CH_PAGEGUARD = UE::UE_CH_PAGEGUARD,
	UE_CH_EVERYTHINGELSE = UE::UE_CH_EVERYTHINGELSE,
	UE_CH_CREATETHREAD = UE::UE_CH_CREATETHREAD,
	UE_CH_EXITTHREAD = UE::UE_CH_EXITTHREAD,
	UE_CH_CREATEPROCESS = UE::UE_CH_CREATEPROCESS,
	UE_CH_EXITPROCESS = UE::UE_CH_EXITPROCESS,
	UE_CH_LOADDLL = UE::UE_CH_LOADDLL,
	UE_CH_UNLOADDLL = UE::UE_CH_UNLOADDLL,
	UE_CH_OUTPUTDEBUGSTRING = UE::UE_CH_OUTPUTDEBUGSTRING
};

enum eHandlerReturnType : DWORD
{
	UE_OPTION_HANDLER_RETURN_HANDLECOUNT = UE::UE_OPTION_HANDLER_RETURN_HANDLECOUNT,
	UE_OPTION_HANDLER_RETURN_ACCESS = UE::UE_OPTION_HANDLER_RETURN_ACCESS,
	UE_OPTION_HANDLER_RETURN_FLAGS = UE::UE_OPTION_HANDLER_RETURN_FLAGS,
	UE_OPTION_HANDLER_RETURN_TYPENAME = UE::UE_OPTION_HANDLER_RETURN_TYPENAME
};

enum eBPState
{
	UE_BPXREMOVED = UE::UE_BPXREMOVED,
	UE_BPXACTIVE = UE::UE_BPXACTIVE,
	UE_BPXINACTIVE = UE::UE_BPXINACTIVE
};

enum eBPType
{
	UE_BREAKPOINT = UE::UE_BREAKPOINT,
	UE_SINGLESHOOT = UE::UE_SINGLESHOOT,
	//UE_HARDWARE = UE::UE_HARDWARE,
};

enum eMemoryBPType
{
	UE_MEMORY = UE::UE_MEMORY,
	UE_MEMORY_READ = UE::UE_MEMORY_READ,
	UE_MEMORY_WRITE = UE::UE_MEMORY_WRITE
};

enum eHWBPType : DWORD
{
	UE_HARDWARE_EXECUTE = UE::UE_HARDWARE_EXECUTE,
	UE_HARDWARE_WRITE = UE::UE_HARDWARE_WRITE,
	UE_HARDWARE_READWRITE = UE::UE_HARDWARE_READWRITE
};

enum eHWBPSize : DWORD
{
	UE_HARDWARE_SIZE_1 = UE::UE_HARDWARE_SIZE_1,
	UE_HARDWARE_SIZE_2 = UE::UE_HARDWARE_SIZE_2,
	UE_HARDWARE_SIZE_4 = UE::UE_HARDWARE_SIZE_4
};

enum eLibraryEvent : DWORD
{
	UE_ON_LIB_LOAD = UE::UE_ON_LIB_LOAD,
	UE_ON_LIB_UNLOAD = UE::UE_ON_LIB_UNLOAD,
	UE_ON_LIB_ALL = UE::UE_ON_LIB_ALL
};

enum eBPPlace : DWORD
{
	UE_APISTART = UE::UE_APISTART,
	UE_APIEND = UE::UE_APIEND
};

enum ePlatform : int
{
	UE_PLATFORM_x86 = UE::UE_PLATFORM_x86,
	UE_PLATFORM_x64 = UE::UE_PLATFORM_x64,
	UE_PLATFORM_ALL = UE::UE_PLATFORM_ALL
};

enum eFunctionType : DWORD
{
	UE_FUNCTION_STDCALL = UE::UE_FUNCTION_STDCALL,
	UE_FUNCTION_CCALL = UE::UE_FUNCTION_CCALL,
	UE_FUNCTION_FASTCALL = UE::UE_FUNCTION_FASTCALL,
	UE_FUNCTION_STDCALL_RET = UE::UE_FUNCTION_STDCALL_RET,
	UE_FUNCTION_CCALL_RET = UE::UE_FUNCTION_CCALL_RET,
	UE_FUNCTION_FASTCALL_RET = UE::UE_FUNCTION_FASTCALL_RET,
	UE_FUNCTION_STDCALL_CALL = UE::UE_FUNCTION_STDCALL_CALL,
	UE_FUNCTION_CCALL_CALL = UE::UE_FUNCTION_CCALL_CALL,
	UE_FUNCTION_FASTCALL_CALL = UE::UE_FUNCTION_FASTCALL_CALL
};

enum eParameterType : DWORD
{
	UE_PARAMETER_BYTE = UE::UE_PARAMETER_BYTE,
	UE_PARAMETER_WORD = UE::UE_PARAMETER_WORD,
	UE_PARAMETER_DWORD = UE::UE_PARAMETER_DWORD,
	UE_PARAMETER_QWORD = UE::UE_PARAMETER_QWORD,
	UE_PARAMETER_PTR_BYTE = UE::UE_PARAMETER_PTR_BYTE,
	UE_PARAMETER_PTR_WORD = UE::UE_PARAMETER_PTR_WORD,
	UE_PARAMETER_PTR_DWORD = UE::UE_PARAMETER_PTR_DWORD,
	UE_PARAMETER_PTR_QWORD = UE::UE_PARAMETER_PTR_QWORD,
	UE_PARAMETER_STRING = UE::UE_PARAMETER_STRING,
	UE_PARAMETER_UNICODE = UE::UE_PARAMETER_UNICODE
};

enum eCompareCondition : DWORD
{
	UE_CMP_NOCONDITION = UE::UE_CMP_NOCONDITION,
	UE_CMP_EQUAL = UE::UE_CMP_EQUAL,
	UE_CMP_NOTEQUAL = UE::UE_CMP_NOTEQUAL,
	UE_CMP_GREATER = UE::UE_CMP_GREATER,
	UE_CMP_GREATEROREQUAL = UE::UE_CMP_GREATEROREQUAL,
	UE_CMP_LOWER = UE::UE_CMP_LOWER,
	UE_CMP_LOWEROREQUAL = UE::UE_CMP_LOWEROREQUAL,
	UE_CMP_REG_EQUAL = UE::UE_CMP_REG_EQUAL,
	UE_CMP_REG_NOTEQUAL = UE::UE_CMP_REG_NOTEQUAL,
	UE_CMP_REG_GREATER = UE::UE_CMP_REG_GREATER,
	UE_CMP_REG_GREATEROREQUAL = UE::UE_CMP_REG_GREATEROREQUAL,
	UE_CMP_REG_LOWER = UE::UE_CMP_REG_LOWER,
	UE_CMP_REG_LOWEROREQUAL = UE::UE_CMP_REG_LOWEROREQUAL,
	UE_CMP_ALWAYSFALSE = UE::UE_CMP_ALWAYSFALSE
};

enum eContextData : DWORD
{
	UE_EAX = UE::UE_EAX,
	UE_EBX = UE::UE_EBX,
	UE_ECX = UE::UE_ECX,
	UE_EDX = UE::UE_EDX,
	UE_EDI = UE::UE_EDI,
	UE_ESI = UE::UE_ESI,
	UE_EBP = UE::UE_EBP,
	UE_ESP = UE::UE_ESP,
	UE_EIP = UE::UE_EIP,
	UE_EFLAGS = UE::UE_EFLAGS,
	UE_DR0 = UE::UE_DR0,
	UE_DR1 = UE::UE_DR1,
	UE_DR2 = UE::UE_DR2,
	UE_DR3 = UE::UE_DR3,
	UE_DR6 = UE::UE_DR6,
	UE_DR7 = UE::UE_DR7,
	UE_RAX = UE::UE_RAX,
	UE_RBX = UE::UE_RBX,
	UE_RCX = UE::UE_RCX,
	UE_RDX = UE::UE_RDX,
	UE_RDI = UE::UE_RDI,
	UE_RSI = UE::UE_RSI,
	UE_RBP = UE::UE_RBP,
	UE_RSP = UE::UE_RSP,
	UE_RIP = UE::UE_RIP,
	UE_RFLAGS = UE::UE_RFLAGS,
	UE_R8 = UE::UE_R8,
	UE_R9 = UE::UE_R9,
	UE_R10 = UE::UE_R10,
	UE_R11 = UE::UE_R11,
	UE_R12 = UE::UE_R12,
	UE_R13 = UE::UE_R13,
	UE_R14 = UE::UE_R14,
	UE_R15 = UE::UE_R15,
	UE_CIP = UE::UE_CIP,
	UE_CSP = UE::UE_CSP
};

enum eCheckDepth : DWORD
{
	UE_DEPTH_SURFACE = UE::UE_DEPTH_SURFACE,
	UE_DEPTH_DEEP = UE::UE_DEPTH_DEEP
};

enum eFieldState : BYTE
{
	UE_FIELD_OK = UE::UE_FIELD_OK,
	UE_FIELD_BROKEN_NON_FIXABLE = UE::UE_FIELD_BROKEN_NON_FIXABLE,
	UE_FIELD_BROKEN_NON_CRITICAL = UE::UE_FIELD_BROKEN_NON_CRITICAL,
	UE_FIELD_BROKEN_FIXABLE_FOR_STATIC_USE = UE::UE_FIELD_BROKEN_FIXABLE_FOR_STATIC_USE,
	UE_FIELD_BROKEN_BUT_CAN_BE_EMULATED = UE::UE_FIELD_BROKEN_BUT_CAN_BE_EMULATED,
	UE_FILED_FIXABLE_NON_CRITICAL = UE::UE_FILED_FIXABLE_NON_CRITICAL,
	UE_FILED_FIXABLE_CRITICAL = UE::UE_FILED_FIXABLE_CRITICAL,
	UE_FIELD_NOT_PRESET = UE::UE_FIELD_NOT_PRESET,
	UE_FIELD_NOT_PRESET_WARNING = UE::UE_FIELD_NOT_PRESET_WARNING
};

enum eFileState : BYTE
{
	UE_RESULT_FILE_OK = UE::UE_RESULT_FILE_OK,
	UE_RESULT_FILE_INVALID_BUT_FIXABLE = UE::UE_RESULT_FILE_INVALID_BUT_FIXABLE,
	UE_RESULT_FILE_INVALID_AND_NON_FIXABLE = UE::UE_RESULT_FILE_INVALID_AND_NON_FIXABLE,
	UE_RESULT_FILE_INVALID_FORMAT = UE::UE_RESULT_FILE_INVALID_FORMAT
};

// ----

class DumperA;
class DumperW;

class DumperX
{
	friend class DumperA;
	friend class DumperW;

protected:

	typedef UE::PEStruct PEStruct;

	static long long GetPE32DataFromMappedFile(ULONG_PTR FileMapVA, DWORD WhichSection, ePE32Data WhichData)
	{
		return UE::GetPE32DataFromMappedFile(FileMapVA, WhichSection, WhichData);
	}
	static bool GetPE32DataFromMappedFileEx(ULONG_PTR FileMapVA, PEStruct* DataStorage)
	{
		return UE::GetPE32DataFromMappedFileEx(FileMapVA, DataStorage);
	}
	static bool SetPE32DataForMappedFile(ULONG_PTR FileMapVA, DWORD WhichSection, ePE32Data WhichData, ULONG_PTR NewDataValue)
	{
		return UE::SetPE32DataForMappedFile(FileMapVA, WhichSection, WhichData, NewDataValue);
	}
	static bool SetPE32DataForMappedFileEx(ULONG_PTR FileMapVA, PEStruct* DataStorage)
	{
		return UE::SetPE32DataForMappedFileEx(FileMapVA, DataStorage);
	}
	static long GetPE32SectionNumberFromVA(ULONG_PTR FileMapVA, ULONG_PTR AddressToConvert)
	{
		return UE::GetPE32SectionNumberFromVA(FileMapVA, AddressToConvert);
	}
	static long long ConvertVAtoFileOffset(ULONG_PTR FileMapVA, ULONG_PTR AddressToConvert, bool ReturnType)
	{
		return UE::ConvertVAtoFileOffset(FileMapVA, AddressToConvert, ReturnType);
	}
	static long long ConvertVAtoFileOffsetEx(ULONG_PTR FileMapVA, DWORD FileSize, ULONG_PTR ImageBase, ULONG_PTR AddressToConvert, bool AddressIsRVA, bool ReturnType)
	{
		return UE::ConvertVAtoFileOffsetEx(FileMapVA, FileSize, ImageBase, AddressToConvert, AddressIsRVA, ReturnType);
	}
	static long long ConvertFileOffsetToVA(ULONG_PTR FileMapVA, ULONG_PTR AddressToConvert, bool ReturnType)
	{
		return UE::ConvertFileOffsetToVA(FileMapVA, AddressToConvert, ReturnType);
	}
	static long long ConvertFileOffsetToVAEx(ULONG_PTR FileMapVA, DWORD FileSize, ULONG_PTR ImageBase, ULONG_PTR AddressToConvert, bool ReturnType)
	{
		return UE::ConvertFileOffsetToVAEx(FileMapVA, FileSize, ImageBase, AddressToConvert, ReturnType);
	}
};

class DumperA
{
public:

	static bool DumpProcess(HANDLE hProcess, void* ImageBase, char* szDumpFileName, ULONG_PTR EntryPoint)
	{
		return UE::DumpProcess(hProcess, ImageBase, szDumpFileName, EntryPoint);
	}
	static bool DumpProcessEx(DWORD ProcessId, void* ImageBase, char* szDumpFileName, ULONG_PTR EntryPoint)
	{
		return UE::DumpProcessEx(ProcessId, ImageBase, szDumpFileName, EntryPoint);
	}
	static bool DumpMemory(HANDLE hProcess, void* MemoryStart, ULONG_PTR MemorySize, char* szDumpFileName)
	{
		return UE::DumpMemory(hProcess, MemoryStart, MemorySize, szDumpFileName);
	}
	static bool DumpMemoryEx(DWORD ProcessId, void* MemoryStart, ULONG_PTR MemorySize, char* szDumpFileName)
	{
		return UE::DumpMemoryEx(ProcessId, MemoryStart, MemorySize, szDumpFileName);
	}
	static bool DumpRegions(HANDLE hProcess, char* szDumpFolder, bool DumpAboveImageBaseOnly)
	{
		return UE::DumpRegions(hProcess, szDumpFolder, DumpAboveImageBaseOnly);
	}
	static bool DumpRegionsEx(DWORD ProcessId, char* szDumpFolder, bool DumpAboveImageBaseOnly)
	{
		return UE::DumpRegionsEx(ProcessId, szDumpFolder, DumpAboveImageBaseOnly);
	}
	static bool DumpModule(HANDLE hProcess, void* ModuleBase, char* szDumpFileName)
	{
		return UE::DumpModule(hProcess, ModuleBase, szDumpFileName);
	}
	static bool DumpModuleEx(DWORD ProcessId, void* ModuleBase, char* szDumpFileName)
	{
		return UE::DumpModuleEx(ProcessId, ModuleBase, szDumpFileName);
	}
	static bool PastePEHeader(HANDLE hProcess, void* ImageBase, char* szDebuggedFileName)
	{
		return UE::PastePEHeader(hProcess, ImageBase, szDebuggedFileName);
	}
	static bool ExtractSection(char* szFileName, char* szDumpFileName, DWORD SectionNumber)
	{
		return UE::ExtractSection(szFileName, szDumpFileName, SectionNumber);
	}
	static bool ResortFileSections(char* szFileName)
	{
		return UE::ResortFileSections(szFileName);
	}
	static bool FindOverlay(char* szFileName, DWORD* OverlayStart, DWORD* OverlaySize)
	{
		return UE::FindOverlay(szFileName, OverlayStart, OverlaySize);
	}
	static bool ExtractOverlay(char* szFileName, char* szExtractedFileName)
	{
		return UE::ExtractOverlay(szFileName, szExtractedFileName);
	}
	static bool AddOverlay(char* szFileName, char* szOverlayFileName)
	{
		return UE::AddOverlay(szFileName, szOverlayFileName);
	}
	static bool CopyOverlay(char* szInFileName, char* szOutFileName)
	{
		return UE::CopyOverlay(szInFileName, szOutFileName);
	}
	static bool RemoveOverlay(char* szFileName)
	{
		return UE::RemoveOverlay(szFileName);
	}
	static bool MakeAllSectionsRWE(char* szFileName)
	{
		return UE::MakeAllSectionsRWE(szFileName);
	}
	static long AddNewSectionEx(char* szFileName, char* szSectionName, DWORD SectionSize, DWORD SectionAttributes, void* SectionContent, DWORD ContentSize)
	{
		return UE::AddNewSectionEx(szFileName, szSectionName, SectionSize, SectionAttributes, SectionContent, ContentSize);
	}
	static long AddNewSection(char* szFileName, char* szSectionName, DWORD SectionSize)
	{
		return UE::AddNewSection(szFileName, szSectionName, SectionSize);
	}
	static bool ResizeLastSection(char* szFileName, DWORD NumberOfExpandBytes, bool AlignResizeData)
	{
		return UE::ResizeLastSection(szFileName, NumberOfExpandBytes, AlignResizeData);
	}
	static void SetSharedOverlay(char* szFileName)
	{
		return UE::SetSharedOverlay(szFileName);
	}
	static const char* GetSharedOverlay()
	{
		return UE::GetSharedOverlay();
	}
	static bool DeleteLastSection(char* szFileName)
	{
		return UE::DeleteLastSection(szFileName);
	}
	static bool DeleteLastSectionEx(char* szFileName, DWORD NumberOfSections)
	{
		return UE::DeleteLastSectionEx(szFileName, NumberOfSections);
	}
	static long long GetPE32Data(char* szFileName, DWORD WhichSection, ePE32Data WhichData)
	{
		return UE::GetPE32Data(szFileName, WhichSection, WhichData);
	}
	static bool GetPE32DataEx(char* szFileName, DumperX::PEStruct* DataStorage)
	{
		return UE::GetPE32DataEx(szFileName, DataStorage);
	}
	static bool SetPE32Data(char* szFileName, DWORD WhichSection, ePE32Data WhichData, ULONG_PTR NewDataValue)
	{
		return UE::SetPE32Data(szFileName, WhichSection, WhichData, NewDataValue);
	}
	static bool SetPE32DataEx(char* szFileName, DumperX::PEStruct* DataStorage)
	{
		return UE::SetPE32DataEx(szFileName, DataStorage);
	}
};

class DumperW
{
public:

	static bool DumpProcess(HANDLE hProcess, void* ImageBase, wchar_t* szDumpFileName, ULONG_PTR EntryPoint)
	{
		return UE::DumpProcessW(hProcess, ImageBase, szDumpFileName, EntryPoint);
	}
	static bool DumpProcessEx(DWORD ProcessId, void* ImageBase, wchar_t* szDumpFileName, ULONG_PTR EntryPoint)
	{
		return UE::DumpProcessExW(ProcessId, ImageBase, szDumpFileName, EntryPoint);
	}
	static bool DumpMemory(HANDLE hProcess, void* MemoryStart, ULONG_PTR MemorySize, wchar_t* szDumpFileName)
	{
		return UE::DumpMemoryW(hProcess, MemoryStart, MemorySize, szDumpFileName);
	}
	static bool DumpMemoryEx(DWORD ProcessId, void* MemoryStart, ULONG_PTR MemorySize, wchar_t* szDumpFileName)
	{
		return UE::DumpMemoryExW(ProcessId, MemoryStart, MemorySize, szDumpFileName);
	}
	static bool DumpRegions(HANDLE hProcess, wchar_t* szDumpFolder, bool DumpAboveImageBaseOnly)
	{
		return UE::DumpRegionsW(hProcess, szDumpFolder, DumpAboveImageBaseOnly);
	}
	static bool DumpRegionsEx(DWORD ProcessId, wchar_t* szDumpFolder, bool DumpAboveImageBaseOnly)
	{
		return UE::DumpRegionsExW(ProcessId, szDumpFolder, DumpAboveImageBaseOnly);
	}
	static bool DumpModule(HANDLE hProcess, void* ModuleBase, wchar_t* szDumpFileName)
	{
		return UE::DumpModuleW(hProcess, ModuleBase, szDumpFileName);
	}
	static bool DumpModuleEx(DWORD ProcessId, void* ModuleBase, wchar_t* szDumpFileName)
	{
		return UE::DumpModuleExW(ProcessId, ModuleBase, szDumpFileName);
	}
	static bool PastePEHeader(HANDLE hProcess, void* ImageBase, wchar_t* szDebuggedFileName)
	{
		return UE::PastePEHeaderW(hProcess, ImageBase, szDebuggedFileName);
	}
	static bool ExtractSection(wchar_t* szFileName, wchar_t* szDumpFileName, DWORD SectionNumber)
	{
		return UE::ExtractSectionW(szFileName, szDumpFileName, SectionNumber);
	}
	static bool ResortFileSections(wchar_t* szFileName)
	{
		return UE::ResortFileSectionsW(szFileName);
	}
	static bool FindOverlay(wchar_t* szFileName, DWORD* OverlayStart, DWORD* OverlaySize)
	{
		return UE::FindOverlayW(szFileName, OverlayStart, OverlaySize);
	}
	static bool ExtractOverlay(wchar_t* szFileName, wchar_t* szExtractedFileName)
	{
		return UE::ExtractOverlayW(szFileName, szExtractedFileName);
	}
	static bool AddOverlay(wchar_t* szFileName, wchar_t* szOverlayFileName)
	{
		return UE::AddOverlayW(szFileName, szOverlayFileName);
	}
	static bool CopyOverlay(wchar_t* szInFileName, wchar_t* szOutFileName)
	{
		return UE::CopyOverlayW(szInFileName, szOutFileName);
	}
	static bool RemoveOverlay(wchar_t* szFileName)
	{
		return UE::RemoveOverlayW(szFileName);
	}
	static bool MakeAllSectionsRWE(wchar_t* szFileName)
	{
		return UE::MakeAllSectionsRWEW(szFileName);
	}
	static long AddNewSectionEx(wchar_t* szFileName, char* szSectionName, DWORD SectionSize, DWORD SectionAttributes, void* SectionContent, DWORD ContentSize)
	{
		return UE::AddNewSectionExW(szFileName, szSectionName, SectionSize, SectionAttributes, SectionContent, ContentSize);
	}
	static long AddNewSection(wchar_t* szFileName, char* szSectionName, DWORD SectionSize)
	{
		return UE::AddNewSectionW(szFileName, szSectionName, SectionSize);
	}
	static bool ResizeLastSection(wchar_t* szFileName, DWORD NumberOfExpandBytes, bool AlignResizeData)
	{
		return UE::ResizeLastSectionW(szFileName, NumberOfExpandBytes, AlignResizeData);
	}
	static void SetSharedOverlay(wchar_t* szFileName)
	{
		return UE::SetSharedOverlayW(szFileName);
	}
	static const wchar_t* GetSharedOverlay()
	{
		return UE::GetSharedOverlayW();
	}
	static bool DeleteLastSection(wchar_t* szFileName)
	{
		return UE::DeleteLastSectionW(szFileName);
	}
	static bool DeleteLastSectionEx(wchar_t* szFileName, DWORD NumberOfSections)
	{
		return UE::DeleteLastSectionExW(szFileName, NumberOfSections);
	}
	static long long GetPE32Data(wchar_t* szFileName, DWORD WhichSection, ePE32Data WhichData)
	{
		return UE::GetPE32DataW(szFileName, WhichSection, WhichData);
	}
	static bool GetPE32DataEx(wchar_t* szFileName, DumperX::PEStruct* DataStorage)
	{
		return UE::GetPE32DataExW(szFileName, DataStorage);
	}
	static bool SetPE32Data(wchar_t* szFileName, DWORD WhichSection, ePE32Data WhichData, ULONG_PTR NewDataValue)
	{
		return UE::SetPE32DataW(szFileName, WhichSection, WhichData, NewDataValue);
	}
	static bool SetPE32DataEx(wchar_t* szFileName, DumperX::PEStruct* DataStorage)
	{
		return UE::SetPE32DataExW(szFileName, DataStorage);
	}
};

class Dumper : DumperX, DumperA, DumperW
{
public:

	using DumperX::PEStruct;

	using DumperA::DumpProcess;
	using DumperW::DumpProcess;
	using DumperA::DumpProcessEx;
	using DumperW::DumpProcessEx;
	using DumperA::DumpMemory;
	using DumperW::DumpMemory;
	using DumperA::DumpMemoryEx;
	using DumperW::DumpMemoryEx;
	using DumperA::DumpRegions;
	using DumperW::DumpRegions;
	using DumperA::DumpRegionsEx;
	using DumperW::DumpRegionsEx;
	using DumperA::DumpModule;
	using DumperW::DumpModule;
	using DumperA::DumpModuleEx;
	using DumperW::DumpModuleEx;
	using DumperA::PastePEHeader;
	using DumperW::PastePEHeader;
	using DumperA::ExtractSection;
	using DumperW::ExtractSection;
	using DumperA::ResortFileSections;
	using DumperW::ResortFileSections;
	using DumperA::FindOverlay;
	using DumperW::FindOverlay;
	using DumperA::ExtractOverlay;
	using DumperW::ExtractOverlay;
	using DumperA::AddOverlay;
	using DumperW::AddOverlay;
	using DumperA::CopyOverlay;
	using DumperW::CopyOverlay;
	using DumperA::RemoveOverlay;
	using DumperW::RemoveOverlay;
	using DumperA::MakeAllSectionsRWE;
	using DumperW::MakeAllSectionsRWE;
	using DumperA::AddNewSectionEx;
	using DumperW::AddNewSectionEx;
	using DumperA::AddNewSection;
	using DumperW::AddNewSection;
	using DumperA::ResizeLastSection;
	using DumperW::ResizeLastSection;
	using DumperA::SetSharedOverlay;
	using DumperW::SetSharedOverlay;
	#ifndef UNICODE
	using DumperA::GetSharedOverlay;
	#else
	using DumperW::GetSharedOverlay;
	#endif
	using DumperA::DeleteLastSection;
	using DumperW::DeleteLastSection;
	using DumperA::DeleteLastSectionEx;
	using DumperW::DeleteLastSectionEx;
	using DumperX::GetPE32DataFromMappedFile;
	using DumperA::GetPE32Data;
	using DumperW::GetPE32Data;
	using DumperX::GetPE32DataFromMappedFileEx;
	using DumperA::GetPE32DataEx;
	using DumperW::GetPE32DataEx;
	using DumperX::SetPE32DataForMappedFile;
	using DumperA::SetPE32Data;
	using DumperW::SetPE32Data;
	using DumperX::SetPE32DataForMappedFileEx;
	using DumperA::SetPE32DataEx;
	using DumperW::SetPE32DataEx;
	using DumperX::GetPE32SectionNumberFromVA;
	using DumperX::ConvertVAtoFileOffset;
	using DumperX::ConvertVAtoFileOffsetEx;
	using DumperX::ConvertFileOffsetToVA;
	using DumperX::ConvertFileOffsetToVAEx;
};

class RealignerA;
class RealignerW;

class RealignerX
{
	friend class RealignerA;
	friend class RealignerW;

protected:

	typedef UE::FILE_STATUS_INFO FILE_STATUS_INFO;
	typedef UE::FILE_FIX_INFO FILE_FIX_INFO;

	static long RealignPE(ULONG_PTR FileMapVA, DWORD FileSize, DWORD RealingMode)
	{
		return UE::RealignPE(FileMapVA, FileSize, RealingMode);
	}
};

class RealignerA
{
public:

	static bool FixHeaderCheckSum(char* szFileName)
	{
		return UE::FixHeaderCheckSum(szFileName);
	}
	static long RealignPEEx(char* szFileName, DWORD RealingFileSize, DWORD ForcedFileAlignment)
	{
		return UE::RealignPEEx(szFileName, RealingFileSize, ForcedFileAlignment);
	}
	static bool WipeSection(char* szFileName, int WipeSectionNumber, bool RemovePhysically)
	{
		return UE::WipeSection(szFileName, WipeSectionNumber, RemovePhysically);
	}
	static bool IsPE32FileValidEx(char* szFileName, eCheckDepth CheckDepth, RealignerX::FILE_STATUS_INFO* FileStatusInfo)
	{
		return UE::IsPE32FileValidEx(szFileName, CheckDepth, FileStatusInfo);
	}
	static bool FixBrokenPE32FileEx(char* szFileName, RealignerX::FILE_STATUS_INFO* FileStatusInfo, RealignerX::FILE_FIX_INFO* FileFixInfo)
	{
		return UE::FixBrokenPE32FileEx(szFileName, FileStatusInfo, FileFixInfo);
	}
	static bool IsFileDLL(char* szFileName, ULONG_PTR FileMapVA)
	{
		return UE::IsFileDLL(szFileName, FileMapVA);
	}
};

class RealignerW
{
public:

	static bool FixHeaderCheckSum(wchar_t* szFileName)
	{
		return UE::FixHeaderCheckSumW(szFileName);
	}
	static long RealignPEEx(wchar_t* szFileName, DWORD RealingFileSize, DWORD ForcedFileAlignment)
	{
		return UE::RealignPEExW(szFileName, RealingFileSize, ForcedFileAlignment);
	}
	static bool WipeSection(wchar_t* szFileName, int WipeSectionNumber, bool RemovePhysically)
	{
		return UE::WipeSectionW(szFileName, WipeSectionNumber, RemovePhysically);
	}
	static bool IsPE32FileValidEx(wchar_t* szFileName, eCheckDepth CheckDepth, RealignerX::FILE_STATUS_INFO* FileStatusInfo)
	{
		return UE::IsPE32FileValidExW(szFileName, CheckDepth, FileStatusInfo);
	}
	static bool FixBrokenPE32FileEx(wchar_t* szFileName, RealignerX::FILE_STATUS_INFO* FileStatusInfo, RealignerX::FILE_FIX_INFO* FileFixInfo)
	{
		return UE::FixBrokenPE32FileExW(szFileName, FileStatusInfo, FileFixInfo);
	}
	static bool IsFileDLL(wchar_t* szFileName, ULONG_PTR FileMapVA)
	{
		return UE::IsFileDLLW(szFileName, FileMapVA);
	}
};

class Realigner: RealignerX, RealignerA, RealignerW
{
public:

	using RealignerX::FILE_STATUS_INFO;
	using RealignerX::FILE_FIX_INFO;

	using RealignerA::FixHeaderCheckSum;
	using RealignerW::FixHeaderCheckSum;
	using RealignerX::RealignPE;
	using RealignerA::RealignPEEx;
	using RealignerW::RealignPEEx;
	using RealignerA::WipeSection;
	using RealignerW::WipeSection;
	using RealignerA::IsPE32FileValidEx;
	using RealignerW::IsPE32FileValidEx;
	using RealignerA::FixBrokenPE32FileEx;
	using RealignerW::FixBrokenPE32FileEx;
	using RealignerA::IsFileDLL;
	using RealignerW::IsFileDLL;
};

class Hider
{
public:

	static void* GetPEBLocation(HANDLE hProcess)
	{
		return UE::GetPEBLocation(hProcess);
	}
	static bool HideDebugger(HANDLE hProcess, eHideLevel PatchAPILevel)
	{
		return UE::HideDebugger(hProcess, PatchAPILevel);
	}
	static bool UnHideDebugger(HANDLE hProcess, eHideLevel PatchAPILevel)
	{
		return UE::UnHideDebugger(hProcess, PatchAPILevel);
	}
};

class RelocaterX
{
protected:

	static void Cleanup()
	{
		UE::RelocaterCleanup();
	}
	static void Init(DWORD MemorySize, ULONG_PTR OldImageBase, ULONG_PTR NewImageBase)
	{
		UE::RelocaterInit(MemorySize, OldImageBase, NewImageBase);
	}
	static void AddNewRelocation(HANDLE hProcess, ULONG_PTR RelocateAddress, DWORD RelocateState)
	{
		UE::RelocaterAddNewRelocation(hProcess, RelocateAddress, RelocateState);
	}
	static long EstimatedSize()
	{
		return UE::RelocaterEstimatedSize();
	}
	static bool ExportRelocation(ULONG_PTR StorePlace, DWORD StorePlaceRVA, ULONG_PTR FileMapVA)
	{
		return UE::RelocaterExportRelocation(StorePlace, StorePlaceRVA, FileMapVA);
	}
	static bool GrabRelocationTable(HANDLE hProcess, ULONG_PTR MemoryStart, DWORD MemorySize)
	{
		return UE::RelocaterGrabRelocationTable(hProcess, MemoryStart, MemorySize);
	}
	static bool GrabRelocationTableEx(HANDLE hProcess, ULONG_PTR MemoryStart, ULONG_PTR MemorySize, DWORD NtSizeOfImage)
	{
		return UE::RelocaterGrabRelocationTableEx(hProcess, MemoryStart, MemorySize, NtSizeOfImage);
	}
	static bool RelocateMemoryBlock(ULONG_PTR FileMapVA, ULONG_PTR MemoryLocation, void* RelocateMemory, DWORD RelocateMemorySize, ULONG_PTR CurrentLoadedBase, ULONG_PTR RelocateBase)
	{
		return UE::RelocaterRelocateMemoryBlock(FileMapVA, MemoryLocation, RelocateMemory, RelocateMemorySize, CurrentLoadedBase, RelocateBase);
	}
};

class RelocaterA
{
public:

	static bool ExportRelocationEx(char* szFileName, char* szSectionName)
	{
		return UE::RelocaterExportRelocationEx(szFileName, szSectionName);
	}
	static bool MakeSnapshot(HANDLE hProcess, char* szSaveFileName, void* MemoryStart, ULONG_PTR MemorySize)
	{
		return UE::RelocaterMakeSnapshot(hProcess, szSaveFileName, MemoryStart, MemorySize);
	}
	static bool CompareTwoSnapshots(HANDLE hProcess, ULONG_PTR LoadedImageBase, ULONG_PTR NtSizeOfImage, char* szDumpFile1, char* szDumpFile2, ULONG_PTR MemStart)
	{
		return UE::RelocaterCompareTwoSnapshots(hProcess, LoadedImageBase, NtSizeOfImage, szDumpFile1, szDumpFile2, MemStart);
	}
	static bool ChangeFileBase(char* szFileName, ULONG_PTR NewImageBase)
	{
		return UE::RelocaterChangeFileBase(szFileName, NewImageBase);
	}
	static bool WipeRelocationTable(char* szFileName)
	{
		return UE::RelocaterWipeRelocationTable(szFileName);
	}
};

class RelocaterW
{
public:

	static bool ExportRelocationEx(wchar_t* szFileName, char* szSectionName)
	{
		return UE::RelocaterExportRelocationExW(szFileName, szSectionName);
	}
	static bool MakeSnapshot(HANDLE hProcess, wchar_t* szSaveFileName, void* MemoryStart, ULONG_PTR MemorySize)
	{
		return UE::RelocaterMakeSnapshotW(hProcess, szSaveFileName, MemoryStart, MemorySize);
	}
	static bool CompareTwoSnapshots(HANDLE hProcess, ULONG_PTR LoadedImageBase, ULONG_PTR NtSizeOfImage, wchar_t* szDumpFile1, wchar_t* szDumpFile2, ULONG_PTR MemStart)
	{
		return UE::RelocaterCompareTwoSnapshotsW(hProcess, LoadedImageBase, NtSizeOfImage, szDumpFile1, szDumpFile2, MemStart);
	}
	static bool ChangeFileBase(wchar_t* szFileName, ULONG_PTR NewImageBase)
	{
		return UE::RelocaterChangeFileBaseW(szFileName, NewImageBase);
	}
	static bool WipeRelocationTable(wchar_t* szFileName)
	{
		return UE::RelocaterWipeRelocationTableW(szFileName);
	}
};

class Relocater : RelocaterX, RelocaterA, RelocaterW
{
public:

	using RelocaterX::Cleanup;
	using RelocaterX::Init;
	using RelocaterX::AddNewRelocation;
	using RelocaterX::EstimatedSize;
	using RelocaterX::ExportRelocation;
	using RelocaterA::ExportRelocationEx;
	using RelocaterW::ExportRelocationEx;
	using RelocaterX::GrabRelocationTable;
	using RelocaterX::GrabRelocationTableEx;
	using RelocaterA::MakeSnapshot;
	using RelocaterW::MakeSnapshot;
	using RelocaterA::CompareTwoSnapshots;
	using RelocaterW::CompareTwoSnapshots;
	using RelocaterA::ChangeFileBase;
	using RelocaterW::ChangeFileBase;
	using RelocaterX::RelocateMemoryBlock;
	using RelocaterA::WipeRelocationTable;
	using RelocaterW::WipeRelocationTable;
};

class ResourcerA;
class ResourcerW;

class ResourcerX
{
	friend class ResourcerA;
	friend class ResourcerW;

protected:

	typedef void(__stdcall *fResourceEnumCallback)(const wchar_t* szResourceType, DWORD ResourceType, const wchar_t* szResourceName, DWORD ResourceName, DWORD ResourceLanguage, DWORD ResourceData, DWORD ResourceSize);

	static bool FreeLoadedFile(void* LoadedFileBase)
	{
		return UE::ResourcerFreeLoadedFile(LoadedFileBase);
	}
	static bool ExtractResourceFromFileEx(ULONG_PTR FileMapVA, char* szResourceType, char* szResourceName, char* szExtractedFileName)
	{
		return UE::ResourcerExtractResourceFromFileEx(FileMapVA, szResourceType, szResourceName, szExtractedFileName);
	}
	static bool FindResourceEx(ULONG_PTR FileMapVA, DWORD FileSize, wchar_t* szResourceType, DWORD ResourceType, wchar_t* szResourceName, DWORD ResourceName, DWORD ResourceLanguage, ULONG_PTR* pResourceData, DWORD* pResourceSize)
	{
		return UE::ResourcerFindResourceEx(FileMapVA, FileSize, szResourceType, ResourceType, szResourceName, ResourceName, ResourceLanguage, pResourceData, pResourceSize);
	}
	static void EnumerateResourceEx(ULONG_PTR FileMapVA, DWORD FileSize, fResourceEnumCallback CallBack)
	{
		UE::ResourcerEnumerateResourceEx(FileMapVA, FileSize, (void*)CallBack);
	}
};

class ResourcerA
{
public:

	static long long LoadFileForResourceUse(char* szFileName)
	{
		return UE::ResourcerLoadFileForResourceUse(szFileName);
	}
	static bool ExtractResourceFromFile(char* szFileName, char* szResourceType, char* szResourceName, char* szExtractedFileName)
	{
		return UE::ResourcerExtractResourceFromFile(szFileName, szResourceType, szResourceName, szExtractedFileName);
	}
	static bool FindResource(char* szFileName, char* szResourceType, DWORD ResourceType, char* szResourceName, DWORD ResourceName, DWORD ResourceLanguage, ULONG_PTR* pResourceData, DWORD* pResourceSize)
	{
		return UE::ResourcerFindResource(szFileName, szResourceType, ResourceType, szResourceName, ResourceName, ResourceLanguage, pResourceData, pResourceSize);
	}
	static void EnumerateResource(char* szFileName, ResourcerX::fResourceEnumCallback CallBack)
	{
		UE::ResourcerEnumerateResource(szFileName, (void*)CallBack);
	}
};

class ResourcerW
{
public:

	static long long LoadFileForResourceUse(wchar_t* szFileName)
	{
		return UE::ResourcerLoadFileForResourceUseW(szFileName);
	}
	static bool ExtractResourceFromFile(wchar_t* szFileName, char* szResourceType, char* szResourceName, char* szExtractedFileName)
	{
		return UE::ResourcerExtractResourceFromFileW(szFileName, szResourceType, szResourceName, szExtractedFileName);
	}
	static bool FindResource(wchar_t* szFileName, wchar_t* szResourceType, DWORD ResourceType, wchar_t* szResourceName, DWORD ResourceName, DWORD ResourceLanguage, ULONG_PTR* pResourceData, DWORD* pResourceSize)
	{
		return UE::ResourcerFindResourceW(szFileName, szResourceType, ResourceType, szResourceName, ResourceName, ResourceLanguage, pResourceData, pResourceSize);
	}
	static void EnumerateResource(wchar_t* szFileName, ResourcerX::fResourceEnumCallback CallBack)
	{
		UE::ResourcerEnumerateResourceW(szFileName, (void*)CallBack);
	}
};

class Resourcer : ResourcerX, ResourcerA, ResourcerW
{
public:

	using ResourcerX::fResourceEnumCallback;

	using ResourcerA::LoadFileForResourceUse;
	using ResourcerW::LoadFileForResourceUse;
	using ResourcerX::FreeLoadedFile;
	using ResourcerX::ExtractResourceFromFileEx;
	using ResourcerA::ExtractResourceFromFile;
	using ResourcerW::ExtractResourceFromFile;
	using ResourcerA::FindResource;
	using ResourcerW::FindResource;
	using ResourcerX::FindResourceEx;
	using ResourcerA::EnumerateResource;
	using ResourcerW::EnumerateResource;
	using ResourcerX::EnumerateResourceEx;
};

class Threader
{
public:

	typedef UE::THREAD_ITEM_DATA THREAD_ITEM_DATA;

	typedef void(__stdcall *fThreadEnumCallback)(const THREAD_ITEM_DATA* fThreadDetail);
	typedef void(__stdcall *fThreadExitCallback)(const EXIT_THREAD_DEBUG_INFO* SpecialDBG);

	static bool ImportRunningThreadData(DWORD ProcessId)
	{
		return UE::ThreaderImportRunningThreadData(ProcessId);
	}
	static const THREAD_ITEM_DATA* GetThreadInfo(HANDLE hThread, DWORD ThreadId)
	{
		return (const THREAD_ITEM_DATA*)UE::ThreaderGetThreadInfo(hThread, ThreadId);
	}
	static void EnumThreadInfo(fThreadEnumCallback EnumCallBack)
	{
		UE::ThreaderEnumThreadInfo((void*)EnumCallBack);
	}
	static bool PauseThread(HANDLE hThread)
	{
		return UE::ThreaderPauseThread(hThread);
	}
	static bool ResumeThread(HANDLE hThread)
	{
		return UE::ThreaderResumeThread(hThread);
	}
	static bool TerminateThread(HANDLE hThread, DWORD ThreadExitCode)
	{
		return UE::ThreaderTerminateThread(hThread, ThreadExitCode);
	}
	static bool PauseAllThreads(bool LeaveMainRunning)
	{
		return UE::ThreaderPauseAllThreads(LeaveMainRunning);
	}
	static bool ResumeAllThreads(bool LeaveMainPaused)
	{
		return UE::ThreaderResumeAllThreads(LeaveMainPaused);
	}
	static bool PauseProcess()
	{
		return UE::ThreaderPauseProcess();
	}
	static bool ResumeProcess()
	{
		return UE::ThreaderResumeProcess();
	}
	static long long CreateRemoteThread(ULONG_PTR ThreadStartAddress, bool AutoCloseTheHandle, void* ThreadPassParameter, DWORD* ThreadId)
	{
		return UE::ThreaderCreateRemoteThread(ThreadStartAddress, AutoCloseTheHandle, ThreadPassParameter, ThreadId);
	}
	static bool InjectAndExecuteCode(void* InjectCode, DWORD StartDelta, DWORD InjectSize)
	{
		return UE::ThreaderInjectAndExecuteCode(InjectCode, StartDelta, InjectSize);
	}
	static long long CreateRemoteThreadEx(HANDLE hProcess, ULONG_PTR ThreadStartAddress, bool AutoCloseTheHandle, void* ThreadPassParameter, DWORD* ThreadId)
	{
		return UE::ThreaderCreateRemoteThreadEx(hProcess, ThreadStartAddress, AutoCloseTheHandle, ThreadPassParameter, ThreadId);
	}
	static bool InjectAndExecuteCodeEx(HANDLE hProcess, void* InjectCode, DWORD StartDelta, DWORD InjectSize)
	{
		return UE::ThreaderInjectAndExecuteCodeEx(hProcess, InjectCode, StartDelta, InjectSize);
	}
	static void SetCallBackForNextExitThreadEvent(fThreadExitCallback exitThreadCallBack)
	{
		UE::ThreaderSetCallBackForNextExitThreadEvent((void*)exitThreadCallBack);
	}
	static bool IsThreadStillRunning(HANDLE hThread)
	{
		return UE::ThreaderIsThreadStillRunning(hThread);
	}
	static bool IsThreadActive(HANDLE hThread)
	{
		return UE::ThreaderIsThreadActive(hThread);
	}
	static bool IsAnyThreadActive()
	{
		return UE::ThreaderIsAnyThreadActive();
	}
	static bool ExecuteOnlyInjectedThreads()
	{
		return UE::ThreaderExecuteOnlyInjectedThreads();
	}
	static long long GetOpenHandleForThread(DWORD ThreadId)
	{
		return UE::ThreaderGetOpenHandleForThread(ThreadId);
	}
	static const THREAD_ITEM_DATA* GetThreadData()
	{
		return (const THREAD_ITEM_DATA*)UE::ThreaderGetThreadData();
	}
	static bool IsExceptionInMainThread()
	{
		return UE::ThreaderIsExceptionInMainThread();
	}
};

// --

class DebuggerA;
class DebuggerW;

class DebuggerX
{
	friend class DebuggerA;
	friend class DebuggerW;

protected:

	typedef void(__stdcall *fBreakPointCallback)();
	typedef void(__stdcall *fCustomHandlerCallback)(void* ExceptionData);

	static const char* StaticDisassembleEx(ULONG_PTR DisassmStart, void* DisassmAddress)
	{
		return (const char*)UE::StaticDisassembleEx(DisassmStart, DisassmAddress);
	}
	static const char* StaticDisassemble(void* DisassmAddress)
	{
		return (const char*)UE::StaticDisassemble(DisassmAddress);
	}
	static const char* DisassembleEx(HANDLE hProcess, void* DisassmAddress, bool ReturnInstructionType)
	{
		return (const char*)UE::DisassembleEx(hProcess, DisassmAddress, ReturnInstructionType);
	}
	static const char* Disassemble(void* DisassmAddress)
	{
		return (const char*)UE::Disassemble(DisassmAddress);
	}
	static long StaticLengthDisassemble(void* DisassmAddress)
	{
		return UE::StaticLengthDisassemble(DisassmAddress);
	}
	static long LengthDisassembleEx(HANDLE hProcess, void* DisassmAddress)
	{
		return UE::LengthDisassembleEx(hProcess, DisassmAddress);
	}
	static long LengthDisassemble(void* DisassmAddress)
	{
		return UE::LengthDisassemble(DisassmAddress);
	}
	static bool StopDebug()
	{
		return UE::StopDebug();
	}
	static void SetBPXOptions(long DefaultBreakPointType)
	{
		UE::SetBPXOptions(DefaultBreakPointType);
	}
	static bool IsBPXEnabled(ULONG_PTR bpxAddress)
	{
		return UE::IsBPXEnabled(bpxAddress);
	}
	static bool EnableBPX(ULONG_PTR bpxAddress)
	{
		return UE::EnableBPX(bpxAddress);
	}
	static bool DisableBPX(ULONG_PTR bpxAddress)
	{
		return UE::DisableBPX(bpxAddress);
	}
	static bool SetBPX(ULONG_PTR bpxAddress, eBPType bpxType, fBreakPointCallback bpxCallBack)
	{
		return UE::SetBPX(bpxAddress, bpxType, (void*)bpxCallBack);
	}
	static bool SetBPXEx(ULONG_PTR bpxAddress, eBPType bpxType, DWORD NumberOfExecution, eContextData CmpRegister, eCompareCondition CmpCondition, ULONG_PTR CmpValue, fBreakPointCallback bpxCallBack, fBreakPointCallback bpxCompareCallBack, fBreakPointCallback bpxRemoveCallBack)
	{
		return UE::SetBPXEx(bpxAddress, bpxType, NumberOfExecution, CmpRegister, CmpCondition, CmpValue, (void*)bpxCallBack, (void*)bpxCompareCallBack, (void*)bpxRemoveCallBack);
	}
	static bool DeleteBPX(ULONG_PTR bpxAddress)
	{
		return UE::DeleteBPX(bpxAddress);
	}
	static bool SafeDeleteBPX(ULONG_PTR bpxAddress)
	{
		return UE::SafeDeleteBPX(bpxAddress);
	}
	static bool SetAPIBreakPoint(char* szDLLName, char* szAPIName, eBPType bpxType, eBPPlace bpxPlace, fBreakPointCallback bpxCallBack)
	{
		return UE::SetAPIBreakPoint(szDLLName, szAPIName, bpxType, bpxPlace, (void*)bpxCallBack);
	}
	static bool DeleteAPIBreakPoint(char* szDLLName, char* szAPIName, eBPPlace bpxPlace)
	{
		return UE::DeleteAPIBreakPoint(szDLLName, szAPIName, bpxPlace);
	}
	static bool SafeDeleteAPIBreakPoint(char* szDLLName, char* szAPIName, eBPPlace bpxPlace)
	{
		return UE::SafeDeleteAPIBreakPoint(szDLLName, szAPIName, bpxPlace);
	}
	static bool SetMemoryBPX(ULONG_PTR MemoryStart, DWORD SizeOfMemory, fBreakPointCallback bpxCallBack)
	{
		return UE::SetMemoryBPX(MemoryStart, SizeOfMemory, (void*)bpxCallBack);
	}
	static bool SetMemoryBPXEx(ULONG_PTR MemoryStart, DWORD SizeOfMemory, eMemoryBPType BreakPointType, bool RestoreOnHit, fBreakPointCallback bpxCallBack)
	{
		return UE::SetMemoryBPXEx(MemoryStart, SizeOfMemory, BreakPointType, RestoreOnHit, (void*)bpxCallBack);
	}
	static bool RemoveMemoryBPX(ULONG_PTR MemoryStart, DWORD SizeOfMemory)
	{
		return UE::RemoveMemoryBPX(MemoryStart, SizeOfMemory);
	}
	static bool GetContextFPUDataEx(HANDLE hActiveThread, void* FPUSaveArea)
	{
		return UE::GetContextFPUDataEx(hActiveThread, FPUSaveArea);
	}
	static long long GetContextDataEx(HANDLE hActiveThread, eContextData IndexOfRegister)
	{
		return UE::GetContextDataEx(hActiveThread, IndexOfRegister);
	}
	static long long GetContextData(eContextData IndexOfRegister)
	{
		return UE::GetContextData(IndexOfRegister);
	}
	static bool SetContextFPUDataEx(HANDLE hActiveThread, void* FPUSaveArea)
	{
		return UE::SetContextFPUDataEx(hActiveThread, FPUSaveArea);
	}
	static bool SetContextDataEx(HANDLE hActiveThread, eContextData IndexOfRegister, ULONG_PTR NewRegisterValue)
	{
		return UE::SetContextDataEx(hActiveThread, IndexOfRegister, NewRegisterValue);
	}
	static bool SetContextData(eContextData IndexOfRegister, ULONG_PTR NewRegisterValue)
	{
		return UE::SetContextData(IndexOfRegister, NewRegisterValue);
	}
	static void ClearExceptionNumber()
	{
		UE::ClearExceptionNumber();
	}
	static long CurrentExceptionNumber()
	{
		return UE::CurrentExceptionNumber();
	}
	static bool MatchPatternEx(HANDLE hProcess, void* MemoryToCheck, int SizeOfMemoryToCheck, void* PatternToMatch, int SizeOfPatternToMatch, PBYTE WildCard)
	{
		return UE::MatchPatternEx(hProcess, MemoryToCheck, SizeOfMemoryToCheck, PatternToMatch, SizeOfPatternToMatch, WildCard);
	}
	static bool MatchPattern(void* MemoryToCheck, int SizeOfMemoryToCheck, void* PatternToMatch, int SizeOfPatternToMatch, PBYTE WildCard)
	{
		return UE::MatchPattern(MemoryToCheck, SizeOfMemoryToCheck, PatternToMatch, SizeOfPatternToMatch, WildCard);
	}
	static long long FindEx(HANDLE hProcess, void* MemoryStart, DWORD MemorySize, void* SearchPattern, DWORD PatternSize, BYTE* WildCard)
	{
		return UE::FindEx(hProcess, MemoryStart, MemorySize, SearchPattern, PatternSize, WildCard);
	}
	static long long Find(void* MemoryStart, DWORD MemorySize, void* SearchPattern, DWORD PatternSize, BYTE* WildCard)
	{
		return UE::Find(MemoryStart, MemorySize, SearchPattern, PatternSize, WildCard);
	}
	static bool FillEx(HANDLE hProcess, void* MemoryStart, DWORD MemorySize, BYTE* FillByte)
	{
		return UE::FillEx(hProcess, MemoryStart, MemorySize, FillByte);
	}
	static bool Fill(void* MemoryStart, DWORD MemorySize, BYTE* FillByte)
	{
		return UE::Fill(MemoryStart, MemorySize, FillByte);
	}
	static bool PatchEx(HANDLE hProcess, void* MemoryStart, DWORD MemorySize, void* ReplacePattern, DWORD ReplaceSize, bool AppendNOP, bool PrependNOP)
	{
		return UE::PatchEx(hProcess, MemoryStart, MemorySize, ReplacePattern, ReplaceSize, AppendNOP, PrependNOP);
	}
	static bool Patch(void* MemoryStart, DWORD MemorySize, void* ReplacePattern, DWORD ReplaceSize, bool AppendNOP, bool PrependNOP)
	{
		return UE::Patch(MemoryStart, MemorySize, ReplacePattern, ReplaceSize, AppendNOP, PrependNOP);
	}
	static bool ReplaceEx(HANDLE hProcess, void* MemoryStart, DWORD MemorySize, void* SearchPattern, DWORD PatternSize, DWORD NumberOfRepetitions, void* ReplacePattern, DWORD ReplaceSize, BYTE* WildCard)
	{
		return UE::ReplaceEx(hProcess, MemoryStart, MemorySize, SearchPattern, PatternSize, NumberOfRepetitions, ReplacePattern, ReplaceSize, WildCard);
	}
	static bool Replace(void* MemoryStart, DWORD MemorySize, void* SearchPattern, DWORD PatternSize, DWORD NumberOfRepetitions, void* ReplacePattern, DWORD ReplaceSize, BYTE* WildCard)
	{
		return UE::Replace(MemoryStart, MemorySize, SearchPattern, PatternSize, NumberOfRepetitions, ReplacePattern, ReplaceSize, WildCard);
	}
	static const DEBUG_EVENT* GetDebugData()
	{
		return (const DEBUG_EVENT*)UE::GetDebugData();
	}
	static const DEBUG_EVENT* GetTerminationData()
	{
		return (const DEBUG_EVENT*)UE::GetTerminationData();
	}
	static long GetExitCode()
	{
		return UE::GetExitCode();
	}
	static long long GetDebuggedDLLBaseAddress()
	{
		return UE::GetDebuggedDLLBaseAddress();
	}
	static long long GetDebuggedFileBaseAddress()
	{
		return UE::GetDebuggedFileBaseAddress();
	}
	static bool GetRemoteString(HANDLE hProcess, void* StringAddress, void* StringStorage, int MaximumStringSize)
	{
		return UE::GetRemoteString(hProcess, StringAddress, StringStorage, MaximumStringSize);
	}
	static long long GetFunctionParameter(HANDLE hProcess, eFunctionType FunctionType, DWORD ParameterNumber, eParameterType ParameterType)
	{
		return UE::GetFunctionParameter(hProcess, FunctionType, ParameterNumber, ParameterType);
	}
	static long long GetJumpDestinationEx(HANDLE hProcess, ULONG_PTR InstructionAddress, bool JustJumps)
	{
		return UE::GetJumpDestinationEx(hProcess, InstructionAddress, JustJumps);
	}
	static long long GetJumpDestination(HANDLE hProcess, ULONG_PTR InstructionAddress)
	{
		return UE::GetJumpDestination(hProcess, InstructionAddress);
	}
	static bool IsJumpGoingToExecuteEx(HANDLE hProcess, HANDLE hThread, ULONG_PTR InstructionAddress, ULONG_PTR RegFlags)
	{
		return UE::IsJumpGoingToExecuteEx(hProcess, hThread, InstructionAddress, RegFlags);
	}
	static bool IsJumpGoingToExecute()
	{
		return UE::IsJumpGoingToExecute();
	}
	static void SetCustomHandler(eCustomException ExceptionId, fCustomHandlerCallback CallBack)
	{
		UE::SetCustomHandler(ExceptionId, (void*)CallBack);
	}
	static void ForceClose()
	{
		UE::ForceClose();
	}
	static void StepInto(fBreakPointCallback traceCallBack)
	{
		UE::StepInto((void*)traceCallBack);
	}
	static void StepOver(fBreakPointCallback traceCallBack)
	{
		UE::StepOver((void*)traceCallBack);
	}
	static void SingleStep(DWORD StepCount, fBreakPointCallback StepCallBack)
	{
		UE::SingleStep(StepCount, (void*)StepCallBack);
	}
	static bool GetUnusedHardwareBreakPointRegister(DWORD* RegisterIndex)
	{
		return UE::GetUnusedHardwareBreakPointRegister(RegisterIndex);
	}
	static bool SetHardwareBreakPointEx(HANDLE hActiveThread, ULONG_PTR bpxAddress, DWORD IndexOfRegister, eHWBPType bpxType, eHWBPSize bpxSize, fBreakPointCallback bpxCallBack, DWORD* IndexOfSelectedRegister)
	{
		return UE::SetHardwareBreakPointEx(hActiveThread, bpxAddress, IndexOfRegister, bpxType, bpxSize, (void*)bpxCallBack, IndexOfSelectedRegister);
	}
	static bool SetHardwareBreakPoint(ULONG_PTR bpxAddress, DWORD IndexOfRegister, eHWBPType bpxType, eHWBPSize bpxSize, fBreakPointCallback bpxCallBack)
	{
		return UE::SetHardwareBreakPoint(bpxAddress, IndexOfRegister, bpxType, bpxSize, (void*)bpxCallBack);
	}
	static bool DeleteHardwareBreakPoint(DWORD IndexOfRegister)
	{
		return UE::DeleteHardwareBreakPoint(IndexOfRegister);
	}
	static bool RemoveAllBreakPoints(eBPRemoveOption RemoveOption)
	{
		return UE::RemoveAllBreakPoints(RemoveOption);
	}
	static const PROCESS_INFORMATION* GetProcessInformation()
	{
		return (const PROCESS_INFORMATION*)UE::GetProcessInformation();
	}
	static const STARTUPINFOW* GetStartupInformation()
	{
		return (const STARTUPINFOW*)UE::GetStartupInformation();
	}
	static void DebugLoop()
	{
		UE::DebugLoop();
	}
	static void SetDebugLoopTimeOut(DWORD TimeOut)
	{
		UE::SetDebugLoopTimeOut(TimeOut);
	}
	static void SetNextDbgContinueStatus(DWORD SetDbgCode)
	{
		UE::SetNextDbgContinueStatus(SetDbgCode);
	}
	static bool AttachDebugger(DWORD ProcessId, bool KillOnExit, PROCESS_INFORMATION* DebugInfo, fBreakPointCallback CallBack)
	{
		return UE::AttachDebugger(ProcessId, KillOnExit, DebugInfo, (void*)CallBack);
	}
	static bool DetachDebugger(DWORD ProcessId)
	{
		return UE::DetachDebugger(ProcessId);
	}
	static bool DetachDebuggerEx(DWORD ProcessId)
	{
		return UE::DetachDebuggerEx(ProcessId);
	}
	static void DebugLoopEx(DWORD TimeOut)
	{
		UE::DebugLoopEx(TimeOut);
	}
	static bool IsFileBeingDebugged()
	{
		return UE::IsFileBeingDebugged();
	}
	static void SetErrorModel(bool DisplayErrorMessages)
	{
		return UE::SetErrorModel(DisplayErrorMessages);
	}
};

class DebuggerA
{
public:

	static const PROCESS_INFORMATION* InitDebug(char* szFileName, char* szCommandLine, char* szCurrentFolder)
	{
		return (const PROCESS_INFORMATION*)UE::InitDebug(szFileName, szCommandLine, szCurrentFolder);
	}
	static const PROCESS_INFORMATION* InitDebugEx(char* szFileName, char* szCommandLine, char* szCurrentFolder, DebuggerX::fBreakPointCallback EntryCallBack)
	{
		return (const PROCESS_INFORMATION*)UE::InitDebugEx(szFileName, szCommandLine, szCurrentFolder, (void*)EntryCallBack);
	}
	static const PROCESS_INFORMATION* InitDLLDebug(char* szFileName, bool ReserveModuleBase, char* szCommandLine, char* szCurrentFolder, DebuggerX::fBreakPointCallback EntryCallBack)
	{
		return (const PROCESS_INFORMATION*)UE::InitDLLDebug(szFileName, ReserveModuleBase, szCommandLine, szCurrentFolder, (void*)EntryCallBack);
	}
	static void AutoDebugEx(char* szFileName, bool ReserveModuleBase, char* szCommandLine, char* szCurrentFolder, DWORD TimeOut, DebuggerX::fBreakPointCallback EntryCallBack)
	{
		UE::AutoDebugEx(szFileName, ReserveModuleBase, szCommandLine, szCurrentFolder, TimeOut, (void*)EntryCallBack);
	}
};

class DebuggerW
{
public:

	static const PROCESS_INFORMATION* InitDebug(wchar_t* szFileName, wchar_t* szCommandLine, wchar_t* szCurrentFolder)
	{
		return (const PROCESS_INFORMATION*)UE::InitDebugW(szFileName, szCommandLine, szCurrentFolder);
	}
	static const PROCESS_INFORMATION* InitDebugEx(wchar_t* szFileName, wchar_t* szCommandLine, wchar_t* szCurrentFolder, DebuggerX::fBreakPointCallback EntryCallBack)
	{
		return (const PROCESS_INFORMATION*)UE::InitDebugExW(szFileName, szCommandLine, szCurrentFolder, (void*)EntryCallBack);
	}
	static const PROCESS_INFORMATION* InitDLLDebug(wchar_t* szFileName, bool ReserveModuleBase, wchar_t* szCommandLine, wchar_t* szCurrentFolder, DebuggerX::fBreakPointCallback EntryCallBack)
	{
		return (const PROCESS_INFORMATION*)UE::InitDLLDebugW(szFileName, ReserveModuleBase, szCommandLine, szCurrentFolder, (void*)EntryCallBack);
	}
	static void AutoDebugEx(wchar_t* szFileName, bool ReserveModuleBase, wchar_t* szCommandLine, wchar_t* szCurrentFolder, DWORD TimeOut, DebuggerX::fBreakPointCallback EntryCallBack)
	{
		UE::AutoDebugExW(szFileName, ReserveModuleBase, szCommandLine, szCurrentFolder, TimeOut, (void*)EntryCallBack);
	}
};

class Debugger : DebuggerX, DebuggerA, DebuggerW
{
public:

	using DebuggerX::fBreakPointCallback;
	using DebuggerX::fCustomHandlerCallback;

	using DebuggerX::StaticDisassembleEx;
	using DebuggerX::StaticDisassemble;
	using DebuggerX::DisassembleEx;
	using DebuggerX::Disassemble;
	using DebuggerX::StaticLengthDisassemble;
	using DebuggerX::LengthDisassembleEx;
	using DebuggerX::LengthDisassemble;
	using DebuggerA::InitDebug;
	using DebuggerW::InitDebug;
	using DebuggerA::InitDebugEx;
	using DebuggerW::InitDebugEx;
	using DebuggerA::InitDLLDebug;
	using DebuggerW::InitDLLDebug;
	using DebuggerX::StopDebug;
	using DebuggerX::SetBPXOptions;
	using DebuggerX::IsBPXEnabled;
	using DebuggerX::EnableBPX;
	using DebuggerX::DisableBPX;
	using DebuggerX::SetBPX;
	using DebuggerX::SetBPXEx;
	using DebuggerX::DeleteBPX;
	using DebuggerX::SafeDeleteBPX;
	using DebuggerX::SetAPIBreakPoint;
	using DebuggerX::DeleteAPIBreakPoint;
	using DebuggerX::SafeDeleteAPIBreakPoint;
	using DebuggerX::SetMemoryBPX;
	using DebuggerX::SetMemoryBPXEx;
	using DebuggerX::RemoveMemoryBPX;
	using DebuggerX::GetContextFPUDataEx;
	using DebuggerX::GetContextDataEx;
	using DebuggerX::GetContextData;
	using DebuggerX::SetContextFPUDataEx;
	using DebuggerX::SetContextDataEx;
	using DebuggerX::SetContextData;
	using DebuggerX::ClearExceptionNumber;
	using DebuggerX::CurrentExceptionNumber;
	using DebuggerX::MatchPatternEx;
	using DebuggerX::MatchPattern;
	using DebuggerX::FindEx;
	using DebuggerX::Find;
	using DebuggerX::FillEx;
	using DebuggerX::Fill;
	using DebuggerX::PatchEx;
	using DebuggerX::Patch;
	using DebuggerX::ReplaceEx;
	using DebuggerX::Replace;
	using DebuggerX::GetDebugData;
	using DebuggerX::GetTerminationData;
	using DebuggerX::GetExitCode;
	using DebuggerX::GetDebuggedDLLBaseAddress;
	using DebuggerX::GetDebuggedFileBaseAddress;
	using DebuggerX::GetRemoteString;
	using DebuggerX::GetFunctionParameter;
	using DebuggerX::GetJumpDestinationEx;
	using DebuggerX::GetJumpDestination;
	using DebuggerX::IsJumpGoingToExecuteEx;
	using DebuggerX::IsJumpGoingToExecute;
	using DebuggerX::SetCustomHandler;
	using DebuggerX::ForceClose;
	using DebuggerX::StepInto;
	using DebuggerX::StepOver;
	using DebuggerX::SingleStep;
	using DebuggerX::GetUnusedHardwareBreakPointRegister;
	using DebuggerX::SetHardwareBreakPointEx;
	using DebuggerX::SetHardwareBreakPoint;
	using DebuggerX::DeleteHardwareBreakPoint;
	using DebuggerX::RemoveAllBreakPoints;
	using DebuggerX::GetProcessInformation;
	using DebuggerX::GetStartupInformation;
	using DebuggerX::DebugLoop;
	using DebuggerX::SetDebugLoopTimeOut;
	using DebuggerX::SetNextDbgContinueStatus;
	using DebuggerX::AttachDebugger;
	using DebuggerX::DetachDebugger;
	using DebuggerX::DetachDebuggerEx;
	using DebuggerX::DebugLoopEx;
	using DebuggerA::AutoDebugEx;
	using DebuggerW::AutoDebugEx;
	using DebuggerX::IsFileBeingDebugged;
	using DebuggerX::SetErrorModel;
};

class FindOEPX
{
protected:

	static void Init()
	{
		return UE::FindOEPInit();
	}
};

class FindOEPA
{
public:

	static bool Generically(char* szFileName, Debugger::fBreakPointCallback TraceInitCallBack, Debugger::fBreakPointCallback CallBack)
	{
		return UE::FindOEPGenerically(szFileName, (void*)TraceInitCallBack, (void*)CallBack);
	}
};

class FindOEPW
{
public:

	static bool Generically(wchar_t* szFileName, Debugger::fBreakPointCallback TraceInitCallBack, Debugger::fBreakPointCallback CallBack)
	{
		return UE::FindOEPGenericallyW(szFileName, (void*)TraceInitCallBack, (void*)CallBack);
	}
};

class FindOEP : FindOEPX, FindOEPA, FindOEPW
{
public:

	using FindOEPX::Init;
	using FindOEPA::Generically;
	using FindOEPW::Generically;
};

class ImporterA;
class ImporterW;

class ImporterX
{
	friend class ImporterA;
	friend class ImporterW;

protected:

	typedef UE::ImportEnumData ImportEnumData;

	typedef void(__stdcall *fImportEnumCallBack)(const ImportEnumData* ptrImportEnumData);
	typedef void*(__stdcall *fImportFixCallback)(void* fIATPointer);

	static void Cleanup()
	{
		UE::ImporterCleanup();
	}
	static void SetImageBase(ULONG_PTR ImageBase)
	{
		UE::ImporterSetImageBase(ImageBase);
	}
	static void SetUnknownDelta(ULONG_PTR DeltaAddress)
	{
		UE::ImporterSetUnknownDelta(DeltaAddress);
	}
	static long long GetCurrentDelta()
	{
		return UE::ImporterGetCurrentDelta();
	}
	static void Init(DWORD MemorySize, ULONG_PTR ImageBase)
	{
		UE::ImporterInit(MemorySize, ImageBase);
	}
	static void AddNewDll(char* szDLLName, ULONG_PTR FirstThunk)
	{
		UE::ImporterAddNewDll(szDLLName, FirstThunk);
	}
	static void AddNewAPI(char* szAPIName, ULONG_PTR ThunkValue)
	{
		UE::ImporterAddNewAPI(szAPIName, ThunkValue);
	}
	static void AddNewOrdinalAPI(ULONG_PTR OrdinalNumber, ULONG_PTR ThunkValue)
	{
		UE::ImporterAddNewOrdinalAPI(OrdinalNumber, ThunkValue);
	}
	static long GetAddedDllCount()
	{
		return UE::ImporterGetAddedDllCount();
	}
	static long GetAddedAPICount()
	{
		return UE::ImporterGetAddedAPICount();
	}
	static const char* GetLastAddedDLLName()
	{
		return (const char*)UE::ImporterGetLastAddedDLLName();
	}
	static void MoveIAT()
	{
		UE::ImporterMoveIAT();
	}
	static bool ExportIAT(ULONG_PTR StorePlace, ULONG_PTR FileMapVA)
	{
		return UE::ImporterExportIAT(StorePlace, FileMapVA);
	}
	static long EstimatedSize()
	{
		return UE::ImporterEstimatedSize();
	}
	static long long FindAPIWriteLocation(char* szAPIName)
	{
		return UE::ImporterFindAPIWriteLocation(szAPIName);
	}
	static long long FindOrdinalAPIWriteLocation(ULONG_PTR OrdinalNumber)
	{
		return UE::ImporterFindOrdinalAPIWriteLocation(OrdinalNumber);
	}
	static long long FindAPIByWriteLocation(ULONG_PTR APIWriteLocation)
	{
		return UE::ImporterFindAPIByWriteLocation(APIWriteLocation);
	}
	static long long FindDLLByWriteLocation(ULONG_PTR APIWriteLocation)
	{
		return UE::ImporterFindDLLByWriteLocation(APIWriteLocation);
	}
	static const char* GetDLLName(ULONG_PTR APIAddress)
	{
		return (const char*)UE::ImporterGetDLLName(APIAddress);
	}
	static const char* GetAPIName(ULONG_PTR APIAddress)
	{
		return (const char*)UE::ImporterGetAPIName(APIAddress);
	}
	static long long GetAPIOrdinalNumber(ULONG_PTR APIAddress)
	{
		return UE::ImporterGetAPIOrdinalNumber(APIAddress);
	}
	static const char* GetAPINameEx(ULONG_PTR APIAddress, HMODULE* DLLBasesList)
	{
		return (const char*)UE::ImporterGetAPINameEx(APIAddress, (ULONG_PTR)DLLBasesList);
	}
	static long long GetRemoteAPIAddress(HANDLE hProcess, ULONG_PTR APIAddress)
	{
		return UE::ImporterGetRemoteAPIAddress(hProcess, APIAddress);
	}
	static long long GetRemoteAPIAddressEx(char* szDLLName, char* szAPIName)
	{
		return UE::ImporterGetRemoteAPIAddressEx(szDLLName, szAPIName);
	}
	static long long GetLocalAPIAddress(HANDLE hProcess, ULONG_PTR APIAddress)
	{
		return UE::ImporterGetLocalAPIAddress(hProcess, APIAddress);
	}
	static const char* GetDLLNameFromDebugee(HANDLE hProcess, ULONG_PTR APIAddress)
	{
		return (const char*)UE::ImporterGetDLLNameFromDebugee(hProcess, APIAddress);
	}
	static const char* GetAPINameFromDebugee(HANDLE hProcess, ULONG_PTR APIAddress)
	{
		return (const char*)UE::ImporterGetAPINameFromDebugee(hProcess, APIAddress);
	}
	static long long GetAPIOrdinalNumberFromDebugee(HANDLE hProcess, ULONG_PTR APIAddress)
	{
		return UE::ImporterGetAPIOrdinalNumberFromDebugee(hProcess, APIAddress);
	}
	static long GetDLLIndexEx(ULONG_PTR APIAddress, HMODULE* DLLBasesList)
	{
		return UE::ImporterGetDLLIndexEx(APIAddress, (ULONG_PTR)DLLBasesList);
	}
	static long GetDLLIndex(HANDLE hProcess, ULONG_PTR APIAddress, HMODULE* DLLBasesList)
	{
		return UE::ImporterGetDLLIndex(hProcess, APIAddress, (ULONG_PTR)DLLBasesList);
	}
	static long long GetRemoteDLLBase(HANDLE hProcess, HMODULE LocalModuleBase)
	{
		return UE::ImporterGetRemoteDLLBase(hProcess, LocalModuleBase);
	}
	static bool RelocateWriteLocation(ULONG_PTR AddValue)
	{
		return UE::ImporterRelocateWriteLocation(AddValue);
	}
	static bool IsForwardedAPI(HANDLE hProcess, ULONG_PTR APIAddress)
	{
		return UE::ImporterIsForwardedAPI(hProcess, APIAddress);
	}
	static const char* GetForwardedAPIName(HANDLE hProcess, ULONG_PTR APIAddress)
	{
		return (const char*)UE::ImporterGetForwardedAPIName(hProcess, APIAddress);
	}
	static const char* GetForwardedDLLName(HANDLE hProcess, ULONG_PTR APIAddress)
	{
		return (const char*)UE::ImporterGetForwardedDLLName(hProcess, APIAddress);
	}
	static long GetForwardedDLLIndex(HANDLE hProcess, ULONG_PTR APIAddress, HMODULE* DLLBasesList)
	{
		return UE::ImporterGetForwardedDLLIndex(hProcess, APIAddress, (ULONG_PTR)DLLBasesList);
	}
	static long long GetForwardedAPIOrdinalNumber(HANDLE hProcess, ULONG_PTR APIAddress)
	{
		return UE::ImporterGetForwardedAPIOrdinalNumber(hProcess, APIAddress);
	}
	static long long GetNearestAPIAddress(HANDLE hProcess, ULONG_PTR APIAddress)
	{
		return UE::ImporterGetNearestAPIAddress(hProcess, APIAddress);
	}
	static const char* GetNearestAPIName(HANDLE hProcess, ULONG_PTR APIAddress)
	{
		return (const char*)UE::ImporterGetNearestAPIName(hProcess, APIAddress);
	}
	static void AutoSearchIATEx(HANDLE hProcess, ULONG_PTR ImageBase, ULONG_PTR SearchStart, DWORD SearchSize, ULONG_PTR* pIATStart, ULONG_PTR* pIATSize)
	{
		UE::ImporterAutoSearchIATEx(hProcess, ImageBase, SearchStart, SearchSize, pIATStart, pIATSize);
	}
	static void EnumAddedData(fImportEnumCallBack EnumCallBack)
	{
		UE::ImporterEnumAddedData((void*)EnumCallBack);
	}
};

class ImporterA
{
public:

	static bool ExportIATEx(char* szExportFileName, char* szSectionName)
	{
		return UE::ImporterExportIATEx(szExportFileName, szSectionName);
	}
	static bool CopyOriginalIAT(char* szOriginalFile, char* szDumpFile)
	{
		return UE::ImporterCopyOriginalIAT(szOriginalFile, szDumpFile);
	}
	static bool LoadImportTable(char* szFileName)
	{
		return UE::ImporterLoadImportTable(szFileName);
	}
	static bool MoveOriginalIAT(char* szOriginalFile, char* szDumpFile, char* szSectionName)
	{
		return UE::ImporterMoveOriginalIAT(szOriginalFile, szDumpFile, szSectionName);
	}
	static void AutoSearchIAT(HANDLE hProcess, char* szFileName, ULONG_PTR ImageBase, ULONG_PTR SearchStart, DWORD SearchSize, ULONG_PTR* pIATStart, ULONG_PTR* pIATSize)
	{
		UE::ImporterAutoSearchIAT(hProcess, szFileName, ImageBase, SearchStart, SearchSize, pIATStart, pIATSize);
	}
	static long AutoFixIATEx(HANDLE hProcess, char* szDumpedFile, char* szSectionName, bool DumpRunningProcess, bool RealignFile, ULONG_PTR EntryPointAddress, ULONG_PTR ImageBase, ULONG_PTR SearchStart, DWORD SearchSize, DWORD SearchStep, bool TryAutoFix, bool FixEliminations, ImporterX::fImportFixCallback UnknownPointerFixCallback)
	{
		return UE::ImporterAutoFixIATEx(hProcess, szDumpedFile, szSectionName, DumpRunningProcess, RealignFile, EntryPointAddress, ImageBase, SearchStart, SearchSize, SearchStep, TryAutoFix, FixEliminations, (void*)UnknownPointerFixCallback);
	}
	static long AutoFixIAT(HANDLE hProcess, char* szDumpedFile, ULONG_PTR ImageBase, ULONG_PTR SearchStart, DWORD SearchSize, DWORD SearchStep)
	{
		return UE::ImporterAutoFixIAT(hProcess, szDumpedFile, ImageBase, SearchStart, SearchSize, SearchStep);
	}
};

class ImporterW
{
public:

	static bool ExportIATEx(wchar_t* szExportFileName, char* szSectionName)
	{
		return UE::ImporterExportIATExW(szExportFileName, szSectionName);
	}
	static bool CopyOriginalIAT(wchar_t* szOriginalFile, wchar_t* szDumpFile)
	{
		return UE::ImporterCopyOriginalIATW(szOriginalFile, szDumpFile);
	}
	static bool LoadImportTable(wchar_t* szFileName)
	{
		return UE::ImporterLoadImportTableW(szFileName);
	}
	static bool MoveOriginalIAT(wchar_t* szOriginalFile, wchar_t* szDumpFile, char* szSectionName)
	{
		return UE::ImporterMoveOriginalIATW(szOriginalFile, szDumpFile, szSectionName);
	}
	static void AutoSearchIAT(HANDLE hProcess, wchar_t* szFileName, ULONG_PTR ImageBase, ULONG_PTR SearchStart, DWORD SearchSize, ULONG_PTR* pIATStart, ULONG_PTR* pIATSize)
	{
		UE::ImporterAutoSearchIATW(hProcess, szFileName, ImageBase, SearchStart, SearchSize, pIATStart, pIATSize);
	}
	static long AutoFixIATEx(HANDLE hProcess, wchar_t* szDumpedFile, char* szSectionName, bool DumpRunningProcess, bool RealignFile, ULONG_PTR EntryPointAddress, ULONG_PTR ImageBase, ULONG_PTR SearchStart, DWORD SearchSize, DWORD SearchStep, bool TryAutoFix, bool FixEliminations, ImporterX::fImportFixCallback UnknownPointerFixCallback)
	{
		return UE::ImporterAutoFixIATExW(hProcess, szDumpedFile, szSectionName, DumpRunningProcess, RealignFile, EntryPointAddress, ImageBase, SearchStart, SearchSize, SearchStep, TryAutoFix, FixEliminations, (void*)UnknownPointerFixCallback);
	}
	static long AutoFixIAT(HANDLE hProcess, wchar_t* szDumpedFile, ULONG_PTR ImageBase, ULONG_PTR SearchStart, DWORD SearchSize, DWORD SearchStep)
	{
		return UE::ImporterAutoFixIATW(hProcess, szDumpedFile, ImageBase, SearchStart, SearchSize, SearchStep);
	}
};

class Importer : ImporterX, ImporterA, ImporterW
{
public:

	using ImporterX::fImportEnumCallBack;
	using ImporterX::fImportFixCallback;

	using ImporterX::Cleanup;
	using ImporterX::SetImageBase;
	using ImporterX::SetUnknownDelta;
	using ImporterX::GetCurrentDelta;
	using ImporterX::Init;
	using ImporterX::AddNewDll;
	using ImporterX::AddNewAPI;
	using ImporterX::AddNewOrdinalAPI;
	using ImporterX::GetAddedDllCount;
	using ImporterX::GetAddedAPICount;
	using ImporterX::GetLastAddedDLLName;
	using ImporterX::MoveIAT;
	using ImporterX::ExportIAT;
	using ImporterX::EstimatedSize;
	using ImporterA::ExportIATEx;
	using ImporterW::ExportIATEx;
	using ImporterX::FindAPIWriteLocation;
	using ImporterX::FindOrdinalAPIWriteLocation;
	using ImporterX::FindAPIByWriteLocation;
	using ImporterX::FindDLLByWriteLocation;
	using ImporterX::GetDLLName;
	using ImporterX::GetAPIName;
	using ImporterX::GetAPIOrdinalNumber;
	using ImporterX::GetAPINameEx;
	using ImporterX::GetRemoteAPIAddress;
	using ImporterX::GetRemoteAPIAddressEx;
	using ImporterX::GetLocalAPIAddress;
	using ImporterX::GetDLLNameFromDebugee;
	using ImporterX::GetAPINameFromDebugee;
	using ImporterX::GetAPIOrdinalNumberFromDebugee;
	using ImporterX::GetDLLIndexEx;
	using ImporterX::GetDLLIndex;
	using ImporterX::GetRemoteDLLBase;
	using ImporterX::RelocateWriteLocation;
	using ImporterX::IsForwardedAPI;
	using ImporterX::GetForwardedAPIName;
	using ImporterX::GetForwardedDLLName;
	using ImporterX::GetForwardedDLLIndex;
	using ImporterX::GetForwardedAPIOrdinalNumber;
	using ImporterX::GetNearestAPIAddress;
	using ImporterX::GetNearestAPIName;
	using ImporterA::CopyOriginalIAT;
	using ImporterW::CopyOriginalIAT;
	using ImporterA::LoadImportTable;
	using ImporterW::LoadImportTable;
	using ImporterA::MoveOriginalIAT;
	using ImporterW::MoveOriginalIAT;
	using ImporterA::AutoSearchIAT;
	using ImporterW::AutoSearchIAT;
	using ImporterX::AutoSearchIATEx;
	using ImporterX::EnumAddedData;
	using ImporterA::AutoFixIATEx;
	using ImporterW::AutoFixIATEx;
	using ImporterA::AutoFixIAT;
	using ImporterW::AutoFixIAT;
};

// ---

class LibrarianX
{
protected:

	typedef void(__stdcall *fLibraryBreakPointCallback)(const LOAD_DLL_DEBUG_INFO* SpecialDBG);

	static bool SetBreakPoint(char* szLibraryName, eLibraryEvent bpxType, bool SingleShoot, fLibraryBreakPointCallback bpxCallBack)
	{
		return UE::LibrarianSetBreakPoint(szLibraryName, bpxType, SingleShoot, (void*)bpxCallBack);
	}
	static bool RemoveBreakPoint(char* szLibraryName, eLibraryEvent bpxType)
	{
		return UE::LibrarianRemoveBreakPoint(szLibraryName, bpxType);
	}
};

class LibrarianA
{
public:

	typedef UE::LIBRARY_ITEM_DATA LIBRARY_ITEM_DATA;

	typedef void(__stdcall *fLibraryEnumCallback)(const LIBRARY_ITEM_DATA* fLibraryDetail);

	static const LIBRARY_ITEM_DATA* GetLibraryInfo(char* szLibraryName)
	{
		return (const LIBRARY_ITEM_DATA*)UE::LibrarianGetLibraryInfo(szLibraryName);
	}
	static const LIBRARY_ITEM_DATA* GetLibraryInfoEx(void* BaseOfDll)
	{
		return (const LIBRARY_ITEM_DATA*)UE::LibrarianGetLibraryInfoEx(BaseOfDll);
	}
	static void EnumLibraryInfo(fLibraryEnumCallback EnumCallBack)
	{
		UE::LibrarianEnumLibraryInfo((void*)EnumCallBack);
	}
};

class LibrarianW
{
public:

	typedef UE::LIBRARY_ITEM_DATAW LIBRARY_ITEM_DATA;

	typedef void(__stdcall *fLibraryEnumCallback)(const LIBRARY_ITEM_DATA* fLibraryDetail);

	static const LIBRARY_ITEM_DATA* GetLibraryInfo(wchar_t* szLibraryName)
	{
		return (const LIBRARY_ITEM_DATA*)UE::LibrarianGetLibraryInfoW(szLibraryName);
	}
	static const LIBRARY_ITEM_DATA* GetLibraryInfoEx(void* BaseOfDll)
	{
		return (const LIBRARY_ITEM_DATA*)UE::LibrarianGetLibraryInfoExW(BaseOfDll);
	}
	static void EnumLibraryInfo(fLibraryEnumCallback EnumCallBack)
	{
		UE::LibrarianEnumLibraryInfoW((void*)EnumCallBack);
	}
};

class Librarian : LibrarianX, LibrarianA, LibrarianW
{
public:

	#ifndef UNICODE
	typedef LibrarianA::LIBRARY_ITEM_DATA LIBRARY_ITEM_DATA;
	#else
	typedef LibrarianW::LIBRARY_ITEM_DATA LIBRARY_ITEM_DATA;
	#endif

	using LibrarianX::fLibraryBreakPointCallback;
	#ifndef UNICODE
	typedef LibrarianA::fLibraryEnumCallback fLibraryEnumCallback;
	#else
	typedef LibrarianW::fLibraryEnumCallback fLibraryEnumCallback;
	#endif

	using LibrarianX::SetBreakPoint;
	using LibrarianX::RemoveBreakPoint;
	using LibrarianA::GetLibraryInfo;
	using LibrarianW::GetLibraryInfo;
	#ifndef UNICODE
	using LibrarianA::GetLibraryInfoEx;
	#else
	using LibrarianW::GetLibraryInfoEx;
	#endif
	using LibrarianA::EnumLibraryInfo;
	using LibrarianW::EnumLibraryInfo;
};

class Hooks
{
public:

	typedef UE::HOOK_ENTRY HOOK_ENTRY;

	typedef bool(__stdcall *fHookEnumCallBack)(const HOOK_ENTRY* HookDetails, void* ptrOriginalInstructions, const LibrarianA::LIBRARY_ITEM_DATA* ModuleInformation, DWORD SizeOfImage);

	static bool SafeTransitionEx(void** HookAddressArray, int NumberOfHooks, bool TransitionStart)
	{
		return UE::HooksSafeTransitionEx(HookAddressArray, NumberOfHooks, TransitionStart);
	}
	static bool SafeTransition(void* HookAddress, bool TransitionStart)
	{
		return UE::HooksSafeTransition(HookAddress, TransitionStart);
	}
	static bool IsAddressRedirected(void* HookAddress)
	{
		return UE::HooksIsAddressRedirected(HookAddress);
	}
	static void* GetTrampolineAddress(void* HookAddress)
	{
		return UE::HooksGetTrampolineAddress(HookAddress);
	}
	static HOOK_ENTRY* GetHookEntryDetails(void* HookAddress)
	{
		return (HOOK_ENTRY*)UE::HooksGetHookEntryDetails(HookAddress);
	}
	static bool InsertNewRedirection(void* HookAddress, void* RedirectTo, eHookType HookType)
	{
		return UE::HooksInsertNewRedirection(HookAddress, RedirectTo, HookType);
	}
	static bool InsertNewIATRedirectionEx(ULONG_PTR FileMapVA, ULONG_PTR LoadedModuleBase, char* szHookFunction, void* RedirectTo)
	{
		return UE::HooksInsertNewIATRedirectionEx(FileMapVA, LoadedModuleBase, szHookFunction, RedirectTo);
	}
	static bool InsertNewIATRedirection(char* szModuleName, char* szHookFunction, void* RedirectTo)
	{
		return UE::HooksInsertNewIATRedirection(szModuleName, szHookFunction, RedirectTo);
	}
	static bool RemoveRedirection(void* HookAddress, bool RemoveAll)
	{
		return UE::HooksRemoveRedirection(HookAddress, RemoveAll);
	}
	static bool RemoveRedirectionsForModule(HMODULE ModuleBase)
	{
		return UE::HooksRemoveRedirectionsForModule(ModuleBase);
	}
	static bool RemoveIATRedirection(char* szModuleName, char* szHookFunction, bool RemoveAll)
	{
		return UE::HooksRemoveIATRedirection(szModuleName, szHookFunction, RemoveAll);
	}
	static bool DisableRedirection(void* HookAddress, bool DisableAll)
	{
		return UE::HooksDisableRedirection(HookAddress, DisableAll);
	}
	static bool DisableRedirectionsForModule(HMODULE ModuleBase)
	{
		return UE::HooksDisableRedirectionsForModule(ModuleBase);
	}
	static bool DisableIATRedirection(char* szModuleName, char* szHookFunction, bool DisableAll)
	{
		return UE::HooksDisableIATRedirection(szModuleName, szHookFunction, DisableAll);
	}
	static bool EnableRedirection(void* HookAddress, bool EnableAll)
	{
		return UE::HooksEnableRedirection(HookAddress, EnableAll);
	}
	static bool EnableRedirectionsForModule(HMODULE ModuleBase)
	{
		return UE::HooksEnableRedirectionsForModule(ModuleBase);
	}
	static bool EnableIATRedirection(char* szModuleName, char* szHookFunction, bool EnableAll)
	{
		return UE::HooksEnableIATRedirection(szModuleName, szHookFunction, EnableAll);
	}
	static void ScanModuleMemory(HMODULE ModuleBase, fHookEnumCallBack CallBack)
	{
		UE::HooksScanModuleMemory(ModuleBase, (void*)CallBack);
	}
	static void ScanEntireProcessMemory(fHookEnumCallBack CallBack)
	{
		UE::HooksScanEntireProcessMemory((void*)CallBack);
	}
	static void ScanEntireProcessMemoryEx()
	{
		UE::HooksScanEntireProcessMemoryEx();
	}
};

class Tracer
{
public:

	static void Init()
	{
		UE::TracerInit();
	}
	static long long Level1(HANDLE hProcess, ULONG_PTR AddressToTrace)
	{
		return UE::TracerLevel1(hProcess, AddressToTrace);
	}
	static long long HashTracerLevel1(HANDLE hProcess, ULONG_PTR AddressToTrace, DWORD InputNumberOfInstructions)
	{
		return UE::HashTracerLevel1(hProcess, AddressToTrace, InputNumberOfInstructions);
	}
	static long DetectRedirection(HANDLE hProcess, ULONG_PTR AddressToTrace)
	{
		return UE::TracerDetectRedirection(hProcess, AddressToTrace);
	}
	static long long FixKnownRedirection(HANDLE hProcess, ULONG_PTR AddressToTrace, DWORD RedirectionId)
	{
		return UE::TracerFixKnownRedirection(hProcess, AddressToTrace, RedirectionId);
	}
	static long long FixRedirectionViaModule(HMODULE hModuleHandle, HANDLE hProcess, ULONG_PTR AddressToTrace, DWORD IdParameter)
	{
		return UE::TracerFixRedirectionViaModule(hModuleHandle, hProcess, AddressToTrace, IdParameter);
	}
	static long long DetectRedirectionViaModule(HMODULE hModuleHandle, HANDLE hProcess, ULONG_PTR AddressToTrace, DWORD* ReturnedId)
	{
		return UE::TracerDetectRedirectionViaModule(hModuleHandle, hProcess, AddressToTrace, ReturnedId);
	}
	static long FixRedirectionViaImpRecPlugin(HANDLE hProcess, char* szPluginName, ULONG_PTR AddressToTrace)
	{
		return UE::TracerFixRedirectionViaImpRecPlugin(hProcess, szPluginName, AddressToTrace);
	}
};

class ExporterX
{
protected:

	static void Cleanup()
	{
		UE::ExporterCleanup();
	}
	static void SetImageBase(ULONG_PTR ImageBase)
	{
		UE::ExporterSetImageBase(ImageBase);
	}
	static void Init(DWORD MemorySize, ULONG_PTR ImageBase, DWORD ExportOrdinalBase, char* szExportModuleName)
	{
		UE::ExporterInit(MemorySize, ImageBase, ExportOrdinalBase, szExportModuleName);
	}
	static bool AddNewExport(char* szExportName, DWORD ExportRelativeAddress)
	{
		return UE::ExporterAddNewExport(szExportName, ExportRelativeAddress);
	}
	static bool AddNewOrdinalExport(DWORD OrdinalNumber, DWORD ExportRelativeAddress)
	{
		return UE::ExporterAddNewOrdinalExport(OrdinalNumber, ExportRelativeAddress);
	}
	static long GetAddedExportCount()
	{
		return UE::ExporterGetAddedExportCount();
	}
	static long EstimatedSize()
	{
		return UE::ExporterEstimatedSize();
	}
	static bool BuildExportTable(ULONG_PTR StorePlace, ULONG_PTR FileMapVA)
	{
		return UE::ExporterBuildExportTable(StorePlace, FileMapVA);
	}
};

class ExporterA
{
public:

	static bool BuildExportTableEx(char* szExportFileName, char* szSectionName)
	{
		return UE::ExporterBuildExportTableEx(szExportFileName, szSectionName);
	}
	static bool LoadExportTable(char* szFileName)
	{
		return UE::ExporterLoadExportTable(szFileName);
	}
};

class ExporterW
{
public:

	static bool BuildExportTableEx(wchar_t* szExportFileName, char* szSectionName)
	{
		return UE::ExporterBuildExportTableExW(szExportFileName, szSectionName);
	}
	static bool LoadExportTable(wchar_t* szFileName)
	{
		return UE::ExporterLoadExportTableW(szFileName);
	}
};

class Exporter : ExporterX, ExporterA, ExporterW
{
public:

	using ExporterX::Cleanup;
	using ExporterX::SetImageBase;
	using ExporterX::Init;
	using ExporterX::AddNewExport;
	using ExporterX::AddNewOrdinalExport;
	using ExporterX::GetAddedExportCount;
	using ExporterX::EstimatedSize;
	using ExporterX::BuildExportTable;
	using ExporterA::BuildExportTableEx;
	using ExporterW::BuildExportTableEx;
	using ExporterA::LoadExportTable;
	using ExporterW::LoadExportTable;
};

class ProcessX
{
protected:

	typedef void(__stdcall *fProcessWithLibraryEnumCallback)(DWORD ProcessId, HMODULE ModuleBaseAddress);

	static void EnumProcessesWithLibrary(char* szLibraryName, fProcessWithLibraryEnumCallback EnumFunction)
	{
		UE::EnumProcessesWithLibrary(szLibraryName, (void*)EnumFunction);
	}
};

class ProcessA
{
public:

	static long GetActiveProcessId(char* szImageName)
	{
		return UE::GetActiveProcessId(szImageName);
	}
};

class ProcessW
{
public:

	static long GetActiveProcessId(wchar_t* szImageName)
	{
		return UE::GetActiveProcessIdW(szImageName);
	}
};

class Process : ProcessX, ProcessA, ProcessW
{
public:

	using ProcessX::fProcessWithLibraryEnumCallback;

	using ProcessA::GetActiveProcessId;
	using ProcessW::GetActiveProcessId;
	using ProcessX::EnumProcessesWithLibrary;
};

class TLSX
{
protected:

	static bool BreakOnCallBack(ULONG_PTR* ArrayOfCallBacks, DWORD NumberOfCallBacks, Debugger::fBreakPointCallback bpxCallBack)
	{
		return UE::TLSBreakOnCallBack(ArrayOfCallBacks, NumberOfCallBacks, (void*)bpxCallBack);
	}
	static bool RestoreData()
	{
		return UE::TLSRestoreData();
	}
	static bool BuildNewTable(ULONG_PTR FileMapVA, ULONG_PTR StorePlace, ULONG_PTR StorePlaceRVA, ULONG_PTR* ArrayOfCallBacks, DWORD NumberOfCallBacks)
	{
		return UE::TLSBuildNewTable(FileMapVA, StorePlace, StorePlaceRVA, ArrayOfCallBacks, NumberOfCallBacks);
	}
};

class TLSA
{
public:

	static bool GrabCallBackData(char* szFileName, ULONG_PTR* ArrayOfCallBacks, DWORD* NumberOfCallBacks)
	{
		return UE::TLSGrabCallBackData(szFileName, ArrayOfCallBacks, NumberOfCallBacks);
	}
	static bool BreakOnCallBackEx(char* szFileName, Debugger::fBreakPointCallback bpxCallBack)
	{
		return UE::TLSBreakOnCallBackEx(szFileName, (void*)bpxCallBack);
	}
	static bool RemoveCallback(char* szFileName)
	{
		return UE::TLSRemoveCallback(szFileName);
	}
	static bool RemoveTable(char* szFileName)
	{
		return UE::TLSRemoveTable(szFileName);
	}
	static bool BackupData(char* szFileName)
	{
		return UE::TLSBackupData(szFileName);
	}
	static bool BuildNewTableEx(char* szFileName, char* szSectionName, ULONG_PTR* ArrayOfCallBacks, DWORD NumberOfCallBacks)
	{
		return UE::TLSBuildNewTableEx(szFileName, szSectionName, ArrayOfCallBacks, NumberOfCallBacks);
	}
};

class TLSW
{
public:

	static bool GrabCallBackData(wchar_t* szFileName, ULONG_PTR* ArrayOfCallBacks, DWORD* NumberOfCallBacks)
	{
		return UE::TLSGrabCallBackDataW(szFileName, ArrayOfCallBacks, NumberOfCallBacks);
	}
	static bool BreakOnCallBackEx(wchar_t* szFileName, Debugger::fBreakPointCallback bpxCallBack)
	{
		return UE::TLSBreakOnCallBackExW(szFileName, (void*)bpxCallBack);
	}
	static bool RemoveCallback(wchar_t* szFileName)
	{
		return UE::TLSRemoveCallbackW(szFileName);
	}
	static bool RemoveTable(wchar_t* szFileName)
	{
		return UE::TLSRemoveTableW(szFileName);
	}
	static bool BackupData(wchar_t* szFileName)
	{
		return UE::TLSBackupDataW(szFileName);
	}
	static bool BuildNewTableEx(wchar_t* szFileName, char* szSectionName, ULONG_PTR* ArrayOfCallBacks, DWORD NumberOfCallBacks)
	{
		return UE::TLSBuildNewTableExW(szFileName, szSectionName, ArrayOfCallBacks, NumberOfCallBacks);
	}
};

class TLS : TLSX, TLSA, TLSW
{
public:

	using TLSX::BreakOnCallBack;
	using TLSA::GrabCallBackData;
	using TLSW::GrabCallBackData;
	using TLSA::BreakOnCallBackEx;
	using TLSW::BreakOnCallBackEx;
	using TLSA::RemoveCallback;
	using TLSW::RemoveCallback;
	using TLSA::RemoveTable;
	using TLSW::RemoveTable;
	using TLSA::BackupData;
	using TLSW::BackupData;
	using TLSX::RestoreData;
	using TLSX::BuildNewTable;
	using TLSA::BuildNewTableEx;
	using TLSW::BuildNewTableEx;
};

class TranslateA
{
public:

	static const char* NativeName(char* szNativeName)
	{
		return (const char*)UE::TranslateNativeName(szNativeName);
	}
};

class TranslateW
{
public:

	static const wchar_t* NativeName(wchar_t* szNativeName)
	{
		return (const wchar_t*)UE::TranslateNativeNameW(szNativeName);
	}
};

class Translate : TranslateA, TranslateW
{
public:

	using TranslateA::NativeName;
	using TranslateW::NativeName;
};

class HandlerA;
class HandlerW;

class HandlerX
{
	friend class HandlerA;
	friend class HandlerW;

protected:

	typedef UE::HandlerArray HandlerArray;

	static long GetActiveHandleCount(DWORD ProcessId)
	{
		return UE::HandlerGetActiveHandleCount(ProcessId);
	}
	static bool IsHandleOpen(DWORD ProcessId, HANDLE hHandle)
	{
		return UE::HandlerIsHandleOpen(ProcessId, hHandle);
	}
	static long EnumerateOpenHandles(DWORD ProcessId, HandlerArray* HandleBuffer, DWORD MaxHandleCount)
	{
		return UE::HandlerEnumerateOpenHandles(ProcessId, HandleBuffer, MaxHandleCount);
	}
	static long long GetHandleDetails(HANDLE hProcess, DWORD ProcessId, HANDLE hHandle, eHandlerReturnType InformationReturn)
	{
		return UE::HandlerGetHandleDetails(hProcess, ProcessId, hHandle, InformationReturn);
	}
	static bool CloseRemoteHandle(HANDLE hProcess, HANDLE hHandle)
	{
		return UE::HandlerCloseRemoteHandle(hProcess, hHandle);
	}
	static long EnumerateOpenMutexes(HANDLE hProcess, DWORD ProcessId, HANDLE* HandleBuffer, DWORD MaxHandleCount)
	{
		return UE::HandlerEnumerateOpenMutexes(hProcess, ProcessId, HandleBuffer, MaxHandleCount);
	}
};

class HandlerA
{
public:

	static const char* GetHandleName(HANDLE hProcess, DWORD ProcessId, HANDLE hHandle, bool TranslateName)
	{
		return (const char*)UE::HandlerGetHandleName(hProcess, ProcessId, hHandle, TranslateName);
	}
	static long EnumerateLockHandles(char* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated, HandlerX::HandlerArray* HandleDataBuffer, DWORD MaxHandleCount)
	{
		return UE::HandlerEnumerateLockHandles(szFileOrFolderName, NameIsFolder, NameIsTranslated, HandleDataBuffer, MaxHandleCount);
	}
	static bool CloseAllLockHandles(char* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated)
	{
		return UE::HandlerCloseAllLockHandles(szFileOrFolderName, NameIsFolder, NameIsTranslated);
	}
	static bool IsFileLocked(char* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated)
	{
		return UE::HandlerIsFileLocked(szFileOrFolderName, NameIsFolder, NameIsTranslated);
	}
	static long long GetOpenMutexHandle(HANDLE hProcess, DWORD ProcessId, char* szMutexString)
	{
		return UE::HandlerGetOpenMutexHandle(hProcess, ProcessId, szMutexString);
	}
	static long GetProcessIdWhichCreatedMutex(char* szMutexString)
	{
		return UE::HandlerGetProcessIdWhichCreatedMutex(szMutexString);
	}
};

class HandlerW
{
public:

	static const wchar_t* GetHandleName(HANDLE hProcess, DWORD ProcessId, HANDLE hHandle, bool TranslateName)
	{
		return (const wchar_t*)UE::HandlerGetHandleNameW(hProcess, ProcessId, hHandle, TranslateName);
	}
	static long EnumerateLockHandles(wchar_t* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated, HandlerX::HandlerArray* HandleDataBuffer, DWORD MaxHandleCount)
	{
		return UE::HandlerEnumerateLockHandlesW(szFileOrFolderName, NameIsFolder, NameIsTranslated, HandleDataBuffer, MaxHandleCount);
	}
	static bool CloseAllLockHandles(wchar_t* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated)
	{
		return UE::HandlerCloseAllLockHandlesW(szFileOrFolderName, NameIsFolder, NameIsTranslated);
	}
	static bool IsFileLocked(wchar_t* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated)
	{
		return UE::HandlerIsFileLockedW(szFileOrFolderName, NameIsFolder, NameIsTranslated);
	}
	static long long GetOpenMutexHandle(HANDLE hProcess, DWORD ProcessId, wchar_t* szMutexString)
	{
		return UE::HandlerGetOpenMutexHandleW(hProcess, ProcessId, szMutexString);
	}
	static long GetProcessIdWhichCreatedMutex(wchar_t* szMutexString)
	{
		return UE::HandlerGetProcessIdWhichCreatedMutexW(szMutexString);
	}
};

class Handler : HandlerX, HandlerA, HandlerW
{
public:

	using HandlerX::HandlerArray;

	using HandlerX::GetActiveHandleCount;
	using HandlerX::IsHandleOpen;
	#ifndef UNICODE
	using HandlerA::GetHandleName;
	#else
	using HandlerW::GetHandleName;
	#endif
	using HandlerX::EnumerateOpenHandles;
	using HandlerX::GetHandleDetails;
	using HandlerX::CloseRemoteHandle;
	using HandlerA::EnumerateLockHandles;
	using HandlerW::EnumerateLockHandles;
	using HandlerA::CloseAllLockHandles;
	using HandlerW::CloseAllLockHandles;
	using HandlerA::IsFileLocked;
	using HandlerW::IsFileLocked;
	using HandlerX::EnumerateOpenMutexes;
	using HandlerA::GetOpenMutexHandle;
	using HandlerW::GetOpenMutexHandle;
	using HandlerA::GetProcessIdWhichCreatedMutex;
	using HandlerW::GetProcessIdWhichCreatedMutex;
};

class RemoteX
{
protected:

	static bool ExitProcess(HANDLE hProcess, DWORD ExitCode)
	{
		return UE::RemoteExitProcess(hProcess, ExitCode);
	}
};

class RemoteA
{
public:

	static bool LoadLibrary(HANDLE hProcess, char* szLibraryFile, bool WaitForThreadExit)
	{
		return UE::RemoteLoadLibrary(hProcess, szLibraryFile, WaitForThreadExit);
	}
	static bool FreeLibrary(HANDLE hProcess, HMODULE hModule, char* szLibraryFile, bool WaitForThreadExit)
	{
		return UE::RemoteFreeLibrary(hProcess, hModule, szLibraryFile, WaitForThreadExit);
	}
};

class RemoteW
{
public:

	static bool LoadLibrary(HANDLE hProcess, wchar_t* szLibraryFile, bool WaitForThreadExit)
	{
		return UE::RemoteLoadLibraryW(hProcess, szLibraryFile, WaitForThreadExit);
	}
	static bool FreeLibrary(HANDLE hProcess, HMODULE hModule, wchar_t* szLibraryFile, bool WaitForThreadExit)
	{
		return UE::RemoteFreeLibraryW(hProcess, hModule, szLibraryFile, WaitForThreadExit);
	}
};

class Remote : RemoteX, RemoteA, RemoteW
{
public:

	using RemoteA::LoadLibrary;
	using RemoteW::LoadLibrary;
	using RemoteA::FreeLibrary;
	using RemoteW::FreeLibrary;
	using RemoteX::ExitProcess;
};

class StaticX
{
protected:

	typedef bool(__stdcall *fStaticDecryptCallback)(void* sMemoryStart, int sKeySize);

	static bool FileGetContent(HANDLE FileHandle, DWORD FilePositionLow, LPDWORD FilePositionHigh, void* Buffer, DWORD Size)
	{
		return UE::StaticFileGetContent(FileHandle, FilePositionLow, FilePositionHigh, Buffer, Size);
	}
	static void FileClose(HANDLE FileHandle)
	{
		return UE::StaticFileClose(FileHandle);
	}
	static void MemoryDecrypt(void* MemoryStart, DWORD MemorySize, eDecryptionType DecryptionType, eDecryptionKeySize DecryptionKeySize, ULONG_PTR DecryptionKey)
	{
		UE::StaticMemoryDecrypt(MemoryStart, MemorySize, DecryptionType, DecryptionKeySize, DecryptionKey);
	}
	static void MemoryDecryptEx(void* MemoryStart, DWORD MemorySize, eDecryptionKeySize DecryptionKeySize, fStaticDecryptCallback DecryptionCallBack)
	{
		UE::StaticMemoryDecryptEx(MemoryStart, MemorySize, DecryptionKeySize, (void*)DecryptionCallBack);
	}
	static void MemoryDecryptSpecial(void* MemoryStart, DWORD MemorySize, eDecryptionKeySize DecryptionKeySize, eDecryptionDirection SpecDecryptionType, fStaticDecryptCallback DecryptionCallBack)
	{
		UE::StaticMemoryDecryptSpecial(MemoryStart, MemorySize, DecryptionKeySize, SpecDecryptionType, (void*)DecryptionCallBack);
	}
	static void SectionDecrypt(ULONG_PTR FileMapVA, DWORD SectionNumber, bool SimulateLoad, eDecryptionType DecryptionType, eDecryptionKeySize DecryptionKeySize, ULONG_PTR DecryptionKey)
	{
		UE::StaticSectionDecrypt(FileMapVA, SectionNumber, SimulateLoad, DecryptionType, DecryptionKeySize, DecryptionKey);
	}
	static bool MemoryDecompress(void* Source, DWORD SourceSize, void* Destination, DWORD DestinationSize, eCompressionAlgorithm Algorithm)
	{
		return UE::StaticMemoryDecompress(Source, SourceSize, Destination, DestinationSize, Algorithm);
	}
	static bool HashMemory(void* MemoryToHash, DWORD SizeOfMemory, void* HashDigest, bool OutputString, eHashAlgorithm Algorithm)
	{
		return UE::StaticHashMemory(MemoryToHash, SizeOfMemory, HashDigest, OutputString, Algorithm);
	}
};

class StaticA
{
public:

	static bool FileLoad(char* szFileName, eAccess DesiredAccess, bool SimulateLoad, HANDLE* FileHandle, DWORD* LoadedSize, HANDLE* FileMap, ULONG_PTR* FileMapVA)
	{
		return UE::StaticFileLoad(szFileName, DesiredAccess, SimulateLoad, FileHandle, LoadedSize, FileMap, FileMapVA);
	}
	static bool FileUnload(char* szFileName, bool CommitChanges, HANDLE FileHandle, DWORD LoadedSize, HANDLE FileMap, ULONG_PTR FileMapVA)
	{
		return UE::StaticFileUnload(szFileName, CommitChanges, FileHandle, LoadedSize, FileMap, FileMapVA);
	}
	static bool FileOpen(char* szFileName, DWORD DesiredAccess, LPHANDLE FileHandle, LPDWORD FileSizeLow, LPDWORD FileSizeHigh)
	{
		return UE::StaticFileOpen(szFileName, DesiredAccess, FileHandle, FileSizeLow, FileSizeHigh);
	}
	static bool RawMemoryCopy(HANDLE hFile, ULONG_PTR FileMapVA, ULONG_PTR VitualAddressToCopy, DWORD Size, bool AddressIsRVA, char* szDumpFileName)
	{
		return UE::StaticRawMemoryCopy(hFile, FileMapVA, VitualAddressToCopy, Size, AddressIsRVA, szDumpFileName);
	}
	static bool RawMemoryCopyEx(HANDLE hFile, DWORD RawAddressToCopy, DWORD Size, char* szDumpFileName)
	{
		return UE::StaticRawMemoryCopyEx(hFile, RawAddressToCopy, Size, szDumpFileName);
	}
	static bool RawMemoryCopyEx64(HANDLE hFile, DWORD64 RawAddressToCopy, DWORD64 Size, char* szDumpFileName)
	{
		return UE::StaticRawMemoryCopyEx64(hFile, RawAddressToCopy, Size, szDumpFileName);
	}
	static bool HashFile(char* szFileName, void* HashDigest, bool OutputString, eHashAlgorithm Algorithm)
	{
		return UE::StaticHashFile(szFileName, (char*)HashDigest, OutputString, Algorithm);
	}
};

class StaticW
{
public:

	static bool FileLoad(wchar_t* szFileName, eAccess DesiredAccess, bool SimulateLoad, HANDLE* FileHandle, DWORD* LoadedSize, HANDLE* FileMap, ULONG_PTR* FileMapVA)
	{
		return UE::StaticFileLoadW(szFileName, DesiredAccess, SimulateLoad, FileHandle, LoadedSize, FileMap, FileMapVA);
	}
	static bool FileUnload(wchar_t* szFileName, bool CommitChanges, HANDLE FileHandle, DWORD LoadedSize, HANDLE FileMap, ULONG_PTR FileMapVA)
	{
		return UE::StaticFileUnloadW(szFileName, CommitChanges, FileHandle, LoadedSize, FileMap, FileMapVA);
	}
	static bool FileOpen(wchar_t* szFileName, DWORD DesiredAccess, LPHANDLE FileHandle, LPDWORD FileSizeLow, LPDWORD FileSizeHigh)
	{
		return UE::StaticFileOpenW(szFileName, DesiredAccess, FileHandle, FileSizeLow, FileSizeHigh);
	}
	static bool RawMemoryCopy(HANDLE hFile, ULONG_PTR FileMapVA, ULONG_PTR VitualAddressToCopy, DWORD Size, bool AddressIsRVA, wchar_t* szDumpFileName)
	{
		return UE::StaticRawMemoryCopyW(hFile, FileMapVA, VitualAddressToCopy, Size, AddressIsRVA, szDumpFileName);
	}
	static bool RawMemoryCopyEx(HANDLE hFile, DWORD RawAddressToCopy, DWORD Size, wchar_t* szDumpFileName)
	{
		return UE::StaticRawMemoryCopyExW(hFile, RawAddressToCopy, Size, szDumpFileName);
	}
	static bool RawMemoryCopyEx64(HANDLE hFile, DWORD64 RawAddressToCopy, DWORD64 Size, wchar_t* szDumpFileName)
	{
		return UE::StaticRawMemoryCopyEx64W(hFile, RawAddressToCopy, Size, szDumpFileName);
	}
	static bool HashFile(wchar_t* szFileName, void* HashDigest, bool OutputString, eHashAlgorithm Algorithm)
	{
		return UE::StaticHashFileW(szFileName, (char*)HashDigest, OutputString, Algorithm);
	}
};

class Static : StaticX, StaticA, StaticW
{
public:

	using StaticX::fStaticDecryptCallback;

	using StaticA::FileLoad;
	using StaticW::FileLoad;
	using StaticA::FileUnload;
	using StaticW::FileUnload;
	using StaticA::FileOpen;
	using StaticW::FileOpen;
	using StaticX::FileGetContent;
	using StaticX::FileClose;
	using StaticX::MemoryDecrypt;
	using StaticX::MemoryDecryptEx;
	using StaticX::MemoryDecryptSpecial;
	using StaticX::SectionDecrypt;
	using StaticX::MemoryDecompress;
	using StaticA::RawMemoryCopy;
	using StaticW::RawMemoryCopy;
	using StaticA::RawMemoryCopyEx;
	using StaticW::RawMemoryCopyEx;
	using StaticA::RawMemoryCopyEx64;
	using StaticW::RawMemoryCopyEx64;
	using StaticX::HashMemory;
	using StaticA::HashFile;
	using StaticW::HashFile;
};

class EngineX
{
protected:

	static void SetEngineVariable(eEngineVariable VariableId, bool VariableSet)
	{
		UE::SetEngineVariable(VariableId, VariableSet);
	}
	static bool FakeMissingDependencies(HANDLE hProcess)
	{
		return UE::EngineFakeMissingDependencies(hProcess);
	}
	static bool DeleteCreatedDependencies()
	{
		return UE::EngineDeleteCreatedDependencies();
	}
	static bool CreateUnpackerWindow(char* WindowUnpackerTitle, char* WindowUnpackerLongTitle, char* WindowUnpackerName, char* WindowUnpackerAuthor, void* StartUnpackingCallBack)
	{
		return UE::EngineCreateUnpackerWindow(WindowUnpackerTitle, WindowUnpackerLongTitle, WindowUnpackerName, WindowUnpackerAuthor, StartUnpackingCallBack);
	}
	static void AddUnpackerWindowLogMessage(char* szLogMessage)
	{
		return UE::EngineAddUnpackerWindowLogMessage(szLogMessage);
	}
};

class EngineA
{
public:

	static bool CreateMissingDependencies(char* szFileName, char* szOutputFolder, bool LogCreatedFiles)
	{
		return UE::EngineCreateMissingDependencies(szFileName, szOutputFolder, LogCreatedFiles);
	}
};

class EngineW
{
public:

	static bool CreateMissingDependencies(wchar_t* szFileName, wchar_t* szOutputFolder, bool LogCreatedFiles)
	{
		return UE::EngineCreateMissingDependenciesW(szFileName, szOutputFolder, LogCreatedFiles);
	}
};

class Engine : EngineX, EngineA, EngineW
{
public:

	using EngineX::SetEngineVariable;
	using EngineA::CreateMissingDependencies;
	using EngineW::CreateMissingDependencies;
	using EngineX::FakeMissingDependencies;
	using EngineX::DeleteCreatedDependencies;
	using EngineX::CreateUnpackerWindow;
	using EngineX::AddUnpackerWindowLogMessage;
};

class ExtensionManager
{
public:

	typedef UE::PluginInformation PluginInformation;

	static bool IsPluginLoaded(char* szPluginName)
	{
		return UE::ExtensionManagerIsPluginLoaded(szPluginName);
	}
	static bool IsPluginEnabled(char* szPluginName)
	{
		return UE::ExtensionManagerIsPluginEnabled(szPluginName);
	}
	static bool DisableAllPlugins()
	{
		return UE::ExtensionManagerDisableAllPlugins();
	}
	static bool DisablePlugin(char* szPluginName)
	{
		return UE::ExtensionManagerDisablePlugin(szPluginName);
	}
	static bool EnableAllPlugins()
	{
		return UE::ExtensionManagerEnableAllPlugins();
	}
	static bool EnablePlugin(char* szPluginName)
	{
		return UE::ExtensionManagerEnablePlugin(szPluginName);
	}
	static bool UnloadAllPlugins()
	{
		return UE::ExtensionManagerUnloadAllPlugins();
	}
	static bool UnloadPlugin(char* szPluginName)
	{
		return UE::ExtensionManagerUnloadPlugin(szPluginName);
	}
	static PluginInformation* GetPluginInfo(char* szPluginName)
	{
		return (PluginInformation*)UE::ExtensionManagerGetPluginInfo(szPluginName);
	}
};

} /* namespace TE */

#endif /*TITANENGINE_CPP*/
