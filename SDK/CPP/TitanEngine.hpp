#ifndef TITANENGINE_CPP
#define TITANENGINE_CPP

#define TITCALL

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

enum eStructType : DWORD
{
    UE_STRUCT_PE32STRUCT = UE::UE_STRUCT_PE32STRUCT,
    UE_STRUCT_PE64STRUCT = UE::UE_STRUCT_PE64STRUCT,
    UE_STRUCT_PESTRUCT = UE::UE_STRUCT_PESTRUCT,
    UE_STRUCT_IMPORTENUMDATA = UE::UE_STRUCT_IMPORTENUMDATA,
    UE_STRUCT_THREAD_ITEM_DATA = UE::UE_STRUCT_THREAD_ITEM_DATA,
    UE_STRUCT_LIBRARY_ITEM_DATA = UE::UE_STRUCT_LIBRARY_ITEM_DATA,
    UE_STRUCT_LIBRARY_ITEM_DATAW = UE::UE_STRUCT_LIBRARY_ITEM_DATAW,
    UE_STRUCT_PROCESS_ITEM_DATA = UE::UE_STRUCT_PROCESS_ITEM_DATA,
    UE_STRUCT_HANDLERARRAY = UE::UE_STRUCT_HANDLERARRAY,
    UE_STRUCT_PLUGININFORMATION = UE::UE_STRUCT_PLUGININFORMATION,
    UE_STRUCT_HOOK_ENTRY = UE::UE_STRUCT_HOOK_ENTRY,
    UE_STRUCT_FILE_STATUS_INFO = UE::UE_STRUCT_FILE_STATUS_INFO,
    UE_STRUCT_FILE_FIX_INFO = UE::UE_STRUCT_FILE_FIX_INFO
};

enum eHideLevel : DWORD
{
    UE_HIDE_PEBONLY = UE::UE_HIDE_PEBONLY,
    UE_HIDE_BASIC = UE::UE_HIDE_BASIC
};

enum ePluginCallReason : int
{
    UE_PLUGIN_CALL_REASON_PREDEBUG = UE::UE_PLUGIN_CALL_REASON_PREDEBUG,
    UE_PLUGIN_CALL_REASON_EXCEPTION = UE::UE_PLUGIN_CALL_REASON_EXCEPTION,
    UE_PLUGIN_CALL_REASON_POSTDEBUG = UE::UE_PLUGIN_CALL_REASON_POSTDEBUG,
    UE_PLUGIN_CALL_REASON_UNHANDLEDEXCEPTION = UE::UE_PLUGIN_CALL_REASON_UNHANDLEDEXCEPTION
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
    UE_ENGINE_CALL_PLUGIN_DEBUG_CALLBACK = UE::UE_ENGINE_CALL_PLUGIN_DEBUG_CALLBACK,
    UE_ENGINE_SET_DEBUG_PRIVILEGE = UE::UE_ENGINE_SET_DEBUG_PRIVILEGE
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
    UE_BASEOFCODE = UE::UE_BASEOFCODE,
    UE_BASEOFDATA = UE::UE_BASEOFDATA,
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

const long UE_VANOTFOUND = UE::UE_VANOTFOUND;

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
    UE_CH_OUTPUTDEBUGSTRING = UE::UE_CH_OUTPUTDEBUGSTRING,
    UE_CH_AFTEREXCEPTIONPROCESSING = UE::UE_CH_AFTEREXCEPTIONPROCESSING,
    UE_CH_SYSTEMBREAKPOINT = UE::UE_CH_SYSTEMBREAKPOINT,
    UE_CH_UNHANDLEDEXCEPTION = UE::UE_CH_UNHANDLEDEXCEPTION,
    UE_CH_RIPEVENT = UE::UE_CH_RIPEVENT,
    UE_CH_DEBUGEVENT = UE::UE_CH_DEBUGEVENT
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
    UE_MEMORY_WRITE = UE::UE_MEMORY_WRITE,
    UE_MEMORY_EXECUTE = UE::UE_MEMORY_EXECUTE
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
    UE_HARDWARE_SIZE_4 = UE::UE_HARDWARE_SIZE_4,
    UE_HARDWARE_SIZE_8 = UE::UE_HARDWARE_SIZE_8
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
    UE_CSP = UE::UE_CSP,
    UE_SEG_GS = UE::UE_SEG_GS,
    UE_SEG_FS = UE::UE_SEG_FS,
    UE_SEG_ES = UE::UE_SEG_ES,
    UE_SEG_DS = UE::UE_SEG_DS,
    UE_SEG_CS = UE::UE_SEG_CS,
    UE_SEG_SS = UE::UE_SEG_SS
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
    UE_FIELD_FIXABLE_NON_CRITICAL = UE::UE_FIELD_FIXABLE_NON_CRITICAL,
    UE_FIELD_FIXABLE_CRITICAL = UE::UE_FIELD_FIXABLE_CRITICAL,
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

    static ULONG_PTR GetPE32DataFromMappedFile(ULONG_PTR FileMapVA, DWORD WhichSection, ePE32Data WhichData)
    {
        return UE::GetPE32DataFromMappedFile(FileMapVA, WhichSection, WhichData);
    }
    static bool GetPE32DataFromMappedFileEx(ULONG_PTR FileMapVA, PEStruct* DataStorage)
    {
        return UE::GetPE32DataFromMappedFileEx(FileMapVA, (void*)DataStorage);
    }
    static bool SetPE32DataForMappedFile(ULONG_PTR FileMapVA, DWORD WhichSection, ePE32Data WhichData, ULONG_PTR NewDataValue)
    {
        return UE::SetPE32DataForMappedFile(FileMapVA, WhichSection, WhichData, NewDataValue);
    }
    static bool SetPE32DataForMappedFileEx(ULONG_PTR FileMapVA, PEStruct* DataStorage)
    {
        return UE::SetPE32DataForMappedFileEx(FileMapVA, (void*)DataStorage);
    }
    static long GetPE32SectionNumberFromVA(ULONG_PTR FileMapVA, ULONG_PTR AddressToConvert)
    {
        return UE::GetPE32SectionNumberFromVA(FileMapVA, AddressToConvert);
    }
    static ULONG_PTR ConvertVAtoFileOffset(ULONG_PTR FileMapVA, ULONG_PTR AddressToConvert, bool ReturnType)
    {
        return UE::ConvertVAtoFileOffset(FileMapVA, AddressToConvert, ReturnType);
    }
    static ULONG_PTR ConvertVAtoFileOffsetEx(ULONG_PTR FileMapVA, DWORD FileSize, ULONG_PTR ImageBase, ULONG_PTR AddressToConvert, bool AddressIsRVA, bool ReturnType)
    {
        return UE::ConvertVAtoFileOffsetEx(FileMapVA, FileSize, ImageBase, AddressToConvert, AddressIsRVA, ReturnType);
    }
    static ULONG_PTR ConvertFileOffsetToVA(ULONG_PTR FileMapVA, ULONG_PTR AddressToConvert, bool ReturnType)
    {
        return UE::ConvertFileOffsetToVA(FileMapVA, AddressToConvert, ReturnType);
    }
    static ULONG_PTR ConvertFileOffsetToVAEx(ULONG_PTR FileMapVA, DWORD FileSize, ULONG_PTR ImageBase, ULONG_PTR AddressToConvert, bool ReturnType)
    {
        return UE::ConvertFileOffsetToVAEx(FileMapVA, FileSize, ImageBase, AddressToConvert, ReturnType);
    }
    static bool MemoryReadSafe(HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
    {
        return UE::MemoryReadSafe(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    }
    static bool MemoryWriteSafe(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
    {
        return UE::MemoryWriteSafe(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    }
};

class DumperA
{
public:

    static bool DumpProcess(HANDLE hProcess, void* ImageBase, const char* szDumpFileName, ULONG_PTR EntryPoint)
    {
        return UE::DumpProcess(hProcess, ImageBase, (char*)szDumpFileName, EntryPoint);
    }
    static bool DumpProcessEx(DWORD ProcessId, void* ImageBase, const char* szDumpFileName, ULONG_PTR EntryPoint)
    {
        return UE::DumpProcessEx(ProcessId, ImageBase, (char*)szDumpFileName, EntryPoint);
    }
    static bool DumpMemory(HANDLE hProcess, void* MemoryStart, ULONG_PTR MemorySize, const char* szDumpFileName)
    {
        return UE::DumpMemory(hProcess, MemoryStart, MemorySize, (char*)szDumpFileName);
    }
    static bool DumpMemoryEx(DWORD ProcessId, void* MemoryStart, ULONG_PTR MemorySize, const char* szDumpFileName)
    {
        return UE::DumpMemoryEx(ProcessId, MemoryStart, MemorySize, (char*)szDumpFileName);
    }
    static bool DumpRegions(HANDLE hProcess, const char* szDumpFolder, bool DumpAboveImageBaseOnly)
    {
        return UE::DumpRegions(hProcess, (char*)szDumpFolder, DumpAboveImageBaseOnly);
    }
    static bool DumpRegionsEx(DWORD ProcessId, const char* szDumpFolder, bool DumpAboveImageBaseOnly)
    {
        return UE::DumpRegionsEx(ProcessId, (char*)szDumpFolder, DumpAboveImageBaseOnly);
    }
    static bool DumpModule(HANDLE hProcess, void* ModuleBase, const char* szDumpFileName)
    {
        return UE::DumpModule(hProcess, ModuleBase, (char*)szDumpFileName);
    }
    static bool DumpModuleEx(DWORD ProcessId, void* ModuleBase, const char* szDumpFileName)
    {
        return UE::DumpModuleEx(ProcessId, ModuleBase, (char*)szDumpFileName);
    }
    static bool PastePEHeader(HANDLE hProcess, void* ImageBase, const char* szDebuggedFileName)
    {
        return UE::PastePEHeader(hProcess, ImageBase, (char*)szDebuggedFileName);
    }
    static bool ExtractSection(const char* szFileName, const char* szDumpFileName, DWORD SectionNumber)
    {
        return UE::ExtractSection((char*)szFileName, (char*)szDumpFileName, SectionNumber);
    }
    static bool ResortFileSections(const char* szFileName)
    {
        return UE::ResortFileSections((char*)szFileName);
    }
    static bool FindOverlay(const char* szFileName, DWORD* OverlayStart, DWORD* OverlaySize)
    {
        return UE::FindOverlay((char*)szFileName, OverlayStart, OverlaySize);
    }
    static bool ExtractOverlay(const char* szFileName, const char* szExtractedFileName)
    {
        return UE::ExtractOverlay((char*)szFileName, (char*)szExtractedFileName);
    }
    static bool AddOverlay(const char* szFileName, const char* szOverlayFileName)
    {
        return UE::AddOverlay((char*)szFileName, (char*)szOverlayFileName);
    }
    static bool CopyOverlay(const char* szInFileName, const char* szOutFileName)
    {
        return UE::CopyOverlay((char*)szInFileName, (char*)szOutFileName);
    }
    static bool RemoveOverlay(const char* szFileName)
    {
        return UE::RemoveOverlay((char*)szFileName);
    }
    static bool MakeAllSectionsRWE(const char* szFileName)
    {
        return UE::MakeAllSectionsRWE((char*)szFileName);
    }
    static long AddNewSectionEx(const char* szFileName, const char* szSectionName, DWORD SectionSize, DWORD SectionAttributes, const void* SectionContent, DWORD ContentSize)
    {
        return UE::AddNewSectionEx((char*)szFileName, (char*)szSectionName, SectionSize, SectionAttributes, (void*)SectionContent, ContentSize);
    }
    static long AddNewSection(const char* szFileName, const char* szSectionName, DWORD SectionSize)
    {
        return UE::AddNewSection((char*)szFileName, (char*)szSectionName, SectionSize);
    }
    static bool ResizeLastSection(const char* szFileName, DWORD NumberOfExpandBytes, bool AlignResizeData)
    {
        return UE::ResizeLastSection((char*)szFileName, NumberOfExpandBytes, AlignResizeData);
    }
    static void SetSharedOverlay(const char* szFileName)
    {
        return UE::SetSharedOverlay((char*)szFileName);
    }
    static const char* GetSharedOverlay()
    {
        return UE::GetSharedOverlay();
    }
    static bool DeleteLastSection(const char* szFileName)
    {
        return UE::DeleteLastSection((char*)szFileName);
    }
    static bool DeleteLastSectionEx(const char* szFileName, DWORD NumberOfSections)
    {
        return UE::DeleteLastSectionEx((char*)szFileName, NumberOfSections);
    }
    static ULONG_PTR GetPE32Data(const char* szFileName, DWORD WhichSection, ePE32Data WhichData)
    {
        return UE::GetPE32Data((char*)szFileName, WhichSection, WhichData);
    }
    static bool GetPE32DataEx(const char* szFileName, DumperX::PEStruct* DataStorage)
    {
        return UE::GetPE32DataEx((char*)szFileName, DataStorage);
    }
    static bool SetPE32Data(const char* szFileName, DWORD WhichSection, ePE32Data WhichData, ULONG_PTR NewDataValue)
    {
        return UE::SetPE32Data((char*)szFileName, WhichSection, WhichData, NewDataValue);
    }
    static bool SetPE32DataEx(const char* szFileName, const DumperX::PEStruct* DataStorage)
    {
        return UE::SetPE32DataEx((char*)szFileName, (void*)DataStorage);
    }
};

class DumperW
{
public:

    static bool DumpProcess(HANDLE hProcess, void* ImageBase, const wchar_t* szDumpFileName, ULONG_PTR EntryPoint)
    {
        return UE::DumpProcessW(hProcess, ImageBase, (wchar_t*)szDumpFileName, EntryPoint);
    }
    static bool DumpProcessEx(DWORD ProcessId, void* ImageBase, const wchar_t* szDumpFileName, ULONG_PTR EntryPoint)
    {
        return UE::DumpProcessExW(ProcessId, ImageBase, (wchar_t*)szDumpFileName, EntryPoint);
    }
    static bool DumpMemory(HANDLE hProcess, void* MemoryStart, ULONG_PTR MemorySize, const wchar_t* szDumpFileName)
    {
        return UE::DumpMemoryW(hProcess, MemoryStart, MemorySize, (wchar_t*)szDumpFileName);
    }
    static bool DumpMemoryEx(DWORD ProcessId, void* MemoryStart, ULONG_PTR MemorySize, const wchar_t* szDumpFileName)
    {
        return UE::DumpMemoryExW(ProcessId, MemoryStart, MemorySize, (wchar_t*)szDumpFileName);
    }
    static bool DumpRegions(HANDLE hProcess, const wchar_t* szDumpFolder, bool DumpAboveImageBaseOnly)
    {
        return UE::DumpRegionsW(hProcess, (wchar_t*)szDumpFolder, DumpAboveImageBaseOnly);
    }
    static bool DumpRegionsEx(DWORD ProcessId, const wchar_t* szDumpFolder, bool DumpAboveImageBaseOnly)
    {
        return UE::DumpRegionsExW(ProcessId, (wchar_t*)szDumpFolder, DumpAboveImageBaseOnly);
    }
    static bool DumpModule(HANDLE hProcess, void* ModuleBase, const wchar_t* szDumpFileName)
    {
        return UE::DumpModuleW(hProcess, ModuleBase, (wchar_t*)szDumpFileName);
    }
    static bool DumpModuleEx(DWORD ProcessId, void* ModuleBase, const wchar_t* szDumpFileName)
    {
        return UE::DumpModuleExW(ProcessId, ModuleBase, (wchar_t*)szDumpFileName);
    }
    static bool PastePEHeader(HANDLE hProcess, void* ImageBase, const wchar_t* szDebuggedFileName)
    {
        return UE::PastePEHeaderW(hProcess, ImageBase, (wchar_t*)szDebuggedFileName);
    }
    static bool ExtractSection(const wchar_t* szFileName, const wchar_t* szDumpFileName, DWORD SectionNumber)
    {
        return UE::ExtractSectionW((wchar_t*)szFileName, (wchar_t*)szDumpFileName, SectionNumber);
    }
    static bool ResortFileSections(const wchar_t* szFileName)
    {
        return UE::ResortFileSectionsW((wchar_t*)szFileName);
    }
    static bool FindOverlay(const wchar_t* szFileName, DWORD* OverlayStart, DWORD* OverlaySize)
    {
        return UE::FindOverlayW((wchar_t*)szFileName, OverlayStart, OverlaySize);
    }
    static bool ExtractOverlay(const wchar_t* szFileName, const wchar_t* szExtractedFileName)
    {
        return UE::ExtractOverlayW((wchar_t*)szFileName, (wchar_t*)szExtractedFileName);
    }
    static bool AddOverlay(const wchar_t* szFileName, const wchar_t* szOverlayFileName)
    {
        return UE::AddOverlayW((wchar_t*)szFileName, (wchar_t*)szOverlayFileName);
    }
    static bool CopyOverlay(const wchar_t* szInFileName, const wchar_t* szOutFileName)
    {
        return UE::CopyOverlayW((wchar_t*)szInFileName, (wchar_t*)szOutFileName);
    }
    static bool RemoveOverlay(const wchar_t* szFileName)
    {
        return UE::RemoveOverlayW((wchar_t*)szFileName);
    }
    static bool MakeAllSectionsRWE(const wchar_t* szFileName)
    {
        return UE::MakeAllSectionsRWEW((wchar_t*)szFileName);
    }
    static long AddNewSectionEx(const wchar_t* szFileName, const char* szSectionName, DWORD SectionSize, DWORD SectionAttributes, const void* SectionContent, DWORD ContentSize)
    {
        return UE::AddNewSectionExW((wchar_t*)szFileName, (char*)szSectionName, SectionSize, SectionAttributes, (void*)SectionContent, ContentSize);
    }
    static long AddNewSection(const wchar_t* szFileName, const char* szSectionName, DWORD SectionSize)
    {
        return UE::AddNewSectionW((wchar_t*)szFileName, (char*)szSectionName, SectionSize);
    }
    static bool ResizeLastSection(const wchar_t* szFileName, DWORD NumberOfExpandBytes, bool AlignResizeData)
    {
        return UE::ResizeLastSectionW((wchar_t*)szFileName, NumberOfExpandBytes, AlignResizeData);
    }
    static void SetSharedOverlay(const wchar_t* szFileName)
    {
        return UE::SetSharedOverlayW((wchar_t*)szFileName);
    }
    static const wchar_t* GetSharedOverlay()
    {
        return UE::GetSharedOverlayW();
    }
    static bool DeleteLastSection(const wchar_t* szFileName)
    {
        return UE::DeleteLastSectionW((wchar_t*)szFileName);
    }
    static bool DeleteLastSectionEx(const wchar_t* szFileName, DWORD NumberOfSections)
    {
        return UE::DeleteLastSectionExW((wchar_t*)szFileName, NumberOfSections);
    }
    static ULONG_PTR GetPE32Data(const wchar_t* szFileName, DWORD WhichSection, ePE32Data WhichData)
    {
        return UE::GetPE32DataW((wchar_t*)szFileName, WhichSection, WhichData);
    }
    static bool GetPE32DataEx(const wchar_t* szFileName, DumperX::PEStruct* DataStorage)
    {
        return UE::GetPE32DataExW((wchar_t*)szFileName, DataStorage);
    }
    static bool SetPE32Data(const wchar_t* szFileName, DWORD WhichSection, ePE32Data WhichData, ULONG_PTR NewDataValue)
    {
        return UE::SetPE32DataW((wchar_t*)szFileName, WhichSection, WhichData, NewDataValue);
    }
    static bool SetPE32DataEx(const wchar_t* szFileName, const DumperX::PEStruct* DataStorage)
    {
        return UE::SetPE32DataExW((wchar_t*)szFileName, (void*)DataStorage);
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
    using DumperX::MemoryReadSafe;
    using DumperX::MemoryWriteSafe;
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

    static bool FixHeaderCheckSum(const char* szFileName)
    {
        return UE::FixHeaderCheckSum((char*)szFileName);
    }
    static long RealignPEEx(const char* szFileName, DWORD RealingFileSize, DWORD ForcedFileAlignment)
    {
        return UE::RealignPEEx((char*)szFileName, RealingFileSize, ForcedFileAlignment);
    }
    static bool WipeSection(const char* szFileName, int WipeSectionNumber, bool RemovePhysically)
    {
        return UE::WipeSection((char*)szFileName, WipeSectionNumber, RemovePhysically);
    }
    static bool IsPE32FileValidEx(const char* szFileName, eCheckDepth CheckDepth, RealignerX::FILE_STATUS_INFO* FileStatusInfo)
    {
        return UE::IsPE32FileValidEx((char*)szFileName, CheckDepth, (void*)FileStatusInfo);
    }
    static bool FixBrokenPE32FileEx(const char* szFileName, const RealignerX::FILE_STATUS_INFO* FileStatusInfo, RealignerX::FILE_FIX_INFO* FileFixInfo)
    {
        return UE::FixBrokenPE32FileEx((char*)szFileName, (void*)FileStatusInfo, (void*)FileFixInfo);
    }
    static bool IsFileDLL(const char* szFileName, ULONG_PTR FileMapVA)
    {
        return UE::IsFileDLL((char*)szFileName, FileMapVA);
    }
};

class RealignerW
{
public:

    static bool FixHeaderCheckSum(const wchar_t* szFileName)
    {
        return UE::FixHeaderCheckSumW((wchar_t*)szFileName);
    }
    static long RealignPEEx(const wchar_t* szFileName, DWORD RealingFileSize, DWORD ForcedFileAlignment)
    {
        return UE::RealignPEExW((wchar_t*)szFileName, RealingFileSize, ForcedFileAlignment);
    }
    static bool WipeSection(const wchar_t* szFileName, int WipeSectionNumber, bool RemovePhysically)
    {
        return UE::WipeSectionW((wchar_t*)szFileName, WipeSectionNumber, RemovePhysically);
    }
    static bool IsPE32FileValidEx(const wchar_t* szFileName, eCheckDepth CheckDepth, RealignerX::FILE_STATUS_INFO* FileStatusInfo)
    {
        return UE::IsPE32FileValidExW((wchar_t*)szFileName, CheckDepth, FileStatusInfo);
    }
    static bool FixBrokenPE32FileEx(const wchar_t* szFileName, const RealignerX::FILE_STATUS_INFO* FileStatusInfo, RealignerX::FILE_FIX_INFO* FileFixInfo)
    {
        return UE::FixBrokenPE32FileExW((wchar_t*)szFileName, (void*)FileStatusInfo, (void*)FileFixInfo);
    }
    static bool IsFileDLL(const wchar_t* szFileName, ULONG_PTR FileMapVA)
    {
        return UE::IsFileDLLW((wchar_t*)szFileName, FileMapVA);
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
    static void* GetPEBLocation64(HANDLE hProcess)
    {
        return UE::GetPEBLocation64(hProcess);
    }
    static void* GetTEBLocation(HANDLE hProcess)
    {
        return UE::GetTEBLocation(hProcess);
    }
    static void* GetTEBLocation64(HANDLE hProcess)
    {
        return UE::GetTEBLocation64(hProcess);
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

    static bool ExportRelocationEx(const char* szFileName, const char* szSectionName)
    {
        return UE::RelocaterExportRelocationEx((char*)szFileName, (char*)szSectionName);
    }
    static bool MakeSnapshot(HANDLE hProcess, const char* szSaveFileName, void* MemoryStart, ULONG_PTR MemorySize)
    {
        return UE::RelocaterMakeSnapshot(hProcess, (char*)szSaveFileName, MemoryStart, MemorySize);
    }
    static bool CompareTwoSnapshots(HANDLE hProcess, ULONG_PTR LoadedImageBase, ULONG_PTR NtSizeOfImage, const char* szDumpFile1, const char* szDumpFile2, ULONG_PTR MemStart)
    {
        return UE::RelocaterCompareTwoSnapshots(hProcess, LoadedImageBase, NtSizeOfImage, (char*)szDumpFile1, (char*)szDumpFile2, MemStart);
    }
    static bool ChangeFileBase(const char* szFileName, ULONG_PTR NewImageBase)
    {
        return UE::RelocaterChangeFileBase((char*)szFileName, NewImageBase);
    }
    static bool WipeRelocationTable(const char* szFileName)
    {
        return UE::RelocaterWipeRelocationTable((char*)szFileName);
    }
};

class RelocaterW
{
public:

    static bool ExportRelocationEx(const wchar_t* szFileName, char* szSectionName)
    {
        return UE::RelocaterExportRelocationExW((wchar_t*)szFileName, (char*)szSectionName);
    }
    static bool MakeSnapshot(HANDLE hProcess, const wchar_t* szSaveFileName, void* MemoryStart, ULONG_PTR MemorySize)
    {
        return UE::RelocaterMakeSnapshotW(hProcess, (wchar_t*)szSaveFileName, MemoryStart, MemorySize);
    }
    static bool CompareTwoSnapshots(HANDLE hProcess, ULONG_PTR LoadedImageBase, ULONG_PTR NtSizeOfImage, const wchar_t* szDumpFile1, const wchar_t* szDumpFile2, ULONG_PTR MemStart)
    {
        return UE::RelocaterCompareTwoSnapshotsW(hProcess, LoadedImageBase, NtSizeOfImage, (wchar_t*)szDumpFile1, (wchar_t*)szDumpFile2, MemStart);
    }
    static bool ChangeFileBase(const wchar_t* szFileName, ULONG_PTR NewImageBase)
    {
        return UE::RelocaterChangeFileBaseW((wchar_t*)szFileName, NewImageBase);
    }
    static bool WipeRelocationTable(const wchar_t* szFileName)
    {
        return UE::RelocaterWipeRelocationTableW((wchar_t*)szFileName);
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

    typedef void(TITCALL* fResourceEnumCallback)(const wchar_t* szResourceType, DWORD ResourceType, const wchar_t* szResourceName, DWORD ResourceName, DWORD ResourceLanguage, DWORD ResourceData, DWORD ResourceSize);

    static bool FreeLoadedFile(void* LoadedFileBase)
    {
        return UE::ResourcerFreeLoadedFile(LoadedFileBase);
    }
    static bool ExtractResourceFromFileEx(HMODULE hFile, char* szResourceType, char* szResourceName, char* szExtractedFileName)
    {
        return UE::ResourcerExtractResourceFromFileEx(hFile, szResourceType, szResourceName, szExtractedFileName);
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

    static ULONG_PTR LoadFileForResourceUse(char* szFileName)
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

    static ULONG_PTR LoadFileForResourceUse(wchar_t* szFileName)
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

    typedef void(TITCALL* fThreadEnumCallback)(const THREAD_ITEM_DATA* fThreadDetail);
    typedef void(TITCALL* fThreadExitCallback)(const EXIT_THREAD_DEBUG_INFO* SpecialDBG);

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
    static ULONG_PTR CreateRemoteThread(ULONG_PTR ThreadStartAddress, bool AutoCloseTheHandle, void* ThreadPassParameter, DWORD* ThreadId)
    {
        return UE::ThreaderCreateRemoteThread(ThreadStartAddress, AutoCloseTheHandle, ThreadPassParameter, ThreadId);
    }
    static bool InjectAndExecuteCode(void* InjectCode, DWORD StartDelta, DWORD InjectSize)
    {
        return UE::ThreaderInjectAndExecuteCode(InjectCode, StartDelta, InjectSize);
    }
    static ULONG_PTR CreateRemoteThreadEx(HANDLE hProcess, ULONG_PTR ThreadStartAddress, bool AutoCloseTheHandle, void* ThreadPassParameter, DWORD* ThreadId)
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
    static ULONG_PTR GetOpenHandleForThread(DWORD ThreadId)
    {
        return UE::ThreaderGetOpenHandleForThread(ThreadId);
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

    typedef void (TITCALL* fBreakPointCallback)();
    typedef void (TITCALL* fCustomHandlerCallback)(const void* ExceptionData);

    static const char* StaticDisassembleEx(ULONG_PTR DisassmStart, const void* DisassmAddress)
    {
        return (const char*)UE::StaticDisassembleEx(DisassmStart, (void*)DisassmAddress);
    }
    static const char* StaticDisassemble(const void* DisassmAddress)
    {
        return (const char*)UE::StaticDisassemble((void*)DisassmAddress);
    }
    static const char* DisassembleEx(HANDLE hProcess, void* DisassmAddress, bool ReturnInstructionType)
    {
        return (const char*)UE::DisassembleEx(hProcess, DisassmAddress, ReturnInstructionType);
    }
    static const char* Disassemble(void* DisassmAddress)
    {
        return (const char*)UE::Disassemble(DisassmAddress);
    }
    static long StaticLengthDisassemble(const void* DisassmAddress)
    {
        return UE::StaticLengthDisassemble((void*)DisassmAddress);
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
    static bool DeleteBPX(ULONG_PTR bpxAddress)
    {
        return UE::DeleteBPX(bpxAddress);
    }
    static bool SafeDeleteBPX(ULONG_PTR bpxAddress)
    {
        return UE::SafeDeleteBPX(bpxAddress);
    }
    static bool SetAPIBreakPoint(const char* szDLLName, const char* szAPIName, eBPType bpxType, eBPPlace bpxPlace, fBreakPointCallback bpxCallBack)
    {
        return UE::SetAPIBreakPoint(szDLLName, szAPIName, bpxType, bpxPlace, (void*)bpxCallBack);
    }
    static bool DeleteAPIBreakPoint(const char* szDLLName, const char* szAPIName, eBPPlace bpxPlace)
    {
        return UE::DeleteAPIBreakPoint(szDLLName, szAPIName, bpxPlace);
    }
    static bool SafeDeleteAPIBreakPoint(const char* szDLLName, const char* szAPIName, eBPPlace bpxPlace)
    {
        return UE::SafeDeleteAPIBreakPoint(szDLLName, szAPIName, bpxPlace);
    }
    static bool SetMemoryBPX(ULONG_PTR MemoryStart, SIZE_T SizeOfMemory, fBreakPointCallback bpxCallBack)
    {
        return UE::SetMemoryBPX(MemoryStart, SizeOfMemory, (void*)bpxCallBack);
    }
    static bool SetMemoryBPXEx(ULONG_PTR MemoryStart, SIZE_T SizeOfMemory, eMemoryBPType BreakPointType, bool RestoreOnHit, fBreakPointCallback bpxCallBack)
    {
        return UE::SetMemoryBPXEx(MemoryStart, SizeOfMemory, BreakPointType, RestoreOnHit, (void*)bpxCallBack);
    }
    static bool RemoveMemoryBPX(ULONG_PTR MemoryStart, SIZE_T SizeOfMemory)
    {
        return UE::RemoveMemoryBPX(MemoryStart, SizeOfMemory);
    }
#ifdef _WIN64
    static bool GetContextFPUDataEx(HANDLE hActiveThread, XMM_SAVE_AREA32* FPUSaveArea)
#else
    static bool GetContextFPUDataEx(HANDLE hActiveThread, FLOATING_SAVE_AREA* FPUSaveArea)
#endif
    {
        return UE::GetContextFPUDataEx(hActiveThread, FPUSaveArea);
    }
    static ULONG_PTR GetContextDataEx(HANDLE hActiveThread, eContextData IndexOfRegister)
    {
        return UE::GetContextDataEx(hActiveThread, IndexOfRegister);
    }
    static ULONG_PTR GetContextData(eContextData IndexOfRegister)
    {
        return UE::GetContextData(IndexOfRegister);
    }
#ifdef _WIN64
    static bool SetContextFPUDataEx(HANDLE hActiveThread, const XMM_SAVE_AREA32* FPUSaveArea)
#else
    static bool SetContextFPUDataEx(HANDLE hActiveThread, const FLOATING_SAVE_AREA* FPUSaveArea)
#endif
    {
        return UE::SetContextFPUDataEx(hActiveThread, (void*)FPUSaveArea);
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
    static bool MatchPatternEx(HANDLE hProcess, void* MemoryToCheck, int SizeOfMemoryToCheck, const void* PatternToMatch, int SizeOfPatternToMatch, const BYTE* WildCard)
    {
        return UE::MatchPatternEx(hProcess, MemoryToCheck, SizeOfMemoryToCheck, (void*)PatternToMatch, SizeOfPatternToMatch, (BYTE*)WildCard);
    }
    static bool MatchPattern(void* MemoryToCheck, int SizeOfMemoryToCheck, const void* PatternToMatch, int SizeOfPatternToMatch, const BYTE* WildCard)
    {
        return UE::MatchPattern(MemoryToCheck, SizeOfMemoryToCheck, (void*)PatternToMatch, SizeOfPatternToMatch, (BYTE*)WildCard);
    }
    static ULONG_PTR FindEx(HANDLE hProcess, void* MemoryStart, DWORD MemorySize, const void* SearchPattern, DWORD PatternSize, const BYTE* WildCard)
    {
        return UE::FindEx(hProcess, MemoryStart, MemorySize, (void*)SearchPattern, PatternSize, (BYTE*)WildCard);
    }
    static ULONG_PTR Find(void* MemoryStart, DWORD MemorySize, const void* SearchPattern, DWORD PatternSize, const BYTE* WildCard)
    {
        return UE::Find(MemoryStart, MemorySize, (void*)SearchPattern, PatternSize, (BYTE*)WildCard);
    }
    static bool FillEx(HANDLE hProcess, void* MemoryStart, DWORD MemorySize, const BYTE* FillByte)
    {
        return UE::FillEx(hProcess, MemoryStart, MemorySize, (BYTE*)FillByte);
    }
    static bool Fill(void* MemoryStart, DWORD MemorySize, const BYTE* FillByte)
    {
        return UE::Fill(MemoryStart, MemorySize, (BYTE*)FillByte);
    }
    static bool PatchEx(HANDLE hProcess, void* MemoryStart, DWORD MemorySize, const void* ReplacePattern, DWORD ReplaceSize, bool AppendNOP, bool PrependNOP)
    {
        return UE::PatchEx(hProcess, MemoryStart, MemorySize, (void*)ReplacePattern, ReplaceSize, AppendNOP, PrependNOP);
    }
    static bool Patch(void* MemoryStart, DWORD MemorySize, const void* ReplacePattern, DWORD ReplaceSize, bool AppendNOP, bool PrependNOP)
    {
        return UE::Patch(MemoryStart, MemorySize, (void*)ReplacePattern, ReplaceSize, AppendNOP, PrependNOP);
    }
    static bool ReplaceEx(HANDLE hProcess, void* MemoryStart, DWORD MemorySize, const void* SearchPattern, DWORD PatternSize, DWORD NumberOfRepetitions, const void* ReplacePattern, DWORD ReplaceSize, const BYTE* WildCard)
    {
        return UE::ReplaceEx(hProcess, MemoryStart, MemorySize, (void*)SearchPattern, PatternSize, NumberOfRepetitions, (void*)ReplacePattern, ReplaceSize, (BYTE*)WildCard);
    }
    static bool Replace(void* MemoryStart, DWORD MemorySize, const void* SearchPattern, DWORD PatternSize, DWORD NumberOfRepetitions, const void* ReplacePattern, DWORD ReplaceSize, const BYTE* WildCard)
    {
        return UE::Replace(MemoryStart, MemorySize, (void*)SearchPattern, PatternSize, NumberOfRepetitions, (void*)ReplacePattern, ReplaceSize, (BYTE*)WildCard);
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
    static ULONG_PTR GetDebuggedDLLBaseAddress()
    {
        return UE::GetDebuggedDLLBaseAddress();
    }
    static ULONG_PTR GetDebuggedFileBaseAddress()
    {
        return UE::GetDebuggedFileBaseAddress();
    }
    static bool GetRemoteString(HANDLE hProcess, void* StringAddress, void* StringStorage, int MaximumStringSize)
    {
        return UE::GetRemoteString(hProcess, StringAddress, StringStorage, MaximumStringSize);
    }
    static ULONG_PTR GetFunctionParameter(HANDLE hProcess, eFunctionType FunctionType, DWORD ParameterNumber, eParameterType ParameterType)
    {
        return UE::GetFunctionParameter(hProcess, FunctionType, ParameterNumber, ParameterType);
    }
    static ULONG_PTR GetJumpDestinationEx(HANDLE hProcess, ULONG_PTR InstructionAddress, bool JustJumps)
    {
        return UE::GetJumpDestinationEx(hProcess, InstructionAddress, JustJumps);
    }
    static ULONG_PTR GetJumpDestination(HANDLE hProcess, ULONG_PTR InstructionAddress)
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
    static void StepOut(fBreakPointCallback StepOutCallBack, bool FinalStep)
    {
        UE::StepOut((void*)StepOutCallBack, FinalStep);
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
        return (const PROCESS_INFORMATION*)UE::TitanGetProcessInformation();
    }
    static const STARTUPINFOW* GetStartupInformation()
    {
        return (const STARTUPINFOW*)UE::TitanGetStartupInformation();
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
        UE::SetErrorModel(DisplayErrorMessages);
    }
};

class DebuggerA
{
public:

    static const PROCESS_INFORMATION* InitDebug(const char* szFileName, const char* szCommandLine, const char* szCurrentFolder)
    {
        return (const PROCESS_INFORMATION*)UE::InitDebug((char*)szFileName, (char*)szCommandLine, (char*)szCurrentFolder);
    }
    static const PROCESS_INFORMATION* InitDebugEx(const char* szFileName, const char* szCommandLine, const char* szCurrentFolder, DebuggerX::fBreakPointCallback EntryCallBack)
    {
        return (const PROCESS_INFORMATION*)UE::InitDebugEx((char*)szFileName, (char*)szCommandLine, (char*)szCurrentFolder, (void*)EntryCallBack);
    }
    static const PROCESS_INFORMATION* InitDLLDebug(const char* szFileName, bool ReserveModuleBase, const char* szCommandLine, const char* szCurrentFolder, DebuggerX::fBreakPointCallback EntryCallBack)
    {
        return (const PROCESS_INFORMATION*)UE::InitDLLDebug((char*)szFileName, ReserveModuleBase, (char*)szCommandLine, (char*)szCurrentFolder, (void*)EntryCallBack);
    }
    static void AutoDebugEx(const char* szFileName, bool ReserveModuleBase, const char* szCommandLine, const char* szCurrentFolder, DWORD TimeOut, DebuggerX::fBreakPointCallback EntryCallBack)
    {
        UE::AutoDebugEx((char*)szFileName, ReserveModuleBase, (char*)szCommandLine, (char*)szCurrentFolder, TimeOut, (void*)EntryCallBack);
    }
};

class DebuggerW
{
public:

    static const PROCESS_INFORMATION* InitDebug(const wchar_t* szFileName, const wchar_t* szCommandLine, const wchar_t* szCurrentFolder)
    {
        return (const PROCESS_INFORMATION*)UE::InitDebugW((wchar_t*)szFileName, (wchar_t*)szCommandLine, (wchar_t*)szCurrentFolder);
    }
    static const PROCESS_INFORMATION* InitDebugEx(const wchar_t* szFileName, const wchar_t* szCommandLine, const wchar_t* szCurrentFolder, DebuggerX::fBreakPointCallback EntryCallBack)
    {
        return (const PROCESS_INFORMATION*)UE::InitDebugExW((wchar_t*)szFileName, (wchar_t*)szCommandLine, (wchar_t*)szCurrentFolder, (void*)EntryCallBack);
    }
    static const PROCESS_INFORMATION* InitDLLDebug(const wchar_t* szFileName, bool ReserveModuleBase, const wchar_t* szCommandLine, const wchar_t* szCurrentFolder, DebuggerX::fBreakPointCallback EntryCallBack)
    {
        return (const PROCESS_INFORMATION*)UE::InitDLLDebugW((wchar_t*)szFileName, ReserveModuleBase, (wchar_t*)szCommandLine, (wchar_t*)szCurrentFolder, (void*)EntryCallBack);
    }
    static void AutoDebugEx(const wchar_t* szFileName, bool ReserveModuleBase, const wchar_t* szCommandLine, const wchar_t* szCurrentFolder, DWORD TimeOut, DebuggerX::fBreakPointCallback EntryCallBack)
    {
        UE::AutoDebugExW((wchar_t*)szFileName, ReserveModuleBase, (wchar_t*)szCommandLine, (wchar_t*)szCurrentFolder, TimeOut, (void*)EntryCallBack);
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
    using DebuggerX::StepOut;
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

public:

    typedef UE::ImportEnumData ImportEnumData;

protected:

    typedef void (TITCALL* fImportEnumCallBack)(void* ptrImportEnumData);
    typedef void* (TITCALL* fImportFixCallback)(void* fIATPointer);

    static void AddNewDll(const char* szDLLName, ULONG_PTR FirstThunk)
    {
        UE::ImporterAddNewDll((char*)szDLLName, FirstThunk);
    }
    static void AddNewAPI(const char* szAPIName, ULONG_PTR ThunkValue)
    {
        UE::ImporterAddNewAPI((char*)szAPIName, ThunkValue);
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
    static bool ExportIAT(ULONG_PTR StorePlace, ULONG_PTR FileMapVA, HANDLE hFileMap)
    {
        return UE::ImporterExportIAT(StorePlace, FileMapVA, hFileMap);
    }
    static long EstimatedSize()
    {
        return UE::ImporterEstimatedSize();
    }
    static ULONG_PTR FindAPIWriteLocation(const char* szAPIName)
    {
        return UE::ImporterFindAPIWriteLocation((char*)szAPIName);
    }
    static ULONG_PTR FindOrdinalAPIWriteLocation(ULONG_PTR OrdinalNumber)
    {
        return UE::ImporterFindOrdinalAPIWriteLocation(OrdinalNumber);
    }
    static ULONG_PTR FindAPIByWriteLocation(ULONG_PTR APIWriteLocation)
    {
        return UE::ImporterFindAPIByWriteLocation(APIWriteLocation);
    }
    static ULONG_PTR FindDLLByWriteLocation(ULONG_PTR APIWriteLocation)
    {
        return UE::ImporterFindDLLByWriteLocation(APIWriteLocation);
    }
    static const char* GetDLLName(ULONG_PTR APIAddress)
    {
        return (const char*)UE::ImporterGetDLLName(APIAddress);
    }
    static const wchar_t* GetDLLNameW(ULONG_PTR APIAddress)
    {
        return (const wchar_t*)UE::ImporterGetDLLNameW(APIAddress);
    }
    static const char* GetAPIName(ULONG_PTR APIAddress)
    {
        return (const char*)UE::ImporterGetAPIName(APIAddress);
    }
    static ULONG_PTR GetAPIOrdinalNumber(ULONG_PTR APIAddress)
    {
        return UE::ImporterGetAPIOrdinalNumber(APIAddress);
    }
    static const char* GetAPINameEx(ULONG_PTR APIAddress, const HMODULE* DLLBasesList)
    {
        return (const char*)UE::ImporterGetAPINameEx(APIAddress, (ULONG_PTR)DLLBasesList);
    }
    static ULONG_PTR GetRemoteAPIAddress(HANDLE hProcess, ULONG_PTR APIAddress)
    {
        return UE::ImporterGetRemoteAPIAddress(hProcess, APIAddress);
    }
    static ULONG_PTR GetRemoteAPIAddressEx(const char* szDLLName, const char* szAPIName)
    {
        return UE::ImporterGetRemoteAPIAddressEx((char*)szDLLName, (char*)szAPIName);
    }
    static ULONG_PTR GetLocalAPIAddress(HANDLE hProcess, ULONG_PTR APIAddress)
    {
        return UE::ImporterGetLocalAPIAddress(hProcess, APIAddress);
    }
    static const char* GetDLLNameFromDebugee(HANDLE hProcess, ULONG_PTR APIAddress)
    {
        return (const char*)UE::ImporterGetDLLNameFromDebugee(hProcess, APIAddress);
    }
    static const wchar_t* GetDLLNameFromDebugeeW(HANDLE hProcess, ULONG_PTR APIAddress)
    {
        return (const wchar_t*)UE::ImporterGetDLLNameFromDebugeeW(hProcess, APIAddress);
    }
    static const char* GetAPINameFromDebugee(HANDLE hProcess, ULONG_PTR APIAddress)
    {
        return (const char*)UE::ImporterGetAPINameFromDebugee(hProcess, APIAddress);
    }
    static ULONG_PTR GetAPIOrdinalNumberFromDebugee(HANDLE hProcess, ULONG_PTR APIAddress)
    {
        return UE::ImporterGetAPIOrdinalNumberFromDebugee(hProcess, APIAddress);
    }
    static long GetDLLIndexEx(ULONG_PTR APIAddress, const HMODULE* DLLBasesList)
    {
        return UE::ImporterGetDLLIndexEx(APIAddress, (ULONG_PTR)DLLBasesList);
    }
    static long GetDLLIndex(HANDLE hProcess, ULONG_PTR APIAddress, const HMODULE* DLLBasesList)
    {
        return UE::ImporterGetDLLIndex(hProcess, APIAddress, (ULONG_PTR)DLLBasesList);
    }
    static ULONG_PTR GetRemoteDLLBase(HANDLE hProcess, HMODULE LocalModuleBase)
    {
        return UE::ImporterGetRemoteDLLBase(hProcess, LocalModuleBase);
    }
    static ULONG_PTR GetRemoteDLLBaseEx(HANDLE hProcess, char* szModuleName)
    {
        return UE::ImporterGetRemoteDLLBaseEx(hProcess, szModuleName);
    }
    static void* GetRemoteDLLBaseExW(HANDLE hProcess, WCHAR* szModuleName)
    {
        return UE::ImporterGetRemoteDLLBaseExW(hProcess, szModuleName);
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
    static long GetForwardedDLLIndex(HANDLE hProcess, ULONG_PTR APIAddress, const HMODULE* DLLBasesList)
    {
        return UE::ImporterGetForwardedDLLIndex(hProcess, APIAddress, (ULONG_PTR)DLLBasesList);
    }
    static ULONG_PTR GetForwardedAPIOrdinalNumber(HANDLE hProcess, ULONG_PTR APIAddress)
    {
        return UE::ImporterGetForwardedAPIOrdinalNumber(hProcess, APIAddress);
    }
    static ULONG_PTR GetNearestAPIAddress(HANDLE hProcess, ULONG_PTR APIAddress)
    {
        return UE::ImporterGetNearestAPIAddress(hProcess, APIAddress);
    }
    static const char* GetNearestAPIName(HANDLE hProcess, ULONG_PTR APIAddress)
    {
        return (const char*)UE::ImporterGetNearestAPIName(hProcess, APIAddress);
    }
    static void AutoSearchIATEx(DWORD ProcessId, ULONG_PTR ImageBase, ULONG_PTR SearchStart, ULONG_PTR* pIATStart, ULONG_PTR* pIATSize)
    {
        UE::ImporterAutoSearchIATEx(ProcessId, ImageBase, SearchStart, pIATStart, pIATSize);
    }
    static void EnumAddedData(fImportEnumCallBack EnumCallBack)
    {
        UE::ImporterEnumAddedData((void*)EnumCallBack);
    }
    static bool DeleteAPI(DWORD_PTR apiAddr)
    {
        return UE::ImporterDeleteAPI(apiAddr);
    }
};

class ImporterA
{
public:

    static bool ExportIATEx(const char* szDumpFileName, const char* szExportFileName, const char* szSectionName)
    {
        return UE::ImporterExportIATEx((char*)szDumpFileName, (char*)szExportFileName, (char*)szSectionName);
    }
    static bool CopyOriginalIAT(const char* szOriginalFile, const char* szDumpFile)
    {
        return UE::ImporterCopyOriginalIAT((char*)szOriginalFile, (char*)szDumpFile);
    }
    static bool LoadImportTable(const char* szFileName)
    {
        return UE::ImporterLoadImportTable((char*)szFileName);
    }
    static bool MoveOriginalIAT(const char* szOriginalFile, const char* szDumpFile, const char* szSectionName)
    {
        return UE::ImporterMoveOriginalIAT((char*)szOriginalFile, (char*)szDumpFile, (char*)szSectionName);
    }
    static void AutoSearchIAT(DWORD ProcessId, char* szFileName, ULONG_PTR SearchStart, LPVOID pIATStart, LPVOID pIATSize)
    {
        UE::ImporterAutoSearchIAT(ProcessId, (char*)szFileName, SearchStart, pIATStart, pIATSize);
    }
    static long AutoFixIATEx(DWORD ProcessId, const char* szDumpedFile, const char* szSectionName, bool DumpRunningProcess, bool RealignFile, ULONG_PTR EntryPointAddress, ULONG_PTR ImageBase, ULONG_PTR SearchStart, DWORD SearchSize, DWORD SearchStep, bool TryAutoFix, bool FixEliminations, ImporterX::fImportFixCallback UnknownPointerFixCallback)
    {
        return UE::ImporterAutoFixIATEx(ProcessId, (char*)szDumpedFile, (char*)szSectionName, DumpRunningProcess, RealignFile, EntryPointAddress, ImageBase, SearchStart, TryAutoFix, FixEliminations, (void*)UnknownPointerFixCallback);
    }
    static long AutoFixIAT(DWORD ProcessId, const char* szDumpedFile, ULONG_PTR SearchStart)
    {
        return UE::ImporterAutoFixIAT(ProcessId, (char*)szDumpedFile, SearchStart);
    }
};

class ImporterW
{
public:

    static bool ExportIATEx(const wchar_t* szDumpFileName, const wchar_t* szExportFileName, const wchar_t* szSectionName)
    {
        return UE::ImporterExportIATExW((wchar_t*)szDumpFileName, (wchar_t*)szExportFileName, (wchar_t*)szSectionName);
    }
    static bool CopyOriginalIAT(const wchar_t* szOriginalFile, const wchar_t* szDumpFile)
    {
        return UE::ImporterCopyOriginalIATW((wchar_t*)szOriginalFile, (wchar_t*)szDumpFile);
    }
    static bool LoadImportTable(const wchar_t* szFileName)
    {
        return UE::ImporterLoadImportTableW((wchar_t*)szFileName);
    }
    static bool MoveOriginalIAT(const wchar_t* szOriginalFile, const wchar_t* szDumpFile, const char* szSectionName)
    {
        return UE::ImporterMoveOriginalIATW((wchar_t*)szOriginalFile, (wchar_t*)szDumpFile, (char*)szSectionName);
    }
    static void AutoSearchIAT(DWORD ProcessId, const wchar_t* szFileName, ULONG_PTR SearchStart, ULONG_PTR* pIATStart, ULONG_PTR* pIATSize)
    {
        UE::ImporterAutoSearchIATW(ProcessId, (wchar_t*)szFileName, SearchStart, pIATStart, pIATSize);
    }
    static long AutoFixIATEx(DWORD ProcessId, const wchar_t* szDumpedFile, const char* szSectionName, bool DumpRunningProcess, bool RealignFile, ULONG_PTR EntryPointAddress, ULONG_PTR ImageBase, ULONG_PTR SearchStart, bool TryAutoFix, bool FixEliminations, ImporterX::fImportFixCallback UnknownPointerFixCallback)
    {
        return UE::ImporterAutoFixIATExW(ProcessId, (wchar_t*)szDumpedFile, (char*)szSectionName, DumpRunningProcess, RealignFile, EntryPointAddress, ImageBase, SearchStart, TryAutoFix, FixEliminations, (void*)UnknownPointerFixCallback);
    }
    static long AutoFixIAT(DWORD ProcessId, const wchar_t* szDumpedFile, ULONG_PTR SearchStart)
    {
        return UE::ImporterAutoFixIATW(ProcessId, (wchar_t*)szDumpedFile, SearchStart);
    }
};

class Importer : public ImporterX, ImporterA, ImporterW
{
public:

    using ImporterX::fImportEnumCallBack;
    using ImporterX::fImportFixCallback;

    using ImporterX::AddNewDll;
    using ImporterX::AddNewAPI;
    using ImporterX::AddNewOrdinalAPI;
    using ImporterX::GetAddedDllCount;
    using ImporterX::GetAddedAPICount;
    using ImporterX::ExportIAT;
    using ImporterX::EstimatedSize;
    using ImporterA::ExportIATEx;
    using ImporterW::ExportIATEx;
    using ImporterX::FindAPIWriteLocation;
    using ImporterX::FindOrdinalAPIWriteLocation;
    using ImporterX::FindAPIByWriteLocation;
    using ImporterX::FindDLLByWriteLocation;
    using ImporterX::GetDLLName;
    using ImporterX::GetDLLNameW;
    using ImporterX::GetAPIName;
    using ImporterX::GetAPIOrdinalNumber;
    using ImporterX::GetAPINameEx;
    using ImporterX::GetRemoteAPIAddress;
    using ImporterX::GetRemoteAPIAddressEx;
    using ImporterX::GetLocalAPIAddress;
    using ImporterX::GetDLLNameFromDebugee;
    using ImporterX::GetDLLNameFromDebugeeW;
    using ImporterX::GetAPINameFromDebugee;
    using ImporterX::GetAPIOrdinalNumberFromDebugee;
    using ImporterX::GetDLLIndexEx;
    using ImporterX::GetDLLIndex;
    using ImporterX::GetRemoteDLLBase;
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
    using ImporterX::DeleteAPI;
    using ImporterA::AutoFixIATEx;
    using ImporterW::AutoFixIATEx;
    using ImporterA::AutoFixIAT;
    using ImporterW::AutoFixIAT;
};

// ---

class LibrarianX
{
protected:

    typedef void (TITCALL* fLibraryBreakPointCallback)(const LOAD_DLL_DEBUG_INFO* SpecialDBG);

    static bool SetBreakPoint(const char* szLibraryName, eLibraryEvent bpxType, bool SingleShoot, fLibraryBreakPointCallback bpxCallBack)
    {
        return UE::LibrarianSetBreakPoint((char*)szLibraryName, bpxType, SingleShoot, (void*)bpxCallBack);
    }
    static bool RemoveBreakPoint(const char* szLibraryName, eLibraryEvent bpxType)
    {
        return UE::LibrarianRemoveBreakPoint((char*)szLibraryName, bpxType);
    }
};

class LibrarianA
{
public:

    typedef UE::LIBRARY_ITEM_DATA LIBRARY_ITEM_DATA;

    typedef void (TITCALL* fLibraryEnumCallback)(const LIBRARY_ITEM_DATA* fLibraryDetail);

    static const LIBRARY_ITEM_DATA* GetLibraryInfo(const char* szLibraryName)
    {
        return (const LIBRARY_ITEM_DATA*)UE::LibrarianGetLibraryInfo((char*)szLibraryName);
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

    typedef void (TITCALL* fLibraryEnumCallback)(const LIBRARY_ITEM_DATA* fLibraryDetail);

    static const LIBRARY_ITEM_DATA* GetLibraryInfo(const wchar_t* szLibraryName)
    {
        return (const LIBRARY_ITEM_DATA*)UE::LibrarianGetLibraryInfoW((wchar_t*)szLibraryName);
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

    typedef bool(TITCALL* fHookEnumCallBack)(const HOOK_ENTRY* HookDetails, void* ptrOriginalInstructions, const LibrarianA::LIBRARY_ITEM_DATA* ModuleInformation, DWORD SizeOfImage);

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
    static ULONG_PTR Level1(HANDLE hProcess, ULONG_PTR AddressToTrace)
    {
        return UE::TracerLevel1(hProcess, AddressToTrace);
    }
    static ULONG_PTR HashTracerLevel1(HANDLE hProcess, ULONG_PTR AddressToTrace, DWORD InputNumberOfInstructions)
    {
        return UE::HashTracerLevel1(hProcess, AddressToTrace, InputNumberOfInstructions);
    }
    static long DetectRedirection(HANDLE hProcess, ULONG_PTR AddressToTrace)
    {
        return UE::TracerDetectRedirection(hProcess, AddressToTrace);
    }
    static ULONG_PTR FixKnownRedirection(HANDLE hProcess, ULONG_PTR AddressToTrace, DWORD RedirectionId)
    {
        return UE::TracerFixKnownRedirection(hProcess, AddressToTrace, RedirectionId);
    }
    static ULONG_PTR FixRedirectionViaModule(HMODULE hModuleHandle, HANDLE hProcess, ULONG_PTR AddressToTrace, DWORD IdParameter)
    {
        return UE::TracerFixRedirectionViaModule(hModuleHandle, hProcess, AddressToTrace, IdParameter);
    }
    static ULONG_PTR DetectRedirectionViaModule(HMODULE hModuleHandle, HANDLE hProcess, ULONG_PTR AddressToTrace, DWORD* ReturnedId)
    {
        return UE::TracerDetectRedirectionViaModule(hModuleHandle, hProcess, AddressToTrace, ReturnedId);
    }
    static long FixRedirectionViaImpRecPlugin(HANDLE hProcess, const char* szPluginName, ULONG_PTR AddressToTrace)
    {
        return UE::TracerFixRedirectionViaImpRecPlugin(hProcess, (char*)szPluginName, AddressToTrace);
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
    static void Init(DWORD MemorySize, ULONG_PTR ImageBase, DWORD ExportOrdinalBase, const char* szExportModuleName)
    {
        UE::ExporterInit(MemorySize, ImageBase, ExportOrdinalBase, (char*)szExportModuleName);
    }
    static bool AddNewExport(const char* szExportName, DWORD ExportRelativeAddress)
    {
        return UE::ExporterAddNewExport((char*)szExportName, ExportRelativeAddress);
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

    static bool BuildExportTableEx(const char* szExportFileName, const char* szSectionName)
    {
        return UE::ExporterBuildExportTableEx((char*)szExportFileName, (char*)szSectionName);
    }
    static bool LoadExportTable(const char* szFileName)
    {
        return UE::ExporterLoadExportTable((char*)szFileName);
    }
};

class ExporterW
{
public:

    static bool BuildExportTableEx(const wchar_t* szExportFileName, const char* szSectionName)
    {
        return UE::ExporterBuildExportTableExW((wchar_t*)szExportFileName, (char*)szSectionName);
    }
    static bool LoadExportTable(const wchar_t* szFileName)
    {
        return UE::ExporterLoadExportTableW((wchar_t*)szFileName);
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

    typedef void(TITCALL* fProcessWithLibraryEnumCallback)(DWORD ProcessId, HMODULE ModuleBaseAddress);

    static void EnumProcessesWithLibrary(char* szLibraryName, fProcessWithLibraryEnumCallback EnumFunction)
    {
        UE::EnumProcessesWithLibrary(szLibraryName, (void*)EnumFunction);
    }

    static HANDLE Open(DWORD dwDesiredAccess, bool bInheritHandle, DWORD dwProcessId)
    {
        return UE::TitanOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
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
    using ProcessX::Open;
};

class TLSX
{
protected:

    static bool BreakOnCallBack(const ULONG_PTR* ArrayOfCallBacks, DWORD NumberOfCallBacks, Debugger::fBreakPointCallback bpxCallBack)
    {
        return UE::TLSBreakOnCallBack((void*)ArrayOfCallBacks, NumberOfCallBacks, (void*)bpxCallBack);
    }
    static bool RestoreData()
    {
        return UE::TLSRestoreData();
    }
    static bool BuildNewTable(ULONG_PTR FileMapVA, ULONG_PTR StorePlace, ULONG_PTR StorePlaceRVA, const ULONG_PTR* ArrayOfCallBacks, DWORD NumberOfCallBacks)
    {
        return UE::TLSBuildNewTable(FileMapVA, StorePlace, StorePlaceRVA, (void*)ArrayOfCallBacks, NumberOfCallBacks);
    }
};

class TLSA
{
public:

    static bool GrabCallBackData(const char* szFileName, ULONG_PTR* ArrayOfCallBacks, DWORD* NumberOfCallBacks)
    {
        return UE::TLSGrabCallBackData((char*)szFileName, (void*)ArrayOfCallBacks, NumberOfCallBacks);
    }
    static bool BreakOnCallBackEx(const char* szFileName, Debugger::fBreakPointCallback bpxCallBack)
    {
        return UE::TLSBreakOnCallBackEx((char*)szFileName, (void*)bpxCallBack);
    }
    static bool RemoveCallback(const char* szFileName)
    {
        return UE::TLSRemoveCallback((char*)szFileName);
    }
    static bool RemoveTable(const char* szFileName)
    {
        return UE::TLSRemoveTable((char*)szFileName);
    }
    static bool BackupData(const char* szFileName)
    {
        return UE::TLSBackupData((char*)szFileName);
    }
    static bool BuildNewTableEx(const char* szFileName, const char* szSectionName, const ULONG_PTR* ArrayOfCallBacks, DWORD NumberOfCallBacks)
    {
        return UE::TLSBuildNewTableEx((char*)szFileName, (char*)szSectionName, (void*)ArrayOfCallBacks, NumberOfCallBacks);
    }
};

class TLSW
{
public:

    static bool GrabCallBackData(const wchar_t* szFileName, ULONG_PTR* ArrayOfCallBacks, DWORD* NumberOfCallBacks)
    {
        return UE::TLSGrabCallBackDataW((wchar_t*)szFileName, (void*)ArrayOfCallBacks, NumberOfCallBacks);
    }
    static bool BreakOnCallBackEx(const wchar_t* szFileName, Debugger::fBreakPointCallback bpxCallBack)
    {
        return UE::TLSBreakOnCallBackExW((wchar_t*)szFileName, (void*)bpxCallBack);
    }
    static bool RemoveCallback(const wchar_t* szFileName)
    {
        return UE::TLSRemoveCallbackW((wchar_t*)szFileName);
    }
    static bool RemoveTable(const wchar_t* szFileName)
    {
        return UE::TLSRemoveTableW((wchar_t*)szFileName);
    }
    static bool BackupData(const wchar_t* szFileName)
    {
        return UE::TLSBackupDataW((wchar_t*)szFileName);
    }
    static bool BuildNewTableEx(const wchar_t* szFileName, const char* szSectionName, const ULONG_PTR* ArrayOfCallBacks, DWORD NumberOfCallBacks)
    {
        return UE::TLSBuildNewTableExW((wchar_t*)szFileName, (char*)szSectionName, (void*)ArrayOfCallBacks, NumberOfCallBacks);
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
    static ULONG_PTR GetHandleDetails(HANDLE hProcess, DWORD ProcessId, HANDLE hHandle, eHandlerReturnType InformationReturn)
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
    static ULONG_PTR GetOpenMutexHandle(HANDLE hProcess, DWORD ProcessId, char* szMutexString)
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
    static ULONG_PTR GetOpenMutexHandle(HANDLE hProcess, DWORD ProcessId, wchar_t* szMutexString)
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

    static bool LoadLibrary(HANDLE hProcess, const char* szLibraryFile, bool WaitForThreadExit)
    {
        return UE::RemoteLoadLibrary(hProcess, (char*)szLibraryFile, WaitForThreadExit);
    }
    static bool FreeLibrary(HANDLE hProcess, HMODULE hModule, const char* szLibraryFile, bool WaitForThreadExit)
    {
        return UE::RemoteFreeLibrary(hProcess, hModule, (char*)szLibraryFile, WaitForThreadExit);
    }
};

class RemoteW
{
public:

    static bool LoadLibrary(HANDLE hProcess, const wchar_t* szLibraryFile, bool WaitForThreadExit)
    {
        return UE::RemoteLoadLibraryW(hProcess, (wchar_t*)szLibraryFile, WaitForThreadExit);
    }
    static bool FreeLibrary(HANDLE hProcess, HMODULE hModule, const wchar_t* szLibraryFile, bool WaitForThreadExit)
    {
        return UE::RemoteFreeLibraryW(hProcess, hModule, (wchar_t*)szLibraryFile, WaitForThreadExit);
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

    typedef bool (__stdcall* fStaticDecryptCallback)(void* sMemoryStart, int sKeySize);

    static bool FileGetContent(HANDLE FileHandle, DWORD FilePositionLow, const DWORD* FilePositionHigh, void* Buffer, DWORD Size)
    {
        return UE::StaticFileGetContent(FileHandle, FilePositionLow, (DWORD*)FilePositionHigh, Buffer, Size);
    }
    static void FileClose(HANDLE FileHandle)
    {
        UE::StaticFileClose(FileHandle);
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
    static bool MemoryDecompress(const void* Source, DWORD SourceSize, void* Destination, DWORD DestinationSize, eCompressionAlgorithm Algorithm)
    {
        return UE::StaticMemoryDecompress((void*)Source, SourceSize, Destination, DestinationSize, Algorithm);
    }
    static bool HashMemory(const void* MemoryToHash, DWORD SizeOfMemory, void* HashDigest, bool OutputString, eHashAlgorithm Algorithm)
    {
        return UE::StaticHashMemory((void*)MemoryToHash, SizeOfMemory, HashDigest, OutputString, Algorithm);
    }
};

class StaticA
{
public:

    static bool FileLoad(const char* szFileName, eAccess DesiredAccess, bool SimulateLoad, HANDLE* FileHandle, DWORD* LoadedSize, HANDLE* FileMap, ULONG_PTR* FileMapVA)
    {
        return UE::StaticFileLoad((char*)szFileName, DesiredAccess, SimulateLoad, FileHandle, LoadedSize, FileMap, FileMapVA);
    }
    static bool FileUnload(const char* szFileName, bool CommitChanges, HANDLE FileHandle, DWORD LoadedSize, HANDLE FileMap, ULONG_PTR FileMapVA)
    {
        return UE::StaticFileUnload((char*)szFileName, CommitChanges, FileHandle, LoadedSize, FileMap, FileMapVA);
    }
    static bool FileOpen(const char* szFileName, DWORD DesiredAccess, HANDLE* FileHandle, DWORD* FileSizeLow, DWORD* FileSizeHigh)
    {
        return UE::StaticFileOpen((char*)szFileName, DesiredAccess, FileHandle, FileSizeLow, FileSizeHigh);
    }
    static bool RawMemoryCopy(HANDLE hFile, ULONG_PTR FileMapVA, ULONG_PTR VitualAddressToCopy, DWORD Size, bool AddressIsRVA, const char* szDumpFileName)
    {
        return UE::StaticRawMemoryCopy(hFile, FileMapVA, VitualAddressToCopy, Size, AddressIsRVA, (char*)szDumpFileName);
    }
    static bool RawMemoryCopyEx(HANDLE hFile, DWORD RawAddressToCopy, DWORD Size, const char* szDumpFileName)
    {
        return UE::StaticRawMemoryCopyEx(hFile, RawAddressToCopy, Size, (char*)szDumpFileName);
    }
    static bool RawMemoryCopyEx64(HANDLE hFile, DWORD64 RawAddressToCopy, DWORD64 Size, const char* szDumpFileName)
    {
        return UE::StaticRawMemoryCopyEx64(hFile, RawAddressToCopy, Size, (char*)szDumpFileName);
    }
    static bool HashFile(const char* szFileName, void* HashDigest, bool OutputString, eHashAlgorithm Algorithm)
    {
        return UE::StaticHashFile((char*)szFileName, (char*)HashDigest, OutputString, Algorithm);
    }
};

class StaticW
{
public:

    static bool FileLoad(const wchar_t* szFileName, eAccess DesiredAccess, bool SimulateLoad, HANDLE* FileHandle, DWORD* LoadedSize, HANDLE* FileMap, ULONG_PTR* FileMapVA)
    {
        return UE::StaticFileLoadW((wchar_t*)szFileName, DesiredAccess, SimulateLoad, FileHandle, LoadedSize, FileMap, FileMapVA);
    }
    static bool FileUnload(const wchar_t* szFileName, bool CommitChanges, HANDLE FileHandle, DWORD LoadedSize, HANDLE FileMap, ULONG_PTR FileMapVA)
    {
        return UE::StaticFileUnloadW((wchar_t*)szFileName, CommitChanges, FileHandle, LoadedSize, FileMap, FileMapVA);
    }
    static bool FileOpen(const wchar_t* szFileName, DWORD DesiredAccess, HANDLE* FileHandle, DWORD* FileSizeLow, DWORD* FileSizeHigh)
    {
        return UE::StaticFileOpenW((wchar_t*)szFileName, DesiredAccess, FileHandle, FileSizeLow, FileSizeHigh);
    }
    static bool RawMemoryCopy(HANDLE hFile, ULONG_PTR FileMapVA, ULONG_PTR VitualAddressToCopy, DWORD Size, bool AddressIsRVA, const wchar_t* szDumpFileName)
    {
        return UE::StaticRawMemoryCopyW(hFile, FileMapVA, VitualAddressToCopy, Size, AddressIsRVA, (wchar_t*)szDumpFileName);
    }
    static bool RawMemoryCopyEx(HANDLE hFile, DWORD RawAddressToCopy, DWORD Size, const wchar_t* szDumpFileName)
    {
        return UE::StaticRawMemoryCopyExW(hFile, RawAddressToCopy, Size, (wchar_t*)szDumpFileName);
    }
    static bool RawMemoryCopyEx64(HANDLE hFile, DWORD64 RawAddressToCopy, DWORD64 Size, const wchar_t* szDumpFileName)
    {
        return UE::StaticRawMemoryCopyEx64W(hFile, RawAddressToCopy, Size, (wchar_t*)szDumpFileName);
    }
    static bool HashFile(const wchar_t* szFileName, void* HashDigest, bool OutputString, eHashAlgorithm Algorithm)
    {
        return UE::StaticHashFileW((wchar_t*)szFileName, (char*)HashDigest, OutputString, Algorithm);
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
    static bool EngineCheckStructAlignment(DWORD StructureType, ULONG_PTR StructureSize)
    {
        return UE::EngineCheckStructAlignment(StructureType, StructureSize);
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
    using EngineX::EngineCheckStructAlignment;
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
