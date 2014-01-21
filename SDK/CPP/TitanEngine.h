#ifndef TITANENGINE
#define TITANENGINE

#define TITCALL

#if _MSC_VER > 1000
#pragma once
#endif

#include <windows.h>

#pragma pack(push, 1)

// Global.Constant.Structure.Declaration:
// Engine.External:
const BYTE UE_ACCESS_READ = 0;
const BYTE UE_ACCESS_WRITE = 1;
const BYTE UE_ACCESS_ALL = 2;

const BYTE UE_HIDE_PEBONLY = 0;
const BYTE UE_HIDE_BASIC = 1;

const BYTE UE_PLUGIN_CALL_REASON_PREDEBUG = 1;
const BYTE UE_PLUGIN_CALL_REASON_EXCEPTION = 2;
const BYTE UE_PLUGIN_CALL_REASON_POSTDEBUG = 3;

const BYTE TEE_HOOK_NRM_JUMP = 1;
const BYTE TEE_HOOK_NRM_CALL = 3;
const BYTE TEE_HOOK_IAT = 5;

const BYTE UE_ENGINE_ALOW_MODULE_LOADING = 1;
const BYTE UE_ENGINE_AUTOFIX_FORWARDERS = 2;
const BYTE UE_ENGINE_PASS_ALL_EXCEPTIONS = 3;
const BYTE UE_ENGINE_NO_CONSOLE_WINDOW = 4;
const BYTE UE_ENGINE_BACKUP_FOR_CRITICAL_FUNCTIONS = 5;
const BYTE UE_ENGINE_CALL_PLUGIN_CALLBACK = 6;
const BYTE UE_ENGINE_RESET_CUSTOM_HANDLER = 7;
const BYTE UE_ENGINE_CALL_PLUGIN_DEBUG_CALLBACK = 8;

const BYTE UE_OPTION_REMOVEALL = 1;
const BYTE UE_OPTION_DISABLEALL = 2;
const BYTE UE_OPTION_REMOVEALLDISABLED = 3;
const BYTE UE_OPTION_REMOVEALLENABLED = 4;

const BYTE UE_STATIC_DECRYPTOR_XOR = 1;
const BYTE UE_STATIC_DECRYPTOR_SUB = 2;
const BYTE UE_STATIC_DECRYPTOR_ADD = 3;

const BYTE UE_STATIC_DECRYPTOR_FOREWARD = 1;
const BYTE UE_STATIC_DECRYPTOR_BACKWARD = 2;

const BYTE UE_STATIC_KEY_SIZE_1 = 1;
const BYTE UE_STATIC_KEY_SIZE_2 = 2;
const BYTE UE_STATIC_KEY_SIZE_4 = 4;
const BYTE UE_STATIC_KEY_SIZE_8 = 8;

const BYTE UE_STATIC_APLIB = 1;
const BYTE UE_STATIC_APLIB_DEPACK = 2;
const BYTE UE_STATIC_LZMA = 3;

const BYTE UE_STATIC_HASH_MD5 = 1;
const BYTE UE_STATIC_HASH_SHA1 = 2;
const BYTE UE_STATIC_HASH_CRC32 = 3;

const DWORD UE_RESOURCE_LANGUAGE_ANY = -1;

const BYTE UE_PE_OFFSET = 0;
const BYTE UE_IMAGEBASE = 1;
const BYTE UE_OEP = 2;
const BYTE UE_SIZEOFIMAGE = 3;
const BYTE UE_SIZEOFHEADERS = 4;
const BYTE UE_SIZEOFOPTIONALHEADER = 5;
const BYTE UE_SECTIONALIGNMENT = 6;
const BYTE UE_IMPORTTABLEADDRESS = 7;
const BYTE UE_IMPORTTABLESIZE = 8;
const BYTE UE_RESOURCETABLEADDRESS = 9;
const BYTE UE_RESOURCETABLESIZE = 10;
const BYTE UE_EXPORTTABLEADDRESS = 11;
const BYTE UE_EXPORTTABLESIZE = 12;
const BYTE UE_TLSTABLEADDRESS = 13;
const BYTE UE_TLSTABLESIZE = 14;
const BYTE UE_RELOCATIONTABLEADDRESS = 15;
const BYTE UE_RELOCATIONTABLESIZE = 16;
const BYTE UE_TIMEDATESTAMP = 17;
const BYTE UE_SECTIONNUMBER = 18;
const BYTE UE_CHECKSUM = 19;
const BYTE UE_SUBSYSTEM = 20;
const BYTE UE_CHARACTERISTICS = 21;
const BYTE UE_NUMBEROFRVAANDSIZES = 22;
const BYTE UE_BASEOFCODE = 23;
const BYTE UE_BASEOFDATA = 24;
//leaving some enum space here for future additions
const BYTE UE_SECTIONNAME = 40;
const BYTE UE_SECTIONVIRTUALOFFSET = 41;
const BYTE UE_SECTIONVIRTUALSIZE = 42;
const BYTE UE_SECTIONRAWOFFSET = 43;
const BYTE UE_SECTIONRAWSIZE = 44;
const BYTE UE_SECTIONFLAGS = 45;

const long UE_VANOTFOUND = -2;

const BYTE UE_CH_BREAKPOINT = 1;
const BYTE UE_CH_SINGLESTEP = 2;
const BYTE UE_CH_ACCESSVIOLATION = 3;
const BYTE UE_CH_ILLEGALINSTRUCTION = 4;
const BYTE UE_CH_NONCONTINUABLEEXCEPTION = 5;
const BYTE UE_CH_ARRAYBOUNDSEXCEPTION = 6;
const BYTE UE_CH_FLOATDENORMALOPERAND = 7;
const BYTE UE_CH_FLOATDEVIDEBYZERO = 8;
const BYTE UE_CH_INTEGERDEVIDEBYZERO = 9;
const BYTE UE_CH_INTEGEROVERFLOW = 10;
const BYTE UE_CH_PRIVILEGEDINSTRUCTION = 11;
const BYTE UE_CH_PAGEGUARD = 12;
const BYTE UE_CH_EVERYTHINGELSE = 13;
const BYTE UE_CH_CREATETHREAD = 14;
const BYTE UE_CH_EXITTHREAD = 15;
const BYTE UE_CH_CREATEPROCESS = 16;
const BYTE UE_CH_EXITPROCESS = 17;
const BYTE UE_CH_LOADDLL = 18;
const BYTE UE_CH_UNLOADDLL = 19;
const BYTE UE_CH_OUTPUTDEBUGSTRING = 20;
const BYTE UE_CH_AFTEREXCEPTIONPROCESSING = 21;
const BYTE UE_CH_ALLEVENTS = 22;
const BYTE UE_CH_SYSTEMBREAKPOINT = 23;
const BYTE UE_CH_UNHANDLEDEXCEPTION = 24;

const BYTE UE_OPTION_HANDLER_RETURN_HANDLECOUNT = 1;
const BYTE UE_OPTION_HANDLER_RETURN_ACCESS = 2;
const BYTE UE_OPTION_HANDLER_RETURN_FLAGS = 3;
const BYTE UE_OPTION_HANDLER_RETURN_TYPENAME = 4;

const BYTE UE_BREAKPOINT_INT3 = 1;
const BYTE UE_BREAKPOINT_LONG_INT3 = 2;
const BYTE UE_BREAKPOINT_UD2 = 3;

const BYTE UE_BPXREMOVED = 0;
const BYTE UE_BPXACTIVE = 1;
const BYTE UE_BPXINACTIVE = 2;

const BYTE UE_BREAKPOINT = 0;
const BYTE UE_SINGLESHOOT = 1;
const BYTE UE_HARDWARE = 2;
const BYTE UE_MEMORY = 3;
const BYTE UE_MEMORY_READ = 4;
const BYTE UE_MEMORY_WRITE = 5;
const BYTE UE_MEMORY_EXECUTE = 6;
const DWORD UE_BREAKPOINT_TYPE_INT3 = 0x10000000;
const DWORD UE_BREAKPOINT_TYPE_LONG_INT3 = 0x20000000;
const DWORD UE_BREAKPOINT_TYPE_UD2 = 0x30000000;

const BYTE UE_HARDWARE_EXECUTE = 4;
const BYTE UE_HARDWARE_WRITE = 5;
const BYTE UE_HARDWARE_READWRITE = 6;

const BYTE UE_HARDWARE_SIZE_1 = 7;
const BYTE UE_HARDWARE_SIZE_2 = 8;
const BYTE UE_HARDWARE_SIZE_4 = 9;
const BYTE UE_HARDWARE_SIZE_8 = 10;

const BYTE UE_ON_LIB_LOAD = 1;
const BYTE UE_ON_LIB_UNLOAD = 2;
const BYTE UE_ON_LIB_ALL = 3;

const BYTE UE_APISTART = 0;
const BYTE UE_APIEND = 1;

const BYTE UE_PLATFORM_x86 = 1;
const BYTE UE_PLATFORM_x64 = 2;
const BYTE UE_PLATFORM_ALL = 3;

const BYTE UE_FUNCTION_STDCALL = 1;
const BYTE UE_FUNCTION_CCALL = 2;
const BYTE UE_FUNCTION_FASTCALL = 3;
const BYTE UE_FUNCTION_STDCALL_RET = 4;
const BYTE UE_FUNCTION_CCALL_RET = 5;
const BYTE UE_FUNCTION_FASTCALL_RET = 6;
const BYTE UE_FUNCTION_STDCALL_CALL = 7;
const BYTE UE_FUNCTION_CCALL_CALL = 8;
const BYTE UE_FUNCTION_FASTCALL_CALL = 9;
const BYTE UE_PARAMETER_BYTE = 0;
const BYTE UE_PARAMETER_WORD = 1;
const BYTE UE_PARAMETER_DWORD = 2;
const BYTE UE_PARAMETER_QWORD = 3;
const BYTE UE_PARAMETER_PTR_BYTE = 4;
const BYTE UE_PARAMETER_PTR_WORD = 5;
const BYTE UE_PARAMETER_PTR_DWORD = 6;
const BYTE UE_PARAMETER_PTR_QWORD = 7;
const BYTE UE_PARAMETER_STRING = 8;
const BYTE UE_PARAMETER_UNICODE = 9;

const BYTE UE_CMP_NOCONDITION = 0;
const BYTE UE_CMP_EQUAL = 1;
const BYTE UE_CMP_NOTEQUAL = 2;
const BYTE UE_CMP_GREATER = 3;
const BYTE UE_CMP_GREATEROREQUAL = 4;
const BYTE UE_CMP_LOWER = 5;
const BYTE UE_CMP_LOWEROREQUAL = 6;
const BYTE UE_CMP_REG_EQUAL = 7;
const BYTE UE_CMP_REG_NOTEQUAL = 8;
const BYTE UE_CMP_REG_GREATER = 9;
const BYTE UE_CMP_REG_GREATEROREQUAL = 10;
const BYTE UE_CMP_REG_LOWER = 11;
const BYTE UE_CMP_REG_LOWEROREQUAL = 12;
const BYTE UE_CMP_ALWAYSFALSE = 13;

const BYTE UE_EAX = 1;
const BYTE UE_EBX = 2;
const BYTE UE_ECX = 3;
const BYTE UE_EDX = 4;
const BYTE UE_EDI = 5;
const BYTE UE_ESI = 6;
const BYTE UE_EBP = 7;
const BYTE UE_ESP = 8;
const BYTE UE_EIP = 9;
const BYTE UE_EFLAGS = 10;
const BYTE UE_DR0 = 11;
const BYTE UE_DR1 = 12;
const BYTE UE_DR2 = 13;
const BYTE UE_DR3 = 14;
const BYTE UE_DR6 = 15;
const BYTE UE_DR7 = 16;
const BYTE UE_RAX = 17;
const BYTE UE_RBX = 18;
const BYTE UE_RCX = 19;
const BYTE UE_RDX = 20;
const BYTE UE_RDI = 21;
const BYTE UE_RSI = 22;
const BYTE UE_RBP = 23;
const BYTE UE_RSP = 24;
const BYTE UE_RIP = 25;
const BYTE UE_RFLAGS = 26;
const BYTE UE_R8 = 27;
const BYTE UE_R9 = 28;
const BYTE UE_R10 = 29;
const BYTE UE_R11 = 30;
const BYTE UE_R12 = 31;
const BYTE UE_R13 = 32;
const BYTE UE_R14 = 33;
const BYTE UE_R15 = 34;
const BYTE UE_CIP = 35;
const BYTE UE_CSP = 36;
#ifdef _WIN64
const BYTE UE_CFLAGS = UE_RFLAGS;
#else
const BYTE UE_CFLAGS = UE_EFLAGS;
#endif
const BYTE UE_SEG_GS = 37;
const BYTE UE_SEG_FS = 38;
const BYTE UE_SEG_ES = 39;
const BYTE UE_SEG_DS = 40;
const BYTE UE_SEG_CS = 41;
const BYTE UE_SEG_SS = 42;

typedef struct
{
    DWORD PE32Offset;
    DWORD ImageBase;
    DWORD OriginalEntryPoint;
    DWORD BaseOfCode;
    DWORD BaseOfData;
    DWORD NtSizeOfImage;
    DWORD NtSizeOfHeaders;
    WORD SizeOfOptionalHeaders;
    DWORD FileAlignment;
    DWORD SectionAligment;
    DWORD ImportTableAddress;
    DWORD ImportTableSize;
    DWORD ResourceTableAddress;
    DWORD ResourceTableSize;
    DWORD ExportTableAddress;
    DWORD ExportTableSize;
    DWORD TLSTableAddress;
    DWORD TLSTableSize;
    DWORD RelocationTableAddress;
    DWORD RelocationTableSize;
    DWORD TimeDateStamp;
    WORD SectionNumber;
    DWORD CheckSum;
    WORD SubSystem;
    WORD Characteristics;
    DWORD NumberOfRvaAndSizes;
} PE32Struct, *PPE32Struct;

typedef struct
{
    DWORD PE64Offset;
    DWORD64 ImageBase;
    DWORD OriginalEntryPoint;
    DWORD BaseOfCode;
    DWORD BaseOfData;
    DWORD NtSizeOfImage;
    DWORD NtSizeOfHeaders;
    WORD SizeOfOptionalHeaders;
    DWORD FileAlignment;
    DWORD SectionAligment;
    DWORD ImportTableAddress;
    DWORD ImportTableSize;
    DWORD ResourceTableAddress;
    DWORD ResourceTableSize;
    DWORD ExportTableAddress;
    DWORD ExportTableSize;
    DWORD TLSTableAddress;
    DWORD TLSTableSize;
    DWORD RelocationTableAddress;
    DWORD RelocationTableSize;
    DWORD TimeDateStamp;
    WORD SectionNumber;
    DWORD CheckSum;
    WORD SubSystem;
    WORD Characteristics;
    DWORD NumberOfRvaAndSizes;
} PE64Struct, *PPE64Struct;

#if defined(_WIN64)
typedef PE64Struct PEStruct;
#else
typedef PE32Struct PEStruct;
#endif

typedef struct
{
    bool NewDll;
    int NumberOfImports;
    ULONG_PTR ImageBase;
    ULONG_PTR BaseImportThunk;
    ULONG_PTR ImportThunk;
    char* APIName;
    char* DLLName;
} ImportEnumData, *PImportEnumData;

typedef struct
{
    HANDLE hThread;
    DWORD dwThreadId;
    void* ThreadStartAddress;
    void* ThreadLocalBase;
} THREAD_ITEM_DATA, *PTHREAD_ITEM_DATA;

typedef struct
{
    HANDLE hFile;
    void* BaseOfDll;
    HANDLE hFileMapping;
    void* hFileMappingView;
    char szLibraryPath[MAX_PATH];
    char szLibraryName[MAX_PATH];
} LIBRARY_ITEM_DATA, *PLIBRARY_ITEM_DATA;

typedef struct
{
    HANDLE hFile;
    void* BaseOfDll;
    HANDLE hFileMapping;
    void* hFileMappingView;
    wchar_t szLibraryPath[MAX_PATH];
    wchar_t szLibraryName[MAX_PATH];
} LIBRARY_ITEM_DATAW, *PLIBRARY_ITEM_DATAW;

typedef struct
{
    HANDLE hProcess;
    DWORD dwProcessId;
    HANDLE hThread;
    DWORD dwThreadId;
    HANDLE hFile;
    void* BaseOfImage;
    void* ThreadStartAddress;
    void* ThreadLocalBase;
} PROCESS_ITEM_DATA, *PPROCESS_ITEM_DATA;

typedef struct
{
    ULONG ProcessId;
    HANDLE hHandle;
} HandlerArray, *PHandlerArray;

typedef struct
{
    char PluginName[64];
    DWORD PluginMajorVersion;
    DWORD PluginMinorVersion;
    HMODULE PluginBaseAddress;
    void* TitanDebuggingCallBack;
    void* TitanRegisterPlugin;
    void* TitanReleasePlugin;
    void* TitanResetPlugin;
    bool PluginDisabled;
} PluginInformation, *PPluginInformation;

const size_t TEE_MAXIMUM_HOOK_SIZE = 14;
const size_t TEE_MAXIMUM_HOOK_RELOCS = 7;
#if defined(_WIN64)
const size_t TEE_MAXIMUM_HOOK_INSERT_SIZE = 14;
#else
const size_t TEE_MAXIMUM_HOOK_INSERT_SIZE = 5;
#endif

typedef struct HOOK_ENTRY
{
    bool IATHook;
    BYTE HookType;
    DWORD HookSize;
    void* HookAddress;
    void* RedirectionAddress;
    BYTE HookBytes[TEE_MAXIMUM_HOOK_SIZE];
    BYTE OriginalBytes[TEE_MAXIMUM_HOOK_SIZE];
    void* IATHookModuleBase;
    DWORD IATHookNameHash;
    bool HookIsEnabled;
    bool HookIsRemote;
    void* PatchedEntry;
    DWORD RelocationInfo[TEE_MAXIMUM_HOOK_RELOCS];
    int RelocationCount;
} HOOK_ENTRY, *PHOOK_ENTRY;

const BYTE UE_DEPTH_SURFACE = 0;
const BYTE UE_DEPTH_DEEP = 1;

const BYTE UE_UNPACKER_CONDITION_SEARCH_FROM_EP = 1;

const BYTE UE_UNPACKER_CONDITION_LOADLIBRARY = 1;
const BYTE UE_UNPACKER_CONDITION_GETPROCADDRESS = 2;
const BYTE UE_UNPACKER_CONDITION_ENTRYPOINTBREAK = 3;
const BYTE UE_UNPACKER_CONDITION_RELOCSNAPSHOT1 = 4;
const BYTE UE_UNPACKER_CONDITION_RELOCSNAPSHOT2 = 5;

const BYTE UE_FIELD_OK = 0;
const BYTE UE_FIELD_BROKEN_NON_FIXABLE = 1;
const BYTE UE_FIELD_BROKEN_NON_CRITICAL = 2;
const BYTE UE_FIELD_BROKEN_FIXABLE_FOR_STATIC_USE = 3;
const BYTE UE_FIELD_BROKEN_BUT_CAN_BE_EMULATED = 4;
const BYTE UE_FILED_FIXABLE_NON_CRITICAL = 5;
const BYTE UE_FILED_FIXABLE_CRITICAL = 6;
const BYTE UE_FIELD_NOT_PRESET = 7;
const BYTE UE_FIELD_NOT_PRESET_WARNING = 8;

const BYTE UE_RESULT_FILE_OK = 10;
const BYTE UE_RESULT_FILE_INVALID_BUT_FIXABLE = 11;
const BYTE UE_RESULT_FILE_INVALID_AND_NON_FIXABLE = 12;
const BYTE UE_RESULT_FILE_INVALID_FORMAT = 13;

typedef struct
{
    BYTE OveralEvaluation;
    bool EvaluationTerminatedByException;
    bool FileIs64Bit;
    bool FileIsDLL;
    bool FileIsConsole;
    bool MissingDependencies;
    bool MissingDeclaredAPIs;
    BYTE SignatureMZ;
    BYTE SignaturePE;
    BYTE EntryPoint;
    BYTE ImageBase;
    BYTE SizeOfImage;
    BYTE FileAlignment;
    BYTE SectionAlignment;
    BYTE ExportTable;
    BYTE RelocationTable;
    BYTE ImportTable;
    BYTE ImportTableSection;
    BYTE ImportTableData;
    BYTE IATTable;
    BYTE TLSTable;
    BYTE LoadConfigTable;
    BYTE BoundImportTable;
    BYTE COMHeaderTable;
    BYTE ResourceTable;
    BYTE ResourceData;
    BYTE SectionTable;
} FILE_STATUS_INFO, *PFILE_STATUS_INFO;

typedef struct
{
    BYTE OveralEvaluation;
    bool FixingTerminatedByException;
    bool FileFixPerformed;
    bool StrippedRelocation;
    bool DontFixRelocations;
    DWORD OriginalRelocationTableAddress;
    DWORD OriginalRelocationTableSize;
    bool StrippedExports;
    bool DontFixExports;
    DWORD OriginalExportTableAddress;
    DWORD OriginalExportTableSize;
    bool StrippedResources;
    bool DontFixResources;
    DWORD OriginalResourceTableAddress;
    DWORD OriginalResourceTableSize;
    bool StrippedTLS;
    bool DontFixTLS;
    DWORD OriginalTLSTableAddress;
    DWORD OriginalTLSTableSize;
    bool StrippedLoadConfig;
    bool DontFixLoadConfig;
    DWORD OriginalLoadConfigTableAddress;
    DWORD OriginalLoadConfigTableSize;
    bool StrippedBoundImports;
    bool DontFixBoundImports;
    DWORD OriginalBoundImportTableAddress;
    DWORD OriginalBoundImportTableSize;
    bool StrippedIAT;
    bool DontFixIAT;
    DWORD OriginalImportAddressTableAddress;
    DWORD OriginalImportAddressTableSize;
    bool StrippedCOM;
    bool DontFixCOM;
    DWORD OriginalCOMTableAddress;
    DWORD OriginalCOMTableSize;
} FILE_FIX_INFO, *PFILE_FIX_INFO;

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

// Global.Function.Declaration:
// TitanEngine.Dumper.functions:
__declspec(dllimport) bool TITCALL DumpProcess(HANDLE hProcess, LPVOID ImageBase, char* szDumpFileName, ULONG_PTR EntryPoint);
__declspec(dllimport) bool TITCALL DumpProcessW(HANDLE hProcess, LPVOID ImageBase, wchar_t* szDumpFileName, ULONG_PTR EntryPoint);
__declspec(dllimport) bool TITCALL DumpProcessEx(DWORD ProcessId, LPVOID ImageBase, char* szDumpFileName, ULONG_PTR EntryPoint);
__declspec(dllimport) bool TITCALL DumpProcessExW(DWORD ProcessId, LPVOID ImageBase, wchar_t* szDumpFileName, ULONG_PTR EntryPoint);
__declspec(dllimport) bool TITCALL DumpMemory(HANDLE hProcess, LPVOID MemoryStart, ULONG_PTR MemorySize, char* szDumpFileName);
__declspec(dllimport) bool TITCALL DumpMemoryW(HANDLE hProcess, LPVOID MemoryStart, ULONG_PTR MemorySize, wchar_t* szDumpFileName);
__declspec(dllimport) bool TITCALL DumpMemoryEx(DWORD ProcessId, LPVOID MemoryStart, ULONG_PTR MemorySize, char* szDumpFileName);
__declspec(dllimport) bool TITCALL DumpMemoryExW(DWORD ProcessId, LPVOID MemoryStart, ULONG_PTR MemorySize, wchar_t* szDumpFileName);
__declspec(dllimport) bool TITCALL DumpRegions(HANDLE hProcess, char* szDumpFolder, bool DumpAboveImageBaseOnly);
__declspec(dllimport) bool TITCALL DumpRegionsW(HANDLE hProcess, wchar_t* szDumpFolder, bool DumpAboveImageBaseOnly);
__declspec(dllimport) bool TITCALL DumpRegionsEx(DWORD ProcessId, char* szDumpFolder, bool DumpAboveImageBaseOnly);
__declspec(dllimport) bool TITCALL DumpRegionsExW(DWORD ProcessId, wchar_t* szDumpFolder, bool DumpAboveImageBaseOnly);
__declspec(dllimport) bool TITCALL DumpModule(HANDLE hProcess, LPVOID ModuleBase, char* szDumpFileName);
__declspec(dllimport) bool TITCALL DumpModuleW(HANDLE hProcess, LPVOID ModuleBase, wchar_t* szDumpFileName);
__declspec(dllimport) bool TITCALL DumpModuleEx(DWORD ProcessId, LPVOID ModuleBase, char* szDumpFileName);
__declspec(dllimport) bool TITCALL DumpModuleExW(DWORD ProcessId, LPVOID ModuleBase, wchar_t* szDumpFileName);
__declspec(dllimport) bool TITCALL PastePEHeader(HANDLE hProcess, LPVOID ImageBase, char* szDebuggedFileName);
__declspec(dllimport) bool TITCALL PastePEHeaderW(HANDLE hProcess, LPVOID ImageBase, wchar_t* szDebuggedFileName);
__declspec(dllimport) bool TITCALL ExtractSection(char* szFileName, char* szDumpFileName, DWORD SectionNumber);
__declspec(dllimport) bool TITCALL ExtractSectionW(wchar_t* szFileName, wchar_t* szDumpFileName, DWORD SectionNumber);
__declspec(dllimport) bool TITCALL ResortFileSections(char* szFileName);
__declspec(dllimport) bool TITCALL ResortFileSectionsW(wchar_t* szFileName);
__declspec(dllimport) bool TITCALL FindOverlay(char* szFileName, LPDWORD OverlayStart, LPDWORD OverlaySize);
__declspec(dllimport) bool TITCALL FindOverlayW(wchar_t* szFileName, LPDWORD OverlayStart, LPDWORD OverlaySize);
__declspec(dllimport) bool TITCALL ExtractOverlay(char* szFileName, char* szExtractedFileName);
__declspec(dllimport) bool TITCALL ExtractOverlayW(wchar_t* szFileName, wchar_t* szExtractedFileName);
__declspec(dllimport) bool TITCALL AddOverlay(char* szFileName, char* szOverlayFileName);
__declspec(dllimport) bool TITCALL AddOverlayW(wchar_t* szFileName, wchar_t* szOverlayFileName);
__declspec(dllimport) bool TITCALL CopyOverlay(char* szInFileName, char* szOutFileName);
__declspec(dllimport) bool TITCALL CopyOverlayW(wchar_t* szInFileName, wchar_t* szOutFileName);
__declspec(dllimport) bool TITCALL RemoveOverlay(char* szFileName);
__declspec(dllimport) bool TITCALL RemoveOverlayW(wchar_t* szFileName);
__declspec(dllimport) bool TITCALL MakeAllSectionsRWE(char* szFileName);
__declspec(dllimport) bool TITCALL MakeAllSectionsRWEW(wchar_t* szFileName);
__declspec(dllimport) long TITCALL AddNewSectionEx(char* szFileName, char* szSectionName, DWORD SectionSize, DWORD SectionAttributes, LPVOID SectionContent, DWORD ContentSize);
__declspec(dllimport) long TITCALL AddNewSectionExW(wchar_t* szFileName, char* szSectionName, DWORD SectionSize, DWORD SectionAttributes, LPVOID SectionContent, DWORD ContentSize);
__declspec(dllimport) long TITCALL AddNewSection(char* szFileName, char* szSectionName, DWORD SectionSize);
__declspec(dllimport) long TITCALL AddNewSectionW(wchar_t* szFileName, char* szSectionName, DWORD SectionSize);
__declspec(dllimport) bool TITCALL ResizeLastSection(char* szFileName, DWORD NumberOfExpandBytes, bool AlignResizeData);
__declspec(dllimport) bool TITCALL ResizeLastSectionW(wchar_t* szFileName, DWORD NumberOfExpandBytes, bool AlignResizeData);
__declspec(dllimport) void TITCALL SetSharedOverlay(char* szFileName);
__declspec(dllimport) void TITCALL SetSharedOverlayW(wchar_t* szFileName);
__declspec(dllimport) char* TITCALL GetSharedOverlay();
__declspec(dllimport) wchar_t* TITCALL GetSharedOverlayW();
__declspec(dllimport) bool TITCALL DeleteLastSection(char* szFileName);
__declspec(dllimport) bool TITCALL DeleteLastSectionW(wchar_t* szFileName);
__declspec(dllimport) bool TITCALL DeleteLastSectionEx(char* szFileName, DWORD NumberOfSections);
__declspec(dllimport) bool TITCALL DeleteLastSectionExW(wchar_t* szFileName, DWORD NumberOfSections);
__declspec(dllimport) long long TITCALL GetPE32DataFromMappedFile(ULONG_PTR FileMapVA, DWORD WhichSection, DWORD WhichData);
__declspec(dllimport) long long TITCALL GetPE32Data(char* szFileName, DWORD WhichSection, DWORD WhichData);
__declspec(dllimport) long long TITCALL GetPE32DataW(wchar_t* szFileName, DWORD WhichSection, DWORD WhichData);
__declspec(dllimport) bool TITCALL GetPE32DataFromMappedFileEx(ULONG_PTR FileMapVA, LPVOID DataStorage);
__declspec(dllimport) bool TITCALL GetPE32DataEx(char* szFileName, LPVOID DataStorage);
__declspec(dllimport) bool TITCALL GetPE32DataExW(wchar_t* szFileName, LPVOID DataStorage);
__declspec(dllimport) bool TITCALL SetPE32DataForMappedFile(ULONG_PTR FileMapVA, DWORD WhichSection, DWORD WhichData, ULONG_PTR NewDataValue);
__declspec(dllimport) bool TITCALL SetPE32Data(char* szFileName, DWORD WhichSection, DWORD WhichData, ULONG_PTR NewDataValue);
__declspec(dllimport) bool TITCALL SetPE32DataW(wchar_t* szFileName, DWORD WhichSection, DWORD WhichData, ULONG_PTR NewDataValue);
__declspec(dllimport) bool TITCALL SetPE32DataForMappedFileEx(ULONG_PTR FileMapVA, LPVOID DataStorage);
__declspec(dllimport) bool TITCALL SetPE32DataEx(char* szFileName, LPVOID DataStorage);
__declspec(dllimport) bool TITCALL SetPE32DataExW(wchar_t* szFileName, LPVOID DataStorage);
__declspec(dllimport) long TITCALL GetPE32SectionNumberFromVA(ULONG_PTR FileMapVA, ULONG_PTR AddressToConvert);
__declspec(dllimport) long long TITCALL ConvertVAtoFileOffset(ULONG_PTR FileMapVA, ULONG_PTR AddressToConvert, bool ReturnType);
__declspec(dllimport) long long TITCALL ConvertVAtoFileOffsetEx(ULONG_PTR FileMapVA, DWORD FileSize, ULONG_PTR ImageBase, ULONG_PTR AddressToConvert, bool AddressIsRVA, bool ReturnType);
__declspec(dllimport) long long TITCALL ConvertFileOffsetToVA(ULONG_PTR FileMapVA, ULONG_PTR AddressToConvert, bool ReturnType);
__declspec(dllimport) long long TITCALL ConvertFileOffsetToVAEx(ULONG_PTR FileMapVA, DWORD FileSize, ULONG_PTR ImageBase, ULONG_PTR AddressToConvert, bool ReturnType);
// TitanEngine.Realigner.functions:
__declspec(dllimport) bool TITCALL FixHeaderCheckSum(char* szFileName);
__declspec(dllimport) bool TITCALL FixHeaderCheckSumW(wchar_t* szFileName);
__declspec(dllimport) long TITCALL RealignPE(ULONG_PTR FileMapVA, DWORD FileSize, DWORD RealingMode);
__declspec(dllimport) long TITCALL RealignPEEx(char* szFileName, DWORD RealingFileSize, DWORD ForcedFileAlignment);
__declspec(dllimport) long TITCALL RealignPEExW(wchar_t* szFileName, DWORD RealingFileSize, DWORD ForcedFileAlignment);
__declspec(dllimport) bool TITCALL WipeSection(char* szFileName, int WipeSectionNumber, bool RemovePhysically);
__declspec(dllimport) bool TITCALL WipeSectionW(wchar_t* szFileName, int WipeSectionNumber, bool RemovePhysically);
__declspec(dllimport) bool TITCALL IsPE32FileValidEx(char* szFileName, DWORD CheckDepth, LPVOID FileStatusInfo);
__declspec(dllimport) bool TITCALL IsPE32FileValidExW(wchar_t* szFileName, DWORD CheckDepth, LPVOID FileStatusInfo);
__declspec(dllimport) bool TITCALL FixBrokenPE32FileEx(char* szFileName, LPVOID FileStatusInfo, LPVOID FileFixInfo);
__declspec(dllimport) bool TITCALL FixBrokenPE32FileExW(wchar_t* szFileName, LPVOID FileStatusInfo, LPVOID FileFixInfo);
__declspec(dllimport) bool TITCALL IsFileDLL(char* szFileName, ULONG_PTR FileMapVA);
__declspec(dllimport) bool TITCALL IsFileDLLW(wchar_t* szFileName, ULONG_PTR FileMapVA);
// TitanEngine.Hider.functions:
__declspec(dllimport) void* TITCALL GetPEBLocation(HANDLE hProcess);
__declspec(dllimport) bool TITCALL HideDebugger(HANDLE hProcess, DWORD PatchAPILevel);
__declspec(dllimport) bool TITCALL UnHideDebugger(HANDLE hProcess, DWORD PatchAPILevel);
// TitanEngine.Relocater.functions:
__declspec(dllimport) void TITCALL RelocaterCleanup();
__declspec(dllimport) void TITCALL RelocaterInit(DWORD MemorySize, ULONG_PTR OldImageBase, ULONG_PTR NewImageBase);
__declspec(dllimport) void TITCALL RelocaterAddNewRelocation(HANDLE hProcess, ULONG_PTR RelocateAddress, DWORD RelocateState);
__declspec(dllimport) long TITCALL RelocaterEstimatedSize();
__declspec(dllimport) bool TITCALL RelocaterExportRelocation(ULONG_PTR StorePlace, DWORD StorePlaceRVA, ULONG_PTR FileMapVA);
__declspec(dllimport) bool TITCALL RelocaterExportRelocationEx(char* szFileName, char* szSectionName);
__declspec(dllimport) bool TITCALL RelocaterExportRelocationExW(wchar_t* szFileName, char* szSectionName);
__declspec(dllimport) bool TITCALL RelocaterGrabRelocationTable(HANDLE hProcess, ULONG_PTR MemoryStart, DWORD MemorySize);
__declspec(dllimport) bool TITCALL RelocaterGrabRelocationTableEx(HANDLE hProcess, ULONG_PTR MemoryStart, ULONG_PTR MemorySize, DWORD NtSizeOfImage);
__declspec(dllimport) bool TITCALL RelocaterMakeSnapshot(HANDLE hProcess, char* szSaveFileName, LPVOID MemoryStart, ULONG_PTR MemorySize);
__declspec(dllimport) bool TITCALL RelocaterMakeSnapshotW(HANDLE hProcess, wchar_t* szSaveFileName, LPVOID MemoryStart, ULONG_PTR MemorySize);
__declspec(dllimport) bool TITCALL RelocaterCompareTwoSnapshots(HANDLE hProcess, ULONG_PTR LoadedImageBase, ULONG_PTR NtSizeOfImage, char* szDumpFile1, char* szDumpFile2, ULONG_PTR MemStart);
__declspec(dllimport) bool TITCALL RelocaterCompareTwoSnapshotsW(HANDLE hProcess, ULONG_PTR LoadedImageBase, ULONG_PTR NtSizeOfImage, wchar_t* szDumpFile1, wchar_t* szDumpFile2, ULONG_PTR MemStart);
__declspec(dllimport) bool TITCALL RelocaterChangeFileBase(char* szFileName, ULONG_PTR NewImageBase);
__declspec(dllimport) bool TITCALL RelocaterChangeFileBaseW(wchar_t* szFileName, ULONG_PTR NewImageBase);
__declspec(dllimport) bool TITCALL RelocaterRelocateMemoryBlock(ULONG_PTR FileMapVA, ULONG_PTR MemoryLocation, void* RelocateMemory, DWORD RelocateMemorySize, ULONG_PTR CurrentLoadedBase, ULONG_PTR RelocateBase);
__declspec(dllimport) bool TITCALL RelocaterWipeRelocationTable(char* szFileName);
__declspec(dllimport) bool TITCALL RelocaterWipeRelocationTableW(wchar_t* szFileName);
// TitanEngine.Resourcer.functions:
__declspec(dllimport) long long TITCALL ResourcerLoadFileForResourceUse(char* szFileName);
__declspec(dllimport) long long TITCALL ResourcerLoadFileForResourceUseW(wchar_t* szFileName);
__declspec(dllimport) bool TITCALL ResourcerFreeLoadedFile(LPVOID LoadedFileBase);
__declspec(dllimport) bool TITCALL ResourcerExtractResourceFromFileEx(ULONG_PTR FileMapVA, char* szResourceType, char* szResourceName, char* szExtractedFileName);
__declspec(dllimport) bool TITCALL ResourcerExtractResourceFromFile(char* szFileName, char* szResourceType, char* szResourceName, char* szExtractedFileName);
__declspec(dllimport) bool TITCALL ResourcerExtractResourceFromFileW(wchar_t* szFileName, char* szResourceType, char* szResourceName, char* szExtractedFileName);
__declspec(dllimport) bool TITCALL ResourcerFindResource(char* szFileName, char* szResourceType, DWORD ResourceType, char* szResourceName, DWORD ResourceName, DWORD ResourceLanguage, PULONG_PTR pResourceData, LPDWORD pResourceSize);
__declspec(dllimport) bool TITCALL ResourcerFindResourceW(wchar_t* szFileName, wchar_t* szResourceType, DWORD ResourceType, wchar_t* szResourceName, DWORD ResourceName, DWORD ResourceLanguage, PULONG_PTR pResourceData, LPDWORD pResourceSize);
__declspec(dllimport) bool TITCALL ResourcerFindResourceEx(ULONG_PTR FileMapVA, DWORD FileSize, wchar_t* szResourceType, DWORD ResourceType, wchar_t* szResourceName, DWORD ResourceName, DWORD ResourceLanguage, PULONG_PTR pResourceData, LPDWORD pResourceSize);
__declspec(dllimport) void TITCALL ResourcerEnumerateResource(char* szFileName, void* CallBack);
__declspec(dllimport) void TITCALL ResourcerEnumerateResourceW(wchar_t* szFileName, void* CallBack);
__declspec(dllimport) void TITCALL ResourcerEnumerateResourceEx(ULONG_PTR FileMapVA, DWORD FileSize, void* CallBack);
// TitanEngine.Threader.functions:
__declspec(dllimport) bool TITCALL ThreaderImportRunningThreadData(DWORD ProcessId);
__declspec(dllimport) void* TITCALL ThreaderGetThreadInfo(HANDLE hThread, DWORD ThreadId);
__declspec(dllimport) void TITCALL ThreaderEnumThreadInfo(void* EnumCallBack);
__declspec(dllimport) bool TITCALL ThreaderPauseThread(HANDLE hThread);
__declspec(dllimport) bool TITCALL ThreaderResumeThread(HANDLE hThread);
__declspec(dllimport) bool TITCALL ThreaderTerminateThread(HANDLE hThread, DWORD ThreadExitCode);
__declspec(dllimport) bool TITCALL ThreaderPauseAllThreads(bool LeaveMainRunning);
__declspec(dllimport) bool TITCALL ThreaderResumeAllThreads(bool LeaveMainPaused);
__declspec(dllimport) bool TITCALL ThreaderPauseProcess();
__declspec(dllimport) bool TITCALL ThreaderResumeProcess();
__declspec(dllimport) long long TITCALL ThreaderCreateRemoteThread(ULONG_PTR ThreadStartAddress, bool AutoCloseTheHandle, LPVOID ThreadPassParameter, LPDWORD ThreadId);
__declspec(dllimport) bool TITCALL ThreaderInjectAndExecuteCode(LPVOID InjectCode, DWORD StartDelta, DWORD InjectSize);
__declspec(dllimport) long long TITCALL ThreaderCreateRemoteThreadEx(HANDLE hProcess, ULONG_PTR ThreadStartAddress, bool AutoCloseTheHandle, LPVOID ThreadPassParameter, LPDWORD ThreadId);
__declspec(dllimport) bool TITCALL ThreaderInjectAndExecuteCodeEx(HANDLE hProcess, LPVOID InjectCode, DWORD StartDelta, DWORD InjectSize);
__declspec(dllimport) void TITCALL ThreaderSetCallBackForNextExitThreadEvent(LPVOID exitThreadCallBack);
__declspec(dllimport) bool TITCALL ThreaderIsThreadStillRunning(HANDLE hThread);
__declspec(dllimport) bool TITCALL ThreaderIsThreadActive(HANDLE hThread);
__declspec(dllimport) bool TITCALL ThreaderIsAnyThreadActive();
__declspec(dllimport) bool TITCALL ThreaderExecuteOnlyInjectedThreads();
__declspec(dllimport) long long TITCALL ThreaderGetOpenHandleForThread(DWORD ThreadId);
__declspec(dllimport) void* TITCALL ThreaderGetThreadData();
__declspec(dllimport) bool TITCALL ThreaderIsExceptionInMainThread();
// TitanEngine.Debugger.functions:
__declspec(dllimport) void* TITCALL StaticDisassembleEx(ULONG_PTR DisassmStart, LPVOID DisassmAddress);
__declspec(dllimport) void* TITCALL StaticDisassemble(LPVOID DisassmAddress);
__declspec(dllimport) void* TITCALL DisassembleEx(HANDLE hProcess, LPVOID DisassmAddress, bool ReturnInstructionType);
__declspec(dllimport) void* TITCALL Disassemble(LPVOID DisassmAddress);
__declspec(dllimport) long TITCALL StaticLengthDisassemble(LPVOID DisassmAddress);
__declspec(dllimport) long TITCALL LengthDisassembleEx(HANDLE hProcess, LPVOID DisassmAddress);
__declspec(dllimport) long TITCALL LengthDisassemble(LPVOID DisassmAddress);
__declspec(dllimport) void* TITCALL InitDebug(char* szFileName, char* szCommandLine, char* szCurrentFolder);
__declspec(dllimport) void* TITCALL InitDebugW(wchar_t* szFileName, wchar_t* szCommandLine, wchar_t* szCurrentFolder);
__declspec(dllimport) void* TITCALL InitDebugEx(char* szFileName, char* szCommandLine, char* szCurrentFolder, LPVOID EntryCallBack);
__declspec(dllimport) void* TITCALL InitDebugExW(wchar_t* szFileName, wchar_t* szCommandLine, wchar_t* szCurrentFolder, LPVOID EntryCallBack);
__declspec(dllimport) void* TITCALL InitDLLDebug(char* szFileName, bool ReserveModuleBase, char* szCommandLine, char* szCurrentFolder, LPVOID EntryCallBack);
__declspec(dllimport) void* TITCALL InitDLLDebugW(wchar_t* szFileName, bool ReserveModuleBase, wchar_t* szCommandLine, wchar_t* szCurrentFolder, LPVOID EntryCallBack);
__declspec(dllimport) bool TITCALL StopDebug();
__declspec(dllimport) void TITCALL SetBPXOptions(long DefaultBreakPointType);
__declspec(dllimport) bool TITCALL IsBPXEnabled(ULONG_PTR bpxAddress);
__declspec(dllimport) bool TITCALL EnableBPX(ULONG_PTR bpxAddress);
__declspec(dllimport) bool TITCALL DisableBPX(ULONG_PTR bpxAddress);
__declspec(dllimport) bool TITCALL SetBPX(ULONG_PTR bpxAddress, DWORD bpxType, LPVOID bpxCallBack);
__declspec(dllimport) bool TITCALL SetBPXEx(ULONG_PTR bpxAddress, DWORD bpxType, DWORD NumberOfExecution, DWORD CmpRegister, DWORD CmpCondition, ULONG_PTR CmpValue, LPVOID bpxCallBack, LPVOID bpxCompareCallBack, LPVOID bpxRemoveCallBack);
__declspec(dllimport) bool TITCALL DeleteBPX(ULONG_PTR bpxAddress);
__declspec(dllimport) bool TITCALL SafeDeleteBPX(ULONG_PTR bpxAddress);
__declspec(dllimport) bool TITCALL SetAPIBreakPoint(char* szDLLName, char* szAPIName, DWORD bpxType, DWORD bpxPlace, LPVOID bpxCallBack);
__declspec(dllimport) bool TITCALL DeleteAPIBreakPoint(char* szDLLName, char* szAPIName, DWORD bpxPlace);
__declspec(dllimport) bool TITCALL SafeDeleteAPIBreakPoint(char* szDLLName, char* szAPIName, DWORD bpxPlace);
__declspec(dllimport) bool TITCALL SetMemoryBPX(ULONG_PTR MemoryStart, DWORD SizeOfMemory, LPVOID bpxCallBack);
__declspec(dllimport) bool TITCALL SetMemoryBPXEx(ULONG_PTR MemoryStart, DWORD SizeOfMemory, DWORD BreakPointType, bool RestoreOnHit, LPVOID bpxCallBack);
__declspec(dllimport) bool TITCALL RemoveMemoryBPX(ULONG_PTR MemoryStart, DWORD SizeOfMemory);
__declspec(dllimport) bool TITCALL GetContextFPUDataEx(HANDLE hActiveThread, void* FPUSaveArea);
__declspec(dllimport) long long TITCALL GetContextDataEx(HANDLE hActiveThread, DWORD IndexOfRegister);
__declspec(dllimport) long long TITCALL GetContextData(DWORD IndexOfRegister);
__declspec(dllimport) bool TITCALL SetContextFPUDataEx(HANDLE hActiveThread, void* FPUSaveArea);
__declspec(dllimport) bool TITCALL SetContextDataEx(HANDLE hActiveThread, DWORD IndexOfRegister, ULONG_PTR NewRegisterValue);
__declspec(dllimport) bool TITCALL SetContextData(DWORD IndexOfRegister, ULONG_PTR NewRegisterValue);
__declspec(dllimport) void TITCALL ClearExceptionNumber();
__declspec(dllimport) long TITCALL CurrentExceptionNumber();
__declspec(dllimport) bool TITCALL MatchPatternEx(HANDLE hProcess, void* MemoryToCheck, int SizeOfMemoryToCheck, void* PatternToMatch, int SizeOfPatternToMatch, PBYTE WildCard);
__declspec(dllimport) bool TITCALL MatchPattern(void* MemoryToCheck, int SizeOfMemoryToCheck, void* PatternToMatch, int SizeOfPatternToMatch, PBYTE WildCard);
__declspec(dllimport) long long TITCALL FindEx(HANDLE hProcess, LPVOID MemoryStart, DWORD MemorySize, LPVOID SearchPattern, DWORD PatternSize, LPBYTE WildCard);
__declspec(dllimport) long long TITCALL Find(LPVOID MemoryStart, DWORD MemorySize, LPVOID SearchPattern, DWORD PatternSize, LPBYTE WildCard);
__declspec(dllimport) bool TITCALL FillEx(HANDLE hProcess, LPVOID MemoryStart, DWORD MemorySize, PBYTE FillByte);
__declspec(dllimport) bool TITCALL Fill(LPVOID MemoryStart, DWORD MemorySize, PBYTE FillByte);
__declspec(dllimport) bool TITCALL PatchEx(HANDLE hProcess, LPVOID MemoryStart, DWORD MemorySize, LPVOID ReplacePattern, DWORD ReplaceSize, bool AppendNOP, bool PrependNOP);
__declspec(dllimport) bool TITCALL Patch(LPVOID MemoryStart, DWORD MemorySize, LPVOID ReplacePattern, DWORD ReplaceSize, bool AppendNOP, bool PrependNOP);
__declspec(dllimport) bool TITCALL ReplaceEx(HANDLE hProcess, LPVOID MemoryStart, DWORD MemorySize, LPVOID SearchPattern, DWORD PatternSize, DWORD NumberOfRepetitions, LPVOID ReplacePattern, DWORD ReplaceSize, PBYTE WildCard);
__declspec(dllimport) bool TITCALL Replace(LPVOID MemoryStart, DWORD MemorySize, LPVOID SearchPattern, DWORD PatternSize, DWORD NumberOfRepetitions, LPVOID ReplacePattern, DWORD ReplaceSize, PBYTE WildCard);
__declspec(dllimport) void* TITCALL GetDebugData();
__declspec(dllimport) void* TITCALL GetTerminationData();
__declspec(dllimport) long TITCALL GetExitCode();
__declspec(dllimport) long long TITCALL GetDebuggedDLLBaseAddress();
__declspec(dllimport) long long TITCALL GetDebuggedFileBaseAddress();
__declspec(dllimport) bool TITCALL GetRemoteString(HANDLE hProcess, LPVOID StringAddress, LPVOID StringStorage, int MaximumStringSize);
__declspec(dllimport) long long TITCALL GetFunctionParameter(HANDLE hProcess, DWORD FunctionType, DWORD ParameterNumber, DWORD ParameterType);
__declspec(dllimport) long long TITCALL GetJumpDestinationEx(HANDLE hProcess, ULONG_PTR InstructionAddress, bool JustJumps);
__declspec(dllimport) long long TITCALL GetJumpDestination(HANDLE hProcess, ULONG_PTR InstructionAddress);
__declspec(dllimport) bool TITCALL IsJumpGoingToExecuteEx(HANDLE hProcess, HANDLE hThread, ULONG_PTR InstructionAddress, ULONG_PTR RegFlags);
__declspec(dllimport) bool TITCALL IsJumpGoingToExecute();
__declspec(dllimport) void TITCALL SetCustomHandler(DWORD ExceptionId, LPVOID CallBack);
__declspec(dllimport) void TITCALL ForceClose();
__declspec(dllimport) void TITCALL StepInto(LPVOID traceCallBack);
__declspec(dllimport) void TITCALL StepOver(LPVOID traceCallBack);
__declspec(dllimport) void TITCALL SingleStep(DWORD StepCount, LPVOID StepCallBack);
__declspec(dllimport) bool TITCALL GetUnusedHardwareBreakPointRegister(LPDWORD RegisterIndex);
__declspec(dllimport) bool TITCALL SetHardwareBreakPointEx(HANDLE hActiveThread, ULONG_PTR bpxAddress, DWORD IndexOfRegister, DWORD bpxType, DWORD bpxSize, LPVOID bpxCallBack, LPDWORD IndexOfSelectedRegister);
__declspec(dllimport) bool TITCALL SetHardwareBreakPoint(ULONG_PTR bpxAddress, DWORD IndexOfRegister, DWORD bpxType, DWORD bpxSize, LPVOID bpxCallBack);
__declspec(dllimport) bool TITCALL DeleteHardwareBreakPoint(DWORD IndexOfRegister);
__declspec(dllimport) bool TITCALL RemoveAllBreakPoints(DWORD RemoveOption);
__declspec(dllimport) void* TITCALL GetProcessInformation();
__declspec(dllimport) void* TITCALL GetStartupInformation();
__declspec(dllimport) void TITCALL DebugLoop();
__declspec(dllimport) void TITCALL SetDebugLoopTimeOut(DWORD TimeOut);
__declspec(dllimport) void TITCALL SetNextDbgContinueStatus(DWORD SetDbgCode);
__declspec(dllimport) bool TITCALL AttachDebugger(DWORD ProcessId, bool KillOnExit, LPVOID DebugInfo, LPVOID CallBack);
__declspec(dllimport) bool TITCALL DetachDebugger(DWORD ProcessId);
__declspec(dllimport) bool TITCALL DetachDebuggerEx(DWORD ProcessId);
__declspec(dllimport) void TITCALL DebugLoopEx(DWORD TimeOut);
__declspec(dllimport) void TITCALL AutoDebugEx(char* szFileName, bool ReserveModuleBase, char* szCommandLine, char* szCurrentFolder, DWORD TimeOut, LPVOID EntryCallBack);
__declspec(dllimport) void TITCALL AutoDebugExW(wchar_t* szFileName, bool ReserveModuleBase, wchar_t* szCommandLine, wchar_t* szCurrentFolder, DWORD TimeOut, LPVOID EntryCallBack);
__declspec(dllimport) bool TITCALL IsFileBeingDebugged();
__declspec(dllimport) void TITCALL SetErrorModel(bool DisplayErrorMessages);
// TitanEngine.FindOEP.functions:
__declspec(dllimport) void TITCALL FindOEPInit();
__declspec(dllimport) bool TITCALL FindOEPGenerically(char* szFileName, LPVOID TraceInitCallBack, LPVOID CallBack);
__declspec(dllimport) bool TITCALL FindOEPGenericallyW(wchar_t* szFileName, LPVOID TraceInitCallBack, LPVOID CallBack);
// TitanEngine.Importer.functions:
__declspec(dllimport) void TITCALL ImporterAddNewDll(char* szDLLName, ULONG_PTR FirstThunk);
__declspec(dllimport) void TITCALL ImporterAddNewAPI(char* szAPIName, ULONG_PTR ThunkValue);
__declspec(dllimport) void TITCALL ImporterAddNewOrdinalAPI(ULONG_PTR OrdinalNumber, ULONG_PTR ThunkValue);
__declspec(dllimport) long TITCALL ImporterGetAddedDllCount();
__declspec(dllimport) long TITCALL ImporterGetAddedAPICount();
__declspec(dllimport) bool TITCALL ImporterExportIAT(ULONG_PTR StorePlace, ULONG_PTR FileMapVA, HANDLE hFileMap);
__declspec(dllimport) long TITCALL ImporterEstimatedSize();
__declspec(dllimport) bool TITCALL ImporterExportIATEx(char* szDumpFileName, char* szExportFileName, char* szSectionName);
__declspec(dllimport) bool TITCALL ImporterExportIATExW(wchar_t* szDumpFileName, wchar_t* szExportFileName, wchar_t* szSectionName = L".RL!TEv2");
__declspec(dllimport) long long TITCALL ImporterFindAPIWriteLocation(char* szAPIName);
__declspec(dllimport) long long TITCALL ImporterFindOrdinalAPIWriteLocation(ULONG_PTR OrdinalNumber);
__declspec(dllimport) long long TITCALL ImporterFindAPIByWriteLocation(ULONG_PTR APIWriteLocation);
__declspec(dllimport) long long TITCALL ImporterFindDLLByWriteLocation(ULONG_PTR APIWriteLocation);
__declspec(dllimport) void* TITCALL ImporterGetDLLName(ULONG_PTR APIAddress);
__declspec(dllimport) void* TITCALL ImporterGetAPIName(ULONG_PTR APIAddress);
__declspec(dllimport) long long TITCALL ImporterGetAPIOrdinalNumber(ULONG_PTR APIAddress);
__declspec(dllimport) void* TITCALL ImporterGetAPINameEx(ULONG_PTR APIAddress, ULONG_PTR DLLBasesList);
__declspec(dllimport) long long TITCALL ImporterGetRemoteAPIAddress(HANDLE hProcess, ULONG_PTR APIAddress);
__declspec(dllimport) long long TITCALL ImporterGetRemoteAPIAddressEx(char* szDLLName, char* szAPIName);
__declspec(dllimport) long long TITCALL ImporterGetLocalAPIAddress(HANDLE hProcess, ULONG_PTR APIAddress);
__declspec(dllimport) void* TITCALL ImporterGetDLLNameFromDebugee(HANDLE hProcess, ULONG_PTR APIAddress);
__declspec(dllimport) void* TITCALL ImporterGetAPINameFromDebugee(HANDLE hProcess, ULONG_PTR APIAddress);
__declspec(dllimport) long long TITCALL ImporterGetAPIOrdinalNumberFromDebugee(HANDLE hProcess, ULONG_PTR APIAddress);
__declspec(dllimport) long TITCALL ImporterGetDLLIndexEx(ULONG_PTR APIAddress, ULONG_PTR DLLBasesList);
__declspec(dllimport) long TITCALL ImporterGetDLLIndex(HANDLE hProcess, ULONG_PTR APIAddress, ULONG_PTR DLLBasesList);
__declspec(dllimport) long long TITCALL ImporterGetRemoteDLLBase(HANDLE hProcess, HMODULE LocalModuleBase);
__declspec(dllimport) bool TITCALL ImporterIsForwardedAPI(HANDLE hProcess, ULONG_PTR APIAddress);
__declspec(dllimport) void* TITCALL ImporterGetForwardedAPIName(HANDLE hProcess, ULONG_PTR APIAddress);
__declspec(dllimport) void* TITCALL ImporterGetForwardedDLLName(HANDLE hProcess, ULONG_PTR APIAddress);
__declspec(dllimport) long TITCALL ImporterGetForwardedDLLIndex(HANDLE hProcess, ULONG_PTR APIAddress, ULONG_PTR DLLBasesList);
__declspec(dllimport) long long TITCALL ImporterGetForwardedAPIOrdinalNumber(HANDLE hProcess, ULONG_PTR APIAddress);
__declspec(dllimport) long long TITCALL ImporterGetNearestAPIAddress(HANDLE hProcess, ULONG_PTR APIAddress);
__declspec(dllimport) void* TITCALL ImporterGetNearestAPIName(HANDLE hProcess, ULONG_PTR APIAddress);
__declspec(dllimport) bool TITCALL ImporterCopyOriginalIAT(char* szOriginalFile, char* szDumpFile);
__declspec(dllimport) bool TITCALL ImporterCopyOriginalIATW(wchar_t* szOriginalFile, wchar_t* szDumpFile);
__declspec(dllimport) bool TITCALL ImporterLoadImportTable(char* szFileName);
__declspec(dllimport) bool TITCALL ImporterLoadImportTableW(wchar_t* szFileName);
__declspec(dllimport) bool TITCALL ImporterMoveOriginalIAT(char* szOriginalFile, char* szDumpFile, char* szSectionName);
__declspec(dllimport) bool TITCALL ImporterMoveOriginalIATW(wchar_t* szOriginalFile, wchar_t* szDumpFile, char* szSectionName);
__declspec(dllimport) void TITCALL ImporterAutoSearchIAT(DWORD ProcessId, char* szFileName, ULONG_PTR SearchStart, LPVOID pIATStart, LPVOID pIATSize);
__declspec(dllimport) void TITCALL ImporterAutoSearchIATW(DWORD ProcessIds, wchar_t* szFileName, ULONG_PTR SearchStart, LPVOID pIATStart, LPVOID pIATSize);
__declspec(dllimport) void TITCALL ImporterAutoSearchIATEx(DWORD ProcessId, ULONG_PTR ImageBase, ULONG_PTR SearchStart, LPVOID pIATStart, LPVOID pIATSize);
__declspec(dllimport) void TITCALL ImporterEnumAddedData(LPVOID EnumCallBack);
__declspec(dllimport) long TITCALL ImporterAutoFixIATEx(DWORD ProcessId, char* szDumpedFile, char* szSectionName, bool DumpRunningProcess, bool RealignFile, ULONG_PTR EntryPointAddress, ULONG_PTR ImageBase, ULONG_PTR SearchStart, bool TryAutoFix, bool FixEliminations, LPVOID UnknownPointerFixCallback);
__declspec(dllimport) long TITCALL ImporterAutoFixIATExW(DWORD ProcessId, wchar_t* szDumpedFile, char* szSectionName, bool DumpRunningProcess, bool RealignFile, ULONG_PTR EntryPointAddress, ULONG_PTR ImageBase, ULONG_PTR SearchStart,  bool TryAutoFix, bool FixEliminations, LPVOID UnknownPointerFixCallback);
__declspec(dllimport) long TITCALL ImporterAutoFixIAT(DWORD ProcessId, char* szDumpedFile, ULONG_PTR SearchStart);
__declspec(dllimport) long TITCALL ImporterAutoFixIATW(DWORD ProcessId, wchar_t* szDumpedFile, ULONG_PTR SearchStart);
__declspec(dllimport) bool TITCALL ImporterDeleteAPI(DWORD_PTR apiAddr);
// Global.Engine.Hook.functions:
__declspec(dllimport) bool TITCALL HooksSafeTransitionEx(LPVOID HookAddressArray, int NumberOfHooks, bool TransitionStart);
__declspec(dllimport) bool TITCALL HooksSafeTransition(LPVOID HookAddress, bool TransitionStart);
__declspec(dllimport) bool TITCALL HooksIsAddressRedirected(LPVOID HookAddress);
__declspec(dllimport) void* TITCALL HooksGetTrampolineAddress(LPVOID HookAddress);
__declspec(dllimport) void* TITCALL HooksGetHookEntryDetails(LPVOID HookAddress);
__declspec(dllimport) bool TITCALL HooksInsertNewRedirection(LPVOID HookAddress, LPVOID RedirectTo, int HookType);
__declspec(dllimport) bool TITCALL HooksInsertNewIATRedirectionEx(ULONG_PTR FileMapVA, ULONG_PTR LoadedModuleBase, char* szHookFunction, LPVOID RedirectTo);
__declspec(dllimport) bool TITCALL HooksInsertNewIATRedirection(char* szModuleName, char* szHookFunction, LPVOID RedirectTo);
__declspec(dllimport) bool TITCALL HooksRemoveRedirection(LPVOID HookAddress, bool RemoveAll);
__declspec(dllimport) bool TITCALL HooksRemoveRedirectionsForModule(HMODULE ModuleBase);
__declspec(dllimport) bool TITCALL HooksRemoveIATRedirection(char* szModuleName, char* szHookFunction, bool RemoveAll);
__declspec(dllimport) bool TITCALL HooksDisableRedirection(LPVOID HookAddress, bool DisableAll);
__declspec(dllimport) bool TITCALL HooksDisableRedirectionsForModule(HMODULE ModuleBase);
__declspec(dllimport) bool TITCALL HooksDisableIATRedirection(char* szModuleName, char* szHookFunction, bool DisableAll);
__declspec(dllimport) bool TITCALL HooksEnableRedirection(LPVOID HookAddress, bool EnableAll);
__declspec(dllimport) bool TITCALL HooksEnableRedirectionsForModule(HMODULE ModuleBase);
__declspec(dllimport) bool TITCALL HooksEnableIATRedirection(char* szModuleName, char* szHookFunction, bool EnableAll);
__declspec(dllimport) void TITCALL HooksScanModuleMemory(HMODULE ModuleBase, LPVOID CallBack);
__declspec(dllimport) void TITCALL HooksScanEntireProcessMemory(LPVOID CallBack);
__declspec(dllimport) void TITCALL HooksScanEntireProcessMemoryEx();
// TitanEngine.Tracer.functions:
__declspec(dllimport) void TITCALL TracerInit();
__declspec(dllimport) long long TITCALL TracerLevel1(HANDLE hProcess, ULONG_PTR AddressToTrace);
__declspec(dllimport) long long TITCALL HashTracerLevel1(HANDLE hProcess, ULONG_PTR AddressToTrace, DWORD InputNumberOfInstructions);
__declspec(dllimport) long TITCALL TracerDetectRedirection(HANDLE hProcess, ULONG_PTR AddressToTrace);
__declspec(dllimport) long long TITCALL TracerFixKnownRedirection(HANDLE hProcess, ULONG_PTR AddressToTrace, DWORD RedirectionId);
__declspec(dllimport) long long TITCALL TracerFixRedirectionViaModule(HMODULE hModuleHandle, HANDLE hProcess, ULONG_PTR AddressToTrace, DWORD IdParameter);
__declspec(dllimport) long long TITCALL TracerDetectRedirectionViaModule(HMODULE hModuleHandle, HANDLE hProcess, ULONG_PTR AddressToTrace, PDWORD ReturnedId);
__declspec(dllimport) long TITCALL TracerFixRedirectionViaImpRecPlugin(HANDLE hProcess, char* szPluginName, ULONG_PTR AddressToTrace);
// TitanEngine.Exporter.functions:
__declspec(dllimport) void TITCALL ExporterCleanup();
__declspec(dllimport) void TITCALL ExporterSetImageBase(ULONG_PTR ImageBase);
__declspec(dllimport) void TITCALL ExporterInit(DWORD MemorySize, ULONG_PTR ImageBase, DWORD ExportOrdinalBase, char* szExportModuleName);
__declspec(dllimport) bool TITCALL ExporterAddNewExport(char* szExportName, DWORD ExportRelativeAddress);
__declspec(dllimport) bool TITCALL ExporterAddNewOrdinalExport(DWORD OrdinalNumber, DWORD ExportRelativeAddress);
__declspec(dllimport) long TITCALL ExporterGetAddedExportCount();
__declspec(dllimport) long TITCALL ExporterEstimatedSize();
__declspec(dllimport) bool TITCALL ExporterBuildExportTable(ULONG_PTR StorePlace, ULONG_PTR FileMapVA);
__declspec(dllimport) bool TITCALL ExporterBuildExportTableEx(char* szExportFileName, char* szSectionName);
__declspec(dllimport) bool TITCALL ExporterBuildExportTableExW(wchar_t* szExportFileName, char* szSectionName);
__declspec(dllimport) bool TITCALL ExporterLoadExportTable(char* szFileName);
__declspec(dllimport) bool TITCALL ExporterLoadExportTableW(wchar_t* szFileName);
// TitanEngine.Librarian.functions:
__declspec(dllimport) bool TITCALL LibrarianSetBreakPoint(char* szLibraryName, DWORD bpxType, bool SingleShoot, LPVOID bpxCallBack);
__declspec(dllimport) bool TITCALL LibrarianRemoveBreakPoint(char* szLibraryName, DWORD bpxType);
__declspec(dllimport) void* TITCALL LibrarianGetLibraryInfo(char* szLibraryName);
__declspec(dllimport) void* TITCALL LibrarianGetLibraryInfoW(wchar_t* szLibraryName);
__declspec(dllimport) void* TITCALL LibrarianGetLibraryInfoEx(void* BaseOfDll);
__declspec(dllimport) void* TITCALL LibrarianGetLibraryInfoExW(void* BaseOfDll);
__declspec(dllimport) void TITCALL LibrarianEnumLibraryInfo(void* EnumCallBack);
__declspec(dllimport) void TITCALL LibrarianEnumLibraryInfoW(void* EnumCallBack);
// TitanEngine.Process.functions:
__declspec(dllimport) long TITCALL GetActiveProcessId(char* szImageName);
__declspec(dllimport) long TITCALL GetActiveProcessIdW(wchar_t* szImageName);
__declspec(dllimport) void TITCALL EnumProcessesWithLibrary(char* szLibraryName, void* EnumFunction);
// TitanEngine.TLSFixer.functions:
__declspec(dllimport) bool TITCALL TLSBreakOnCallBack(LPVOID ArrayOfCallBacks, DWORD NumberOfCallBacks, LPVOID bpxCallBack);
__declspec(dllimport) bool TITCALL TLSGrabCallBackData(char* szFileName, LPVOID ArrayOfCallBacks, LPDWORD NumberOfCallBacks);
__declspec(dllimport) bool TITCALL TLSGrabCallBackDataW(wchar_t* szFileName, LPVOID ArrayOfCallBacks, LPDWORD NumberOfCallBacks);
__declspec(dllimport) bool TITCALL TLSBreakOnCallBackEx(char* szFileName, LPVOID bpxCallBack);
__declspec(dllimport) bool TITCALL TLSBreakOnCallBackExW(wchar_t* szFileName, LPVOID bpxCallBack);
__declspec(dllimport) bool TITCALL TLSRemoveCallback(char* szFileName);
__declspec(dllimport) bool TITCALL TLSRemoveCallbackW(wchar_t* szFileName);
__declspec(dllimport) bool TITCALL TLSRemoveTable(char* szFileName);
__declspec(dllimport) bool TITCALL TLSRemoveTableW(wchar_t* szFileName);
__declspec(dllimport) bool TITCALL TLSBackupData(char* szFileName);
__declspec(dllimport) bool TITCALL TLSBackupDataW(wchar_t* szFileName);
__declspec(dllimport) bool TITCALL TLSRestoreData();
__declspec(dllimport) bool TITCALL TLSBuildNewTable(ULONG_PTR FileMapVA, ULONG_PTR StorePlace, ULONG_PTR StorePlaceRVA, LPVOID ArrayOfCallBacks, DWORD NumberOfCallBacks);
__declspec(dllimport) bool TITCALL TLSBuildNewTableEx(char* szFileName, char* szSectionName, LPVOID ArrayOfCallBacks, DWORD NumberOfCallBacks);
__declspec(dllimport) bool TITCALL TLSBuildNewTableExW(wchar_t* szFileName, char* szSectionName, LPVOID ArrayOfCallBacks, DWORD NumberOfCallBacks);
// TitanEngine.TranslateName.functions:
__declspec(dllimport) void* TITCALL TranslateNativeName(char* szNativeName);
__declspec(dllimport) void* TITCALL TranslateNativeNameW(wchar_t* szNativeName);
// TitanEngine.Handler.functions:
__declspec(dllimport) long TITCALL HandlerGetActiveHandleCount(DWORD ProcessId);
__declspec(dllimport) bool TITCALL HandlerIsHandleOpen(DWORD ProcessId, HANDLE hHandle);
__declspec(dllimport) void* TITCALL HandlerGetHandleName(HANDLE hProcess, DWORD ProcessId, HANDLE hHandle, bool TranslateName);
__declspec(dllimport) void* TITCALL HandlerGetHandleNameW(HANDLE hProcess, DWORD ProcessId, HANDLE hHandle, bool TranslateName);
__declspec(dllimport) long TITCALL HandlerEnumerateOpenHandles(DWORD ProcessId, LPVOID HandleBuffer, DWORD MaxHandleCount);
__declspec(dllimport) long long TITCALL HandlerGetHandleDetails(HANDLE hProcess, DWORD ProcessId, HANDLE hHandle, DWORD InformationReturn);
__declspec(dllimport) bool TITCALL HandlerCloseRemoteHandle(HANDLE hProcess, HANDLE hHandle);
__declspec(dllimport) long TITCALL HandlerEnumerateLockHandles(char* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated, LPVOID HandleDataBuffer, DWORD MaxHandleCount);
__declspec(dllimport) long TITCALL HandlerEnumerateLockHandlesW(wchar_t* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated, LPVOID HandleDataBuffer, DWORD MaxHandleCount);
__declspec(dllimport) bool TITCALL HandlerCloseAllLockHandles(char* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated);
__declspec(dllimport) bool TITCALL HandlerCloseAllLockHandlesW(wchar_t* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated);
__declspec(dllimport) bool TITCALL HandlerIsFileLocked(char* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated);
__declspec(dllimport) bool TITCALL HandlerIsFileLockedW(wchar_t* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated);
// TitanEngine.Handler[Mutex].functions:
__declspec(dllimport) long TITCALL HandlerEnumerateOpenMutexes(HANDLE hProcess, DWORD ProcessId, LPVOID HandleBuffer, DWORD MaxHandleCount);
__declspec(dllimport) long long TITCALL HandlerGetOpenMutexHandle(HANDLE hProcess, DWORD ProcessId, char* szMutexString);
__declspec(dllimport) long long TITCALL HandlerGetOpenMutexHandleW(HANDLE hProcess, DWORD ProcessId, wchar_t* szMutexString);
__declspec(dllimport) long TITCALL HandlerGetProcessIdWhichCreatedMutex(char* szMutexString);
__declspec(dllimport) long TITCALL HandlerGetProcessIdWhichCreatedMutexW(wchar_t* szMutexString);
// TitanEngine.Injector.functions:
__declspec(dllimport) bool TITCALL RemoteLoadLibrary(HANDLE hProcess, char* szLibraryFile, bool WaitForThreadExit);
__declspec(dllimport) bool TITCALL RemoteLoadLibraryW(HANDLE hProcess, wchar_t* szLibraryFile, bool WaitForThreadExit);
__declspec(dllimport) bool TITCALL RemoteFreeLibrary(HANDLE hProcess, HMODULE hModule, char* szLibraryFile, bool WaitForThreadExit);
__declspec(dllimport) bool TITCALL RemoteFreeLibraryW(HANDLE hProcess, HMODULE hModule, wchar_t* szLibraryFile, bool WaitForThreadExit);
__declspec(dllimport) bool TITCALL RemoteExitProcess(HANDLE hProcess, DWORD ExitCode);
// TitanEngine.StaticUnpacker.functions:
__declspec(dllimport) bool TITCALL StaticFileLoad(char* szFileName, DWORD DesiredAccess, bool SimulateLoad, LPHANDLE FileHandle, LPDWORD LoadedSize, LPHANDLE FileMap, PULONG_PTR FileMapVA);
__declspec(dllimport) bool TITCALL StaticFileLoadW(wchar_t* szFileName, DWORD DesiredAccess, bool SimulateLoad, LPHANDLE FileHandle, LPDWORD LoadedSize, LPHANDLE FileMap, PULONG_PTR FileMapVA);
__declspec(dllimport) bool TITCALL StaticFileUnload(char* szFileName, bool CommitChanges, HANDLE FileHandle, DWORD LoadedSize, HANDLE FileMap, ULONG_PTR FileMapVA);
__declspec(dllimport) bool TITCALL StaticFileUnloadW(wchar_t* szFileName, bool CommitChanges, HANDLE FileHandle, DWORD LoadedSize, HANDLE FileMap, ULONG_PTR FileMapVA);
__declspec(dllimport) bool TITCALL StaticFileOpen(char* szFileName, DWORD DesiredAccess, LPHANDLE FileHandle, LPDWORD FileSizeLow, LPDWORD FileSizeHigh);
__declspec(dllimport) bool TITCALL StaticFileOpenW(wchar_t* szFileName, DWORD DesiredAccess, LPHANDLE FileHandle, LPDWORD FileSizeLow, LPDWORD FileSizeHigh);
__declspec(dllimport) bool TITCALL StaticFileGetContent(HANDLE FileHandle, DWORD FilePositionLow, LPDWORD FilePositionHigh, void* Buffer, DWORD Size);
__declspec(dllimport) void TITCALL StaticFileClose(HANDLE FileHandle);
__declspec(dllimport) void TITCALL StaticMemoryDecrypt(LPVOID MemoryStart, DWORD MemorySize, DWORD DecryptionType, DWORD DecryptionKeySize, ULONG_PTR DecryptionKey);
__declspec(dllimport) void TITCALL StaticMemoryDecryptEx(LPVOID MemoryStart, DWORD MemorySize, DWORD DecryptionKeySize, void* DecryptionCallBack);
__declspec(dllimport) void TITCALL StaticMemoryDecryptSpecial(LPVOID MemoryStart, DWORD MemorySize, DWORD DecryptionKeySize, DWORD SpecDecryptionType, void* DecryptionCallBack);
__declspec(dllimport) void TITCALL StaticSectionDecrypt(ULONG_PTR FileMapVA, DWORD SectionNumber, bool SimulateLoad, DWORD DecryptionType, DWORD DecryptionKeySize, ULONG_PTR DecryptionKey);
__declspec(dllimport) bool TITCALL StaticMemoryDecompress(void* Source, DWORD SourceSize, void* Destination, DWORD DestinationSize, int Algorithm);
__declspec(dllimport) bool TITCALL StaticRawMemoryCopy(HANDLE hFile, ULONG_PTR FileMapVA, ULONG_PTR VitualAddressToCopy, DWORD Size, bool AddressIsRVA, char* szDumpFileName);
__declspec(dllimport) bool TITCALL StaticRawMemoryCopyW(HANDLE hFile, ULONG_PTR FileMapVA, ULONG_PTR VitualAddressToCopy, DWORD Size, bool AddressIsRVA, wchar_t* szDumpFileName);
__declspec(dllexport) bool TITCALL StaticRawMemoryCopyEx(HANDLE hFile, DWORD RawAddressToCopy, DWORD Size, char* szDumpFileName);
__declspec(dllexport) bool TITCALL StaticRawMemoryCopyExW(HANDLE hFile, DWORD RawAddressToCopy, DWORD Size, wchar_t* szDumpFileName);
__declspec(dllexport) bool TITCALL StaticRawMemoryCopyEx64(HANDLE hFile, DWORD64 RawAddressToCopy, DWORD64 Size, char* szDumpFileName);
__declspec(dllexport) bool TITCALL StaticRawMemoryCopyEx64W(HANDLE hFile, DWORD64 RawAddressToCopy, DWORD64 Size, wchar_t* szDumpFileName);
__declspec(dllimport) bool TITCALL StaticHashMemory(void* MemoryToHash, DWORD SizeOfMemory, void* HashDigest, bool OutputString, int Algorithm);
__declspec(dllimport) bool TITCALL StaticHashFile(char* szFileName, char* HashDigest, bool OutputString, int Algorithm);
__declspec(dllimport) bool TITCALL StaticHashFileW(wchar_t* szFileName, char* HashDigest, bool OutputString, int Algorithm);
// TitanEngine.Engine.functions:
__declspec(dllimport) void TITCALL SetEngineVariable(DWORD VariableId, bool VariableSet);
__declspec(dllimport) bool TITCALL EngineCreateMissingDependencies(char* szFileName, char* szOutputFolder, bool LogCreatedFiles);
__declspec(dllimport) bool TITCALL EngineCreateMissingDependenciesW(wchar_t* szFileName, wchar_t* szOutputFolder, bool LogCreatedFiles);
__declspec(dllimport) bool TITCALL EngineFakeMissingDependencies(HANDLE hProcess);
__declspec(dllimport) bool TITCALL EngineDeleteCreatedDependencies();
__declspec(dllimport) bool TITCALL EngineCreateUnpackerWindow(char* WindowUnpackerTitle, char* WindowUnpackerLongTitle, char* WindowUnpackerName, char* WindowUnpackerAuthor, void* StartUnpackingCallBack);
__declspec(dllimport) void TITCALL EngineAddUnpackerWindowLogMessage(char* szLogMessage);
// Global.Engine.Extension.Functions:
__declspec(dllimport) bool TITCALL ExtensionManagerIsPluginLoaded(char* szPluginName);
__declspec(dllimport) bool TITCALL ExtensionManagerIsPluginEnabled(char* szPluginName);
__declspec(dllimport) bool TITCALL ExtensionManagerDisableAllPlugins();
__declspec(dllimport) bool TITCALL ExtensionManagerDisablePlugin(char* szPluginName);
__declspec(dllimport) bool TITCALL ExtensionManagerEnableAllPlugins();
__declspec(dllimport) bool TITCALL ExtensionManagerEnablePlugin(char* szPluginName);
__declspec(dllimport) bool TITCALL ExtensionManagerUnloadAllPlugins();
__declspec(dllimport) bool TITCALL ExtensionManagerUnloadPlugin(char* szPluginName);
__declspec(dllimport) void* TITCALL ExtensionManagerGetPluginInfo(char* szPluginName);

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#pragma pack(pop)

#endif /*TITANENGINE*/
