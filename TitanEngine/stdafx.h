// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once
#include "targetver.h"

// Build switches
//#define TITANENGINE_BUILD_ASM_LIB

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>
#include <Winternl.h>

#if !defined(_WIN64)
#include "aplib.h"
#endif
#include "LzmaDec.h"

#define UE_PLATFORM_x86 1
#define UE_PLATFORM_x64 2
#define UE_PLATFORM_ALL 3

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L) // ntsubauth

// Engine.Internal:
#define TITANENGINE_PAGESIZE 0x1000
#define MAX_IMPORT_ALLOC 256 * 256
#define MAX_RELOC_ALLOC 1024 * 1024
#define UE_MAX_RESERVED_MEMORY_LEFT 32
#define MAXIMUM_SECTION_NUMBER 32
#define MAX_DECODE_INSTRUCTIONS 32
#define MAX_INSTRUCTIONS (1000)
#define MAXIMUM_BREAKPOINTS 1000
#define MAXIMUM_INSTRUCTION_SIZE 40
#define MAX_RET_SEARCH_INSTRUCTIONS 100

#define UE_OPTION_IMPORTER_REALIGN_LOCAL_APIADDRESS 0
#define UE_OPTION_IMPORTER_REALIGN_APIADDRESS 1
#define UE_OPTION_IMPORTER_RETURN_APINAME 2 //no kernelbase
#define UE_OPTION_IMPORTER_RETURN_APIADDRESS 3
#define UE_OPTION_IMPORTER_RETURN_DLLNAME 4 //no kernelbase
#define UE_OPTION_IMPORTER_RETURN_DLLINDEX 5
#define UE_OPTION_IMPORTER_RETURN_DLLBASE 6
#define UE_OPTION_IMPORTER_RETURN_FORWARDER_DLLNAME 7
#define UE_OPTION_IMPORTER_RETURN_FORWARDER_DLLINDEX 8
#define UE_OPTION_IMPORTER_RETURN_FORWARDER_APINAME 9
#define UE_OPTION_IMPORTER_RETURN_FORWARDER_API_ORDINAL_NUMBER 10
#define UE_OPTION_IMPORTER_RETURN_NEAREST_APIADDRESS 11
#define UE_OPTION_IMPORTER_RETURN_NEAREST_APINAME 12
#define UE_OPTION_IMPORTER_RETURN_API_ORDINAL_NUMBER 13

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

typedef struct
{
    ULONG_PTR BreakPointAddress;
    ULONG_PTR Parameter1;
    ULONG_PTR Parameter2;
    int SnapShotNumber;
    bool SingleBreak;
} UnpackerInformation, *PUnpackerInformation;

typedef struct
{
    bool ExpertModeActive;
    wchar_t* szFileName;
    bool ReserveModuleBase;
    wchar_t* szCommandLine;
    wchar_t* szCurrentFolder;
    LPVOID EntryCallBack;
} ExpertDebug, *PExpertDebug;

typedef struct
{
    ULONG_PTR fLoadLibrary;
    ULONG_PTR fFreeLibrary;
    ULONG_PTR fGetModuleHandle;
    ULONG_PTR fGetProcAddress;
    ULONG_PTR fVirtualFree;
    ULONG_PTR fExitProcess;
    HMODULE fFreeLibraryHandle;
    DWORD fExitProcessCode;
} InjectCodeData, *PInjectCodeData;

typedef struct
{
    ULONG_PTR fTrace;
    ULONG_PTR fCreateFileA;
    ULONG_PTR fCloseHandle;
    ULONG_PTR fCreateFileMappingA;
    ULONG_PTR AddressToTrace;
} InjectImpRecCodeData, *PInjectImpRecCodeData;

#define UE_MAX_BREAKPOINT_SIZE 2
#define UE_BREAKPOINT_INT3 1
#define UE_BREAKPOINT_LONG_INT3 2
#define UE_BREAKPOINT_UD2 3

typedef struct
{
    BYTE BreakPointActive;
    ULONG_PTR BreakPointAddress;
    DWORD BreakPointSize;
    BYTE OriginalByte[10];
    int BreakPointType;
    int AdvancedBreakPointType;
    int MemoryBpxRestoreOnHit;
    DWORD NumberOfExecutions;
    DWORD CmpRegister;
    int CmpCondition;
    ULONG_PTR CmpValue;
    ULONG_PTR ExecuteCallBack;
    ULONG_PTR CompareCallBack;
    ULONG_PTR RemoveCallBack;
    DWORD UniqueLinkId;
} BreakPointDetail, *PBreakPointDetail;

typedef struct
{
    ULONG_PTR DrxBreakAddress;
    ULONG_PTR DrxCallBack;
    DWORD DrxBreakPointType;
    DWORD DrxBreakPointSize;
    bool DrxEnabled;
    bool DrxExecution;
} HARDWARE_DATA, *PHARDWARE_DATA;

enum HWBP_MODE
{
    MODE_DISABLED=0, //00
    MODE_LOCAL=1, //01
    MODE_GLOBAL=2 //10
};

enum HWBP_TYPE
{
    TYPE_EXECUTE=0, //00
    TYPE_WRITE=1, //01
    TYPE_READWRITE=3 //11
};

enum HWBP_SIZE
{
    SIZE_1=0, //00
    SIZE_2=1, //01
    SIZE_8=2, //10
    SIZE_4=3 //11
};

struct DR7
{
    BYTE HWBP_MODE[4];
    BYTE HWBP_TYPE[4];
    BYTE HWBP_SIZE[4];
};

#define BITSET(a,x) (a|=1<<x)
#define BITCLEAR(a,x) (a&=~(1<<x))
#define BITTOGGLE(a,x) (a^=1<<x)
#define BITGET(a,x) (a&(1<<x))

typedef struct
{
    ULONG_PTR chBreakPoint;
    ULONG_PTR chSingleStep;
    ULONG_PTR chAccessViolation;
    ULONG_PTR chIllegalInstruction;
    ULONG_PTR chNonContinuableException;
    ULONG_PTR chArrayBoundsException;
    ULONG_PTR chFloatDenormalOperand;
    ULONG_PTR chFloatDevideByZero;
    ULONG_PTR chIntegerDevideByZero;
    ULONG_PTR chIntegerOverflow;
    ULONG_PTR chPrivilegedInstruction;
    ULONG_PTR chPageGuard;
    ULONG_PTR chEverythingElse;
    ULONG_PTR chCreateThread;
    ULONG_PTR chExitThread;
    ULONG_PTR chCreateProcess;
    ULONG_PTR chExitProcess;
    ULONG_PTR chLoadDll;
    ULONG_PTR chUnloadDll;
    ULONG_PTR chOutputDebugString;
    ULONG_PTR chAfterException;
    ULONG_PTR chSystemBreakpoint;
    ULONG_PTR chUnhandledException;
} CustomHandler, *PCustomHandler;

typedef struct
{
    DWORD OrdinalBase;
    DWORD NumberOfExportFunctions;
    char FileName[512];
} EXPORT_DATA, *PEXPORT_DATA;

typedef struct
{
    DWORD ExportedItem;
} EXPORTED_DATA, *PEXPORTED_DATA;

typedef struct
{
    WORD OrdinalNumber;
} EXPORTED_DATA_WORD, *PEXPORTED_DATA_WORD;

typedef struct
{
    BYTE DataByte[50];
} MEMORY_CMP_HANDLER, *PMEMORY_CMP_HANDLER;

typedef struct
{
    BYTE DataByte;
} MEMORY_CMP_BYTE_HANDLER, *PMEMORY_CMP_BYTE_HANDLER;

typedef struct MEMORY_COMPARE_HANDLER
{
    union
    {
        BYTE bArrayEntry[1];
        WORD wArrayEntry[1];
        DWORD dwArrayEntry[1];
        DWORD64 qwArrayEntry[1];
    } Array;
} MEMORY_COMPARE_HANDLER, *PMEMORY_COMPARE_HANDLER;

#define MAX_DEBUG_DATA 512

typedef struct
{
    HANDLE hThread;
    DWORD dwThreadId;
    void* ThreadStartAddress;
    void* ThreadLocalBase;
} THREAD_ITEM_DATA, *PTHREAD_ITEM_DATA;

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

#define MAX_LIBRARY_BPX 64
#define UE_ON_LIB_LOAD 1
#define UE_ON_LIB_UNLOAD 2
#define UE_ON_LIB_ALL 3

typedef struct
{
    char szLibraryName[128];
    void* bpxCallBack;
    bool bpxSingleShoot;
    int bpxType;
} LIBRARY_BREAK_DATA, *PLIBRARY_BREAK_DATA;

#define TEE_MAXIMUM_HOOK_SIZE 14
#if defined(_WIN64)
#define TEE_MAXIMUM_HOOK_INSERT_SIZE 14
#else
#define TEE_MAXIMUM_HOOK_INSERT_SIZE 5
#endif

#define TEE_HOOK_NRM_JUMP 1
#define TEE_HOOK_NRM_CALL 3
#define TEE_HOOK_IAT 5
#define TEE_MAXIMUM_HOOK_RELOCS 7

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

// Engine.External:
#define UE_ACCESS_READ 0
#define UE_ACCESS_WRITE 1
#define UE_ACCESS_ALL 2

#define UE_HIDE_BASIC 1

#define UE_PLUGIN_CALL_REASON_PREDEBUG 1
#define UE_PLUGIN_CALL_REASON_EXCEPTION 2
#define UE_PLUGIN_CALL_REASON_POSTDEBUG 3

#define UE_ENGINE_ALOW_MODULE_LOADING 1
#define UE_ENGINE_AUTOFIX_FORWARDERS 2
#define UE_ENGINE_PASS_ALL_EXCEPTIONS 3
#define UE_ENGINE_NO_CONSOLE_WINDOW 4
#define UE_ENGINE_BACKUP_FOR_CRITICAL_FUNCTIONS 5
#define UE_ENGINE_CALL_PLUGIN_CALLBACK 6
#define UE_ENGINE_RESET_CUSTOM_HANDLER 7
#define UE_ENGINE_CALL_PLUGIN_DEBUG_CALLBACK 8

#define UE_OPTION_REMOVEALL 1
#define UE_OPTION_DISABLEALL 2
#define UE_OPTION_REMOVEALLDISABLED 3
#define UE_OPTION_REMOVEALLENABLED 4

#define UE_STATIC_DECRYPTOR_XOR 1
#define UE_STATIC_DECRYPTOR_SUB 2
#define UE_STATIC_DECRYPTOR_ADD 3

#define UE_STATIC_DECRYPTOR_FOREWARD 1
#define UE_STATIC_DECRYPTOR_BACKWARD 2

#define UE_STATIC_KEY_SIZE_1 1
#define UE_STATIC_KEY_SIZE_2 2
#define UE_STATIC_KEY_SIZE_4 4
#define UE_STATIC_KEY_SIZE_8 8

#define UE_STATIC_APLIB 1
#define UE_STATIC_APLIB_DEPACK 2
#define UE_STATIC_LZMA 3

#define UE_STATIC_HASH_MD5 1
#define UE_STATIC_HASH_SHA1 2
#define UE_STATIC_HASH_CRC32 3

#define UE_RESOURCE_LANGUAGE_ANY -1

#define UE_PE_OFFSET 0
#define UE_IMAGEBASE 1
#define UE_OEP 2
#define UE_SIZEOFIMAGE 3
#define UE_SIZEOFHEADERS 4
#define UE_SIZEOFOPTIONALHEADER 5
#define UE_SECTIONALIGNMENT 6
#define UE_IMPORTTABLEADDRESS 7
#define UE_IMPORTTABLESIZE 8
#define UE_RESOURCETABLEADDRESS 9
#define UE_RESOURCETABLESIZE 10
#define UE_EXPORTTABLEADDRESS 11
#define UE_EXPORTTABLESIZE 12
#define UE_TLSTABLEADDRESS 13
#define UE_TLSTABLESIZE 14
#define UE_RELOCATIONTABLEADDRESS 15
#define UE_RELOCATIONTABLESIZE 16
#define UE_TIMEDATESTAMP 17
#define UE_SECTIONNUMBER 18
#define UE_CHECKSUM 19
#define UE_SUBSYSTEM 20
#define UE_CHARACTERISTICS 21
#define UE_NUMBEROFRVAANDSIZES 22
#define UE_BASEOFCODE 23
#define UE_BASEOFDATA 24
//leaving some enum space here for future additions
#define UE_SECTIONNAME 40
#define UE_SECTIONVIRTUALOFFSET 41
#define UE_SECTIONVIRTUALSIZE 42
#define UE_SECTIONRAWOFFSET 43
#define UE_SECTIONRAWSIZE 44
#define UE_SECTIONFLAGS 45

#define UE_CH_BREAKPOINT 1
#define UE_CH_SINGLESTEP 2
#define UE_CH_ACCESSVIOLATION 3
#define UE_CH_ILLEGALINSTRUCTION 4
#define UE_CH_NONCONTINUABLEEXCEPTION 5
#define UE_CH_ARRAYBOUNDSEXCEPTION 6
#define UE_CH_FLOATDENORMALOPERAND 7
#define UE_CH_FLOATDEVIDEBYZERO 8
#define UE_CH_INTEGERDEVIDEBYZERO 9
#define UE_CH_INTEGEROVERFLOW 10
#define UE_CH_PRIVILEGEDINSTRUCTION 11
#define UE_CH_PAGEGUARD 12
#define UE_CH_EVERYTHINGELSE 13
#define UE_CH_CREATETHREAD 14
#define UE_CH_EXITTHREAD 15
#define UE_CH_CREATEPROCESS 16
#define UE_CH_EXITPROCESS 17
#define UE_CH_LOADDLL 18
#define UE_CH_UNLOADDLL 19
#define UE_CH_OUTPUTDEBUGSTRING 20
#define UE_CH_AFTEREXCEPTIONPROCESSING 21
#define UE_CH_ALLEVENTS 22
#define UE_CH_SYSTEMBREAKPOINT 23
#define UE_CH_UNHANDLEDEXCEPTION 24

#define UE_OPTION_HANDLER_RETURN_HANDLECOUNT 1
#define UE_OPTION_HANDLER_RETURN_ACCESS 2
#define UE_OPTION_HANDLER_RETURN_FLAGS 3
#define UE_OPTION_HANDLER_RETURN_TYPENAME 4
#define UE_OPTION_HANDLER_RETURN_TYPENAME_UNICODE 5

typedef struct
{
    ULONG ProcessId;
    HANDLE hHandle;
} HandlerArray, *PHandlerArray;

#define UE_BPXREMOVED 0
#define UE_BPXACTIVE 1
#define UE_BPXINACTIVE 2

#define UE_BREAKPOINT 0
#define UE_SINGLESHOOT 1
#define UE_HARDWARE 2
#define UE_MEMORY 3
#define UE_MEMORY_READ 4
#define UE_MEMORY_WRITE 5
#define UE_MEMORY_EXECUTE 6
#define UE_BREAKPOINT_TYPE_INT3 0x10000000
#define UE_BREAKPOINT_TYPE_LONG_INT3 0x20000000
#define UE_BREAKPOINT_TYPE_UD2 0x30000000

#define UE_HARDWARE_EXECUTE 4
#define UE_HARDWARE_WRITE 5
#define UE_HARDWARE_READWRITE 6

#define UE_HARDWARE_SIZE_1 7
#define UE_HARDWARE_SIZE_2 8
#define UE_HARDWARE_SIZE_4 9
#define UE_HARDWARE_SIZE_8 10

#define UE_APISTART 0
#define UE_APIEND 1

#define UE_FUNCTION_STDCALL 1
#define UE_FUNCTION_CCALL 2
#define UE_FUNCTION_FASTCALL 3
#define UE_FUNCTION_STDCALL_RET 4
#define UE_FUNCTION_CCALL_RET 5
#define UE_FUNCTION_FASTCALL_RET 6
#define UE_FUNCTION_STDCALL_CALL 7
#define UE_FUNCTION_CCALL_CALL 8
#define UE_FUNCTION_FASTCALL_CALL 9
#define UE_PARAMETER_BYTE 0
#define UE_PARAMETER_WORD 1
#define UE_PARAMETER_DWORD 2
#define UE_PARAMETER_QWORD 3
#define UE_PARAMETER_PTR_BYTE 4
#define UE_PARAMETER_PTR_WORD 5
#define UE_PARAMETER_PTR_DWORD 6
#define UE_PARAMETER_PTR_QWORD 7
#define UE_PARAMETER_STRING 8
#define UE_PARAMETER_UNICODE 9

#define UE_CMP_NOCONDITION 0
#define UE_CMP_EQUAL 1
#define UE_CMP_NOTEQUAL 2
#define UE_CMP_GREATER 3
#define UE_CMP_GREATEROREQUAL 4
#define UE_CMP_LOWER 5
#define UE_CMP_LOWEROREQUAL 6
#define UE_CMP_REG_EQUAL 7
#define UE_CMP_REG_NOTEQUAL 8
#define UE_CMP_REG_GREATER 9
#define UE_CMP_REG_GREATEROREQUAL 10
#define UE_CMP_REG_LOWER 11
#define UE_CMP_REG_LOWEROREQUAL 12
#define UE_CMP_ALWAYSFALSE 13

#define UE_EAX 1
#define UE_EBX 2
#define UE_ECX 3
#define UE_EDX 4
#define UE_EDI 5
#define UE_ESI 6
#define UE_EBP 7
#define UE_ESP 8
#define UE_EIP 9
#define UE_EFLAGS 10
#define UE_DR0 11
#define UE_DR1 12
#define UE_DR2 13
#define UE_DR3 14
#define UE_DR6 15
#define UE_DR7 16
#define UE_RAX 17
#define UE_RBX 18
#define UE_RCX 19
#define UE_RDX 20
#define UE_RDI 21
#define UE_RSI 22
#define UE_RBP 23
#define UE_RSP 24
#define UE_RIP 25
#define UE_RFLAGS 26
#define UE_R8 27
#define UE_R9 28
#define UE_R10 29
#define UE_R11 30
#define UE_R12 31
#define UE_R13 32
#define UE_R14 33
#define UE_R15 34
#define UE_CIP 35
#define UE_CSP 36
#define UE_SEG_GS 37
#define UE_SEG_FS 38
#define UE_SEG_ES 39
#define UE_SEG_DS 40
#define UE_SEG_CS 41
#define UE_SEG_SS 42

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

#define UE_DEPTH_SURFACE 0
#define UE_DEPTH_DEEP 1

#define UE_UNPACKER_CONDITION_SEARCH_FROM_EP 1

#define UE_UNPACKER_CONDITION_LOADLIBRARY 1
#define UE_UNPACKER_CONDITION_GETPROCADDRESS 2
#define UE_UNPACKER_CONDITION_ENTRYPOINTBREAK 3
#define UE_UNPACKER_CONDITION_RELOCSNAPSHOT1 4
#define UE_UNPACKER_CONDITION_RELOCSNAPSHOT2 5

#define UE_FIELD_OK 0
#define UE_FIELD_BROKEN_NON_FIXABLE 1
#define UE_FIELD_BROKEN_NON_CRITICAL 2
#define UE_FIELD_BROKEN_FIXABLE_FOR_STATIC_USE 3
#define UE_FIELD_BROKEN_BUT_CAN_BE_EMULATED 4
#define UE_FILED_FIXABLE_NON_CRITICAL 5
#define UE_FILED_FIXABLE_CRITICAL 6
#define UE_FIELD_NOT_PRESET 7
#define UE_FIELD_NOT_PRESET_WARNING 8

#define UE_RESULT_FILE_OK 10
#define UE_RESULT_FILE_INVALID_BUT_FIXABLE 11
#define UE_RESULT_FILE_INVALID_AND_NON_FIXABLE 12
#define UE_RESULT_FILE_INVALID_FORMAT 13

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

typedef struct
{
    void* AllocatedSection;
    DWORD SectionVirtualOffset;
    DWORD SectionVirtualSize;
    DWORD SectionAttributes;
    DWORD SectionDataHash;
    bool AccessedAlready;
    bool WriteCheckMode;
} TracerSectionData, *PTracerSectionData;

typedef struct
{
    int SectionNumber;
    TracerSectionData SectionData[MAXIMUM_SECTION_NUMBER];
    int OriginalEntryPointNum;
    ULONG_PTR OriginalImageBase;
    ULONG_PTR OriginalEntryPoint;
    ULONG_PTR LoadedImageBase;
    ULONG_PTR SizeOfImage;
    ULONG_PTR CurrentIntructionPointer;
    ULONG_PTR MemoryAccessedFrom;
    ULONG_PTR MemoryAccessed;
    ULONG_PTR AccessType;
    void* InitCallBack;
    void* EPCallBack;
    bool FileIsDLL;
    bool FileIs64bit;
} GenericOEPTracerData, *PGenericOEPTracerData;

// UnpackEngine.Handler:

#define NTDLL_SystemHandleInfo 0x10
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

/*typedef enum _POOL_TYPE {
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS,
	MaxPoolType,
	NonPagedPoolSession,
	PagedPoolSession,
	NonPagedPoolMustSucceedSession,
	DontUseThisTypeSession,
	NonPagedPoolCacheAlignedSession,
	PagedPoolCacheAlignedSession,
	NonPagedPoolCacheAlignedMustSSession
} POOL_TYPE;*/

typedef struct
{
    ULONG ProcessId;
    UCHAR ObjectTypeNumber;
    UCHAR Flags; // 0x01 = PROTECT_FROM_CLOSE, 0x02 = INHERIT
    USHORT hHandle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} NTDLL_QUERY_HANDLE_INFO, *PNTDLL_QUERY_HANDLE_INFO;

/*typedef struct _PUBLIC_OBJECT_BASIC_INFORMATION {
	ULONG Attributes;
	ACCESS_MASK GrantedAccess;
	ULONG HandleCount;
	ULONG PointerCount;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
	ULONG Reserved[3];
	ULONG NameInformationLength;
	ULONG TypeInformationLength;
	ULONG SecurityDescriptorLength;
	LARGE_INTEGER CreateTime;
} PUBLIC_OBJECT_BASIC_INFORMATION, *PPUBLIC_OBJECT_BASIC_INFORMATION;*/

typedef struct _PUBLIC_OBJECT_NAME_INFORMATION   // Information Class 1
{
    UNICODE_STRING Name;
} PUBLIC_OBJECT_NAME_INFORMATION, *PPUBLIC_OBJECT_NAME_INFORMATION;

/*typedef struct _PUBLIC_OBJECT_TYPE_INFORMATION { // Information Class 2
	UNICODE_STRING Name;
	ULONG ObjectCount;
	ULONG HandleCount;
	ULONG Reserved1[4];
	ULONG PeakObjectCount;
	ULONG PeakHandleCount;
	ULONG Reserved2[4];
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	UCHAR Unknown;
	BOOLEAN MaintainHandleDatabase;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} PUBLIC_OBJECT_TYPE_INFORMATION, *PPUBLIC_OBJECT_TYPE_INFORMATION;*/

typedef void (*PPEBLOCKROUTINE)(
    PVOID PebLock
);

/*typedef struct _PEB_LDR_DATA {
  ULONG                   Length;
  BOOLEAN                 Initialized;
  PVOID                   SsHandle;
  LIST_ENTRY              InLoadOrderModuleList;
  LIST_ENTRY              InMemoryOrderModuleList;
  LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;*/

/*typedef struct _RTL_DRIVE_LETTER_CURDIR {
  USHORT                  Flags;
  USHORT                  Length;
  ULONG                   TimeStamp;
  UNICODE_STRING          DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  ULONG                   MaximumLength;
  ULONG                   Length;
  ULONG                   Flags;
  ULONG                   DebugFlags;
  PVOID                   ConsoleHandle;
  ULONG                   ConsoleFlags;
  HANDLE                  StdInputHandle;
  HANDLE                  StdOutputHandle;
  HANDLE                  StdErrorHandle;
  UNICODE_STRING          CurrentDirectoryPath;
  HANDLE                  CurrentDirectoryHandle;
  UNICODE_STRING          DllPath;
  UNICODE_STRING          ImagePathName;
  UNICODE_STRING          CommandLine;
  PVOID                   Environment;
  ULONG                   StartingPositionLeft;
  ULONG                   StartingPositionTop;
  ULONG                   Width;
  ULONG                   Height;
  ULONG                   CharWidth;
  ULONG                   CharHeight;
  ULONG                   ConsoleTextAttributes;
  ULONG                   WindowFlags;
  ULONG                   ShowWindowFlags;
  UNICODE_STRING          WindowTitle;
  UNICODE_STRING          DesktopName;
  UNICODE_STRING          ShellInfo;
  UNICODE_STRING          RuntimeData;
  RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;*/

typedef struct _NTPEB
{
    BOOLEAN                 InheritedAddressSpace;
    BOOLEAN                 ReadImageFileExecOptions;
    BOOLEAN                 BeingDebugged;
    BOOLEAN                 Spare;
    HANDLE                  Mutant;
    PVOID                   ImageBaseAddress;
    PPEB_LDR_DATA           LoaderData;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID                   SubSystemData;
    PVOID                   ProcessHeap;
    PVOID                   FastPebLock;
    void*					  FastPebLockRoutine;
    void*					  FastPebUnlockRoutine;
    ULONG                   EnvironmentUpdateCount;
    PVOID*                  KernelCallbackTable;
    PVOID                   EventLogSection;
    PVOID                   EventLog;
    void*					  FreeList;
    ULONG                   TlsExpansionCounter;
    PVOID                   TlsBitmap;
    ULONG                   TlsBitmapBits[0x2];
    PVOID                   ReadOnlySharedMemoryBase;
    PVOID                   ReadOnlySharedMemoryHeap;
    PVOID*                  ReadOnlyStaticServerData;
    PVOID                   AnsiCodePageData;
    PVOID                   OemCodePageData;
    PVOID                   UnicodeCaseTableData;
    ULONG                   NumberOfProcessors;
    ULONG                   NtGlobalFlag;
    BYTE                    Spare2[0x4];
    LARGE_INTEGER           CriticalSectionTimeout;
    ULONG                   HeapSegmentReserve;
    ULONG                   HeapSegmentCommit;
    ULONG                   HeapDeCommitTotalFreeThreshold;
    ULONG                   HeapDeCommitFreeBlockThreshold;
    ULONG                   NumberOfHeaps;
    ULONG                   MaximumNumberOfHeaps;
    PVOID*                  *ProcessHeaps;
    PVOID                   GdiSharedHandleTable;
    PVOID                   ProcessStarterHelper;
    PVOID                   GdiDCAttributeList;
    PVOID                   LoaderLock;
    ULONG                   OSMajorVersion;
    ULONG                   OSMinorVersion;
    ULONG                   OSBuildNumber;
    ULONG                   OSPlatformId;
    ULONG                   ImageSubSystem;
    ULONG                   ImageSubSystemMajorVersion;
    ULONG                   ImageSubSystemMinorVersion;
    ULONG                   GdiHandleBuffer[0x22];
    ULONG                   PostProcessInitRoutine;
    ULONG                   TlsExpansionBitmap;
    BYTE                    TlsExpansionBitmapBits[0x80];
    ULONG                   SessionId;
} NTPEB, *PNTPEB;
