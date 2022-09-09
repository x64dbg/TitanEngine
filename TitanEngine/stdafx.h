// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include "targetver.h"

// Build switches
//#define TITANENGINE_BUILD_ASM_LIB

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers

// Allow including Windows.h without bringing in a redefined and outdated subset of NTSTATUSes.
// To get NTSTATUS defines, #undef WIN32_NO_STATUS after Windows.h and then #include <ntstatus.h>
#define WIN32_NO_STATUS

// Windows Header Files:
#include <windows.h>

#include <imagehlp.h>
#include <wincrypt.h>
#include <psapi.h>
#include <commdlg.h>
#include <shellapi.h>
#include <tlhelp32.h>


//stl/crt
#include <vector>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

#ifndef _Out_writes_opt_
#define _Out_writes_opt_(x)
#endif

#ifndef _In_reads_
#define _In_reads_(x)
#endif

#ifndef _Inout_updates_bytes_
#define _Inout_updates_bytes_(x)
#endif

#ifndef _Out_writes_bytes_opt_
#define _Out_writes_bytes_opt_(X)
#endif

//#include <winternl.h>
#include "ntdll.h"
#include "aplib.h"
#include "LzmaDec.h"

#include "Global.Helper.h"

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L) // ntsubauth

// Engine.Internal:
#define TITANENGINE_PAGESIZE (0x1000)
#define MAX_IMPORT_ALLOC (256 * 256)
#define MAX_RELOC_ALLOC (1024 * 1024)
#define UE_MAX_RESERVED_MEMORY_LEFT (32)
#define MAXIMUM_SECTION_NUMBER (32)
#define MAX_DECODE_INSTRUCTIONS (32)
#define MAX_INSTRUCTIONS (1000)
#define MAXIMUM_BREAKPOINTS (1000)
#define MAXIMUM_INSTRUCTION_SIZE (16) //maximum instruction size == 16
#define MAX_RET_SEARCH_INSTRUCTIONS (100)

#define UE_TRAP_FLAG (0x100)
#define UE_RESUME_FLAG (0x10000)

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

#pragma pack(push)
#pragma pack(1)

//EngineCheckStructAlignment
#define UE_STRUCT_PE32STRUCT 1
#define UE_STRUCT_PE64STRUCT 2
#define UE_STRUCT_PESTRUCT 3
#define UE_STRUCT_IMPORTENUMDATA 4
#define UE_STRUCT_THREAD_ITEM_DATA 5
#define UE_STRUCT_LIBRARY_ITEM_DATA 6
#define UE_STRUCT_LIBRARY_ITEM_DATAW 7
#define UE_STRUCT_PROCESS_ITEM_DATA 8
#define UE_STRUCT_HANDLERARRAY 9
#define UE_STRUCT_PLUGININFORMATION 10
#define UE_STRUCT_HOOK_ENTRY 11
#define UE_STRUCT_FILE_STATUS_INFO 12
#define UE_STRUCT_FILE_FIX_INFO 13
#define UE_STRUCT_X87FPUREGISTER 14
#define UE_STRUCT_X87FPU 15
#define UE_STRUCT_TITAN_ENGINE_CONTEXT 16

#ifndef CONTEXT_EXTENDED_REGISTERS
#define CONTEXT_EXTENDED_REGISTERS 0
#endif

typedef struct DECLSPEC_ALIGN(16) _XmmRegister_t
{
    ULONGLONG Low;
    LONGLONG High;
} XmmRegister_t;

typedef struct
{
    XmmRegister_t Low; //XMM/SSE part
    XmmRegister_t High; //AVX part
} YmmRegister_t;

typedef struct
{
    BYTE    data[10];
    int     st_value;
    int     tag;
} x87FPURegister_t;

typedef struct
{
    WORD   ControlWord;
    WORD   StatusWord;
    WORD   TagWord;
    DWORD   ErrorOffset;
    DWORD   ErrorSelector;
    DWORD   DataOffset;
    DWORD   DataSelector;
    DWORD   Cr0NpxState;
} x87FPU_t;

typedef struct
{
    ULONG_PTR cax;
    ULONG_PTR ccx;
    ULONG_PTR cdx;
    ULONG_PTR cbx;
    ULONG_PTR csp;
    ULONG_PTR cbp;
    ULONG_PTR csi;
    ULONG_PTR cdi;
#ifdef _WIN64
    ULONG_PTR r8;
    ULONG_PTR r9;
    ULONG_PTR r10;
    ULONG_PTR r11;
    ULONG_PTR r12;
    ULONG_PTR r13;
    ULONG_PTR r14;
    ULONG_PTR r15;
#endif //_WIN64
    ULONG_PTR cip;
    ULONG_PTR eflags;
    unsigned short gs;
    unsigned short fs;
    unsigned short es;
    unsigned short ds;
    unsigned short cs;
    unsigned short ss;
    ULONG_PTR dr0;
    ULONG_PTR dr1;
    ULONG_PTR dr2;
    ULONG_PTR dr3;
    ULONG_PTR dr6;
    ULONG_PTR dr7;
    BYTE RegisterArea[80];
    x87FPU_t x87fpu;
    DWORD MxCsr;
#ifdef _WIN64
    XmmRegister_t XmmRegisters[16];
    YmmRegister_t YmmRegisters[16];
#else // x86
    XmmRegister_t XmmRegisters[8];
    YmmRegister_t YmmRegisters[8];
#endif
} TITAN_ENGINE_CONTEXT_t;

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
    SIZE_T BreakPointSize;
    BYTE OriginalByte[UE_MAX_BREAKPOINT_SIZE];
    int BreakPointType;
    int AdvancedBreakPointType;
    int MemoryBpxRestoreOnHit;
    ULONG_PTR ExecuteCallBack;
    DWORD OldProtect;
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
    MODE_DISABLED = 0, //00
    MODE_LOCAL = 1, //01
    MODE_GLOBAL = 2 //10
};

enum HWBP_TYPE
{
    TYPE_EXECUTE = 0, //00
    TYPE_WRITE = 1, //01
    TYPE_READWRITE = 3 //11
};

enum HWBP_SIZE
{
    SIZE_1 = 0, //00
    SIZE_2 = 1, //01
    SIZE_8 = 2, //10
    SIZE_4 = 3 //11
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
    ULONG_PTR chRipEvent;
    ULONG_PTR chDebugEvent;
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

typedef struct
{
    HANDLE hThread;
    DWORD dwThreadId;
    void* ThreadStartAddress;
    void* ThreadLocalBase;
    void* TebAddress;
    ULONG WaitTime;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
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

#define UE_HIDE_PEBONLY 0
#define UE_HIDE_BASIC 1

#define UE_PLUGIN_CALL_REASON_PREDEBUG 1
#define UE_PLUGIN_CALL_REASON_EXCEPTION 2
#define UE_PLUGIN_CALL_REASON_POSTDEBUG 3
#define UE_PLUGIN_CALL_REASON_UNHANDLEDEXCEPTION 4

#define UE_ENGINE_ALOW_MODULE_LOADING 1
#define UE_ENGINE_AUTOFIX_FORWARDERS 2
#define UE_ENGINE_PASS_ALL_EXCEPTIONS 3
#define UE_ENGINE_NO_CONSOLE_WINDOW 4
#define UE_ENGINE_BACKUP_FOR_CRITICAL_FUNCTIONS 5
#define UE_ENGINE_CALL_PLUGIN_CALLBACK 6
#define UE_ENGINE_RESET_CUSTOM_HANDLER 7
#define UE_ENGINE_CALL_PLUGIN_DEBUG_CALLBACK 8
#define UE_ENGINE_SET_DEBUG_PRIVILEGE 9
#define UE_ENGINE_SAFE_ATTACH 10
#define UE_ENGINE_MEMBP_ALT 11
#define UE_ENGINE_DISABLE_ASLR 12
#define UE_ENGINE_SAFE_STEP 13

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
#define UE_DLLCHARACTERISTICS 25
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
#define UE_CH_SYSTEMBREAKPOINT 23
#define UE_CH_UNHANDLEDEXCEPTION 24
#define UE_CH_RIPEVENT 25
#define UE_CH_DEBUGEVENT 26

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
#define UE_x87_r0 43
#define UE_x87_r1 44
#define UE_x87_r2 45
#define UE_x87_r3 46
#define UE_x87_r4 47
#define UE_x87_r5 48
#define UE_x87_r6 49
#define UE_x87_r7 50
#define UE_X87_STATUSWORD 51
#define UE_X87_CONTROLWORD 52
#define UE_X87_TAGWORD 53
#define UE_MXCSR 54
#define UE_MMX0 55
#define UE_MMX1 56
#define UE_MMX2 57
#define UE_MMX3 58
#define UE_MMX4 59
#define UE_MMX5 60
#define UE_MMX6 61
#define UE_MMX7 62
#define UE_XMM0 63
#define UE_XMM1 64
#define UE_XMM2 65
#define UE_XMM3 66
#define UE_XMM4 67
#define UE_XMM5 68
#define UE_XMM6 69
#define UE_XMM7 70
#define UE_XMM8 71
#define UE_XMM9 72
#define UE_XMM10 73
#define UE_XMM11 74
#define UE_XMM12 75
#define UE_XMM13 76
#define UE_XMM14 77
#define UE_XMM15 78
#define UE_x87_ST0 79
#define UE_x87_ST1 80
#define UE_x87_ST2 81
#define UE_x87_ST3 82
#define UE_x87_ST4 83
#define UE_x87_ST5 84
#define UE_x87_ST6 85
#define UE_x87_ST7 86
#define UE_YMM0 87
#define UE_YMM1 88
#define UE_YMM2 89
#define UE_YMM3 90
#define UE_YMM4 91
#define UE_YMM5 92
#define UE_YMM6 93
#define UE_YMM7 94
#define UE_YMM8 95
#define UE_YMM9 96
#define UE_YMM10 97
#define UE_YMM11 98
#define UE_YMM12 99
#define UE_YMM13 100
#define UE_YMM14 101
#define UE_YMM15 102

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

#ifdef _WIN64
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
#define UE_FIELD_FIXABLE_NON_CRITICAL 5
#define UE_FIELD_FIXABLE_CRITICAL 6
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



///////////////////////////////////////////////////////////////////////////////////////
//Evolution of Process Environment Block (PEB) http://blog.rewolf.pl/blog/?p=573
//March 2, 2013 / ReWolf posted in programming, reverse engineering, source code, x64 /

template <class T>
struct LIST_ENTRY_T
{
    T Flink;
    T Blink;
};

template <class T>
struct UNICODE_STRING_T
{
    union
    {
        struct
        {
            WORD Length;
            WORD MaximumLength;
        };
        T dummy;
    };
    T _Buffer;
};

template <class T, class NGF, int A>
struct _PEB_T
{
    union
    {
        struct
        {
            BYTE InheritedAddressSpace;
            BYTE ReadImageFileExecOptions;
            BYTE BeingDebugged;
            BYTE _SYSTEM_DEPENDENT_01;
        };
        T dummy01;
    };
    T Mutant;
    T ImageBaseAddress;
    T Ldr;
    T ProcessParameters;
    T SubSystemData;
    T ProcessHeap;
    T FastPebLock;
    T _SYSTEM_DEPENDENT_02;
    T _SYSTEM_DEPENDENT_03;
    T _SYSTEM_DEPENDENT_04;
    union
    {
        T KernelCallbackTable;
        T UserSharedInfoPtr;
    };
    DWORD SystemReserved;
    DWORD _SYSTEM_DEPENDENT_05;
    T _SYSTEM_DEPENDENT_06;
    T TlsExpansionCounter;
    T TlsBitmap;
    DWORD TlsBitmapBits[2];
    T ReadOnlySharedMemoryBase;
    T _SYSTEM_DEPENDENT_07;
    T ReadOnlyStaticServerData;
    T AnsiCodePageData;
    T OemCodePageData;
    T UnicodeCaseTableData;
    DWORD NumberOfProcessors;
    union
    {
        DWORD NtGlobalFlag;
        NGF dummy02;
    };
    LARGE_INTEGER CriticalSectionTimeout;
    T HeapSegmentReserve;
    T HeapSegmentCommit;
    T HeapDeCommitTotalFreeThreshold;
    T HeapDeCommitFreeBlockThreshold;
    DWORD NumberOfHeaps;
    DWORD MaximumNumberOfHeaps;
    T ProcessHeaps;

    //FULL PEB not needed
    T GdiSharedHandleTable;
    T ProcessStarterHelper;
    DWORD GdiDCAttributeList;
    T LoaderLock;
    DWORD OSMajorVersion;
    DWORD OSMinorVersion;
    WORD OSBuildNumber;
    WORD OSCSDVersion;
    DWORD OSPlatformId;
    DWORD ImageSubsystem;
    DWORD ImageSubsystemMajorVersion;
    T ImageSubsystemMinorVersion;
    union
    {
        T ImageProcessAffinityMask;
        T ActiveProcessAffinityMask;
    };
    T GdiHandleBuffer[A];
    T PostProcessInitRoutine;
    T TlsExpansionBitmap;
    DWORD TlsExpansionBitmapBits[32];
    T SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    T pShimData;
    T AppCompatInfo;
    UNICODE_STRING_T<T> CSDVersion;
    T ActivationContextData;
    T ProcessAssemblyStorageMap;
    T SystemDefaultActivationContextData;
    T SystemAssemblyStorageMap;
    T MinimumStackCommit;
};

typedef _PEB_T<DWORD, DWORD64, 34> PEB32;
typedef _PEB_T<DWORD64, DWORD, 30> PEB64;

#ifdef _WIN64
typedef PEB64 PEB_CURRENT;
#else
typedef PEB32 PEB_CURRENT;
#endif

//GetThreadContext:
// - The handle must have THREAD_GET_CONTEXT access to the thread.
// - WOW64: The handle must also have THREAD_QUERY_INFORMATION access.
//SetThreadContext:
// - The handle must have the THREAD_SET_CONTEXT access right to the thread.
//SuspendThread/ResumeThread:
// - The handle must have the THREAD_SUSPEND_RESUME access right.
#define THREAD_GETSETSUSPEND (THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION)

#pragma pack(pop)
