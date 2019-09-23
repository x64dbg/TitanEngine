# -*- coding: utf-8 -*-
import sys
from ctypes import *
from ctypes.wintypes import *

_WIN64 = sys.maxsize > 0x7fffffff
LONGLONG = c_longlong
ULONGLONG = c_ulonglong
DWORD64 = c_ulonglong
ULONG_PTR = POINTER(ULONG)
SIZE_T = ULONG_PTR
LPDWORD = POINTER(DWORD)
PULONG_PTR = POINTER(ULONG_PTR)
PBYTE = POINTER(BYTE)
LPBYTE = POINTER(BYTE)
DWORD_PTR = POINTER(DWORD)
LPHANDLE = POINTER(HANDLE)
PVOID = c_void_p
LPTHREAD_START_ROUTINE = c_void_p

TE = windll.LoadLibrary("TitanEngine.dll")

# Global.Constant.Structure.Declaration:
# Engine.External:
UE_STRUCT_PE32STRUCT = 1
UE_STRUCT_PE64STRUCT = 2
UE_STRUCT_PESTRUCT = 3
UE_STRUCT_IMPORTENUMDATA = 4
UE_STRUCT_THREAD_ITEM_DATA = 5
UE_STRUCT_LIBRARY_ITEM_DATA = 6
UE_STRUCT_LIBRARY_ITEM_DATAW = 7
UE_STRUCT_PROCESS_ITEM_DATA = 8
UE_STRUCT_HANDLERARRAY = 9
UE_STRUCT_PLUGININFORMATION = 10
UE_STRUCT_HOOK_ENTRY = 11
UE_STRUCT_FILE_STATUS_INFO = 12
UE_STRUCT_FILE_FIX_INFO = 13
UE_STRUCT_X87FPUREGISTER = 14
UE_STRUCT_X87FPU = 15
UE_STRUCT_TITAN_ENGINE_CONTEXT = 16

UE_ACCESS_READ = 0
UE_ACCESS_WRITE = 1
UE_ACCESS_ALL = 2

UE_HIDE_PEBONLY = 0
UE_HIDE_BASIC = 1

UE_PLUGIN_CALL_REASON_PREDEBUG = 1
UE_PLUGIN_CALL_REASON_EXCEPTION = 2
UE_PLUGIN_CALL_REASON_POSTDEBUG = 3
UE_PLUGIN_CALL_REASON_UNHANDLEDEXCEPTION = 4

TEE_HOOK_NRM_JUMP = 1
TEE_HOOK_NRM_CALL = 3
TEE_HOOK_IAT = 5

UE_ENGINE_ALOW_MODULE_LOADING = 1
UE_ENGINE_AUTOFIX_FORWARDERS = 2
UE_ENGINE_PASS_ALL_EXCEPTIONS = 3
UE_ENGINE_NO_CONSOLE_WINDOW = 4
UE_ENGINE_BACKUP_FOR_CRITICAL_FUNCTIONS = 5
UE_ENGINE_CALL_PLUGIN_CALLBACK = 6
UE_ENGINE_RESET_CUSTOM_HANDLER = 7
UE_ENGINE_CALL_PLUGIN_DEBUG_CALLBACK = 8
UE_ENGINE_SET_DEBUG_PRIVILEGE = 9
UE_ENGINE_SAFE_ATTACH = 10

UE_OPTION_REMOVEALL = 1
UE_OPTION_DISABLEALL = 2
UE_OPTION_REMOVEALLDISABLED = 3
UE_OPTION_REMOVEALLENABLED = 4

UE_STATIC_DECRYPTOR_XOR = 1
UE_STATIC_DECRYPTOR_SUB = 2
UE_STATIC_DECRYPTOR_ADD = 3

UE_STATIC_DECRYPTOR_FOREWARD = 1
UE_STATIC_DECRYPTOR_BACKWARD = 2

UE_STATIC_KEY_SIZE_1 = 1
UE_STATIC_KEY_SIZE_2 = 2
UE_STATIC_KEY_SIZE_4 = 4
UE_STATIC_KEY_SIZE_8 = 8

UE_STATIC_APLIB = 1
UE_STATIC_APLIB_DEPACK = 2
UE_STATIC_LZMA = 3

UE_STATIC_HASH_MD5 = 1
UE_STATIC_HASH_SHA1 = 2
UE_STATIC_HASH_CRC32 = 3

UE_RESOURCE_LANGUAGE_ANY = -1

UE_PE_OFFSET = 0
UE_IMAGEBASE = 1
UE_OEP = 2
UE_SIZEOFIMAGE = 3
UE_SIZEOFHEADERS = 4
UE_SIZEOFOPTIONALHEADER = 5
UE_SECTIONALIGNMENT = 6
UE_IMPORTTABLEADDRESS = 7
UE_IMPORTTABLESIZE = 8
UE_RESOURCETABLEADDRESS = 9
UE_RESOURCETABLESIZE = 10
UE_EXPORTTABLEADDRESS = 11
UE_EXPORTTABLESIZE = 12
UE_TLSTABLEADDRESS = 13
UE_TLSTABLESIZE = 14
UE_RELOCATIONTABLEADDRESS = 15
UE_RELOCATIONTABLESIZE = 16
UE_TIMEDATESTAMP = 17
UE_SECTIONNUMBER = 18
UE_CHECKSUM = 19
UE_SUBSYSTEM = 20
UE_CHARACTERISTICS = 21
UE_NUMBEROFRVAANDSIZES = 22
UE_BASEOFCODE = 23
UE_BASEOFDATA = 24
UE_DLLCHARACTERISTICS = 25
# leaving some enum space here for future additions
UE_SECTIONNAME = 40
UE_SECTIONVIRTUALOFFSET = 41
UE_SECTIONVIRTUALSIZE = 42
UE_SECTIONRAWOFFSET = 43
UE_SECTIONRAWSIZE = 44
UE_SECTIONFLAGS = 45

UE_VANOTFOUND = -2

UE_CH_BREAKPOINT = 1
UE_CH_SINGLESTEP = 2
UE_CH_ACCESSVIOLATION = 3
UE_CH_ILLEGALINSTRUCTION = 4
UE_CH_NONCONTINUABLEEXCEPTION = 5
UE_CH_ARRAYBOUNDSEXCEPTION = 6
UE_CH_FLOATDENORMALOPERAND = 7
UE_CH_FLOATDEVIDEBYZERO = 8
UE_CH_INTEGERDEVIDEBYZERO = 9
UE_CH_INTEGEROVERFLOW = 10
UE_CH_PRIVILEGEDINSTRUCTION = 11
UE_CH_PAGEGUARD = 12
UE_CH_EVERYTHINGELSE = 13
UE_CH_CREATETHREAD = 14
UE_CH_EXITTHREAD = 15
UE_CH_CREATEPROCESS = 16
UE_CH_EXITPROCESS = 17
UE_CH_LOADDLL = 18
UE_CH_UNLOADDLL = 19
UE_CH_OUTPUTDEBUGSTRING = 20
UE_CH_AFTEREXCEPTIONPROCESSING = 21
UE_CH_SYSTEMBREAKPOINT = 23
UE_CH_UNHANDLEDEXCEPTION = 24
UE_CH_RIPEVENT = 25
UE_CH_DEBUGEVENT = 26

UE_OPTION_HANDLER_RETURN_HANDLECOUNT = 1
UE_OPTION_HANDLER_RETURN_ACCESS = 2
UE_OPTION_HANDLER_RETURN_FLAGS = 3
UE_OPTION_HANDLER_RETURN_TYPENAME = 4

UE_BREAKPOINT_INT3 = 1
UE_BREAKPOINT_LONG_INT3 = 2
UE_BREAKPOINT_UD2 = 3

UE_BPXREMOVED = 0
UE_BPXACTIVE = 1
UE_BPXINACTIVE = 2

UE_BREAKPOINT = 0
UE_SINGLESHOOT = 1
UE_HARDWARE = 2
UE_MEMORY = 3
UE_MEMORY_READ = 4
UE_MEMORY_WRITE = 5
UE_MEMORY_EXECUTE = 6
UE_BREAKPOINT_TYPE_INT3 = 0x10000000
UE_BREAKPOINT_TYPE_LONG_INT3 = 0x20000000
UE_BREAKPOINT_TYPE_UD2 = 0x30000000

UE_HARDWARE_EXECUTE = 4
UE_HARDWARE_WRITE = 5
UE_HARDWARE_READWRITE = 6

UE_HARDWARE_SIZE_1 = 7
UE_HARDWARE_SIZE_2 = 8
UE_HARDWARE_SIZE_4 = 9
UE_HARDWARE_SIZE_8 = 10

UE_ON_LIB_LOAD = 1
UE_ON_LIB_UNLOAD = 2
UE_ON_LIB_ALL = 3

UE_APISTART = 0
UE_APIEND = 1

UE_PLATFORM_x86 = 1
UE_PLATFORM_x64 = 2
UE_PLATFORM_ALL = 3

UE_FUNCTION_STDCALL = 1
UE_FUNCTION_CCALL = 2
UE_FUNCTION_FASTCALL = 3
UE_FUNCTION_STDCALL_RET = 4
UE_FUNCTION_CCALL_RET = 5
UE_FUNCTION_FASTCALL_RET = 6
UE_FUNCTION_STDCALL_CALL = 7
UE_FUNCTION_CCALL_CALL = 8
UE_FUNCTION_FASTCALL_CALL = 9
UE_PARAMETER_BYTE = 0
UE_PARAMETER_WORD = 1
UE_PARAMETER_DWORD = 2
UE_PARAMETER_QWORD = 3
UE_PARAMETER_PTR_BYTE = 4
UE_PARAMETER_PTR_WORD = 5
UE_PARAMETER_PTR_DWORD = 6
UE_PARAMETER_PTR_QWORD = 7
UE_PARAMETER_STRING = 8
UE_PARAMETER_UNICODE = 9

UE_EAX = 1
UE_EBX = 2
UE_ECX = 3
UE_EDX = 4
UE_EDI = 5
UE_ESI = 6
UE_EBP = 7
UE_ESP = 8
UE_EIP = 9
UE_EFLAGS = 10
UE_DR0 = 11
UE_DR1 = 12
UE_DR2 = 13
UE_DR3 = 14
UE_DR6 = 15
UE_DR7 = 16
UE_RAX = 17
UE_RBX = 18
UE_RCX = 19
UE_RDX = 20
UE_RDI = 21
UE_RSI = 22
UE_RBP = 23
UE_RSP = 24
UE_RIP = 25
UE_RFLAGS = 26
UE_R8 = 27
UE_R9 = 28
UE_R10 = 29
UE_R11 = 30
UE_R12 = 31
UE_R13 = 32
UE_R14 = 33
UE_R15 = 34
UE_CIP = 35
UE_CSP = 36

if _WIN64:
    UE_CFLAGS = UE_RFLAGS
else:
    UE_CFLAGS = UE_EFLAGS

UE_SEG_GS = 37
UE_SEG_FS = 38
UE_SEG_ES = 39
UE_SEG_DS = 40
UE_SEG_CS = 41
UE_SEG_SS = 42
UE_x87_r0 = 43
UE_x87_r1 = 44
UE_x87_r2 = 45
UE_x87_r3 = 46
UE_x87_r4 = 47
UE_x87_r5 = 48
UE_x87_r6 = 49
UE_x87_r7 = 50
UE_X87_STATUSWORD = 51
UE_X87_CONTROLWORD = 52
UE_X87_TAGWORD = 53
UE_MXCSR = 54
UE_MMX0 = 55
UE_MMX1 = 56
UE_MMX2 = 57
UE_MMX3 = 58
UE_MMX4 = 59
UE_MMX5 = 60
UE_MMX6 = 61
UE_MMX7 = 62
UE_XMM0 = 63
UE_XMM1 = 64
UE_XMM2 = 65
UE_XMM3 = 66
UE_XMM4 = 67
UE_XMM5 = 68
UE_XMM6 = 69
UE_XMM7 = 70
UE_XMM8 = 71
UE_XMM9 = 72
UE_XMM10 = 73
UE_XMM11 = 74
UE_XMM12 = 75
UE_XMM13 = 76
UE_XMM14 = 77
UE_XMM15 = 78
UE_x87_ST0 = 79
UE_x87_ST1 = 80
UE_x87_ST2 = 81
UE_x87_ST3 = 82
UE_x87_ST4 = 83
UE_x87_ST5 = 84
UE_x87_ST6 = 85
UE_x87_ST7 = 86
UE_YMM0 = 87
UE_YMM1 = 88
UE_YMM2 = 89
UE_YMM3 = 90
UE_YMM4 = 91
UE_YMM5 = 92
UE_YMM6 = 93
UE_YMM7 = 94
UE_YMM8 = 95
UE_YMM9 = 96
UE_YMM10 = 97
UE_YMM11 = 98
UE_YMM12 = 99
UE_YMM13 = 100
UE_YMM14 = 101
UE_YMM15 = 102

CONTEXT_EXTENDED_REGISTERS = 0


class PE32Struct(Structure):
    _pack_ = 1
    _fields_ = [
        ("PE32Offset", DWORD),
        ("ImageBase", DWORD),
        ("OriginalEntryPoint", DWORD),
        ("NtSizeOfImage", DWORD),
        ("NtSizeOfHeaders", DWORD),
        ("SizeOfOptionalHeaders", WORD),
        ("FileAlignment", DWORD),
        ("SectionAligment", DWORD),
        ("ImportTableAddress", DWORD),
        ("ImportTableSize", DWORD),
        ("ResourceTableAddress", DWORD),
        ("ResourceTableSize", DWORD),
        ("ExportTableAddress", DWORD),
        ("ExportTableSize", DWORD),
        ("TLSTableAddress", DWORD),
        ("TLSTableSize", DWORD),
        ("RelocationTableAddress", DWORD),
        ("RelocationTableSize", DWORD),
        ("TimeDateStamp", DWORD),
        ("SectionNumber", WORD),
        ("CheckSum", DWORD),
        ("SubSystem", WORD),
        ("Characteristics", WORD),
        ("NumberOfRvaAndSizes", DWORD)
    ]

class PE64Struct(Structure):
    _pack_ = 1
    _fields_ = [
        ("PE64Offset", DWORD),
        ("ImageBase", DWORD64),
        ("OriginalEntryPoint", DWORD),
        ("NtSizeOfImage", DWORD),
        ("NtSizeOfHeaders", DWORD),
        ("SizeOfOptionalHeaders", WORD),
        ("FileAlignment", DWORD),
        ("SectionAligment", DWORD),
        ("ImportTableAddress", DWORD),
        ("ImportTableSize", DWORD),
        ("ResourceTableAddress", DWORD),
        ("ResourceTableSize", DWORD),
        ("ExportTableAddress", DWORD),
        ("ExportTableSize", DWORD),
        ("TLSTableAddress", DWORD),
        ("TLSTableSize", DWORD),
        ("RelocationTableAddress", DWORD),
        ("RelocationTableSize", DWORD),
        ("TimeDateStamp", DWORD),
        ("SectionNumber", WORD),
        ("CheckSum", DWORD),
        ("SubSystem", WORD),
        ("Characteristics", WORD),
        ("NumberOfRvaAndSizes", DWORD)
    ]

if _WIN64:
    PEStruct = PE64Struct
else:
    PEStruct = PE32Struct

class ImportEnumData(Structure):
    _pack_ = 1
    _fields_ = [
        ("NewDll", c_bool),
        ("NumberOfImports", c_int),
        ("ImageBase", ULONG_PTR),
        ("BaseImportThunk", ULONG_PTR),
        ("ImportThunk", ULONG_PTR),
        ("APIName", c_char_p),
        ("DLLName", c_char_p)
    ]

class THREAD_ITEM_DATA(Structure):
    _pack_ = 1
    _fields_ = [
        ("hThread", HANDLE),
        ("dwThreadId", DWORD),
        ("ThreadStartAddress", c_void_p),
        ("ThreadLocalBase", c_void_p),
        ("TebAddress", c_void_p),
        ("WaitTime", ULONG),
        ("Priority", LONG),
        ("BasePriority", LONG),
        ("ContextSwitches", ULONG),
        ("ThreadState", ULONG),
        ("WaitReason", ULONG)
    ]

class LIBRARY_ITEM_DATA(Structure):
    _pack_ = 1
    _fields_ = [
        ("hFile", HANDLE),
        ("BaseOfDll", c_void_p),
        ("hFileMapping", HANDLE),
        ("hFileMappingView", c_void_p),
        ("szLibraryPath", c_char * MAX_PATH),
        ("szLibraryName", c_char * MAX_PATH)
    ]

class LIBRARY_ITEM_DATAW(Structure):
    _pack_ = 1
    _fields_ = [
        ("hFile", HANDLE),
        ("BaseOfDll", c_void_p),
        ("hFileMapping", HANDLE),
        ("hFileMappingView", c_void_p),
        ("szLibraryPath", c_wchar * MAX_PATH),
        ("szLibraryName", c_wchar * MAX_PATH)
    ]

class PROCESS_ITEM_DATA(Structure):
    _pack_ = 1
    _fields_ = [
        ("hProcess", HANDLE),
        ("dwProcessId", DWORD),
        ("hThread", HANDLE),
        ("dwThreadId", DWORD),
        ("hFile", HANDLE),
        ("BaseOfImage", c_void_p),
        ("ThreadStartAddress", c_void_p),
        ("ThreadLocalBase", c_void_p)
    ]

class HandlerArray(Structure):
    _pack_ = 1
    _fields_ = [
        ("ProcessId", ULONG),
        ("hHandle", HANDLE)
    ]

class PluginInformation(Structure):
    _pack_ = 1
    _fields_ = [
        ("PluginName", c_char * 64),
        ("PluginMajorVersion", DWORD),
        ("PluginMinorVersion", DWORD),
        ("PluginBaseAddress", HMODULE),
        ("TitanDebuggingCallBack", c_void_p),
        ("TitanRegisterPlugin", c_void_p),
        ("TitanReleasePlugin", c_void_p),
        ("TitanResetPlugin", c_void_p),
        ("PluginDisabled", c_bool)
    ]

TEE_MAXIMUM_HOOK_SIZE = 14
TEE_MAXIMUM_HOOK_RELOCS = 7

if _WIN64:
    TEE_MAXIMUM_HOOK_INSERT_SIZE = 14
else:
    TEE_MAXIMUM_HOOK_INSERT_SIZE = 5

class HOOK_ENTRY(Structure):
    _pack_ = 1
    _fields_ = [
        ("IATHook", c_bool),
        ("HookType", BYTE),
        ("HookSize", DWORD),
        ("HookAddress", c_void_p),
        ("RedirectionAddress", c_void_p),
        ("HookBytes", BYTE * TEE_MAXIMUM_HOOK_SIZE),
        ("OriginalBytes", BYTE * TEE_MAXIMUM_HOOK_SIZE),
        ("IATHookModuleBase", c_void_p),
        ("IATHookNameHash", DWORD),
        ("HookIsEnabled", c_bool),
        ("HookIsRemote", c_bool),
        ("PatchedEntry", c_void_p),
        ("RelocationInfo", DWORD * TEE_MAXIMUM_HOOK_RELOCS),
        ("RelocationCount", c_int)
    ]

UE_DEPTH_SURFACE = 0
UE_DEPTH_DEEP = 1

UE_UNPACKER_CONDITION_SEARCH_FROM_EP = 1

UE_UNPACKER_CONDITION_LOADLIBRARY = 1
UE_UNPACKER_CONDITION_GETPROCADDRESS = 2
UE_UNPACKER_CONDITION_ENTRYPOINTBREAK = 3
UE_UNPACKER_CONDITION_RELOCSNAPSHOT1 = 4
UE_UNPACKER_CONDITION_RELOCSNAPSHOT2 = 5

UE_FIELD_OK = 0
UE_FIELD_BROKEN_NON_FIXABLE = 1
UE_FIELD_BROKEN_NON_CRITICAL = 2
UE_FIELD_BROKEN_FIXABLE_FOR_STATIC_USE = 3
UE_FIELD_BROKEN_BUT_CAN_BE_EMULATED = 4
UE_FIELD_FIXABLE_NON_CRITICAL = 5
UE_FILED_FIXABLE_CRITICAL = 6
UE_FIELD_NOT_PRESET = 7
UE_FIELD_NOT_PRESET_WARNING = 8

UE_RESULT_FILE_OK = 10
UE_RESULT_FILE_INVALID_BUT_FIXABLE = 11
UE_RESULT_FILE_INVALID_AND_NON_FIXABLE = 12
UE_RESULT_FILE_INVALID_FORMAT = 13

class FILE_STATUS_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ("OveralEvaluation", BYTE),
        ("EvaluationTerminatedByException", c_bool),
        ("FileIs64Bit", c_bool),
        ("FileIsDLL", c_bool),
        ("FileIsConsole", c_bool),
        ("MissingDependencies", c_bool),
        ("MissingDeclaredAPIs", c_bool),
        ("SignatureMZ", BYTE),
        ("SignaturePE", BYTE),
        ("EntryPoint", BYTE),
        ("ImageBase", BYTE),
        ("SizeOfImage", BYTE),
        ("FileAlignment", BYTE),
        ("SectionAlignment", BYTE),
        ("ExportTable", BYTE),
        ("RelocationTable", BYTE),
        ("ImportTable", BYTE),
        ("ImportTableSection", BYTE),
        ("ImportTableData", BYTE),
        ("IATTable", BYTE),
        ("TLSTable", BYTE),
        ("LoadConfigTable", BYTE),
        ("BoundImportTable", BYTE),
        ("COMHeaderTable", BYTE),
        ("ResourceTable", BYTE),
        ("ResourceData", BYTE),
        ("SectionTable", BYTE)
    ]

class FILE_FIX_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ("OveralEvaluation", BYTE),
        ("FixingTerminatedByException", c_bool),
        ("FileFixPerformed", c_bool),
        ("StrippedRelocation", c_bool),
        ("DontFixRelocations", c_bool),
        ("OriginalRelocationTableAddress", DWORD),
        ("OriginalRelocationTableSize", DWORD),
        ("StrippedExports", c_bool),
        ("DontFixExports", c_bool),
        ("OriginalExportTableAddress", DWORD),
        ("OriginalExportTableSize", DWORD),
        ("StrippedResources", c_bool),
        ("DontFixResources", c_bool),
        ("OriginalResourceTableAddress", DWORD),
        ("OriginalResourceTableSize", DWORD),
        ("StrippedTLS", c_bool),
        ("DontFixTLS", c_bool),
        ("OriginalTLSTableAddress", DWORD),
        ("OriginalTLSTableSize", DWORD),
        ("StrippedLoadConfig", c_bool),
        ("DontFixLoadConfig", c_bool),
        ("OriginalLoadConfigTableAddress", DWORD),
        ("OriginalLoadConfigTableSize", DWORD),
        ("StrippedBoundImports", c_bool),
        ("DontFixBoundImports", c_bool),
        ("OriginalBoundImportTableAddress", DWORD),
        ("OriginalBoundImportTableSize", DWORD),
        ("StrippedIAT", c_bool),
        ("DontFixIAT", c_bool),
        ("OriginalImportAddressTableAddress", DWORD),
        ("OriginalImportAddressTableSize", DWORD),
        ("StrippedCOM", c_bool),
        ("DontFixCOM", c_bool),
        ("OriginalCOMTableAddress", DWORD),
        ("OriginalCOMTableSize", DWORD)
    ]

class XmmRegister_t(Structure):
    _pack_ = 1
    _fields_ = [
        ("Low", ULONGLONG),
        ("High", LONGLONG)
    ]

class YmmRegister_t(Structure):
    _pack_ = 1
    _fields_ = [
        ("Low", XmmRegister_t),
        ("High", XmmRegister_t)
    ]

class x87FPURegister_t(Structure):
    _pack_ = 1
    _fields_ = [
        ("data", BYTE * 10),
        ("st_value", c_int),
        ("tag", c_int)
    ]

class x87FPU_t(Structure):
    _pack_ = 1
    _fields_ = [
        ("ControlWord", WORD),
        ("StatusWord", WORD),
        ("TagWord", WORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", DWORD),
        ("DataOffset", DWORD),
        ("DataSelector", DWORD),
        ("Cr0NpxState", DWORD)
    ]

class TITAN_ENGINE_CONTEXT32_t(Structure):
    _pack_ = 1
    _fields_ = [
        ("cax", ULONG_PTR),
        ("ccx", ULONG_PTR),
        ("cdx", ULONG_PTR),
        ("cbx", ULONG_PTR),
        ("csp", ULONG_PTR),
        ("cbp", ULONG_PTR),
        ("csi", ULONG_PTR),
        ("cdi", ULONG_PTR),
        ("cip", ULONG_PTR),
        ("eflags", ULONG_PTR),
        ("gs", c_ushort),
        ("fs", c_ushort),
        ("es", c_ushort),
        ("ds", c_ushort),
        ("cs", c_ushort),
        ("ss", c_ushort),
        ("dr0", ULONG_PTR),
        ("dr1", ULONG_PTR),
        ("dr2", ULONG_PTR),
        ("dr3", ULONG_PTR),
        ("dr4", ULONG_PTR),
        ("dr5", ULONG_PTR),
        ("dr6", ULONG_PTR),
        ("dr7", ULONG_PTR),
        ("RegisterArea", BYTE * 80),
        ("x87fpu", x87FPU_t),
        ("MxCsr", DWORD),
        ("XmmRegisters", XmmRegister_t * 8),
        ("YmmRegisters", YmmRegister_t * 8)
    ]

class TITAN_ENGINE_CONTEXT64_t(Structure):
    _pack_ = 1
    _fields_ = [
        ("cax", ULONG_PTR),
        ("ccx", ULONG_PTR),
        ("cdx", ULONG_PTR),
        ("cbx", ULONG_PTR),
        ("csp", ULONG_PTR),
        ("cbp", ULONG_PTR),
        ("csi", ULONG_PTR),
        ("cdi", ULONG_PTR),
        ("r8", ULONG_PTR),
        ("r9", ULONG_PTR),
        ("r10", ULONG_PTR),
        ("r11", ULONG_PTR),
        ("r12", ULONG_PTR),
        ("r13", ULONG_PTR),
        ("r14", ULONG_PTR),
        ("r15", ULONG_PTR),
        ("cip", ULONG_PTR),
        ("eflags", ULONG_PTR),
        ("gs", c_ushort),
        ("fs", c_ushort),
        ("es", c_ushort),
        ("ds", c_ushort),
        ("cs", c_ushort),
        ("ss", c_ushort),
        ("dr0", ULONG_PTR),
        ("dr1", ULONG_PTR),
        ("dr2", ULONG_PTR),
        ("dr3", ULONG_PTR),
        ("dr4", ULONG_PTR),
        ("dr5", ULONG_PTR),
        ("dr6", ULONG_PTR),
        ("dr7", ULONG_PTR),
        ("RegisterArea", BYTE * 80),
        ("x87fpu", x87FPU_t),
        ("MxCsr", DWORD),
        ("XmmRegisters", XmmRegister_t * 16),
        ("YmmRegisters", YmmRegister_t * 16)
    ]

if _WIN64:
    TITAN_ENGINE_CONTEXT_t = TITAN_ENGINE_CONTEXT64_t
else:
    TITAN_ENGINE_CONTEXT_t = TITAN_ENGINE_CONTEXT32_t

class PROCESS_INFORMATION(Structure):
    _pack_ = 1
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD)
    ]

EXCEPTION_MAXIMUM_PARAMETERS = 15

class EXCEPTION_RECORD(Structure):
    _pack_ = 1

EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", DWORD),
    ("ExceptionFlags", DWORD),
    ("ExceptionRecord", POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress", PVOID),
    ("NumberParameters", DWORD),
    ("ExceptionInformation", ULONG_PTR * EXCEPTION_MAXIMUM_PARAMETERS)
]

class EXCEPTION_DEBUG_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD),
        ("dwFirstChance", DWORD)
    ]

class CREATE_THREAD_DEBUG_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ("hThread", HANDLE),
        ("lpThreadLocalBase", LPVOID),
        ("lpStartAddress", LPTHREAD_START_ROUTINE)
    ]

class CREATE_PROCESS_DEBUG_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ("hFile", HANDLE),
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("lpBaseOfImage", LPVOID),
        ("dwDebugInfoFileOffset", DWORD),
        ("nDebugInfoSize", DWORD),
        ("lpThreadLocalBase", LPVOID),
        ("lpStartAddress", LPTHREAD_START_ROUTINE),
        ("lpImageName", LPVOID),
        ("fUnicode", WORD)
    ]

class EXIT_THREAD_DEBUG_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ("dwExitCode", DWORD)
    ]

class EXIT_PROCESS_DEBUG_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ("dwExitCode", DWORD)
    ]

class LOAD_DLL_DEBUG_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ("hFile", HANDLE),
        ("lpBaseOfDll", LPVOID),
        ("dwDebugInfoFileOffset", DWORD),
        ("nDebugInfoSize", DWORD),
        ("lpImageName", LPVOID),
        ("fUnicode", WORD)
    ]

class UNLOAD_DLL_DEBUG_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ("lpBaseOfDll", LPVOID)
    ]

class OUTPUT_DEBUG_STRING_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ("lpDebugStringData", LPSTR),
        ("fUnicode", WORD),
        ("nDebugStringLength", WORD)
    ]

class RIP_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ("dwError", DWORD),
        ("dwType", DWORD)
    ]

class _U(Union):
    _pack_ = 1
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
        ("CreateThread", CREATE_THREAD_DEBUG_INFO),
        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
        ("ExitThread", EXIT_THREAD_DEBUG_INFO),
        ("ExitProcess", EXIT_PROCESS_DEBUG_INFO),
        ("LoadDll", LOAD_DLL_DEBUG_INFO),
        ("UnloadDll", UNLOAD_DLL_DEBUG_INFO),
        ("DebugString", OUTPUT_DEBUG_STRING_INFO),
        ("RipInfo", RIP_INFO)
    ]

class DEBUG_EVENT(Structure):
    _pack_ = 1
    _anonymous_ = ("u",)
    _fields_ = [
        ("dwDebugEventCode", DWORD),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
        ("u", _U)
    ]

class STARTUPINFOW(Structure):
    _pack_ = 1
    _fields_ = [
        ("cb", DWORD),
        ("lpReserved", LPWSTR),
        ("lpDesktop", LPWSTR),
        ("lpTitle", LPWSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", LPBYTE),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE)
    ]

fImportEnum = WINFUNCTYPE(None, POINTER(ImportEnumData))
fImportFix = WINFUNCTYPE(c_void_p, c_void_p)
fResourceEnum = WINFUNCTYPE(None, c_wchar_p, DWORD, c_wchar_p, DWORD, DWORD, DWORD, DWORD)
fThreadEnum = WINFUNCTYPE(None, POINTER(THREAD_ITEM_DATA))
fThreadExit = WINFUNCTYPE(None, POINTER(EXIT_THREAD_DEBUG_INFO))
fBreakPoint = WINFUNCTYPE(None)
fCustomHandler = WINFUNCTYPE(None, c_void_p)
fLibraryBreakPoint = WINFUNCTYPE(None, POINTER(LOAD_DLL_DEBUG_INFO))
fLibraryEnum = WINFUNCTYPE(None, POINTER(LIBRARY_ITEM_DATA))
fLibraryEnumW = WINFUNCTYPE(None, POINTER(LIBRARY_ITEM_DATAW))
fHookEnum = WINFUNCTYPE(c_bool, POINTER(HOOK_ENTRY), c_void_p, POINTER(LIBRARY_ITEM_DATA), DWORD)
fProcessWithLibraryEnum = WINFUNCTYPE(None, DWORD, HMODULE)
fStaticDecrypt = WINFUNCTYPE(c_bool, c_void_p, c_long)
fInitializeDbg = WINFUNCTYPE(None, c_char_p, c_ubyte, c_ubyte)

# Global.Function.Declaration:
# TitanEngine.Dumper.functions:
DumpProcess = WINFUNCTYPE(c_bool, HANDLE, LPVOID, c_char_p, ULONG_PTR)(TE.DumpProcess)
DumpProcessW = WINFUNCTYPE(c_bool, HANDLE, LPVOID, c_wchar_p, ULONG_PTR)(TE.DumpProcessW)
DumpProcessEx = WINFUNCTYPE(c_bool, DWORD, LPVOID, c_char_p, ULONG_PTR)(TE.DumpProcessEx)
DumpProcessExW = WINFUNCTYPE(c_bool, DWORD, LPVOID, c_wchar_p, ULONG_PTR)(TE.DumpProcessExW)
DumpMemory = WINFUNCTYPE(c_bool, HANDLE, LPVOID, ULONG_PTR, c_char_p)(TE.DumpMemory)
DumpMemoryW = WINFUNCTYPE(c_bool, HANDLE, LPVOID, ULONG_PTR, c_wchar_p)(TE.DumpMemoryW)
DumpMemoryEx = WINFUNCTYPE(c_bool, DWORD, LPVOID, ULONG_PTR, c_char_p)(TE.DumpMemoryEx)
DumpMemoryExW = WINFUNCTYPE(c_bool, DWORD, LPVOID, ULONG_PTR, c_wchar_p)(TE.DumpMemoryExW)
DumpRegions = WINFUNCTYPE(c_bool, HANDLE, c_char_p, c_bool)(TE.DumpRegions)
DumpRegionsW = WINFUNCTYPE(c_bool, HANDLE, c_wchar_p, c_bool)(TE.DumpRegionsW)
DumpRegionsEx = WINFUNCTYPE(c_bool, DWORD, c_char_p, c_bool)(TE.DumpRegionsEx)
DumpRegionsExW = WINFUNCTYPE(c_bool, DWORD, c_wchar_p, c_bool)(TE.DumpRegionsExW)
DumpModule = WINFUNCTYPE(c_bool, HANDLE, LPVOID, c_char_p)(TE.DumpModule)
DumpModuleW = WINFUNCTYPE(c_bool, HANDLE, LPVOID, c_wchar_p)(TE.DumpModuleW)
DumpModuleEx = WINFUNCTYPE(c_bool, DWORD, LPVOID, c_char_p)(TE.DumpModuleEx)
DumpModuleExW = WINFUNCTYPE(c_bool, DWORD, LPVOID, c_wchar_p)(TE.DumpModuleExW)
PastePEHeader = WINFUNCTYPE(c_bool, HANDLE, LPVOID, c_char_p)(TE.PastePEHeader)
PastePEHeaderW = WINFUNCTYPE(c_bool, HANDLE, LPVOID, c_wchar_p)(TE.PastePEHeaderW)
ExtractSection = WINFUNCTYPE(c_bool, c_char_p, c_char_p, DWORD)(TE.ExtractSection)
ExtractSectionW = WINFUNCTYPE(c_bool, c_wchar_p, c_wchar_p, DWORD)(TE.ExtractSectionW)
ResortFileSections = WINFUNCTYPE(c_bool, c_char_p)(TE.ResortFileSections)
ResortFileSectionsW = WINFUNCTYPE(c_bool, c_wchar_p)(TE.ResortFileSectionsW)
FindOverlay = WINFUNCTYPE(c_bool, c_char_p, LPDWORD, LPDWORD)(TE.FindOverlay)
FindOverlayW = WINFUNCTYPE(c_bool, c_wchar_p, LPDWORD, LPDWORD)(TE.FindOverlayW)
ExtractOverlay = WINFUNCTYPE(c_bool, c_char_p, c_char_p)(TE.ExtractOverlay)
ExtractOverlayW = WINFUNCTYPE(c_bool, c_wchar_p, c_wchar_p)(TE.ExtractOverlayW)
AddOverlay = WINFUNCTYPE(c_bool, c_char_p, c_char_p)(TE.AddOverlay)
AddOverlayW = WINFUNCTYPE(c_bool, c_wchar_p, c_wchar_p)(TE.AddOverlayW)
CopyOverlay = WINFUNCTYPE(c_bool, c_char_p, c_char_p)(TE.CopyOverlay)
CopyOverlayW = WINFUNCTYPE(c_bool, c_wchar_p, c_wchar_p)(TE.CopyOverlayW)
RemoveOverlay = WINFUNCTYPE(c_bool, c_char_p)(TE.RemoveOverlay)
RemoveOverlayW = WINFUNCTYPE(c_bool, c_wchar_p)(TE.RemoveOverlayW)
MakeAllSectionsRWE = WINFUNCTYPE(c_bool, c_char_p)(TE.MakeAllSectionsRWE)
MakeAllSectionsRWEW = WINFUNCTYPE(c_bool, c_wchar_p)(TE.MakeAllSectionsRWEW)
AddNewSectionEx = WINFUNCTYPE(c_long, c_char_p, c_char_p, DWORD, DWORD, LPVOID, DWORD)(TE.AddNewSectionEx)
AddNewSectionExW = WINFUNCTYPE(c_long, c_wchar_p, c_char_p, DWORD, DWORD, LPVOID, DWORD)(TE.AddNewSectionExW)
AddNewSection = WINFUNCTYPE(c_long, c_char_p, c_char_p, DWORD)(TE.AddNewSection)
AddNewSectionW = WINFUNCTYPE(c_long, c_wchar_p, c_char_p, DWORD)(TE.AddNewSectionW)
ResizeLastSection = WINFUNCTYPE(c_bool, c_char_p, DWORD, c_bool)(TE.ResizeLastSection)
ResizeLastSectionW = WINFUNCTYPE(c_bool, c_wchar_p, DWORD, c_bool)(TE.ResizeLastSectionW)
SetSharedOverlay = WINFUNCTYPE(None, c_char_p)(TE.SetSharedOverlay)
SetSharedOverlayW = WINFUNCTYPE(None, c_wchar_p)(TE.SetSharedOverlayW)
GetSharedOverlay = WINFUNCTYPE(c_char_p)(TE.GetSharedOverlay)
GetSharedOverlayW = WINFUNCTYPE(c_wchar_p)(TE.GetSharedOverlayW)
DeleteLastSection = WINFUNCTYPE(c_bool, c_char_p)(TE.DeleteLastSection)
DeleteLastSectionW = WINFUNCTYPE(c_bool, c_wchar_p)(TE.DeleteLastSectionW)
DeleteLastSectionEx = WINFUNCTYPE(c_bool, c_char_p, DWORD)(TE.DeleteLastSectionEx)
DeleteLastSectionExW = WINFUNCTYPE(c_bool, c_wchar_p, DWORD)(TE.DeleteLastSectionExW)
GetPE32DataFromMappedFile = WINFUNCTYPE(c_void_p, ULONG_PTR, DWORD, DWORD)(TE.GetPE32DataFromMappedFile)
GetPE32DataFromMappedFile.restype = ULONG_PTR
GetPE32Data = WINFUNCTYPE(c_void_p, c_char_p, DWORD, DWORD)(TE.GetPE32Data)
GetPE32Data.restype = ULONG_PTR
GetPE32DataW = WINFUNCTYPE(c_void_p, c_wchar_p, DWORD, DWORD)(TE.GetPE32DataW)
GetPE32DataW.restype = ULONG_PTR
GetPE32DataFromMappedFileEx = WINFUNCTYPE(c_bool, ULONG_PTR, LPVOID)(TE.GetPE32DataFromMappedFileEx)
GetPE32DataEx = WINFUNCTYPE(c_bool, c_char_p, LPVOID)(TE.GetPE32DataEx)
GetPE32DataExW = WINFUNCTYPE(c_bool, c_wchar_p, LPVOID)(TE.GetPE32DataExW)
SetPE32DataForMappedFile = WINFUNCTYPE(c_bool, ULONG_PTR, DWORD, DWORD, ULONG_PTR)(TE.SetPE32DataForMappedFile)
SetPE32Data = WINFUNCTYPE(c_bool, c_char_p, DWORD, DWORD, ULONG_PTR)(TE.SetPE32Data)
SetPE32DataW = WINFUNCTYPE(c_bool, c_wchar_p, DWORD, DWORD, ULONG_PTR)(TE.SetPE32DataW)
SetPE32DataForMappedFileEx = WINFUNCTYPE(c_bool, ULONG_PTR, LPVOID)(TE.SetPE32DataForMappedFileEx)
SetPE32DataEx = WINFUNCTYPE(c_bool, c_char_p, LPVOID)(TE.SetPE32DataEx)
SetPE32DataExW = WINFUNCTYPE(c_bool, c_wchar_p, LPVOID)(TE.SetPE32DataExW)
GetPE32SectionNumberFromVA = WINFUNCTYPE(c_long, ULONG_PTR, ULONG_PTR)(TE.GetPE32SectionNumberFromVA)
ConvertVAtoFileOffset = WINFUNCTYPE(c_void_p, ULONG_PTR, ULONG_PTR, c_bool)(TE.ConvertVAtoFileOffset)
ConvertVAtoFileOffset.restype = ULONG_PTR
ConvertVAtoFileOffsetEx = WINFUNCTYPE(c_void_p, ULONG_PTR, DWORD, ULONG_PTR, ULONG_PTR, c_bool, c_bool)(TE.ConvertVAtoFileOffsetEx)
ConvertVAtoFileOffsetEx.restype = ULONG_PTR
ConvertFileOffsetToVA = WINFUNCTYPE(c_void_p, ULONG_PTR, ULONG_PTR, c_bool)(TE.ConvertFileOffsetToVA)
ConvertFileOffsetToVA.restype = ULONG_PTR
ConvertFileOffsetToVAEx = WINFUNCTYPE(c_void_p, ULONG_PTR, DWORD, ULONG_PTR, ULONG_PTR, c_bool)(TE.ConvertFileOffsetToVAEx)
ConvertFileOffsetToVAEx.restype = ULONG_PTR
MemoryReadSafe = WINFUNCTYPE(c_bool, HANDLE, LPVOID, LPVOID, SIZE_T, POINTER(SIZE_T))(TE.MemoryReadSafe)
MemoryWriteSafe = WINFUNCTYPE(c_bool, HANDLE, LPVOID, LPCVOID, SIZE_T, POINTER(SIZE_T))(TE.MemoryWriteSafe)

# TitanEngine.Realigner.functions:
FixHeaderCheckSum = WINFUNCTYPE(c_bool, c_char_p)(TE.FixHeaderCheckSum)
FixHeaderCheckSumW = WINFUNCTYPE(c_bool, c_wchar_p)(TE.FixHeaderCheckSumW)
RealignPE = WINFUNCTYPE(c_long, ULONG_PTR, DWORD, DWORD)(TE.RealignPE)
RealignPEEx = WINFUNCTYPE(c_long, c_char_p, DWORD, DWORD)(TE.RealignPEEx)
RealignPEExW = WINFUNCTYPE(c_long, c_wchar_p, DWORD, DWORD)(TE.RealignPEExW)
WipeSection = WINFUNCTYPE(c_bool, c_char_p, c_int, c_bool)(TE.WipeSection)
WipeSectionW = WINFUNCTYPE(c_bool, c_wchar_p, c_int, c_bool)(TE.WipeSectionW)
IsPE32FileValidEx = WINFUNCTYPE(c_bool, c_char_p, DWORD, LPVOID)(TE.IsPE32FileValidEx)
IsPE32FileValidExW = WINFUNCTYPE(c_bool, c_wchar_p, DWORD, LPVOID)(TE.IsPE32FileValidExW)
FixBrokenPE32FileEx = WINFUNCTYPE(c_bool, c_char_p, LPVOID, LPVOID)(TE.FixBrokenPE32FileEx)
FixBrokenPE32FileExW = WINFUNCTYPE(c_bool, c_wchar_p, LPVOID, LPVOID)(TE.FixBrokenPE32FileExW)
IsFileDLL = WINFUNCTYPE(c_bool, c_char_p, ULONG_PTR)(TE.IsFileDLL)
IsFileDLLW = WINFUNCTYPE(c_bool, c_wchar_p, ULONG_PTR)(TE.IsFileDLLW)

# TitanEngine.Hider.functions:
GetPEBLocation = WINFUNCTYPE(c_void_p, HANDLE)(TE.GetPEBLocation)
GetPEBLocation64 = WINFUNCTYPE(c_void_p, HANDLE)(TE.GetPEBLocation64)
GetTEBLocation = WINFUNCTYPE(c_void_p, HANDLE)(TE.GetTEBLocation)
GetTEBLocation64 = WINFUNCTYPE(c_void_p, HANDLE)(TE.GetTEBLocation64)
HideDebugger = WINFUNCTYPE(c_bool, HANDLE, DWORD)(TE.HideDebugger)
UnHideDebugger = WINFUNCTYPE(c_bool, HANDLE, DWORD)(TE.UnHideDebugger)

# TitanEngine.Relocater.functions:
RelocaterCleanup = WINFUNCTYPE(None)(TE.RelocaterCleanup)
RelocaterInit = WINFUNCTYPE(None, DWORD, ULONG_PTR, ULONG_PTR)(TE.RelocaterInit)
RelocaterAddNewRelocation = WINFUNCTYPE(None, HANDLE, ULONG_PTR, DWORD)(TE.RelocaterAddNewRelocation)
RelocaterEstimatedSize = WINFUNCTYPE(c_long)(TE.RelocaterEstimatedSize)
RelocaterExportRelocation = WINFUNCTYPE(c_bool, ULONG_PTR, DWORD, ULONG_PTR)(TE.RelocaterExportRelocation)
RelocaterExportRelocationEx = WINFUNCTYPE(c_bool, c_char_p, c_char_p)(TE.RelocaterExportRelocationEx)
RelocaterExportRelocationExW = WINFUNCTYPE(c_bool, c_wchar_p, c_char_p)(TE.RelocaterExportRelocationExW)
RelocaterGrabRelocationTable = WINFUNCTYPE(c_bool, HANDLE, ULONG_PTR, DWORD)(TE.RelocaterGrabRelocationTable)
RelocaterGrabRelocationTableEx = WINFUNCTYPE(c_bool, HANDLE, ULONG_PTR, ULONG_PTR, DWORD)(TE.RelocaterGrabRelocationTableEx)
RelocaterMakeSnapshot = WINFUNCTYPE(c_bool, HANDLE, c_char_p, LPVOID, ULONG_PTR)(TE.RelocaterMakeSnapshot)
RelocaterMakeSnapshotW = WINFUNCTYPE(c_bool, HANDLE, c_wchar_p, LPVOID, ULONG_PTR)(TE.RelocaterMakeSnapshotW)
RelocaterCompareTwoSnapshots = WINFUNCTYPE(c_bool, HANDLE, ULONG_PTR, ULONG_PTR, c_char_p, c_char_p, ULONG_PTR)(TE.RelocaterCompareTwoSnapshots)
RelocaterCompareTwoSnapshotsW = WINFUNCTYPE(c_bool, HANDLE, ULONG_PTR, ULONG_PTR, c_wchar_p, c_wchar_p, ULONG_PTR)(TE.RelocaterCompareTwoSnapshotsW)
RelocaterChangeFileBase = WINFUNCTYPE(c_bool, c_char_p, ULONG_PTR)(TE.RelocaterChangeFileBase)
RelocaterChangeFileBaseW = WINFUNCTYPE(c_bool, c_wchar_p, ULONG_PTR)(TE.RelocaterChangeFileBaseW)
RelocaterRelocateMemoryBlock = WINFUNCTYPE(c_bool, ULONG_PTR, ULONG_PTR, c_void_p, DWORD, ULONG_PTR, ULONG_PTR)(TE.RelocaterRelocateMemoryBlock)
RelocaterWipeRelocationTable = WINFUNCTYPE(c_bool, c_char_p)(TE.RelocaterWipeRelocationTable)
RelocaterWipeRelocationTableW = WINFUNCTYPE(c_bool, c_wchar_p)(TE.RelocaterWipeRelocationTableW)

# TitanEngine.Resourcer.functions:
ResourcerLoadFileForResourceUse = WINFUNCTYPE(c_void_p, c_char_p)(TE.ResourcerLoadFileForResourceUse)
ResourcerLoadFileForResourceUse.restype = ULONG_PTR
ResourcerLoadFileForResourceUseW = WINFUNCTYPE(c_void_p, c_wchar_p)(TE.ResourcerLoadFileForResourceUseW)
ResourcerLoadFileForResourceUseW.restype = ULONG_PTR
ResourcerFreeLoadedFile = WINFUNCTYPE(c_bool, LPVOID)(TE.ResourcerFreeLoadedFile)
ResourcerExtractResourceFromFileEx = WINFUNCTYPE(c_bool, HMODULE, c_char_p, c_char_p, c_char_p)(TE.ResourcerExtractResourceFromFileEx)
ResourcerExtractResourceFromFile = WINFUNCTYPE(c_bool, c_char_p, c_char_p, c_char_p, c_char_p)(TE.ResourcerExtractResourceFromFile)
ResourcerExtractResourceFromFileW = WINFUNCTYPE(c_bool, c_wchar_p, c_char_p, c_char_p, c_char_p)(TE.ResourcerExtractResourceFromFileW)
ResourcerFindResource = WINFUNCTYPE(c_bool, c_char_p, c_char_p, DWORD, c_char_p, DWORD, DWORD, PULONG_PTR, LPDWORD)(TE.ResourcerFindResource)
ResourcerFindResourceW = WINFUNCTYPE(c_bool, c_wchar_p, c_wchar_p, DWORD, c_wchar_p, DWORD, DWORD, PULONG_PTR, LPDWORD)(TE.ResourcerFindResourceW)
ResourcerFindResourceEx = WINFUNCTYPE(c_bool, ULONG_PTR, DWORD, c_wchar_p, DWORD, c_wchar_p, DWORD, DWORD, PULONG_PTR, LPDWORD)(TE.ResourcerFindResourceEx)
ResourcerEnumerateResource = WINFUNCTYPE(None, c_char_p, c_void_p)(TE.ResourcerEnumerateResource)
ResourcerEnumerateResourceW = WINFUNCTYPE(None, c_wchar_p, c_void_p)(TE.ResourcerEnumerateResourceW)
ResourcerEnumerateResourceEx = WINFUNCTYPE(None, ULONG_PTR, DWORD, c_void_p)(TE.ResourcerEnumerateResourceEx)

# TitanEngine.Threader.functions:
ThreaderImportRunningThreadData = WINFUNCTYPE(c_bool, DWORD)(TE.ThreaderImportRunningThreadData)
ThreaderGetThreadInfo = WINFUNCTYPE(c_void_p, HANDLE, DWORD)(TE.ThreaderGetThreadInfo)
ThreaderGetThreadInfo.restype = POINTER(THREAD_ITEM_DATA)
ThreaderEnumThreadInfo = WINFUNCTYPE(None, c_void_p)(TE.ThreaderEnumThreadInfo)
ThreaderPauseThread = WINFUNCTYPE(c_bool, HANDLE)(TE.ThreaderPauseThread)
ThreaderResumeThread = WINFUNCTYPE(c_bool, HANDLE)(TE.ThreaderResumeThread)
ThreaderTerminateThread = WINFUNCTYPE(c_bool, HANDLE, DWORD)(TE.ThreaderTerminateThread)
ThreaderPauseAllThreads = WINFUNCTYPE(c_bool, c_bool)(TE.ThreaderPauseAllThreads)
ThreaderResumeAllThreads = WINFUNCTYPE(c_bool, c_bool)(TE.ThreaderResumeAllThreads)
ThreaderPauseProcess = WINFUNCTYPE(c_bool)(TE.ThreaderPauseProcess)
ThreaderResumeProcess = WINFUNCTYPE(c_bool)(TE.ThreaderResumeProcess)
ThreaderCreateRemoteThread = WINFUNCTYPE(c_void_p, ULONG_PTR, c_bool, LPVOID, LPDWORD)(TE.ThreaderCreateRemoteThread)
ThreaderCreateRemoteThread.restype = ULONG_PTR
ThreaderInjectAndExecuteCode = WINFUNCTYPE(c_bool, LPVOID, DWORD, DWORD)(TE.ThreaderInjectAndExecuteCode)
ThreaderCreateRemoteThreadEx = WINFUNCTYPE(c_void_p, HANDLE, ULONG_PTR, c_bool, LPVOID, LPDWORD)(TE.ThreaderCreateRemoteThreadEx)
ThreaderCreateRemoteThreadEx.restype = ULONG_PTR
ThreaderInjectAndExecuteCodeEx = WINFUNCTYPE(c_bool, HANDLE, LPVOID, DWORD, DWORD)(TE.ThreaderInjectAndExecuteCodeEx)
ThreaderSetCallBackForNextExitThreadEvent = WINFUNCTYPE(None, LPVOID)(TE.ThreaderSetCallBackForNextExitThreadEvent)
ThreaderIsThreadStillRunning = WINFUNCTYPE(c_bool, HANDLE)(TE.ThreaderIsThreadStillRunning)
ThreaderIsThreadActive = WINFUNCTYPE(c_bool, HANDLE)(TE.ThreaderIsThreadActive)
ThreaderIsAnyThreadActive = WINFUNCTYPE(c_bool)(TE.ThreaderIsAnyThreadActive)
ThreaderExecuteOnlyInjectedThreads = WINFUNCTYPE(c_bool)(TE.ThreaderExecuteOnlyInjectedThreads)
ThreaderGetOpenHandleForThread = WINFUNCTYPE(c_void_p, DWORD)(TE.ThreaderGetOpenHandleForThread)
ThreaderGetOpenHandleForThread.restype = ULONG_PTR
ThreaderIsExceptionInMainThread = WINFUNCTYPE(c_bool)(TE.ThreaderIsExceptionInMainThread)

# TitanEngine.Debugger.functions:
StaticDisassembleEx = WINFUNCTYPE(c_void_p, ULONG_PTR, LPVOID)(TE.StaticDisassembleEx)
StaticDisassemble = WINFUNCTYPE(c_void_p, LPVOID)(TE.StaticDisassemble)
DisassembleEx = WINFUNCTYPE(c_void_p, HANDLE, LPVOID, c_bool)(TE.DisassembleEx)
Disassemble = WINFUNCTYPE(c_void_p, LPVOID)(TE.Disassemble)
StaticLengthDisassemble = WINFUNCTYPE(c_long, LPVOID)(TE.StaticLengthDisassemble)
LengthDisassembleEx = WINFUNCTYPE(c_long, HANDLE, LPVOID)(TE.LengthDisassembleEx)
LengthDisassemble = WINFUNCTYPE(c_long, LPVOID)(TE.LengthDisassemble)
InitDebug = WINFUNCTYPE(c_void_p, c_char_p, c_char_p, c_char_p)(TE.InitDebug)
InitDebug.restype = POINTER(PROCESS_INFORMATION)
InitDebugW = WINFUNCTYPE(c_void_p, c_wchar_p, c_wchar_p, c_wchar_p)(TE.InitDebugW)
InitDebugW.restype = POINTER(PROCESS_INFORMATION)
InitNativeDebug = WINFUNCTYPE(c_void_p, c_char_p, c_char_p, c_char_p)(TE.InitNativeDebug)
InitNativeDebug.restype = POINTER(PROCESS_INFORMATION)
InitNativeDebugW = WINFUNCTYPE(c_void_p, c_wchar_p, c_wchar_p, c_wchar_p)(TE.InitNativeDebugW)
InitNativeDebugW.restype = POINTER(PROCESS_INFORMATION)
InitDebugEx = WINFUNCTYPE(c_void_p, c_char_p, c_char_p, c_char_p, LPVOID)(TE.InitDebugEx)
InitDebugEx.restype = POINTER(PROCESS_INFORMATION)
InitDebugExW = WINFUNCTYPE(c_void_p, c_wchar_p, c_wchar_p, c_wchar_p, LPVOID)(TE.InitDebugExW)
InitDebugExW.restype = POINTER(PROCESS_INFORMATION)
InitDLLDebug = WINFUNCTYPE(c_void_p, c_char_p, c_bool, c_char_p, c_char_p, LPVOID)(TE.InitDLLDebug)
InitDLLDebug.restype = POINTER(PROCESS_INFORMATION)
InitDLLDebugW = WINFUNCTYPE(c_void_p, c_wchar_p, c_bool, c_wchar_p, c_wchar_p, LPVOID)(TE.InitDLLDebugW)
InitDLLDebugW.restype = POINTER(PROCESS_INFORMATION)
StopDebug = WINFUNCTYPE(c_bool)(TE.StopDebug)
SetBPXOptions = WINFUNCTYPE(None, c_long)(TE.SetBPXOptions)
IsBPXEnabled = WINFUNCTYPE(c_bool, ULONG_PTR)(TE.IsBPXEnabled)
EnableBPX = WINFUNCTYPE(c_bool, ULONG_PTR)(TE.EnableBPX)
DisableBPX = WINFUNCTYPE(c_bool, ULONG_PTR)(TE.DisableBPX)
SetBPX = WINFUNCTYPE(c_bool, ULONG_PTR, DWORD, LPVOID)(TE.SetBPX)
DeleteBPX = WINFUNCTYPE(c_bool, ULONG_PTR)(TE.DeleteBPX)
SafeDeleteBPX = WINFUNCTYPE(c_bool, ULONG_PTR)(TE.SafeDeleteBPX)
SetAPIBreakPoint = WINFUNCTYPE(c_bool, c_char_p, c_char_p, DWORD, DWORD, LPVOID)(TE.SetAPIBreakPoint)
DeleteAPIBreakPoint = WINFUNCTYPE(c_bool, c_char_p, c_char_p, DWORD)(TE.DeleteAPIBreakPoint)
SafeDeleteAPIBreakPoint = WINFUNCTYPE(c_bool, c_char_p, c_char_p, DWORD)(TE.SafeDeleteAPIBreakPoint)
SetMemoryBPX = WINFUNCTYPE(c_bool, ULONG_PTR, SIZE_T, LPVOID)(TE.SetMemoryBPX)
SetMemoryBPXEx = WINFUNCTYPE(c_bool, ULONG_PTR, SIZE_T, DWORD, c_bool, LPVOID)(TE.SetMemoryBPXEx)
RemoveMemoryBPX = WINFUNCTYPE(c_bool, ULONG_PTR, SIZE_T)(TE.RemoveMemoryBPX)
GetContextFPUDataEx = WINFUNCTYPE(c_bool, HANDLE, c_void_p)(TE.GetContextFPUDataEx)
Getx87FPURegisters = WINFUNCTYPE(None, x87FPURegister_t, POINTER(TITAN_ENGINE_CONTEXT_t))(TE.Getx87FPURegisters)
GetMMXRegisters = WINFUNCTYPE(None, c_ulonglong, POINTER(TITAN_ENGINE_CONTEXT_t))(TE.GetMMXRegisters)
GetFullContextDataEx = WINFUNCTYPE(c_bool, HANDLE, POINTER(TITAN_ENGINE_CONTEXT_t))(TE.GetFullContextDataEx)
SetFullContextDataEx = WINFUNCTYPE(c_bool, HANDLE, POINTER(TITAN_ENGINE_CONTEXT_t))(TE.SetFullContextDataEx)
GetContextDataEx = WINFUNCTYPE(c_void_p, HANDLE, DWORD)(TE.GetContextDataEx)
GetContextDataEx.restype = ULONG_PTR
GetContextData = WINFUNCTYPE(c_void_p, DWORD)(TE.GetContextData)
GetContextData.restype = ULONG_PTR
SetContextFPUDataEx = WINFUNCTYPE(c_bool, HANDLE, c_void_p)(TE.SetContextFPUDataEx)
SetContextDataEx = WINFUNCTYPE(c_bool, HANDLE, DWORD, ULONG_PTR)(TE.SetContextDataEx)
SetContextData = WINFUNCTYPE(c_bool, DWORD, ULONG_PTR)(TE.SetContextData)
GetAVXContext = WINFUNCTYPE(c_bool, HANDLE, POINTER(TITAN_ENGINE_CONTEXT_t))(TE.GetAVXContext)
SetAVXContext = WINFUNCTYPE(c_bool, HANDLE, POINTER(TITAN_ENGINE_CONTEXT_t))(TE.SetAVXContext)
ClearExceptionNumber = WINFUNCTYPE(None)(TE.ClearExceptionNumber)
CurrentExceptionNumber = WINFUNCTYPE(c_long)(TE.CurrentExceptionNumber)
MatchPatternEx = WINFUNCTYPE(c_bool, HANDLE, c_void_p, c_int, c_void_p, c_int, PBYTE)(TE.MatchPatternEx)
MatchPattern = WINFUNCTYPE(c_bool, c_void_p, c_int, c_void_p, c_int, PBYTE)(TE.MatchPattern)
FindEx = WINFUNCTYPE(c_void_p, HANDLE, LPVOID, DWORD, LPVOID, DWORD, LPBYTE)(TE.FindEx)
FindEx.restype = ULONG_PTR
FillEx = WINFUNCTYPE(c_bool, HANDLE, LPVOID, DWORD, PBYTE)(TE.FillEx)
Fill = WINFUNCTYPE(c_bool, LPVOID, DWORD, PBYTE)(TE.Fill)
PatchEx = WINFUNCTYPE(c_bool, HANDLE, LPVOID, DWORD, LPVOID, DWORD, c_bool, c_bool)(TE.PatchEx)
Patch = WINFUNCTYPE(c_bool, LPVOID, DWORD, LPVOID, DWORD, c_bool, c_bool)(TE.Patch)
ReplaceEx = WINFUNCTYPE(c_bool, HANDLE, LPVOID, DWORD, LPVOID, DWORD, DWORD, LPVOID, DWORD, PBYTE)(TE.ReplaceEx)
Replace = WINFUNCTYPE(c_bool, LPVOID, DWORD, LPVOID, DWORD, DWORD, LPVOID, DWORD, PBYTE)(TE.Replace)
GetDebugData = WINFUNCTYPE(c_void_p)(TE.GetDebugData)
GetDebugData.restype = POINTER(DEBUG_EVENT)
GetTerminationData = WINFUNCTYPE(c_void_p)(TE.GetTerminationData)
GetTerminationData.restype = POINTER(DEBUG_EVENT)
GetExitCode = WINFUNCTYPE(c_long)(TE.GetExitCode)
GetDebuggedDLLBaseAddress = WINFUNCTYPE(c_void_p)(TE.GetDebuggedDLLBaseAddress)
GetDebuggedDLLBaseAddress.restype = ULONG_PTR
GetDebuggedFileBaseAddress = WINFUNCTYPE(c_void_p)(TE.GetDebuggedFileBaseAddress)
GetDebuggedFileBaseAddress.restype = ULONG_PTR
GetRemoteString = WINFUNCTYPE(c_bool, HANDLE, LPVOID, LPVOID, c_int)(TE.GetRemoteString)
GetFunctionParameter = WINFUNCTYPE(c_void_p, HANDLE, DWORD, DWORD, DWORD)(TE.GetFunctionParameter)
GetFunctionParameter.restype = ULONG_PTR
GetJumpDestinationEx = WINFUNCTYPE(c_void_p, HANDLE, ULONG_PTR, c_bool)(TE.GetJumpDestinationEx)
GetJumpDestinationEx.restype = ULONG_PTR
GetJumpDestination = WINFUNCTYPE(c_void_p, HANDLE, ULONG_PTR)(TE.GetJumpDestination)
GetJumpDestination.restype = ULONG_PTR
IsJumpGoingToExecuteEx = WINFUNCTYPE(c_bool, HANDLE, HANDLE, ULONG_PTR, ULONG_PTR)(TE.IsJumpGoingToExecuteEx)
IsJumpGoingToExecute = WINFUNCTYPE(c_bool)(TE.IsJumpGoingToExecute)
SetCustomHandler = WINFUNCTYPE(None, DWORD, LPVOID)(TE.SetCustomHandler)
ForceClose = WINFUNCTYPE(None)(TE.ForceClose)
StepInto = WINFUNCTYPE(None, LPVOID)(TE.StepInto)
StepOver = WINFUNCTYPE(None, LPVOID)(TE.StepOver)
StepOut = WINFUNCTYPE(None, LPVOID, c_bool)(TE.StepOut)
SingleStep = WINFUNCTYPE(None, DWORD, LPVOID)(TE.SingleStep)
GetUnusedHardwareBreakPointRegister = WINFUNCTYPE(c_bool, LPDWORD)(TE.GetUnusedHardwareBreakPointRegister)
SetHardwareBreakPointEx = WINFUNCTYPE(c_bool, HANDLE, ULONG_PTR, DWORD, DWORD, DWORD, LPVOID, LPDWORD)(TE.SetHardwareBreakPointEx)
SetHardwareBreakPoint = WINFUNCTYPE(c_bool, ULONG_PTR, DWORD, DWORD, DWORD, LPVOID)(TE.SetHardwareBreakPoint)
DeleteHardwareBreakPoint = WINFUNCTYPE(c_bool, DWORD)(TE.DeleteHardwareBreakPoint)
RemoveAllBreakPoints = WINFUNCTYPE(c_bool, DWORD)(TE.RemoveAllBreakPoints)
TitanGetProcessInformation = WINFUNCTYPE(c_void_p)(TE.TitanGetProcessInformation)
TitanGetProcessInformation.restype = POINTER(PROCESS_INFORMATION)
TitanGetStartupInformation = WINFUNCTYPE(c_void_p)(TE.TitanGetStartupInformation)
TitanGetStartupInformation.restype = POINTER(STARTUPINFOW)
DebugLoop = WINFUNCTYPE(None)(TE.DebugLoop)
SetDebugLoopTimeOut = WINFUNCTYPE(None, DWORD)(TE.SetDebugLoopTimeOut)
SetNextDbgContinueStatus = WINFUNCTYPE(None, DWORD)(TE.SetNextDbgContinueStatus)
AttachDebugger = WINFUNCTYPE(c_bool, DWORD, c_bool, LPVOID, LPVOID)(TE.AttachDebugger)
DetachDebugger = WINFUNCTYPE(c_bool, DWORD)(TE.DetachDebugger)
DetachDebuggerEx = WINFUNCTYPE(c_bool, DWORD)(TE.DetachDebuggerEx)
DebugLoopEx = WINFUNCTYPE(None, DWORD)(TE.DebugLoopEx)
AutoDebugEx = WINFUNCTYPE(None, c_char_p, c_bool, c_char_p, c_char_p, DWORD, LPVOID)(TE.AutoDebugEx)
AutoDebugExW = WINFUNCTYPE(None, c_wchar_p, c_bool, c_wchar_p, c_wchar_p, DWORD, LPVOID)(TE.AutoDebugExW)
IsFileBeingDebugged = WINFUNCTYPE(c_bool)(TE.IsFileBeingDebugged)
SetErrorModel = WINFUNCTYPE(None, c_bool)(TE.SetErrorModel)

# TitanEngine.FindOEP.functions:
FindOEPInit = WINFUNCTYPE(None)(TE.FindOEPInit)
FindOEPGenerically = WINFUNCTYPE(c_bool, c_char_p, LPVOID, LPVOID)(TE.FindOEPGenerically)
FindOEPGenericallyW = WINFUNCTYPE(c_bool, c_wchar_p, LPVOID, LPVOID)(TE.FindOEPGenericallyW)

# TitanEngine.Importer.functions:
ImporterAddNewDll = WINFUNCTYPE(None, c_char_p, ULONG_PTR)(TE.ImporterAddNewDll)
ImporterAddNewAPI = WINFUNCTYPE(None, c_char_p, ULONG_PTR)(TE.ImporterAddNewAPI)
ImporterAddNewOrdinalAPI = WINFUNCTYPE(None, ULONG_PTR, ULONG_PTR)(TE.ImporterAddNewOrdinalAPI)
ImporterGetAddedDllCount = WINFUNCTYPE(c_long)(TE.ImporterGetAddedDllCount)
ImporterGetAddedAPICount = WINFUNCTYPE(c_long)(TE.ImporterGetAddedAPICount)
ImporterExportIAT = WINFUNCTYPE(c_bool, ULONG_PTR, ULONG_PTR, HANDLE)(TE.ImporterExportIAT)
ImporterEstimatedSize = WINFUNCTYPE(c_long)(TE.ImporterEstimatedSize)
ImporterExportIATEx = WINFUNCTYPE(c_bool, c_char_p, c_char_p, c_char_p)(TE.ImporterExportIATEx)
ImporterExportIATExW = WINFUNCTYPE(c_bool, c_wchar_p, c_wchar_p, c_wchar_p)(TE.ImporterExportIATExW)
ImporterFindAPIWriteLocation = WINFUNCTYPE(c_void_p, c_char_p)(TE.ImporterFindAPIWriteLocation)
ImporterFindAPIWriteLocation.restype = ULONG_PTR
ImporterFindOrdinalAPIWriteLocation = WINFUNCTYPE(c_void_p, ULONG_PTR)(TE.ImporterFindOrdinalAPIWriteLocation)
ImporterFindOrdinalAPIWriteLocation.restype = ULONG_PTR
ImporterFindAPIByWriteLocation = WINFUNCTYPE(c_void_p, ULONG_PTR)(TE.ImporterFindAPIByWriteLocation)
ImporterFindAPIByWriteLocation.restype = ULONG_PTR
ImporterFindDLLByWriteLocation = WINFUNCTYPE(c_void_p, ULONG_PTR)(TE.ImporterFindDLLByWriteLocation)
ImporterFindDLLByWriteLocation.restype = ULONG_PTR
ImporterGetDLLName = WINFUNCTYPE(c_void_p, ULONG_PTR)(TE.ImporterGetDLLName)
ImporterGetDLLNameW = WINFUNCTYPE(c_void_p, ULONG_PTR)(TE.ImporterGetDLLNameW)
ImporterGetAPIName = WINFUNCTYPE(c_void_p, ULONG_PTR)(TE.ImporterGetAPIName)
ImporterGetAPIOrdinalNumber = WINFUNCTYPE(c_void_p, ULONG_PTR)(TE.ImporterGetAPIOrdinalNumber)
ImporterGetAPIOrdinalNumber.restype = ULONG_PTR
ImporterGetAPINameEx = WINFUNCTYPE(c_void_p, ULONG_PTR, ULONG_PTR)(TE.ImporterGetAPINameEx)
ImporterGetRemoteAPIAddress = WINFUNCTYPE(c_void_p, HANDLE, ULONG_PTR)(TE.ImporterGetRemoteAPIAddress)
ImporterGetRemoteAPIAddress.restype = ULONG_PTR
ImporterGetRemoteAPIAddressEx = WINFUNCTYPE(c_void_p, c_char_p, c_char_p)(TE.ImporterGetRemoteAPIAddressEx)
ImporterGetRemoteAPIAddressEx.restype = ULONG_PTR
ImporterGetLocalAPIAddress = WINFUNCTYPE(c_void_p, HANDLE, ULONG_PTR)(TE.ImporterGetLocalAPIAddress)
ImporterGetLocalAPIAddress.restype = ULONG_PTR
ImporterGetDLLNameFromDebugee = WINFUNCTYPE(c_void_p, HANDLE, ULONG_PTR)(TE.ImporterGetDLLNameFromDebugee)
ImporterGetDLLNameFromDebugeeW = WINFUNCTYPE(c_void_p, HANDLE, ULONG_PTR)(TE.ImporterGetDLLNameFromDebugeeW)
ImporterGetAPINameFromDebugee = WINFUNCTYPE(c_void_p, HANDLE, ULONG_PTR)(TE.ImporterGetAPINameFromDebugee)
ImporterGetAPIOrdinalNumberFromDebugee = WINFUNCTYPE(c_void_p, HANDLE, ULONG_PTR)(TE.ImporterGetAPIOrdinalNumberFromDebugee)
ImporterGetAPIOrdinalNumberFromDebugee.restype = ULONG_PTR
ImporterGetDLLIndexEx = WINFUNCTYPE(c_long, ULONG_PTR, ULONG_PTR)(TE.ImporterGetDLLIndexEx)
ImporterGetDLLIndex = WINFUNCTYPE(c_long, HANDLE, ULONG_PTR, ULONG_PTR)(TE.ImporterGetDLLIndex)
ImporterGetRemoteDLLBase = WINFUNCTYPE(c_void_p, HANDLE, HMODULE)(TE.ImporterGetRemoteDLLBase)
ImporterGetRemoteDLLBase.restype = ULONG_PTR
ImporterGetRemoteDLLBaseEx = WINFUNCTYPE(c_void_p, HANDLE, c_char_p)(TE.ImporterGetRemoteDLLBaseEx)
ImporterGetRemoteDLLBaseEx.restype = ULONG_PTR
ImporterGetRemoteDLLBaseExW = WINFUNCTYPE(c_void_p, HANDLE, c_wchar_p)(TE.ImporterGetRemoteDLLBaseExW)
ImporterIsForwardedAPI = WINFUNCTYPE(c_bool, HANDLE, ULONG_PTR)(TE.ImporterIsForwardedAPI)
ImporterGetForwardedAPIName = WINFUNCTYPE(c_void_p, HANDLE, ULONG_PTR)(TE.ImporterGetForwardedAPIName)
ImporterGetForwardedDLLName = WINFUNCTYPE(c_void_p, HANDLE, ULONG_PTR)(TE.ImporterGetForwardedDLLName)
ImporterGetForwardedDLLIndex = WINFUNCTYPE(c_long, HANDLE, ULONG_PTR, ULONG_PTR)(TE.ImporterGetForwardedDLLIndex)
ImporterGetForwardedAPIOrdinalNumber = WINFUNCTYPE(c_void_p, HANDLE, ULONG_PTR)(TE.ImporterGetForwardedAPIOrdinalNumber)
ImporterGetForwardedAPIOrdinalNumber.restype = ULONG_PTR
ImporterGetNearestAPIAddress = WINFUNCTYPE(c_void_p, HANDLE, ULONG_PTR)(TE.ImporterGetNearestAPIAddress)
ImporterGetNearestAPIAddress.restype = ULONG_PTR
ImporterGetNearestAPIName = WINFUNCTYPE(c_void_p, HANDLE, ULONG_PTR)(TE.ImporterGetNearestAPIName)
ImporterCopyOriginalIAT = WINFUNCTYPE(c_bool, c_char_p, c_char_p)(TE.ImporterCopyOriginalIAT)
ImporterCopyOriginalIATW = WINFUNCTYPE(c_bool, c_wchar_p, c_wchar_p)(TE.ImporterCopyOriginalIATW)
ImporterLoadImportTable = WINFUNCTYPE(c_bool, c_char_p)(TE.ImporterLoadImportTable)
ImporterLoadImportTableW = WINFUNCTYPE(c_bool, c_wchar_p)(TE.ImporterLoadImportTableW)
ImporterMoveOriginalIAT = WINFUNCTYPE(c_bool, c_char_p, c_char_p, c_char_p)(TE.ImporterMoveOriginalIAT)
ImporterMoveOriginalIATW = WINFUNCTYPE(c_bool, c_wchar_p, c_wchar_p, c_char_p)(TE.ImporterMoveOriginalIATW)
ImporterAutoSearchIAT = WINFUNCTYPE(None, DWORD, c_char_p, ULONG_PTR, LPVOID, LPVOID)(TE.ImporterAutoSearchIAT)
ImporterAutoSearchIATW = WINFUNCTYPE(None, DWORD, c_wchar_p, ULONG_PTR, LPVOID, LPVOID)(TE.ImporterAutoSearchIATW)
ImporterAutoSearchIATEx = WINFUNCTYPE(None, DWORD, ULONG_PTR, ULONG_PTR, LPVOID, LPVOID)(TE.ImporterAutoSearchIATEx)
ImporterEnumAddedData = WINFUNCTYPE(None, LPVOID)(TE.ImporterEnumAddedData)
ImporterAutoFixIATEx = WINFUNCTYPE(c_long, DWORD, c_char_p, c_char_p, c_bool, c_bool, ULONG_PTR, ULONG_PTR, ULONG_PTR, c_bool, c_bool, LPVOID)(TE.ImporterAutoFixIATEx)
ImporterAutoFixIATExW = WINFUNCTYPE(c_long, DWORD, c_wchar_p, c_wchar_p, c_bool, c_bool, ULONG_PTR, ULONG_PTR, ULONG_PTR, c_bool, c_bool, LPVOID)(TE.ImporterAutoFixIATExW)
ImporterAutoFixIAT = WINFUNCTYPE(c_long, DWORD, c_char_p, ULONG_PTR)(TE.ImporterAutoFixIAT)
ImporterAutoFixIATW = WINFUNCTYPE(c_long, DWORD, c_wchar_p, ULONG_PTR)(TE.ImporterAutoFixIATW)
ImporterDeleteAPI = WINFUNCTYPE(c_bool, DWORD_PTR)(TE.ImporterDeleteAPI)

# Global.Engine.Hook.functions:
HooksSafeTransitionEx = WINFUNCTYPE(c_bool, LPVOID, c_int, c_bool)(TE.HooksSafeTransitionEx)
HooksSafeTransition = WINFUNCTYPE(c_bool, LPVOID, c_bool)(TE.HooksSafeTransition)
HooksIsAddressRedirected = WINFUNCTYPE(c_bool, LPVOID)(TE.HooksIsAddressRedirected)
HooksGetTrampolineAddress = WINFUNCTYPE(c_void_p, LPVOID)(TE.HooksGetTrampolineAddress)
HooksGetHookEntryDetails = WINFUNCTYPE(c_void_p, LPVOID)(TE.HooksGetHookEntryDetails)
HooksGetHookEntryDetails.restype = POINTER(HOOK_ENTRY)
HooksInsertNewRedirection = WINFUNCTYPE(c_bool, LPVOID, LPVOID, c_int)(TE.HooksInsertNewRedirection)
HooksInsertNewIATRedirectionEx = WINFUNCTYPE(c_bool, ULONG_PTR, ULONG_PTR, c_char_p, LPVOID)(TE.HooksInsertNewIATRedirectionEx)
HooksInsertNewIATRedirection = WINFUNCTYPE(c_bool, c_char_p, c_char_p, LPVOID)(TE.HooksInsertNewIATRedirection)
HooksRemoveRedirection = WINFUNCTYPE(c_bool, LPVOID, c_bool)(TE.HooksRemoveRedirection)
HooksRemoveRedirectionsForModule = WINFUNCTYPE(c_bool, HMODULE)(TE.HooksRemoveRedirectionsForModule)
HooksRemoveIATRedirection = WINFUNCTYPE(c_bool, c_char_p, c_char_p, c_bool)(TE.HooksRemoveIATRedirection)
HooksDisableRedirection = WINFUNCTYPE(c_bool, LPVOID, c_bool)(TE.HooksDisableRedirection)
HooksDisableRedirectionsForModule = WINFUNCTYPE(c_bool, HMODULE)(TE.HooksDisableRedirectionsForModule)
HooksDisableIATRedirection = WINFUNCTYPE(c_bool, c_char_p, c_char_p, c_bool)(TE.HooksDisableIATRedirection)
HooksEnableRedirection = WINFUNCTYPE(c_bool, LPVOID, c_bool)(TE.HooksEnableRedirection)
HooksEnableRedirectionsForModule = WINFUNCTYPE(c_bool, HMODULE)(TE.HooksEnableRedirectionsForModule)
HooksEnableIATRedirection = WINFUNCTYPE(c_bool, c_char_p, c_char_p, c_bool)(TE.HooksEnableIATRedirection)
HooksScanModuleMemory = WINFUNCTYPE(None, HMODULE, LPVOID)(TE.HooksScanModuleMemory)
HooksScanEntireProcessMemory = WINFUNCTYPE(None, LPVOID)(TE.HooksScanEntireProcessMemory)
HooksScanEntireProcessMemoryEx = WINFUNCTYPE(None)(TE.HooksScanEntireProcessMemoryEx)

# TitanEngine.Tracer.functions:
TracerInit = WINFUNCTYPE(None)(TE.TracerInit)
TracerLevel1 = WINFUNCTYPE(c_void_p, HANDLE, ULONG_PTR)(TE.TracerLevel1)
TracerLevel1.restype = ULONG_PTR
HashTracerLevel1 = WINFUNCTYPE(c_void_p, HANDLE, ULONG_PTR, DWORD)(TE.HashTracerLevel1)
HashTracerLevel1.restype = ULONG_PTR
TracerDetectRedirection = WINFUNCTYPE(c_long, HANDLE, ULONG_PTR)(TE.TracerDetectRedirection)
TracerFixKnownRedirection = WINFUNCTYPE(c_void_p, HANDLE, ULONG_PTR, DWORD)(TE.TracerFixKnownRedirection)
TracerFixKnownRedirection.restype = ULONG_PTR
TracerFixRedirectionViaImpRecPlugin = WINFUNCTYPE(c_long, HANDLE, c_char_p, ULONG_PTR)(TE.TracerFixRedirectionViaImpRecPlugin)

# TitanEngine.Exporter.functions:
ExporterCleanup = WINFUNCTYPE(None)(TE.ExporterCleanup)
ExporterSetImageBase = WINFUNCTYPE(None, ULONG_PTR)(TE.ExporterSetImageBase)
ExporterInit = WINFUNCTYPE(None, DWORD, ULONG_PTR, DWORD, c_char_p)(TE.ExporterInit)
ExporterAddNewExport = WINFUNCTYPE(c_bool, c_char_p, DWORD)(TE.ExporterAddNewExport)
ExporterAddNewOrdinalExport = WINFUNCTYPE(c_bool, DWORD, DWORD)(TE.ExporterAddNewOrdinalExport)
ExporterGetAddedExportCount = WINFUNCTYPE(c_long)(TE.ExporterGetAddedExportCount)
ExporterEstimatedSize = WINFUNCTYPE(c_long)(TE.ExporterEstimatedSize)
ExporterBuildExportTable = WINFUNCTYPE(c_bool, ULONG_PTR, ULONG_PTR)(TE.ExporterBuildExportTable)
ExporterBuildExportTableEx = WINFUNCTYPE(c_bool, c_char_p, c_char_p)(TE.ExporterBuildExportTableEx)
ExporterBuildExportTableExW = WINFUNCTYPE(c_bool, c_wchar_p, c_char_p)(TE.ExporterBuildExportTableExW)
ExporterLoadExportTable = WINFUNCTYPE(c_bool, c_char_p)(TE.ExporterLoadExportTable)
ExporterLoadExportTableW = WINFUNCTYPE(c_bool, c_wchar_p)(TE.ExporterLoadExportTableW)

# TitanEngine.Librarian.functions:
LibrarianSetBreakPoint = WINFUNCTYPE(c_bool, c_char_p, DWORD, c_bool, LPVOID)(TE.LibrarianSetBreakPoint)
LibrarianRemoveBreakPoint = WINFUNCTYPE(c_bool, c_char_p, DWORD)(TE.LibrarianRemoveBreakPoint)
LibrarianGetLibraryInfo = WINFUNCTYPE(c_void_p, c_char_p)(TE.LibrarianGetLibraryInfo)
LibrarianGetLibraryInfo.restype = POINTER(LIBRARY_ITEM_DATA)
LibrarianGetLibraryInfoW = WINFUNCTYPE(c_void_p, c_wchar_p)(TE.LibrarianGetLibraryInfoW)
LibrarianGetLibraryInfoW.restype = POINTER(LIBRARY_ITEM_DATAW)
LibrarianGetLibraryInfoEx = WINFUNCTYPE(c_void_p, c_void_p)(TE.LibrarianGetLibraryInfoEx)
LibrarianGetLibraryInfoEx.restype = POINTER(LIBRARY_ITEM_DATA)
LibrarianGetLibraryInfoExW = WINFUNCTYPE(c_void_p, c_void_p)(TE.LibrarianGetLibraryInfoExW)
LibrarianGetLibraryInfoExW.restype = POINTER(LIBRARY_ITEM_DATAW)
LibrarianEnumLibraryInfo = WINFUNCTYPE(None, c_void_p)(TE.LibrarianEnumLibraryInfo)
LibrarianEnumLibraryInfoW = WINFUNCTYPE(None, c_void_p)(TE.LibrarianEnumLibraryInfoW)

# TitanEngine.Process.functions:
GetActiveProcessId = WINFUNCTYPE(c_long, c_char_p)(TE.GetActiveProcessId)
GetActiveProcessIdW = WINFUNCTYPE(c_long, c_wchar_p)(TE.GetActiveProcessIdW)
EnumProcessesWithLibrary = WINFUNCTYPE(None, c_char_p, c_void_p)(TE.EnumProcessesWithLibrary)
TitanOpenProcess = WINFUNCTYPE(HANDLE, DWORD, c_bool, DWORD)(TE.TitanOpenProcess)
TitanOpenThread = WINFUNCTYPE(HANDLE, DWORD, c_bool, DWORD)(TE.TitanOpenThread)

# TitanEngine.TLSFixer.functions:
TLSBreakOnCallBack = WINFUNCTYPE(c_bool, LPVOID, DWORD, LPVOID)(TE.TLSBreakOnCallBack)
TLSGrabCallBackData = WINFUNCTYPE(c_bool, c_char_p, LPVOID, LPDWORD)(TE.TLSGrabCallBackData)
TLSGrabCallBackDataW = WINFUNCTYPE(c_bool, c_wchar_p, LPVOID, LPDWORD)(TE.TLSGrabCallBackDataW)
TLSBreakOnCallBackEx = WINFUNCTYPE(c_bool, c_char_p, LPVOID)(TE.TLSBreakOnCallBackEx)
TLSBreakOnCallBackExW = WINFUNCTYPE(c_bool, c_wchar_p, LPVOID)(TE.TLSBreakOnCallBackExW)
TLSRemoveCallback = WINFUNCTYPE(c_bool, c_char_p)(TE.TLSRemoveCallback)
TLSRemoveCallbackW = WINFUNCTYPE(c_bool, c_wchar_p)(TE.TLSRemoveCallbackW)
TLSRemoveTable = WINFUNCTYPE(c_bool, c_char_p)(TE.TLSRemoveTable)
TLSRemoveTableW = WINFUNCTYPE(c_bool, c_wchar_p)(TE.TLSRemoveTableW)
TLSBackupData = WINFUNCTYPE(c_bool, c_char_p)(TE.TLSBackupData)
TLSBackupDataW = WINFUNCTYPE(c_bool, c_wchar_p)(TE.TLSBackupDataW)
TLSRestoreData = WINFUNCTYPE(c_bool)(TE.TLSRestoreData)
TLSBuildNewTable = WINFUNCTYPE(c_bool, ULONG_PTR, ULONG_PTR, ULONG_PTR, LPVOID, DWORD)(TE.TLSBuildNewTable)
TLSBuildNewTableEx = WINFUNCTYPE(c_bool, c_char_p, c_char_p, LPVOID, DWORD)(TE.TLSBuildNewTableEx)
TLSBuildNewTableExW = WINFUNCTYPE(c_bool, c_wchar_p, c_char_p, LPVOID, DWORD)(TE.TLSBuildNewTableExW)

# TitanEngine.TranslateName.functions:
TranslateNativeName = WINFUNCTYPE(c_void_p, c_char_p)(TE.TranslateNativeName)
TranslateNativeNameW = WINFUNCTYPE(c_void_p, c_wchar_p)(TE.TranslateNativeNameW)

# TitanEngine.Handler.functions:
HandlerGetActiveHandleCount = WINFUNCTYPE(c_long, DWORD)(TE.HandlerGetActiveHandleCount)
HandlerIsHandleOpen = WINFUNCTYPE(c_bool, DWORD, HANDLE)(TE.HandlerIsHandleOpen)
HandlerGetHandleName = WINFUNCTYPE(c_void_p, HANDLE, DWORD, HANDLE, c_bool)(TE.HandlerGetHandleName)
HandlerGetHandleNameW = WINFUNCTYPE(c_void_p, HANDLE, DWORD, HANDLE, c_bool)(TE.HandlerGetHandleNameW)
HandlerEnumerateOpenHandles = WINFUNCTYPE(c_long, DWORD, LPVOID, DWORD)(TE.HandlerEnumerateOpenHandles)
HandlerGetHandleDetails = WINFUNCTYPE(c_void_p, HANDLE, DWORD, HANDLE, DWORD)(TE.HandlerGetHandleDetails)
HandlerGetHandleDetails.restype = ULONG_PTR
HandlerCloseRemoteHandle = WINFUNCTYPE(c_bool, HANDLE, HANDLE)(TE.HandlerCloseRemoteHandle)
HandlerEnumerateLockHandles = WINFUNCTYPE(c_long, c_char_p, c_bool, c_bool, LPVOID, DWORD)(TE.HandlerEnumerateLockHandles)
HandlerEnumerateLockHandlesW = WINFUNCTYPE(c_long, c_wchar_p, c_bool, c_bool, LPVOID, DWORD)(TE.HandlerEnumerateLockHandlesW)
HandlerCloseAllLockHandles = WINFUNCTYPE(c_bool, c_char_p, c_bool, c_bool)(TE.HandlerCloseAllLockHandles)
HandlerCloseAllLockHandlesW = WINFUNCTYPE(c_bool, c_wchar_p, c_bool, c_bool)(TE.HandlerCloseAllLockHandlesW)
HandlerIsFileLocked = WINFUNCTYPE(c_bool, c_char_p, c_bool, c_bool)(TE.HandlerIsFileLocked)
HandlerIsFileLockedW = WINFUNCTYPE(c_bool, c_wchar_p, c_bool, c_bool)(TE.HandlerIsFileLockedW)

# TitanEngine.Handler[Mutex].functions:
HandlerEnumerateOpenMutexes = WINFUNCTYPE(c_long, HANDLE, DWORD, LPVOID, DWORD)(TE.HandlerEnumerateOpenMutexes)
HandlerGetOpenMutexHandle = WINFUNCTYPE(c_void_p, HANDLE, DWORD, c_char_p)(TE.HandlerGetOpenMutexHandle)
HandlerGetOpenMutexHandle.restype = ULONG_PTR
HandlerGetOpenMutexHandleW = WINFUNCTYPE(c_void_p, HANDLE, DWORD, c_wchar_p)(TE.HandlerGetOpenMutexHandleW)
HandlerGetOpenMutexHandleW.restype = ULONG_PTR
HandlerGetProcessIdWhichCreatedMutex = WINFUNCTYPE(c_long, c_char_p)(TE.HandlerGetProcessIdWhichCreatedMutex)
HandlerGetProcessIdWhichCreatedMutexW = WINFUNCTYPE(c_long, c_wchar_p)(TE.HandlerGetProcessIdWhichCreatedMutexW)

# TitanEngine.Injector.functions:
RemoteLoadLibrary = WINFUNCTYPE(c_bool, HANDLE, c_char_p, c_bool)(TE.RemoteLoadLibrary)
RemoteLoadLibraryW = WINFUNCTYPE(c_bool, HANDLE, c_wchar_p, c_bool)(TE.RemoteLoadLibraryW)
RemoteFreeLibrary = WINFUNCTYPE(c_bool, HANDLE, HMODULE, c_char_p, c_bool)(TE.RemoteFreeLibrary)
RemoteFreeLibraryW = WINFUNCTYPE(c_bool, HANDLE, HMODULE, c_wchar_p, c_bool)(TE.RemoteFreeLibraryW)
RemoteExitProcess = WINFUNCTYPE(c_bool, HANDLE, DWORD)(TE.RemoteExitProcess)

# TitanEngine.StaticUnpacker.functions:
StaticFileLoad = WINFUNCTYPE(c_bool, c_char_p, DWORD, c_bool, LPHANDLE, LPDWORD, LPHANDLE, PULONG_PTR)(TE.StaticFileLoad)
StaticFileLoadW = WINFUNCTYPE(c_bool, c_wchar_p, DWORD, c_bool, LPHANDLE, LPDWORD, LPHANDLE, PULONG_PTR)(TE.StaticFileLoadW)
StaticFileUnload = WINFUNCTYPE(c_bool, c_char_p, c_bool, HANDLE, DWORD, HANDLE, ULONG_PTR)(TE.StaticFileUnload)
StaticFileUnloadW = WINFUNCTYPE(c_bool, c_wchar_p, c_bool, HANDLE, DWORD, HANDLE, ULONG_PTR)(TE.StaticFileUnloadW)
StaticFileOpen = WINFUNCTYPE(c_bool, c_char_p, DWORD, LPHANDLE, LPDWORD, LPDWORD)(TE.StaticFileOpen)
StaticFileOpenW = WINFUNCTYPE(c_bool, c_wchar_p, DWORD, LPHANDLE, LPDWORD, LPDWORD)(TE.StaticFileOpenW)
StaticFileGetContent = WINFUNCTYPE(c_bool, HANDLE, DWORD, LPDWORD, c_void_p, DWORD)(TE.StaticFileGetContent)
StaticFileClose = WINFUNCTYPE(None, HANDLE)(TE.StaticFileClose)
StaticMemoryDecrypt = WINFUNCTYPE(None, LPVOID, DWORD, DWORD, DWORD, ULONG_PTR)(TE.StaticMemoryDecrypt)
StaticMemoryDecryptEx = WINFUNCTYPE(None, LPVOID, DWORD, DWORD, c_void_p)(TE.StaticMemoryDecryptEx)
StaticMemoryDecryptSpecial = WINFUNCTYPE(None, LPVOID, DWORD, DWORD, DWORD, c_void_p)(TE.StaticMemoryDecryptSpecial)
StaticSectionDecrypt = WINFUNCTYPE(None, ULONG_PTR, DWORD, c_bool, DWORD, DWORD, ULONG_PTR)(TE.StaticSectionDecrypt)
StaticMemoryDecompress = WINFUNCTYPE(c_bool, c_void_p, DWORD, c_void_p, DWORD, c_int)(TE.StaticMemoryDecompress)
StaticRawMemoryCopy = WINFUNCTYPE(c_bool, HANDLE, ULONG_PTR, ULONG_PTR, DWORD, c_bool, c_char_p)(TE.StaticRawMemoryCopy)
StaticRawMemoryCopyW = WINFUNCTYPE(c_bool, HANDLE, ULONG_PTR, ULONG_PTR, DWORD, c_bool, c_wchar_p)(TE.StaticRawMemoryCopyW)
StaticRawMemoryCopyEx = WINFUNCTYPE(c_bool, HANDLE, DWORD, DWORD, c_char_p)(TE.StaticRawMemoryCopyEx)
StaticRawMemoryCopyExW = WINFUNCTYPE(c_bool, HANDLE, DWORD, DWORD, c_wchar_p)(TE.StaticRawMemoryCopyExW)
StaticRawMemoryCopyEx64 = WINFUNCTYPE(c_bool, HANDLE, DWORD64, DWORD64, c_char_p)(TE.StaticRawMemoryCopyEx64)
StaticRawMemoryCopyEx64W = WINFUNCTYPE(c_bool, HANDLE, DWORD64, DWORD64, c_wchar_p)(TE.StaticRawMemoryCopyEx64W)
StaticHashMemory = WINFUNCTYPE(c_bool, c_void_p, DWORD, c_void_p, c_bool, c_int)(TE.StaticHashMemory)
StaticHashFileW = WINFUNCTYPE(c_bool, c_wchar_p, c_char_p, c_bool, c_int)(TE.StaticHashFileW)
StaticHashFile = WINFUNCTYPE(c_bool, c_char_p, c_char_p, c_bool, c_int)(TE.StaticHashFile)

# TitanEngine.Engine.functions:
EngineUnpackerInitialize = WINFUNCTYPE(None, c_char_p, c_char_p, c_bool, c_bool, c_bool, c_void_p)(TE.EngineUnpackerInitialize)
EngineUnpackerInitializeW = WINFUNCTYPE(None, c_wchar_p, c_wchar_p, c_bool, c_bool, c_bool, c_void_p)(TE.EngineUnpackerInitializeW)
EngineUnpackerSetBreakCondition = WINFUNCTYPE(c_bool, c_void_p, DWORD, c_void_p, DWORD, DWORD, ULONG_PTR, c_bool, DWORD, DWORD)(TE.EngineUnpackerSetBreakCondition)
EngineUnpackerSetEntryPointAddress = WINFUNCTYPE(None, ULONG_PTR)(TE.EngineUnpackerSetEntryPointAddress)
EngineUnpackerFinalizeUnpacking = WINFUNCTYPE(None)(TE.EngineUnpackerFinalizeUnpacking)

# TitanEngine.Engine.functions:
SetEngineVariable = WINFUNCTYPE(None, DWORD, c_bool)(TE.SetEngineVariable)
EngineCreateMissingDependencies = WINFUNCTYPE(c_bool, c_char_p, c_char_p, c_bool)(TE.EngineCreateMissingDependencies)
EngineCreateMissingDependenciesW = WINFUNCTYPE(c_bool, c_wchar_p, c_wchar_p, c_bool)(TE.EngineCreateMissingDependenciesW)
EngineFakeMissingDependencies = WINFUNCTYPE(c_bool, HANDLE)(TE.EngineFakeMissingDependencies)
EngineDeleteCreatedDependencies = WINFUNCTYPE(c_bool)(TE.EngineDeleteCreatedDependencies)
EngineCreateUnpackerWindow = WINFUNCTYPE(c_bool, c_char_p, c_char_p, c_char_p, c_char_p, c_void_p)(TE.EngineCreateUnpackerWindow)
EngineAddUnpackerWindowLogMessage = WINFUNCTYPE(None, c_char_p)(TE.EngineAddUnpackerWindowLogMessage)
EngineCheckStructAlignment = WINFUNCTYPE(c_bool, DWORD, ULONG_PTR)(TE.EngineCheckStructAlignment)

# Global.Engine.Extension.Functions:
ExtensionManagerIsPluginLoaded = WINFUNCTYPE(c_bool, c_char_p)(TE.ExtensionManagerIsPluginLoaded)
ExtensionManagerIsPluginEnabled = WINFUNCTYPE(c_bool, c_char_p)(TE.ExtensionManagerIsPluginEnabled)
ExtensionManagerDisableAllPlugins = WINFUNCTYPE(c_bool)(TE.ExtensionManagerDisableAllPlugins)
ExtensionManagerDisablePlugin = WINFUNCTYPE(c_bool, c_char_p)(TE.ExtensionManagerDisablePlugin)
ExtensionManagerEnableAllPlugins = WINFUNCTYPE(c_bool)(TE.ExtensionManagerEnableAllPlugins)
ExtensionManagerEnablePlugin = WINFUNCTYPE(c_bool, c_char_p)(TE.ExtensionManagerEnablePlugin)
ExtensionManagerUnloadAllPlugins = WINFUNCTYPE(c_bool)(TE.ExtensionManagerUnloadAllPlugins)
ExtensionManagerUnloadPlugin = WINFUNCTYPE(c_bool, c_char_p)(TE.ExtensionManagerUnloadPlugin)
ExtensionManagerGetPluginInfo = WINFUNCTYPE(c_void_p, c_char_p)(TE.ExtensionManagerGetPluginInfo)
ExtensionManagerGetPluginInfo.restype = POINTER(PluginInformation)
