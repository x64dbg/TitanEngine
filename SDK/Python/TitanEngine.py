
from ctypes import *

TE = windll.LoadLibrary("TitanEngine.dll")

# check widechar, x64

UE_ACCESS_READ = 0
UE_ACCESS_WRITE = 1
UE_ACCESS_ALL = 2

UE_HIDE_BASIC = 1

UE_PLUGIN_CALL_REASON_PREDEBUG = 1
UE_PLUGIN_CALL_REASON_EXCEPTION = 2
UE_PLUGIN_CALL_REASON_POSTDEBUG = 3

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
UE_SECTIONNAME = 23
UE_SECTIONVIRTUALOFFSET = 24
UE_SECTIONVIRTUALSIZE = 25
UE_SECTIONRAWOFFSET = 26
UE_SECTIONRAWSIZE = 27
UE_SECTIONFLAGS = 28

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
UE_CH_ALLEVENTS = 22
UE_CH_SYSTEMBREAKPOINT = 23
UE_CH_UNHANDLEDEXCEPTION = 24

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
UE_BREAKPOINT_TYPE_INT3 = 0x10000000
UE_BREAKPOINT_TYPE_LONG_INT3 = 0x20000000
UE_BREAKPOINT_TYPE_UD2 = 0x30000000

UE_HARDWARE_EXECUTE = 4
UE_HARDWARE_WRITE = 5
UE_HARDWARE_READWRITE = 6

UE_HARDWARE_SIZE_1 = 7
UE_HARDWARE_SIZE_2 = 8
UE_HARDWARE_SIZE_4 = 9

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

UE_CMP_NOCONDITION = 0
UE_CMP_EQUAL = 1
UE_CMP_NOTEQUAL = 2
UE_CMP_GREATER = 3
UE_CMP_GREATEROREQUAL = 4
UE_CMP_LOWER = 5
UE_CMP_LOWEROREQUAL = 6
UE_CMP_REG_EQUAL = 7
UE_CMP_REG_NOTEQUAL = 8
UE_CMP_REG_GREATER = 9
UE_CMP_REG_GREATEROREQUAL = 10
UE_CMP_REG_LOWER = 11
UE_CMP_REG_LOWEROREQUAL = 12
UE_CMP_ALWAYSFALSE = 13

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

class PE32Struct(Structure):
    _pack_      = 1
    _fields_    = [ ("PE32Offset",              c_ulong),
                    ("ImageBase",               c_ulong),
                    ("OriginalEntryPoint",      c_ulong),
                    ("NtSizeOfImage",           c_ulong),
                    ("NtSizeOfHeaders",         c_ulong),
                    ("SizeOfOptionalHeaders",   c_ushort),
                    ("FileAlignment",           c_ulong),
                    ("SectionAligment",         c_ulong),
                    ("ImportTableAddress",      c_ulong),
                    ("ImportTableSize",         c_ulong),
                    ("ResourceTableAddress",    c_ulong),
                    ("ResourceTableSize",       c_ulong),
                    ("ExportTableAddress",      c_ulong),
                    ("ExportTableSize",         c_ulong),
                    ("TLSTableAddress",         c_ulong),
                    ("TLSTableSize",            c_ulong),
                    ("RelocationTableAddress",  c_ulong),
                    ("RelocationTableSize",     c_ulong),
                    ("TimeDateStamp",           c_ulong),
                    ("SectionNumber",           c_ushort),
                    ("CheckSum",                c_ulong),
                    ("SubSystem",               c_ushort),
                    ("Characteristics",         c_ushort),
                    ("NumberOfRvaAndSizes",     c_ulong) ]

class PE64Struct(Structure):
    _pack_      = 1
    _fields_    = [ ("PE64Offset",              c_ulong),
                    ("ImageBase",               c_ulonglong),
                    ("OriginalEntryPoint",      c_ulong),
                    ("NtSizeOfImage",           c_ulong),
                    ("NtSizeOfHeaders",         c_ulong),
                    ("SizeOfOptionalHeaders",   c_ushort),
                    ("FileAlignment",           c_ulong),
                    ("SectionAligment",         c_ulong),
                    ("ImportTableAddress",      c_ulong),
                    ("ImportTableSize",         c_ulong),
                    ("ResourceTableAddress",    c_ulong),
                    ("ResourceTableSize",       c_ulong),
                    ("ExportTableAddress",      c_ulong),
                    ("ExportTableSize",         c_ulong),
                    ("TLSTableAddress",         c_ulong),
                    ("TLSTableSize",            c_ulong),
                    ("RelocationTableAddress",  c_ulong),
                    ("RelocationTableSize",     c_ulong),
                    ("TimeDateStamp",           c_ulong),
                    ("SectionNumber",           c_ushort),
                    ("CheckSum",                c_ulong),
                    ("SubSystem",               c_ushort),
                    ("Characteristics",         c_ushort),
                    ("NumberOfRvaAndSizes",     c_ulong) ]

class ImportEnumData(Structure):
    _pack_      = 1
    _fields_    = [ ("NewDll",                  c_bool),
                    ("NumberOfImports",         c_int),
                    ("ImageBase",               c_ulong),
                    ("BaseImportThunk",         c_ulong),
                    ("ImportThunk",             c_ulong),
                    ("APIName",                 c_char_p),
                    ("DLLName",                 c_char_p) ]

class THREAD_ITEM_DATA(Structure):
    _pack_      = 1
    _fields_    = [ ("hThread",                 c_void_p),
                    ("dwThreadId",              c_ulong),
                    ("ThreadStartAddress",      c_void_p),
                    ("ThreadLocalBase",         c_void_p) ]

MAX_PATH = 260

class LIBRARY_ITEM_DATA(Structure):
    _pack_      = 1
    _fields_    = [ ("hFile",                   c_void_p),
                    ("BaseOfDll",               c_void_p),
                    ("hFileMapping",            c_void_p),
                    ("hFileMappingView",        c_void_p),
                    ("szLibraryPath",           c_char * MAX_PATH),
                    ("szLibraryName",           c_char * MAX_PATH) ]

class LIBRARY_ITEM_DATAW(Structure):
    _pack_      = 1
    _fields_    = [ ("hFile",                   c_void_p),
                    ("BaseOfDll",               c_void_p),
                    ("hFileMapping",            c_void_p),
                    ("hFileMappingView",        c_void_p),
                    ("szLibraryPath",           c_wchar * MAX_PATH),
                    ("szLibraryName",           c_wchar * MAX_PATH) ]

class PROCESS_ITEM_DATA(Structure):
    _pack_      = 1
    _fields_    = [ ("hProcess",                c_void_p),
                    ("dwProcessId",             c_ulong),
                    ("hThread",                 c_void_p),
                    ("dwThreadId",              c_ulong),
                    ("hFile",                   c_void_p),
                    ("BaseOfImage",             c_void_p),
                    ("ThreadStartAddress",      c_void_p),
                    ("ThreadLocalBase",         c_void_p) ]

class HandlerArray(Structure):
    _pack_      = 1
    _fields_    = [ ("ProcessId",               c_ulong),
                    ("hHandle",                 c_void_p) ]

class PluginInformation(Structure):
    _pack_      = 1
    _fields_    = [ ("PluginName",              c_char * 64),
                    ("PluginMajorVersion",      c_ulong),
                    ("PluginMinorVersion",      c_ulong),
                    ("PluginBaseAddress",       c_void_p),
                    ("TitanDebuggingCallBack",  c_void_p),
                    ("TitanRegisterPlugin",     c_void_p),
                    ("TitanReleasePlugin",      c_void_p),
                    ("TitanResetPlugin",        c_void_p),
                    ("PluginDisabled",          c_bool) ]

TEE_MAXIMUM_HOOK_SIZE = 14
TEE_MAXIMUM_HOOK_RELOCS = 7

TEE_MAXIMUM_HOOK_INSERT_SIZE = 5
TEE_MAXIMUM_HOOK_INSERT_SIZE64 = 14

class HOOK_ENTRY(Structure):
    _pack_      = 1
    _fields_    = [ ("IATHook",                 c_bool),
                    ("HookType",                c_ubyte),
                    ("HookSize",                c_ulong),
                    ("HookAddress",             c_void_p),
                    ("RedirectionAddress",      c_void_p),
                    ("HookBytes",               c_ubyte * TEE_MAXIMUM_HOOK_SIZE),
                    ("OriginalBytes",           c_ubyte * TEE_MAXIMUM_HOOK_SIZE),
                    ("IATHookModuleBase",       c_void_p),
                    ("IATHookNameHash",         c_ulong),
                    ("HookIsEnabled",           c_bool),
                    ("HookIsRemote",            c_bool),
                    ("PatchedEntry",            c_void_p),
                    ("RelocationInfo",          c_ulong * TEE_MAXIMUM_HOOK_RELOCS),
                    ("RelocationCount",         c_int) ]

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
UE_FILED_FIXABLE_NON_CRITICAL = 5
UE_FILED_FIXABLE_CRITICAL = 6
UE_FIELD_NOT_PRESET = 7
UE_FIELD_NOT_PRESET_WARNING = 8

UE_RESULT_FILE_OK = 10
UE_RESULT_FILE_INVALID_BUT_FIXABLE = 11
UE_RESULT_FILE_INVALID_AND_NON_FIXABLE = 12
UE_RESULT_FILE_INVALID_FORMAT = 13

class FILE_STATUS_INFO(Structure):
    _pack_      = 1
    _fields_    = [ ("OveralEvaluation",                c_ubyte),
                    ("EvaluationTerminatedByException", c_bool),
                    ("FileIs64Bit",                     c_bool),
                    ("FileIsDLL",                       c_bool),
                    ("FileIsConsole",                   c_bool),
                    ("MissingDependencies",             c_bool),
                    ("MissingDeclaredAPIs",             c_bool),
                    ("SignatureMZ",                     c_ubyte),
                    ("SignaturePE",                     c_ubyte),
                    ("EntryPoint",                      c_ubyte),
                    ("ImageBase",                       c_ubyte),
                    ("SizeOfImage",                     c_ubyte),
                    ("FileAlignment",                   c_ubyte),
                    ("SectionAlignment",                c_ubyte),
                    ("ExportTable",                     c_ubyte),
                    ("RelocationTable",                 c_ubyte),
                    ("ImportTable",                     c_ubyte),
                    ("ImportTableSection",              c_ubyte),
                    ("ImportTableData",                 c_ubyte),
                    ("IATTable",                        c_ubyte),
                    ("TLSTable",                        c_ubyte),
                    ("LoadConfigTable",                 c_ubyte),
                    ("BoundImportTable",                c_ubyte),
                    ("COMHeaderTable",                  c_ubyte),
                    ("ResourceTable",                   c_ubyte),
                    ("ResourceData",                    c_ubyte),
                    ("SectionTable",                    c_ubyte) ]

class FILE_FIX_INFO(Structure):
    _pack_      = 1
    _fields_    = [ ("OveralEvaluation",                c_ubyte),
                    ("FixingTerminatedByException",     c_bool),
                    ("FileFixPerformed",                c_bool),
                    ("StrippedRelocation",              c_bool),
                    ("DontFixRelocations",              c_bool),
                    ("OriginalRelocationTableAddress",  c_ulong),
                    ("OriginalRelocationTableSize",     c_ulong),
                    ("StrippedExports",                 c_bool),
                    ("DontFixExports",                  c_bool),
                    ("OriginalExportTableAddress",      c_ulong),
                    ("OriginalExportTableSize",         c_ulong),
                    ("StrippedResources",               c_bool),
                    ("DontFixResources",                c_bool),
                    ("OriginalResourceTableAddress",    c_ulong),
                    ("OriginalResourceTableSize",       c_ulong),
                    ("StrippedTLS",                     c_bool),
                    ("DontFixTLS",                      c_bool),
                    ("OriginalTLSTableAddress",         c_ulong),
                    ("OriginalTLSTableSize",            c_ulong),
                    ("StrippedLoadConfig",              c_bool),
                    ("DontFixLoadConfig",               c_bool),
                    ("OriginalLoadConfigTableAddress",  c_ulong),
                    ("OriginalLoadConfigTableSize",     c_ulong),
                    ("StrippedBoundImports",            c_bool),
                    ("DontFixBoundImports",             c_bool),
                    ("OriginalBoundImportTableAddress", c_ulong),
                    ("OriginalBoundImportTableSize",    c_ulong),
                    ("StrippedIAT",                     c_bool),
                    ("DontFixIAT",                      c_bool),
                    ("OriginalImportAddressTableAddress",   c_ulong),
                    ("OriginalImportAddressTableSize",      c_ulong),
                    ("StrippedCOM",                     c_bool),
                    ("DontFixCOM",                      c_bool),
                    ("OriginalCOMTableAddress",         c_ulong),
                    ("OriginalCOMTableSize",            c_ulong) ]

class PROCESS_INFORMATION(Structure):
    _pack_      = 1
    _fields_    = [ ("hProcess",        c_void_p),
                    ("hThread",         c_void_p),
                    ("dwProcessId",     c_ulong),
                    ("dwThreadId",      c_ulong) ]

EXCEPTION_MAXIMUM_PARAMETERS = 15

class EXCEPTION_RECORD(Structure):
    _pack_      = 1
    pass

EXCEPTION_RECORD._fields_ = [   ("ExceptionCode",           c_ulong),
                                ("ExceptionFlags",          c_ulong),
                                ("ExceptionRecord",         POINTER(EXCEPTION_RECORD)),
                                ("ExceptionAddress",        c_void_p),
                                ("NumberParameters",        c_ulong),
                                ("ExceptionInformation",    c_ulong * EXCEPTION_MAXIMUM_PARAMETERS) ]

class EXCEPTION_DEBUG_INFO(Structure):
    _pack_      = 1
    _fields_    = [ ("ExceptionRecord", EXCEPTION_RECORD),
                    ("dwFirstChance",   c_ulong) ]

class CREATE_THREAD_DEBUG_INFO(Structure):
    _pack_      = 1
    _fields_    = [ ("hThread",             c_void_p),
                    ("lpThreadLocalBase",   c_void_p),
                    ("lpStartAddress",      c_void_p) ]

class CREATE_PROCESS_DEBUG_INFO(Structure):
    _pack_      = 1
    _fields_    = [ ("hFile",                   c_void_p),
                    ("hProcess",                c_void_p),
                    ("hThread",                 c_void_p),
                    ("dwDebugInfoFileOffset",   c_ulong),
                    ("nDebugInfoSize",          c_ulong),
                    ("lpThreadLocalBase",       c_void_p),
                    ("lpStartAddress",          c_void_p),
                    ("lpImageName",             c_void_p),
                    ("fUnicode",                c_ushort) ]

class EXIT_THREAD_DEBUG_INFO(Structure):
    _pack_      = 1
    _fields_    = [ ("dwExitCode", c_ulong) ]

class EXIT_PROCESS_DEBUG_INFO(Structure):
    _pack_      = 1
    _fields_    = [ ("dwExitCode", c_ulong) ]

class LOAD_DLL_DEBUG_INFO(Structure):
    _pack_      = 1
    _fields_    = [ ("hFile",                   c_void_p),
                    ("lpBaseOfDll",             c_void_p),
                    ("dwDebugInfoFileOffset",   c_ulong),
                    ("nDebugInfoSize",          c_ulong),
                    ("lpImageName",             c_void_p),
                    ("fUnicode",                c_ushort) ]

class UNLOAD_DLL_DEBUG_INFO(Structure):
    _pack_      = 1
    _fields_    = [ ("lpBaseOfDll", c_void_p) ]

class OUTPUT_DEBUG_STRING_INFO(Structure):
    _pack_      = 1
    _fields_    = [ ("lpDebugStringData",   c_char_p),
                    ("fUnicode",            c_ushort),
                    ("nDebugStringLength",  c_ushort) ]

class RIP_INFO(Structure):
    _pack_      = 1
    _fields_    = [ ("dwError", c_ulong),
                    ("dwType",  c_ulong) ]

class _U(Union):
    _pack_      = 1
    _fields_    = [ ("Exception",           EXCEPTION_DEBUG_INFO),
                    ("CreateThread",        CREATE_THREAD_DEBUG_INFO),
                    ("CreateProcessInfo",   CREATE_PROCESS_DEBUG_INFO),
                    ("ExitThread",          EXIT_THREAD_DEBUG_INFO),
                    ("ExitProcess",         EXIT_PROCESS_DEBUG_INFO),
                    ("LoadDll",             LOAD_DLL_DEBUG_INFO),
                    ("UnloadDll",           UNLOAD_DLL_DEBUG_INFO),
                    ("DebugString",         OUTPUT_DEBUG_STRING_INFO),
                    ("RipInfo",             RIP_INFO) ]

class DEBUG_EVENT(Structure):
    _pack_      = 1
    _anonymous_ = ("u",)
    _fields_    = [ ("dwDebugEventCode",    c_ulong),
                    ("dwProcessId",         c_ulong),
                    ("dwThreadId",          c_ulong),
                    ("u",                   _U) ]

class STARTUPINFOW(Structure):
    _pack_      = 1
    _fields_    = [ ("cb",                  c_ulong),
                    ("lpReserved",          c_wchar_p),
                    ("lpDesktop",           c_wchar_p),
                    ("lpTitle",             c_wchar_p),
                    ("dwX",                 c_ulong),
                    ("dwY",                 c_ulong),
                    ("dwXSize",             c_ulong),
                    ("dwYSize",             c_ulong),
                    ("dwXCountChars",       c_ulong),
                    ("dwYCountChars",       c_ulong),
                    ("dwFillAttribute",     c_ulong),
                    ("dwFlags",             c_ulong),
                    ("wShowWindow",         c_ushort),
                    ("cbReserved2",         c_ushort),
                    ("lpReserved2",         POINTER(c_ubyte)),
                    ("hStdInput",           c_void_p),
                    ("hStdOutput",          c_void_p),
                    ("hStdError",           c_void_p) ]

fImportEnum     = WINFUNCTYPE(None, POINTER(ImportEnumData))
fImportFix      = WINFUNCTYPE(None, c_void_p)
fResourceEnum   = WINFUNCTYPE(None, c_wchar_p, c_ulong, c_wchar_p, c_ulong, c_ulong, c_ulong, c_ulong)
fThreadEnum     = WINFUNCTYPE(None, POINTER(THREAD_ITEM_DATA))
fThreadExit     = WINFUNCTYPE(None, POINTER(EXIT_THREAD_DEBUG_INFO))
fBreakPoint     = WINFUNCTYPE(None)
fCustomHandler  = WINFUNCTYPE(None, c_void_p)
fLibraryBreakPoint = WINFUNCTYPE(None, POINTER(LOAD_DLL_DEBUG_INFO))
fLibraryEnum    = WINFUNCTYPE(None, POINTER(LIBRARY_ITEM_DATA))
fLibraryEnumW   = WINFUNCTYPE(None, POINTER(LIBRARY_ITEM_DATAW))
fHookEnum       = WINFUNCTYPE(c_bool, POINTER(HOOK_ENTRY), c_void_p, POINTER(LIBRARY_ITEM_DATA), c_ulong)
fProcessWithLibraryEnum = WINFUNCTYPE(None, c_ulong, c_void_p)
fStaticDecrypt  = WINFUNCTYPE(c_bool, c_void_p, c_ulong)
fInitializeDbg  = WINFUNCTYPE(None, c_char_p, c_ubyte, c_ubyte)

TE.GetPE32DataFromMappedFile.restype = c_ulonglong
TE.GetPE32Data.restype = c_ulonglong
TE.GetPE32DataW.restype = c_ulonglong
TE.ConvertVAtoFileOffset.restype = c_ulonglong
TE.ConvertVAtoFileOffsetEx.restype = c_ulonglong
TE.ConvertFileOffsetToVA.restype = c_ulonglong
TE.ConvertFileOffsetToVAEx.restype = c_ulonglong
TE.ResourcerLoadFileForResourceUse.restype = c_ulonglong
TE.ResourcerLoadFileForResourceUseW.restype = c_ulonglong
TE.ThreaderCreateRemoteThread.restype = c_ulonglong
TE.ThreaderCreateRemoteThreadEx.restype = c_ulonglong
TE.ThreaderGetOpenHandleForThread.restype = c_ulonglong
TE.GetContextDataEx.restype = c_ulonglong
TE.GetContextData.restype = c_ulonglong
TE.FindEx.restype = c_ulonglong
TE.Find.restype = c_ulonglong
TE.GetDebuggedDLLBaseAddress.restype = c_ulonglong
TE.GetDebuggedFileBaseAddress.restype = c_ulonglong
TE.GetFunctionParameter.restype = c_ulonglong
TE.GetJumpDestinationEx.restype = c_ulonglong
TE.GetJumpDestination.restype = c_ulonglong
TE.ImporterGetCurrentDelta.restype = c_ulonglong
TE.ImporterFindAPIWriteLocation.restype = c_ulonglong
TE.ImporterFindOrdinalAPIWriteLocation.restype = c_ulonglong
TE.ImporterFindAPIByWriteLocation.restype = c_ulonglong
TE.ImporterFindDLLByWriteLocation.restype = c_ulonglong
TE.ImporterGetAPIOrdinalNumber.restype = c_ulonglong
TE.ImporterGetRemoteAPIAddress.restype = c_ulonglong
TE.ImporterGetRemoteAPIAddressEx.restype = c_ulonglong
TE.ImporterGetLocalAPIAddress.restype = c_ulonglong
TE.ImporterGetAPIOrdinalNumberFromDebugee.restype = c_ulonglong
TE.ImporterGetRemoteDLLBase.restype = c_ulonglong
TE.ImporterGetForwardedAPIOrdinalNumber.restype = c_ulonglong
TE.ImporterGetNearestAPIAddress.restype = c_ulonglong
TE.TracerLevel1.restype = c_ulonglong
TE.HashTracerLevel1.restype = c_ulonglong
TE.TracerFixKnownRedirection.restype = c_ulonglong
TE.HandlerGetHandleDetails.restype = c_ulonglong
TE.HandlerGetOpenMutexHandle.restype = c_ulonglong
TE.HandlerGetOpenMutexHandleW.restype = c_ulonglong

TE.GetSharedOverlay.restype = c_char_p
TE.StaticDisassembleEx.restype = c_char_p
TE.StaticDisassemble.restype = c_char_p
TE.DisassembleEx.restype = c_char_p
TE.Disassemble.restype = c_char_p
TE.ImporterGetLastAddedDLLName.restype = c_char_p
TE.ImporterGetDLLName.restype = c_char_p
TE.ImporterGetAPIName.restype = c_char_p
TE.ImporterGetAPINameEx.restype = c_char_p
TE.ImporterGetDLLNameFromDebugee.restype = c_char_p
TE.ImporterGetAPINameFromDebugee.restype = c_char_p
TE.ImporterGetForwardedAPIName.restype = c_char_p
TE.ImporterGetForwardedDLLName.restype = c_char_p
TE.ImporterGetNearestAPIName.restype = c_char_p
TE.TranslateNativeName.restype = c_char_p
TE.HandlerGetHandleName.restype = c_char_p

TE.GetSharedOverlayW.restype = c_wchar_p
TE.TranslateNativeNameW.restype = c_wchar_p
TE.HandlerGetHandleNameW.restype = c_wchar_p

TE.GetPEBLocation.restype = c_void_p

TE.ThreaderGetThreadInfo.restype = POINTER(THREAD_ITEM_DATA)
TE.ThreaderGetThreadData.restype = POINTER(THREAD_ITEM_DATA)

TE.InitDebug.restype = POINTER(PROCESS_INFORMATION)
TE.InitDebugW.restype = POINTER(PROCESS_INFORMATION)
TE.InitDebugEx.restype = POINTER(PROCESS_INFORMATION)
TE.InitDebugExW.restype = POINTER(PROCESS_INFORMATION)
TE.InitDLLDebug.restype = POINTER(PROCESS_INFORMATION)
TE.InitDLLDebugW.restype = POINTER(PROCESS_INFORMATION)

TE.GetDebugData.restype = POINTER(DEBUG_EVENT)
TE.GetTerminationData.restype = POINTER(DEBUG_EVENT)

TE.GetProcessInformation.restype = POINTER(PROCESS_INFORMATION)
TE.GetStartupInformation.restype = POINTER(STARTUPINFOW)

TE.LibrarianGetLibraryInfo.restype = POINTER(LIBRARY_ITEM_DATA)
TE.LibrarianGetLibraryInfoEx.restype = POINTER(LIBRARY_ITEM_DATA)

TE.LibrarianGetLibraryInfoW.restype = POINTER(LIBRARY_ITEM_DATAW)
TE.LibrarianGetLibraryInfoExW.restype = POINTER(LIBRARY_ITEM_DATAW)

TE.HooksGetHookEntryDetails.restype = POINTER(HOOK_ENTRY)

TE.ExtensionManagerGetPluginInfo.restype = POINTER(PluginInformation)