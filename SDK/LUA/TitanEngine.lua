require 'alien'
local TitanEngine = alien.load 'TitanEngine.dll'
local SystemKernel = alien.load 'kernel32.dll'

--
--
-- TitanEngine 2.0.3 LUA SDK / www.reversinglabs.com
--
--

-- Windows.Constants:

MAX_PATH = 260

-- Global.Constant.Structure.Declaration:
-- Engine.External:
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
UE_ENGINE_SET_DEBUG_PRIVILEGE = 9

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
UE_SEG_GS = 37
UE_SEG_FS = 38
UE_SEG_ES = 39
UE_SEG_DS = 40
UE_SEG_CS = 41
UE_SEG_SS = 42

PE32Struct = alien.defstruct{
  { "PE32Offset", "long" },
  { "ImageBase", "long" },
  { "OriginalEntryPoint", "long" },
  { "NtSizeOfImage", "long" },
  { "NtSizeOfHeaders", "long" },
  { "SizeOfOptionalHeaders", "short" },
  { "FileAlignment", "long" },
  { "SectionAligment", "long" },
  { "ImportTableAddress", "long" },
  { "ImportTableSize", "long" },
  { "ResourceTableAddress", "long" },
  { "ResourceTableSize", "long" },
  { "ExportTableAddress", "long" },
  { "ExportTableSize", "long" },
  { "TLSTableAddress", "long" },
  { "TLSTableSize", "long" },
  { "RelocationTableAddress", "long" },
  { "RelocationTableSize", "long" },
  { "TimeDateStamp", "long" },
  { "SectionNumber", "short" },
  { "CheckSum", "long" },
  { "SubSystem", "short" },
  { "Characteristics", "short" },
  { "NumberOfRvaAndSizes", "long" }
}

ImportEnumData = alien.defstruct{
  { "NewDll", "byte"},
  { "NumberOfImports", "long"},
  { "ImageBase", "long"},
  { "BaseImportThunk", "long"},
  { "ImportThunk", "long"},
  { "APIName", "string"},
  { "DLLName", "string"}
}

THREAD_ITEM_DATA = alien.defstruct{
  { "hThread", "long" },
  { "dwThreadId", "long" },
  { "ThreadStartAddress", "long" },
  { "ThreadLocalBase", "long" }
}

LIBRARY_ITEM_DATA = alien.defstruct{
  { "hFile", "long" },
  { "BaseOfDll", "long" },
  { "hFileMapping", "long" },
  { "hFileMappingView", "long" },
  { "additionalFields", "char" }
}
LIBRARY_ITEM_DATA.size = LIBRARY_ITEM_DATA.size + 2 * MAX_PATH - 1

-- Auxiliary LUA functions
function LibraryItemData_GetLibraryPath(lid)
  local out = {}
  local offset = lid.offsets.additionalFields
  local buf = lf()
  for i = offset, offset+MAX_PATH-1 do
    local c = buf:get(i, "char")
    if c ~= 0 then
      out[#out+1] = string.char(c)
    else
      break
    end
  end
  return table.concat(out)
end

function LibraryItemData_GetLibraryName(lid)
  local out = {}
  local offset = lid.offsets.additionalFields + MAX_PATH
  local buf = lf()
  for i = offset, offset+MAX_PATH-1 do
    local c = buf:get(i, "char")
    if c ~= 0 then
      out[#out+1] = string.char(c)
    else
      break
    end
  end
  return table.concat(out)
end
-- Auxiliary LUA functions

PROCESS_ITEM_DATA = alien.defstruct{
  { "hProcess", "long" },
  { "dwProcessId", "long" },
  { "hThread", "long" },
  { "dwThreadId", "long" },
  { "hFile", "long" },
  { "BaseOfImage", "long" },
  { "ThreadStartAddress", "long" },
  { "ThreadLocalBase", "long" }
}

HandlerArray = alien.defstruct{
  { "ProcessId", "long" },
  { "hHandle", "long" }
}

PluginInformation = alien.defstruct{
  { "PluginName", "byte" },
  { "PluginMajorVersion", "long" },
  { "PluginMinorVersion", "long" },
  { "PluginBaseAddress", "long" },
  { "TitanDebuggingCallBack", "long" },
  { "TitanRegisterPlugin", "long" },
  { "TitanReleasePlugin", "long" },
  { "TitanResetPlugin", "long" },
  { "PluginDisabled", "byte" }
}

TEE_MAXIMUM_HOOK_SIZE = 14
TEE_MAXIMUM_HOOK_RELOCS = 7

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

FILE_STATUS_INFO = alien.defstruct{
  { "OveralEvaluation", "byte" },
  { "EvaluationTerminatedByException", "byte" },
  { "FileIs64Bit", "byte" },
  { "FileIsDLL", "byte" },
  { "FileIsConsole", "byte" },
  { "MissingDependencies", "byte" },
  { "MissingDeclaredAPIs", "byte" },
  { "SignatureMZ", "byte" },
  { "SignaturePE", "byte" },
  { "EntryPoint", "byte" },
  { "ImageBase", "byte" },
  { "SizeOfImage", "byte" },
  { "FileAlignment", "byte" },
  { "SectionAlignment", "byte" },
  { "ExportTable", "byte" },
  { "RelocationTable", "byte" },
  { "ImportTable", "byte" },
  { "ImportTableSection", "byte" },
  { "ImportTableData", "byte" },
  { "IATTable", "byte" },
  { "TLSTable", "byte" },
  { "LoadConfigTable", "byte" },
  { "BoundImportTable", "byte" },
  { "COMHeaderTable", "byte" },
  { "ResourceTable", "byte" },
  { "ResourceData", "byte" },
  { "SectionTable", "byte" }
}

FILE_FIX_INFO = alien.defstruct{
  { "OveralEvaluation", "byte" },
  { "FixingTerminatedByException", "byte" },
  { "FileFixPerformed", "byte" },
  { "StrippedRelocation", "byte" },
  { "DontFixRelocations", "byte" },
  { "OriginalRelocationTableAddress", "long" },
  { "OriginalRelocationTableSize", "long" },
  { "StrippedExports", "byte" },
  { "DontFixExports", "byte" },
  { "OriginalExportTableAddress", "long" },
  { "OriginalExportTableSize", "long" },
  { "StrippedResources", "byte" },
  { "DontFixResources", "byte" },
  { "OriginalResourceTableAddress", "long" },
  { "OriginalResourceTableSize", "long" },
  { "StrippedTLS", "byte" },
  { "DontFixTLS", "byte" },
  { "OriginalTLSTableAddress", "long" },
  { "OriginalTLSTableSize", "long" },
  { "StrippedLoadConfig", "byte" },
  { "DontFixLoadConfig", "byte" },
  { "OriginalLoadConfigTableAddress", "long" },
  { "OriginalLoadConfigTableSize", "long" },
  { "StrippedBoundImports", "byte" },
  { "DontFixBoundImports", "byte" },
  { "OriginalBoundImportTableAddress", "long" },
  { "OriginalBoundImportTableSize", "long" },
  { "StrippedIAT", "byte" },
  { "DontFixIAT", "byte" },
  { "OriginalImportAddressTableAddress", "long" },
  { "OriginalImportAddressTableSize", "long" },
  { "StrippedCOM", "byte" },
  { "DontFixCOM", "byte" },
  { "OriginalCOMTableAddress", "long" },
  { "OriginalCOMTableSize", "long" }
}

-- Global.UtilFunction.Declaration:
	SystemKernel.CopyFileA:types {"string","string","long",abi="stdcall",ret="byte"}
	TE_CopyFileA = SystemKernel.CopyFileA
	SystemKernel.DeleteFileA:types {"string",abi="stdcall",ret="byte"}
	TE_DeleteFileA = SystemKernel.DeleteFileA
	SystemKernel.RtlMoveMemory:types {"pointer","pointer","long",abi="stdcall"}
	TE_RtlMoveMemory = SystemKernel.RtlMoveMemory
	SystemKernel.RtlZeroMemory:types {"pointer","long",abi="stdcall"}
	TE_RtlZeroMemory = SystemKernel.RtlZeroMemory
	SystemKernel.FreeLibrary:types {"long",abi="stdcall",ret="byte"}
	TE_FreeLibrary = SystemKernel.FreeLibrary

-- Global.UtilStructure.Declaration:
PROCESS_INFORMATION = alien.defstruct{
  { "hProcess", "long" },
  { "hThread", "long" },
  { "dwProcessId", "long" },
  { "dwThreadId", "long" }
}

-- Global.UtilVariable.Declaration:
	TE_TRUE = 1
	TE_FALSE = 0

-- Global.Function.Declaration:
--
-- TitanEngine.Dumper.functions:
--
-- __declspec(dllexport) bool __stdcall DumpProcess(HANDLE hProcess, LPVOID ImageBase, char* szDumpFileName, ULONG_PTR EntryPoint);
	TitanEngine.DumpProcess:types {"long","long","string","long",abi="stdcall",ret="byte"}
	TE_DumpProcess = TitanEngine.DumpProcess
-- __declspec(dllexport) bool __stdcall DumpProcessEx(DWORD ProcessId, LPVOID ImageBase, char* szDumpFileName, ULONG_PTR EntryPoint);
	TitanEngine.DumpProcessEx:types {"long","long","string","long",abi="stdcall",ret="byte"}
	TE_DumpProcessEx = TitanEngine.DumpProcessEx
-- __declspec(dllexport) bool __stdcall DumpMemory(HANDLE hProcess, LPVOID MemoryStart, ULONG_PTR MemorySize, char* szDumpFileName);
	TitanEngine.DumpMemory:types {"long","long","long","string",abi="stdcall",ret="byte"}
	TE_DumpMemory = TitanEngine.DumpMemory
-- __declspec(dllexport) bool __stdcall DumpMemoryEx(DWORD ProcessId, LPVOID MemoryStart, ULONG_PTR MemorySize, char* szDumpFileName);
	TitanEngine.DumpMemoryEx:types {"long","long","long","string",abi="stdcall",ret="byte"}
	TE_DumpMemoryEx = TitanEngine.DumpMemoryEx
-- __declspec(dllexport) bool __stdcall DumpRegions(HANDLE hProcess, char* szDumpFolder, bool DumpAboveImageBaseOnly);
	TitanEngine.DumpRegions:types {"long","string","long",abi="stdcall",ret="byte"}
	TE_DumpRegions = TitanEngine.DumpRegions
-- __declspec(dllexport) bool __stdcall DumpRegionsEx(DWORD ProcessId, char* szDumpFolder, bool DumpAboveImageBaseOnly);
	TitanEngine.DumpRegionsEx:types {"long","string","long",abi="stdcall",ret="byte"}
	TE_DumpRegionsEx = TitanEngine.DumpRegionsEx
-- __declspec(dllexport) bool __stdcall DumpModule(HANDLE hProcess, LPVOID ModuleBase, char* szDumpFileName);
	TitanEngine.DumpModule:types {"long","long","string",abi="stdcall",ret="byte"}
	TE_DumpModule = TitanEngine.DumpModule
-- __declspec(dllexport) bool __stdcall DumpModuleEx(DWORD ProcessId, LPVOID ModuleBase, char* szDumpFileName);
	TitanEngine.DumpModuleEx:types {"long","long","string",abi="stdcall",ret="byte"}
	TE_DumpModuleEx = TitanEngine.DumpModuleEx
-- __declspec(dllexport) bool __stdcall PastePEHeader(HANDLE hProcess, LPVOID ImageBase, char* szDebuggedFileName);
	TitanEngine.PastePEHeader:types {"long","long","string",abi="stdcall",ret="byte"}
	TE_PastePEHeader = TitanEngine.PastePEHeader
-- __declspec(dllexport) bool __stdcall ExtractSection(char* szFileName, char* szDumpFileName, DWORD SectionNumber);
	TitanEngine.ExtractSection:types {"string","string","long",abi="stdcall",ret="byte"}
	TE_ExtractSection = TitanEngine.ExtractSection
-- __declspec(dllexport) bool __stdcall ResortFileSections(char* szFileName);
	TitanEngine.ResortFileSections:types {"string",abi="stdcall",ret="byte"}
	TE_ResortFileSections = TitanEngine.ResortFileSections
-- __declspec(dllexport) bool __stdcall FindOverlay(char* szFileName, LPDWORD OverlayStart, LPDWORD OverlaySize);
	TitanEngine.FindOverlay:types {"string","pointer","pointer",abi="stdcall",ret="byte"}
	TE_FindOverlay = TitanEngine.FindOverlay
-- __declspec(dllexport) bool __stdcall ExtractOverlay(char* szFileName, char* szExtactedFileName);
	TitanEngine.ExtractOverlay:types {"string","string",abi="stdcall",ret="byte"}
	TE_ExtractOverlay = TitanEngine.ExtractOverlay
-- __declspec(dllexport) bool __stdcall AddOverlay(char* szFileName, char* szOverlayFileName);
	TitanEngine.AddOverlay:types {"string","string",abi="stdcall",ret="byte"}
	TE_AddOverlay = TitanEngine.AddOverlay
-- __declspec(dllexport) bool __stdcall CopyOverlay(char* szInFileName, char* szOutFileName);
	TitanEngine.CopyOverlay:types {"string","string",abi="stdcall",ret="byte"}
	TE_CopyOverlay = TitanEngine.CopyOverlay
-- __declspec(dllexport) bool __stdcall RemoveOverlay(char* szFileName);
	TitanEngine.RemoveOverlay:types {"string",abi="stdcall",ret="byte"}
	TE_RemoveOverlay = TitanEngine.RemoveOverlay
-- __declspec(dllexport) bool __stdcall MakeAllSectionsRWE(char* szFileName);
	TitanEngine.MakeAllSectionsRWE:types {"string",abi="stdcall",ret="byte"}
	TE_MakeAllSectionsRWE = TitanEngine.MakeAllSectionsRWE
-- __declspec(dllexport) long __stdcall AddNewSectionEx(char* szFileName, char* szSectionName, DWORD SectionSize, DWORD SectionAttributes, LPVOID SectionContent, DWORD ContentSize);
	TitanEngine.AddNewSectionEx:types {"string","string","long","long","pointer","long",abi="stdcall",ret="long"}
	TE_AddNewSectionEx = TitanEngine.AddNewSectionEx
-- __declspec(dllexport) long __stdcall AddNewSection(char* szFileName, char* szSectionName, DWORD SectionSize);
	TitanEngine.AddNewSection:types {"string","string","long",abi="stdcall",ret="long"}
	TE_AddNewSection = TitanEngine.AddNewSection
-- __declspec(dllexport) bool __stdcall ResizeLastSection(char* szFileName, DWORD NumberOfExpandBytes, bool AlignResizeData);
	TitanEngine.ResizeLastSection:types {"string","long","long",abi="stdcall",ret="byte"}
	TE_ResizeLastSection = TitanEngine.ResizeLastSection
-- __declspec(dllexport) void __stdcall SetSharedOverlay(char* szFileName);
	TitanEngine.SetSharedOverlay:types {"string",abi="stdcall"}
	TE_SetSharedOverlay = TitanEngine.SetSharedOverlay
-- __declspec(dllexport) char* __stdcall GetSharedOverlay();
	TitanEngine.GetSharedOverlay:types {abi="stdcall",ret="string"}
	TE_GetSharedOverlay = TitanEngine.GetSharedOverlay
-- __declspec(dllexport) bool __stdcall DeleteLastSection(char* szFileName);
	TitanEngine.DeleteLastSection:types {"string",abi="stdcall",ret="byte"}
	TE_DeleteLastSection = TitanEngine.DeleteLastSection
-- __declspec(dllexport) bool __stdcall DeleteLastSectionEx(char* szFileName, DWORD NumberOfSections);
	TitanEngine.DeleteLastSectionEx:types {"string","long",abi="stdcall",ret="byte"}
	TE_DeleteLastSectionEx = TitanEngine.DeleteLastSectionEx
-- __declspec(dllexport) long long __stdcall GetPE32DataFromMappedFile(ULONG_PTR FileMapVA, DWORD WhichSection, DWORD WhichData);
	TitanEngine.GetPE32DataFromMappedFile:types {"long","long","long",abi="stdcall",ret="long"}
	TE_GetPE32DataFromMappedFile = TitanEngine.GetPE32DataFromMappedFile
-- __declspec(dllexport) long long __stdcall GetPE32Data(char* szFileName, DWORD WhichSection, DWORD WhichData);
	TitanEngine.GetPE32Data:types {"string","long","long",abi="stdcall",ret="long"}
	TE_GetPE32Data = TitanEngine.GetPE32Data
-- __declspec(dllexport) bool __stdcall GetPE32DataFromMappedFileEx(ULONG_PTR FileMapVA, LPVOID DataStorage);
	TitanEngine.GetPE32DataFromMappedFileEx:types {"long","pointer",abi="stdcall",ret="byte"}
	TE_GetPE32DataFromMappedFileEx = TitanEngine.GetPE32DataFromMappedFileEx
-- __declspec(dllexport) bool __stdcall GetPE32DataEx(char* szFileName, LPVOID DataStorage);
	TitanEngine.GetPE32DataEx:types {"string","pointer",abi="stdcall",ret="byte"}
	TE_GetPE32DataEx = TitanEngine.GetPE32DataEx
-- __declspec(dllexport) bool __stdcall SetPE32DataForMappedFile(ULONG_PTR FileMapVA, DWORD WhichSection, DWORD WhichData, ULONG_PTR NewDataValue);
	TitanEngine.SetPE32DataForMappedFile:types {"long","long","long","long",abi="stdcall",ret="byte"}
	TE_SetPE32DataForMappedFile = TitanEngine.SetPE32DataForMappedFile
-- __declspec(dllexport) bool __stdcall SetPE32Data(char* szFileName, DWORD WhichSection, DWORD WhichData, ULONG_PTR NewDataValue);
	TitanEngine.SetPE32Data:types {"string","long","long","long",abi="stdcall",ret="byte"}
	TE_SetPE32Data = TitanEngine.SetPE32Data
-- __declspec(dllexport) bool __stdcall SetPE32DataForMappedFileEx(ULONG_PTR FileMapVA, LPVOID DataStorage);
	TitanEngine.SetPE32DataForMappedFileEx:types {"long","pointer",abi="stdcall",ret="byte"}
	TE_SetPE32DataForMappedFileEx = TitanEngine.SetPE32DataForMappedFileEx
-- __declspec(dllexport) bool __stdcall SetPE32DataEx(char* szFileName, LPVOID DataStorage);
	TitanEngine.SetPE32DataEx:types {"string","pointer",abi="stdcall",ret="byte"}
	TE_SetPE32DataEx = TitanEngine.SetPE32DataEx
-- __declspec(dllexport) long __stdcall GetPE32SectionNumberFromVA(ULONG_PTR FileMapVA, ULONG_PTR AddressToConvert);
	TitanEngine.GetPE32SectionNumberFromVA:types {"long","long",abi="stdcall",ret="long"}
	TE_GetPE32SectionNumberFromVA = TitanEngine.GetPE32SectionNumberFromVA
-- __declspec(dllexport) long long __stdcall ConvertVAtoFileOffset(ULONG_PTR FileMapVA, ULONG_PTR AddressToConvert, bool ReturnType);
	TitanEngine.ConvertVAtoFileOffset:types {"long","long","long",abi="stdcall",ret="long"}
	TE_ConvertVAtoFileOffset = TitanEngine.ConvertVAtoFileOffset
-- __declspec(dllexport) long long __stdcall ConvertVAtoFileOffsetEx(ULONG_PTR FileMapVA, DWORD FileSize, ULONG_PTR ImageBase, ULONG_PTR AddressToConvert, bool AddressIsRVA, bool ReturnType);
	TitanEngine.ConvertVAtoFileOffsetEx:types {"long","long","long","long","long","long",abi="stdcall",ret="long"}
	TE_ConvertVAtoFileOffsetEx = TitanEngine.ConvertVAtoFileOffsetEx
-- __declspec(dllexport) long long __stdcall ConvertFileOffsetToVA(ULONG_PTR FileMapVA, ULONG_PTR AddressToConvert, bool ReturnType);
	TitanEngine.ConvertFileOffsetToVA:types {"long","long","long",abi="stdcall",ret="long"}
	TE_ConvertFileOffsetToVA = TitanEngine.ConvertFileOffsetToVA
-- __declspec(dllexport) long long __stdcall ConvertFileOffsetToVAEx(ULONG_PTR FileMapVA, DWORD FileSize, ULONG_PTR ImageBase, ULONG_PTR AddressToConvert, bool ReturnType);
	TitanEngine.ConvertFileOffsetToVAEx:types {"long","long","long","long","long",abi="stdcall",ret="long"}
	TE_ConvertFileOffsetToVAEx = TitanEngine.ConvertFileOffsetToVAEx
--
-- TitanEngine.Realigner.functions:
--
-- __declspec(dllexport) bool __stdcall FixHeaderCheckSum(char* szFileName);
	TitanEngine.FixHeaderCheckSum:types {"string",abi="stdcall",ret="byte"}
	TE_FixHeaderCheckSum = TitanEngine.FixHeaderCheckSum
-- __declspec(dllexport) long __stdcall RealignPE(ULONG_PTR FileMapVA, DWORD FileSize, DWORD RealingMode);
	TitanEngine.RealignPE:types {"long","long","long",abi="stdcall",ret="long"}
	TE_RealignPE = TitanEngine.RealignPE
-- __declspec(dllexport) long __stdcall RealignPEEx(char* szFileName, DWORD RealingFileSize, DWORD ForcedFileAlignment);
	TitanEngine.RealignPEEx:types {"string","long","long",abi="stdcall",ret="long"}
	TE_RealignPEEx = TitanEngine.RealignPEEx
-- __declspec(dllexport) bool __stdcall WipeSection(char* szFileName, int WipeSectionNumber, bool RemovePhysically);
	TitanEngine.WipeSection:types {"string","long","long",abi="stdcall",ret="byte"}
	TE_WipeSection = TitanEngine.WipeSection
-- __declspec(dllexport) bool __stdcall IsPE32FileValidEx(char* szFileName, DWORD CheckDepth, LPVOID FileStatusInfo);
	TitanEngine.IsPE32FileValidEx:types {"string","long","pointer",abi="stdcall",ret="byte"}
	TE_IsPE32FileValidEx = TitanEngine.IsPE32FileValidEx
-- __declspec(dllexport) bool __stdcall FixBrokenPE32FileEx(char* szFileName, LPVOID FileStatusInfo, LPVOID FileFixInfo);
	TitanEngine.FixBrokenPE32FileEx:types {"string","pointer","pointer",abi="stdcall",ret="byte"}
	TE_FixBrokenPE32FileEx = TitanEngine.FixBrokenPE32FileEx
-- __declspec(dllexport) bool __stdcall IsFileDLL(char* szFileName, ULONG_PTR FileMapVA);
	TitanEngine.IsFileDLL:types {"string","long",abi="stdcall",ret="byte"}
	TE_IsFileDLL = TitanEngine.IsFileDLL
--
-- TitanEngine.Hider.functions:
--
-- __declspec(dllexport) void* __stdcall GetPEBLocation(HANDLE hProcess);
	TitanEngine.GetPEBLocation:types {"long",abi="stdcall",ret="pointer"}
	TE_GetPEBLocation = TitanEngine.GetPEBLocation
-- __declspec(dllexport) void* __stdcall GetPEBLocation64(HANDLE hProcess);
	TitanEngine.GetPEBLocation64:types {"long",abi="stdcall",ret="pointer"}
	TE_GetPEBLocation64 = TitanEngine.GetPEBLocation64
-- __declspec(dllexport) bool __stdcall HideDebugger(HANDLE hProcess, DWORD PatchAPILevel);
	TitanEngine.HideDebugger:types {"long","long",abi="stdcall",ret="byte"}
	TE_HideDebugger = TitanEngine.HideDebugger
-- __declspec(dllexport) bool __stdcall UnHideDebugger(HANDLE hProcess, DWORD PatchAPILevel);
	TitanEngine.UnHideDebugger:types {"long","long",abi="stdcall",ret="byte"}
	TE_UnHideDebugger = TitanEngine.UnHideDebugger
--
-- TitanEngine.Relocater.functions:
--
-- __declspec(dllexport) void __stdcall RelocaterCleanup();
	TitanEngine.RelocaterCleanup:types {abi="stdcall"}
	TE_RelocaterCleanup = TitanEngine.RelocaterCleanup
-- __declspec(dllexport) void __stdcall RelocaterInit(DWORD MemorySize, ULONG_PTR OldImageBase, ULONG_PTR NewImageBase);
	TitanEngine.RelocaterInit:types {"long","long","long",abi="stdcall"}
	TE_RelocaterInit = TitanEngine.RelocaterInit
-- __declspec(dllexport) void __stdcall RelocaterAddNewRelocation(HANDLE hProcess, ULONG_PTR RelocateAddress, DWORD RelocateState);
	TitanEngine.RelocaterAddNewRelocation:types {"long","long","long",abi="stdcall"}
	TE_RelocaterAddNewRelocation = TitanEngine.RelocaterAddNewRelocation
-- __declspec(dllexport) long __stdcall RelocaterEstimatedSize();
	TitanEngine.RelocaterEstimatedSize:types {abi="stdcall",ret="long"}
	TE_RelocaterEstimatedSize = TitanEngine.RelocaterEstimatedSize
-- __declspec(dllexport) bool __stdcall RelocaterExportRelocation(ULONG_PTR StorePlace, DWORD StorePlaceRVA, ULONG_PTR FileMapVA);
	TitanEngine.RelocaterExportRelocation:types {"long","long","long",abi="stdcall",ret="byte"}
	TE_RelocaterExportRelocation = TitanEngine.RelocaterExportRelocation
-- __declspec(dllexport) bool __stdcall RelocaterExportRelocationEx(char* szFileName, char* szSectionName);
	TitanEngine.RelocaterExportRelocationEx:types {"string","string",abi="stdcall",ret="byte"}
	TE_RelocaterExportRelocationEx = TitanEngine.RelocaterExportRelocationEx
-- __declspec(dllexport) bool __stdcall RelocaterGrabRelocationTable(HANDLE hProcess, ULONG_PTR MemoryStart, DWORD MemorySize);
	TitanEngine.RelocaterGrabRelocationTable:types {"long","long","long",abi="stdcall",ret="byte"}
	TE_RelocaterGrabRelocationTable = TitanEngine.RelocaterGrabRelocationTable
-- __declspec(dllexport) bool __stdcall RelocaterGrabRelocationTableEx(HANDLE hProcess, ULONG_PTR MemoryStart, ULONG_PTR MemorySize, DWORD NtSizeOfImage);
	TitanEngine.RelocaterGrabRelocationTableEx:types {"long","long","long","long",abi="stdcall",ret="byte"}
	TE_RelocaterGrabRelocationTableEx = TitanEngine.RelocaterGrabRelocationTableEx
-- __declspec(dllexport) bool __stdcall RelocaterMakeSnapshot(HANDLE hProcess, char* szSaveFileName, LPVOID MemoryStart, ULONG_PTR MemorySize);
	TitanEngine.RelocaterMakeSnapshot:types {"long","string","long","long",abi="stdcall",ret="byte"}
	TE_RelocaterMakeSnapshot = TitanEngine.RelocaterMakeSnapshot
-- __declspec(dllexport) bool __stdcall RelocaterCompareTwoSnapshots(HANDLE hProcess, ULONG_PTR LoadedImageBase, ULONG_PTR NtSizeOfImage, char* szDumpFile1, char* szDumpFile2, ULONG_PTR MemStart);
	TitanEngine.RelocaterCompareTwoSnapshots:types {"long","long","long","string","string","long",abi="stdcall",ret="byte"}
	TE_RelocaterCompareTwoSnapshots = TitanEngine.RelocaterCompareTwoSnapshots
-- __declspec(dllexport) bool __stdcall RelocaterChangeFileBase(char* szFileName, ULONG_PTR NewImageBase);
	TitanEngine.RelocaterChangeFileBase:types {"string","long",abi="stdcall",ret="byte"}
	TE_RelocaterChangeFileBase = TitanEngine.RelocaterChangeFileBase
-- __declspec(dllexport) bool __stdcall RelocaterRelocateMemoryBlock(ULONG_PTR FileMapVA, ULONG_PTR MemoryLocation, void* RelocateMemory, DWORD RelocateMemorySize, ULONG_PTR CurrentLoadedBase, ULONG_PTR RelocateBase);
	TitanEngine.RelocaterRelocateMemoryBlock:types {"long","long","long","long","long","long",abi="stdcall",ret="byte"}
	TE_RelocaterRelocateMemoryBlock = TitanEngine.RelocaterRelocateMemoryBlock
-- __declspec(dllexport) bool __stdcall RelocaterWipeRelocationTable(char* szFileName);
	TitanEngine.RelocaterWipeRelocationTable:types {"string",abi="stdcall",ret="byte"}
	TE_RelocaterWipeRelocationTable = TitanEngine.RelocaterWipeRelocationTable
--
-- TitanEngine.Resourcer.functions:
--
-- __declspec(dllexport) long long __stdcall ResourcerLoadFileForResourceUse(char* szFileName);
	TitanEngine.ResourcerLoadFileForResourceUse:types {"string",abi="stdcall",ret="long"}
	TE_ResourcerLoadFileForResourceUse = TitanEngine.ResourcerLoadFileForResourceUse
-- __declspec(dllexport) bool __stdcall ResourcerFreeLoadedFile(LPVOID LoadedFileBase);
	TitanEngine.ResourcerFreeLoadedFile:types {"long",abi="stdcall",ret="byte"}
	TE_ResourcerFreeLoadedFile = TitanEngine.ResourcerFreeLoadedFile
-- __declspec(dllexport) bool __stdcall ResourcerExtractResourceFromFileEx(ULONG_PTR FileMapVA, char* szResourceType, char* szResourceName, char* szExtractedFileName);
	TitanEngine.ResourcerExtractResourceFromFileEx:types {"long","string","string","string",abi="stdcall",ret="byte"}
	TE_ResourcerExtractResourceFromFileEx = TitanEngine.ResourcerExtractResourceFromFileEx
-- __declspec(dllexport) bool __stdcall ResourcerExtractResourceFromFile(char* szFileName, char* szResourceType, char* szResourceName, char* szExtractedFileName);
	TitanEngine.ResourcerExtractResourceFromFile:types {"string","string","string","string",abi="stdcall",ret="byte"}
	TE_ResourcerExtractResourceFromFile = TitanEngine.ResourcerExtractResourceFromFile
-- __declspec(dllexport) bool __stdcall ResourcerFindResource(char* szFileName, char* szResourceType, DWORD ResourceType, char* szResourceName, DWORD ResourceName, DWORD ResourceLanguage, PULONG_PTR pResourceData, LPDWORD pResourceSize);
	TitanEngine.ResourcerFindResource:types {"string","string","long","string","long","long","pointer","pointer",abi="stdcall",ret="byte"}
	TE_ResourcerFindResource = TitanEngine.ResourcerFindResource
-- __declspec(dllexport) void __stdcall ResourcerEnumerateResource(char* szFileName, void* CallBack);
	TitanEngine.ResourcerEnumerateResource:types {"string","callback",abi="stdcall"}
	TE_ResourcerEnumerateResource = TitanEngine.ResourcerEnumerateResource
-- __declspec(dllexport) void __stdcall ResourcerEnumerateResourceEx(ULONG_PTR FileMapVA, DWORD FileSize, void* CallBack);
	TitanEngine.ResourcerEnumerateResourceEx:types {"long","long","callback",abi="stdcall"}
	TE_ResourcerEnumerateResourceEx = TitanEngine.ResourcerEnumerateResourceEx
-- CallBacks:
-- typedef bool(__stdcall *fResourceEnumerator)(wchar_t* szResourceType, DWORD ResourceType, wchar_t* szResourceName, DWORD ResourceName, DWORD ResourceLanguage, DWORD ResourceData, DWORD ResourceSize);
--	TE_ResourcerEnumerateResource_CB = alien.callback(YourFunctionHere, "pointer", "long", "pointer", "long", "long", "long", "long")
--	TE_ResourcerEnumerateResourceEx_CB = alien.callback(YourFunctionHere, "pointer", "long", "pointer", "long", "long", "long", "long")
--
-- TitanEngine.Threader.functions:
--
-- __declspec(dllexport) bool __stdcall ThreaderImportRunningThreadData(DWORD ProcessId);
	TitanEngine.ThreaderImportRunningThreadData:types {"long",abi="stdcall",ret="byte"}
	TE_ThreaderImportRunningThreadData = TitanEngine.ThreaderImportRunningThreadData
-- __declspec(dllexport) void* __stdcall ThreaderGetThreadInfo(HANDLE hThread, DWORD ThreadId);
	TitanEngine.ThreaderGetThreadInfo:types {"long","long",abi="stdcall",ret="pointer"}
	TE_ThreaderGetThreadInfo = TitanEngine.ThreaderGetThreadInfo
-- __declspec(dllexport) void __stdcall ThreaderEnumThreadInfo(void* EnumCallBack);
	TitanEngine.ThreaderEnumThreadInfo:types {"callback",abi="stdcall"}
	TE_ThreaderEnumThreadInfo = TitanEngine.ThreaderEnumThreadInfo
-- __declspec(dllexport) bool __stdcall ThreaderPauseThread(HANDLE hThread);
	TitanEngine.ThreaderPauseThread:types {"long",abi="stdcall",ret="byte"}
	TE_ThreaderPauseThread = TitanEngine.ThreaderPauseThread
-- __declspec(dllexport) bool __stdcall ThreaderResumeThread(HANDLE hThread);
	TitanEngine.ThreaderResumeThread:types {"long",abi="stdcall",ret="byte"}
	TE_ThreaderResumeThread = TitanEngine.ThreaderResumeThread
-- __declspec(dllexport) bool __stdcall ThreaderTerminateThread(HANDLE hThread, DWORD ThreadExitCode);
	TitanEngine.ThreaderTerminateThread:types {"long","long",abi="stdcall",ret="byte"}
	TE_ThreaderTerminateThread = TitanEngine.ThreaderTerminateThread
-- __declspec(dllexport) bool __stdcall ThreaderPauseAllThreads(bool LeaveMainRunning);
	TitanEngine.ThreaderPauseAllThreads:types {"long",abi="stdcall",ret="byte"}
	TE_ThreaderPauseAllThreads = TitanEngine.ThreaderPauseAllThreads
-- __declspec(dllexport) bool __stdcall ThreaderResumeAllThreads(bool LeaveMainPaused);
	TitanEngine.ThreaderResumeAllThreads:types {"long",abi="stdcall",ret="byte"}
	TE_ThreaderResumeAllThreads = TitanEngine.ThreaderResumeAllThreads
-- __declspec(dllexport) bool __stdcall ThreaderPauseProcess();
	TitanEngine.ThreaderPauseProcess:types {abi="stdcall",ret="byte"}
	TE_ThreaderPauseProcess = TitanEngine.ThreaderPauseProcess
-- __declspec(dllexport) bool __stdcall ThreaderResumeProcess();
	TitanEngine.ThreaderResumeProcess:types {abi="stdcall",ret="byte"}
	TE_ThreaderResumeProcess = TitanEngine.ThreaderResumeProcess
-- __declspec(dllexport) long long __stdcall ThreaderCreateRemoteThread(ULONG_PTR ThreadStartAddress, bool AutoCloseTheHandle, LPVOID ThreadPassParameter, LPDWORD ThreadId);
	TitanEngine.ThreaderCreateRemoteThread:types {"long","long","long","pointer",abi="stdcall",ret="long"}
	TE_ThreaderCreateRemoteThread = TitanEngine.ThreaderCreateRemoteThread
-- __declspec(dllexport) bool __stdcall ThreaderInjectAndExecuteCode(LPVOID InjectCode, DWORD StartDelta, DWORD InjectSize);
	TitanEngine.ThreaderInjectAndExecuteCode:types {"pointer","long","long",abi="stdcall",ret="byte"}
	TE_ThreaderInjectAndExecuteCode = TitanEngine.ThreaderInjectAndExecuteCode
-- __declspec(dllexport) long long __stdcall ThreaderCreateRemoteThreadEx(HANDLE hProcess, ULONG_PTR ThreadStartAddress, bool AutoCloseTheHandle, LPVOID ThreadPassParameter, LPDWORD ThreadId);
	TitanEngine.ThreaderCreateRemoteThreadEx:types {"long","long","long","long","pointer",abi="stdcall",ret="long"}
	TE_ThreaderCreateRemoteThreadEx = TitanEngine.ThreaderCreateRemoteThreadEx
-- __declspec(dllexport) bool __stdcall ThreaderInjectAndExecuteCodeEx(HANDLE hProcess, LPVOID InjectCode, DWORD StartDelta, DWORD InjectSize);
	TitanEngine.ThreaderInjectAndExecuteCodeEx:types {"long","long","long","long",abi="stdcall",ret="byte"}
	TE_ThreaderInjectAndExecuteCodeEx = TitanEngine.ThreaderInjectAndExecuteCodeEx
-- __declspec(dllexport) void __stdcall ThreaderSetCallBackForNextExitThreadEvent(LPVOID exitThreadCallBack);
	TitanEngine.ThreaderSetCallBackForNextExitThreadEvent:types {"callback",abi="stdcall"}
	TE_ThreaderSetCallBackForNextExitThreadEvent = TitanEngine.ThreaderSetCallBackForNextExitThreadEvent
-- __declspec(dllexport) bool __stdcall ThreaderIsThreadStillRunning(HANDLE hThread);
	TitanEngine.ThreaderIsThreadStillRunning:types {"long",abi="stdcall",ret="byte"}
	TE_ThreaderIsThreadStillRunning = TitanEngine.ThreaderIsThreadStillRunning
-- __declspec(dllexport) bool __stdcall ThreaderIsThreadActive(HANDLE hThread);
	TitanEngine.ThreaderIsThreadActive:types {"long",abi="stdcall",ret="byte"}
	TE_ThreaderIsThreadActive = TitanEngine.ThreaderIsThreadActive
-- __declspec(dllexport) bool __stdcall ThreaderIsAnyThreadActive();
	TitanEngine.ThreaderIsAnyThreadActive:types {abi="stdcall",ret="byte"}
	TE_ThreaderIsAnyThreadActive = TitanEngine.ThreaderIsAnyThreadActive
-- __declspec(dllexport) bool __stdcall ThreaderExecuteOnlyInjectedThreads();
	TitanEngine.ThreaderExecuteOnlyInjectedThreads:types {abi="stdcall",ret="byte"}
	TE_ThreaderExecuteOnlyInjectedThreads = TitanEngine.ThreaderExecuteOnlyInjectedThreads
-- __declspec(dllexport) long long __stdcall ThreaderGetOpenHandleForThread(DWORD ThreadId);
	TitanEngine.ThreaderGetOpenHandleForThread:types {"long",abi="stdcall",ret="long"}
	TE_ThreaderGetOpenHandleForThread = TitanEngine.ThreaderGetOpenHandleForThread
-- __declspec(dllexport) bool __stdcall ThreaderIsExceptionInMainThread();
	TitanEngine.ThreaderIsExceptionInMainThread:types {abi="stdcall",ret="byte"}
	TE_ThreaderIsExceptionInMainThread = TitanEngine.ThreaderIsExceptionInMainThread
-- CallBacks:
-- typedef void(__stdcall *fEnumCallBack)(LPVOID fThreadDetail);
--	TE_ThreaderEnumThreadInfo_CB = alien.callback(YourFunctionHere, "pointer", abi = "stdcall")
-- typedef void(__stdcall *fCustomHandler)(void* SpecialDBG);
--	TE_ThreaderSetCallBackForNextExitThreadEvent_CB = alien.callback(YourFunctionHere, "pointer", abi = "stdcall")
--
-- TitanEngine.Debugger.functions:
--
-- __declspec(dllexport) void* __stdcall StaticDisassembleEx(ULONG_PTR DisassmStart, LPVOID DisassmAddress);
	TitanEngine.StaticDisassembleEx:types {"long","long",abi="stdcall",ret="string"}
	TE_StaticDisassembleEx = TitanEngine.StaticDisassembleEx
-- __declspec(dllexport) void* __stdcall StaticDisassemble(LPVOID DisassmAddress);
	TitanEngine.StaticDisassemble:types {"long",abi="stdcall",ret="string"}
	TE_StaticDisassemble = TitanEngine.StaticDisassemble
-- __declspec(dllexport) void* __stdcall DisassembleEx(HANDLE hProcess, LPVOID DisassmAddress);
	TitanEngine.DisassembleEx:types {"long","long",abi="stdcall",ret="string"}
	TE_DisassembleEx = TitanEngine.DisassembleEx
-- __declspec(dllexport) void* __stdcall Disassemble(LPVOID DisassmAddress);
	TitanEngine.Disassemble:types {"long",abi="stdcall",ret="string"}
	TE_Disassemble = TitanEngine.Disassemble
-- __declspec(dllexport) long __stdcall StaticLengthDisassemble(LPVOID DisassmAddress);
	TitanEngine.StaticLengthDisassemble:types {"long",abi="stdcall",ret="long"}
	TE_StaticLengthDisassemble = TitanEngine.StaticLengthDisassemble
-- __declspec(dllexport) long __stdcall LengthDisassembleEx(HANDLE hProcess, LPVOID DisassmAddress);
	TitanEngine.LengthDisassembleEx:types {"long","long",abi="stdcall",ret="long"}
	TE_LengthDisassembleEx = TitanEngine.LengthDisassembleEx
-- __declspec(dllexport) long __stdcall LengthDisassemble(LPVOID DisassmAddress);
	TitanEngine.LengthDisassemble:types {"long",abi="stdcall",ret="long"}
	TE_LengthDisassemble = TitanEngine.LengthDisassemble
-- __declspec(dllexport) void* __stdcall InitDebug(char* szFileName, char* szCommandLine, char* szCurrentFolder);
	TitanEngine.InitDebug:types {"string","string","string",abi="stdcall",ret="pointer"}
	TE_InitDebug = TitanEngine.InitDebug
-- __declspec(dllexport) void* __stdcall InitDebugEx(char* szFileName, char* szCommandLine, char* szCurrentFolder, LPVOID EntryCallBack);
	TitanEngine.InitDebugEx:types {"string","string","string","callback",abi="stdcall",ret="pointer"}
	TE_InitDebugEx = TitanEngine.InitDebugEx
-- __declspec(dllexport) void* __stdcall InitDLLDebug(char* szFileName, bool ReserveModuleBase, char* szCommandLine, char* szCurrentFolder, LPVOID EntryCallBack);
	TitanEngine.InitDLLDebug:types {"string","long","string","string","callback",abi="stdcall",ret="pointer"}
	TE_InitDLLDebug = TitanEngine.InitDLLDebug
-- __declspec(dllexport) bool __stdcall StopDebug();
	TitanEngine.StopDebug:types {abi="stdcall",ret="byte"}
	TE_StopDebug = TitanEngine.StopDebug
-- __declspec(dllexport) void __stdcall SetBPXOptions(long DefaultBreakPointType);
	TitanEngine.SetBPXOptions:types {"long",abi="stdcall"}
	TE_SetBPXOptions = TitanEngine.SetBPXOptions
-- __declspec(dllexport) bool __stdcall IsBPXEnabled(ULONG_PTR bpxAddress);
	TitanEngine.IsBPXEnabled:types {"long",abi="stdcall",ret="byte"}
	TE_IsBPXEnabled = TitanEngine.IsBPXEnabled
-- __declspec(dllexport) bool __stdcall EnableBPX(ULONG_PTR bpxAddress);
	TitanEngine.EnableBPX:types {"long",abi="stdcall",ret="byte"}
	TE_EnableBPX = TitanEngine.EnableBPX
-- __declspec(dllexport) bool __stdcall DisableBPX(ULONG_PTR bpxAddress);
	TitanEngine.DisableBPX:types {"long",abi="stdcall",ret="byte"}
	TE_DisableBPX = TitanEngine.DisableBPX
-- __declspec(dllexport) bool __stdcall SetBPX(ULONG_PTR bpxAddress, DWORD bpxType, LPVOID bpxCallBack);
	TitanEngine.SetBPX:types {"long","long","callback",abi="stdcall",ret="byte"}
	TE_SetBPX = TitanEngine.SetBPX
-- __declspec(dllexport) bool __stdcall DeleteBPX(ULONG_PTR bpxAddress);
	TitanEngine.DeleteBPX:types {"long",abi="stdcall",ret="byte"}
	TE_DeleteBPX = TitanEngine.DeleteBPX
-- __declspec(dllexport) bool __stdcall SafeDeleteBPX(ULONG_PTR bpxAddress);
	TitanEngine.SafeDeleteBPX:types {"long",abi="stdcall",ret="byte"}
	TE_SafeDeleteBPX = TitanEngine.SafeDeleteBPX
-- __declspec(dllexport) bool __stdcall SetAPIBreakPoint(char* szDLLName, char* szAPIName, DWORD bpxType, DWORD bpxPlace, LPVOID bpxCallBack);
	TitanEngine.SetAPIBreakPoint:types {"string","string","long","long","callback",abi="stdcall",ret="byte"}
	TE_SetAPIBreakPoint = TitanEngine.SetAPIBreakPoint
-- __declspec(dllexport) bool __stdcall DeleteAPIBreakPoint(char* szDLLName, char* szAPIName, DWORD bpxPlace);
	TitanEngine.DeleteAPIBreakPoint:types {"string","string","long",abi="stdcall",ret="byte"}
	TE_DeleteAPIBreakPoint = TitanEngine.DeleteAPIBreakPoint
-- __declspec(dllexport) bool __stdcall SafeDeleteAPIBreakPoint(char* szDLLName, char* szAPIName, DWORD bpxPlace);
	TitanEngine.SafeDeleteAPIBreakPoint:types {"string","string","long",abi="stdcall",ret="byte"}
	TE_SafeDeleteAPIBreakPoint = TitanEngine.SafeDeleteAPIBreakPoint
-- __declspec(dllexport) bool __stdcall SetMemoryBPX(ULONG_PTR MemoryStart, ULONG_PTR SizeOfMemory, LPVOID bpxCallBack);
	TitanEngine.SetMemoryBPX:types {"long","long","callback",abi="stdcall",ret="byte"}
	TE_SetMemoryBPX = TitanEngine.SetMemoryBPX
-- __declspec(dllexport) bool __stdcall SetMemoryBPXEx(ULONG_PTR MemoryStart, ULONG_PTR SizeOfMemory, DWORD BreakPointType, bool RestoreOnHit, LPVOID bpxCallBack);
	TitanEngine.SetMemoryBPXEx:types {"long","long","long","long","callback",abi="stdcall",ret="byte"}
	TE_SetMemoryBPXEx = TitanEngine.SetMemoryBPXEx
-- __declspec(dllexport) bool __stdcall RemoveMemoryBPX(ULONG_PTR MemoryStart, ULONG_PTR SizeOfMemory);
	TitanEngine.RemoveMemoryBPX:types {"long","long",abi="stdcall",ret="byte"}
	TE_RemoveMemoryBPX = TitanEngine.RemoveMemoryBPX
-- __declspec(dllexport) bool __stdcall GetContextFPUDataEx(HANDLE hActiveThread, void* FPUSaveArea);
	TitanEngine.GetContextFPUDataEx:types {"long","pointer",abi="stdcall",ret="byte"}
	TE_GetContextFPUDataEx = TitanEngine.GetContextFPUDataEx
-- __declspec(dllexport) long long __stdcall GetContextDataEx(HANDLE hActiveThread, DWORD IndexOfRegister);
	TitanEngine.GetContextDataEx:types {"long","long",abi="stdcall",ret="long"}
	TE_GetContextDataEx = TitanEngine.GetContextDataEx
-- __declspec(dllexport) long long __stdcall GetContextData(DWORD IndexOfRegister);
	TitanEngine.GetContextData:types {"long",abi="stdcall",ret="long"}
	TE_GetContextData = TitanEngine.GetContextData
-- __declspec(dllexport) bool __stdcall SetContextFPUDataEx(HANDLE hActiveThread, void* FPUSaveArea);
	TitanEngine.SetContextFPUDataEx:types {"long","pointer",abi="stdcall",ret="byte"}
	TE_SetContextFPUDataEx = TitanEngine.SetContextFPUDataEx
-- __declspec(dllexport) bool __stdcall SetContextDataEx(HANDLE hActiveThread, DWORD IndexOfRegister, ULONG_PTR NewRegisterValue);
	TitanEngine.SetContextDataEx:types {"long","long","long",abi="stdcall",ret="byte"}
	TE_SetContextDataEx = TitanEngine.SetContextDataEx
-- __declspec(dllexport) bool __stdcall SetContextData(DWORD IndexOfRegister, ULONG_PTR NewRegisterValue);
	TitanEngine.SetContextData:types {"long","long",abi="stdcall",ret="byte"}
	TE_SetContextData = TitanEngine.SetContextData
-- __declspec(dllexport) void __stdcall ClearExceptionNumber();
	TitanEngine.ClearExceptionNumber:types {abi="stdcall"}
	TE_ClearExceptionNumber = TitanEngine.ClearExceptionNumber
-- __declspec(dllexport) long __stdcall CurrentExceptionNumber();
	TitanEngine.CurrentExceptionNumber:types {abi="stdcall",ret="long"}
	TE_CurrentExceptionNumber = TitanEngine.CurrentExceptionNumber
-- __declspec(dllexport) bool __stdcall MatchPatternEx(HANDLE hProcess, void* MemoryToCheck, int SizeOfMemoryToCheck, void* PatternToMatch, int SizeOfPatternToMatch, PBYTE WildCard);
	TitanEngine.MatchPatternEx:types {"long","long","long","pointer","long","pointer",abi="stdcall",ret="byte"}
	TE_MatchPatternEx = TitanEngine.MatchPatternEx
-- __declspec(dllexport) bool __stdcall MatchPattern(void* MemoryToCheck, int SizeOfMemoryToCheck, void* PatternToMatch, int SizeOfPatternToMatch, PBYTE WildCard);
	TitanEngine.MatchPattern:types {"long","long","pointer","long","pointer",abi="stdcall",ret="byte"}
	TE_MatchPattern = TitanEngine.MatchPattern
-- __declspec(dllexport) long long __stdcall FindEx(HANDLE hProcess, LPVOID MemoryStart, DWORD MemorySize, LPVOID SearchPattern, DWORD PatternSize, LPBYTE WildCard);
	TitanEngine.FindEx:types {"long","long","long","pointer","long","pointer",abi="stdcall",ret="long"}
	TE_FindEx = TitanEngine.FindEx
-- __declspec(dllexport) long long __stdcall Find(LPVOID MemoryStart, DWORD MemorySize, LPVOID SearchPattern, DWORD PatternSize, LPBYTE WildCard);
	TitanEngine.Find:types {"long","long","pointer","long","pointer",abi="stdcall",ret="long"}
	TE_Find = TitanEngine.Find
-- __declspec(dllexport) bool __stdcall FillEx(HANDLE hProcess, LPVOID MemoryStart, DWORD MemorySize, PBYTE FillByte);
	TitanEngine.FillEx:types {"long","long","long","pointer",abi="stdcall",ret="byte"}
	TE_FillEx = TitanEngine.FillEx
-- __declspec(dllexport) bool __stdcall Fill(LPVOID MemoryStart, DWORD MemorySize, PBYTE FillByte);
	TitanEngine.Fill:types {"long","long","pointer",abi="stdcall",ret="byte"}
	TE_Fill = TitanEngine.Fill
-- __declspec(dllexport) bool __stdcall PatchEx(HANDLE hProcess, LPVOID MemoryStart, DWORD MemorySize, LPVOID ReplacePattern, DWORD ReplaceSize, bool AppendNOP, bool PrependNOP);
	TitanEngine.PatchEx:types {"long","long","long","pointer","long","long","long",abi="stdcall",ret="byte"}
	TE_PatchEx = TitanEngine.PatchEx
-- __declspec(dllexport) bool __stdcall Patch(LPVOID MemoryStart, DWORD MemorySize, LPVOID ReplacePattern, DWORD ReplaceSize, bool AppendNOP, bool PrependNOP);
	TitanEngine.Patch:types {"long","long","pointer","long","long","long",abi="stdcall",ret="byte"}
	TE_Patch = TitanEngine.Patch
-- __declspec(dllexport) bool __stdcall ReplaceEx(HANDLE hProcess, LPVOID MemoryStart, DWORD MemorySize, LPVOID SearchPattern, DWORD PatternSize, DWORD NumberOfRepetitions, LPVOID ReplacePattern, DWORD ReplaceSize, PBYTE WildCard);
	TitanEngine.ReplaceEx:types {"long","long","long","pointer","long","long","pointer","long","pointer",abi="stdcall",ret="byte"}
	TE_ReplaceEx = TitanEngine.ReplaceEx
-- __declspec(dllexport) bool __stdcall Replace(LPVOID MemoryStart, DWORD MemorySize, LPVOID SearchPattern, DWORD PatternSize, DWORD NumberOfRepetitions, LPVOID ReplacePattern, DWORD ReplaceSize, PBYTE WildCard);
	TitanEngine.Replace:types {"long","long","pointer","long","long","pointer","long","pointer",abi="stdcall",ret="byte"}
	TE_Replace = TitanEngine.Replace
-- __declspec(dllexport) void* __stdcall GetDebugData();
	TitanEngine.GetDebugData:types {abi="stdcall",ret="pointer"}
	TE_GetDebugData = TitanEngine.GetDebugData
-- __declspec(dllexport) void* __stdcall GetTerminationData();
	TitanEngine.GetTerminationData:types {abi="stdcall",ret="pointer"}
	TE_GetTerminationData = TitanEngine.GetTerminationData
-- __declspec(dllexport) long __stdcall GetExitCode();
	TitanEngine.GetExitCode:types {abi="stdcall",ret="long"}
	TE_GetExitCode = TitanEngine.GetExitCode
-- __declspec(dllexport) long long __stdcall GetDebuggedDLLBaseAddress();
	TitanEngine.GetDebuggedDLLBaseAddress:types {abi="stdcall",ret="long"}
	TE_GetDebuggedDLLBaseAddress = TitanEngine.GetDebuggedDLLBaseAddress
-- __declspec(dllexport) long long __stdcall GetDebuggedFileBaseAddress();
	TitanEngine.GetDebuggedFileBaseAddress:types {abi="stdcall",ret="long"}
	TE_GetDebuggedFileBaseAddress = TitanEngine.GetDebuggedFileBaseAddress
-- __declspec(dllexport) bool __stdcall GetRemoteString(HANDLE hProcess, LPVOID StringAddress, LPVOID StringStorage, int MaximumStringSize);
	TitanEngine.GetRemoteString:types {"long","long","pointer","long",abi="stdcall",ret="byte"}
	TE_GetRemoteString = TitanEngine.GetRemoteString
-- __declspec(dllexport) long long __stdcall GetFunctionParameter(HANDLE hProcess, DWORD FunctionType, DWORD ParameterNumber, DWORD ParameterType);
	TitanEngine.GetFunctionParameter:types {"long","long","long","long",abi="stdcall",ret="long"}
	TE_GetFunctionParameter = TitanEngine.GetFunctionParameter
-- __declspec(dllexport) long long __stdcall GetJumpDestinationEx(HANDLE hProcess, ULONG_PTR InstructionAddress, bool JustJumps);
	TitanEngine.GetJumpDestinationEx:types {"long","long","long",abi="stdcall",ret="long"}
	TE_GetJumpDestinationEx = TitanEngine.GetJumpDestinationEx
-- __declspec(dllexport) long long __stdcall GetJumpDestination(HANDLE hProcess, ULONG_PTR InstructionAddress);
	TitanEngine.GetJumpDestination:types {"long","long",abi="stdcall",ret="long"}
	TE_GetJumpDestination = TitanEngine.GetJumpDestination
-- __declspec(dllexport) bool __stdcall IsJumpGoingToExecuteEx(HANDLE hProcess, HANDLE hThread, ULONG_PTR InstructionAddress, ULONG_PTR RegFlags);
	TitanEngine.IsJumpGoingToExecuteEx:types {"long","long","long","long",abi="stdcall",ret="byte"}
	TE_IsJumpGoingToExecuteEx = TitanEngine.IsJumpGoingToExecuteEx
-- __declspec(dllexport) bool __stdcall IsJumpGoingToExecute();
	TitanEngine.IsJumpGoingToExecute:types {abi="stdcall",ret="byte"}
	TE_IsJumpGoingToExecute = TitanEngine.IsJumpGoingToExecute
-- __declspec(dllexport) void __stdcall SetCustomHandler(DWORD ExceptionId, LPVOID CallBack);
	TitanEngine.SetCustomHandler:types {"long","callback",abi="stdcall"}
	TE_SetCustomHandler = TitanEngine.SetCustomHandler
-- __declspec(dllexport) void __stdcall ForceClose();
	TitanEngine.ForceClose:types {abi="stdcall"}
	TE_ForceClose = TitanEngine.ForceClose
-- __declspec(dllexport) void __stdcall StepInto(LPVOID traceCallBack);
	TitanEngine.StepInto:types {"callback",abi="stdcall"}
	TE_StepInto = TitanEngine.StepInto
-- __declspec(dllexport) void __stdcall StepOver(LPVOID traceCallBack);
	TitanEngine.StepOver:types {"callback",abi="stdcall"}
	TE_StepOver = TitanEngine.StepOver
-- __declspec(dllexport) void __stdcall SingleStep(DWORD StepCount, LPVOID StepCallBack);
	TitanEngine.SingleStep:types {"long","callback",abi="stdcall"}
	TE_SingleStep = TitanEngine.SingleStep
-- __declspec(dllexport) bool __stdcall GetUnusedHardwareBreakPointRegister(LPDWORD RegisterIndex);
	TitanEngine.GetUnusedHardwareBreakPointRegister:types {"long",abi="stdcall",ret="byte"}
	TE_GetUnusedHardwareBreakPointRegister = TitanEngine.GetUnusedHardwareBreakPointRegister
-- __declspec(dllexport) bool __stdcall SetHardwareBreakPointEx(HANDLE hActiveThread, ULONG_PTR bpxAddress, DWORD IndexOfRegister, DWORD bpxType, DWORD bpxSize, LPVOID bpxCallBack, LPDWORD IndexOfSelectedRegister);
	TitanEngine.SetHardwareBreakPointEx:types {"long","long","long","long","long","callback","pointer",abi="stdcall",ret="byte"}
	TE_SetHardwareBreakPointEx = TitanEngine.SetHardwareBreakPointEx
-- __declspec(dllexport) bool __stdcall SetHardwareBreakPoint(ULONG_PTR bpxAddress, DWORD IndexOfRegister, DWORD bpxType, DWORD bpxSize, LPVOID bpxCallBack);
	TitanEngine.SetHardwareBreakPoint:types {"long","long","long","long","callback",abi="stdcall",ret="byte"}
	TE_SetHardwareBreakPoint = TitanEngine.SetHardwareBreakPoint
-- __declspec(dllexport) bool __stdcall DeleteHardwareBreakPoint(DWORD IndexOfRegister);
	TitanEngine.DeleteHardwareBreakPoint:types {"long",abi="stdcall",ret="byte"}
	TE_DeleteHardwareBreakPoint = TitanEngine.DeleteHardwareBreakPoint
-- __declspec(dllexport) bool __stdcall RemoveAllBreakPoints(DWORD RemoveOption);
	TitanEngine.RemoveAllBreakPoints:types {"long",abi="stdcall",ret="byte"}
	TE_RemoveAllBreakPoints = TitanEngine.RemoveAllBreakPoints
-- __declspec(dllexport) void* __stdcall GetProcessInformation();
	TitanEngine.GetProcessInformation:types {abi="stdcall",ret="pointer"}
	TE_GetProcessInformation = TitanEngine.GetProcessInformation
-- __declspec(dllexport) void* __stdcall GetStartupInformation();
	TitanEngine.GetStartupInformation:types {abi="stdcall",ret="pointer"}
	TE_GetStartupInformation = TitanEngine.GetStartupInformation
-- __declspec(dllexport) void __stdcall DebugLoop();
	TitanEngine.DebugLoop:types {abi="stdcall"}
	TE_DebugLoop = TitanEngine.DebugLoop
-- __declspec(dllexport) void __stdcall SetDebugLoopTimeOut(DWORD TimeOut);
	TitanEngine.SetDebugLoopTimeOut:types {"long",abi="stdcall"}
	TE_SetDebugLoopTimeOut = TitanEngine.SetDebugLoopTimeOut
-- __declspec(dllexport) void __stdcall SetNextDbgContinueStatus(DWORD SetDbgCode);
	TitanEngine.SetNextDbgContinueStatus:types {"long",abi="stdcall"}
	TE_SetNextDbgContinueStatus = TitanEngine.SetNextDbgContinueStatus
-- __declspec(dllexport) bool __stdcall AttachDebugger(DWORD ProcessId, bool KillOnExit, LPVOID DebugInfo, LPVOID CallBack);
	TitanEngine.AttachDebugger:types {"long","long","pointer","callback",abi="stdcall",ret="byte"}
	TE_AttachDebugger = TitanEngine.AttachDebugger
-- __declspec(dllexport) bool __stdcall DetachDebugger(DWORD ProcessId);
	TitanEngine.DetachDebugger:types {"long",abi="stdcall",ret="byte"}
	TE_DetachDebugger = TitanEngine.DetachDebugger
-- __declspec(dllexport) bool __stdcall DetachDebuggerEx(DWORD ProcessId);
	TitanEngine.DetachDebuggerEx:types {"long",abi="stdcall",ret="byte"}
	TE_DetachDebuggerEx = TitanEngine.DetachDebuggerEx
-- __declspec(dllexport) void __stdcall DebugLoopEx(DWORD TimeOut);
	TitanEngine.DebugLoopEx:types {"long",abi="stdcall"}
	TE_DebugLoopEx = TitanEngine.DebugLoopEx
-- __declspec(dllexport) void __stdcall DebugLoop();
	TitanEngine.DebugLoop:types {abi="stdcall"}
	TE_DebugLoop = TitanEngine.DebugLoop
-- __declspec(dllexport) void __stdcall AutoDebugEx(char* szFileName, bool ReserveModuleBase, char* szCommandLine, char* szCurrentFolder, DWORD TimeOut, LPVOID EntryCallBack);
	TitanEngine.AutoDebugEx:types {"string","long","string","string","long","callback",abi="stdcall"}
	TE_AutoDebugEx = TitanEngine.AutoDebugEx
-- __declspec(dllexport) bool __stdcall IsFileBeingDebugged();
	TitanEngine.IsFileBeingDebugged:types {abi="stdcall",ret="byte"}
	TE_IsFileBeingDebugged = TitanEngine.IsFileBeingDebugged
-- __declspec(dllexport) void __stdcall SetErrorModel(bool DisplayErrorMessages);
	TitanEngine.SetErrorModel:types {"byte",abi="stdcall"}
	TE_SetErrorModel = TitanEngine.SetErrorModel
--
-- TitanEngine.FindOEP.functions:
--
-- __declspec(dllexport) void __stdcall FindOEPInit();
	TitanEngine.FindOEPInit:types {abi="stdcall"}
	TE_FindOEPInit = TitanEngine.FindOEPInit
-- __declspec(dllexport) bool __stdcall FindOEPGenerically(char* szFileName, LPVOID TraceInitCallBack, LPVOID CallBack);
	TitanEngine.FindOEPGenerically:types {"string","callback","callback",abi="stdcall",ret="byte"}
	TE_FindOEPGenerically = TitanEngine.FindOEPGenerically
--
-- TitanEngine.Importer.functions:
--
-- __declspec(dllexport) void __stdcall ImporterCleanup();
	TitanEngine.ImporterCleanup:types {abi="stdcall"}
	TE_ImporterCleanup = TitanEngine.ImporterCleanup
-- __declspec(dllexport) void __stdcall ImporterSetImageBase(ULONG_PTR ImageBase);
	TitanEngine.ImporterSetImageBase:types {"long",abi="stdcall"}
	TE_ImporterSetImageBase = TitanEngine.ImporterSetImageBase
-- __declspec(dllexport) void __stdcall ImporterSetUnknownDelta(ULONG_PTR DeltaAddress);
	TitanEngine.ImporterSetUnknownDelta:types {"long",abi="stdcall"}
	TE_ImporterSetUnknownDelta = TitanEngine.ImporterSetUnknownDelta
-- __declspec(dllexport) long long __stdcall ImporterGetCurrentDelta();
	TitanEngine.ImporterGetCurrentDelta:types {abi="stdcall",ret="long"}
	TE_ImporterGetCurrentDelta = TitanEngine.ImporterGetCurrentDelta
-- __declspec(dllexport) void __stdcall ImporterInit(DWORD MemorySize, ULONG_PTR ImageBase);
	TitanEngine.ImporterInit:types {"long","long",abi="stdcall"}
	TE_ImporterInit = TitanEngine.ImporterInit
-- __declspec(dllexport) void __stdcall ImporterAddNewDll(char* szDLLName, ULONG_PTR FirstThunk);
	TitanEngine.ImporterAddNewDll:types {"string","long",abi="stdcall"}
	TE_ImporterAddNewDll = TitanEngine.ImporterAddNewDll
-- __declspec(dllexport) void __stdcall ImporterAddNewAPI(char* szAPIName, ULONG_PTR ThunkValue);
	TitanEngine.ImporterAddNewAPI:types {"string","long",abi="stdcall"}
	TE_ImporterAddNewAPI = TitanEngine.ImporterAddNewAPI
-- __declspec(dllexport) void __stdcall ImporterAddNewOrdinalAPI(ULONG_PTR OrdinalNumber, ULONG_PTR ThunkValue);
	TitanEngine.ImporterAddNewOrdinalAPI:types {"long","long",abi="stdcall"}
	TE_ImporterAddNewOrdinalAPI = TitanEngine.ImporterAddNewOrdinalAPI
-- __declspec(dllexport) long __stdcall ImporterGetAddedDllCount();
	TitanEngine.ImporterGetAddedDllCount:types {abi="stdcall",ret="long"}
	TE_ImporterGetAddedDllCount = TitanEngine.ImporterGetAddedDllCount
-- __declspec(dllexport) long __stdcall ImporterGetAddedAPICount();
	TitanEngine.ImporterGetAddedAPICount:types {abi="stdcall",ret="long"}
	TE_ImporterGetAddedAPICount = TitanEngine.ImporterGetAddedAPICount
-- __declspec(dllexport) void* __stdcall ImporterGetLastAddedDLLName();
	TitanEngine.ImporterGetLastAddedDLLName:types {abi="stdcall",ret="string"}
	TE_ImporterGetLastAddedDLLName = TitanEngine.ImporterGetLastAddedDLLName
-- __declspec(dllexport) void __stdcall ImporterMoveIAT();
	TitanEngine.ImporterMoveIAT:types {abi="stdcall"}
	TE_ImporterMoveIAT = TitanEngine.ImporterMoveIAT
-- __declspec(dllexport) bool __stdcall ImporterExportIAT(ULONG_PTR StorePlace, ULONG_PTR FileMapVA);
	TitanEngine.ImporterExportIAT:types {"long","long",abi="stdcall"}
	TE_ImporterExportIAT = TitanEngine.ImporterExportIAT
-- __declspec(dllexport) long __stdcall ImporterEstimatedSize();
	TitanEngine.ImporterEstimatedSize:types {abi="stdcall",ret="long"}
	TE_ImporterEstimatedSize = TitanEngine.ImporterEstimatedSize
-- __declspec(dllexport) bool __stdcall ImporterExportIATEx(char* szExportFileName, char* szSectionName);
	TitanEngine.ImporterExportIATEx:types {"string","string",abi="stdcall",ret="byte"}
	TE_ImporterExportIATEx = TitanEngine.ImporterExportIATEx
-- __declspec(dllexport) long long __stdcall ImporterFindAPIWriteLocation(char* szAPIName);
	TitanEngine.ImporterFindAPIWriteLocation:types {"string",abi="stdcall",ret="long"}
	TE_ImporterFindAPIWriteLocation = TitanEngine.ImporterFindAPIWriteLocation
-- __declspec(dllexport) long long __stdcall ImporterFindOrdinalAPIWriteLocation(ULONG_PTR OrdinalNumber);
	TitanEngine.ImporterFindOrdinalAPIWriteLocation:types {"long",abi="stdcall",ret="long"}
	TE_ImporterFindOrdinalAPIWriteLocation = TitanEngine.ImporterFindOrdinalAPIWriteLocation
-- __declspec(dllexport) long long __stdcall ImporterFindAPIByWriteLocation(char* szAPIName);
	TitanEngine.ImporterFindAPIByWriteLocation:types {"string",abi="stdcall",ret="long"}
	TE_ImporterFindAPIByWriteLocation = TitanEngine.ImporterFindAPIByWriteLocation
-- __declspec(dllexport) long long __stdcall ImporterFindDLLByWriteLocation(ULONG_PTR APIWriteLocation);
	TitanEngine.ImporterFindDLLByWriteLocation:types {"long",abi="stdcall",ret="long"}
	TE_ImporterFindDLLByWriteLocation = TitanEngine.ImporterFindDLLByWriteLocation
-- __declspec(dllexport) void* __stdcall ImporterGetDLLName(ULONG_PTR APIAddress);
	TitanEngine.ImporterGetDLLName:types {"long",abi="stdcall",ret="string"}
	TE_ImporterGetDLLName = TitanEngine.ImporterGetDLLName
-- __declspec(dllexport) void* __stdcall ImporterGetAPIName(ULONG_PTR APIAddress);
	TitanEngine.ImporterGetAPIName:types {"long",abi="stdcall",ret="string"}
	TE_ImporterGetAPIName = TitanEngine.ImporterGetAPIName
-- __declspec(dllexport) long long __stdcall ImporterGetAPIOrdinalNumber(ULONG_PTR APIAddress);
	TitanEngine.ImporterGetAPIOrdinalNumber:types {"long",abi="stdcall",ret="long"}
	TE_ImporterGetAPIOrdinalNumber = TitanEngine.ImporterGetAPIOrdinalNumber
-- __declspec(dllexport) void* __stdcall ImporterGetAPINameEx(ULONG_PTR APIAddress, ULONG_PTR DLLBasesList);
	TitanEngine.ImporterGetAPINameEx:types {"long","pointer",abi="stdcall",ret="string"}
	TE_ImporterGetAPINameEx = TitanEngine.ImporterGetAPINameEx
-- __declspec(dllexport) long long __stdcall ImporterGetRemoteAPIAddress(HANDLE hProcess, ULONG_PTR APIAddress);
	TitanEngine.ImporterGetRemoteAPIAddress:types {"long","long",abi="stdcall",ret="long"}
	TE_ImporterGetRemoteAPIAddress = TitanEngine.ImporterGetRemoteAPIAddress
-- __declspec(dllexport) long long __stdcall ImporterGetRemoteAPIAddressEx(char* szDLLName, char* szAPIName);
	TitanEngine.ImporterGetRemoteAPIAddressEx:types {"string","string",abi="stdcall",ret="long"}
	TE_ImporterGetRemoteAPIAddressEx = TitanEngine.ImporterGetRemoteAPIAddressEx
-- __declspec(dllexport) long long __stdcall ImporterGetLocalAPIAddress(HANDLE hProcess, ULONG_PTR APIAddress);
	TitanEngine.ImporterGetLocalAPIAddress:types {"long","long",abi="stdcall",ret="long"}
	TE_ImporterGetLocalAPIAddress = TitanEngine.ImporterGetLocalAPIAddress
-- __declspec(dllexport) void* __stdcall ImporterGetDLLNameFromDebugee(HANDLE hProcess, ULONG_PTR APIAddress);
	TitanEngine.ImporterGetDLLNameFromDebugee:types {"long","long",abi="stdcall",ret="string"}
	TE_ImporterGetDLLNameFromDebugee = TitanEngine.ImporterGetDLLNameFromDebugee
-- __declspec(dllexport) void* __stdcall ImporterGetAPINameFromDebugee(HANDLE hProcess, ULONG_PTR APIAddress);
	TitanEngine.ImporterGetAPINameFromDebugee:types {"long","long",abi="stdcall",ret="string"}
	TE_ImporterGetAPINameFromDebugee = TitanEngine.ImporterGetAPINameFromDebugee
-- __declspec(dllexport) long long __stdcall ImporterGetAPIOrdinalNumberFromDebugee(HANDLE hProcess, ULONG_PTR APIAddress);
	TitanEngine.ImporterGetAPIOrdinalNumberFromDebugee:types {"long","long",abi="stdcall",ret="long"}
	TE_ImporterGetAPIOrdinalNumberFromDebugee = TitanEngine.ImporterGetAPIOrdinalNumberFromDebugee
-- __declspec(dllexport) long __stdcall ImporterGetDLLIndexEx(ULONG_PTR APIAddress, ULONG_PTR DLLBasesList);
	TitanEngine.ImporterGetDLLIndexEx:types {"long","pointer",abi="stdcall",ret="long"}
	TE_ImporterGetDLLIndexEx = TitanEngine.ImporterGetDLLIndexEx
-- __declspec(dllexport) long __stdcall ImporterGetDLLIndex(HANDLE hProcess, ULONG_PTR APIAddress, ULONG_PTR DLLBasesList);
	TitanEngine.ImporterGetDLLIndex:types {"long","long","pointer",abi="stdcall",ret="long"}
	TE_ImporterGetDLLIndex = TitanEngine.ImporterGetDLLIndex
-- __declspec(dllexport) long long __stdcall ImporterGetRemoteDLLBase(HANDLE hProcess, HMODULE LocalModuleBase);
	TitanEngine.ImporterGetRemoteDLLBase:types {"long","long",abi="stdcall",ret="long"}
	TE_ImporterGetRemoteDLLBase = TitanEngine.ImporterGetRemoteDLLBase
-- __declspec(dllexport) bool __stdcall ImporterRelocateWriteLocation(ULONG_PTR AddValue);
	TitanEngine.ImporterRelocateWriteLocation:types {"long",abi="stdcall",ret="byte"}
	TE_ImporterRelocateWriteLocation = TitanEngine.ImporterRelocateWriteLocation
-- __declspec(dllexport) bool __stdcall ImporterIsForwardedAPI(HANDLE hProcess, ULONG_PTR APIAddress);
	TitanEngine.ImporterIsForwardedAPI:types {"long","long",abi="stdcall",ret="byte"}
	TE_ImporterIsForwardedAPI = TitanEngine.ImporterIsForwardedAPI
-- __declspec(dllexport) void* __stdcall ImporterGetForwardedAPIName(HANDLE hProcess, ULONG_PTR APIAddress);
	TitanEngine.ImporterGetForwardedAPIName:types {"long","long",abi="stdcall",ret="string"}
	TE_ImporterGetForwardedAPIName = TitanEngine.ImporterGetForwardedAPIName
-- __declspec(dllexport) void* __stdcall ImporterGetForwardedDLLName(HANDLE hProcess, ULONG_PTR APIAddress);
	TitanEngine.ImporterGetForwardedDLLName:types {"long","long",abi="stdcall",ret="string"}
	TE_ImporterGetForwardedDLLName = TitanEngine.ImporterGetForwardedDLLName
-- __declspec(dllexport) long __stdcall ImporterGetForwardedDLLIndex(HANDLE hProcess, ULONG_PTR APIAddress, ULONG_PTR DLLBasesList);
	TitanEngine.ImporterGetForwardedDLLIndex:types {"long","long","pointer",abi="stdcall",ret="long"}
	TE_ImporterGetForwardedDLLIndex = TitanEngine.ImporterGetForwardedDLLIndex
-- __declspec(dllexport) long long __stdcall ImporterGetForwardedAPIOrdinalNumber(HANDLE hProcess, ULONG_PTR APIAddress);
	TitanEngine.ImporterGetForwardedAPIOrdinalNumber:types {"long","long",abi="stdcall",ret="long"}
	TE_ImporterGetForwardedAPIOrdinalNumber = TitanEngine.ImporterGetForwardedAPIOrdinalNumber
-- __declspec(dllexport) long long __stdcall ImporterGetNearestAPIAddress(HANDLE hProcess, ULONG_PTR APIAddress);
	TitanEngine.ImporterGetNearestAPIAddress:types {"long","long",abi="stdcall",ret="long"}
	TE_ImporterGetNearestAPIAddress = TitanEngine.ImporterGetNearestAPIAddress
-- __declspec(dllexport) void* __stdcall ImporterGetNearestAPIName(HANDLE hProcess, ULONG_PTR APIAddress);
	TitanEngine.ImporterGetNearestAPIName:types {"long","long",abi="stdcall",ret="string"}
	TE_ImporterGetNearestAPIName = TitanEngine.ImporterGetNearestAPIName
-- __declspec(dllexport) bool __stdcall ImporterCopyOriginalIAT(char* szOriginalFile, char* szDumpFile);
	TitanEngine.ImporterCopyOriginalIAT:types {"string","string",abi="stdcall",ret="byte"}
	TE_ImporterCopyOriginalIAT = TitanEngine.ImporterCopyOriginalIAT
-- __declspec(dllexport) bool __stdcall ImporterLoadImportTable(char* szFileName);
	TitanEngine.ImporterLoadImportTable:types {"string",abi="stdcall",ret="byte"}
	TE_ImporterLoadImportTable = TitanEngine.ImporterLoadImportTable
-- __declspec(dllexport) bool __stdcall ImporterMoveOriginalIAT(char* szOriginalFile, char* szDumpFile, char* szSectionName);
	TitanEngine.ImporterMoveOriginalIAT:types {"string","string","string",abi="stdcall",ret="byte"}
	TE_ImporterMoveOriginalIAT = TitanEngine.ImporterMoveOriginalIAT
-- __declspec(dllexport) void __stdcall ImporterAutoSearchIAT(HANDLE hProcess, char* szFileName, ULONG_PTR ImageBase, ULONG_PTR SearchStart, DWORD SearchSize, LPVOID pIATStart, LPVOID pIATSize);
	TitanEngine.ImporterAutoSearchIAT:types {"long","string","long","long","long","pointer","pointer",abi="stdcall"}
	TE_ImporterAutoSearchIAT = TitanEngine.ImporterAutoSearchIAT
-- __declspec(dllexport) void __stdcall ImporterAutoSearchIATEx(HANDLE hProcess, ULONG_PTR ImageBase, ULONG_PTR SearchStart, DWORD SearchSize, LPVOID pIATStart, LPVOID pIATSize);
	TitanEngine.ImporterAutoSearchIATEx:types {"long","long","long","long","pointer","pointer",abi="stdcall"}
	TE_ImporterAutoSearchIATEx = TitanEngine.ImporterAutoSearchIATEx
-- __declspec(dllexport) void __stdcall ImporterEnumAddedData(LPVOID EnumCallBack);
	TitanEngine.ImporterEnumAddedData:types {"callback",abi="stdcall"}
	TE_ImporterEnumAddedData = TitanEngine.ImporterEnumAddedData
-- __declspec(dllexport) long __stdcall ImporterAutoFixIATEx(HANDLE hProcess, char* szDumpedFile, char* szSectionName, bool DumpRunningProcess, bool RealignFile, ULONG_PTR EntryPointAddress, ULONG_PTR ImageBase, ULONG_PTR SearchStart, DWORD SearchSize, DWORD SearchStep, bool TryAutoFix, bool FixEliminations, LPVOID UnknownPointerFixCallback);
	TitanEngine.ImporterAutoSearchIATEx:types {"long","string","string","long","long","long","long","long","long","long","long","long","callback",abi="stdcall",ret="long"}
	TE_ImporterAutoSearchIATEx = TitanEngine.ImporterAutoSearchIATEx
-- __declspec(dllexport) long __stdcall ImporterAutoFixIAT(HANDLE hProcess, char* szDumpedFile, ULONG_PTR ImageBase, ULONG_PTR SearchStart, DWORD SearchSize, DWORD SearchStep);
	TitanEngine.ImporterAutoFixIAT:types {"long","string","long","long","long","long",abi="stdcall",ret="long"}
	TE_ImporterAutoFixIAT = TitanEngine.ImporterAutoFixIAT
--
--  Global.Engine.Hook.functions:
--
-- __declspec(dllexport) bool __stdcall HooksSafeTransitionEx(LPVOID HookAddressArray, int NumberOfHooks, bool TransitionStart);
	TitanEngine.HooksSafeTransitionEx:types {"pointer","long","long",abi="stdcall",ret="byte"}
	TE_HooksSafeTransitionEx = TitanEngine.HooksSafeTransitionEx
-- __declspec(dllexport) bool __stdcall HooksSafeTransition(LPVOID HookAddress, bool TransitionStart);
	TitanEngine.HooksSafeTransition:types {"long","long",abi="stdcall",ret="byte"}
	TE_HooksSafeTransition = TitanEngine.HooksSafeTransition
-- __declspec(dllexport) bool __stdcall HooksIsAddressRedirected(LPVOID HookAddress);
	TitanEngine.HooksIsAddressRedirected:types {"long",abi="stdcall",ret="byte"}
	TE_HooksIsAddressRedirected = TitanEngine.HooksIsAddressRedirected
-- __declspec(dllexport) void* __stdcall HooksGetTrampolineAddress(LPVOID HookAddress);
	TitanEngine.HooksGetTrampolineAddress:types {"long",abi="stdcall",ret="pointer"}
	TE_HooksGetTrampolineAddress = TitanEngine.HooksGetTrampolineAddress
-- __declspec(dllexport) void* __stdcall HooksGetHookEntryDetails(LPVOID HookAddress);
	TitanEngine.HooksGetHookEntryDetails:types {"long",abi="stdcall",ret="pointer"}
	TE_HooksGetHookEntryDetails = TitanEngine.HooksGetHookEntryDetails
-- __declspec(dllexport) bool __stdcall HooksInsertNewRedirection(LPVOID HookAddress, LPVOID RedirectTo, int HookType);
	TitanEngine.HooksInsertNewRedirection:types {"long","long","long",abi="stdcall",ret="byte"}
	TE_HooksInsertNewRedirection = TitanEngine.HooksInsertNewRedirection
-- __declspec(dllexport) bool __stdcall HooksInsertNewIATRedirectionEx(ULONG_PTR FileMapVA, ULONG_PTR LoadedModuleBase, char* szHookFunction, LPVOID RedirectTo);
	TitanEngine.HooksInsertNewIATRedirectionEx:types {"long","long","string","long",abi="stdcall",ret="byte"}
	TE_HooksInsertNewIATRedirectionEx = TitanEngine.HooksInsertNewIATRedirectionEx
-- __declspec(dllexport) bool __stdcall HooksInsertNewIATRedirection(char* szModuleName, char* szHookFunction, LPVOID RedirectTo);
	TitanEngine.HooksInsertNewIATRedirection:types {"string","string","long",abi="stdcall",ret="byte"}
	TE_HooksInsertNewIATRedirection = TitanEngine.HooksInsertNewIATRedirection
-- __declspec(dllexport) bool __stdcall HooksRemoveRedirection(LPVOID HookAddress, bool RemoveAll);
	TitanEngine.HooksRemoveRedirection:types {"long","long",abi="stdcall",ret="byte"}
	TE_HooksRemoveRedirection = TitanEngine.HooksRemoveRedirection
-- __declspec(dllexport) bool __stdcall HooksRemoveRedirectionsForModule(HMODULE ModuleBase);
	TitanEngine.HooksRemoveRedirectionsForModule:types {"long",abi="stdcall",ret="byte"}
	TE_HooksRemoveRedirectionsForModule = TitanEngine.HooksRemoveRedirectionsForModule
-- __declspec(dllexport) bool __stdcall HooksRemoveIATRedirection(char* szModuleName, char* szHookFunction, bool RemoveAll);
	TitanEngine.HooksRemoveIATRedirection:types {"string","string","long",abi="stdcall",ret="byte"}
	TE_HooksRemoveIATRedirection = TitanEngine.HooksRemoveIATRedirection
-- __declspec(dllexport) bool __stdcall HooksDisableRedirection(LPVOID HookAddress, bool DisableAll);
	TitanEngine.HooksDisableRedirection:types {"long","long",abi="stdcall",ret="byte"}
	TE_HooksDisableRedirection = TitanEngine.HooksDisableRedirection
-- __declspec(dllexport) bool __stdcall HooksDisableRedirectionsForModule(HMODULE ModuleBase);
	TitanEngine.HooksDisableRedirectionsForModule:types {"long",abi="stdcall",ret="byte"}
	TE_HooksDisableRedirectionsForModule = TitanEngine.HooksDisableRedirectionsForModule
-- __declspec(dllexport) bool __stdcall HooksDisableIATRedirection(char* szModuleName, char* szHookFunction, bool DisableAll);
	TitanEngine.HooksDisableIATRedirection:types {"string","string","long",abi="stdcall",ret="byte"}
	TE_HooksDisableIATRedirection = TitanEngine.HooksDisableIATRedirection
-- __declspec(dllexport) bool __stdcall HooksEnableRedirection(LPVOID HookAddress, bool EnableAll);
	TitanEngine.HooksEnableRedirection:types {"long","long",abi="stdcall",ret="byte"}
	TE_HooksEnableRedirection = TitanEngine.HooksEnableRedirection
-- __declspec(dllexport) bool __stdcall HooksEnableRedirectionsForModule(HMODULE ModuleBase);
	TitanEngine.HooksEnableRedirectionsForModule:types {"long",abi="stdcall",ret="byte"}
	TE_HooksEnableRedirectionsForModule = TitanEngine.HooksEnableRedirectionsForModule
-- __declspec(dllexport) bool __stdcall HooksEnableIATRedirection(char* szModuleName, char* szHookFunction, bool EnableAll);
	TitanEngine.HooksEnableIATRedirection:types {"string","string","long",abi="stdcall",ret="byte"}
	TE_HooksEnableIATRedirection = TitanEngine.HooksEnableIATRedirection
-- __declspec(dllexport) void __stdcall HooksScanModuleMemory(HMODULE ModuleBase, LPVOID CallBack);
	TitanEngine.HooksScanModuleMemory:types {"long","callback",abi="stdcall"}
	TE_HooksScanModuleMemory = TitanEngine.HooksScanModuleMemory
-- __declspec(dllexport) void __stdcall HooksScanEntireProcessMemory(LPVOID CallBack);
	TitanEngine.HooksScanModuleMemory:types {"callback",abi="stdcall"}
	TE_HooksScanModuleMemory = TitanEngine.HooksScanModuleMemory
-- __declspec(dllexport) void __stdcall HooksScanEntireProcessMemoryEx();
	TitanEngine.HooksScanEntireProcessMemoryEx:types {abi="stdcall"}
	TE_HooksScanEntireProcessMemoryEx = TitanEngine.HooksScanEntireProcessMemoryEx
--
-- TitanEngine.Tracer.functions:
--
-- __declspec(dllexport) void __stdcall TracerInit();
	TitanEngine.TracerInit:types {abi="stdcall"}
	TE_TracerInit = TitanEngine.TracerInit
-- __declspec(dllexport) long long __stdcall TracerLevel1(HANDLE hProcess, ULONG_PTR AddressToTrace);
	TitanEngine.TracerLevel1:types {"long","long",abi="stdcall",ret="long"}
	TE_TracerLevel1 = TitanEngine.TracerLevel1
-- __declspec(dllexport) long long __stdcall HashTracerLevel1(HANDLE hProcess, ULONG_PTR AddressToTrace, DWORD InputNumberOfInstructions);
	TitanEngine.HashTracerLevel1:types {"long","long","long",abi="stdcall",ret="long"}
	TE_HashTracerLevel1 = TitanEngine.HashTracerLevel1
-- __declspec(dllexport) long __stdcall TracerDetectRedirection(HANDLE hProcess, ULONG_PTR AddressToTrace);
	TitanEngine.TracerDetectRedirection:types {"long","long",abi="stdcall",ret="long"}
	TE_TracerDetectRedirection = TitanEngine.TracerDetectRedirection
-- __declspec(dllexport) long long __stdcall TracerFixKnownRedirection(HANDLE hProcess, ULONG_PTR AddressToTrace, DWORD RedirectionId);
	TitanEngine.TracerFixKnownRedirection:types {"long","long","long",abi="stdcall",ret="long"}
	TE_TracerFixKnownRedirection = TitanEngine.TracerFixKnownRedirection
-- __declspec(dllexport) long __stdcall TracerFixRedirectionViaImpRecPlugin(HANDLE hProcess, char* szPluginName, ULONG_PTR AddressToTrace);
	TitanEngine.TracerFixRedirectionViaImpRecPlugin:types {"long","string","long",abi="stdcall",ret="long"}
	TE_TracerFixRedirectionViaImpRecPlugin = TitanEngine.TracerFixRedirectionViaImpRecPlugin
--
-- TitanEngine.Exporter.functions:
--
-- __declspec(dllexport) void __stdcall ExporterCleanup();
	TitanEngine.ExporterCleanup:types {abi="stdcall"}
	TE_ExporterCleanup = TitanEngine.ExporterCleanup
-- __declspec(dllexport) void __stdcall ExporterSetImageBase(ULONG_PTR ImageBase);
	TitanEngine.ExporterSetImageBase:types {"long",abi="stdcall"}
	TE_ExporterSetImageBase = TitanEngine.ExporterSetImageBase
-- __declspec(dllexport) void __stdcall ExporterInit(DWORD MemorySize, ULONG_PTR ImageBase, DWORD ExportOrdinalBase, char* szExportModuleName);
	TitanEngine.ExporterInit:types {"long","long","long","string",abi="stdcall"}
	TE_ExporterInit = TitanEngine.ExporterInit
-- __declspec(dllexport) bool __stdcall ExporterAddNewExport(char* szExportName, DWORD ExportRelativeAddress);
	TitanEngine.ExporterAddNewExport:types {"string","long",abi="stdcall",ret="byte"}
	TE_ExporterAddNewExport = TitanEngine.ExporterAddNewExport
-- __declspec(dllexport) bool __stdcall ExporterAddNewOrdinalExport(DWORD OrdinalNumber, DWORD ExportRelativeAddress);
	TitanEngine.ExporterAddNewOrdinalExport:types {"long","long",abi="stdcall",ret="byte"}
	TE_ExporterAddNewOrdinalExport = TitanEngine.ExporterAddNewOrdinalExport
-- __declspec(dllexport) long __stdcall ExporterGetAddedExportCount();
	TitanEngine.ExporterGetAddedExportCount:types {abi="stdcall",ret="long"}
	TE_ExporterGetAddedExportCount = TitanEngine.ExporterGetAddedExportCount
-- __declspec(dllexport) long __stdcall ExporterEstimatedSize();
	TitanEngine.ExporterEstimatedSize:types {abi="stdcall",ret="long"}
	TE_ExporterEstimatedSize = TitanEngine.ExporterEstimatedSize
-- __declspec(dllexport) bool __stdcall ExporterBuildExportTable(ULONG_PTR StorePlace, ULONG_PTR FileMapVA);
	TitanEngine.ExporterBuildExportTable:types {"long","long",abi="stdcall",ret="byte"}
	TE_ExporterBuildExportTable = TitanEngine.ExporterBuildExportTable
-- __declspec(dllexport) bool __stdcall ExporterBuildExportTableEx(char* szExportFileName, char* szSectionName);
	TitanEngine.ExporterBuildExportTableEx:types {"string","string",abi="stdcall",ret="byte"}
	TE_ExporterBuildExportTableEx = TitanEngine.ExporterBuildExportTableEx
-- __declspec(dllexport) bool __stdcall ExporterLoadExportTable(char* szFileName);
	TitanEngine.ExporterLoadExportTable:types {"string",abi="stdcall",ret="byte"}
	TE_ExporterLoadExportTable = TitanEngine.ExporterLoadExportTable
--
-- TitanEngine.Librarian.functions:
--
-- __declspec(dllexport) bool __stdcall LibrarianSetBreakPoint(char* szLibraryName, DWORD bpxType, bool SingleShoot, LPVOID bpxCallBack);
	TitanEngine.LibrarianSetBreakPoint:types {"string","long","long","callback",abi="stdcall",ret="byte"}
	TE_LibrarianSetBreakPoint = TitanEngine.LibrarianSetBreakPoint
-- __declspec(dllexport) bool __stdcall LibrarianRemoveBreakPoint(char* szLibraryName, DWORD bpxType);
	TitanEngine.LibrarianRemoveBreakPoint:types {"string","long",abi="stdcall",ret="byte"}
	TE_LibrarianRemoveBreakPoint = TitanEngine.LibrarianRemoveBreakPoint
-- __declspec(dllexport) void* __stdcall LibrarianGetLibraryInfo(char* szLibraryName);
	TitanEngine.LibrarianGetLibraryInfo:types {"string",abi="stdcall",ret="pointer"}
	TE_LibrarianGetLibraryInfo = TitanEngine.LibrarianGetLibraryInfo
-- __declspec(dllexport) void* __stdcall LibrarianGetLibraryInfoEx(void* BaseOfDll);
	TitanEngine.LibrarianGetLibraryInfoEx:types {"long",abi="stdcall",ret="pointer"}
	TE_LibrarianGetLibraryInfoEx = TitanEngine.LibrarianGetLibraryInfoEx
-- __declspec(dllexport) void __stdcall LibrarianEnumLibraryInfo(void* EnumCallBack);
	TitanEngine.LibrarianEnumLibraryInfo:types {"callback",abi="stdcall"}
	TE_LibrarianEnumLibraryInfo = TitanEngine.LibrarianEnumLibraryInfo
--
-- TitanEngine.Process.functions:
--
-- __declspec(dllexport) long __stdcall GetActiveProcessId(char* szImageName);
	TitanEngine.GetActiveProcessId:types {"string",abi="stdcall",ret="long"}
	TE_GetActiveProcessId = TitanEngine.GetActiveProcessId
-- __declspec(dllexport) void __stdcall EnumProcessesWithLibrary(char* szLibraryName, void* EnumFunction);
	TitanEngine.EnumProcessesWithLibrary:types {"string","callback",abi="stdcall"}
	TE_EnumProcessesWithLibrary = TitanEngine.EnumProcessesWithLibrary
--
-- TitanEngine.TLSFixer.functions:
--
-- __declspec(dllexport) bool __stdcall TLSBreakOnCallBack(LPVOID ArrayOfCallBacks, DWORD NumberOfCallBacks, LPVOID bpxCallBack);
	TitanEngine.TLSBreakOnCallBack:types {"pointer","long","callback",abi="stdcall",ret="byte"}
	TE_TLSBreakOnCallBack = TitanEngine.TLSBreakOnCallBack
-- __declspec(dllexport) bool __stdcall TLSGrabCallBackData(char* szFileName, LPVOID ArrayOfCallBacks, LPDWORD NumberOfCallBacks);
	TitanEngine.TLSGrabCallBackData:types {"string","pointer","pointer",abi="stdcall",ret="byte"}
	TE_TLSGrabCallBackData = TitanEngine.TLSGrabCallBackData
-- __declspec(dllexport) bool __stdcall TLSBreakOnCallBackEx(char* szFileName, LPVOID bpxCallBack);
	TitanEngine.TLSBreakOnCallBackEx:types {"string","callback",abi="stdcall",ret="byte"}
	TE_TLSBreakOnCallBackEx = TitanEngine.TLSBreakOnCallBackEx
-- __declspec(dllexport) bool __stdcall TLSRemoveCallback(char* szFileName);
	TitanEngine.TLSRemoveCallback:types {"string",abi="stdcall",ret="byte"}
	TE_TLSRemoveCallback = TitanEngine.TLSRemoveCallback
-- __declspec(dllexport) bool __stdcall TLSRemoveTable(char* szFileName);
	TitanEngine.TLSRemoveTable:types {"string",abi="stdcall",ret="byte"}
	TE_TLSRemoveTable = TitanEngine.TLSRemoveTable
-- __declspec(dllexport) bool __stdcall TLSBackupData(char* szFileName);
	TitanEngine.TLSBackupData:types {"string",abi="stdcall",ret="byte"}
	TE_TLSBackupData = TitanEngine.TLSBackupData
-- __declspec(dllexport) bool __stdcall TLSRestoreData();
	TitanEngine.TLSRestoreData:types {abi="stdcall",ret="byte"}
	TE_TLSRestoreData = TitanEngine.TLSRestoreData
-- __declspec(dllexport) bool __stdcall TLSBuildNewTable(ULONG_PTR FileMapVA, ULONG_PTR StorePlace, ULONG_PTR StorePlaceRVA, LPVOID ArrayOfCallBacks, DWORD NumberOfCallBacks);
	TitanEngine.TLSBuildNewTable:types {"long","long","long","pointer","long",abi="stdcall",ret="byte"}
	TE_TLSBuildNewTable = TitanEngine.TLSBuildNewTable
-- __declspec(dllexport) bool __stdcall TLSBuildNewTableEx(char* szFileName, char* szSectionName, LPVOID ArrayOfCallBacks, DWORD NumberOfCallBacks);
	TitanEngine.TLSBuildNewTableEx:types {"string","string","pointer","long",abi="stdcall",ret="byte"}
	TE_TLSBuildNewTableEx = TitanEngine.TLSBuildNewTableEx
--
--  TitanEngine.Handler.functions:
--
-- __declspec(dllexport) long __stdcall HandlerGetActiveHandleCount(DWORD ProcessId);
	TitanEngine.HandlerGetActiveHandleCount:types {"long",abi="stdcall",ret="long"}
	TE_HandlerGetActiveHandleCount = TitanEngine.HandlerGetActiveHandleCount
-- __declspec(dllexport) bool __stdcall HandlerIsHandleOpen(DWORD ProcessId, HANDLE hHandle);
	TitanEngine.HandlerIsHandleOpen:types {"long","long",abi="stdcall",ret="byte"}
	TE_HandlerIsHandleOpen = TitanEngine.HandlerIsHandleOpen
-- __declspec(dllexport) void* __stdcall HandlerGetHandleName(HANDLE hProcess, DWORD ProcessId, HANDLE hHandle, bool TranslateName);
	TitanEngine.HandlerGetHandleName:types {"long","long","long","long",abi="stdcall",ret="string"}
	TE_HandlerGetHandleName = TitanEngine.HandlerGetHandleName
-- __declspec(dllexport) long __stdcall HandlerEnumerateOpenHandles(DWORD ProcessId, LPVOID HandleBuffer, DWORD MaxHandleCount);
	TitanEngine.HandlerEnumerateOpenHandles:types {"long","pointer","long",abi="stdcall",ret="long"}
	TE_HandlerEnumerateOpenHandles = TitanEngine.HandlerEnumerateOpenHandles
-- __declspec(dllexport) long long __stdcall HandlerGetHandleDetails(HANDLE hProcess, DWORD ProcessId, HANDLE hHandle, DWORD InformationReturn);
	TitanEngine.HandlerGetHandleDetails:types {"long","long","long","long",abi="stdcall",ret="long"}
	TE_HandlerGetHandleDetails = TitanEngine.HandlerGetHandleDetails
-- __declspec(dllexport) bool __stdcall HandlerCloseRemoteHandle(HANDLE hProcess, HANDLE hHandle);
	TitanEngine.HandlerCloseRemoteHandle:types {"long","long",abi="stdcall",ret="byte"}
	TE_HandlerCloseRemoteHandle = TitanEngine.HandlerCloseRemoteHandle
-- __declspec(dllexport) long __stdcall HandlerEnumerateLockHandles(char* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated, LPVOID HandleDataBuffer, DWORD MaxHandleCount);
	TitanEngine.HandlerEnumerateLockHandles:types {"string","long","long","pointer","long",abi="stdcall",ret="long"}
	TE_HandlerEnumerateLockHandles = TitanEngine.HandlerEnumerateLockHandles
-- __declspec(dllexport) bool __stdcall HandlerCloseAllLockHandles(char* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated);
	TitanEngine.HandlerCloseAllLockHandles:types {"string","long","long",abi="stdcall",ret="byte"}
	TE_HandlerCloseAllLockHandles = TitanEngine.HandlerCloseAllLockHandles
-- __declspec(dllexport) bool __stdcall HandlerIsFileLocked(char* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated);
	TitanEngine.HandlerIsFileLocked:types {"string","long","long",abi="stdcall",ret="byte"}
	TE_HandlerIsFileLocked = TitanEngine.HandlerIsFileLocked
-- __declspec(dllexport) long __stdcall HandlerEnumerateOpenMutexes(HANDLE hProcess, DWORD ProcessId, LPVOID HandleBuffer, DWORD MaxHandleCount);
	TitanEngine.HandlerEnumerateOpenMutexes:types {"long","long","pointer","long",abi="stdcall",ret="long"}
	TE_HandlerEnumerateOpenMutexes = TitanEngine.HandlerEnumerateOpenMutexes
-- __declspec(dllexport) long long __stdcall HandlerGetOpenMutexHandle(HANDLE hProcess, DWORD ProcessId, char* szMutexString);
	TitanEngine.HandlerGetOpenMutexHandle:types {"long","long","string",abi="stdcall",ret="long"}
	TE_HandlerGetOpenMutexHandle = TitanEngine.HandlerGetOpenMutexHandle
-- ___declspec(dllexport) long __stdcall HandlerGetProcessIdWhichCreatedMutex(char* szMutexString);
	TitanEngine.HandlerGetProcessIdWhichCreatedMutex:types {"string",abi="stdcall",ret="long"}
	TE_HandlerGetProcessIdWhichCreatedMutex = TitanEngine.HandlerGetProcessIdWhichCreatedMutex
--
-- TitanEngine.TranslateName.functions:
--
-- __declspec(dllexport) void* __stdcall TranslateNativeName(char* szNativeName);
	TitanEngine.TranslateNativeName:types {"string",abi="stdcall",ret="string"}
	TE_TranslateNativeName = TitanEngine.TranslateNativeName
--
--  TitanEngine.Injector.functions:
--
-- __declspec(dllexport) bool __stdcall RemoteLoadLibrary(HANDLE hProcess, char* szLibraryFile, bool WaitForThreadExit);
	TitanEngine.RemoteLoadLibrary:types {"long","string","long",abi="stdcall",ret="byte"}
	TE_RemoteLoadLibrary = TitanEngine.RemoteLoadLibrary
-- __declspec(dllexport) bool __stdcall RemoteFreeLibrary(HANDLE hProcess, HMODULE hModule, char* szLibraryFile, bool WaitForThreadExit);
	TitanEngine.RemoteFreeLibrary:types {"long","long","string","long",abi="stdcall",ret="byte"}
	TE_RemoteFreeLibrary = TitanEngine.RemoteFreeLibrary
-- __declspec(dllexport) bool __stdcall RemoteExitProcess(HANDLE hProcess, DWORD ExitCode);
	TitanEngine.RemoteExitProcess:types {"long","long",abi="stdcall",ret="byte"}
	TE_RemoteExitProcess = TitanEngine.RemoteExitProcess
--
-- TitanEngine.StaticUnpacker.functions:
--
-- __declspec(dllexport) bool __stdcall StaticFileLoad(char* szFileName, DWORD DesiredAccess, bool SimulateLoad, LPHANDLE FileHandle, LPDWORD LoadedSize, LPHANDLE FileMap, PULONG_PTR FileMapVA);
	TitanEngine.StaticFileLoad:types {"string","long","long","pointer","pointer","pointer","pointer",abi="stdcall",ret="byte"}
	TE_StaticFileLoad = TitanEngine.StaticFileLoad
-- __declspec(dllexport) bool __stdcall StaticFileUnload(char* szFileName, bool CommitChanges, HANDLE FileHandle, DWORD LoadedSize, HANDLE FileMap, ULONG_PTR FileMapVA);
	TitanEngine.StaticFileUnload:types {"string","long","long","long","long","long",abi="stdcall",ret="byte"}
	TE_StaticFileUnload = TitanEngine.StaticFileUnload
-- __declspec(dllexport) bool __stdcall StaticFileOpen(char* szFileName, DWORD DesiredAccess, LPHANDLE FileHandle, LPDWORD FileSizeLow, LPDWORD FileSizeHigh);
	TitanEngine.StaticFileOpen:types {"string","long","pointer","pointer","pointer",abi="stdcall",ret="byte"}
	TE_StaticFileOpen = TitanEngine.StaticFileOpen
-- __declspec(dllexport) bool __stdcall StaticFileGetContent(HANDLE FileHandle, DWORD FilePositionLow, LPDWORD FilePositionHigh, void* Buffer, DWORD Size);
	TitanEngine.StaticFileGetContent:types {"long","long","pointer","pointer","long",abi="stdcall",ret="byte"}
	TE_StaticFileGetContent = TitanEngine.StaticFileGetContent
-- __declspec(dllexport) void __stdcall StaticFileClose(HANDLE FileHandle);
	TitanEngine.StaticFileClose:types {"long",abi="stdcall"}
	TE_StaticFileClose = TitanEngine.StaticFileClose
-- __declspec(dllexport) void __stdcall StaticMemoryDecrypt(LPVOID MemoryStart, DWORD MemorySize, DWORD DecryptionType, DWORD DecryptionKeySize, ULONG_PTR DecryptionKey);
	TitanEngine.StaticMemoryDecrypt:types {"long","long","long","long","long",abi="stdcall"}
	TE_StaticMemoryDecrypt = TitanEngine.StaticMemoryDecrypt
-- __declspec(dllexport) void __stdcall StaticMemoryDecryptEx(LPVOID MemoryStart, DWORD MemorySize, DWORD DecryptionKeySize, void* DecryptionCallBack);
	TitanEngine.StaticMemoryDecryptEx:types {"long","long","long","long","callback",abi="stdcall"}
	TE_StaticMemoryDecryptEx = TitanEngine.StaticMemoryDecryptEx
-- __declspec(dllexport) void __stdcall StaticMemoryDecryptSpecial(LPVOID MemoryStart, DWORD MemorySize, DWORD DecryptionKeySize, DWORD SpecDecryptionType, void* DecryptionCallBack);
	TitanEngine.StaticMemoryDecryptSpecial:types {"long","long","long","long","callback",abi="stdcall"}
	TE_StaticMemoryDecryptSpecial = TitanEngine.StaticMemoryDecryptSpecial
-- __declspec(dllexport) void __stdcall StaticSectionDecrypt(ULONG_PTR FileMapVA, DWORD SectionNumber, bool SimulateLoad, DWORD DecryptionType, DWORD DecryptionKeySize, ULONG_PTR DecryptionKey);
	TitanEngine.StaticSectionDecrypt:types {"long","long","long","long","long","long",abi="stdcall"}
	TE_StaticSectionDecrypt = TitanEngine.StaticSectionDecrypt
-- __declspec(dllexport) bool __stdcall StaticMemoryDecompress(void* Source, DWORD SourceSize, void* Destination, DWORD DestinationSize, int Algorithm);
	TitanEngine.StaticMemoryDecompress:types {"pointer","long","pointer","long","long",abi="stdcall",ret="byte"}
	TE_StaticMemoryDecompress = TitanEngine.StaticMemoryDecompress
-- __declspec(dllexport) bool __stdcall StaticRawMemoryCopy(HANDLE hFile, ULONG_PTR FileMapVA, ULONG_PTR VitualAddressToCopy, DWORD Size, bool AddressIsRVA, char* szDumpFileName);
	TitanEngine.StaticRawMemoryCopy:types {"long","long","long","long","long","string",abi="stdcall",ret="byte"}
	TE_StaticRawMemoryCopy = TitanEngine.StaticRawMemoryCopy
-- __declspec(dllexport) bool __stdcall StaticRawMemoryCopyEx(HANDLE hFile, ULONG_PTR RawAddressToCopy, DWORD Size, char* szDumpFileName);
	TitanEngine.StaticRawMemoryCopyEx:types {"long","long","long","string",abi="stdcall",ret="byte"}
	TE_StaticRawMemoryCopyEx = TitanEngine.StaticRawMemoryCopyEx
-- __declspec(dllexport) bool __stdcall StaticHashMemory(void* MemoryToHash, DWORD SizeOfMemory, void* HashDigest, bool OutputString, int Algorithm);
	TitanEngine.StaticHashMemory:types {"long","long","pointer","long","long",abi="stdcall",ret="byte"}
	TE_StaticHashMemory = TitanEngine.StaticHashMemory
-- __declspec(dllexport) bool __stdcall StaticHashFile(char* szFileName, char* HashDigest, bool OutputString, int Algorithm);
	TitanEngine.StaticHashFile:types {"string","string","long","long",abi="stdcall",ret="byte"}
	TE_StaticHashFile = TitanEngine.StaticHashFile
-- CallBacks:
-- typedef bool(__stdcall *fStaticCallBack)(void* sMemoryStart, int sKeySize);
--	TE_StaticMemoryDecryptEx_CB = alien.callback(YourFunctionHere, "pointer", "int", abi = "stdcall", ret = "byte")
--	TE_StaticMemoryDecryptSpecial_CB = alien.callback(YourFunctionHere, "pointer", "int", abi = "stdcall", ret = "byte")
--
--  TitanEngine.Engine.functions:
--
-- __declspec(dllexport) void __stdcall SetEngineVariable(DWORD VariableId, bool VariableSet);
	TitanEngine.SetEngineVariable:types {"long","long",abi="stdcall"}
	TE_SetEngineVariable = TitanEngine.SetEngineVariable
-- __declspec(dllexport) bool __stdcall EngineCreateMissingDependencies(char* szFileName, char* szOutputFolder, bool LogCreatedFiles);
	TitanEngine.EngineCreateMissingDependencies:types {"string","string","long",abi="stdcall",ret="byte"}
	TE_EngineCreateMissingDependencies = TitanEngine.EngineCreateMissingDependencies
-- __declspec(dllexport) bool __stdcall EngineFakeMissingDependencies(HANDLE hProcess);
	TitanEngine.EngineFakeMissingDependencies:types {"long",abi="stdcall",ret="byte"}
	TE_EngineFakeMissingDependencies = TitanEngine.EngineFakeMissingDependencies
-- __declspec(dllexport) bool __stdcall EngineDeleteCreatedDependencies();
	TitanEngine.EngineDeleteCreatedDependencies:types {abi="stdcall",ret="byte"}
	TE_EngineDeleteCreatedDependencies = TitanEngine.EngineDeleteCreatedDependencies
-- __declspec(dllexport) bool __stdcall EngineCreateUnpackerWindow(char* WindowUnpackerTitle, char* WindowUnpackerLongTitle, char* WindowUnpackerName, char* WindowUnpackerAuthor, void* StartUnpackingCallBack);
	TitanEngine.EngineCreateUnpackerWindow:types {"string","string","string","string","callback",abi="stdcall",ret="byte"}
	TE_EngineCreateUnpackerWindow = TitanEngine.EngineCreateUnpackerWindow
-- __declspec(dllexport) bool __stdcall EngineAddUnpackerWindowLogMessage(char* szLogMessage);
	TitanEngine.EngineAddUnpackerWindowLogMessage:types {"string",abi="stdcall",ret="byte"}
	TE_EngineAddUnpackerWindowLogMessage = TitanEngine.EngineAddUnpackerWindowLogMessage
--
--  TitanEngine.Engine.functions:
--
-- __declspec(dllexport) bool __stdcall ExtensionManagerIsPluginLoaded(char* szPluginName);
	TitanEngine.ExtensionManagerIsPluginLoaded:types {"string",abi="stdcall",ret="byte"}
	TE_ExtensionManagerIsPluginLoaded = TitanEngine.ExtensionManagerIsPluginLoaded
-- __declspec(dllexport) bool __stdcall ExtensionManagerIsPluginEnabled(char* szPluginName);
	TitanEngine.ExtensionManagerIsPluginEnabled:types {"string",abi="stdcall",ret="byte"}
	TE_ExtensionManagerIsPluginEnabled = TitanEngine.ExtensionManagerIsPluginEnabled
-- __declspec(dllexport) bool __stdcall ExtensionManagerDisableAllPlugins();
	TitanEngine.ExtensionManagerDisableAllPlugins:types {abi="stdcall",ret="byte"}
	TE_ExtensionManagerDisableAllPlugins = TitanEngine.ExtensionManagerDisableAllPlugins
-- __declspec(dllexport) bool __stdcall ExtensionManagerDisablePlugin(char* szPluginName);
	TitanEngine.ExtensionManagerDisablePlugin:types {"string",abi="stdcall",ret="byte"}
	TE_ExtensionManagerDisablePlugin = TitanEngine.ExtensionManagerDisablePlugin
-- __declspec(dllexport) bool __stdcall ExtensionManagerEnableAllPlugins();
	TitanEngine.ExtensionManagerEnableAllPlugins:types {abi="stdcall",ret="byte"}
	TE_ExtensionManagerEnableAllPlugins = TitanEngine.ExtensionManagerEnableAllPlugins
-- __declspec(dllexport) bool __stdcall ExtensionManagerEnablePlugin(char* szPluginName);
	TitanEngine.ExtensionManagerEnablePlugin:types {"string",abi="stdcall",ret="byte"}
	TE_ExtensionManagerEnablePlugin = TitanEngine.ExtensionManagerEnablePlugin
-- __declspec(dllexport) bool __stdcall ExtensionManagerUnloadAllPlugins();
	TitanEngine.ExtensionManagerUnloadAllPlugins:types {abi="stdcall",ret="byte"}
	TE_ExtensionManagerUnloadAllPlugins = TitanEngine.ExtensionManagerUnloadAllPlugins
-- __declspec(dllexport) bool __stdcall ExtensionManagerUnloadPlugin(char* szPluginName);
	TitanEngine.ExtensionManagerUnloadPlugin:types {"string",abi="stdcall",ret="byte"}
	TE_ExtensionManagerUnloadPlugin = TitanEngine.ExtensionManagerUnloadPlugin
