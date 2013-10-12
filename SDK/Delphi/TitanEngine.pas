unit TitanEngine;

interface

{TitanEngine Delphi SDK - 2.0.3}
{http://www.reversinglabs.com/}
{Types}
type
  PE32Structure = ^PE_32_STRUCT;
  PE_32_STRUCT = packed record
	PE32Offset : LongInt;
	ImageBase : LongInt;
	OriginalEntryPoint : LongInt;
	NtSizeOfImage : LongInt;
	NtSizeOfHeaders : LongInt;
	SizeOfOptionalHeaders : SmallInt;
	FileAlignment : LongInt;
	SectionAligment : LongInt;
	ImportTableAddress : LongInt;
	ImportTableSize : LongInt;
	ResourceTableAddress : LongInt;
	ResourceTableSize : LongInt;
	ExportTableAddress : LongInt;
	ExportTableSize : LongInt;
	TLSTableAddress : LongInt;
	TLSTableSize : LongInt;
	RelocationTableAddress : LongInt;
	RelocationTableSize : LongInt;
	TimeDateStamp : LongInt;
	SectionNumber : SmallInt;
	CheckSum : LongInt;
	SubSystem : SmallInt;
	Characteristics : SmallInt;
	NumberOfRvaAndSizes : LongInt;
  end;

  FileStatusInfo = ^FILE_STATUS_INFO;
  FILE_STATUS_INFO = packed record
	OveralEvaluation : BYTE;
	EvaluationTerminatedByException : boolean;
	FileIs64Bit : boolean;
	FileIsDLL : boolean;
	FileIsConsole : boolean;
	MissingDependencies : boolean;
	MissingDeclaredAPIs : boolean;
	SignatureMZ : BYTE;
	SignaturePE : BYTE;
	EntryPoint : BYTE;
	ImageBase : BYTE;
	SizeOfImage : BYTE;
	FileAlignment : BYTE;
	SectionAlignment : BYTE;
	ExportTable : BYTE;
	RelocationTable : BYTE;
	ImportTable : BYTE;
	ImportTableSection : BYTE;
	ImportTableData : BYTE;
	IATTable : BYTE;
	TLSTable : BYTE;
	LoadConfigTable : BYTE;
	BoundImportTable : BYTE;
	COMHeaderTable : BYTE;
	ResourceTable : BYTE;
	ResourceData : BYTE;
	SectionTable : BYTE;
  end;

  FileFixInfo = ^FILE_FIX_INFO;
  FILE_FIX_INFO = packed record
	OveralEvaluation : BYTE;
	FixingTerminatedByException : boolean;
	FileFixPerformed : boolean;
	StrippedRelocation : boolean;
	DontFixRelocations : boolean;
	OriginalRelocationTableAddress : LongInt;
	OriginalRelocationTableSize : LongInt;
	StrippedExports : boolean;
	DontFixExports : boolean;
	OriginalExportTableAddress : LongInt;
	OriginalExportTableSize : LongInt;
	StrippedResources : boolean;
	DontFixResources : boolean;
	OriginalResourceTableAddress : LongInt;
	OriginalResourceTableSize : LongInt;
	StrippedTLS : boolean;
	DontFixTLS : boolean;
	OriginalTLSTableAddress : LongInt;
	OriginalTLSTableSize : LongInt;
	StrippedLoadConfig : boolean;
	DontFixLoadConfig : boolean;
	OriginalLoadConfigTableAddress : LongInt;
	OriginalLoadConfigTableSize : LongInt;
	StrippedBoundImports : boolean;
	DontFixBoundImports : boolean;
	OriginalBoundImportTableAddress : LongInt;
	OriginalBoundImportTableSize : LongInt;
	StrippedIAT : boolean;
	DontFixIAT : boolean;
	OriginalImportAddressTableAddress : LongInt;
	OriginalImportAddressTableSize : LongInt;
	StrippedCOM : boolean;
	DontFixCOM : boolean;
	OriginalCOMTableAddress : LongInt;
	OriginalCOMTableSize : LongInt;
  end;

  ImportEnumData = ^IMPORT_ENUM_DATA;
  IMPORT_ENUM_DATA = packed record
	NewDll : boolean;
	NumberOfImports : LongInt;
	ImageBase : LongInt;
	BaseImportThunk : LongInt;
	ImportThunk : LongInt;
	APIName : PAnsiChar;
	DLLName : PAnsiChar;
  end;
  
  ThreadItemData = ^THREAD_ITEM_DATA;
  THREAD_ITEM_DATA = packed record
	hThread : THandle;
	dwThreadId : LongInt;
	ThreadStartAddress : LongInt;
	ThreadLocalBase : LongInt;
  end;
  
  LibraryItemData = ^LIBRARY_ITEM_DATA;
  LIBRARY_ITEM_DATA = packed record
	hFile : THandle;
	BaseOfDll : Pointer;
	hFileMapping : THandle;
	hFileMappingView : Pointer;
	szLibraryPath:array[1..260] of AnsiChar;
	szLibraryName:array[1..260] of AnsiChar;
  end;
  
  ProcessItemData = ^PROCESS_ITEM_DATA;
  PROCESS_ITEM_DATA = packed record
	hProcess : THandle;
	dwProcessId : LongInt;
	hThread : THandle;
	dwThreadId : LongInt;
	hFile : THandle;
	BaseOfImage : Pointer;
	ThreadStartAddress : Pointer;
	ThreadLocalBase : Pointer;
  end;
  
  HandlerArray = ^HANDLER_ARRAY;
  HANDLER_ARRAY = packed record
	ProcessId : LongInt;
	hHandle : THandle;
  end;

  HookEntry = ^HOOK_ENTRY;
  HOOK_ENTRY = packed record
	IATHook : boolean;
	HookType : BYTE;
	HookSize : LongInt;
	HookAddress : Pointer;
	RedirectionAddress : Pointer;
	HookBytes:array[1..14] of BYTE;
	OriginalBytes:array[1..14] of BYTE;
	IATHookModuleBase : Pointer;
	IATHookNameHash : LongInt;
	HookIsEnabled : boolean;
	HookIsRemote : boolean;
	PatchedEntry : Pointer;
	RelocationInfo:array[1..7] of LongInt;
	RelocationCount : LongInt;
  end;

  PluginInformation = ^PLUGIN_INFORMATION;
  PLUGIN_INFORMATION = packed record
	PluginName:array[1..64] of AnsiChar;
	PluginMajorVersion : LongInt;
	PluginMinorVersion : LongInt;
	PluginBaseAddress : LongInt;
	TitanDebuggingCallBack : Pointer;
	TitanRegisterPlugin : Pointer;
	TitanReleasePlugin : Pointer;
	TitanResetPlugin : Pointer;
	PluginDisabled : boolean;
  end;
const
{Registers}
	UE_EAX = 1;
	UE_EBX = 2;
	UE_ECX = 3;
	UE_EDX = 4;
	UE_EDI = 5;
	UE_ESI = 6;
	UE_EBP = 7;
	UE_ESP = 8;
	UE_EIP = 9;
	UE_EFLAGS = 10;
	UE_DR0 = 11;
	UE_DR1 = 12;
	UE_DR2 = 13;
	UE_DR3 = 14;
	UE_DR6 = 15;
	UE_DR7 = 16;
	UE_CIP = 35;
	UE_CSP = 36;
	UE_SEG_GS = 37;
	UE_SEG_FS = 38;
	UE_SEG_ES = 39;
	UE_SEG_DS = 40;
	UE_SEG_CS = 41;
	UE_SEG_SS = 42;
{Constants}
	UE_PE_OFFSET = 0;
	UE_IMAGEBASE = 1;
	UE_OEP = 2;
	UE_SIZEOFIMAGE = 3;
	UE_SIZEOFHEADERS = 4;
	UE_SIZEOFOPTIONALHEADER = 5;
	UE_SECTIONALIGNMENT = 6;
	UE_IMPORTTABLEADDRESS = 7;
	UE_IMPORTTABLESIZE = 8;
	UE_RESOURCETABLEADDRESS = 9;
	UE_RESOURCETABLESIZE = 10;
	UE_EXPORTTABLEADDRESS = 11;
	UE_EXPORTTABLESIZE = 12;
	UE_TLSTABLEADDRESS = 13;
	UE_TLSTABLESIZE = 14;
	UE_RELOCATIONTABLEADDRESS = 15;
	UE_RELOCATIONTABLESIZE = 16;
	UE_TIMEDATESTAMP = 17;
	UE_SECTIONNUMBER = 18;
	UE_CHECKSUM = 19;
	UE_SUBSYSTEM = 20;
	UE_CHARACTERISTICS = 21;
	UE_NUMBEROFRVAANDSIZES = 22;
	UE_SECTIONNAME = 23;
	UE_SECTIONVIRTUALOFFSET = 24;
	UE_SECTIONVIRTUALSIZE = 25;
	UE_SECTIONRAWOFFSET = 26;
	UE_SECTIONRAWSIZE = 27;
	UE_SECTIONFLAGS = 28;

	UE_CH_BREAKPOINT = 1;
	UE_CH_SINGLESTEP = 2;
	UE_CH_ACCESSVIOLATION = 3;
	UE_CH_ILLEGALINSTRUCTION = 4;
	UE_CH_NONCONTINUABLEEXCEPTION = 5;
	UE_CH_ARRAYBOUNDSEXCEPTION = 6;
	UE_CH_FLOATDENORMALOPERAND = 7;
	UE_CH_FLOATDEVIDEBYZERO = 8;
	UE_CH_INTEGERDEVIDEBYZERO = 9;
	UE_CH_INTEGEROVERFLOW = 10;
	UE_CH_PRIVILEGEDINSTRUCTION = 11;
	UE_CH_PAGEGUARD = 12;
	UE_CH_EVERYTHINGELSE = 13;
	UE_CH_CREATETHREAD = 14;
	UE_CH_EXITTHREAD = 15;
	UE_CH_CREATEPROCESS = 16;
	UE_CH_EXITPROCESS = 17;
	UE_CH_LOADDLL = 18;
	UE_CH_UNLOADDLL = 19;
	UE_CH_OUTPUTDEBUGSTRING = 20;
        UE_CH_AFTEREXCEPTIONPROCESSING = 21;
        UE_CH_ALLEVENTS = 22;
        UE_CH_SYSTEMBREAKPOINT = 23;
        UE_CH_UNHANDLEDEXCEPTION = 24;
	
	UE_FUNCTION_STDCALL = 1;
	UE_FUNCTION_CCALL = 2;
	UE_FUNCTION_FASTCALL = 3;
	UE_FUNCTION_STDCALL_RET = 4;
	UE_FUNCTION_CCALL_RET = 5;
	UE_FUNCTION_FASTCALL_RET = 6;
	UE_FUNCTION_STDCALL_CALL = 7;
	UE_FUNCTION_CCALL_CALL = 8;
	UE_FUNCTION_FASTCALL_CALL = 9;
	UE_PARAMETER_BYTE = 0;
	UE_PARAMETER_WORD = 1;
	UE_PARAMETER_DWORD = 2;
	UE_PARAMETER_QWORD = 3;
	UE_PARAMETER_PTR_BYTE = 4;
	UE_PARAMETER_PTR_WORD = 5;
	UE_PARAMETER_PTR_DWORD = 6;
	UE_PARAMETER_PTR_QWORD = 7;
	UE_PARAMETER_STRING = 8;
	UE_PARAMETER_UNICODE = 9;

	UE_CMP_NOCONDITION = 0;
	UE_CMP_EQUAL = 1;
	UE_CMP_NOTEQUAL = 2;
	UE_CMP_GREATER = 3;
	UE_CMP_GREATEROREQUAL = 4;
	UE_CMP_LOWER = 5;
	UE_CMP_LOWEROREQUAL = 6;
	UE_CMP_REG_EQUAL = 7;
	UE_CMP_REG_NOTEQUAL = 8;
	UE_CMP_REG_GREATER = 9;
	UE_CMP_REG_GREATEROREQUAL = 10;
	UE_CMP_REG_LOWER = 11;
	UE_CMP_REG_LOWEROREQUAL = 12;
	UE_CMP_ALWAYSFALSE = 13;
	UE_OPTION_HANDLER_RETURN_HANDLECOUNT = 1;
	UE_OPTION_HANDLER_RETURN_ACCESS = 2;
	UE_OPTION_HANDLER_RETURN_FLAGS = 3;
	UE_OPTION_HANDLER_RETURN_TYPENAME = 4;

	UE_BREAKPOINT_INT3 = 1;
	UE_BREAKPOINT_LONG_INT3 = 2;
	UE_BREAKPOINT_UD2 = 3;

	UE_BPXREMOVED = 0;
	UE_BPXACTIVE = 1;
	UE_BPXINACTIVE = 2;

	UE_BREAKPOINT = 0;
	UE_SINGLESHOOT = 1;
	UE_HARDWARE = 2;
	UE_MEMORY = 3;
	UE_MEMORY_READ = 4;
	UE_MEMORY_WRITE = 5;
	UE_BREAKPOINT_TYPE_INT3 = $10000000;
	UE_BREAKPOINT_TYPE_LONG_INT3 = $20000000;
	UE_BREAKPOINT_TYPE_UD2 = $30000000;

	UE_HARDWARE_EXECUTE = 4;
	UE_HARDWARE_WRITE = 5;
	UE_HARDWARE_READWRITE = 6;

	UE_HARDWARE_SIZE_1 = 7;
	UE_HARDWARE_SIZE_2 = 8;
	UE_HARDWARE_SIZE_4 = 9;

	UE_ON_LIB_LOAD = 1;
	UE_ON_LIB_UNLOAD = 2;
	UE_ON_LIB_ALL = 3;

	UE_APISTART = 0;
	UE_APIEND = 1;

	UE_PLATFORM_x86 = 1;
	UE_PLATFORM_x64 = 2;
	UE_PLATFORM_ALL = 3;

	UE_ACCESS_READ = 0;
	UE_ACCESS_WRITE = 1;
	UE_ACCESS_ALL = 2;
	
	UE_HIDE_BASIC = 1;

	UE_ENGINE_ALOW_MODULE_LOADING = 1;
	UE_ENGINE_AUTOFIX_FORWARDERS = 2;
	UE_ENGINE_PASS_ALL_EXCEPTIONS = 3;
	UE_ENGINE_NO_CONSOLE_WINDOW = 4;
	UE_ENGINE_BACKUP_FOR_CRITICAL_FUNCTIONS = 5;
	UE_ENGINE_CALL_PLUGIN_CALLBACK = 6;
	UE_ENGINE_RESET_CUSTOM_HANDLER = 7;
	UE_ENGINE_CALL_PLUGIN_DEBUG_CALLBACK = 8;

	UE_OPTION_REMOVEALL = 1;
	UE_OPTION_DISABLEALL = 2;
	UE_OPTION_REMOVEALLDISABLED = 3;
	UE_OPTION_REMOVEALLENABLED = 4;

	UE_STATIC_DECRYPTOR_XOR = 1;
	UE_STATIC_DECRYPTOR_SUB = 2;
	UE_STATIC_DECRYPTOR_ADD = 3;
	
	UE_STATIC_DECRYPTOR_FOREWARD = 1;
	UE_STATIC_DECRYPTOR_BACKWARD = 2;

	UE_STATIC_KEY_SIZE_1 = 1;
	UE_STATIC_KEY_SIZE_2 = 2;
	UE_STATIC_KEY_SIZE_4 = 4;
	UE_STATIC_KEY_SIZE_8 = 8;
	
	UE_STATIC_APLIB = 1;
	UE_STATIC_APLIB_DEPACK = 2;
	UE_STATIC_LZMA = 3;
	
	UE_STATIC_HASH_MD5 = 1;
	UE_STATIC_HASH_SHA1 = 2;
	UE_STATIC_HASH_CRC32 = 3;
	
	UE_RESOURCE_LANGUAGE_ANY = -1;

	UE_DEPTH_SURFACE = 0;
	UE_DEPTH_DEEP = 1;
	
	UE_UNPACKER_CONDITION_SEARCH_FROM_EP = 1;
	
	UE_UNPACKER_CONDITION_LOADLIBRARY = 1;
	UE_UNPACKER_CONDITION_GETPROCADDRESS = 2;
	UE_UNPACKER_CONDITION_ENTRYPOINTBREAK = 3;
	UE_UNPACKER_CONDITION_RELOCSNAPSHOT1 = 4;
	UE_UNPACKER_CONDITION_RELOCSNAPSHOT2 = 5;

	UE_FIELD_OK = 0;
	UE_FIELD_BROKEN_NON_FIXABLE = 1;
	UE_FIELD_BROKEN_NON_CRITICAL = 2;
	UE_FIELD_BROKEN_FIXABLE_FOR_STATIC_USE = 3;
	UE_FIELD_BROKEN_BUT_CAN_BE_EMULATED = 4;
	UE_FILED_FIXABLE_NON_CRITICAL = 5;
	UE_FILED_FIXABLE_CRITICAL = 6;
	UE_FIELD_NOT_PRESET = 7;
	UE_FIELD_NOT_PRESET_WARNING = 8;

	UE_RESULT_FILE_OK = 10;
	UE_RESULT_FILE_INVALID_BUT_FIXABLE = 11;
	UE_RESULT_FILE_INVALID_AND_NON_FIXABLE = 12;
	UE_RESULT_FILE_INVALID_FORMAT = 13;
	
	UE_PLUGIN_CALL_REASON_PREDEBUG = 1;
	UE_PLUGIN_CALL_REASON_EXCEPTION = 2;
	UE_PLUGIN_CALL_REASON_POSTDEBUG = 3;

	TEE_HOOK_NRM_JUMP = 1;
	TEE_HOOK_NRM_CALL = 3;
	TEE_HOOK_IAT = 5;

{TitanEngine.Dumper.functions}
  function DumpProcess(hProcess:THandle; ImageBase:LongInt; szDumpFileName:PAnsiChar; EntryPoint:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'DumpProcess';
  function DumpProcessEx(ProcessId:LongInt; ImageBase:LongInt; szDumpFileName:PAnsiChar; EntryPoint:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'DumpProcessEx';
  function DumpMemory(hProcess:THandle; MemoryStart,MemorySize:LongInt; szDumpFileName:PAnsiChar):boolean; stdcall;  external 'TitanEngine.dll' name 'DumpMemory';
  function DumpMemoryEx(ProcessId:LongInt; MemoryStart,MemorySize:LongInt; szDumpFileName:PAnsiChar):boolean; stdcall;  external 'TitanEngine.dll' name 'DumpMemoryEx';
  function DumpRegions(hProcess:THandle; szDumpFolder:PAnsiChar; DumpAboveImageBaseOnly:boolean):boolean; stdcall;  external 'TitanEngine.dll' name 'DumpRegions';
  function DumpRegionsEx(ProcessId:LongInt; szDumpFolder:PAnsiChar; DumpAboveImageBaseOnly:boolean):boolean; stdcall;  external 'TitanEngine.dll' name 'DumpRegionsEx';
  function DumpModule(hProcess:THandle; ModuleBase:LongInt; szDumpFileName:PAnsiChar):boolean; stdcall;  external 'TitanEngine.dll' name 'DumpModule';
  function DumpModuleEx(ProcessId:LongInt; ModuleBase:LongInt; szDumpFileName:PAnsiChar):boolean; stdcall;  external 'TitanEngine.dll' name 'DumpModuleEx';
  function PastePEHeader(hProcess:THandle; ImageBase:LongInt; szDebuggedFileName:PAnsiChar):boolean; stdcall;  external 'TitanEngine.dll' name 'PastePEHeader';
  function ExtractSection(szFileName,szDumpFileName:PAnsiChar; SectionNumber:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'ExtractSection';
  function ResortFileSections(szFileName:PAnsiChar):boolean; stdcall;  external 'TitanEngine.dll' name 'ResortFileSections';
  function FindOverlay(szFileName:PAnsiChar; OverlayStart,OverlaySize:Pointer):boolean; stdcall;  external 'TitanEngine.dll' name 'FindOverlay';
  function ExtractOverlay(szFileName,szExtactedFileName:PAnsiChar):boolean; stdcall;  external 'TitanEngine.dll' name 'ExtractOverlay';
  function AddOverlay(szFileName,szOverlayFileName:PAnsiChar):boolean; stdcall;  external 'TitanEngine.dll' name 'AddOverlay';
  function CopyOverlay(szInFileName,szOutFileName:PAnsiChar):boolean; stdcall;  external 'TitanEngine.dll' name 'CopyOverlay';
  function RemoveOverlay(szFileName:PAnsiChar):boolean; stdcall;  external 'TitanEngine.dll' name 'RemoveOverlay';
  function MakeAllSectionsRWE(szFileName:PAnsiChar):boolean; stdcall;  external 'TitanEngine.dll' name 'MakeAllSectionsRWE';
  function AddNewSectionEx(szFileName,szSectionName:PAnsiChar; SectionSize,SectionAttributes:LongInt; SectionContent:Pointer; ContentSize:LongInt):LongInt; stdcall;  external 'TitanEngine.dll' name 'AddNewSectionEx';
  function AddNewSection(szFileName,szSectionName:PAnsiChar; SectionSize:LongInt):LongInt; stdcall;  external 'TitanEngine.dll' name 'AddNewSection';
  function ResizeLastSection(szFileName:PAnsiChar; NumberOfExpandBytes:LongInt; AlignResizeData:boolean):boolean; stdcall;  external 'TitanEngine.dll' name 'ResizeLastSection';
  procedure SetSharedOverlay(szFileName:PAnsiChar); stdcall;  external 'TitanEngine.dll' name 'SetSharedOverlay';
  function GetSharedOverlay():PAnsiChar; stdcall;  external 'TitanEngine.dll' name 'GetSharedOverlay';
  function DeleteLastSection(szFileName:PAnsiChar):boolean; stdcall;  external 'TitanEngine.dll' name 'DeleteLastSection';
  function DeleteLastSectionEx(szFileName:PAnsiChar; NumberOfSections:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'DeleteLastSectionEx';
  function GetPE32DataFromMappedFile(FileMapVA,WhichSection,WhichData:LongInt):LongInt; stdcall;  external 'TitanEngine.dll' name 'GetPE32DataFromMappedFile';
  function GetPE32Data(szFileName:PAnsiChar; WhichSection,WhichData:LongInt):LongInt; stdcall;  external 'TitanEngine.dll' name 'GetPE32Data';
  function GetPE32DataFromMappedFileEx(FileMapVA:LongInt; DataStorage:Pointer):boolean; stdcall;  external 'TitanEngine.dll' name 'GetPE32DataFromMappedFileEx';
  function GetPE32DataEx(szFileName:PAnsiChar; DataStorage:Pointer):boolean; stdcall;  external 'TitanEngine.dll' name 'GetPE32DataEx';
  function SetPE32DataForMappedFile(FileMapVA,WhichSection,WhichData,NewDataValue:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'SetPE32DataForMappedFile';
  function SetPE32Data(szFileName:PAnsiChar; WhichSection,WhichData,NewDataValue:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'SetPE32Data';
  function SetPE32DataForMappedFileEx(szFileName:PAnsiChar; DataStorage:Pointer):boolean; stdcall;  external 'TitanEngine.dll' name 'SetPE32DataForMappedFileEx';
  function SetPE32DataEx(szFileName:PAnsiChar; DataStorage:Pointer):boolean; stdcall;  external 'TitanEngine.dll' name 'SetPE32DataEx';
  function GetPE32SectionNumberFromVA(FileMapVA,AddressToConvert:LongInt):LongInt; stdcall;  external 'TitanEngine.dll' name 'GetPE32SectionNumberFromVA';
  function ConvertVAtoFileOffset(FileMapVA,AddressToConvert:LongInt; ReturnType:boolean):LongInt; stdcall;  external 'TitanEngine.dll' name 'ConvertVAtoFileOffset';
  function ConvertVAtoFileOffsetEx(FileMapVA,FileSize,ImageBase,AddressToConvert:LongInt; AddressIsRVA,ReturnType:boolean):LongInt; stdcall;  external 'TitanEngine.dll' name 'ConvertVAtoFileOffsetEx';
  function ConvertFileOffsetToVA(FileMapVA,AddressToConvert:LongInt; ReturnType:boolean):LongInt; stdcall;  external 'TitanEngine.dll' name 'ConvertFileOffsetToVA';
  function ConvertFileOffsetToVAEx(FileMapVA,FileSize,ImageBase,AddressToConvert:LongInt; ReturnType:boolean):LongInt; stdcall;  external 'TitanEngine.dll' name 'ConvertFileOffsetToVAEx';
{TitanEngine.Realigner.functions}
  function FixHeaderCheckSum(szFileName:PAnsiChar):boolean; stdcall;  external 'TitanEngine.dll' name 'FixHeaderCheckSum';
  function RealignPE(FileMapVA,FileSize,RealingMode:LongInt):LongInt; stdcall;  external 'TitanEngine.dll' name 'RealignPE';
  function RealignPEEx(szFileName:PAnsiChar; RealingFileSize,ForcedFileAlignment:LongInt):LongInt; stdcall;  external 'TitanEngine.dll' name 'RealignPEEx';
  function WipeSection(szFileName:PAnsiChar; WipeSectionNumber:LongInt; RemovePhysically:boolean):boolean; stdcall;  external 'TitanEngine.dll' name 'WipeSection';
  function IsPE32FileValidEx(szFileName:PAnsiChar; CheckDepth:LongInt; FileStatusInfo:Pointer):boolean; stdcall;  external 'TitanEngine.dll' name 'IsPE32FileValidEx';
  function FixBrokenPE32FileEx(szFileName:PAnsiChar; FileStatusInfo,FileFixInfo:Pointer):boolean; stdcall;  external 'TitanEngine.dll' name 'FixBrokenPE32FileEx';
  function IsFileDLL(szFileName:PAnsiChar; FileMapVA:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'IsFileDLL';
{TitanEngine.Hider.functions}
  function GetPEBLocation(hProcess:THandle):LongInt; stdcall;  external 'TitanEngine.dll' name 'GetPEBLocation';
  function HideDebugger(hProcess:THandle; PatchAPILevel:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'HideDebugger';
  function UnHideDebugger(hProcess:THandle; PatchAPILevel:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'UnHideDebugger';
{TitanEngine.Relocater.functions}
  procedure RelocaterCleanup(); stdcall;  external 'TitanEngine.dll' name 'RelocaterCleanup';
  procedure RelocaterInit(MemorySize,OldImageBase,NewImageBase:LongInt); stdcall;  external 'TitanEngine.dll' name 'RelocaterInit';
  procedure RelocaterAddNewRelocation(hProcess:THandle; RelocateAddress,RelocateState:LongInt); stdcall;  external 'TitanEngine.dll' name 'RelocaterAddNewRelocation';
  function RelocaterEstimatedSize():LongInt; stdcall;  external 'TitanEngine.dll' name 'RelocaterEstimatedSize';
  function RelocaterExportRelocation(StorePlace,StorePlaceRVA,FileMapVA:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'RelocaterExportRelocation';
  function RelocaterExportRelocationEx(szFileName,szSectionName:PAnsiChar; StorePlace,StorePlaceRVA:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'RelocaterExportRelocationEx';
  function RelocaterGrabRelocationTable(hProcess:THandle; MemoryStart,MemorySize:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'RelocaterGrabRelocationTable';
  function RelocaterGrabRelocationTableEx(hProcess:THandle; MemoryStart,MemorySize,NtSizeOfImage:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'RelocaterGrabRelocationTableEx';
  function RelocaterMakeSnapshot(hProcess:THandle; szSaveFileName:PAnsiChar; MemoryStart,MemorySize:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'RelocaterMakeSnapshot';
  function RelocaterCompareTwoSnapshots(hProcess:THandle; LoadedImageBase,NtSizeOfImage:LongInt; szDumpFile1,szDumpFile2:PAnsiChar; MemStart:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'RelocaterCompareTwoSnapshots';
  function RelocaterChangeFileBase(szFileName:PAnsiChar; NewImageBase:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'RelocaterChangeFileBase';
  function RelocaterRelocateMemoryBlock(FileMapVA,MemoryLocation:LongInt; RelocateMemory:Pointer; RelocateMemorySize,CurrentLoadedBase,RelocateBase:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'RelocaterRelocateMemoryBlock';
  function RelocaterWipeRelocationTable(szFileName:PAnsiChar):boolean; stdcall;  external 'TitanEngine.dll' name 'RelocaterWipeRelocationTable';
{TitanEngine.Resourcer.functions}
  function ResourcerLoadFileForResourceUse(szFileName:PAnsiChar):LongInt; stdcall;  external 'TitanEngine.dll' name 'ResourcerLoadFileForResourceUse';
  function ResourcerFreeLoadedFile(LoadedFileBase:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'ResourcerFreeLoadedFile';
  function ResourcerExtractResourceFromFileEx(FileMapVA:LongInt; szResourceType,szResourceName,szExtractedFileName:PAnsiChar):boolean; stdcall;  external 'TitanEngine.dll' name 'ResourcerExtractResourceFromFileEx';
  function ResourcerExtractResourceFromFile(szFileName,szResourceType,szResourceName,szExtractedFileName:PAnsiChar):boolean; stdcall;  external 'TitanEngine.dll' name 'ResourcerExtractResourceFromFile';
  function ResourcerFindResource(szFileName,szResourceType:PAnsiChar; ResourceType:LongInt; szResourceName:PAnsiChar; ResourceName,ResourceLanguage:LongInt; pResourceData,pResourceSize:Pointer):boolean; stdcall;  external 'TitanEngine.dll' name 'ResourcerFindResource';
  function ResourcerFindResourceEx(FileMapVA,FileSize:LongInt; szResourceType:PAnsiChar; ResourceType:LongInt; szResourceName:PAnsiChar; ResourceName,ResourceLanguage:LongInt; pResourceData,pResourceSize:Pointer):boolean; stdcall;  external 'TitanEngine.dll' name 'ResourcerFindResourceEx';
  procedure ResourcerEnumerateResource(szFileName:PAnsiChar; CallBack:LongInt); stdcall;  external 'TitanEngine.dll' name 'ResourcerEnumerateResource';
  procedure ResourcerEnumerateResourceEx(FileMapVA,FileSize:LongInt; CallBack:LongInt); stdcall;  external 'TitanEngine.dll' name 'ResourcerEnumerateResourceEx';
{TitanEngine.FindOEP.functions}
  procedure FindOEPInit(); stdcall;  external 'TitanEngine.dll' name 'FindOEPInit';
  procedure FindOEPGenerically(szFileName:PAnsiChar; TraceInitCallBack,CallBack:Pointer); stdcall;  external 'TitanEngine.dll' name 'FindOEPGenerically';
{TitanEngine.Threader.functions}
  function ThreaderImportRunningThreadData(ProcessId:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'ThreaderImportRunningThreadData';
  function ThreaderGetThreadInfo(hThread:THandle; ThreadId:LongInt):LongInt; stdcall;  external 'TitanEngine.dll' name 'ThreaderGetThreadInfo';
  procedure ThreaderEnumThreadInfo(EnumCallBack:Pointer); stdcall;  external 'TitanEngine.dll' name 'ThreaderGetThreadInfo';
  function ThreaderPauseThread(hThread:THandle):boolean; stdcall;  external 'TitanEngine.dll' name 'ThreaderPauseThread';
  function ThreaderResumeThread(hThread:THandle):boolean; stdcall;  external 'TitanEngine.dll' name 'ThreaderResumeThread';
  function ThreaderTerminateThread(hThread:THandle; ThreadExitCode:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'ThreaderTerminateThread';
  function ThreaderPauseAllThreads(LeaveMainRunning:boolean):boolean; stdcall;  external 'TitanEngine.dll' name 'ThreaderPauseAllThreads';
  function ThreaderResumeAllThreads(LeaveMainPaused:boolean):boolean; stdcall;  external 'TitanEngine.dll' name 'ThreaderResumeAllThreads';
  function ThreaderPauseProcess():boolean; stdcall;  external 'TitanEngine.dll' name 'ThreaderPauseProcess';
  function ThreaderResumeProcess():boolean; stdcall;  external 'TitanEngine.dll' name 'ThreaderResumeProcess';
  function ThreaderCreateRemoteThread(ThreadStartAddress:LongInt; AutoCloseTheHandle:boolean; ThreadPassParameter,ThreadId:Pointer):LongInt; stdcall;  external 'TitanEngine.dll' name 'ThreaderCreateRemoteThread';
  function ThreaderInjectAndExecuteCode(InjectCode:Pointer; StartDelta,InjectSize:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'ThreaderInjectAndExecuteCode';
  function ThreaderCreateRemoteThreadEx(hProcess:THandle; ThreadStartAddress:LongInt; AutoCloseTheHandle:boolean; ThreadPassParameter,ThreadId:Pointer):LongInt; stdcall;  external 'TitanEngine.dll' name 'ThreaderCreateRemoteThreadEx';
  function ThreaderInjectAndExecuteCodeEx(hProcess:THandle; InjectCode:Pointer; StartDelta,InjectSize:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'ThreaderInjectAndExecuteCodeEx';
  procedure ThreaderSetCallBackForNextExitThreadEvent(exitThreadCallBack:Pointer); stdcall;  external 'TitanEngine.dll' name 'ThreaderSetCallBackForNextExitThreadEvent';
  function ThreaderIsThreadStillRunning(hThread:THandle):boolean; stdcall;  external 'TitanEngine.dll' name 'ThreaderIsThreadStillRunning';
  function ThreaderIsThreadActive(hThread:THandle):boolean; stdcall;  external 'TitanEngine.dll' name 'ThreaderIsThreadActive';
  function ThreaderIsAnyThreadActive():boolean; stdcall;  external 'TitanEngine.dll' name 'ThreaderIsAnyThreadActive';
  function ThreaderExecuteOnlyInjectedThreads():boolean; stdcall;  external 'TitanEngine.dll' name 'ThreaderExecuteOnlyInjectedThreads';
  function ThreaderGetOpenHandleForThread(ThreadId:LongInt):THandle; stdcall;  external 'TitanEngine.dll' name 'ThreaderGetOpenHandleForThread';
  function ThreaderGetThreadData():Pointer; stdcall;  external 'TitanEngine.dll' name 'ThreaderGetThreadData';
  function ThreaderIsExceptionInMainThread():boolean; stdcall;  external 'TitanEngine.dll' name 'ThreaderIsExceptionInMainThread';
{TitanEngine.Debugger.functions}
  function StaticDisassembleEx(DisassmStart:LongInt; DisassmAddress:Pointer):PAnsiChar; stdcall;  external 'TitanEngine.dll' name 'StaticDisassembleEx';
  function StaticDisassemble(DisassmAddress:Pointer):PAnsiChar; stdcall;  external 'TitanEngine.dll' name 'StaticDisassemble';
  function DisassembleEx(hProcess:THandle; DisassmAddress:Pointer):PAnsiChar; stdcall;  external 'TitanEngine.dll' name 'DisassembleEx';
  function Disassemble(DisassmAddress:Pointer):PAnsiChar; stdcall;  external 'TitanEngine.dll' name 'Disassemble';
  function StaticLengthDisassemble(DisassmAddress:Pointer):LongInt; stdcall;  external 'TitanEngine.dll' name 'StaticLengthDisassemble';
  function LengthDisassembleEx(hProcess:THandle; DisassmAddress:Pointer):LongInt; stdcall;  external 'TitanEngine.dll' name 'LengthDisassembleEx';
  function LengthDisassemble(DisassmAddress:Pointer):LongInt; stdcall;  external 'TitanEngine.dll' name 'LengthDisassemble';
  function InitDebug(szFileName,szCommandLine,szCurrentFolder:PAnsiChar): Pointer; stdcall; external 'TitanEngine.dll' name 'InitDebug';
  function InitDebugEx(szFileName,szCommandLine,szCurrentFolder:PAnsiChar; EntryCallBack:Pointer): Pointer; stdcall; external 'TitanEngine.dll' name 'InitDebugEx';
  function InitDLLDebug(szFileName:PAnsiChar; ReserveModuleBase:boolean; szCommandLine,szCurrentFolder:PAnsiChar; EntryCallBack:Pointer): Pointer; stdcall; external 'TitanEngine.dll' name 'InitDLLDebug';
  function StopDebug(): Boolean; stdcall; external 'TitanEngine.dll' name 'StopDebug';
  procedure SetBPXOptions(DefaultBreakPointType:LongInt); stdcall; external 'TitanEngine.dll' name 'SetBPXOptions';
  function IsBPXEnabled(bpxAddress:LongInt): boolean; stdcall; external 'TitanEngine.dll' name 'IsBPXEnabled';
  function EnableBPX(bpxAddress:LongInt): boolean; stdcall; external 'TitanEngine.dll' name 'EnableBPX';
  function DisableBPX(bpxAddress:LongInt): boolean; stdcall; external 'TitanEngine.dll' name 'DisableBPX';
  function SetBPX(bpxAddress,bpxType:LongInt; bpxCallBack:Pointer): boolean; stdcall; external 'TitanEngine.dll' name 'SetBPX';
  function SetBPXEx(bpxAddress,bpxType,NumberOfExecution,CmpRegister,CmpCondition,CmpValue:LongInt; bpxCallBack,bpxCompareCallBack,bpxRemoveCallBack:Pointer): boolean; stdcall; external 'TitanEngine.dll' name 'SetBPXEx';
  function DeleteBPX(bpxAddress:LongInt): boolean; stdcall; external 'TitanEngine.dll' name 'DeleteBPX';
  function SafeDeleteBPX(bpxAddress:LongInt): boolean; stdcall; external 'TitanEngine.dll' name 'SafeDeleteBPX';
  function SetAPIBreakPoint(szDLLName,szAPIName:PAnsiChar; bpxType,bpxPlace:LongInt; bpxCallBack:Pointer):boolean; stdcall; external 'TitanEngine.dll' name 'SetAPIBreakPoint';
  function DeleteAPIBreakPoint(szDLLName,szAPIName:PAnsiChar; bpxPlace:LongInt):boolean; stdcall; external 'TitanEngine.dll' name 'DeleteAPIBreakPoint';
  function SafeDeleteAPIBreakPoint(szDLLName,szAPIName:PAnsiChar; bpxPlace:LongInt):boolean; stdcall; external 'TitanEngine.dll' name 'SafeDeleteAPIBreakPoint';
  function SetMemoryBPX(MemoryStart,SizeOfMemory:LongInt; bpxCallBack:Pointer):boolean; stdcall; external 'TitanEngine.dll' name 'SetMemoryBPX';
  function SetMemoryBPXEx(MemoryStart,SizeOfMemory,BreakPointType:LongInt; RestoreOnHit:boolean; bpxCallBack:Pointer):boolean; stdcall; external 'TitanEngine.dll' name 'SetMemoryBPXEx';
  function RemoveMemoryBPX(MemoryStart,SizeOfMemory:LongInt):boolean; stdcall; external 'TitanEngine.dll' name 'RemoveMemoryBPX';
  function GetContextFPUDataEx(hActiveThread:THandle; FPUSaveArea:Pointer): boolean; stdcall; external 'TitanEngine.dll' name 'GetContextFPUDataEx';
  function GetContextDataEx(hActiveThread:THandle; IndexOfRegister:LongInt): LongInt; stdcall; external 'TitanEngine.dll' name 'GetContextDataEx';
  function GetContextData(IndexOfRegister:LongInt): LongInt; stdcall; external 'TitanEngine.dll' name 'GetContextData';
  function SetContextFPUDataEx(hActiveThread:THandle; FPUSaveArea:Pointer): boolean; stdcall; external 'TitanEngine.dll' name 'SetContextFPUDataEx';
  function SetContextDataEx(hActiveThread:THandle; IndexOfRegister,NewRegisterValue:LongInt):boolean; stdcall; external 'TitanEngine.dll' name 'SetContextDataEx';
  function SetContextData(IndexOfRegister,NewRegisterValue:LongInt):boolean; stdcall; external 'TitanEngine.dll' name 'SetContextData';
  procedure ClearExceptionNumber(); stdcall; external 'TitanEngine.dll' name 'ClearExceptionNumber';
  function CurrentExceptionNumber(): LongInt; stdcall; external 'TitanEngine.dll' name 'CurrentExceptionNumber';
  function MatchPatternEx(hProcess:THandle; MemoryToCheck,SizeOfMemoryToCheck:LongInt; PatternToMatch:Pointer; SizeOfPatternToMatch:LongInt; WildCard:Pointer): boolean; stdcall; external 'TitanEngine.dll' name 'MatchPatternEx';
  function MatchPattern(MemoryToCheck,SizeOfMemoryToCheck:LongInt; PatternToMatch:Pointer; SizeOfPatternToMatch:LongInt; WildCard:Pointer): boolean; stdcall; external 'TitanEngine.dll' name 'MatchPattern';
  function FindEx(hProcess:THandle; MemoryStart,MemorySize:LongInt; SearchPattern:Pointer; PatternSize:LongInt; WildCard:Pointer): LongInt; stdcall; external 'TitanEngine.dll' name 'FindEx';
  function Find(MemoryStart,MemorySize:LongInt; SearchPattern:Pointer; PatternSize:LongInt; WildCard:Pointer): LongInt; stdcall; external 'TitanEngine.dll' name 'Find';
  function FillEx(hProcess:THandle; MemoryStart,MemorySize:LongInt; FillByte:Pointer): boolean; stdcall; external 'TitanEngine.dll' name 'FillEx';
  function Fill(MemoryStart,MemorySize:LongInt; FillByte:Pointer): boolean; stdcall; external 'TitanEngine.dll' name 'Fill';
  function PatchEx(hProcess:THandle; MemoryStart,MemorySize:LongInt; ReplacePattern:Pointer; ReplaceSize:LongInt; AppendNOP,PrependNOP:boolean): boolean; stdcall; external 'TitanEngine.dll' name 'PatchEx';
  function Patch(MemoryStart,MemorySize:LongInt; ReplacePattern:Pointer; ReplaceSize:LongInt; AppendNOP,PrependNOP:boolean): boolean; stdcall; external 'TitanEngine.dll' name 'Patch';
  function ReplaceEx(hProcess:THandle; MemoryStart,MemorySize:LongInt; SearchPattern:Pointer; PatternSize,NumberOfRepetitions:LongInt; ReplacePattern:Pointer; ReplaceSize:LongInt; WildCard:Pointer): boolean; stdcall; external 'TitanEngine.dll' name 'ReplaceEx';
  function Replace(MemoryStart,MemorySize:LongInt; SearchPattern:Pointer; PatternSize,NumberOfRepetitions:LongInt; ReplacePattern:Pointer; ReplaceSize:LongInt; WildCard:Pointer): boolean; stdcall; external 'TitanEngine.dll' name 'Replace';
  function GetDebugData(): Pointer; stdcall; external 'TitanEngine.dll' name 'GetDebugData';
  function GetTerminationData(): Pointer; stdcall; external 'TitanEngine.dll' name 'GetTerminationData';
  function GetExitCode():LongInt; stdcall; external 'TitanEngine.dll' name 'GetExitCode';
  function GetDebuggedDLLBaseAddress(): LongInt; stdcall; external 'TitanEngine.dll' name 'GetDebuggedDLLBaseAddress';
  function GetDebuggedFileBaseAddress(): LongInt; stdcall; external 'TitanEngine.dll' name 'GetDebuggedFileBaseAddress';
  function GetRemoteString(hProcess:THandle; StringAddress:LongInt; StringStorage:Pointer; MaximumStringSize:LongInt): LongInt; stdcall; external 'TitanEngine.dll' name 'GetRemoteString';
  function GetFunctionParameter(hProcess:THandle; FunctionType,ParameterNumber,ParameterType:LongInt): LongInt; stdcall; external 'TitanEngine.dll' name 'GetFunctionParameter';
  function GetJumpDestinationEx(hProcess:THandle; InstructionAddress:LongInt; JustJumps:boolean): LongInt; stdcall; external 'TitanEngine.dll' name 'GetJumpDestinationEx';
  function GetJumpDestination(hProcess:THandle; InstructionAddress:LongInt; JustJumps:boolean): LongInt; stdcall; external 'TitanEngine.dll' name 'GetJumpDestination';
  function IsJumpGoingToExecuteEx(hProcess,hThread:THandle; InstructionAddress,RegFlags:LongInt): boolean; stdcall; external 'TitanEngine.dll' name 'IsJumpGoingToExecuteEx';
  function IsJumpGoingToExecute(): boolean; stdcall; external 'TitanEngine.dll' name 'IsJumpGoingToExecute';
  procedure SetCustomHandler(WhichException:LongInt; CallBack:Pointer); stdcall; external 'TitanEngine.dll' name 'SetCustomHandler';
  procedure ForceClose(); stdcall; external 'TitanEngine.dll' name 'ForceClose';
  procedure StepInto(traceCallBack:Pointer); stdcall; external 'TitanEngine.dll' name 'StepInto';
  procedure StepOver(traceCallBack:Pointer); stdcall; external 'TitanEngine.dll' name 'StepOver';
  procedure SingleStep(StepCount:LongInt; StepCallBack:Pointer); stdcall; external 'TitanEngine.dll' name 'SingleStep';
  function GetUnusedHardwareBreakPointRegister(RegisterIndex:Pointer):boolean; stdcall; external 'TitanEngine.dll' name 'GetUnusedHardwareBreakPointRegister';
  function SetHardwareBreakPointEx(hActiveThread:THandle; bpxAddress,IndexOfRegister,bpxType,bpxSize:LongInt; bpxCallBack,IndexOfSelectedRegister:Pointer):boolean; stdcall; external 'TitanEngine.dll' name 'SetHardwareBreakPointEx';
  function SetHardwareBreakPoint(bpxAddress,IndexOfRegister,bpxType,bpxSize:LongInt; bpxCallBack:Pointer):boolean; stdcall; external 'TitanEngine.dll' name 'SetHardwareBreakPoint';
  function DeleteHardwareBreakPoint(IndexOfRegister:LongInt):boolean; stdcall; external 'TitanEngine.dll' name 'DeleteHardwareBreakPoint';
  function RemoveAllBreakPoints(RemoveOption:LongInt):boolean; stdcall; external 'TitanEngine.dll' name 'RemoveAllBreakPoints';
  function GetProcessInformation(): Pointer; stdcall; external 'TitanEngine.dll' name 'GetProcessInformation';
  function GetStartupInformation(): Pointer; stdcall; external 'TitanEngine.dll' name 'GetStartupInformation';
  procedure DebugLoop(); stdcall; external 'TitanEngine.dll' name 'DebugLoop';
  procedure SetDebugLoopTimeOut(TimeOut:LongInt); stdcall; external 'TitanEngine.dll' name 'SetDebugLoopTimeOut';
  procedure SetNextDbgContinueStatus(SetDbgCode:LongInt); stdcall; external 'TitanEngine.dll' name 'SetNextDbgContinueStatus';
  function AttachDebugger(ProcessId:LongInt; KillOnExit:Boolean; DebugInfo,CallBack:Pointer): Pointer; stdcall; external 'TitanEngine.dll' name 'AttachDebugger';
  function DetachDebugger(ProcessId:LongInt): Pointer; stdcall; external 'TitanEngine.dll' name 'DetachDebugger';
  function DetachDebuggerEx(ProcessId:LongInt): Pointer; stdcall; external 'TitanEngine.dll' name 'DetachDebuggerEx';
  function DebugLoopEx(TimeOut:LongInt): LongInt; stdcall; external 'TitanEngine.dll' name 'DebugLoopEx';
  procedure AutoDebugEx(szFileName:PAnsiChar; ReserveModuleBase:boolean; szCommandLine,szCurrentFolder:PAnsiChar; TimeOut:LongInt; EntryCallBack:Pointer); stdcall; external 'TitanEngine.dll' name 'AutoDebugEx';
  function IsFileBeingDebugged(): boolean; stdcall; external 'TitanEngine.dll' name 'IsFileBeingDebugged';
  procedure SetErrorModel(DisplayErrorMessages:boolean); stdcall; external 'TitanEngine.dll' name 'SetErrorModel';
{TitanEngine.Importer.functions}
  procedure ImporterCleanup(); stdcall;  external 'TitanEngine.dll' name 'ImporterCleanup';
  procedure ImporterSetImageBase(ImageBase:LongInt); stdcall;  external 'TitanEngine.dll' name 'ImporterSetImageBase';
  procedure ImporterSetUnknownDelta(DeltaAddress:LongInt); stdcall;  external 'TitanEngine.dll' name 'ImporterSetUnknownDelta';
  function ImporterGetCurrentDelta():LongInt; stdcall;  external 'TitanEngine.dll' name 'ImporterGetCurrentDelta';
  procedure ImporterInit(MemorySize,ImageBase:LongInt); stdcall;  external 'TitanEngine.dll' name 'ImporterInit';
  procedure ImporterAddNewDll(DLLName:PAnsiChar; FirstThunk:LongInt); stdcall;  external 'TitanEngine.dll' name 'ImporterAddNewDll';
  procedure ImporterAddNewAPI(APIName:PAnsiChar; FirstThunk:LongInt); stdcall;  external 'TitanEngine.dll' name 'ImporterAddNewAPI';
  procedure ImporterAddNewOrdinalAPI(dwAPIName,FirstThunk:LongInt); stdcall;  external 'TitanEngine.dll' name 'ImporterAddNewAPI';
  function ImporterGetAddedDllCount(): LongInt; stdcall;  external 'TitanEngine.dll' name 'ImporterGetAddedDllCount';
  function ImporterGetAddedAPICount(): LongInt; stdcall;  external 'TitanEngine.dll' name 'ImporterGetAddedAPICount';
  function ImporterGetLastAddedDLLName(): PAnsiChar; stdcall;  external 'TitanEngine.dll' name 'ImporterGetLastAddedDLLName';
  procedure ImporterMoveIAT(); stdcall;  external 'TitanEngine.dll' name 'ImporterMoveIAT';
  function ImporterExportIAT(StorePlace,FileMap:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'ImporterExportIAT';
  function ImporterEstimatedSize(): LongInt; stdcall;  external 'TitanEngine.dll' name 'ImporterEstimatedSize';
  function ImporterExportIATEx(szExportFileName,szSectionName:PAnsiChar):boolean; stdcall;  external 'TitanEngine.dll' name 'ImporterExportIATEx';
  function ImporterFindAPIWriteLocation(szAPIName:PAnsiChar): LongInt; stdcall;  external 'TitanEngine.dll' name 'ImporterFindAPIWriteLocation';
  function ImporterFindOrdinalAPIWriteLocation(OrdinalNumber:LongInt): LongInt; stdcall;  external 'TitanEngine.dll' name 'ImporterFindOrdinalAPIWriteLocation';
  function ImporterFindAPIByWriteLocation(APIWriteLocation:PAnsiChar): LongInt; stdcall;  external 'TitanEngine.dll' name 'ImporterFindAPIByWriteLocation';
  function ImporterFindDLLByWriteLocation(APIWriteLocation:PAnsiChar): LongInt; stdcall;  external 'TitanEngine.dll' name 'ImporterFindDLLByWriteLocation';
  function ImporterGetDLLName(APIAddress:LongInt): PAnsiChar; stdcall;  external 'TitanEngine.dll' name 'ImporterGetDLLName';
  function ImporterGetAPIName(APIAddress:LongInt): PAnsiChar; stdcall;  external 'TitanEngine.dll' name 'ImporterGetAPIName';
  function ImporterGetAPIOrdinalNumber(APIAddress:LongInt): LongInt; stdcall;  external 'TitanEngine.dll' name 'ImporterGetAPIOrdinalNumber';
  function ImporterGetAPINameEx(APIAddress:LongInt; pDLLBases:Pointer): PAnsiChar; stdcall;  external 'TitanEngine.dll' name 'ImporterGetAPINameEx';
  function ImporterGetRemoteAPIAddress(hProcess:THandle; APIAddress:LongInt): LongInt; stdcall;  external 'TitanEngine.dll' name 'ImporterGetRemoteAPIAddress';
  function ImporterGetRemoteAPIAddressEx(szDLLName,szAPIName:PAnsiChar): LongInt; stdcall;  external 'TitanEngine.dll' name 'ImporterGetRemoteAPIAddressEx';
  function ImporterGetLocalAPIAddress(hProcess:THandle; APIAddress:LongInt): LongInt; stdcall;  external 'TitanEngine.dll' name 'ImporterGetLocalAPIAddress';
  function ImporterGetDLLNameFromDebugee(hProcess:THandle; APIAddress:LongInt): PAnsiChar; stdcall;  external 'TitanEngine.dll' name 'ImporterGetDLLNameFromDebugee';
  function ImporterGetAPINameFromDebugee(hProcess:THandle; APIAddress:LongInt): PAnsiChar; stdcall;  external 'TitanEngine.dll' name 'ImporterGetAPINameFromDebugee';
  function ImporterGetAPIOrdinalNumberFromDebugee(hProcess:THandle; APIAddress:LongInt): LongInt; stdcall;  external 'TitanEngine.dll' name 'ImporterGetAPIOrdinalNumberFromDebugee';
  function ImporterGetDLLIndexEx(APIAddress:LongInt; pDLLBases:Pointer): LongInt; stdcall;  external 'TitanEngine.dll' name 'ImporterGetDLLIndexEx';
  function ImporterGetDLLIndex(hProcess:THandle; APIAddress:LongInt; pDLLBases:Pointer): LongInt; stdcall;  external 'TitanEngine.dll' name 'ImporterGetDLLIndex';
  function ImporterGetRemoteDLLBase(hProcess:THandle; LocalModuleBase:LongInt): LongInt; stdcall;  external 'TitanEngine.dll' name 'ImporterGetRemoteDLLBase';
  function ImporterRelocateWriteLocation(AddValue:LongInt): boolean; stdcall;  external 'TitanEngine.dll' name 'ImporterRelocateWriteLocation';
  function ImporterIsForwardedAPI(hProcess:THandle; APIAddress:LongInt): boolean; stdcall;  external 'TitanEngine.dll' name 'ImporterIsForwardedAPI';
  function ImporterGetForwardedAPIName(hProcess:THandle; APIAddress:LongInt): PAnsiChar; stdcall;  external 'TitanEngine.dll' name 'ImporterGetForwardedAPIName';
  function ImporterGetForwardedDLLName(hProcess:THandle; APIAddress:LongInt): PAnsiChar; stdcall;  external 'TitanEngine.dll' name 'ImporterGetForwardedDLLName';
  function ImporterGetForwardedDLLIndex(hProcess:THandle; APIAddress:LongInt; pDLLBases:Pointer): LongInt; stdcall;  external 'TitanEngine.dll' name 'ImporterGetForwardedDLLIndex';
  function ImporterGetForwardedAPIOrdinalNumber(hProcess:THandle; APIAddress:LongInt): LongInt; stdcall;  external 'TitanEngine.dll' name 'ImporterGetForwardedAPIOrdinalNumber';
  function ImporterGetNearestAPIAddress(hProcess:THandle; APIAddress:LongInt): LongInt; stdcall;  external 'TitanEngine.dll' name 'ImporterGetNearestAPIAddress';
  function ImporterGetNearestAPIName(hProcess:THandle; APIAddress:LongInt): PAnsiChar; stdcall;  external 'TitanEngine.dll' name 'ImporterGetNearestAPIName';
  function ImporterCopyOriginalIAT(szOriginalFile,szDumpFile:PAnsiChar): boolean; stdcall;  external 'TitanEngine.dll' name 'ImporterCopyOriginalIAT';
  function ImporterLoadImportTable(szFileName:PAnsiChar): boolean; stdcall;  external 'TitanEngine.dll' name 'ImporterLoadImportTable';
  function ImporterMoveOriginalIAT(szOriginalFile,szDumpFile,szSectionName:PAnsiChar): boolean; stdcall;  external 'TitanEngine.dll' name 'ImporterMoveOriginalIAT';
  procedure ImporterAutoSearchIAT(pFileName:PAnsiChar;ImageBase,SearchStart,SearchSize:LongInt;pIATStart,pIATSize:Pointer); stdcall;  external 'TitanEngine.dll' name 'ImporterAutoSearchIAT';
  procedure ImporterAutoSearchIATEx(hProcess:LongInt;ImageBase,SearchStart,SearchSize:LongInt;pIATStart,pIATSize:Pointer); stdcall;  external 'TitanEngine.dll' name 'ImporterAutoSearchIATEx';
  procedure ImporterEnumAddedData(EnumCallBack:Pointer); stdcall;  external 'TitanEngine.dll' name 'ImporterEnumAddedData';
  function ImporterAutoFixIAT(hProcess:LongInt;pFileName:PAnsiChar;ImageBase,SearchStart,SearchSize,SearchStep:LongInt):LongInt; stdcall;  external 'TitanEngine.dll' name 'ImporterAutoFixIAT';
  function ImporterAutoFixIATEx(hProcess:LongInt;pFileName,szSectionName:PAnsiChar;DumpRunningProcess,RealignFile:boolean;EntryPointAddress,ImageBase,SearchStart,SearchSize,SearchStep:LongInt;TryAutoFix,FixEliminations:boolean;UnknownPointerFixCallback:LongInt):LongInt; stdcall;  external 'TitanEngine.dll' name 'ImporterAutoFixIATEx';
{TitanEngine.Hooks.functions}
  function HooksSafeTransitionEx(HookAddressArray:Pointer; NumberOfHooks:LongInt; TransitionStart:boolean):boolean; stdcall;  external 'TitanEngine.dll' name 'HooksSafeTransitionEx';
  function HooksSafeTransition(HookAddressArray:Pointer; TransitionStart:boolean):boolean; stdcall;  external 'TitanEngine.dll' name 'HooksSafeTransition';
  function HooksIsAddressRedirected(HookAddressArray:Pointer):boolean; stdcall;  external 'TitanEngine.dll' name 'HooksIsAddressRedirected';
  function HooksGetTrampolineAddress(HookAddressArray:Pointer):Pointer; stdcall;  external 'TitanEngine.dll' name 'HooksGetTrampolineAddress';
  function HooksGetHookEntryDetails(HookAddressArray:Pointer):Pointer; stdcall;  external 'TitanEngine.dll' name 'HooksGetHookEntryDetails';
  function HooksInsertNewRedirection(HookAddressArray,RedirectTo:Pointer; HookType:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'HooksInsertNewRedirection';
  function HooksInsertNewIATRedirectionEx(FileMapVA,LoadedModuleBase:LongInt; szHookFunction:PAnsiChar; RedirectTo:Pointer):boolean; stdcall;  external 'TitanEngine.dll' name 'HooksInsertNewIATRedirectionEx';
  function HooksInsertNewIATRedirection(szModuleName,szHookFunction:PAnsiChar; RedirectTo:Pointer):boolean; stdcall;  external 'TitanEngine.dll' name 'HooksInsertNewIATRedirection';
  function HooksRemoveRedirection(HookAddressArray:Pointer; RemoveAll:boolean):boolean; stdcall;  external 'TitanEngine.dll' name 'HooksRemoveRedirection';
  function HooksRemoveRedirectionsForModule(ModuleBase:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'HooksRemoveRedirectionsForModule';
  function HooksDisableRedirection(HookAddressArray:Pointer; DisableAll:boolean):boolean; stdcall;  external 'TitanEngine.dll' name 'HooksDisableRedirection';
  function HooksDisableRedirectionsForModule(ModuleBase:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'HooksDisableRedirectionsForModule';
  function HooksEnableRedirection(HookAddressArray:Pointer; EnableAll:boolean):boolean; stdcall;  external 'TitanEngine.dll' name 'HooksEnableRedirection';
  function HooksEnableRedirectionsForModule(ModuleBase:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'HooksEnableRedirectionsForModule';  
  function HooksRemoveIATRedirection(szModuleName,szHookFunction:PAnsiChar; RemoveAll:boolean):boolean; stdcall;  external 'TitanEngine.dll' name 'HooksRemoveIATRedirection';
  function HooksDisableIATRedirection(szModuleName,szHookFunction:PAnsiChar; DisableAll:boolean):boolean; stdcall;  external 'TitanEngine.dll' name 'HooksDisableIATRedirection';
  function HooksEnableIATRedirection(szModuleName,szHookFunction:PAnsiChar; EnableAll:boolean):boolean; stdcall;  external 'TitanEngine.dll' name 'HooksEnableIATRedirection';
  procedure HooksScanModuleMemory(ModuleBase:LongInt; CallBack:Pointer); stdcall;  external 'TitanEngine.dll' name 'HooksScanModuleMemory';
  procedure HooksScanEntireProcessMemory(CallBack:Pointer); stdcall;  external 'TitanEngine.dll' name 'HooksScanEntireProcessMemory';
  procedure HooksScanEntireProcessMemoryEx(); stdcall;  external 'TitanEngine.dll' name 'HooksScanEntireProcessMemoryEx';
{TitanEngine.Tracer.functions}
  procedure TracerInit(); stdcall;  external 'TitanEngine.dll' name 'TracerInit';
  function TracerLevel1(hProcess,APIAddress:LongInt):LongInt; stdcall;  external 'TitanEngine.dll' name 'TracerLevel1';
  function HashTracerLevel1(hProcess,APIAddress,NumberOfInstructions:LongInt):LongInt; stdcall;  external 'TitanEngine.dll' name 'HashTracerLevel1';
  function TracerDetectRedirection(hProcess,APIAddress:LongInt):LongInt; stdcall;  external 'TitanEngine.dll' name 'TracerDetectRedirection';
  function TracerFixKnownRedirection(hProcess,APIAddress,RedirectionId:LongInt):LongInt; stdcall;  external 'TitanEngine.dll' name 'TracerFixKnownRedirection';
  function TracerFixRedirectionViaImpRecPlugin(hProcess:LongInt;szPluginName:PAnsiChar;APIAddress:LongInt):LongInt; stdcall;  external 'TitanEngine.dll' name 'TracerFixRedirectionViaImpRecPlugin';
{TitanEngine.Exporter.functions}
  procedure ExporterCleanup(); stdcall;  external 'TitanEngine.dll' name 'ExporterCleanup';
  procedure ExporterSetImageBase(ImageBase:LongInt); stdcall;  external 'TitanEngine.dll' name 'ExporterSetImageBase';
  procedure ExporterInit(MemorySize,ImageBase,ExportOrdinalBase:LongInt; szExportModuleName:PAnsiChar); stdcall;  external 'TitanEngine.dll' name 'ExporterInit';
  function ExporterAddNewExport(szExportName:PAnsiChar; ExportRelativeAddress:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'ExporterAddNewExport';
  function ExporterAddNewOrdinalExport(OrdinalNumber,ExportRelativeAddress:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'ExporterAddNewOrdinalExport';
  function ExporterGetAddedExportCount():LongInt; stdcall;  external 'TitanEngine.dll' name 'ExporterGetAddedExportCount';
  function ExporterEstimatedSize():LongInt; stdcall;  external 'TitanEngine.dll' name 'ExporterEstimatedSize';
  function ExporterBuildExportTable(StorePlace,FileMapVA:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'ExporterBuildExportTable';
  function ExporterBuildExportTableEx(szExportFileName,szSectionName:PAnsiChar):boolean; stdcall;  external 'TitanEngine.dll' name 'ExporterBuildExportTableEx';
  function ExporterLoadExportTable(szFileName:PAnsiChar):boolean; stdcall;  external 'TitanEngine.dll' name 'ExporterLoadExportTable';
{TitanEngine.Librarian.functions}
  function LibrarianSetBreakPoint(szLibraryName:PAnsiChar; bpxType:LongInt; SingleShoot:boolean; bpxCallBack:Pointer):boolean; stdcall;  external 'TitanEngine.dll' name 'LibrarianSetBreakPoint';
  function LibrarianRemoveBreakPoint(szLibraryName:PAnsiChar; bpxType:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'LibrarianRemoveBreakPoint';
  function LibrarianGetLibraryInfo(szLibraryName:PAnsiChar):Pointer; stdcall;  external 'TitanEngine.dll' name 'LibrarianGetLibraryInfo';
  function LibrarianGetLibraryInfoEx(BaseOfDll:Pointer):Pointer; stdcall;  external 'TitanEngine.dll' name 'LibrarianGetLibraryInfoEx';
  procedure LibrarianEnumLibraryInfo(BaseOfDll:Pointer); stdcall;  external 'TitanEngine.dll' name 'LibrarianEnumLibraryInfo';
{TitanEngine.Process.functions}
  function GetActiveProcessId(szImageName:PAnsiChar):LongInt; stdcall;  external 'TitanEngine.dll' name 'GetActiveProcessId';
  function EnumProcessesWithLibrary(szLibraryName:PAnsiChar; EnumFunction:Pointer):LongInt; stdcall;  external 'TitanEngine.dll' name 'EnumProcessesWithLibrary';
{TitanEngine.TLSFixer.functions}
  function TLSBreakOnCallBack(ArrayOfCallBacks:Pointer; NumberOfCallBacks:LongInt; bpxCallBack:Pointer):boolean; stdcall;  external 'TitanEngine.dll' name 'TLSBreakOnCallBack';
  function TLSGrabCallBackData(szFileName:PAnsiChar; ArrayOfCallBacks,NumberOfCallBacks:Pointer):boolean; stdcall;  external 'TitanEngine.dll' name 'TLSGrabCallBackData';
  function TLSBreakOnCallBackEx(szFileName:PAnsiChar; bpxCallBack:Pointer):boolean; stdcall;  external 'TitanEngine.dll' name 'TLSBreakOnCallBackEx';
  function TLSRemoveCallback(szFileName:PAnsiChar):boolean; stdcall;  external 'TitanEngine.dll' name 'TLSRemoveCallback';
  function TLSRemoveTable(szFileName:PAnsiChar):boolean; stdcall;  external 'TitanEngine.dll' name 'TLSRemoveTable';
  function TLSBackupData(szFileName:PAnsiChar):boolean; stdcall;  external 'TitanEngine.dll' name 'TLSBackupData';
  function TLSRestoreData():boolean; stdcall;  external 'TitanEngine.dll' name 'TLSRestoreData';
  function TLSBuildNewTable(FileMapVA,StorePlace,StorePlaceRVA:LongInt; ArrayOfCallBacks:Pointer; NumberOfCallBacks:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'TLSBuildNewTable';
  function TLSBuildNewTableEx(szFileName,szSectionName:PAnsiChar; ArrayOfCallBacks:Pointer; NumberOfCallBacks:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'TLSBuildNewTableEx';
{TitanEngine.TranslateName.functions}
  function TranslateNativeName(szNativeName:PAnsiChar):PAnsiChar; stdcall;  external 'TitanEngine.dll' name 'TranslateNativeName';
{TitanEngine.Handler.functions}
  function HandlerGetActiveHandleCount(ProcessId:LongInt):LongInt; stdcall;  external 'TitanEngine.dll' name 'HandlerGetActiveHandleCount';
  function HandlerIsHandleOpen(ProcessId:LongInt; hHandle:THandle):boolean; stdcall;  external 'TitanEngine.dll' name 'HandlerIsHandleOpen';
  function HandlerGetHandleName(hProcess:THandle; ProcessId:LongInt; hHandle:THandle; TranslateName:boolean):PAnsiChar; stdcall;  external 'TitanEngine.dll' name 'HandlerGetHandleName';
  function HandlerEnumerateOpenHandles(ProcessId:LongInt; HandleBuffer:Pointer; MaxHandleCount:LongInt):LongInt; stdcall;  external 'TitanEngine.dll' name 'HandlerEnumerateOpenHandles';
  function HandlerGetHandleDetails(hProcess:THandle; ProcessId:LongInt; hHandle:THandle; InformationReturn:LongInt):LongInt; stdcall;  external 'TitanEngine.dll' name 'HandlerGetHandleDetails';
  function HandlerCloseRemoteHandle(ProcessId:LongInt; hHandle:THandle):boolean; stdcall;  external 'TitanEngine.dll' name 'HandlerCloseRemoteHandle';
  function HandlerEnumerateLockHandles(szFileOrFolderName:PAnsiChar; NameIsFolder,NameIsTranslated:boolean; HandleDataBuffer:Pointer; MaxHandleCount:LongInt):LongInt; stdcall;  external 'TitanEngine.dll' name 'HandlerEnumerateLockHandles';
  function HandlerCloseAllLockHandles(szFileOrFolderName:PAnsiChar; NameIsFolder,NameIsTranslated:boolean):boolean; stdcall;  external 'TitanEngine.dll' name 'HandlerCloseAllLockHandles';
  function HandlerIsFileLocked(szFileOrFolderName:PAnsiChar; NameIsFolder,NameIsTranslated:boolean):boolean; stdcall;  external 'TitanEngine.dll' name 'HandlerIsFileLocked';
  function HandlerEnumerateOpenMutexes(hProcess:THandle; ProcessId:LongInt; HandleBuffer:Pointer; MaxHandleCount:LongInt):LongInt; stdcall;  external 'TitanEngine.dll' name 'HandlerEnumerateOpenMutexes';
  function HandlerGetOpenMutexHandle(hProcess:THandle; ProcessId:LongInt; szMutexString:PAnsiChar):LongInt; stdcall;  external 'TitanEngine.dll' name 'HandlerGetOpenMutexHandle';
  function HandlerGetProcessIdWhichCreatedMutex(szMutexString:PAnsiChar):LongInt; stdcall;  external 'TitanEngine.dll' name 'HandlerGetProcessIdWhichCreatedMutex';
{TitanEngine.Injector.functions}
  function RemoteLoadLibrary(hProcess:THandle; szLibraryFile:PAnsiChar; WaitForThreadExit:boolean):boolean; stdcall;  external 'TitanEngine.dll' name 'RemoteLoadLibrary';
  function RemoteFreeLibrary(hProcess:THandle; hModule:LongInt; szLibraryFile:PAnsiChar; WaitForThreadExit:boolean):boolean; stdcall;  external 'TitanEngine.dll' name 'RemoteFreeLibrary';
  function RemoteExitProcess(hProcess:THandle; ExitCode:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'RemoteExitProcess';
{TitanEngine.StaticUnpacker.functions}
  function StaticFileLoad(szFileName:PAnsiChar; DesiredAccess:LongInt; SimulateLoad:boolean; FileHandle,LoadedSize,FileMap,FileMapVA:Pointer):boolean; stdcall;  external 'TitanEngine.dll' name 'StaticFileLoad';
  function StaticFileUnload(szFileName:PAnsiChar; CommitChanges:boolean; FileHandle,LoadedSize,FileMap,FileMapVA:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'StaticFileUnload';
  function StaticFileOpen(szFileName:PAnsiChar; DesiredAccess:LongInt; FileHandle,FileSizeLow,FileSizeHigh:Pointer):boolean; stdcall;  external 'TitanEngine.dll' name 'StaticFileOpen';
  function StaticFileGetContent(FileHandle:THandle; FilePositionLow:LongInt; FilePositionHigh,Buffer:Pointer; Size:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'StaticFileGetContent';
  procedure StaticFileClose(FileHandle:THandle); stdcall;  external 'TitanEngine.dll' name 'StaticFileClose';
  procedure StaticMemoryDecrypt(MemoryStart,MemorySize,DecryptionType,DecryptionKeySize,DecryptionKey:LongInt); stdcall;  external 'TitanEngine.dll' name 'StaticMemoryDecrypt';
  procedure StaticMemoryDecryptEx(MemoryStart,MemorySize,DecryptionKeySize:LongInt; DecryptionCallBack:Pointer); stdcall;  external 'TitanEngine.dll' name 'StaticMemoryDecryptEx';
  procedure StaticMemoryDecryptSpecial(MemoryStart,MemorySize,DecryptionKeySize,SpecDecryptionType:LongInt; DecryptionCallBack:Pointer); stdcall;  external 'TitanEngine.dll' name 'StaticMemoryDecryptSpecial';
  procedure StaticSectionDecrypt(FileMapVA,SectionNumber:LongInt; SimulateLoad:boolean; DecryptionType,DecryptionKeySize,DecryptionKey:LongInt); stdcall;  external 'TitanEngine.dll' name 'StaticSectionDecrypt';
  function StaticMemoryDecompress(Source,SourceSize,Destination,DestinationSize,Algorithm:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'StaticMemoryDecompress';
  function StaticRawMemoryCopy(hFile:THandle; FileMapVA,VitualAddressToCopy,Size:LongInt; AddressIsRVA:boolean; szDumpFileName:PAnsiChar):boolean; stdcall;  external 'TitanEngine.dll' name 'StaticRawMemoryCopy';
  function StaticHashMemory(MemoryToHash:Pointer; SizeOfMemory:LongInt; HashDigest:Pointer; OutputString:boolean; Algorithm:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'StaticHashMemory';
  function StaticHashFile(szFileName,HashDigest:PAnsiChar; OutputString:boolean; Algorithm:LongInt):boolean; stdcall;  external 'TitanEngine.dll' name 'StaticHashFile';
{TitanEngine.Engine.functions}
  procedure SetEngineVariable(VariableId:LongInt; VariableSet:boolean); stdcall;  external 'TitanEngine.dll' name 'SetEngineVariable';
  function EngineCreateMissingDependencies(szFileName,szOutputFolder:PAnsiChar; LogCreatedFiles:boolean):boolean; stdcall;  external 'TitanEngine.dll' name 'EngineCreateMissingDependencies';
  function EngineFakeMissingDependencies(hProcess:THandle):boolean; stdcall;  external 'TitanEngine.dll' name 'EngineCreateMissingDependencies';
  function EngineDeleteCreatedDependencies():boolean; stdcall;  external 'TitanEngine.dll' name 'EngineDeleteCreatedDependencies';
  function EngineCreateUnpackerWindow(WindowUnpackerTitle,WindowUnpackerLongTitleWindowUnpackerName,WindowUnpackerAuthor:PChar; StartUnpackingCallBack:Pointer):boolean; stdcall;  external 'TitanEngine.dll' name 'EngineCreateUnpackerWindow';
  procedure EngineAddUnpackerWindowLogMessage(szLogMessage:PChar); stdcall;  external 'TitanEngine.dll' name 'EngineAddUnpackerWindowLogMessage';
{TitanEngine.Extension.functions}
  function ExtensionManagerIsPluginLoaded(szPluginName:PAnsiChar):boolean; stdcall;  external 'TitanEngine.dll' name 'ExtensionManagerIsPluginLoaded';
  function ExtensionManagerIsPluginEnabled(szPluginName:PAnsiChar):boolean; stdcall;  external 'TitanEngine.dll' name 'ExtensionManagerIsPluginEnabled';
  function ExtensionManagerDisableAllPlugins():boolean; stdcall;  external 'TitanEngine.dll' name 'ExtensionManagerDisableAllPlugins';
  function ExtensionManagerDisablePlugin(szPluginName:PAnsiChar):boolean; stdcall;  external 'TitanEngine.dll' name 'ExtensionManagerDisablePlugin';
  function ExtensionManagerEnableAllPlugins():boolean; stdcall;  external 'TitanEngine.dll' name 'ExtensionManagerEnableAllPlugins';
  function ExtensionManagerEnablePlugin(szPluginName:PAnsiChar):boolean; stdcall;  external 'TitanEngine.dll' name 'ExtensionManagerEnablePlugin';
  function ExtensionManagerUnloadAllPlugins():boolean; stdcall;  external 'TitanEngine.dll' name 'ExtensionManagerUnloadAllPlugins';
  function ExtensionManagerUnloadPlugin(szPluginName:PAnsiChar):boolean; stdcall;  external 'TitanEngine.dll' name 'ExtensionManagerUnloadPlugin';
  function ExtensionManagerGetPluginInfo(szPluginName:PAnsiChar):Pointer; stdcall;  external 'TitanEngine.dll' name 'ExtensionManagerGetPluginInfo';

implementation

end.
