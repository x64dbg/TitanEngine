;--- include file created by h2incx v0.99.20 (copyright 2005-2009 japheth)
;--- source file: C:\Users\Administrator\Desktop\h2incx\SDK.h, last modified: 3/8/2010 17:0
;--- cmdline used for creation:  -a -b -d3 -y sdk.h

include windows.inc
includelib TitanEngine_x86.lib
 
UE_ACCESS_READ	EQU	0
UE_ACCESS_WRITE	EQU	1
UE_ACCESS_ALL	EQU	2
UE_HIDE_BASIC	EQU	1
UE_PLUGIN_CALL_REASON_PREDEBUG	EQU	1
UE_PLUGIN_CALL_REASON_EXCEPTION	EQU	2
UE_PLUGIN_CALL_REASON_POSTDEBUG	EQU	3
TEE_HOOK_NRM_JUMP	EQU	1
TEE_HOOK_NRM_CALL	EQU	3
TEE_HOOK_IAT	EQU	5
UE_ENGINE_ALOW_MODULE_LOADING	EQU	1
UE_ENGINE_AUTOFIX_FORWARDERS	EQU	2
UE_ENGINE_PASS_ALL_EXCEPTIONS	EQU	3
UE_ENGINE_NO_CONSOLE_WINDOW	EQU	4
UE_ENGINE_BACKUP_FOR_CRITICAL_FUNCTIONS	EQU	5
UE_ENGINE_CALL_PLUGIN_CALLBACK	EQU	6
UE_ENGINE_RESET_CUSTOM_HANDLER	EQU	7
UE_ENGINE_CALL_PLUGIN_DEBUG_CALLBACK	EQU	8
UE_OPTION_REMOVEALL	EQU	1
UE_OPTION_DISABLEALL	EQU	2
UE_OPTION_REMOVEALLDISABLED	EQU	3
UE_OPTION_REMOVEALLENABLED	EQU	4
UE_STATIC_DECRYPTOR_XOR	EQU	1
UE_STATIC_DECRYPTOR_SUB	EQU	2
UE_STATIC_DECRYPTOR_ADD	EQU	3
UE_STATIC_DECRYPTOR_FOREWARD	EQU	1
UE_STATIC_DECRYPTOR_BACKWARD	EQU	2
UE_STATIC_KEY_SIZE_1	EQU	1
UE_STATIC_KEY_SIZE_2	EQU	2
UE_STATIC_KEY_SIZE_4	EQU	4
UE_STATIC_KEY_SIZE_8	EQU	8
UE_STATIC_APLIB	EQU	1
UE_STATIC_APLIB_DEPACK	EQU	2
UE_STATIC_LZMA	EQU	3
UE_STATIC_HASH_MD5	EQU	1
UE_STATIC_HASH_SHA1	EQU	2
UE_STATIC_HASH_CRC32	EQU	3
UE_RESOURCE_LANGUAGE_ANY	EQU	- 1
UE_PE_OFFSET	EQU	0
UE_IMAGEBASE	EQU	1
UE_OEP	EQU	2
UE_SIZEOFIMAGE	EQU	3
UE_SIZEOFHEADERS	EQU	4
UE_SIZEOFOPTIONALHEADER	EQU	5
UE_SECTIONALIGNMENT	EQU	6
UE_IMPORTTABLEADDRESS	EQU	7
UE_IMPORTTABLESIZE	EQU	8
UE_RESOURCETABLEADDRESS	EQU	9
UE_RESOURCETABLESIZE	EQU	10
UE_EXPORTTABLEADDRESS	EQU	11
UE_EXPORTTABLESIZE	EQU	12
UE_TLSTABLEADDRESS	EQU	13
UE_TLSTABLESIZE	EQU	14
UE_RELOCATIONTABLEADDRESS	EQU	15
UE_RELOCATIONTABLESIZE	EQU	16
UE_TIMEDATESTAMP	EQU	17
UE_SECTIONNUMBER	EQU	18
UE_CHECKSUM	EQU	19
UE_SUBSYSTEM	EQU	20
UE_CHARACTERISTICS	EQU	21
UE_NUMBEROFRVAANDSIZES	EQU	22
UE_SECTIONNAME	EQU	23
UE_SECTIONVIRTUALOFFSET	EQU	24
UE_SECTIONVIRTUALSIZE	EQU	25
UE_SECTIONRAWOFFSET	EQU	26
UE_SECTIONRAWSIZE	EQU	27
UE_SECTIONFLAGS	EQU	28
UE_CH_BREAKPOINT	EQU	1
UE_CH_SINGLESTEP	EQU	2
UE_CH_ACCESSVIOLATION	EQU	3
UE_CH_ILLEGALINSTRUCTION	EQU	4
UE_CH_NONCONTINUABLEEXCEPTION	EQU	5
UE_CH_ARRAYBOUNDSEXCEPTION	EQU	6
UE_CH_FLOATDENORMALOPERAND	EQU	7
UE_CH_FLOATDEVIDEBYZERO	EQU	8
UE_CH_INTEGERDEVIDEBYZERO	EQU	9
UE_CH_INTEGEROVERFLOW	EQU	10
UE_CH_PRIVILEGEDINSTRUCTION	EQU	11
UE_CH_PAGEGUARD	EQU	12
UE_CH_EVERYTHINGELSE	EQU	13
UE_CH_CREATETHREAD	EQU	14
UE_CH_EXITTHREAD	EQU	15
UE_CH_CREATEPROCESS	EQU	16
UE_CH_EXITPROCESS	EQU	17
UE_CH_LOADDLL	EQU	18
UE_CH_UNLOADDLL	EQU	19
UE_CH_OUTPUTDEBUGSTRING	EQU	20
UE_CH_AFTEREXCEPTIONPROCESSING	EQU	21
UE_CH_ALLEVENTS	EQU	22
UE_CH_SYSTEMBREAKPOINT EQU 23
UE_CH_UNHANDLEDEXCEPTION EQU 24

UE_OPTION_HANDLER_RETURN_HANDLECOUNT	EQU	1
UE_OPTION_HANDLER_RETURN_ACCESS	EQU	2
UE_OPTION_HANDLER_RETURN_FLAGS	EQU	3
UE_OPTION_HANDLER_RETURN_TYPENAME	EQU	4
UE_BREAKPOINT_INT3 EQU 1
UE_BREAKPOINT_LONG_INT3 EQU 2
UE_BREAKPOINT_UD2 EQU 3
UE_BPXREMOVED	EQU	0
UE_BPXACTIVE	EQU	1
UE_BPXINACTIVE	EQU	2
UE_BREAKPOINT	EQU	0
UE_SINGLESHOOT	EQU	1
UE_HARDWARE	EQU	2
UE_MEMORY	EQU	3
UE_MEMORY_READ	EQU	4
UE_MEMORY_WRITE	EQU	5
UE_BREAKPOINT_TYPE_INT3 EQU 10000000h
UE_BREAKPOINT_TYPE_LONG_INT3 EQU 20000000h
UE_BREAKPOINT_TYPE_UD2 EQU 30000000h
UE_HARDWARE_EXECUTE	EQU	4
UE_HARDWARE_WRITE	EQU	5
UE_HARDWARE_READWRITE	EQU	6
UE_HARDWARE_SIZE_1	EQU	7
UE_HARDWARE_SIZE_2	EQU	8
UE_HARDWARE_SIZE_4	EQU	9
UE_ON_LIB_LOAD	EQU	1
UE_ON_LIB_UNLOAD	EQU	2
UE_ON_LIB_ALL	EQU	3
UE_APISTART	EQU	0
UE_APIEND	EQU	1
UE_PLATFORM_x86	EQU	1
UE_PLATFORM_x64	EQU	2
UE_PLATFORM_ALL	EQU	3
UE_FUNCTION_STDCALL	EQU	1
UE_FUNCTION_CCALL	EQU	2
UE_FUNCTION_FASTCALL	EQU	3
UE_FUNCTION_STDCALL_RET	EQU	4
UE_FUNCTION_CCALL_RET	EQU	5
UE_FUNCTION_FASTCALL_RET	EQU	6
UE_FUNCTION_STDCALL_CALL	EQU	7
UE_FUNCTION_CCALL_CALL	EQU	8
UE_FUNCTION_FASTCALL_CALL	EQU	9
UE_PARAMETER_BYTE	EQU	0
UE_PARAMETER_WORD	EQU	1
UE_PARAMETER_DWORD	EQU	2
UE_PARAMETER_QWORD	EQU	3
UE_PARAMETER_PTR_BYTE	EQU	4
UE_PARAMETER_PTR_WORD	EQU	5
UE_PARAMETER_PTR_DWORD	EQU	6
UE_PARAMETER_PTR_QWORD	EQU	7
UE_PARAMETER_STRING	EQU	8
UE_PARAMETER_UNICODE	EQU	9
UE_CMP_NOCONDITION	EQU	0
UE_CMP_EQUAL	EQU	1
UE_CMP_NOTEQUAL	EQU	2
UE_CMP_GREATER	EQU	3
UE_CMP_GREATEROREQUAL	EQU	4
UE_CMP_LOWER	EQU	5
UE_CMP_LOWEROREQUAL	EQU	6
UE_CMP_REG_EQUAL	EQU	7
UE_CMP_REG_NOTEQUAL	EQU	8
UE_CMP_REG_GREATER	EQU	9
UE_CMP_REG_GREATEROREQUAL	EQU	10
UE_CMP_REG_LOWER	EQU	11
UE_CMP_REG_LOWEROREQUAL	EQU	12
UE_CMP_ALWAYSFALSE	EQU	13
UE_EAX	EQU	1
UE_EBX	EQU	2
UE_ECX	EQU	3
UE_EDX	EQU	4
UE_EDI	EQU	5
UE_ESI	EQU	6
UE_EBP	EQU	7
UE_ESP	EQU	8
UE_EIP	EQU	9
UE_EFLAGS	EQU	10
UE_DR0	EQU	11
UE_DR1	EQU	12
UE_DR2	EQU	13
UE_DR3	EQU	14
UE_DR6	EQU	15
UE_DR7	EQU	16
UE_RAX	EQU	17
UE_RBX	EQU	18
UE_RCX	EQU	19
UE_RDX	EQU	20
UE_RDI	EQU	21
UE_RSI	EQU	22
UE_RBP	EQU	23
UE_RSP	EQU	24
UE_RIP	EQU	25
UE_RFLAGS	EQU	26
UE_R8	EQU	27
UE_R9	EQU	28
UE_R10	EQU	29
UE_R11	EQU	30
UE_R12	EQU	31
UE_R13	EQU	32
UE_R14	EQU	33
UE_R15	EQU	34
UE_CIP	EQU	35
UE_CSP	EQU	36
UE_SEG_GS	EQU	37
UE_SEG_FS	EQU	38
UE_SEG_ES	EQU	39
UE_SEG_DS	EQU	40
UE_SEG_CS	EQU	41
UE_SEG_SS	EQU	42
ifndef @align
@align equ <>
endif
PE32Struct	struct @align
PE32Offset	DWORD	?
ImageBase	DWORD	?
OriginalEntryPoint	DWORD	?
NtSizeOfImage	DWORD	?
NtSizeOfHeaders	DWORD	?
SizeOfOptionalHeaders	WORD	?
FileAlignment	DWORD	?
SectionAligment	DWORD	?
ImportTableAddress	DWORD	?
ImportTableSize	DWORD	?
ResourceTableAddress	DWORD	?
ResourceTableSize	DWORD	?
ExportTableAddress	DWORD	?
ExportTableSize	DWORD	?
TLSTableAddress	DWORD	?
TLSTableSize	DWORD	?
RelocationTableAddress	DWORD	?
RelocationTableSize	DWORD	?
TimeDateStamp	DWORD	?
SectionNumber	WORD	?
CheckSum	DWORD	?
SubSystem	WORD	?
Characteristics	WORD	?
NumberOfRvaAndSizes	DWORD	?
PE32Struct	ends

PPE32Struct typedef ptr PE32Struct

ImportEnumData	struct @align
NewDll	bool	?
NumberOfImports	DWORD	?
ImageBase	DWORD	?
BaseImportThunk	DWORD	?
ImportThunk	DWORD	?
APIName	DWORD	?
DLLName	DWORD	?
ImportEnumData	ends

PImportEnumData typedef ptr ImportEnumData

THREAD_ITEM_DATA	struct @align
hThread	HANDLE	?
dwThreadId	DWORD	?
ThreadStartAddress	DWORD	?
ThreadLocalBase	DWORD	?
THREAD_ITEM_DATA	ends

PTHREAD_ITEM_DATA typedef ptr THREAD_ITEM_DATA

LIBRARY_ITEM_DATA	struct @align
hFile	HANDLE	?
BaseOfDll	DWORD	?
hFileMapping	HANDLE	?
hFileMappingView	DWORD	?
szLibraryPath	SBYTE MAX_PATH dup (?)
szLibraryName	SBYTE MAX_PATH dup (?)
LIBRARY_ITEM_DATA	ends

PLIBRARY_ITEM_DATA typedef ptr LIBRARY_ITEM_DATA

LIBRARY_ITEM_DATAW	struct @align
hFile	HANDLE	?
BaseOfDll	DWORD	?
hFileMapping	HANDLE	?
hFileMappingView	DWORD	?
szLibraryPath	WORD MAX_PATH dup (?)
szLibraryName	WORD MAX_PATH dup (?)
LIBRARY_ITEM_DATAW	ends

PLIBRARY_ITEM_DATAW typedef ptr LIBRARY_ITEM_DATAW

PROCESS_ITEM_DATA	struct @align
hProcess	HANDLE	?
dwProcessId	DWORD	?
hThread	HANDLE	?
dwThreadId	DWORD	?
hFile	HANDLE	?
BaseOfImage	DWORD	?
ThreadStartAddress	DWORD	?
ThreadLocalBase	DWORD	?
PROCESS_ITEM_DATA	ends

PPROCESS_ITEM_DATA typedef ptr PROCESS_ITEM_DATA

HandlerArray	struct @align
ProcessId	DWORD	?
hHandle	HANDLE	?
HandlerArray	ends

PHandlerArray typedef ptr HandlerArray

PluginInformation	struct @align
PluginName	SBYTE 64 dup (?)
PluginMajorVersion	DWORD	?
PluginMinorVersion	DWORD	?
PluginBaseAddress	HMODULE	?
TitanDebuggingCallBack	DWORD	?
TitanRegisterPlugin	DWORD	?
TitanReleasePlugin	DWORD	?
TitanResetPlugin	DWORD	?
PluginDisabled	bool	?
PluginInformation	ends

PPluginInformation typedef ptr PluginInformation

TEE_MAXIMUM_HOOK_SIZE	EQU	14
TEE_MAXIMUM_HOOK_RELOCS	EQU	7
TEE_MAXIMUM_HOOK_INSERT_SIZE	EQU	5

HOOK_ENTRY	struct @align
IATHook	bool	?
HookType	BYTE	?
HookSize	DWORD	?
HookAddress	DWORD	?
RedirectionAddress	DWORD	?
HookBytes	BYTE TEE_MAXIMUM_HOOK_SIZE dup (?)
OriginalBytes	BYTE TEE_MAXIMUM_HOOK_SIZE dup (?)
IATHookModuleBase	DWORD	?
IATHookNameHash	DWORD	?
HookIsEnabled	bool	?
HookIsRemote	bool	?
PatchedEntry	DWORD	?
RelocationInfo	DWORD TEE_MAXIMUM_HOOK_RELOCS dup (?)
RelocationCount	DWORD	?
HOOK_ENTRY	ends

PHOOK_ENTRY typedef ptr HOOK_ENTRY

UE_DEPTH_SURFACE	EQU	0
UE_DEPTH_DEEP	EQU	1
UE_UNPACKER_CONDITION_SEARCH_FROM_EP	EQU	1
UE_UNPACKER_CONDITION_LOADLIBRARY	EQU	1
UE_UNPACKER_CONDITION_GETPROCADDRESS	EQU	2
UE_UNPACKER_CONDITION_ENTRYPOINTBREAK	EQU	3
UE_UNPACKER_CONDITION_RELOCSNAPSHOT1	EQU	4
UE_UNPACKER_CONDITION_RELOCSNAPSHOT2	EQU	5
UE_FIELD_OK	EQU	0
UE_FIELD_BROKEN_NON_FIXABLE	EQU	1
UE_FIELD_BROKEN_NON_CRITICAL	EQU	2
UE_FIELD_BROKEN_FIXABLE_FOR_STATIC_USE	EQU	3
UE_FIELD_BROKEN_BUT_CAN_BE_EMULATED	EQU	4
UE_FILED_FIXABLE_NON_CRITICAL	EQU	5
UE_FILED_FIXABLE_CRITICAL	EQU	6
UE_FIELD_NOT_PRESET	EQU	7
UE_FIELD_NOT_PRESET_WARNING	EQU	8
UE_RESULT_FILE_OK	EQU	10
UE_RESULT_FILE_INVALID_BUT_FIXABLE	EQU	11
UE_RESULT_FILE_INVALID_AND_NON_FIXABLE	EQU	12
UE_RESULT_FILE_INVALID_FORMAT	EQU	13
FILE_STATUS_INFO	struct @align
OveralEvaluation	BYTE	?
EvaluationTerminatedByException	bool	?
FileIs64Bit	bool	?
FileIsDLL	bool	?
FileIsConsole	bool	?
MissingDependencies	bool	?
MissingDeclaredAPIs	bool	?
SignatureMZ	BYTE	?
SignaturePE	BYTE	?
EntryPoint	BYTE	?
ImageBase	BYTE	?
SizeOfImage	BYTE	?
FileAlignment	BYTE	?
SectionAlignment	BYTE	?
ExportTable	BYTE	?
RelocationTable	BYTE	?
ImportTable	BYTE	?
ImportTableSection	BYTE	?
ImportTableData	BYTE	?
IATTable	BYTE	?
TLSTable	BYTE	?
LoadConfigTable	BYTE	?
BoundImportTable	BYTE	?
COMHeaderTable	BYTE	?
ResourceTable	BYTE	?
ResourceData	BYTE	?
SectionTable	BYTE	?
FILE_STATUS_INFO	ends

PFILE_STATUS_INFO typedef ptr FILE_STATUS_INFO

FILE_FIX_INFO	struct @align
OveralEvaluation	BYTE	?
FixingTerminatedByException	bool	?
FileFixPerformed	bool	?
StrippedRelocation	bool	?
DontFixRelocations	bool	?
OriginalRelocationTableAddress	DWORD	?
OriginalRelocationTableSize	DWORD	?
StrippedExports	bool	?
DontFixExports	bool	?
OriginalExportTableAddress	DWORD	?
OriginalExportTableSize	DWORD	?
StrippedResources	bool	?
DontFixResources	bool	?
OriginalResourceTableAddress	DWORD	?
OriginalResourceTableSize	DWORD	?
StrippedTLS	bool	?
DontFixTLS	bool	?
OriginalTLSTableAddress	DWORD	?
OriginalTLSTableSize	DWORD	?
StrippedLoadConfig	bool	?
DontFixLoadConfig	bool	?
OriginalLoadConfigTableAddress	DWORD	?
OriginalLoadConfigTableSize	DWORD	?
StrippedBoundImports	bool	?
DontFixBoundImports	bool	?
OriginalBoundImportTableAddress	DWORD	?
OriginalBoundImportTableSize	DWORD	?
StrippedIAT	bool	?
DontFixIAT	bool	?
OriginalImportAddressTableAddress	DWORD	?
OriginalImportAddressTableSize	DWORD	?
StrippedCOM	bool	?
DontFixCOM	bool	?
OriginalCOMTableAddress	DWORD	?
OriginalCOMTableSize	DWORD	?
FILE_FIX_INFO	ends

PFILE_FIX_INFO typedef ptr FILE_FIX_INFO

DumpProcess proto stdcall :HANDLE, :LPVOID, :ptr SBYTE, :DWORD
DumpProcessW proto stdcall :HANDLE, :LPVOID, :ptr WORD, :DWORD
DumpProcessEx proto stdcall :DWORD, :LPVOID, :ptr SBYTE, :DWORD
DumpProcessExW proto stdcall :DWORD, :LPVOID, :ptr WORD, :DWORD
DumpMemory proto stdcall :HANDLE, :LPVOID, :DWORD, :ptr SBYTE
DumpMemoryW proto stdcall :HANDLE, :LPVOID, :DWORD, :ptr WORD
DumpMemoryEx proto stdcall :DWORD, :LPVOID, :DWORD, :ptr SBYTE
DumpMemoryExW proto stdcall :DWORD, :LPVOID, :DWORD, :ptr WORD
DumpRegions proto stdcall :HANDLE, :ptr SBYTE, :bool
DumpRegionsW proto stdcall :HANDLE, :ptr WORD, :bool
DumpRegionsEx proto stdcall :DWORD, :ptr SBYTE, :bool
DumpRegionsExW proto stdcall :DWORD, :ptr WORD, :bool
DumpModule proto stdcall :HANDLE, :LPVOID, :ptr SBYTE
DumpModuleW proto stdcall :HANDLE, :LPVOID, :ptr WORD
DumpModuleEx proto stdcall :DWORD, :LPVOID, :ptr SBYTE
DumpModuleExW proto stdcall :DWORD, :LPVOID, :ptr WORD
PastePEHeader proto stdcall :HANDLE, :LPVOID, :ptr SBYTE
PastePEHeaderW proto stdcall :HANDLE, :LPVOID, :ptr WORD
ExtractSection proto stdcall :ptr SBYTE, :ptr SBYTE, :DWORD
ExtractSectionW proto stdcall :ptr WORD, :ptr WORD, :DWORD
ResortFileSections proto stdcall :ptr SBYTE
ResortFileSectionsW proto stdcall :ptr WORD
FindOverlay proto stdcall :ptr SBYTE, :LPDWORD, :LPDWORD
FindOverlayW proto stdcall :ptr WORD, :LPDWORD, :LPDWORD
ExtractOverlay proto stdcall :ptr SBYTE, :ptr SBYTE
ExtractOverlayW proto stdcall :ptr WORD, :ptr WORD
AddOverlay proto stdcall :ptr SBYTE, :ptr SBYTE
AddOverlayW proto stdcall :ptr WORD, :ptr WORD
CopyOverlay proto stdcall :ptr SBYTE, :ptr SBYTE
CopyOverlayW proto stdcall :ptr WORD, :ptr WORD
RemoveOverlay proto stdcall :ptr SBYTE
RemoveOverlayW proto stdcall :ptr WORD
MakeAllSectionsRWE proto stdcall :ptr SBYTE
MakeAllSectionsRWEW proto stdcall :ptr WORD
AddNewSectionEx proto stdcall :ptr SBYTE, :ptr SBYTE, :DWORD, :DWORD, :LPVOID, :DWORD
AddNewSectionExW proto stdcall :ptr WORD, :ptr SBYTE, :DWORD, :DWORD, :LPVOID, :DWORD
AddNewSection proto stdcall :ptr SBYTE, :ptr SBYTE, :DWORD
AddNewSectionW proto stdcall :ptr WORD, :ptr SBYTE, :DWORD
ResizeLastSection proto stdcall :ptr SBYTE, :DWORD, :bool
ResizeLastSectionW proto stdcall :ptr WORD, :DWORD, :bool
SetSharedOverlay proto stdcall :ptr SBYTE
SetSharedOverlayW proto stdcall :ptr WORD
GetSharedOverlay proto stdcall 
GetSharedOverlayW proto stdcall 
DeleteLastSection proto stdcall :ptr SBYTE
DeleteLastSectionW proto stdcall :ptr WORD
DeleteLastSectionEx proto stdcall :ptr SBYTE, :DWORD
DeleteLastSectionExW proto stdcall :ptr WORD, :DWORD
GetPE32DataFromMappedFile proto stdcall :DWORD, :DWORD, :DWORD
GetPE32Data proto stdcall :ptr SBYTE, :DWORD, :DWORD
GetPE32DataW proto stdcall :ptr WORD, :DWORD, :DWORD
GetPE32DataFromMappedFileEx proto stdcall :DWORD, :LPVOID
GetPE32DataEx proto stdcall :ptr SBYTE, :LPVOID
GetPE32DataExW proto stdcall :ptr WORD, :LPVOID
SetPE32DataForMappedFile proto stdcall :DWORD, :DWORD, :DWORD, :DWORD
SetPE32Data proto stdcall :ptr SBYTE, :DWORD, :DWORD, :DWORD
SetPE32DataW proto stdcall :ptr WORD, :DWORD, :DWORD, :DWORD
SetPE32DataForMappedFileEx proto stdcall :DWORD, :LPVOID
SetPE32DataEx proto stdcall :ptr SBYTE, :LPVOID
GetPE32SectionNumberFromVA proto stdcall :DWORD, :DWORD
ConvertVAtoFileOffset proto stdcall :DWORD, :DWORD, :bool
ConvertVAtoFileOffsetEx proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :bool, :bool
ConvertFileOffsetToVA proto stdcall :DWORD, :DWORD, :bool
ConvertFileOffsetToVAEx proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :bool
FixHeaderCheckSum proto stdcall :ptr SBYTE
FixHeaderCheckSumW proto stdcall :ptr WORD
RealignPE proto stdcall :DWORD, :DWORD, :DWORD
RealignPEEx proto stdcall :ptr SBYTE, :DWORD, :DWORD
RealignPEExW proto stdcall :ptr WORD, :DWORD, :DWORD
WipeSection proto stdcall :ptr SBYTE, :DWORD, :bool
WipeSectionW proto stdcall :ptr WORD, :DWORD, :bool
IsPE32FileValidEx proto stdcall :ptr SBYTE, :DWORD, :LPVOID
IsPE32FileValidExW proto stdcall :ptr WORD, :DWORD, :LPVOID
FixBrokenPE32FileEx proto stdcall :ptr SBYTE, :LPVOID, :LPVOID
FixBrokenPE32FileExW proto stdcall :ptr WORD, :LPVOID, :LPVOID
IsFileDLL proto stdcall :ptr SBYTE, :DWORD
IsFileDLLW proto stdcall :ptr WORD, :DWORD
GetPEBLocation proto stdcall :HANDLE
HideDebugger proto stdcall :HANDLE, :DWORD
UnHideDebugger proto stdcall :HANDLE, :DWORD
RelocaterCleanup proto stdcall 
RelocaterInit proto stdcall :DWORD, :DWORD, :DWORD
RelocaterAddNewRelocation proto stdcall :HANDLE, :DWORD, :DWORD
RelocaterEstimatedSize proto stdcall 
RelocaterExportRelocation proto stdcall :DWORD, :DWORD, :DWORD
RelocaterExportRelocationEx proto stdcall :ptr SBYTE, :ptr SBYTE
RelocaterExportRelocationExW proto stdcall :ptr WORD, :ptr SBYTE
RelocaterGrabRelocationTable proto stdcall :HANDLE, :DWORD, :DWORD
RelocaterGrabRelocationTableEx proto stdcall :HANDLE, :DWORD, :DWORD, :DWORD
RelocaterMakeSnapshot proto stdcall :HANDLE, :ptr SBYTE, :LPVOID, :DWORD
RelocaterMakeSnapshotW proto stdcall :HANDLE, :ptr WORD, :LPVOID, :DWORD
RelocaterCompareTwoSnapshots proto stdcall :HANDLE, :DWORD, :DWORD, :ptr SBYTE, :ptr SBYTE, :DWORD
RelocaterCompareTwoSnapshotsW proto stdcall :HANDLE, :DWORD, :DWORD, :ptr WORD, :ptr WORD, :DWORD
RelocaterChangeFileBase proto stdcall :ptr SBYTE, :DWORD
RelocaterChangeFileBaseW proto stdcall :ptr WORD, :DWORD
RelocaterRelocateMemoryBlock proto stdcall :DWORD, :DWORD, :ptr , :DWORD, :DWORD, :DWORD
RelocaterWipeRelocationTable proto stdcall :ptr SBYTE
RelocaterWipeRelocationTableW proto stdcall :ptr WORD
ResourcerLoadFileForResourceUse proto stdcall :ptr SBYTE
ResourcerLoadFileForResourceUseW proto stdcall :ptr WORD
ResourcerFreeLoadedFile proto stdcall :LPVOID
ResourcerExtractResourceFromFileEx proto stdcall :DWORD, :ptr SBYTE, :ptr SBYTE, :ptr SBYTE
ResourcerExtractResourceFromFile proto stdcall :ptr SBYTE, :ptr SBYTE, :ptr SBYTE, :ptr SBYTE
ResourcerExtractResourceFromFileW proto stdcall :ptr WORD, :ptr SBYTE, :ptr SBYTE, :ptr SBYTE
ResourcerFindResource proto stdcall :ptr SBYTE, :ptr SBYTE, :DWORD, :ptr SBYTE, :DWORD, :DWORD, :ptr DWORD, :LPDWORD
ResourcerFindResourceW proto stdcall :ptr WORD, :ptr WORD, :DWORD, :ptr WORD, :DWORD, :DWORD, :ptr DWORD, :LPDWORD
ResourcerFindResourceEx proto stdcall :DWORD, :DWORD, :ptr WORD, :DWORD, :ptr WORD, :DWORD, :DWORD, :ptr DWORD, :LPDWORD
ResourcerEnumerateResource proto stdcall :ptr SBYTE, :ptr 
ResourcerEnumerateResourceW proto stdcall :ptr WORD, :ptr 
ResourcerEnumerateResourceEx proto stdcall :DWORD, :DWORD, :ptr 
ThreaderImportRunningThreadData proto stdcall :DWORD
ThreaderGetThreadInfo proto stdcall :HANDLE, :DWORD
ThreaderEnumThreadInfo proto stdcall :ptr 
ThreaderPauseThread proto stdcall :HANDLE
ThreaderResumeThread proto stdcall :HANDLE
ThreaderTerminateThread proto stdcall :HANDLE, :DWORD
ThreaderPauseAllThreads proto stdcall :bool
ThreaderResumeAllThreads proto stdcall :bool
ThreaderPauseProcess proto stdcall 
ThreaderResumeProcess proto stdcall 
ThreaderCreateRemoteThread proto stdcall :DWORD, :bool, :LPVOID, :LPDWORD
ThreaderInjectAndExecuteCode proto stdcall :LPVOID, :DWORD, :DWORD
ThreaderCreateRemoteThreadEx proto stdcall :HANDLE, :DWORD, :bool, :LPVOID, :LPDWORD
ThreaderInjectAndExecuteCodeEx proto stdcall :HANDLE, :LPVOID, :DWORD, :DWORD
ThreaderSetCallBackForNextExitThreadEvent proto stdcall :LPVOID
ThreaderIsThreadStillRunning proto stdcall :HANDLE
ThreaderIsThreadActive proto stdcall :HANDLE
ThreaderIsAnyThreadActive proto stdcall 
ThreaderExecuteOnlyInjectedThreads proto stdcall 
ThreaderGetOpenHandleForThread proto stdcall :DWORD
ThreaderGetThreadData proto stdcall 
ThreaderIsExceptionInMainThread proto stdcall 
StaticDisassembleEx proto stdcall :DWORD, :LPVOID
StaticDisassemble proto stdcall :LPVOID
DisassembleEx proto stdcall :HANDLE, :LPVOID
Disassemble proto stdcall :LPVOID
StaticLengthDisassemble proto stdcall :LPVOID
LengthDisassembleEx proto stdcall :HANDLE, :LPVOID
LengthDisassemble proto stdcall :LPVOID
InitDebug proto stdcall :ptr SBYTE, :ptr SBYTE, :ptr SBYTE
InitDebugW proto stdcall :ptr WORD, :ptr WORD, :ptr WORD
InitDebugEx proto stdcall :ptr SBYTE, :ptr SBYTE, :ptr SBYTE, :LPVOID
InitDebugExW proto stdcall :ptr WORD, :ptr WORD, :ptr WORD, :LPVOID
InitDLLDebug proto stdcall :ptr SBYTE, :bool, :ptr SBYTE, :ptr SBYTE, :LPVOID
InitDLLDebugW proto stdcall :ptr WORD, :bool, :ptr WORD, :ptr WORD, :LPVOID
StopDebug proto stdcall 
SetBPXOptions proto stdcall :SDWORD
IsBPXEnabled proto stdcall :DWORD
EnableBPX proto stdcall :DWORD
DisableBPX proto stdcall :DWORD
SetBPX proto stdcall :DWORD, :DWORD, :LPVOID
SetBPXEx proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :LPVOID, :LPVOID, :LPVOID
DeleteBPX proto stdcall :DWORD
SafeDeleteBPX proto stdcall :DWORD
SetAPIBreakPoint proto stdcall :ptr SBYTE, :ptr SBYTE, :DWORD, :DWORD, :LPVOID
DeleteAPIBreakPoint proto stdcall :ptr SBYTE, :ptr SBYTE, :DWORD
SafeDeleteAPIBreakPoint proto stdcall :ptr SBYTE, :ptr SBYTE, :DWORD
SetMemoryBPX proto stdcall :DWORD, :DWORD, :LPVOID
SetMemoryBPXEx proto stdcall :DWORD, :DWORD, :DWORD, :bool, :LPVOID
RemoveMemoryBPX proto stdcall :DWORD, :DWORD
GetContextFPUDataEx proto stdcall :HANDLE, :ptr 
GetContextDataEx proto stdcall :HANDLE, :DWORD
GetContextData proto stdcall :DWORD
SetContextFPUDataEx proto stdcall :HANDLE, :ptr 
SetContextDataEx proto stdcall :HANDLE, :DWORD, :DWORD
SetContextData proto stdcall :DWORD, :DWORD
ClearExceptionNumber proto stdcall 
CurrentExceptionNumber proto stdcall 
MatchPatternEx proto stdcall :HANDLE, :ptr , :DWORD, :ptr , :DWORD, :PBYTE
MatchPattern proto stdcall :ptr , :DWORD, :ptr , :DWORD, :PBYTE
FindEx proto stdcall :HANDLE, :LPVOID, :DWORD, :LPVOID, :DWORD, :LPBYTE
Find proto stdcall :LPVOID, :DWORD, :LPVOID, :DWORD, :LPBYTE
FillEx proto stdcall :HANDLE, :LPVOID, :DWORD, :PBYTE
Fill proto stdcall :LPVOID, :DWORD, :PBYTE
PatchEx proto stdcall :HANDLE, :LPVOID, :DWORD, :LPVOID, :DWORD, :bool, :bool
Patch proto stdcall :LPVOID, :DWORD, :LPVOID, :DWORD, :bool, :bool
ReplaceEx proto stdcall :HANDLE, :LPVOID, :DWORD, :LPVOID, :DWORD, :DWORD, :LPVOID, :DWORD, :PBYTE
Replace proto stdcall :LPVOID, :DWORD, :LPVOID, :DWORD, :DWORD, :LPVOID, :DWORD, :PBYTE
GetDebugData proto stdcall 
GetTerminationData proto stdcall 
GetExitCode proto stdcall 
GetDebuggedDLLBaseAddress proto stdcall 
GetDebuggedFileBaseAddress proto stdcall 
GetRemoteString proto stdcall :HANDLE, :LPVOID, :LPVOID, :DWORD
GetFunctionParameter proto stdcall :HANDLE, :DWORD, :DWORD, :DWORD
GetJumpDestinationEx proto stdcall :HANDLE, :DWORD, :bool
GetJumpDestination proto stdcall :HANDLE, :DWORD
IsJumpGoingToExecuteEx proto stdcall :HANDLE, :HANDLE, :DWORD, :DWORD
IsJumpGoingToExecute proto stdcall 
SetCustomHandler proto stdcall :DWORD, :LPVOID
ForceClose proto stdcall 
StepInto proto stdcall :LPVOID
StepOver proto stdcall :LPVOID
SingleStep proto stdcall :DWORD, :LPVOID
GetUnusedHardwareBreakPointRegister proto stdcall :LPDWORD
SetHardwareBreakPointEx proto stdcall :HANDLE, :DWORD, :DWORD, :DWORD, :DWORD, :LPVOID, :LPDWORD
SetHardwareBreakPoint proto stdcall :DWORD, :DWORD, :DWORD, :DWORD, :LPVOID
DeleteHardwareBreakPoint proto stdcall :DWORD
RemoveAllBreakPoints proto stdcall :DWORD
GetProcessInformation proto stdcall 
GetStartupInformation proto stdcall 
DebugLoop proto stdcall 
SetDebugLoopTimeOut proto stdcall :DWORD
SetNextDbgContinueStatus proto stdcall :DWORD
AttachDebugger proto stdcall :DWORD, :bool, :LPVOID, :LPVOID
DetachDebugger proto stdcall :DWORD
DetachDebuggerEx proto stdcall :DWORD
DebugLoopEx proto stdcall :DWORD
AutoDebugEx proto stdcall :ptr SBYTE, :bool, :ptr SBYTE, :ptr SBYTE, :DWORD, :LPVOID
AutoDebugExW proto stdcall :ptr WORD, :bool, :ptr WORD, :ptr WORD, :DWORD, :LPVOID
IsFileBeingDebugged proto stdcall 
SetErrorModel proto stdcall :bool
FindOEPInit proto stdcall 
FindOEPGenerically proto stdcall :ptr SBYTE, :LPVOID, :LPVOID
FindOEPGenericallyW proto stdcall :ptr WORD, :LPVOID, :LPVOID
ImporterCleanup proto stdcall 
ImporterSetImageBase proto stdcall :DWORD
ImporterSetUnknownDelta proto stdcall :DWORD
ImporterGetCurrentDelta proto stdcall 
ImporterInit proto stdcall :DWORD, :DWORD
ImporterAddNewDll proto stdcall :ptr SBYTE, :DWORD
ImporterAddNewAPI proto stdcall :ptr SBYTE, :DWORD
ImporterAddNewOrdinalAPI proto stdcall :DWORD, :DWORD
ImporterGetAddedDllCount proto stdcall 
ImporterGetAddedAPICount proto stdcall 
ImporterGetLastAddedDLLName proto stdcall 
ImporterMoveIAT proto stdcall 
ImporterExportIAT proto stdcall :DWORD, :DWORD
ImporterEstimatedSize proto stdcall 
ImporterExportIATEx proto stdcall :ptr SBYTE, :ptr SBYTE
ImporterExportIATExW proto stdcall :ptr WORD, :ptr SBYTE
ImporterFindAPIWriteLocation proto stdcall :ptr SBYTE
ImporterFindOrdinalAPIWriteLocation proto stdcall :DWORD
ImporterFindAPIByWriteLocation proto stdcall :DWORD
ImporterFindDLLByWriteLocation proto stdcall :DWORD
ImporterGetDLLName proto stdcall :DWORD
ImporterGetAPIName proto stdcall :DWORD
ImporterGetAPIOrdinalNumber proto stdcall :DWORD
ImporterGetAPINameEx proto stdcall :DWORD, :DWORD
ImporterGetRemoteAPIAddress proto stdcall :HANDLE, :DWORD
ImporterGetRemoteAPIAddressEx proto stdcall :ptr SBYTE, :ptr SBYTE
ImporterGetLocalAPIAddress proto stdcall :HANDLE, :DWORD
ImporterGetDLLNameFromDebugee proto stdcall :HANDLE, :DWORD
ImporterGetAPINameFromDebugee proto stdcall :HANDLE, :DWORD
ImporterGetAPIOrdinalNumberFromDebugee proto stdcall :HANDLE, :DWORD
ImporterGetDLLIndexEx proto stdcall :DWORD, :DWORD
ImporterGetDLLIndex proto stdcall :HANDLE, :DWORD, :DWORD
ImporterGetRemoteDLLBase proto stdcall :HANDLE, :HMODULE
ImporterRelocateWriteLocation proto stdcall :DWORD
ImporterIsForwardedAPI proto stdcall :HANDLE, :DWORD
ImporterGetForwardedAPIName proto stdcall :HANDLE, :DWORD
ImporterGetForwardedDLLName proto stdcall :HANDLE, :DWORD
ImporterGetForwardedDLLIndex proto stdcall :HANDLE, :DWORD, :DWORD
ImporterGetForwardedAPIOrdinalNumber proto stdcall :HANDLE, :DWORD
ImporterGetNearestAPIAddress proto stdcall :HANDLE, :DWORD
ImporterGetNearestAPIName proto stdcall :HANDLE, :DWORD
ImporterCopyOriginalIAT proto stdcall :ptr SBYTE, :ptr SBYTE
ImporterCopyOriginalIATW proto stdcall :ptr WORD, :ptr WORD
ImporterLoadImportTable proto stdcall :ptr SBYTE
ImporterLoadImportTableW proto stdcall :ptr WORD
ImporterMoveOriginalIAT proto stdcall :ptr SBYTE, :ptr SBYTE, :ptr SBYTE
ImporterMoveOriginalIATW proto stdcall :ptr WORD, :ptr WORD, :ptr SBYTE
ImporterAutoSearchIAT proto stdcall :HANDLE, :ptr SBYTE, :DWORD, :DWORD, :DWORD, :LPVOID, :LPVOID
ImporterAutoSearchIATW proto stdcall :HANDLE, :ptr WORD, :DWORD, :DWORD, :DWORD, :LPVOID, :LPVOID
ImporterAutoSearchIATEx proto stdcall :HANDLE, :DWORD, :DWORD, :DWORD, :LPVOID, :LPVOID
ImporterEnumAddedData proto stdcall :LPVOID
ImporterAutoFixIATEx proto stdcall :HANDLE, :ptr SBYTE, :ptr SBYTE, :bool, :bool, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :bool, :bool, :LPVOID
ImporterAutoFixIATExW proto stdcall :HANDLE, :ptr WORD, :ptr SBYTE, :bool, :bool, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :bool, :bool, :LPVOID
ImporterAutoFixIAT proto stdcall :HANDLE, :ptr SBYTE, :DWORD, :DWORD, :DWORD, :DWORD
ImporterAutoFixIATW proto stdcall :HANDLE, :ptr WORD, :DWORD, :DWORD, :DWORD, :DWORD
HooksSafeTransitionEx proto stdcall :LPVOID, :DWORD, :bool
HooksSafeTransition proto stdcall :LPVOID, :bool
HooksIsAddressRedirected proto stdcall :LPVOID
HooksGetTrampolineAddress proto stdcall :LPVOID
HooksGetHookEntryDetails proto stdcall :LPVOID
HooksInsertNewRedirection proto stdcall :LPVOID, :LPVOID, :DWORD
HooksInsertNewIATRedirectionEx proto stdcall :DWORD, :DWORD, :ptr SBYTE, :LPVOID
HooksInsertNewIATRedirection proto stdcall :ptr SBYTE, :ptr SBYTE, :LPVOID
HooksRemoveRedirection proto stdcall :LPVOID, :bool
HooksRemoveRedirectionsForModule proto stdcall :HMODULE
HooksRemoveIATRedirection proto stdcall :ptr SBYTE, :ptr SBYTE, :bool
HooksDisableRedirection proto stdcall :LPVOID, :bool
HooksDisableRedirectionsForModule proto stdcall :HMODULE
HooksDisableIATRedirection proto stdcall :ptr SBYTE, :ptr SBYTE, :bool
HooksEnableRedirection proto stdcall :LPVOID, :bool
HooksEnableRedirectionsForModule proto stdcall :HMODULE
HooksEnableIATRedirection proto stdcall :ptr SBYTE, :ptr SBYTE, :bool
HooksScanModuleMemory proto stdcall :HMODULE, :LPVOID
HooksScanEntireProcessMemory proto stdcall :LPVOID
HooksScanEntireProcessMemoryEx proto stdcall 
TracerInit proto stdcall 
TracerLevel1 proto stdcall :HANDLE, :DWORD
HashTracerLevel1 proto stdcall :HANDLE, :DWORD, :DWORD
TracerDetectRedirection proto stdcall :HANDLE, :DWORD
TracerFixKnownRedirection proto stdcall :HANDLE, :DWORD, :DWORD
TracerFixRedirectionViaImpRecPlugin proto stdcall :HANDLE, :ptr SBYTE, :DWORD
ExporterCleanup proto stdcall 
ExporterSetImageBase proto stdcall :DWORD
ExporterInit proto stdcall :DWORD, :DWORD, :DWORD, :ptr SBYTE
ExporterAddNewExport proto stdcall :ptr SBYTE, :DWORD
ExporterAddNewOrdinalExport proto stdcall :DWORD, :DWORD
ExporterGetAddedExportCount proto stdcall 
ExporterEstimatedSize proto stdcall 
ExporterBuildExportTable proto stdcall :DWORD, :DWORD
ExporterBuildExportTableEx proto stdcall :ptr SBYTE, :ptr SBYTE
ExporterBuildExportTableExW proto stdcall :ptr WORD, :ptr SBYTE
ExporterLoadExportTable proto stdcall :ptr SBYTE
ExporterLoadExportTableW proto stdcall :ptr WORD
LibrarianSetBreakPoint proto stdcall :ptr SBYTE, :DWORD, :bool, :LPVOID
LibrarianRemoveBreakPoint proto stdcall :ptr SBYTE, :DWORD
LibrarianGetLibraryInfo proto stdcall :ptr SBYTE
LibrarianGetLibraryInfoW proto stdcall :ptr WORD
LibrarianGetLibraryInfoEx proto stdcall :ptr 
LibrarianGetLibraryInfoExW proto stdcall :ptr 
LibrarianEnumLibraryInfo proto stdcall :ptr 
LibrarianEnumLibraryInfoW proto stdcall :ptr 
GetActiveProcessId proto stdcall :ptr SBYTE
GetActiveProcessIdW proto stdcall :ptr WORD
EnumProcessesWithLibrary proto stdcall :ptr SBYTE, :ptr 
TLSBreakOnCallBack proto stdcall :LPVOID, :DWORD, :LPVOID
TLSGrabCallBackData proto stdcall :ptr SBYTE, :LPVOID, :LPDWORD
TLSGrabCallBackDataW proto stdcall :ptr WORD, :LPVOID, :LPDWORD
TLSBreakOnCallBackEx proto stdcall :ptr SBYTE, :LPVOID
TLSBreakOnCallBackExW proto stdcall :ptr WORD, :LPVOID
TLSRemoveCallback proto stdcall :ptr SBYTE
TLSRemoveCallbackW proto stdcall :ptr WORD
TLSRemoveTable proto stdcall :ptr SBYTE
TLSRemoveTableW proto stdcall :ptr WORD
TLSBackupData proto stdcall :ptr SBYTE
TLSBackupDataW proto stdcall :ptr WORD
TLSRestoreData proto stdcall 
TLSBuildNewTable proto stdcall :DWORD, :DWORD, :DWORD, :LPVOID, :DWORD
TLSBuildNewTableEx proto stdcall :ptr SBYTE, :ptr SBYTE, :LPVOID, :DWORD
TLSBuildNewTableExW proto stdcall :ptr WORD, :ptr SBYTE, :LPVOID, :DWORD
TranslateNativeName proto stdcall :ptr SBYTE
TranslateNativeNameW proto stdcall :ptr WORD
HandlerGetActiveHandleCount proto stdcall :DWORD
HandlerIsHandleOpen proto stdcall :DWORD, :HANDLE
HandlerGetHandleName proto stdcall :HANDLE, :DWORD, :HANDLE, :bool
HandlerGetHandleNameW proto stdcall :HANDLE, :DWORD, :HANDLE, :bool
HandlerEnumerateOpenHandles proto stdcall :DWORD, :LPVOID, :DWORD
HandlerGetHandleDetails proto stdcall :HANDLE, :DWORD, :HANDLE, :DWORD
HandlerCloseRemoteHandle proto stdcall :HANDLE, :HANDLE
HandlerEnumerateLockHandles proto stdcall :ptr SBYTE, :bool, :bool, :LPVOID, :DWORD
HandlerEnumerateLockHandlesW proto stdcall :ptr WORD, :bool, :bool, :LPVOID, :DWORD
HandlerCloseAllLockHandles proto stdcall :ptr SBYTE, :bool, :bool
HandlerCloseAllLockHandlesW proto stdcall :ptr WORD, :bool, :bool
HandlerIsFileLocked proto stdcall :ptr SBYTE, :bool, :bool
HandlerIsFileLockedW proto stdcall :ptr WORD, :bool, :bool
HandlerEnumerateOpenMutexes proto stdcall :HANDLE, :DWORD, :LPVOID, :DWORD
HandlerGetOpenMutexHandle proto stdcall :HANDLE, :DWORD, :ptr SBYTE
HandlerGetOpenMutexHandleW proto stdcall :HANDLE, :DWORD, :ptr WORD
HandlerGetProcessIdWhichCreatedMutex proto stdcall :ptr SBYTE
HandlerGetProcessIdWhichCreatedMutexW proto stdcall :ptr WORD
RemoteLoadLibrary proto stdcall :HANDLE, :ptr SBYTE, :bool
RemoteLoadLibraryW proto stdcall :HANDLE, :ptr WORD, :bool
RemoteFreeLibrary proto stdcall :HANDLE, :HMODULE, :ptr SBYTE, :bool
RemoteFreeLibraryW proto stdcall :HANDLE, :HMODULE, :ptr WORD, :bool
RemoteExitProcess proto stdcall :HANDLE, :DWORD
StaticFileLoad proto stdcall :ptr SBYTE, :DWORD, :bool, :LPHANDLE, :LPDWORD, :LPHANDLE, :ptr DWORD
StaticFileLoadW proto stdcall :ptr WORD, :DWORD, :bool, :LPHANDLE, :LPDWORD, :LPHANDLE, :ptr DWORD
StaticFileUnload proto stdcall :ptr SBYTE, :bool, :HANDLE, :DWORD, :HANDLE, :DWORD
StaticFileUnloadW proto stdcall :ptr WORD, :bool, :HANDLE, :DWORD, :HANDLE, :DWORD
StaticFileOpen proto stdcall :ptr SBYTE, :DWORD, :LPHANDLE, :LPDWORD, :LPDWORD
StaticFileOpenW proto stdcall :ptr WORD, :DWORD, :LPHANDLE, :LPDWORD, :LPDWORD
StaticFileGetContent proto stdcall :HANDLE, :DWORD, :LPDWORD, :ptr , :DWORD
StaticFileClose proto stdcall :HANDLE
StaticMemoryDecrypt proto stdcall :LPVOID, :DWORD, :DWORD, :DWORD, :DWORD
StaticMemoryDecryptEx proto stdcall :LPVOID, :DWORD, :DWORD, :ptr 
StaticMemoryDecryptSpecial proto stdcall :LPVOID, :DWORD, :DWORD, :DWORD, :ptr 
StaticSectionDecrypt proto stdcall :DWORD, :DWORD, :bool, :DWORD, :DWORD, :DWORD
StaticMemoryDecompress proto stdcall :ptr , :DWORD, :ptr , :DWORD, :DWORD
StaticRawMemoryCopy proto stdcall :HANDLE, :DWORD, :DWORD, :DWORD, :bool, :ptr SBYTE
StaticRawMemoryCopyW proto stdcall :HANDLE, :DWORD, :DWORD, :DWORD, :bool, :ptr WORD
StaticRawMemoryCopyEx proto stdcall :HANDLE, :DWORD, :DWORD, :ptr SBYTE
StaticRawMemoryCopyExW proto stdcall :HANDLE, :DWORD, :DWORD, :ptr WORD
StaticHashMemory proto stdcall :ptr , :DWORD, :ptr , :bool, :DWORD
StaticHashFileW proto stdcall :ptr WORD, :ptr SBYTE, :bool, :DWORD
StaticHashFile proto stdcall :ptr SBYTE, :ptr SBYTE, :bool, :DWORD
EngineUnpackerInitialize proto stdcall :ptr SBYTE, :ptr SBYTE, :bool, :bool, :bool, :ptr 
EngineUnpackerInitializeW proto stdcall :ptr WORD, :ptr WORD, :bool, :bool, :bool, :ptr 
EngineUnpackerSetBreakCondition proto stdcall :ptr , :DWORD, :ptr , :DWORD, :DWORD, :DWORD, :bool, :DWORD, :DWORD
EngineUnpackerSetEntryPointAddress proto stdcall :DWORD
EngineUnpackerFinalizeUnpacking proto stdcall 
SetEngineVariable proto stdcall :DWORD, :bool
EngineCreateMissingDependencies proto stdcall :ptr SBYTE, :ptr SBYTE, :bool
EngineCreateMissingDependenciesW proto stdcall :ptr WORD, :ptr WORD, :bool
EngineFakeMissingDependencies proto stdcall :HANDLE
EngineDeleteCreatedDependencies proto stdcall 
EngineCreateUnpackerWindow proto stdcall :ptr SBYTE, :ptr SBYTE, :ptr SBYTE, :ptr SBYTE, :ptr 
EngineAddUnpackerWindowLogMessage proto stdcall :ptr SBYTE
ExtensionManagerIsPluginLoaded proto stdcall :ptr SBYTE
ExtensionManagerIsPluginEnabled proto stdcall :ptr SBYTE
ExtensionManagerDisableAllPlugins proto stdcall 
ExtensionManagerDisablePlugin proto stdcall :ptr SBYTE
ExtensionManagerEnableAllPlugins proto stdcall 
ExtensionManagerEnablePlugin proto stdcall :ptr SBYTE
ExtensionManagerUnloadAllPlugins proto stdcall 
ExtensionManagerUnloadPlugin proto stdcall :ptr SBYTE
ExtensionManagerGetPluginInfo proto stdcall :ptr SBYTE

;--- errors: 0
;--- end of file ---