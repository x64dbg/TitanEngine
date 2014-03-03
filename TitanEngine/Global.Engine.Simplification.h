#ifndef _GLOBAL_ENGINE_SIMPLIFICATION_H
#define _GLOBAL_ENGINE_SIMPLIFICATION_H

#include <vector>

extern bool EngineUnpackerOptionLogData;
extern bool EngineUnpackerFileImporterInit;
extern bool EngineUnpackerOptionRealingFile;
extern bool EngineUnpackerOptionMoveOverlay;
extern bool EngineUnpackerOptionRelocationFix;
extern ULONG_PTR EngineUnpackerOptionUnpackedOEP;
extern wchar_t szEngineUnpackerInputFile[MAX_PATH];
extern wchar_t szEngineUnpackerOutputFile[MAX_PATH];
extern wchar_t szEngineUnpackerSnapShot1[MAX_PATH];
extern wchar_t szEngineUnpackerSnapShot2[MAX_PATH];
extern FILE_STATUS_INFO EngineUnpackerFileStatus;
extern LPPROCESS_INFORMATION pEngineUnpackerProcessHandle;
extern std::vector<UnpackerInformation> EngineUnpackerBreakInfo;

void EngineSimplifyLoadLibraryCallBack();
void EngineSimplifyGetProcAddressCallBack();
void EngineSimplifyMakeSnapshotCallBack();
void EngineSimplifyEntryPointCallBack();

#endif //_GLOBAL_ENGINE_SIMPLIFICATION_H