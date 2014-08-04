#include "stdafx.h"

/* Scylla definitions */
const BYTE SCY_ERROR_SUCCESS = 0;
const BYTE SCY_ERROR_PROCOPEN = -1;
const BYTE SCY_ERROR_IATWRITE = -2;
const BYTE SCY_ERROR_IATSEARCH = -3;
const BYTE SCY_ERROR_IATNOTFOUND = -4;

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/
//iat exports
int scylla_searchIAT(DWORD pid, DWORD_PTR & iatStart, DWORD & iatSize, DWORD_PTR searchStart, bool advancedSearch);
int scylla_getImports(DWORD_PTR iatAddr, DWORD iatSize, DWORD pid, LPVOID invalidImportCallback = NULL);
bool scylla_addModule(const WCHAR* moduleName, DWORD_PTR firstThunkRVA);
bool scylla_addImport(const WCHAR* importName, DWORD_PTR thunkVA);
bool scylla_importsValid();
bool scylla_cutImport(DWORD_PTR apiAddr);
int scylla_fixDump(WCHAR* dumpFile, WCHAR* iatFixFile, WCHAR* sectionName = L".scy");
int scylla_fixMappedDump(DWORD_PTR iatVA, DWORD_PTR FileMapVA, HANDLE hFileMap);
int scylla_getModuleCount();
int scylla_getImportCount();
void scylla_enumImportTree(LPVOID enumCallBack);
long scylla_estimatedIATSize();
DWORD_PTR scylla_findImportWriteLocation(char* importName);
DWORD_PTR scylla_findOrdinalImportWriteLocation(DWORD_PTR ordinalNumber);
DWORD_PTR scylla_findImportNameByWriteLocation(DWORD_PTR thunkVA);
DWORD_PTR scylla_findModuleNameByWriteLocation(DWORD_PTR thunkVA);

//dumper exports
bool scylla_dumpProcessW(DWORD_PTR pid, const WCHAR* fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR* fileResult);
bool scylla_dumpProcessA(DWORD_PTR pid, const char* fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const char* fileResult);

//rebuilder exports
bool scylla_rebuildFileW(const WCHAR* fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup);
bool scylla_rebuildFileA(const char* fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup);
#ifdef __cplusplus
}
#endif /*__cplusplus*/

/* Scylla definitions */
