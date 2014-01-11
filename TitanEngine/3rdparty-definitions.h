#include "stdafx.h"

/* Scylla definitions */
#define SCY_ERROR_SUCCESS  0;
#define SCY_ERROR_PROCOPEN = -1;
#define SCY_ERROR_IATWRITE = -2;
#define SCY_ERROR_IATSEARCH = -3;
#define SCY_ERROR_IATNOTFOUND = -4;

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/
//IAT exports
int scylla_searchIAT(DWORD pid, DWORD_PTR &iatStart, DWORD &iatSize, DWORD_PTR searchStart, bool advancedSearch);
int scylla_getImports(DWORD_PTR iatAddr, DWORD iatSize, DWORD pid);
bool scylla_importsValid();
int scylla_fixDump(WCHAR* dumpFile, WCHAR* iatFixFile);
#ifdef __cplusplus
}
#endif /*__cplusplus*/

/* Scylla definitions */