#ifndef _GLOBAL_ENGINE_GUI_H
#define _GLOBAL_ENGINE_GUI_H

#include "resource.h"

extern char szWindowUnpackerName[128];
extern char szWindowUnpackerTitle[128];
extern char szWindowUnpackerLongTitle[128];
extern char szWindowUnpackerAuthor[128];

extern HWND EngineBoxHandle;

bool EngineGetFileDialog(char* GlobalBuffer);
long EngineWndProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

#endif //_GLOBAL_ENGINE_GUI_H