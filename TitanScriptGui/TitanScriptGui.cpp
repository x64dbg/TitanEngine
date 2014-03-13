#include "stdafx.h"
#include "TitanScriptGui.h"
#include "TitanEngine.h"
#include "TitanScript.h"

HINSTANCE hInst;
HWND hLogBox;
TCHAR FileNameTarget[MAX_PATH] = {};
TCHAR FileNameScript[MAX_PATH] = {};

INT_PTR CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
bool GetFileDialog(TCHAR[MAX_PATH]);
void AddLogMessage(const char* szLogMessage, eLogType Type);

tScripterLoadFileA load_file = NULL;
tScripterExecuteWithTitanMistA exec = NULL;
tScripterSetLogCallback set_log_callback = NULL;

int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    DialogBox(hInstance, MAKEINTRESOURCE(IDD_MAINWINDOW), NULL, &WndProc);
    ExitProcess(NULL);
}

INT_PTR CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{

    switch (message)
    {
    case WM_INITDIALOG: {
        hLogBox = GetDlgItem(hWnd, IDC_LOG);

        //make sure TitanScript is available
        if ( !ExtensionManagerIsPluginLoaded( "TitanScript" ) || !ExtensionManagerIsPluginEnabled( "TitanScript" ) ) {
            AddLogMessage("TitanScript failed to load", TS_LOG_ERROR);
            AddLogMessage("Ensure plugins\\x86\\TitanScript.dll exists !", TS_LOG_ERROR);

            EnableWindow(GetDlgItem(hWnd, IDC_RUN ), FALSE);
        } else {
            load_file = GetTSFunctionPointer( LoadFileA );
            exec = GetTSFunctionPointer( ExecuteWithTitanMistA );
            set_log_callback = GetTSFunctionPointer( SetLogCallback );

            set_log_callback(&AddLogMessage);
        }

        break;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_BROWSETARGET: {
            if(GetFileDialog(FileNameTarget))
            {
                SetDlgItemText(hWnd, IDC_TARGETPATH, FileNameTarget);
            }
            break;
        }
        case IDC_BROWSESCRIPT: {
            if(GetFileDialog(FileNameScript))
            {
                SetDlgItemText(hWnd, IDC_SCRIPTPATH, FileNameScript);
            }
            break;
        }
        case IDC_RUN: {
            char buf[MAX_PATH] = {0};

            wcstombs(buf, FileNameScript, sizeof(buf));
            if(!load_file(buf)) {
                AddLogMessage("Script failed to load", TS_LOG_ERROR);
                break;
            }

            wcstombs(buf, FileNameTarget, sizeof(buf));
            if(!exec(buf, "dump.exe")) {
                AddLogMessage("Failed to execute", TS_LOG_ERROR);
                break;
            }

            break;
        }

        }
        break;
    case WM_CLOSE:
        EndDialog(hWnd, NULL);
        break;
    default:
        return false;
    }
    return 0;
}

bool GetFileDialog(TCHAR Buffer[MAX_PATH])
{
    OPENFILENAME sOpenFileName = {0};
    const TCHAR szFilterString[] = _T("All Files \0*.*\0\0");
    const TCHAR szDialogTitle[] = _T("TitanScriptGUI");

    Buffer[0] = 0;

    sOpenFileName.lStructSize = sizeof(sOpenFileName);
    sOpenFileName.lpstrFilter = szFilterString;
    sOpenFileName.lpstrFile = Buffer;
    sOpenFileName.nMaxFile = MAX_PATH;
    sOpenFileName.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_LONGNAMES | OFN_EXPLORER | OFN_HIDEREADONLY;
    sOpenFileName.lpstrTitle = szDialogTitle;

    return (TRUE == GetOpenFileName(&sOpenFileName));
}

void AddLogMessage(const char* szLogMessage, eLogType Type)
{
    TCHAR buf[100] = {0};
    mbstowcs(buf, szLogMessage, sizeof(buf));
    LRESULT cSelect = SendMessage(hLogBox, LB_INSERTSTRING, (WPARAM)-1, (LPARAM)buf);
    SendMessage(hLogBox, LB_SETCURSEL, cSelect, NULL);
}