#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.GUI.h"
#include "Global.Engine.h"

#define TE_VER_MAJOR 2
#define TE_VER_MIDDLE 1
#define TE_VER_MINOR 0

char szWindowUnpackerName[128];
char szWindowUnpackerTitle[128];
char szWindowUnpackerLongTitle[128];
char szWindowUnpackerAuthor[128];

HWND EngineBoxHandle;

static HWND EngineWindowHandle;

// Global.TitanEngine.Engine.functions:
bool EngineGetFileDialog(char* GlobalBuffer)
{
    OPENFILENAMEA sOpenFileName;
    char szFilterString[] = "All Files \0*.*\0\0";
    char szDialogTitle[] = "TitanEngine2 from Reversing Labs";

    RtlZeroMemory(&sOpenFileName, sizeof(OPENFILENAMEA));
    sOpenFileName.lStructSize = sizeof(OPENFILENAMEA);
    sOpenFileName.lpstrFilter = szFilterString;
    sOpenFileName.lpstrFile = GlobalBuffer;
    sOpenFileName.nMaxFile = 1024;
    sOpenFileName.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_LONGNAMES | OFN_EXPLORER | OFN_HIDEREADONLY;
    sOpenFileName.lpstrTitle = szDialogTitle;
    if(!GetOpenFileNameA(&sOpenFileName))
    {
        RtlZeroMemory(GlobalBuffer, 1024);
        return false;
    }
    else
    {
        return true;
    }
}

long EngineWndProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    char szAboutTitle[] = "[ About ]";
    char szAboutText[] = "%s \r\n\r\n ReversingLabs - http://www.reversinglabs.com \r\n\r\n  Minimum engine version needed:\r\n- TitanEngine %i.%i.%i by RevLabs\r\n\r\nUnpacker coded by %s";
    typedef void(TITCALL * fStartUnpacking)(char* szInputFile, bool RealignFile, bool CopyOverlay);
    fStartUnpacking myStartUnpacking = (fStartUnpacking)EngineStartUnpackingCallBack;
    char GlobalBuffer[1024] = {};
    char AboutBuffer[1024] = {};
    bool bRealignFile = false;
    bool bCopyOverlay = false;

    if(uMsg == WM_INITDIALOG)
    {
        SendMessageA(hwndDlg, WM_SETTEXT, NULL, (LPARAM)&szWindowUnpackerTitle);
        HICON hIconLarge = (HICON)LoadImage(engineHandle, MAKEINTRESOURCE(IDI_ICON1), IMAGE_ICON, 32, 32, LR_DEFAULTSIZE);
        SendMessage(hwndDlg, WM_SETICON, ICON_BIG, (LPARAM)hIconLarge);
        HICON hIconSmall = (HICON)LoadImage(engineHandle, MAKEINTRESOURCE(IDI_ICON1), IMAGE_ICON, 16, 16, LR_DEFAULTSIZE);
        SendMessage(hwndDlg, WM_SETICON, ICON_SMALL, (LPARAM)hIconSmall);
        SetDlgItemTextA(hwndDlg, IDD_UNPACKERTITLE, szWindowUnpackerLongTitle);
        SetDlgItemTextA(hwndDlg, IDC_FILENAME, "filename.exe");
        CheckDlgButton(hwndDlg, IDC_REALING, 1);
        EngineWindowHandle = hwndDlg;
    }
    else if(uMsg == WM_DROPFILES)
    {
        DragQueryFileA((HDROP)wParam, NULL, GlobalBuffer, sizeof(GlobalBuffer));
        SetDlgItemTextA(hwndDlg, IDC_FILENAME, GlobalBuffer);
    }
    else if(uMsg == WM_CLOSE)
    {
        EndDialog(hwndDlg, NULL);
    }
    else if(uMsg == WM_COMMAND)
    {
        if(wParam == IDC_UNPACK)
        {
            GetDlgItemTextA(hwndDlg, IDC_FILENAME, GlobalBuffer, sizeof(GlobalBuffer));
            if(!IsFileBeingDebugged() && EngineFileExists(GlobalBuffer))
            {
                EngineBoxHandle = GetDlgItem(hwndDlg, IDC_LISTBOX);
                SendMessageA(EngineBoxHandle, LB_RESETCONTENT, NULL, NULL);
                if(IsDlgButtonChecked(EngineWindowHandle, IDC_REALING))
                {
                    bRealignFile = true;
                }
                if(IsDlgButtonChecked(EngineWindowHandle, IDC_COPYOVERLAY))
                {
                    bCopyOverlay = true;
                }
                myStartUnpacking(GlobalBuffer, bRealignFile, bCopyOverlay);
            }
        }
        else if(wParam == IDC_BROWSE)
        {
            if(EngineGetFileDialog(GlobalBuffer))
            {
                SetDlgItemTextA(hwndDlg, IDC_FILENAME, GlobalBuffer);
            }
        }
        else if(wParam == IDC_ABOUT)
        {
            wsprintfA(AboutBuffer, szAboutText, szWindowUnpackerName, TE_VER_MAJOR, TE_VER_MIDDLE, TE_VER_MINOR, szWindowUnpackerAuthor);
            MessageBoxA(hwndDlg, AboutBuffer, szAboutTitle, MB_ICONASTERISK);
        }
        else if(wParam == IDC_EXIT)
        {
            EndDialog(hwndDlg, NULL);
        }
    }
    return 0;
}
