#include "stdafx.h"
#include "TitanScriptGui.h"
#include "..\SDK\CPP\TitanEngine.h"
#include "TitanScript.h"

//variables
static HINSTANCE hInst;
static HWND hLogBox;
static TCHAR FileNameTarget[MAX_PATH] = {};
static TCHAR FileNameScript[MAX_PATH] = {};
static TCHAR FileNameIni[MAX_PATH] = {};

//functions
static INT_PTR CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
static bool GetFileDialog(TCHAR[MAX_PATH]);
static void AddLogMessage(const char* szLogMessage, eLogType Type);
static void SettingSet(const TCHAR* name, const TCHAR* value);
static void SettingGet(const TCHAR* name, TCHAR* value, int value_size);
static bool FileExists(LPCTSTR szPath);
static void CreateDummyUnicodeFile(const TCHAR* szFileName);

//TitanScript functions
static tScripterLoadFileA load_file = NULL;
static tScripterExecuteWithTitanMistA exec = NULL;
static tScripterSetLogCallback set_log_callback = NULL;

int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    hInst = hInstance;

    DialogBox(hInstance, MAKEINTRESOURCE(IDD_MAINWINDOW), NULL, &WndProc);
    ExitProcess(NULL);
}

INT_PTR CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_INITDIALOG:
    {
        //set icon
        HICON hIconLarge = (HICON)LoadImage(hInst, MAKEINTRESOURCE(IDI_ICON1), IMAGE_ICON, 32, 32, LR_DEFAULTSIZE);
        SendMessage(hWnd, WM_SETICON, ICON_BIG, (LPARAM)hIconLarge);
        HICON hIconSmall = (HICON)LoadImage(hInst, MAKEINTRESOURCE(IDI_ICON1), IMAGE_ICON, 16, 16, LR_DEFAULTSIZE);
        SendMessage(hWnd, WM_SETICON, ICON_SMALL, (LPARAM)hIconSmall);

        //initialize variables
        hLogBox = GetDlgItem(hWnd, IDC_LOG);
        int i = GetModuleFileName(hInst, FileNameIni, _countof(FileNameIni));
        while(FileNameIni[i] != TCHAR('\\') && i)
            i--;
        if(i)
        {
            int len = lstrlen(FileNameIni);
            while(FileNameIni[i] != TCHAR('.') && i < len)
                i++;
            if(i+1 < len)
                FileNameIni[i] = TCHAR('\0');
        }
        lstrcat(FileNameIni, _T(".ini"));
        CreateDummyUnicodeFile(FileNameIni);

        //restore last files
        SettingGet(_T("Target"), FileNameTarget, _countof(FileNameTarget));
        if(lstrlen(FileNameTarget))
            SetDlgItemText(hWnd, IDC_TARGETPATH, FileNameTarget);
        SettingGet(_T("Script"), FileNameScript, _countof(FileNameScript));
        if(lstrlen(FileNameScript))
            SetDlgItemText(hWnd, IDC_SCRIPTPATH, FileNameScript);

        //make sure TitanScript is available
        if ( !ExtensionManagerIsPluginLoaded( "TitanScript" ) || !ExtensionManagerIsPluginEnabled( "TitanScript" ) )
        {
            AddLogMessage("TitanScript failed to load", TS_LOG_ERROR);
#ifdef _WIN64
            AddLogMessage("Ensure plugins\\x64\\TitanScript.dll exists !", TS_LOG_ERROR);
#else
            AddLogMessage("Ensure plugins\\x86\\TitanScript.dll exists !", TS_LOG_ERROR);
#endif //_WIN64
            EnableWindow(GetDlgItem(hWnd, IDC_RUN ), FALSE);
        }
        else
        {
            load_file = GetTSFunctionPointer( LoadFileA );
            exec = GetTSFunctionPointer( ExecuteWithTitanMistA );
            set_log_callback = GetTSFunctionPointer( SetLogCallback );
            set_log_callback(&AddLogMessage);
        }

        break;
    }

    case WM_COMMAND:
    {
        switch (LOWORD(wParam))
        {
        case IDC_BROWSETARGET:
        {
            if(GetFileDialog(FileNameTarget))
            {
                SetDlgItemText(hWnd, IDC_TARGETPATH, FileNameTarget);
                SettingSet(_T("Target"), FileNameTarget);
            }
            break;
        }
        case IDC_BROWSESCRIPT:
        {
            if(GetFileDialog(FileNameScript))
            {
                SetDlgItemText(hWnd, IDC_SCRIPTPATH, FileNameScript);
                SettingSet(_T("Script"), FileNameScript);
            }
            break;
        }
        case IDC_RUN:
        {
            char buf[MAX_PATH] = {0};

            wcstombs(buf, FileNameScript, sizeof(buf));
            if(!load_file(buf))
            {
                AddLogMessage("Script failed to load", TS_LOG_ERROR);
                break;
            }

            wcstombs(buf, FileNameTarget, sizeof(buf));
            if(!exec(buf, "")) //TitanScript will generate the output filename
            {
                AddLogMessage("Failed to execute", TS_LOG_ERROR);
                break;
            }

            break;
        }

        }
    }
    break;

    case WM_CLOSE:
    {
        EndDialog(hWnd, NULL);
    }
    break;

    default:
    {
        return false;
    }
    }
    return 0;
}

static bool GetFileDialog(TCHAR Buffer[MAX_PATH])
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

static void AddLogMessage(const char* szLogMessage, eLogType Type)
{
    TCHAR buf[100] = {0};
    mbstowcs(buf, szLogMessage, sizeof(buf));
    LRESULT cSelect = SendMessage(hLogBox, LB_INSERTSTRING, (WPARAM)-1, (LPARAM)buf);
    SendMessage(hLogBox, LB_SETCURSEL, cSelect, NULL);
}

static void SettingSet(const TCHAR* name, const TCHAR* value)
{
    WritePrivateProfileString(_T("Settings"), name, value, FileNameIni);
}

static void SettingGet(const TCHAR* name, TCHAR* value, int value_size)
{
    GetPrivateProfileString(_T("Settings"), name, _T(""), value, value_size, FileNameIni);
}

static bool FileExists(LPCTSTR szPath)
{
    DWORD dwAttrib = GetFileAttributes(szPath);
    return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

static void CreateDummyUnicodeFile(const TCHAR* szFileName)
{
    //http://www.codeproject.com/Articles/9071/Using-Unicode-in-INI-files
    if (!FileExists(szFileName))
    {
        // UTF16-LE BOM(FFFE)
        WORD wBOM = 0xFEFF;
        DWORD NumberOfBytesWritten;
        HANDLE hFile = CreateFile(szFileName, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        WriteFile(hFile, &wBOM, sizeof(WORD), &NumberOfBytesWritten, NULL);
        CloseHandle(hFile);
    }
}
