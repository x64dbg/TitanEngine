#include "stdafx.h"
#include "TitanScriptGui.h"
#include "..\SDK\CPP\TitanEngine.h"
#include "TitanScript.h"

#define MAX_LOG_LINE_LENGTH 100
#define MAX_LOG_LINE_COUNT 100

//variables
static HINSTANCE hInst;
static HWND hLogBox;
static HWND hRunBtn;
static bool bRunning;
static TCHAR FileNameTarget[MAX_PATH] = {};
static TCHAR FileNameScript[MAX_PATH] = {};
static TCHAR FileNameIni[MAX_PATH] = {};

//functions
static INT_PTR CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
static bool GetFileDialog(TCHAR[MAX_PATH]);
static void AddLogMessage(const char* szLogMessage, eLogType Type);
static void AddLogMessageW(const wchar_t* szLogMessage, eLogType Type);
static void SettingSet(const TCHAR* name, const TCHAR* value);
static void SettingGet(const TCHAR* name, TCHAR* value, int value_size);
static bool FileExists(LPCTSTR szPath);
static void CreateDummyUnicodeFile(const TCHAR* szFileName);
static DWORD WINAPI TitanScriptExecThread(LPVOID lpParam);

//TitanScript functions
static tScripterLoadFileW load_file = NULL;
static tScripterExecuteWithTitanMistW exec = NULL;
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
            hRunBtn = GetDlgItem(hWnd, IDC_RUN);
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
                AddLogMessageW(L"TitanScript failed to load", TS_LOG_ERROR);
#ifdef _WIN64
                AddLogMessageW(L"Ensure plugins\\x64\\TitanScript.dll exists !", TS_LOG_ERROR);
#else
                AddLogMessageW(L"Ensure plugins\\x86\\TitanScript.dll exists !", TS_LOG_ERROR);
#endif //_WIN64
                EnableWindow(GetDlgItem(hWnd, IDC_RUN ), FALSE);
            }
            else
            {
                load_file = GetTSFunctionPointer( LoadFileW );
                exec = GetTSFunctionPointer( ExecuteWithTitanMistW );
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
                    if(!bRunning)
                        CreateThread(0, 0, TitanScriptExecThread, 0, 0, 0);
                    else
                        StopDebug();

                    break;
                }
            case IDC_COPY: {
                //get lines
                LRESULT cnt = SendMessageW(hLogBox, LB_GETCOUNT, 0, 0);

                if (cnt != 0 && cnt != LB_ERR)
                {
                    WCHAR * copy = (WCHAR *)calloc(1, sizeof(WCHAR));
                    int copyLength = 1;

                    for(LRESULT i=0; i<cnt; i++) {
                        LRESULT stringLength = SendMessageW(hLogBox, LB_GETTEXTLEN, i, 0);
                        copyLength += stringLength + 2;

                        copy = (WCHAR *)realloc(copy, copyLength * sizeof(WCHAR));
                        if (copy)
                        {
                            copy[copyLength - stringLength - 2] = 0;
                        }
                        else
                        {
                            return FALSE;
                        }

                        WCHAR * buf = (WCHAR *)calloc(stringLength + 1, sizeof(WCHAR));

                        if (buf && (SendMessageW(hLogBox, LB_GETTEXT, i, (LPARAM)buf) != LB_ERR))
                        {
                            wcscat(copy, buf);
                            wcscat(copy, L"\r\n");

                            free(buf);
                        }
                    }

                    //copy to clipboard
                    HGLOBAL clipbuffer;
                    WCHAR* buffer;
                    clipbuffer = GlobalAlloc(GMEM_MOVEABLE, (wcslen(copy) + 1) * sizeof(WCHAR));
                    if (clipbuffer)
                    {
                        buffer = (TCHAR*)GlobalLock(clipbuffer);
                        wcscpy(buffer, copy);
                        GlobalUnlock(clipbuffer);
                        OpenClipboard(NULL);
                        EmptyClipboard();
                        UINT format;
#ifdef UNICODE
                        format = CF_UNICODETEXT;
#else
                        format = CF_OEMTEXT;
#endif
                        SetClipboardData(format, clipbuffer);
                    }

                    CloseClipboard();

                    free(copy);
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
            return FALSE;
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

static void AddLogMessageW(const wchar_t* szLogMessage, eLogType Type)
{
    LRESULT cSelect = SendMessage(hLogBox, LB_INSERTSTRING, (WPARAM)-1, (LPARAM)szLogMessage);
    if (cSelect == LB_ERR)
    {
        MessageBoxW(0, L"ERROR LOG MESSAGE - LB_INSERTSTRING", L"ERROR", MB_ICONWARNING);
    } else if (cSelect == LB_ERRSPACE)
    {
        MessageBoxW(0, L"ERROR LOG MESSAGE - LB_ERRSPACE - Not enough space!", L"ERROR", MB_ICONWARNING);
    }
    else
    {
        SendMessage(hLogBox, LB_SETCURSEL, cSelect, NULL);
    }
}

static void AddLogMessage(const char* szLogMessage, eLogType Type)
{
    TCHAR * buf = (TCHAR *)calloc(strlen(szLogMessage) + 1, sizeof(TCHAR));
    if (buf)
    {
        mbstowcs(buf, szLogMessage, strlen(szLogMessage) + 1);
        AddLogMessageW(buf, Type);
        free(buf);
    }

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

static DWORD WINAPI TitanScriptExecThread(LPVOID lpParam)
{
    if(!load_file(FileNameScript))
    {
        AddLogMessageW(L"Script failed to load", TS_LOG_ERROR);
        return 0;
    }
    SetWindowText(hRunBtn, _T("Stop"));
    bRunning = true;
    if(!exec(FileNameTarget, L"")) //TitanScript will generate the output filename
    {
        AddLogMessageW(L"Failed to execute", TS_LOG_ERROR);
    }
    else
        AddLogMessageW(L"Debugging stopped", TS_LOG_NORMAL);
    bRunning = false;
    SetWindowText(hRunBtn, _T("Run"));
    return 0;
}