#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.Hider.h"
#include "Global.Engine.h"
#include "Global.Debugger.h"

// Global.Engine.Hider.functions:
static bool isAtleastVista()
{
	static bool isAtleastVista=false;
	static bool isSet=false;
	if(isSet)
		return isAtleastVista;
	OSVERSIONINFO versionInfo= {0};
	versionInfo.dwOSVersionInfoSize=sizeof(OSVERSIONINFO);
	GetVersionEx(&versionInfo);
	isAtleastVista=versionInfo.dwMajorVersion >= 6;
	isSet=true;
	return isAtleastVista;
}

void FixAntidebugApiInProcess32(HANDLE hProcess, bool Hide)
{
	const BYTE patchCheckRemoteDebuggerPresent[5] = {
		0x33, 0xC0, //XOR EAX,EAX
		0xC2, 0x08, 0x00}; //RETN 0x8

	const BYTE patchGetTickCount[3] = {
		0x33, 0xC0, //XOR EAX,EAX
		0xC3}; //RETN

	ULONG_PTR APIPatchAddress = NULL;
	DWORD OldProtect;
	SIZE_T ueNumberOfBytesRead = 0;

	if(Hide)
	{
		APIPatchAddress = (ULONG_PTR)EngineGlobalAPIHandler(hProcess, NULL, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"),"CheckRemoteDebuggerPresent"), NULL, UE_OPTION_IMPORTER_REALIGN_APIADDRESS);

		VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)APIPatchAddress, sizeof(patchCheckRemoteDebuggerPresent), PAGE_EXECUTE_READWRITE, &OldProtect);
		WriteProcessMemory(hProcess, (LPVOID)(APIPatchAddress), &patchCheckRemoteDebuggerPresent, sizeof(patchCheckRemoteDebuggerPresent), &ueNumberOfBytesRead);
		VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)APIPatchAddress, sizeof(patchCheckRemoteDebuggerPresent), OldProtect, &OldProtect);

		APIPatchAddress = (ULONG_PTR)EngineGlobalAPIHandler(hProcess, NULL, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"),"GetTickCount"), NULL, UE_OPTION_IMPORTER_REALIGN_APIADDRESS);

		VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)APIPatchAddress, sizeof(patchGetTickCount), PAGE_EXECUTE_READWRITE, &OldProtect);
		WriteProcessMemory(hProcess, (LPVOID)(APIPatchAddress), &patchGetTickCount, sizeof(patchGetTickCount), &ueNumberOfBytesRead);
		VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)APIPatchAddress, sizeof(patchGetTickCount), OldProtect, &OldProtect);
	}
	else
	{
		APIPatchAddress = (ULONG_PTR)EngineGlobalAPIHandler(hProcess, NULL, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"),"CheckRemoteDebuggerPresent"), NULL, UE_OPTION_IMPORTER_REALIGN_APIADDRESS);

		VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)APIPatchAddress, sizeof(patchCheckRemoteDebuggerPresent), PAGE_EXECUTE_READWRITE, &OldProtect);
		WriteProcessMemory(hProcess, (LPVOID)(APIPatchAddress), (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"),"CheckRemoteDebuggerPresent"), sizeof(patchCheckRemoteDebuggerPresent), &ueNumberOfBytesRead);
		VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)APIPatchAddress, sizeof(patchCheckRemoteDebuggerPresent), OldProtect, &OldProtect);

		APIPatchAddress = (ULONG_PTR)EngineGlobalAPIHandler(hProcess, NULL, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"),"GetTickCount"), NULL, UE_OPTION_IMPORTER_REALIGN_APIADDRESS);

		VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)APIPatchAddress, sizeof(patchGetTickCount), PAGE_EXECUTE_READWRITE, &OldProtect);
		WriteProcessMemory(hProcess, (LPVOID)(APIPatchAddress), (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"),"GetTickCount"), sizeof(patchGetTickCount), &ueNumberOfBytesRead);
		VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)APIPatchAddress, sizeof(patchGetTickCount), OldProtect, &OldProtect);
	}
}

bool FixPebInProcess(HANDLE hProcess, bool Hide)
{
	PEB_CURRENT myPEB = {0};
	SIZE_T ueNumberOfBytesRead = 0;

#ifndef _WIN64
	PEB64 myPEB64 = {0};
	void * AddressOfPEB64 = GetPEBLocation64(hProcess);
#endif

	void * AddressOfPEB = GetPEBLocation(hProcess);

	if (!AddressOfPEB)
		return false;

	if(ReadProcessMemory(hProcess, AddressOfPEB, (void*)&myPEB, sizeof(PEB_CURRENT), &ueNumberOfBytesRead))
	{
#ifndef _WIN64
		if (AddressOfPEB64)
		{
			ReadProcessMemory(hProcess, AddressOfPEB64, (void*)&myPEB64, sizeof(PEB64), &ueNumberOfBytesRead);
		}
#endif

		if(Hide)
		{
			myPEB.BeingDebugged = FALSE;
			myPEB.NtGlobalFlag &= ~0x70;

#ifndef _WIN64
			myPEB64.BeingDebugged = FALSE;
			myPEB64.NtGlobalFlag &= ~0x70;
#endif

			//Fix heap flags: https://github.com/eschweiler/ProReversing
			//BYTE* Heap = (BYTE*)myPEB.ProcessHeap;
		}
		else
		{
			myPEB.BeingDebugged = TRUE;
#ifndef _WIN64
			myPEB64.BeingDebugged = TRUE;
#endif
		}

		if(WriteProcessMemory(hProcess, AddressOfPEB, (void*)&myPEB, sizeof(PEB_CURRENT), &ueNumberOfBytesRead))
		{
#ifndef _WIN64
			if (AddressOfPEB64)
			{
				WriteProcessMemory(hProcess, AddressOfPEB64, (void*)&myPEB64, sizeof(PEB64), &ueNumberOfBytesRead);
			}
#endif

			return true;
		}
	}

	return false;
}

bool ChangeHideDebuggerState(HANDLE hProcess, DWORD PatchAPILevel, bool Hide)
{
	if(hProcess)
	{
		if (FixPebInProcess(hProcess, Hide))
		{
			if(PatchAPILevel == UE_HIDE_BASIC)
			{
#ifndef _WIN64
				FixAntidebugApiInProcess32(hProcess, Hide);
#endif
			}

			return true;
		}
	}

	return false;
}
