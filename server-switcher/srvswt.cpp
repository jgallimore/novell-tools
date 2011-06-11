/*
   Copyright 2003 Jonathan Gallimore

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/


/*

 Server Switcher Novell Client Login Extension
 Developed for the British Red Cross Society
 By Jonathan Gallimore, Gracemore Microsystems Ltd, (c) 2002-2003


 This program is designed to run as a DLL, and requires the correct registry settings being entered in the Novell section
 i.e. [HKEY_LOCAL_MACHINE\SOFTWARE\Novell\Graphical Login\NWLGE\Srvswt]
      "LoginExtName"="srvswt.dll"
      "LoginExtDesc"="Server Switcher Login Extension"
      "LoginExtType"=dword:00008002



 To Do:

 1, Install / uninstall functions - called with RunDll32.exe
 2, Other registry settings - debug, prompt everytime, what to do if no match...
 3, Comments
 4, Make the cancel button work

 Settings: Config file for tree? Always prompt for server? Debug Information?

 Version Control

 -----------------------------------------------------------------------------------------------------------------
 |   Date    | Change                                                                                            |
 -----------------------------------------------------------------------------------------------------------------
 | 26-Oct-03 | Initial release                                                                                   |
 | 07-Apr-03 | Started adding subnet code                                                                        |
 | 13-Apr-03 | Finished subnet code; added dialog for multiple servers                                           |
 | 16-Apr-03 | Added OS detect and linked to appropriate DLL                                                     |
 -----------------------------------------------------------------------------------------------------------------

*/

#include <windows.h>
#include <stdio.h>
#include <nwalias.h>
#include <nwlgext.h>
#include <winsock2.h>
#include <malloc.h>
#include "list.h"
#include "resource.h"

#pragma resource "dialog.res"

#define WIN32_LEAN_AND_MEAN
#define N_PLAT_WNT

N_TYPEDEF_CALLBACK(NWCCODE,pNWLoginExtInit)(pNWLGAccessRec*,pNWVersion,pNWVersion,nptr,nptr);
N_TYPEDEF_CALLBACK(NWCCODE,pNWLGGetLoginData)(nint,nint,nptr,nint);
N_TYPEDEF_CALLBACK(NWCCODE,pNWLGSetLoginData)(nint,nint,nptr);
N_TYPEDEF_CALLBACK(NWCCODE,pNWLGSetCtrlBreak)();

// Global Variables

NWLGAccessRec MainAccess             = { 0, 0, 0};		// Copy of Pointers passed from Novell Client
NWLGAccessRec *pCurrentAccess        = 0;			// Handler pointers we're manipulating
char          ServerName[100]        = "";			// Final server name to push to Novell
List          PossibleServers;					// List class for servers to offer in dialog

char          ModuleName[15]         = "";
HINSTANCE     MainHandle;

BOOL CALLBACK DlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	int screenx;
	int screeny;
	int newxpos;
	int newypos;
	int index;
	char* str;

	switch (msg)
	{
		case WM_INITDIALOG:
			screenx = GetSystemMetrics (SM_CXSCREEN);
			screeny = GetSystemMetrics (SM_CYSCREEN);
           
			newxpos = (screenx / 2) - (115 / 4 * 3);
			newypos = (screeny / 2) - (100 / 4 * 3);

			SetWindowPos (hwnd, HWND_NOTOPMOST, newxpos, newypos, 0, 0, SWP_NOSIZE);

			str = PossibleServers.getFirst();
			while (str != NULL)
			{
				index = SendMessage (GetDlgItem (hwnd, ID_LIST), LB_ADDSTRING, 0, (LPARAM)str);
				SendMessage (GetDlgItem (hwnd, ID_LIST), LB_SETITEMDATA, (WPARAM)index, (LPARAM)str);
				str = PossibleServers.getNext();
			}



		break;

		case WM_COMMAND:
			switch (LOWORD (wParam))
			{
				case ID_OK:
					index = SendMessage (GetDlgItem (hwnd, ID_LIST), LB_GETCURSEL, 0, 0);
					if (index != LB_ERR)
					{
						str = (char*)SendMessage (GetDlgItem (hwnd, ID_LIST), LB_GETITEMDATA, (WPARAM)index, 0);
						strcpy (ServerName, str);
					}
					EndDialog (hwnd, ID_OK);

				break;
				case ID_CANCEL:
					EndDialog (hwnd, ID_CANCEL);
				break;
				case ID_LIST:
					switch (HIWORD (wParam))
					{
						case LBN_DBLCLK:
							index = SendMessage (GetDlgItem (hwnd, ID_LIST), LB_GETCURSEL, 0, 0);
							if (index != LB_ERR)
							{
								str = (char*)SendMessage (GetDlgItem (hwnd, ID_LIST), LB_GETITEMDATA, (WPARAM)index, 0);
								strcpy (ServerName, str);
							}
							EndDialog (hwnd, ID_OK);
						break;
					}
				break;
			}
		break;
			
		default:
			return FALSE;
	}
	
	return TRUE;
}

int sameSubnet (in_addr wsip, in_addr srvip, int bits)
{
	in_addr netmask;

	netmask.s_addr = htonl(~((1 << (32 - bits)) - 1));

	if ((wsip.s_addr & netmask.s_addr) == (srvip.s_addr & netmask.s_addr))
		return (1);
	else
		return (0);
}

void getServer (char* tree)
{
	FILE* ServerList = NULL;
	FILE* DumpFile;
	HKEY RegKey;
	DWORD ValType;

	int match;
	int ctr;
	char FileLine[200];
	char* strServerName = NULL;
	char* strServerIp = NULL;
	char* strServerMask = NULL;
	char* ptr;
	char* subnetFile = NULL;
	DWORD subnetFileSize;

	in_addr ServerIp;
	in_addr MachineIp;

	int ServerMask;
	hostent* HostData;
	char* HostName;

	WSADATA WinsockData;
	WORD WinsockVersion = MAKEWORD(1,1);

	HostName = (char *) malloc (sizeof (char) * 200);  

	WSAStartup (WinsockVersion, &WinsockData);
	gethostname (HostName, 200);
	HostData = gethostbyname (HostName);

	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, "Software\\Novell\\Graphical Login\\NWLGE\\Srvswt", 0, KEY_ALL_ACCESS, &RegKey) != ERROR_SUCCESS)
		MessageBox ((HWND)NULL, "Couldn't read registry settings", "Error!", MB_ICONEXCLAMATION | MB_OK);
	else
	{
		subnetFileSize = 0;
		if (RegQueryValueEx (RegKey, tree, 0, &ValType, NULL, &subnetFileSize) == ERROR_SUCCESS)
		{
			if (ValType == REG_SZ)
			{
				subnetFile = (char *) malloc (sizeof (char) * subnetFileSize);
				if (RegQueryValueEx (RegKey, tree, 0, &ValType, subnetFile, &subnetFileSize) != ERROR_SUCCESS)
				{
					if (subnetFile) 
						free (subnetFile);
					MessageBox ((HWND)NULL, "Couldn't read registry settings", "Error!", MB_ICONEXCLAMATION | MB_OK);	

				}
			}
			else
				MessageBox ((HWND)NULL, "Couldn't read registry settings", "Error!", MB_ICONEXCLAMATION | MB_OK);
			
		}
		RegCloseKey (RegKey);
	}
		
	if (subnetFile) 
		ServerList = fopen (subnetFile, "r");

	if (ServerList)
	{
		PossibleServers.clear ();

		while (fscanf (ServerList, "%s", &FileLine) != EOF)
		{
			strServerName = FileLine;
			strServerIp = strchr (strServerName, '=');

			if (strServerIp != NULL)
			{
				*strServerIp = '\0';
				strServerIp++;
				strServerMask = strchr (strServerIp, '/');

				if (strServerMask != NULL)
				{
					*strServerMask = '\0';
					strServerMask++;
				}
			}

			if ((strServerName != NULL) && (strServerIp != NULL) && (strServerMask != NULL))
			{
				ServerIp.s_addr = inet_addr (strServerIp);
				ServerMask = atoi (strServerMask);
			}

			if ((ServerMask >=0) && (ServerMask <=32) && (ServerIp.s_addr != -1))
			{
				ctr = 0;
				match = 0;
				while (HostData->h_addr_list[ctr] != NULL)
				{
					memcpy (&MachineIp.s_addr, HostData->h_addr_list[ctr],HostData->h_length);
					if (sameSubnet (MachineIp, ServerIp, ServerMask) == 1)
						match = 1;
					ctr++;
				}

				if (match == 1)
					PossibleServers.addItem (strServerName);
			}
		}
	}

	fclose (ServerList);


	if (subnetFile) 
		free (subnetFile);

	free (HostName);
	WSACleanup ();
}
   
N_GLOBAL_CALLBACK (NWCCODE) ExtEventHandler(pNWLGAccessRec pCurrentAccess,nint event,nint eventType,nint eventSubType, nparam parm1,nparam parm2,nflag32 flags)
{	
	pNWLGGetLoginData NWLGGetLoginData;				// function pointer to NWLGGetLoginData
	pNWLGSetLoginData NWLGSetLoginData;				// function pointer to NWLGSetLoginData
	pNWLGSetCtrlBreak NWLGSetCtrlBreak;				// function pointer to NWLGSetCtrlBreak
	pNWLGStartInfo    LoginData;					// Variable that holds login data
	HINSTANCE         hInst;					// Instance of a Novell DLL
	NWCCODE           FuncReturnCode, CallReturnCode;		// Variables for holding error codes

	FuncReturnCode = NWLG_EVT_OK;
  
	switch (event)
	{
		case NWLG_PRE_LOGIN:
			hInst=GetModuleHandle (ModuleName);
			NWLGGetLoginData = (pNWLGGetLoginData) GetProcAddress (hInst,"NWLGGetLoginData");
			NWLGSetLoginData = (pNWLGSetLoginData) GetProcAddress (hInst,"NWLGSetLoginData");
			NWLGSetCtrlBreak = (pNWLGSetCtrlBreak) GetProcAddress (hInst,"NWLGSetCtrlBreak");

			if (NWLGGetLoginData && NWLGSetLoginData && NWLGSetCtrlBreak)
			{								
				CallReturnCode = NWLGGetLoginData (NWLG_SD_START_INFO, 0, &LoginData, sizeof(LoginData));
				if (CallReturnCode == NWLG_OK)
				{					
					getServer(LoginData->tree);
					switch (PossibleServers.getCount())
					{
						case 0:
							strcpy (ServerName, "");
						break;

						case 1:
							strcpy (ServerName,PossibleServers.getFirst());
						break;

						default:
							if (DialogBox (MainHandle, MAKEINTRESOURCE (ABOUTDLG), 0, DlgProc)==ID_CANCEL)
								NWLGSetCtrlBreak ();
						break;

					}

					if (strcmp (ServerName, "") != 0)
						CallReturnCode = NWLGSetLoginData (NWLG_SD_SERVER,0,ServerName);


				}
			}
		break;	

		case NWLG_TERMINATE:
			pCurrentAccess->pEventHandler = MainAccess.pEventHandler;
		break;
  
		default:
 
		break;
	}

	if (MainAccess.pEventHandler)
		return (MainAccess.pEventHandler (pCurrentAccess,event,eventType,eventSubType,parm1,parm2,flags));
	else 
		return (FuncReturnCode);
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD reason, LPVOID lpReserved)
{
	NWVersion       CompiledVersion, RuntimeVersion;		// Needed for initializing
	NWCCODE         ReturnCode;					// variable for return value
	HINSTANCE       hInst;						// DLL Instance
	pNWLoginExtInit NWLoginExtInit;					// Function pointer to DLL function
	OSVERSIONINFO   OSVer;

	if (reason == DLL_PROCESS_ATTACH)
	{		
		MainHandle = (HINSTANCE)hModule;

		OSVer.dwOSVersionInfoSize = sizeof (OSVERSIONINFO);


		if (GetVersionEx (&OSVer) != 0)
		{
			switch (OSVer.dwPlatformId)
			{
				case VER_PLATFORM_WIN32_NT:
					strcpy (ModuleName, "LGNWNT32.DLL");
				break;

				case VER_PLATFORM_WIN32_WINDOWS:
					strcpy (ModuleName, "LGNW9532.DLL");
				break;
			}
		}

		if ((strcmp (ModuleName, "LGNWNT32.DLL") == 0) || (strcmp (ModuleName, "LGNW9532.DLL") == 0))
		{
			hInst = GetModuleHandle(ModuleName);
			if (hInst)
			{					
				NWLoginExtInit = (pNWLoginExtInit) GetProcAddress(hInst,"NWLoginExtInit");
				NWLGSetVersion (CompiledVersion);			

				if ((ReturnCode = NWLoginExtInit (&pCurrentAccess,&CompiledVersion,&RuntimeVersion,NULL,NULL))==NWLG_OK)
				{			
					MainAccess.pEventHandler = pCurrentAccess->pEventHandler;
					MainAccess.pExceptionHandler = pCurrentAccess->pExceptionHandler;
					MainAccess.pIOHandler = pCurrentAccess->pIOHandler;
        
					if (pCurrentAccess)
						pCurrentAccess->pEventHandler = (pEvtHndlr)ExtEventHandler;
				}
			}
		}			
	}

	return (TRUE);
}

