/*   Copyright 2003 Jonathan Gallimore

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

#include <iostream.h>
#include <fstream.h>
#include <windows.h>

#pragma resource "srvswt.res"

int resourceToFile (char* res, char* filename, HINSTANCE hFile)
{
	HRSRC hFind;
	HRSRC hLoad;
	char* data;

	hFind = FindResource (hFile, res, RT_RCDATA);
	if (hFind == NULL)
		return (1);

	hLoad = (HRSRC) LoadResource ((HMODULE)hFile, hFind);
	if (hLoad == NULL)
		return (1);

	data = (char*) LockResource (hLoad);
	if (data == NULL)
		return (1);

	ofstream fout (filename, ios::binary);
	fout.write (data, SizeofResource(hFile, hFind));
	fout.close ();

	return (0);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	if (resourceToFile ("main", "c:\srvswt.dll", hInstance) == 0) 
		MessageBox ((HWND) NULL, "File Copied Successfully", "Information", MB_ICONEXCLAMATION | MB_OK);
	else
		MessageBox ((HWND) NULL, "File Not Copied Successfully", "Information", MB_ICONEXCLAMATION | MB_OK);

	return (0);
}