癤?/ dllmain.cpp : DLL ?좏뵆由ъ??댁뀡??吏꾩엯?먯쓣 ?뺤쓽?⑸땲??
#include "pch.h"
#include <stdio.h>
#include <Windows.h>
#include <shlobj.h>
#include <wchar.h>
#include <tlhelp32.h>

// Buffer For Debug
char buf[4096];
TCHAR debug[4096];

// Num To check whether process is vulnerable
DWORD fwriteNum = 0;
DWORD WriteFileNum = 0;

// Var For PIPE
HANDLE hPipe = NULL;
const wchar_t* PIPE_NAME = L"\\\\.\\pipe\\jungho";

// Funcs For Hook
size_t Checkfwrite(const void* buffer, size_t size, size_t count, FILE* stream);
size_t Fakefwrite(const void* buffer, size_t size, size_t count, FILE* stream);
BOOL WINAPI CheckWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
BOOL WINAPI FakeWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);

// Funcs For Patch IAT
void PatchIAT(LPDWORD lpAddress, DWORD data);
LPVOID FindTargetVA(LPCSTR lpTargetDllName, LPCSTR lpTargetFuncName);

// Funcs To check whether process is vulnerable
DWORD WINAPI check(LPVOID lpParam);


BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, 0, check, reinterpret_cast<LPVOID>(hModule), 0, 0);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

// Func To Count fwriteNum
size_t Checkfwrite(const void* buffer, size_t size, size_t count, FILE* stream) {
    
    fwriteNum++;

    wsprintfW(debug, L"CheckfWrtie PID: %u fwriteNum: %d", GetCurrentProcessId(), fwriteNum);
    OutputDebugStringW(debug);

    return fwrite(buffer, size, count, stream);
}
////

// Func To block fwrite's leaked text
size_t Fakefwrite(const void* buffer, size_t size, size_t count, FILE* stream) {

    wsprintfW(debug, L"Fakefwrite PID: %u", GetCurrentProcessId());
    OutputDebugStringW(debug);

    DWORD bytesWritten;
    SYSTEMTIME lt;

    GetLocalTime(&lt);
    sprintf_s(buf, "Hacking Detected Time: %04d-%02d-%02d %02d:%02d:%02d\0", lt.wYear, lt.wMonth, lt.wDay, lt.wHour, lt.wMinute, lt.wSecond);

    BOOL result = WriteFile(hPipe, buf, strlen(buf), &bytesWritten, NULL);
    if (!result) {
        sprintf_s(buf, "WriteFile failed with error: %d\n", GetLastError());
        OutputDebugStringA(buf);
    }

    return size;
}
////

// Func To Count WriteFileNum
BOOL WINAPI CheckWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {

    WriteFileNum++;

    wsprintfW(debug, L"CheckWriteFile PID: %u WriteFileNum: %d", GetCurrentProcessId(), WriteFileNum);
    OutputDebugStringW(debug);

    return WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}
////

// Func To block WriteFile's leaked text
BOOL WINAPI FakeWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {

    wsprintfW(debug, L"FakeWriteFile PID: %u", GetCurrentProcessId());
    OutputDebugStringW(debug);

    DWORD bytesWritten;
    SYSTEMTIME lt;

    GetLocalTime(&lt);
    sprintf_s(buf, "Hacking Detected Time: %04d-%02d-%02d %02d:%02d:%02d\0", lt.wYear, lt.wMonth, lt.wDay, lt.wHour, lt.wMinute, lt.wSecond);

    BOOL result = WriteFile(hPipe, buf, strlen(buf), &bytesWritten, NULL);
    if (!result) {
        sprintf_s(buf, "WriteFile failed with error: %d\n", GetLastError());
        OutputDebugStringA(buf);
    }

    return TRUE;
}
////


// Func To patch IAT
void PatchIAT(LPDWORD lpAddress, DWORD data) {
    DWORD flp1, flp2;
    VirtualProtect((LPVOID)lpAddress, sizeof(DWORD), PAGE_READWRITE, &flp1);
    *lpAddress = data;
    VirtualProtect((LPVOID)lpAddress, sizeof(DWORD), PAGE_READWRITE, &flp2);
}
////

// Func To find Function's VA
LPVOID FindTargetVA(LPCSTR lpTargetDllName, LPCSTR lpTargetFuncName) {
    HMODULE hModule = GetModuleHandleA(NULL);
    LPBYTE lpFileBase = (LPBYTE)hModule;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(lpFileBase + pDosHeader->e_lfanew);
    DWORD offset = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(lpFileBase + offset);

    DWORD i = 0, dllIdx = 0xFFFFFFFF, funcIdx = 0xFFFFFFFF;
    while (pImportDescriptor[i].Name != 0) {
        LPCSTR lpDllName = (LPCSTR)(lpFileBase + pImportDescriptor[i].Name);
        sprintf_s(buf, "ImportDescryptor[%d].Name=%s\n", i, lpDllName);
        OutputDebugStringA(buf);

        if (_stricmp(lpDllName, lpTargetDllName) == 0) {
            dllIdx = i;
            break;
        }
        i++;
    }
    if (dllIdx == 0xFFFFFFFF) {
        return NULL;
    }

    LPDWORD lpRvaFuncName = (LPDWORD)(lpFileBase + pImportDescriptor[dllIdx].Characteristics);
    i = 0;
    while (lpRvaFuncName[i] != NULL) {
        LPCSTR lpFuncName = (LPCSTR)lpFileBase + lpRvaFuncName[i] + 2;
        if (strcmp(lpFuncName, lpTargetFuncName) == 0) {
            funcIdx = i;
            break;
        }
        i++;
    }
    if (funcIdx == 0xFFFFFFFF) {
        return NULL;
    }

    LPVOID lpFuncPtr = (LPVOID)(((LPDWORD)(lpFileBase + pImportDescriptor[dllIdx].FirstThunk)) + funcIdx);
    sprintf_s(buf, "Successfully identified %s!%s() at %#x\n", lpTargetDllName, lpTargetFuncName, (DWORD)lpFuncPtr);
    OutputDebugStringA(buf);
    return lpFuncPtr;
}
////

// Func To check whether process is vulnerable
DWORD WINAPI check(LPVOID lpParam) {

    HMODULE hModule = reinterpret_cast<HMODULE>(lpParam);

    DWORD originalWriteFile = NULL;
    DWORD originalfwrite = NULL;

    // Find WriteFile's Real Addr
    LPVOID WriteFileAddr = FindTargetVA("kernel32.dll", "WriteFile");
    if (WriteFileAddr != NULL) {
        originalWriteFile = *(LPDWORD)WriteFileAddr;
        PatchIAT((LPDWORD)WriteFileAddr, (DWORD)CheckWriteFile);
    }

    // Find fwrite's Real Addr
    LPVOID fwriteAddr = FindTargetVA("api-ms-win-crt-stdio-l1-1-0.dll", "fwrite");
    if (fwriteAddr != NULL) {
        originalfwrite = *(LPDWORD)fwriteAddr;
        PatchIAT((LPDWORD)fwriteAddr, (DWORD)Checkfwrite);
    }

    // Wait For 3 secs
    Sleep(3000);

    // Case 1: There's no func in process
    if (fwriteAddr == NULL && WriteFileAddr == NULL) {
        FreeLibraryAndExitThread(hModule, 0);
        return 0;
    }
    // Case 2: There's one or two func in process but not dangerous
    else if (WriteFileNum < 3 && fwriteNum < 3) {
        if (fwriteAddr != NULL) PatchIAT((LPDWORD)fwriteAddr, originalfwrite);
        if (WriteFileAddr != NULL) PatchIAT((LPDWORD)WriteFileAddr, originalWriteFile);

        FreeLibraryAndExitThread(hModule, 0);
        return 0;
    }
    // Case 3: Danger Process!!
    else {

        // Change Func into Fake Func
        if (fwriteNum >= 3) PatchIAT((LPDWORD)fwriteAddr, (DWORD)Fakefwrite);
        if (WriteFileNum >= 3) PatchIAT((LPDWORD)WriteFileAddr, (DWORD)FakeWriteFile);

        // Create File For PIPE
        hPipe = CreateFile(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

        return 0;


    }
}
////
