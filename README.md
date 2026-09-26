# Syscall Apc Injection Trojans (Direct & Indirect)

<img align="right" src="media/indirsys-apc-reshack.png" width="380" />

Collection of remote shellcode Loaders using APCs, direct/indirect syscalls, ntdll and low level utilities, undetected by Windows Defender and BitDefender. This code is for educational purposes only, do not use it for any malicious or unauthorized activity.

This repo is an improved version of [this](https://github.com/Hue-Jhan/Ntdll-Apc-Injection-Trojans), and includes both the direct syscall and indirect syscalls version of a classic shellcode injection via Asynchrnous procedure calls, its dll version, and a DLL injector queuing LoadLibraryA.

# 🖥️ Code

Consists of 6 projects that have the same basic structure and share most of the code, they are: Nt APC injection, DLL version, and a DLL Injector (LoadLibrary using APC), all of these have the direct/indirect syscalls version. The shellcode is for a windows msg box, in all of the samples there are 2 versions of choosing the thread upon which to queue the shellcode/dll:
- We either find the first thread and queue to it;
- Or we enumerate every thread of the process and queue to all of them.

Next to each code as you can see i put the virus total detections for its raw executable.
 
### 0) Direct & Indirect System Calls Explained

On Windows, many native API functions inside ntdll.dll eventually execute a syscall that transitions execution from user mode to kernel mode. This code extracts the system service number (SSN) of some native api functions and puts it in their new unhooked structs. The ssn changes from a windows version to another, so it has to be resolved at runtime. Here is the struct the code looks for:

```asm
mov r10, rcx
mov eax, 0x00001BE   ; SSN
syscall
```

Standard WinAPI wrappers and ntdll functions are frequently monitored or hooked by security solutions at user level, thats why we use the syscalls. Also this is not ntdll unhooking because we do not directly modify the function but simply bypass the hook placed at the beginning of the function (jmp ...). In the indirect syscall version the code also locates the "syscall" instruction inside that function and jumps to that after setting the SSN.

In order to accomplish this the code does the following:

- Creation of custom typedef structs for each function (+ internal structures and objects that they need);
- Manual PE Parsing using a custom export directory traversal function (`GetProcAddressManualEx()`) to read DOS headers, locate NT headers, access the Data Directory, and map function names, ordinals, and RVAs directly from memory.
- Parsing exported native functions to extract the unique System Service Number (`mov eax, SSN`) and constructs unhooked execution paths.
- Execution of syscalls to transition to kernel mode directly from application space. Actually indirect syscalls locate the native `syscall` instruction within unhooked regions of `ntdll.dll` and jump to it after updating the SSN, keeping instruction pointers closer to expected boundaries.

To get the RVA of each nt procedure (located in the export directory) i used ```GetProcAddressManualEx()```, a custom function made by chatgp- ehm i mean me, that parses the PE headers and walks the export directory instead of calling the Windows api. So the process looks like this: 

- Read the __DOS header__ and use ```e_lfanew``` to get to nt headers;
- At ```base + e_lfanew``` find the __NT headers__ (signature + IMAGE_FILE_HEADER + IMAGE_OPTIONAL_HEADER), the OptionalHeader contains the DataDirectory array.
- __OptionalHeader.DataDirectory__[IMAGE_DIRECTORY_ENTRY_EXPORT] gives the RVA/size of the Export Directory, so ```base + rva``` goes to IMAGE_EXPORT_DIRECTORY in memory.
- __Export Directory__ contains 3 lists: 
  - AddressOfNames: array of RVAs to ASCII names, for example ```nameRvas[i] = "LoadLibraryA"```;
  - AddressOfNameOrdinals: each index corresponds to a function name and tells you the ordinal for that name, ```ordinals[i] = index into AddressOfFunctions```;
  - AddressOfFunctions: array of RVAs of the real exported functions, ```funcRvas[ordinal] = RVA of the actual function```.

So to resolve a name we find the name in the AddressOfNames array, get its ```ordinals[i]``` value (index), read ```funcRvas[ordinals[i]]```, and convert the function RVA to an absolute address by adding the module base: ```funct_add = base + funcRvas[ordinals[i]]```. 

If funcRva points back inside the export directory region then the entry is a forwarded export, in this case and in other special cases like failing to validates the DOS header magic (MZ) and the PE signature, or if the RVA is too big, the function simply returns null.


### 1) Syscall APC Process Injection <img align="right" src="media/dirsys-apc.png" width="400" />


1) The encrypted payload is decrypted in memory;
2) System processes are enumerated via `NtQuerySystemInformation()` to identify the target PID, then we obtain a handle using `NtOpenProcess()`; 
<img align="right" src="media/indirsys-apc.png" width="400" />
3) Memory allocation, writing, and protection changes (RWX) are done inside the remote process using custom syscall-backed native routines;
4) Target threads are enumerated, handles are retrieved via `NtOpenThread()`, and the payload is queued using native APC functions (`NtQueueApcThread`) to execute when threads enter an alertable state.

### 2) DLL Version
<img align="right" src="media/syscall-apc-dll.png" width="280" />

The DLL variant operates internally within the process it is loaded into, using `GetCurrentProcessId()` to target its host environment (no need to use syscalls as this function is commonly used in programs). 

Also it spawns a new execution thread outside the loader lock to prevent deadlocks. Try to disable precompiled headers in Visual Studio build config to avoid compile errors.

### 3) DLL Injection via APC
<img align="right" src="media/syscall-apc-dll-inj-shotgun.png" width="400" />

Extracts an embedded DLL resource, writes it to disk, and leverages `LoadLibraryA` queueing via APCs:
1) Extracts resource data and computes path lengths and sizes;
2) Resolves the target process and secures a handle;
3) Allocates space within the remote process, writes the absolute DLL path string, and marks the region RWX;
4) Locates the base address of `kernel32.dll` to acquire the `LoadLibraryA` pointer;
5) Queues `LoadLibraryA` with the path string base address to target thread queues, either to its first thread of the process or to all of them.

This dll injection method is not stealthy at all (because it uses loadlibrary) but it's the fastest, also DLLs are by default stealthier than executables even if they are written to disk.

# 🛡️ AV Detection

<img align="right" src="media/syscall-reshack.png" width="380" />

Executables typically bypass static signatures from Windows Defender and BitDefender, especially when metadata is aligned or wrapped using native utility signatures (e.g., `Mshta.exe` or custom MSI packages).

Advanced behavioral engines (such as Bitdefender Advanced Thread Defense) will however flag abnormal call stacks or interrupt execution if stack pointers or return addresses do not cleanly align with standard `ntdll.dll` transitions.

Modern kernel protections, event tracing (ETW), and technologies like Intel CET (Control-flow Enforcement Technology) monitor indirect branch tracking and shadow stacks, which means kernel-level logging remains the best solution against manual trampolining and non-standard execution flows.
