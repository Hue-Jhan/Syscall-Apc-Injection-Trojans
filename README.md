# Syscall Apc Injection Trojans (Direct & Indirect)
Collection of remote shellcode Loaders using APCs, direct/indirect syscalls, ntdll and low level utilities, undetected by Windows Defender and BitDefender. This code is for educational purposes only, do not use it for any malicious or unauthorized activity.

This code is adn improved version of [this](https://github.com/Hue-Jhan/Ntdll-Apc-Injection-Trojans), and includes both the direct syscall and indirect syscalls version of a classic shellcode injection via APC, its dll version, and a DLL injector queuing LoadLibraryA.

# 🖥️ Code

This repo is a more advanced version of [this one](https://github.com/Hue-Jhan/Ntdll-Apc-Injection-trojans), it consists of 6 projects that have the same basic structure and share most of the code, they are: Nt APC injection, DLL version, and a DLL Injector (LoadLibrary using APC), all of these have the direct/indirect syscalls version. The shellcode is for a windows msg box, in all of the samples there are 2 versions of choosing the thread to queue the shellcode/dll:
- We either find the first thread and queue to it;
- Or we enumerate every thread of the process and queue to all of them.

Next to each code as you can see i put the virus total detections for its raw executable.

...

# 🛡️ AV Detection

a

