# Introduction

I have recently delved in to the world of malware development, and purchased the Maldev Academy courseware. One of the modules in the course goes over Import Address Table obfuscation, which is a topic I find fascinating. In this article, I'll go over what the IAT is, and some ways to obfuscate it that will hopefully evade AV/EDR solutions.

## What is the Import Address Table (IAT?)

Files that execute code, such as .exe and .dll files, have a standard format known as the Portable Executable (PE) format. In simple terms, the PE format contains information that tells Windows how to run the application. The PE format has information about the size of the executable, memory management information, and other helpful details. You can view the details of an executable files PE information using a program called PE-bear. The below screenshot shows an example of what information PE-bear is able to get from the Windows calculator executable (calc.exe):

![image](https://github.com/eXcal1bur589/excal1bur589.github.io/assets/79113755/7498a76e-4b22-4637-975a-d6f51c20588c)

The Imports tab shows the IAT of the PE file. The IAT shows what external dlls the executable is using and the functions within those dlls to operate. The below screenshot shows what dlls and associated functions calc.exe requires to operate:

![image](https://github.com/eXcal1bur589/excal1bur589.github.io/assets/79113755/adfc5e3a-492c-4f15-8e1b-acaffd250fd8)

AV and EDR solutions have the ability to view the IAT of an executable to determine if there are any malicious functions being used. The presence of well known malicious functions will put AV/EDR on alert and the context in which they are used will be heavily scrutinized. Some common functions that may show up in a malicious file's IAT are:

    - CreateRemoteThread: Often used for code injection.
    - VirtualAllocEx: Used to allocate memory in another process.
    - WriteProcessMemory: Writes to another process's memory, often used with VirtualAllocEx.
    - OpenProcess: Opens another process for various purposes, including injection or modification.
    - SetWindowsHookEx: Used to set up system-wide hooks, sometimes for keylogging.
    - GetAsyncKeyState: Often used in keylogging to check the state of a key.
    - RegSetValueEx: Modifies the Windows registry.
    - ShellExecute: Executes programs or opens documents.

These functions are imported from various dlls such as kernel32.dll, etc., which in the context of a legitimate application, are not malicious. Malware can take advantage of the functions as well to perform malicious actions against the victim operating system. Let's take a look at one of the code samples from the Malware Academy course. The code is from Process Injection - Shellcode Injection module, which goes over injecting malicious shellcode in to a remote process. The code utilizes several well signatured functions that surely will get detected by AV/EDR:

    - VirtualAllocEx

    - WriteProcessMemory

    - VirtualProtectEx

    - CreateRemoteThread

