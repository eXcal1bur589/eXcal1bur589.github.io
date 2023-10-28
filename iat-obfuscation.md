# Introduction

I have recently delved in to the world of malware development, and purchased the Maldev Academy courseware. One of the modules in the course goes over Import Address Table obfuscation, which is a topic I find fascinating. In this article, I'll go over what the IAT is, and some ways to obfuscate it that will hopefully evade AV/EDR solutions.

## What is the Import Address Table (IAT?)

Files that execute code, such as .exe and .dll files, have a standard format known as the Portable Executable (PE) format. In simple terms, the PE format contains information that tells Windows how to run the application. The PE format has information about the size of the executable, memory management information, and other helpful details. You can view the details of an executable files PE information using a program called PE-bear. The below screenshot shows an example of what information PE-bear is able to get from the Windows calculator executable (calc.exe):

![image](https://github.com/eXcal1bur589/excal1bur589.github.io/assets/79113755/7498a76e-4b22-4637-975a-d6f51c20588c)

The Imports tab shows the IAT of the PE file. The IAT shows what external dlls the executable is using and the functions within those dlls to operate. The below screenshot shows what dlls and associated functions calc.exe requires to operate:

![image](https://github.com/eXcal1bur589/excal1bur589.github.io/assets/79113755/adfc5e3a-492c-4f15-8e1b-acaffd250fd8)
