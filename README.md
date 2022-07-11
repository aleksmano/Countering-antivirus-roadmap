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
