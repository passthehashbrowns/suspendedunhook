# Obtaining NTDLL from a suspended process
This is a small POC for obtaining a clean copy of NTDLL by spawning a new process in a suspended state and reading the copy of NTDLL that it loads before EDR has a chance to inject their library and place hooks. It simply obtains the base address of NTDLL in the current process and performs a ReadProcessMemory call on the same location from the remote process, as NTDLL should be loaded at the same base address in every process. This example uses the fresh copy of NTDLL to resolve direct syscall stubs, but you can also use it to unhook NTDLL functions. 

## Why do we need a fresh copy of NTDLL?
All modern EDR products place hooks into commonly abused functions found in NTDLL. Several techniques exist for bypassing these hooks, but some of them require a fresh copy of NTDLL. A fresh copy can be found on disk, but performing a double load of NTDLL is a generally suspicious behavior as there are few normal reasons to do this.

It is worth noting that this method is not without drawbacks. The CreateProcess and ReadProcessMemory calls will be hooked in our original process, so the EDR will see us creating a suspended process and then reading from the process memory. 

### Caveats
This code works from x64 parent -> x64 child and x64 parent -> x86 child (since x86 processes have both SysWOW64 and System32 copies of NTDLL loaded). It should only take minor modifications to get it working in x86.


### References
[Syscall stub resolution code - @bats3c](https://github.com/bats3c/shad0w/blob/master/beacon/src/syscalls.c)

[Full DLL unhooking - @spotheplanet](https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++)

[Retrieving syscall stubs at runtime - @spotheplanet](https://www.ired.team/offensive-security/defense-evasion/retrieving-ntdll-syscall-stubs-at-run-time)

[Malware mitigation when direct system calls are used - Cyberbit](https://www.cyberbit.com/blog/endpoint-security/malware-mitigation-when-direct-system-calls-are-used/)
