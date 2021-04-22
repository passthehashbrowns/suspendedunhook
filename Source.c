

#include <windows.h>
#include <psapi.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdio.h>

#include "Header.h"
#pragma comment(lib, "ntdll")

extern CHAR SyscallStub[SYSCALL_STUB_SIZE];

int main(int argc, char* argv[]) {
    //Create our suspended process
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

    if (!pi.hProcess)
    {
        printf("[-] Error creating process\r\n");
    }
    else {
        printf("[i] Created remote process\n");
    }
    
    //Get base address of NTDLL
    HANDLE process = GetCurrentProcess();
    MODULEINFO mi;
    HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");
    GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
    
    //Read the remote copy of NTDLL
    LPVOID buffer;
    buffer = HeapAlloc(GetProcessHeap(), 0, mi.SizeOfImage);
    SIZE_T dwRead;
    BOOL bSuccess = ReadProcessMemory(pi.hProcess, (LPCVOID)mi.lpBaseOfDll, buffer, mi.SizeOfImage, &dwRead);
    printf("[+] Copied remote NTDLL\n");

    //Resolve our syscall
    struct NtInfo NtdllInfo;
    struct Syscalls rSyscall;
    ParseNtdll(&NtdllInfo, &rSyscall, buffer, dwRead, FALSE);
    printf("[+] Parsed remote ntdll\n");
    bSuccess = MakeSyscall("NtAllocateVirtualMemory", NtdllInfo.pExprtDir, NtdllInfo.lpRawData, NtdllInfo.pTextSection, NtdllInfo.pRdataSection, SyscallStub, FALSE);
    if (bSuccess) {
        printf("[+] Created syscall\n");
    }

    LPVOID allocation_start = NULL;
    char shellcode[8000];
    SIZE_T allocation_size = sizeof(shellcode);
    //Call our syscall
    NTSTATUS status = rSyscall.NtAllocateVirtualMemory(pi.hProcess, &allocation_start, 0, (PULONG)&allocation_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (NT_SUCCESS(status)) {
        printf("[+] Syscall succeeded!\n");
    }
    
    CleanSyscall(SyscallStub);
    printf("[i] Cleaned up syscall stub\n");

    CloseHandle(process);
    FreeLibrary(ntdllModule);

    TerminateProcess(pi.hProcess, 0);

    return 1;

}