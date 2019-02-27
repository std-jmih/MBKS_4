#include "ProcessExplorer.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <string.h>


ProcessExplorer::ProcessExplorer()
{
    setlocale(LC_CTYPE, ".866");
}


ProcessExplorer::~ProcessExplorer()
{
}


int ProcessExplorer::GetThreads()
{
    HANDLE processSnapshot;
    HANDLE moduleSnapshot;
    PROCESSENTRY32W processEntry;
    MODULEENTRY32W moduleEntry;

    processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (processSnapshot == INVALID_HANDLE_VALUE)
    {
        return -1;
    }

    if (processSnapshot == INVALID_HANDLE_VALUE)
    {
        return -1;
    }

    processEntry.dwSize = sizeof(PROCESSENTRY32W);
    moduleEntry.dwSize = sizeof(MODULEENTRY32W);

    if (!Process32FirstW(processSnapshot, &processEntry))
    {
        return -1;
    }


    vsThThreads.clear();
    sThread tmp;
    int i = 0;

    do // Now walk the snapshot of processes, and display information about each process in turn
    {
        vsThThreads.push_back(tmp);                                    //PROCESSENTRY32
        vsThThreads[i].uiPID = processEntry.th32ProcessID;             //PROCESSENTRY32
        wcscpy_s(vsThThreads[i].wName, processEntry.szExeFile);        //PROCESSENTRY32
        vsThThreads[i].uiParentPID = processEntry.th32ParentProcessID; //PROCESSENTRY32

        moduleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processEntry.th32ProcessID);
        if (!Module32FirstW(moduleSnapshot, &moduleEntry))
        {
            wcscpy_s(vsThThreads[i].wPath, L"-");                      //MODULEENTRY32
        }
        else
        {
            wcscpy_s(vsThThreads[i].wPath, moduleEntry.szExePath);     //MODULEENTRY32
        }
        i++;
    } while (Process32NextW(processSnapshot, &processEntry));

    CloseHandle(processSnapshot);

    // Parent processes' names; 32/64
    bool flag;

    HANDLE hProcess;
    BOOL bRez;

    for (int i = 0; i < vsThThreads.size(); i++)
    {
        //vv 32/64
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, vsThThreads[i].uiPID);
        IsWow64Process(hProcess, &bRez);
        vsThThreads[i].bType = bRez;
        //^^ 32/64

        //vv parents
        flag = false;
        for (int j = 0; j < vsThThreads.size(); j++)
        {
            if (vsThThreads[j].uiPID == vsThThreads[i].uiParentPID)
            {
                wcscpy_s(vsThThreads[i].wParentName, vsThThreads[j].wName);
                flag = true;
                break;
            }
        }
        if (!flag)
        {
            wcscpy_s(vsThThreads[i].wParentName, L"-");
        }
        //^^parents
    }

    return 0;
}
