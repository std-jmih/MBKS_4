#include "ProcessExplorer.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <string.h>
#include <sddl.h>


ProcessExplorer::ProcessExplorer()
{
    setlocale(LC_CTYPE, ".866");
}


ProcessExplorer::~ProcessExplorer()
{
}

PSID GetSid(LPWSTR wUsername)
{
    int i = 0;
    SID_NAME_USE type_of_SID;
    DWORD dwLengthOfDomainName = 0;
    DWORD dwLengthOfSID = 0;
    DWORD dwErrCode;
    SID *lpSID = NULL;
    LPWSTR lpDomainName = NULL;

    if (!LookupAccountNameW(
        NULL,
        wUsername,
        NULL,
        &dwLengthOfSID,
        NULL,
        &dwLengthOfDomainName,
        &type_of_SID))
    {
        dwErrCode = GetLastError();
        if (dwErrCode == ERROR_INSUFFICIENT_BUFFER)
        {
            lpSID = (SID *) new char[dwLengthOfSID];
            lpDomainName = (LPWSTR) new wchar_t[dwLengthOfDomainName];
        }
        else
        {
            printf("Lookup account name failed.\n");
            printf("Error code: %d\n", dwErrCode);
        }
    }

    if (!LookupAccountNameW(
        NULL,
        wUsername,
        lpSID,
        &dwLengthOfSID,
        lpDomainName,
        &dwLengthOfDomainName,
        &type_of_SID))
    {
        dwErrCode = GetLastError();
        printf("Lookup account name failed.\n");
        printf("Error code: %d\n", dwErrCode);
    }

    delete[] lpDomainName;

    return lpSID;
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

    TOKEN_USER *ptu;
    HANDLE tok = 0;
    DWORD nlen, dlen;
    WCHAR name[512], dom[512], tubuf[512], *pret = 0;
    int iUse;

    SID sSID;
    LPWSTR pSID = NULL;
    DWORD cbSid;
    WCHAR DomainName[512];
    DWORD dSize = 512;
    SID_NAME_USE pe;
    DWORD len = MAX_COMPUTERNAME_LENGTH;
    WCHAR pszServerName[MAX_COMPUTERNAME_LENGTH];
    GetComputerNameW(pszServerName, &len);

    for (int i = 0; i < vsThThreads.size(); i++)
    {
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, vsThThreads[i].uiPID);

        //vv 32/64
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

        // vv parent SID

        if (!OpenProcessToken(hProcess, TOKEN_QUERY, &tok))
        {
            wcscpy_s(vsThThreads[i].wParentUserSID, L"-");
            wcscpy_s(vsThThreads[i].wParentUserName, L"-");
            continue;
        }

        //get the SID of the token
        ptu = (TOKEN_USER *)tubuf;
        if (!GetTokenInformation(tok, (TOKEN_INFORMATION_CLASS)1, ptu, 300, &nlen))
        {
            wcscpy_s(vsThThreads[i].wParentUserSID, L"-");
            wcscpy_s(vsThThreads[i].wParentUserName, L"-");
            continue;
        }

        //get the account/domain name of the SID
        dlen = 512;
        nlen = 512;
        if (!LookupAccountSidW(0, ptu->User.Sid, name, &nlen, dom, &dlen, (PSID_NAME_USE)&iUse))
        {
            wcscpy_s(vsThThreads[i].wParentUserSID, L"-");
            wcscpy_s(vsThThreads[i].wParentUserName, L"-");
            continue;
        }

        ConvertSidToStringSidW(GetSid(name), &pSID);

        wcscpy_s(vsThThreads[i].wParentUserSID, pSID);
        wcscpy_s(vsThThreads[i].wParentUserName, name);
        // ^^ parent SID
    }

    return 0;
}
