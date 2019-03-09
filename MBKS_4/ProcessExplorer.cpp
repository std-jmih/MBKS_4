#include "ProcessExplorer.h"
#include <string.h>
#include <sddl.h>
#include <iostream>

ProcessExplorer::ProcessExplorer()
{
    setlocale(LC_CTYPE, ".866");
}

ProcessExplorer::~ProcessExplorer()
{
}

PSID ProcessExplorer::GetSid(LPWSTR wUsername)
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

int ProcessExplorer::GetIntegrityLevel(HANDLE Token)
{
    DWORD nlen;
    DWORD SidSubAuthority;
    TOKEN_MANDATORY_LABEL *pRez;
    char buf[28];
    pRez = (TOKEN_MANDATORY_LABEL *)buf;

    if (!GetTokenInformation(Token, TOKEN_INFORMATION_CLASS::TokenIntegrityLevel, pRez, 28, &nlen))
    {
        return -1;
    }
    else
    {
        SidSubAuthority = *GetSidSubAuthority(pRez->Label.Sid, 0);
        return SidSubAuthority;
    }
}

vector<stPriv>::iterator ProcessExplorer::unique(vector<stPriv>::iterator first, vector<stPriv>::iterator last)
{
    if (first == last)
    {
        return last;
    }
    vector<stPriv>::iterator result = first;
    while (++first != last)
    {
        if (!(result->wName == first->wName))
        {
            *(++result) = *first;
        }
    }
    return ++result;
}

int ProcessExplorer::GetPrivileges(HANDLE Token, vector<stPriv> *vwPrivileges)
{
    DWORD nlen;
    TOKEN_PRIVILEGES *pRez = NULL;
    bool flag;

    if (Token == NULL)
    {
        return -1;
    }

    GetTokenInformation(Token, TOKEN_INFORMATION_CLASS::TokenPrivileges, pRez, 0, &nlen);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
        pRez = (TOKEN_PRIVILEGES *)new char[nlen];
        SetLastError(0);
    }
    else
    {
        return -1;
    }

    if (!GetTokenInformation(Token, TOKEN_INFORMATION_CLASS::TokenPrivileges, pRez, nlen, &nlen))
    {
        delete[] pRez;
        return -1;
    }
    else
    {
        vwPrivileges->clear();

        for (unsigned int i = 0; i < pRez->PrivilegeCount; i++)
        {
            stPriv stPrTmp;
            WCHAR wPrivilege[128] = { 0 };
            DWORD dBufLen = 128;

            flag = true;

            LookupPrivilegeNameW(NULL, &pRez->Privileges[i].Luid, wPrivilege, &dBufLen);

            stPrTmp.wName = wPrivilege;

            if ((pRez->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) == SE_PRIVILEGE_ENABLED)
            {
                stPrTmp.bEnabled = true;
                flag = false;
            }
            else
            {
                stPrTmp.bEnabled = false;
            }

            if ((pRez->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) == SE_PRIVILEGE_ENABLED_BY_DEFAULT)
            {
                stPrTmp.bEnabledByDefault = true;
                flag = false;
            }
            else
            {
                stPrTmp.bEnabledByDefault = false;
            }

            if ((pRez->Privileges[i].Attributes & SE_PRIVILEGE_USED_FOR_ACCESS) == SE_PRIVILEGE_USED_FOR_ACCESS)
            {
                stPrTmp.bUsedForAccess = true;
                flag = false;
            }
            else
            {
                stPrTmp.bUsedForAccess = false;
            }

            if ((pRez->Privileges[i].Attributes & SE_PRIVILEGE_REMOVED) == SE_PRIVILEGE_REMOVED)
            {
                stPrTmp.bRemoved = true;
                flag = false;
            }
            else
            {
                stPrTmp.bRemoved = false;
            }

            stPrTmp.bDisabled = flag;

            vwPrivileges->push_back(stPrTmp);
        }

        delete[] pRez;

        //vv privileges fix
        //vector<stPriv>::iterator iter = unique((*vwPrivileges).begin(), (*vwPrivileges).end());
        //(*vwPrivileges).erase(iter, (*vwPrivileges).end());
        //^^ privileges fix

        return 0;
    }
}

int ProcessExplorer::GetThreads(vector<sThread> *vsThThreads)
{
    Cleanup(vsThThreads);

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

    sThread tmp;
    int i = 0;
    do // Walk the snapshot of processes
    {
        (*vsThThreads).push_back(tmp);

        (*vsThThreads)[i].uiPID = processEntry.th32ProcessID;             //PROCESSENTRY32
        wcscpy_s((*vsThThreads)[i].wName, processEntry.szExeFile);        //PROCESSENTRY32
        (*vsThThreads)[i].uiParentPID = processEntry.th32ParentProcessID; //PROCESSENTRY32

        moduleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processEntry.th32ProcessID);
        if (!Module32FirstW(moduleSnapshot, &moduleEntry))                //MODULEENTRY32
        {
            wcscpy_s((*vsThThreads)[i].wPath, L"-");
        }
        else
        {
            wcscpy_s((*vsThThreads)[i].wPath, moduleEntry.szExePath);

            //vv DLLs
            while (Module32NextW(moduleSnapshot, &moduleEntry))
            {
                (*vsThThreads)[i].vwDLL.push_back(moduleEntry.szModule);
            }
            //^^ DLLs
        }

        i++;
    } while (Process32NextW(processSnapshot, &processEntry));

    CloseHandle(processSnapshot);

    // Parent processes' names, SIDs; 32/64; DEP/ASLR

    bool flag;

    HANDLE hProcess = NULL;
    BOOL bRez;

    TOKEN_USER *ptu;
    HANDLE tok = 0;
    DWORD nlen, dlen;
    WCHAR name[512], dom[512], tubuf[512], *pret = 0;
    int iUse;

    LPWSTR pSID = NULL;
    PSID   lpSID = NULL;
    DWORD  dSize = 512;
    DWORD  len = MAX_COMPUTERNAME_LENGTH;
    WCHAR  pszServerName[MAX_COMPUTERNAME_LENGTH];
    GetComputerNameW(pszServerName, &len);

    PROCESS_MITIGATION_DEP_POLICY stDEP;
    PROCESS_MITIGATION_ASLR_POLICY stASLR;

    for (int i = 0; i < (*vsThThreads).size(); i++)
    {
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (*vsThThreads)[i].uiPID);

        (*vsThThreads)[i].hProcessHandle = hProcess; // <- Write process handle to thread struct

        //vv 32/64
        IsWow64Process(hProcess, &bRez);
        (*vsThThreads)[i].bType = bRez;
        //^^ 32/64

        //vv parents
        flag = false;
        for (int j = 0; j < (*vsThThreads).size(); j++)
        {
            if ((*vsThThreads)[j].uiPID == (*vsThThreads)[i].uiParentPID)
            {
                wcscpy_s((*vsThThreads)[i].wParentName, (*vsThThreads)[j].wName);
                flag = true;
                break;
            }
        }
        if (!flag)
        {
            wcscpy_s((*vsThThreads)[i].wParentName, L"-");
        }
        //^^ parents

        //vv DEP/ASLR
        if (GetProcessMitigationPolicy(hProcess, ProcessDEPPolicy, &stDEP, sizeof(stDEP))) // DEP
        {
            if (stDEP.Enable)
            {
                (*vsThThreads)[i].iDEP = 1;
            }
            else
            {
                (*vsThThreads)[i].iDEP = 0;
            }
        }
        else
        {
            (*vsThThreads)[i].iDEP = -1;
        }

        if (GetProcessMitigationPolicy(hProcess, ProcessASLRPolicy, &stASLR, sizeof(stASLR))) // ASLR
        {
            if (stASLR.EnableBottomUpRandomization)
            {
                (*vsThThreads)[i].iEnableBottomUpRandomization = 1;
            }
            else
            {
                (*vsThThreads)[i].iEnableBottomUpRandomization = 0;
            }

            if (stASLR.EnableForceRelocateImages)
            {
                (*vsThThreads)[i].iEnableForceRelocateImages = 1;
            }
            else
            {
                (*vsThThreads)[i].iEnableForceRelocateImages = 0;
            }

            if (stASLR.EnableHighEntropy)
            {
                (*vsThThreads)[i].iEnableHighEntropy = 1;
            }
            else
            {
                (*vsThThreads)[i].iEnableHighEntropy = 0;
            }

            if (stASLR.DisallowStrippedImages)
            {
                (*vsThThreads)[i].iDisallowStrippedImages = 1;
            }
            else
            {
                (*vsThThreads)[i].iDisallowStrippedImages = 0;
            }
        }
        else
        {
            (*vsThThreads)[i].iEnableBottomUpRandomization = -1;
            (*vsThThreads)[i].iEnableForceRelocateImages = -1;
            (*vsThThreads)[i].iEnableHighEntropy = -1;
            (*vsThThreads)[i].iDisallowStrippedImages = -1;
        }
        //^^ DEP/ASLR

        //vv integrity level; privileges; parent SID

        if (!OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &tok))
        {
            (*vsThThreads)[i].iIntegrityLevel = -1; // <- integrity level

            wcscpy_s((*vsThThreads)[i].wParentUserSID, L"-");
            wcscpy_s((*vsThThreads)[i].wParentUserName, L"-");
            continue;
        }

        (*vsThThreads)[i].iIntegrityLevel = GetIntegrityLevel(tok);         // <- integrity level

        //GetPrivileges(tok, pszServerName, &(*vsThThreads)[i].vwPrivileges); // <- privileges
        if (GetPrivileges(tok, &(*vsThThreads)[i].vwPrivileges) == -1)
        {
            wcout << L"get priv err " << i << endl;
        }

        //get the SID of the token
        ptu = (TOKEN_USER *)tubuf;
        if (!GetTokenInformation(tok, TOKEN_INFORMATION_CLASS::TokenUser, ptu, 300, &nlen))
        {
            wcscpy_s((*vsThThreads)[i].wParentUserSID, L"-");
            wcscpy_s((*vsThThreads)[i].wParentUserName, L"-");
            continue;
        }

        //get the account/domain name of the SID
        dlen = 512;
        nlen = 512;
        if (!LookupAccountSidW(0, ptu->User.Sid, name, &nlen, dom, &dlen, (PSID_NAME_USE)&iUse))
        {
            wcscpy_s((*vsThThreads)[i].wParentUserSID, L"-");
            wcscpy_s((*vsThThreads)[i].wParentUserName, L"-");
            continue;
        }

        lpSID = GetSid(name);
        ConvertSidToStringSidW(lpSID, &pSID);
        delete[] lpSID;
        lpSID = NULL;

        wcscpy_s((*vsThThreads)[i].wParentUserSID, pSID);
        wcscpy_s((*vsThThreads)[i].wParentUserName, name);
        //^^ integrity level; privileges; parent SID
    }

    return vsThThreads->size();
}

int ProcessExplorer::SetProcessIntegrityLevel(sThread *sProcess, int iNewIntegrityLevel)
{
    HANDLE tok = 0;
    HANDLE hNewToken = 0;
    TOKEN_MANDATORY_LABEL *sLabel;
    DWORD sLabelSize;
    DWORD dStatus = 0;

    WCHAR wSID_untrusted[16] = L"S-1-16-0";
    WCHAR wSID_low[16]       = L"S-1-16-4096";
    WCHAR wSID_medium[16]    = L"S-1-16-8192";
    WCHAR wSID_high[16]      = L"S-1-16-12288";
    WCHAR wSID_system[16]    = L"S-1-16-16384";
    LPWSTR lpSID = NULL;

    if (!OpenProcessToken(sProcess->hProcessHandle, TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &tok))
    {
        return -1;
    }

    switch (iNewIntegrityLevel)
    {
    case SECURITY_MANDATORY_UNTRUSTED_RID:
    {
        lpSID = wSID_untrusted;
        break;
    }
    case SECURITY_MANDATORY_LOW_RID:
    {
        lpSID = wSID_low;
        break;
    }
    case SECURITY_MANDATORY_MEDIUM_RID:
    {
        lpSID = wSID_medium;
        break;
    }
    case SECURITY_MANDATORY_HIGH_RID:
    {
        lpSID = wSID_high;
        break;
    }
    case SECURITY_MANDATORY_SYSTEM_RID:
    {
        lpSID = wSID_system;
        break;
    }
    default:
    {
        return -1;
    }
    }

    GetTokenInformation(tok, TOKEN_INFORMATION_CLASS::TokenIntegrityLevel, NULL, 0, &sLabelSize);

    dStatus = GetLastError();
    if (dStatus != ERROR_INSUFFICIENT_BUFFER && dStatus != ERROR_SUCCESS)
    {
        return dStatus;
    }

    sLabel = (TOKEN_MANDATORY_LABEL *)malloc(sLabelSize);

    if (!GetTokenInformation(tok, TOKEN_INFORMATION_CLASS::TokenIntegrityLevel, sLabel, sLabelSize, &sLabelSize))
    {
        free(sLabel);
        return GetLastError();
    }

    ConvertStringSidToSidW(lpSID, &(sLabel->Label.Sid));

    SetTokenInformation(tok, TOKEN_INFORMATION_CLASS::TokenIntegrityLevel, sLabel, sLabelSize);

    free(sLabel);
    return 0;
}

bool ProcessExplorer::SetProcessPrivilege(sThread *sProcess, const WCHAR *wPriv, bool bAdd)
{
    HANDLE hTok = 0;
    bool retval = false;
    PTOKEN_PRIVILEGES pOldPrivs = NULL;

    size_t sz = sizeof(TOKEN_PRIVILEGES);

    // memory
    PTOKEN_PRIVILEGES pPriv = (PTOKEN_PRIVILEGES)_alloca(sz);

    // fill in buffer
    pPriv->PrivilegeCount = 1;
    if (bAdd)
    {
        pPriv->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    }
    else
    {
        pPriv->Privileges[0].Attributes = 0;
    }

    if (!LookupPrivilegeValueW(NULL, wPriv, &pPriv->Privileges[0].Luid))
    {
        return false;
    }

    // change priv
    if (!OpenProcessToken(sProcess->hProcessHandle, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hTok))
    {
        return false;
    }

    retval = (bool)AdjustTokenPrivileges(hTok, FALSE, pPriv, 0, NULL, NULL);


    return retval;
}

void ProcessExplorer::Cleanup(vector<sThread> *vsThThreads)
{
    for (int k = 0; k < vsThThreads->size(); k++)
    {
        (*vsThThreads)[k].vwDLL.clear();
        (*vsThThreads)[k].vwPrivileges.clear();
        CloseHandle((*vsThThreads)[k].hProcessHandle);
    }
    vsThThreads->clear();
}

HANDLE ProcessExplorer::GetToken(HANDLE hProcess)
{
    HANDLE tok = 0;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &tok))
    {
        return NULL;
    }
    return tok;
}
