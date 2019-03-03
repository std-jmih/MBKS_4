#include "ProcessExplorer.h"
#include <psapi.h>
#include <tlhelp32.h>
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

int GetIntegrityLevel(HANDLE Token)
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

vector<stPriv>::iterator unique(vector<stPriv>::iterator first, vector<stPriv>::iterator last)
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

int GetPrivileges(HANDLE Token, LPCWSTR lpSystemName, vector<stPriv> *vwPrivileges)
{
    DWORD nlen;
    TOKEN_PRIVILEGES *pRez = NULL;
    WCHAR wPrivilege[32];
    DWORD dBufLen = 32;
    stPriv stPrTmp;

    GetTokenInformation(Token, TOKEN_INFORMATION_CLASS::TokenPrivileges, pRez, 0, &nlen);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
        pRez = (TOKEN_PRIVILEGES *)new char[nlen];
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
        for (unsigned int i = 0; i < pRez->PrivilegeCount; i++)
        {
            LookupPrivilegeNameW(lpSystemName, &pRez->Privileges[i].Luid, wPrivilege, &dBufLen);

            stPrTmp.wName = wPrivilege;

            if ((pRez->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) == SE_PRIVILEGE_ENABLED)
            {
                stPrTmp.bEnabled = true;
            }
            else
            {
                stPrTmp.bEnabled = false;
            }

            if ((pRez->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) == SE_PRIVILEGE_ENABLED_BY_DEFAULT)
            {
                stPrTmp.bEnabledByDefault = true;
            }
            else
            {
                stPrTmp.bEnabledByDefault = false;
            }

            if ((pRez->Privileges[i].Attributes & SE_PRIVILEGE_USED_FOR_ACCESS) == SE_PRIVILEGE_USED_FOR_ACCESS)
            {
                stPrTmp.bUsedForAccess = true;
            }
            else
            {
                stPrTmp.bUsedForAccess = false;
            }

            //if ((pRez->Privileges[i].Attributes & SE_PRIVILEGE_REMOVED) == SE_PRIVILEGE_REMOVED)
            //{
            //    wcout << L"SE_PRIVILEGE_REMOVED" << endl;
            //    stPrTmp.bRemoved = true;
            //}
            //else
            //{
            //    stPrTmp.bRemoved = false;
            //}

            vwPrivileges->push_back(stPrTmp);
        }

        delete[] pRez;

        //vv privileges fix
        vector<stPriv>::iterator iter = unique((*vwPrivileges).begin(), (*vwPrivileges).end());
        (*vwPrivileges).erase(iter, (*vwPrivileges).end());
        //^^ privileges fix

        return 0;
    }
}

int ProcessExplorer::GetACL(vector<stACE> *vACEs, const char *chDirName)
{
    if (chDirName == NULL)
    {
        SetLastError(ERROR_INVALID_NAME);
        return ERROR_INVALID_NAME;
    }

    PSECURITY_DESCRIPTOR lpSd = NULL; // указатель на SD

    PACL lpDacl = NULL;               // указатель на список управления доступом
    BOOL bDaclPresent;                // признак присутствия списка DACL
    BOOL bDaclDefaulted;              // признак списка DACL по умолчанию

    void *lpAce = NULL;               // указатель на элемент списка
    LPWSTR StringSid;                 // указатель на строку SID

    DWORD dwLength;                   // длина дескриптора безопасности
    DWORD dwRetCode;                  // код возврата

    // получаем длину дескриптора безопасности
    if (!GetFileSecurity(
        chDirName,                    // имя файла
        DACL_SECURITY_INFORMATION,    // получаем DACL
        lpSd,                         // адрес дескриптора безопасности
        0,                            // определяем длину буфера
        &dwLength))                   // адрес для требуемой длины
    {
        dwRetCode = GetLastError();

        if (dwRetCode != ERROR_INSUFFICIENT_BUFFER)
        {
            // выходим из программы
            return dwRetCode;
        }
    }

    // распределяем память для дескриптора безопасности
    lpSd = (PSECURITY_DESCRIPTOR) new char[dwLength];

    // читаем дескриптор безопасности
    if (!GetFileSecurity(
        chDirName,                   // имя файла
        DACL_SECURITY_INFORMATION,   // получаем DACL
        lpSd,                        // адрес дескриптора безопасности
        dwLength,                    // длину буфера
        &dwLength))                  // адрес для требуемой длины
    {
        dwRetCode = GetLastError();
        return dwRetCode;
    }

    // получаем список DACL из дескриптора безопасности
    if (!GetSecurityDescriptorDacl(
        lpSd,              // адрес дескриптора безопасности
        &bDaclPresent,     // признак присутствия списка DACL
        &lpDacl,           // адрес указателя на DACL
        &bDaclDefaulted))  // признак списка DACL по умолчанию
    {
        dwRetCode = GetLastError();
        return dwRetCode;
    }

    // проверяем, есть ли DACL
    if (!bDaclPresent)
    {
        return 0;
    }

    // печатаем количество элементов
    //printf("Ace count: %u\n", lpDacl->AceCount);

    stACE tmp;

    // получаем элементы списка DACL
    for (unsigned i = 0; i < lpDacl->AceCount; ++i)
    {
        if (!GetAce(
            lpDacl,  // адрес DACL
            i,       // индекс элемента
            &lpAce)) // указатель на элемент списка
        {
            //dwRetCode = GetLastError();
            //return dwRetCode;
            continue;
        }
       
        // преобразуем SID в строку
        if (!ConvertSidToStringSidW(&((ACCESS_ALLOWED_ACE *)lpAce)->SidStart, &StringSid))
        {
            //dwRetCode = GetLastError();
            //return dwRetCode;
            wcscpy_s(tmp.wSID, L"-");
        }
        else
        {
            //printf("%s\n", StringSid);
            wcscpy_s(tmp.wSID, StringSid);
        }
        LocalFree(StringSid);

        // ACE type
        tmp.iAceType = (int)((ACE_HEADER *)lpAce)->AceType;

        // ACE flags
        memset(&tmp.stFlags, 0, sizeof(stAceFlags));
        if      (((ACE_HEADER *)lpAce)->AceFlags == CONTAINER_INHERIT_ACE)
        {
            tmp.stFlags.ContainerInheritAce = 1;
        }
        else if (((ACE_HEADER *)lpAce)->AceFlags == FAILED_ACCESS_ACE_FLAG)
        {
            tmp.stFlags.FailedAccessAce = 1;
        }
        else if (((ACE_HEADER *)lpAce)->AceFlags == INHERIT_ONLY_ACE)
        {
            tmp.stFlags.InheritOnlyAce = 1;
        }
        else if (((ACE_HEADER *)lpAce)->AceFlags == INHERITED_ACE)
        {
            tmp.stFlags.InheritedAce = 1;
        }
        else if (((ACE_HEADER *)lpAce)->AceFlags == NO_PROPAGATE_INHERIT_ACE)
        {
            tmp.stFlags.NoPropagateInheritAce = 1;
        }
        else if (((ACE_HEADER *)lpAce)->AceFlags == OBJECT_INHERIT_ACE)
        {
            tmp.stFlags.ObjectInheritAce = 1;
        }
        else if (((ACE_HEADER *)lpAce)->AceFlags == SUCCESSFUL_ACCESS_ACE_FLAG)
        {
            tmp.stFlags.SuccessfulAccessAceFlag = 1;
        }

        vACEs->push_back(tmp);
    }

    // освобождаем память
    delete[] lpSd;

    return 0;
}

int ProcessExplorer::GetThreads(vector<sThread> *vsThThreads)
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

    sThread tmp;
    int i = 0;
    do // Walk the snapshot of processes
    {
        (*vsThThreads).push_back(tmp);

        (*vsThThreads)[i].uiPID = processEntry.th32ProcessID;             //PROCESSENTRY32
        wcscpy_s((*vsThThreads)[i].wName, processEntry.szExeFile);        //PROCESSENTRY32
        (*vsThThreads)[i].uiParentPID = processEntry.th32ParentProcessID; //PROCESSENTRY32

        moduleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processEntry.th32ProcessID);
        if (!Module32FirstW(moduleSnapshot, &moduleEntry))             //MODULEENTRY32
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

    HANDLE hProcess;
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

        if (!OpenProcessToken(hProcess, TOKEN_QUERY, &tok))
        {
            (*vsThThreads)[i].iIntegrityLevel = -1; // <- integrity level

            wcscpy_s((*vsThThreads)[i].wParentUserSID, L"-");
            wcscpy_s((*vsThThreads)[i].wParentUserName, L"-");
            continue;
        }

        (*vsThThreads)[i].iIntegrityLevel = GetIntegrityLevel(tok);         // <- integrity level

        GetPrivileges(tok, pszServerName, &(*vsThThreads)[i].vwPrivileges); // <- privileges

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

    return 0;
}
