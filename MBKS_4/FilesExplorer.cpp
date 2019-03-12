// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: http://www.viva64.com

#include "FilesExplorer.h"
#include <sddl.h>
#include "accctrl.h"
#include "aclapi.h"
#include <lm.h>
#include <ntsecapi.h> 

#pragma comment(lib, "netapi32.lib")

FilesExplorer::FilesExplorer()
{
    if (!GetUsers(&vUsers))
    {
        SetLastError(ERROR_ACCESS_DENIED);
    }
}

FilesExplorer::~FilesExplorer()
{
    vUsers.clear();
}

bool FilesExplorer::SetPrivileges(HANDLE hCurrentProcess)
{
    HANDLE hTok = 0;

    // memory
    PTOKEN_PRIVILEGES pPriv = (PTOKEN_PRIVILEGES)malloc(offsetof(TOKEN_PRIVILEGES, Privileges) + 2 * sizeof(LUID_AND_ATTRIBUTES));
    if (pPriv == NULL)
    {
        return false;
    }

    // fill in buffer
    pPriv->PrivilegeCount = 2;
    pPriv->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    pPriv->Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValueW(NULL, L"SeTakeOwnershipPrivilege", &pPriv->Privileges[0].Luid))
    {
        return false;
    }
    if (!LookupPrivilegeValueW(NULL, L"SeRestorePrivilege", &pPriv->Privileges[1].Luid))
    {
        return false;
    }

    if (!OpenProcessToken(hCurrentProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hTok))
    {
        return false;
    }

    // change priv
    if (!AdjustTokenPrivileges(hTok, FALSE, pPriv, 0, NULL, NULL))
    {
        return false;
    }
    
    return true;
}

PSID FilesExplorer::GetSid(LPWSTR wUsername)
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
            lpSID = (SID *)malloc((size_t)dwLengthOfSID);
            lpDomainName = (LPWSTR)malloc((size_t)dwLengthOfDomainName * sizeof(WCHAR));
        }
        else
        {
            printf("Lookup account name failed.\n");
            printf("Error code: %u\n", dwErrCode);
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
        printf("Error code: %u\n", dwErrCode);
    }

    free(lpDomainName);

    return lpSID;
}

int FilesExplorer::GetFileOwner(WCHAR *wUsername, WCHAR *wSID, const WCHAR *chDirName)
{
    DWORD dwRtnCode = 0;
    PSID pSidOwner = NULL;
    BOOL bRtnBool = TRUE;
    WCHAR AcctName[MAX_COMPUTERNAME_LENGTH_MY];
    DWORD dwAcctName = MAX_COMPUTERNAME_LENGTH_MY;
    SID_NAME_USE eUse = SidTypeUnknown;
    HANDLE hFile;
    PSECURITY_DESCRIPTOR pSD = NULL;

    DWORD  dwDomainName = MAX_COMPUTERNAME_LENGTH_MY;
    WCHAR  DomainName[MAX_COMPUTERNAME_LENGTH_MY];
    GetComputerNameW(DomainName, &dwDomainName);

    // Get the handle of the file object.
    hFile = CreateFileW(
        chDirName,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    // Check GetLastError for CreateFile error code.
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return GetLastError();
    }

    // Get the owner SID of the file.
    dwRtnCode = GetSecurityInfo(
        hFile,
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION,
        &pSidOwner,
        NULL,
        NULL,
        NULL,
        &pSD);

    // Check GetLastError for GetSecurityInfo error condition.
    if (dwRtnCode != ERROR_SUCCESS)
    {
        LocalFree(pSD);
        CloseHandle(hFile);
        return GetLastError();
    }

    // First call to LookupAccountSid to get the buffer sizes.
    bRtnBool = LookupAccountSidW(
        NULL,           // local computer
        pSidOwner,
        AcctName,
        (LPDWORD)&dwAcctName,
        DomainName,
        (LPDWORD)&dwDomainName,
        &eUse);

    // Second call to LookupAccountSid to get the account name.
    bRtnBool = LookupAccountSidW(
        NULL,                          // name of local or remote computer
        pSidOwner,                     // security identifier
        AcctName,                      // account name buffer
        (LPDWORD)&dwAcctName,          // size of account name buffer 
        DomainName,                    // domain name
        (LPDWORD)&dwDomainName,        // size of domain name buffer
        &eUse);                        // SID type

  // Check GetLastError for LookupAccountSid error condition.
    if (bRtnBool == FALSE)
    {
        LocalFree(pSD);
        CloseHandle(hFile);
        return GetLastError();
    }

    // Copy AcctName to wUsername
#pragma warning (disable: 4996)
    wcsncpy(wUsername, AcctName, (size_t)dwAcctName);
    wUsername[(size_t)dwAcctName] = L'\0';

    // Copy string SID to result buffer
    LPWSTR p = NULL;
    ConvertSidToStringSidW(pSidOwner, &p);
    wcscpy(wSID, p);

    LocalFree(p);
    LocalFree(pSD);
    CloseHandle(hFile);
    return ERROR_SUCCESS;
}

bool FilesExplorer::GetUsers(vector<stUser> *vectUsers)
{
    LPUSER_INFO_0 pBuf = NULL;
    LPUSER_INFO_0 pTmpBuf;
    LPUSER_INFO_4 pTmpBuf1;
    NET_API_STATUS nStatus;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD dwResumeHandle = 0;

    LPWSTR pSID = NULL;

    nStatus = NetUserEnum(
        NULL,
        0,
        FILTER_NORMAL_ACCOUNT,
        (LPBYTE *)&pBuf,
        MAX_PREFERRED_LENGTH,
        &dwEntriesRead,
        &dwTotalEntries,
        &dwResumeHandle);

    if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
    {
        pTmpBuf = pBuf;
        for (unsigned int i = 0; i < dwEntriesRead; i++)
        {
            stUser tmp;

            if (pTmpBuf == NULL)
            {
                printf("An access violation has occurred\n");
                return false;
            }

            NetUserGetInfo(
                NULL,
                pTmpBuf->usri0_name,
                4, //-V112
                (LPBYTE *)&pTmpBuf1);

            ConvertSidToStringSidW(pTmpBuf1->usri4_user_sid, &pSID);

            wcscpy(tmp.wSID, pSID);
            wcscpy(tmp.wUsername, pTmpBuf1->usri4_name);

            vUsers.push_back(tmp);

            pTmpBuf++;
        }
    }
    return true;
}

int FilesExplorer::GetACL(vector<stACE> *vACEs, const WCHAR *chDirName)
{
    if (chDirName == NULL)
    {
        SetLastError(ERROR_INVALID_NAME);
        return ERROR_INVALID_NAME;
    }

    vACEs->clear();

    PSECURITY_DESCRIPTOR lpSd = NULL; // ��������� �� SD

    PACL lpDacl = NULL;               // ��������� �� ������ ���������� ��������
    BOOL bDaclPresent;                // ������� ����������� ������ DACL
    BOOL bDaclDefaulted;              // ������� ������ DACL �� ���������

    void *lpAce = NULL;               // ��������� �� ������� ������
    LPWSTR StringSid;                 // ��������� �� ������ SID

    DWORD dwLength;                   // ����� ����������� ������������
    DWORD dwLengthAllocated;
    DWORD dwRetCode;                  // ��� ��������

    WCHAR wUser[512];
    DWORD dwUserLen;
    WCHAR wDomain[512];
    DWORD dwDomainLen;
    SID_NAME_USE eSidNameUse;
    DWORD dwStatus;

    // �������� ����� ����������� ������������
    if (!GetFileSecurityW(
        chDirName,                    // ��� �����
        DACL_SECURITY_INFORMATION,    // �������� DACL
        lpSd,                         // ����� ����������� ������������
        0,                            // ���������� ����� ������
        &dwLength))                   // ����� ��� ��������� �����
    {
        dwRetCode = GetLastError();

        if (dwRetCode != ERROR_INSUFFICIENT_BUFFER)
        {
            // ������� �� ���������
            return dwRetCode;
        }
    }

    // ������������ ������ ��� ����������� ������������
    lpSd = (PSECURITY_DESCRIPTOR) malloc((size_t)dwLength);
    dwLengthAllocated = dwLength;

    // ������ ���������� ������������
    if (!GetFileSecurityW(
        chDirName,                   // ��� �����
        DACL_SECURITY_INFORMATION,   // �������� DACL
        lpSd,                        // ����� ����������� ������������
        dwLength,                    // ����� ������
        &dwLength))                  // ����� ��� ��������� �����
    {
        dwRetCode = GetLastError();
        return dwRetCode;
    }

    // �������� ������ DACL �� ����������� ������������
    if (!GetSecurityDescriptorDacl(
        lpSd,              // ����� ����������� ������������
        &bDaclPresent,     // ������� ����������� ������ DACL
        &lpDacl,           // ����� ��������� �� DACL
        &bDaclDefaulted))  // ������� ������ DACL �� ���������
    {
        dwRetCode = GetLastError();
        return dwRetCode;
    }

    // ���������, ���� �� DACL
    if (!bDaclPresent)
    {
        return 0;
    }

    stACE tmp;

    // �������� �������� ������ DACL
    for (unsigned i = 0; i < lpDacl->AceCount; ++i)
    {
        if (!GetAce(
            lpDacl,  // ����� DACL
            i,       // ������ ��������
            &lpAce)) // ��������� �� ������� ������
        {
            continue;
        }

        dwUserLen = 0;

        // ����������� SID � ������
        if (!ConvertSidToStringSidW(&((ACCESS_ALLOWED_ACE *)lpAce)->SidStart, &StringSid))
        {
            wcscpy_s(tmp.wSID, L"-");
            wcscpy_s(tmp.wUsername, L"-");
        }
        else
        {
            wcscpy_s(tmp.wSID, StringSid);

            dwUserLen = 512;
            dwDomainLen = 512;
            if (LookupAccountSidW(
                NULL,
                &((ACCESS_ALLOWED_ACE *)lpAce)->SidStart,
                wUser,
                &dwUserLen,
                wDomain,
                &dwDomainLen,
                &eSidNameUse))
            {
                wcscpy_s(tmp.wUsername, wUser);
            }
            else
            {
                wcscpy_s(tmp.wUsername, L"-");
            }
        }
        LocalFree(StringSid);

        // ACE type
        tmp.iAceType = (int)((ACE_HEADER *)lpAce)->AceType;

        // ACE flags
        memset(&tmp.stFlags, 0, sizeof(stAceFlags));
        if (((ACE_HEADER *)lpAce)->AceFlags == CONTAINER_INHERIT_ACE)
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

    // ����������� ������
    free(lpSd);

    return 0;
}

int FilesExplorer::GetFileIntegrityLevel(LPCWSTR FileName)
{
    DWORD integrityLevel = SECURITY_MANDATORY_UNTRUSTED_RID;
    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL acl = 0;
    if (ERROR_SUCCESS == ::GetNamedSecurityInfoW(FileName, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, 0, 0, 0, &acl, &pSD))
    {
        if (0 != acl && 0 < acl->AceCount)
        {
            SYSTEM_MANDATORY_LABEL_ACE* ace = 0;
            if (::GetAce(acl, 0, reinterpret_cast<void**>(&ace)))
            {
                SID *sid = reinterpret_cast<SID *>(&ace->SidStart);
                integrityLevel = sid->SubAuthority[0];
            }
        }

        PWSTR stringSD;
        ULONG stringSDLen = 0;

        ConvertSecurityDescriptorToStringSecurityDescriptorW(pSD, SDDL_REVISION_1, LABEL_SECURITY_INFORMATION, &stringSD, &stringSDLen);

        if (pSD)
        {
            LocalFree(pSD);
        }
    }

    return integrityLevel;
}

bool FilesExplorer::SetFileIntegrityLevel(int level, LPCWSTR FileName)
{
    LPCWSTR INTEGRITY_SDDL_SACL_W = NULL;
    if (level == 0x0000)
    {
        INTEGRITY_SDDL_SACL_W = L""; // seems ok
    }
    else if (level == 0x1000)
    {
        INTEGRITY_SDDL_SACL_W = L"S:(ML;;NR;;;LW)";
    }
    else if (level == 0x2000)
    {
        INTEGRITY_SDDL_SACL_W = L"S:(ML;;NR;;;ME)";
    }
    else if (level == 0x3000)
    {
        INTEGRITY_SDDL_SACL_W = L"S:(ML;;NR;;;HI)";
    }

    DWORD dwErr = ERROR_SUCCESS;
    PSECURITY_DESCRIPTOR pSD = NULL;

    PACL pSacl          = NULL;
    BOOL fSaclPresent   = FALSE;
    BOOL fSaclDefaulted = FALSE;

    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(INTEGRITY_SDDL_SACL_W, SDDL_REVISION_1, &pSD, NULL))
    {
        if (GetSecurityDescriptorSacl(pSD, &fSaclPresent, &pSacl, &fSaclDefaulted))
        {
            dwErr = SetNamedSecurityInfoW(
                (LPWSTR)FileName,
                SE_FILE_OBJECT, 
                LABEL_SECURITY_INFORMATION,
                NULL, NULL, NULL, 
                pSacl);

            if (dwErr == ERROR_SUCCESS)
            {
                return true;
            }
        }
        LocalFree(pSD);
        return false;
    }
    return false;
}

int FilesExplorer::AddFileAcl(const WCHAR *wchDirName, const WCHAR *wchUserName, int iAceType, DWORD dAccessMask)
{
    ACL *lpOldDacl = NULL;             // ��������� �� ������ DACL
    ACL *lpNewDacl = NULL;             // ��������� �� ����� DACL
    LPVOID lpAce;                      // ��������� �� ������� ACE

    DWORD dwDaclLength         = 0;    // ����� DACL
    DWORD dwSdLength           = 0;    // ����� SD
    DWORD dwSidLength          = 0;    // ����� SID
    DWORD dwLengthOfDomainName = 0;    // ����� ����� ������

    PSID lpSid          = NULL;        // ��������� �� ����������� SID
    LPWSTR lpDomainName = NULL;        // ��������� �� ��� ������

    SID_NAME_USE typeOfSid;            // ��� ������� ������

    SECURITY_DESCRIPTOR *lpSd = NULL;  // ����� ����������� ������������
    SECURITY_DESCRIPTOR sdAbsoluteSd;  // ���������� ������ SD
    BOOL bDaclPresent;                 // ������� ����������� ������ DACL
    BOOL bDaclDefaulted;               // ������� ������ DACL �� ���������

    DWORD dwRetCode;                   // ��� ��������
    
    // �������� ����� ����������� ������������
    if (!GetFileSecurityW(
        wchDirName,                    // ��� �����
        DACL_SECURITY_INFORMATION,     // �������� DACL
        lpSd,                          // ����� ����������� ������������
        0,                             // ���������� ����� ������
        &dwSdLength))                  // ����� ��� ��������� �����
    {
        dwRetCode = GetLastError();

        if (dwRetCode == ERROR_INSUFFICIENT_BUFFER)
        {
            lpSd = (SECURITY_DESCRIPTOR *) malloc((size_t)dwSdLength); // ������������ ������ ��� ������
        }
        else
        {
            printf("Get file security failed.\n");
            printf("Error code: %u\n", dwRetCode);

            return dwRetCode;
        }
    }

    // ������ ���������� ������������
    if (!GetFileSecurityW(
        wchDirName,                  // ��� �����
        DACL_SECURITY_INFORMATION,   // �������� DACL
        lpSd,                        // ����� ����������� ������������
        dwSdLength,                  // ����� ������
        &dwSdLength))                // ����� ��� ��������� �����
    {
        dwRetCode = GetLastError();
        printf("Get file security failed.\n");
        printf("Error code: %u\n", dwRetCode);

        return dwRetCode;
    }

    // ���������� ����� SID ������������
    if (!LookupAccountNameW(
        NULL,                        // ���� ��� �� ��������� ����������
        wchUserName,                 // ��� ������������
        NULL,                        // ���������� ����� SID
        &dwSidLength,                // ����� SID
        NULL,                        // ���������� ��� ������
        &dwLengthOfDomainName,       // ����� ����� ������
        &typeOfSid))                 // ��� ������� ������
    {
        dwRetCode = GetLastError();

        if (dwRetCode == ERROR_INSUFFICIENT_BUFFER)
        {
            // ������������ ������ ��� SID
            lpSid        = (SID *)  malloc((size_t)dwSidLength);
            lpDomainName = (LPWSTR) malloc((size_t)dwLengthOfDomainName * sizeof(WCHAR));
        }
        else
        {
            // ������� �� ���������
            printf("Lookup account name failed.\n");
            printf("Error code: %u\n", dwRetCode);

            return dwRetCode;
        }
    }

    // ���������� SID
    if (!LookupAccountNameW(
        NULL,                        // ���� ��� �� ��������� ����������
        wchUserName,                 // ��� ������������
        lpSid,                       // ��������� �� SID
        &dwSidLength,                // ����� SID
        lpDomainName,                // ��������� �� ��� ������
        &dwLengthOfDomainName,       // ����� ����� ������
        &typeOfSid))                 // ��� ������� ������
    {
        dwRetCode = GetLastError();

        printf("Lookup account name failed.\n");
        printf("Error code: %u\n", dwRetCode);

        return dwRetCode;
    }

    // �������� ������ DACL �� ����������� ������������
    if (!GetSecurityDescriptorDacl(
        lpSd,                        // ����� ����������� ������������
        &bDaclPresent,               // ������� ����������� ������ DACL
        &lpOldDacl,                  // ����� ��������� �� DACL
        &bDaclDefaulted))            // ������� ������ DACL �� ���������
    {
        dwRetCode = GetLastError();
        printf("Get security descriptor DACL failed.\n");
        printf("Error code: %u\n", dwRetCode);

        return dwRetCode;
    }

    // ���������� ����� ������ DACL
    dwDaclLength = (DWORD)(lpOldDacl->AclSize + sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + (size_t)dwSidLength);

    // ������������ ������ ��� ����� DACL
    lpNewDacl = (ACL *)malloc((size_t)dwDaclLength);
    if (lpNewDacl == NULL)
    {
        return -1;
    }

    // �������������� ����� DACL
    if (!InitializeAcl(
        lpNewDacl,                   // ����� DACL
        dwDaclLength,                // ����� DACL
        ACL_REVISION))               // ������ DACL
    {
        dwRetCode = GetLastError();

        printf("Lookup account name failed.\n");
        printf("Error code: %u\n", dwRetCode);

        return dwRetCode;
    }

    // ��������� ����� ������� � ����� DACL
    bool bStatus = false;
    switch (iAceType)
    {
    case ACCESS_ALLOWED_ACE_TYPE:
    {
        bStatus = AddAccessDeniedAce(
            lpNewDacl,                   // ����� DACL
            ACL_REVISION,                // ������ DACL
            dAccessMask,                 // access mask
            lpSid);                      // ����� SID
        break;
    }
    case ACCESS_DENIED_ACE_TYPE:
    {
        bStatus = AddAccessDeniedAce(
            lpNewDacl,                   // ����� DACL
            ACL_REVISION,                // ������ DACL
            dAccessMask,                 // access mask
            lpSid);                      // ����� SID
        break;
    }
    default:
    {
        return -1;
    }
    }

    if (!bStatus)
    {
        dwRetCode = GetLastError();
        perror("Add ace failed.\n");
        printf("The last error code: %u\n", dwRetCode);

        return dwRetCode;
    }


    // �������� ����� ������� ACE � ������ ������ DACL
    if (!GetAce(
        lpOldDacl,                   // ����� ������� DACL
        0,                           // ���� ������ �������
        &lpAce))                     // ����� ������� ��������
    {
        dwRetCode = GetLastError();

        printf("Get ace failed.\n");
        printf("Error code: %u\n", dwRetCode);

        return dwRetCode;
    }

    // ������������ �������� �� ������� DACL � ����� DACL
    if (bDaclPresent)
    {
        if (!AddAce(
            lpNewDacl,                                   // ����� ������ DACL
            ACL_REVISION,                                // ������ DACL
            MAXDWORD,                                    // ��������� � ����� ������
            lpAce,                                       // ����� ������� DACL
            (DWORD)(lpOldDacl->AclSize - sizeof(ACL))))  // ����� ������� DACL
        {
            dwRetCode = GetLastError();
            perror("Add access allowed ace failed.\n");
            printf("The last error code: %u\n", dwRetCode);

            return dwRetCode;
        }
    }

    // ��������� ������������� DACL
    if (!IsValidAcl(lpNewDacl))
    {
        dwRetCode = GetLastError();
        perror("The new ACL is invalid.\n");
        printf("The last error code: %u\n", dwRetCode);

        return dwRetCode;
    }

    // ������� ����� ���������� ������������ � ���������� �����
    if (!InitializeSecurityDescriptor(
        &sdAbsoluteSd,       // ����� ��������� SD
        SECURITY_DESCRIPTOR_REVISION))
    {
        dwRetCode = GetLastError();
        perror("Initialize security descriptor failed.\n");
        printf("The last error code: %u\n", dwRetCode);

        return dwRetCode;
    }

    // ������������� DACL  � ����� ���������� ������������
    if (!SetSecurityDescriptorDacl(
        &sdAbsoluteSd,   // ����� ����������� ������������
        TRUE,            // DACL ������������
        lpNewDacl,       // ��������� �� DACL
        FALSE))          // DACL �� ����� �� ���������
    {
        dwRetCode = GetLastError();
        perror("Set security descriptor DACL failed.\n");
        printf("The last error code: %u\n", dwRetCode);

        return dwRetCode;
    }

    // ��������� ��������� ����������� ������������
    if (!IsValidSecurityDescriptor(&sdAbsoluteSd))
    {
        dwRetCode = GetLastError();
        perror("Security descriptor is invalid.\n");
        printf("The last error code: %u\n", dwRetCode);

        return dwRetCode;
    }
    // ������������� ����� ���������� ������������
    if (!SetFileSecurityW(
        wchDirName,                    // ��� �����
        DACL_SECURITY_INFORMATION,     // ������������� DACL
        &sdAbsoluteSd))                // ����� ����������� ������������
    {
        dwRetCode = GetLastError();
        printf("Set file security failed.\n");
        printf("Error code: %u\n", dwRetCode);

        return dwRetCode;
    }

    // ����������� ������
    free(lpSd);
    free(lpSid);
    free(lpDomainName);
    free(lpNewDacl);

    return 0;
}

bool FilesExplorer::DelFileAcl(const WCHAR *wchDirName, const WCHAR *wchUserName, int iAceType)
{
    PSECURITY_DESCRIPTOR lpSd = NULL;  // ��������� �� SD

    PACL lpDacl = NULL;    // ��������� �� ������ ���������� ��������
    BOOL bDaclPresent;     // ������� ����������� ������ DACL
    BOOL bDaclDefaulted;   // ������� ������ DACL �� ���������

    void *lpAce = NULL;    // ��������� �� ������� ������

    DWORD dwLength;        // ����� ����������� ������������
    DWORD dwRetCode;       // ��� ��������

    // �������� ����� ����������� ������������
    if (!GetFileSecurityW(
        wchDirName,                  // ��� �����
        DACL_SECURITY_INFORMATION,   // �������� DACL
        lpSd,                        // ����� ����������� ������������
        0,                           // ���������� ����� ������
        &dwLength))                  // ����� ��� ��������� �����
    {
        dwRetCode = GetLastError();

        if (dwRetCode != ERROR_INSUFFICIENT_BUFFER)
        {
            // ������� �� ���������
            printf("Get file security failed.\n");
            printf("Error code: %u\n", dwRetCode);

            return dwRetCode;
        }
    }

    // ������������ ������ ��� ����������� ������������
    lpSd = (PSECURITY_DESCRIPTOR)malloc((size_t)dwLength * sizeof(WCHAR));

    // ������ ���������� ������������
    if (!GetFileSecurityW(
        wchDirName,                  // ��� �����
        DACL_SECURITY_INFORMATION,   // �������� DACL
        lpSd,                        // ����� ����������� ������������
        dwLength,                    // ����� ������
        &dwLength))                  // ����� ��� ��������� �����
    {
        dwRetCode = GetLastError();
        printf("Get file security failed.\n");
        printf("Error code: %u\n", dwRetCode);

        return dwRetCode;
    }

    // �������� ������ DACL �� ����������� ������������
    if (!GetSecurityDescriptorDacl(
        lpSd,              // ����� ����������� ������������
        &bDaclPresent,     // ������� ����������� ������ DACL
        &lpDacl,           // ����� ��������� �� DACL
        &bDaclDefaulted))  // ������� ������ DACL �� ���������
    {
        dwRetCode = GetLastError();
        printf("Get security descriptor DACL failed.\n");
        printf("Error code: %u\n", dwRetCode);

        return dwRetCode;
    }

    // ���������, ���� �� DACL
    if (!bDaclPresent)
    {
        printf("Dacl is not present.");

        return 0;
    }

    // ������� �������� ������ DACL
    for (unsigned i = 0; i < lpDacl->AceCount; ++i)
    {
        // �������� ������� ������ DACL
        if (!GetAce(
            lpDacl,    // ����� DACL
            i,         // ������ ��������
            &lpAce))   // ��������� �� ������� ������
        {
            dwRetCode = GetLastError();
            printf("Get ace failed.\n");
            printf("Error code: %u\n", dwRetCode);

            return dwRetCode;
        }
        // ��������� ��� ��������
        if (((ACE_HEADER *)lpAce)->AceType == iAceType)
        {
            // ������� ������� �� ������ DACL
            if (!DeleteAce(lpDacl, i))
            {
                dwRetCode = GetLastError();
                printf("Delete ace failed.\n");
                printf("Error code: %u\n", dwRetCode);

                return dwRetCode;
            }
        }
    }
    // ������������� ����� ���������� ������������
    if (!SetFileSecurityW(
        wchDirName,                   // ��� �����
        DACL_SECURITY_INFORMATION,   // ������������� DACL
        lpSd))                       // ����� ����������� ������������
    {
        dwRetCode = GetLastError();
        printf("Set file security failed.\n");
        printf("Error code: %u\n", dwRetCode);

        return dwRetCode;
    }

    // ����������� ������
    free(lpSd);

    return 0;
}

int FilesExplorer::SetFileOwner(WCHAR *wUsername, WCHAR *chDirName)
{
    PSID pSid = NULL;

    pSid = GetSid(wUsername);
    if (pSid == NULL)
    {
        return -1;
    }
    
    HANDLE hCurrentProc = GetCurrentProcess();
    if (!SetPrivileges(hCurrentProc))
    {
        free(pSid);
        return -1;
    }

    DWORD status = SetNamedSecurityInfoW(
        chDirName,
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION,
        pSid,
        NULL,
        NULL,
        NULL);
    if(status != ERROR_SUCCESS)
    {
        free(pSid);
        return -1;
    }

    free(pSid);
    return 0;
}
