#include "FilesExplorer.h"
#include <sddl.h>
#include "accctrl.h"
#include "aclapi.h"

FilesExplorer::FilesExplorer()
{
}

FilesExplorer::~FilesExplorer()
{
}

bool FilesExplorer::SetPrivileges(HANDLE hCurrentProcess)
{
    HANDLE hTok = 0;

    size_t sz = sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES);

    // memory
    PTOKEN_PRIVILEGES pPriv = (PTOKEN_PRIVILEGES)_alloca(sz);

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

int FilesExplorer::GetFileOwner(WCHAR *wUsername, WCHAR *wSID, const WCHAR *chDirName)
{
    DWORD dwRtnCode = 0;
    PSID pSidOwner;
    BOOL bRtnBool = TRUE;
    WCHAR AcctName[MAX_COMPUTERNAME_LENGTH];
    DWORD dwAcctName = MAX_COMPUTERNAME_LENGTH;
    SID_NAME_USE eUse = SidTypeUnknown;
    HANDLE hFile;
    PSECURITY_DESCRIPTOR pSD;

    DWORD  dwDomainName = MAX_COMPUTERNAME_LENGTH;
    WCHAR  DomainName[MAX_COMPUTERNAME_LENGTH];
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

    // Allocate memory for the SID structure.
    pSidOwner = (PSID)GlobalAlloc(GMEM_FIXED, sizeof(PSID));

    // Allocate memory for the security descriptor structure.
    pSD = (PSECURITY_DESCRIPTOR)GlobalAlloc(GMEM_FIXED, sizeof(PSECURITY_DESCRIPTOR));

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
        CloseHandle(hFile);
        return GetLastError();
    }

    // Copy AcctName to wUsername
#pragma warning (disable: 4996)
    wcsncpy(wUsername, AcctName, dwAcctName);
    wUsername[dwAcctName] = L'\0';

    // Copy string SID to result buffer
    LPWSTR p = NULL;
    ConvertSidToStringSidW(pSidOwner, &p);
    wcscpy(wSID, p);
    LocalFree(p);

    CloseHandle(hFile);
    return ERROR_SUCCESS;
}

int FilesExplorer::GetACL(vector<stACE> *vACEs, const WCHAR *chDirName)
{
    if (chDirName == NULL)
    {
        SetLastError(ERROR_INVALID_NAME);
        return ERROR_INVALID_NAME;
    }

    PSECURITY_DESCRIPTOR lpSd = NULL; // ��������� �� SD

    PACL lpDacl = NULL;               // ��������� �� ������ ���������� ��������
    BOOL bDaclPresent;                // ������� ����������� ������ DACL
    BOOL bDaclDefaulted;              // ������� ������ DACL �� ���������

    void *lpAce = NULL;               // ��������� �� ������� ������
    LPWSTR StringSid;                 // ��������� �� ������ SID

    DWORD dwLength;                   // ����� ����������� ������������
    DWORD dwRetCode;                  // ��� ��������

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
    lpSd = (PSECURITY_DESCRIPTOR) new char[dwLength];

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

    // �������� ���������� ���������
    //printf("Ace count: %u\n", lpDacl->AceCount);

    stACE tmp;

    // �������� �������� ������ DACL
    for (unsigned i = 0; i < lpDacl->AceCount; ++i)
    {
        if (!GetAce(
            lpDacl,  // ����� DACL
            i,       // ������ ��������
            &lpAce)) // ��������� �� ������� ������
        {
            //dwRetCode = GetLastError();
            //return dwRetCode;
            continue;
        }

        // ����������� SID � ������
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
    delete[] lpSd;

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

bool FilesExplorer::AddFileAcl(const WCHAR *wchDirName, const WCHAR *wchUserName, int iAceType, DWORD dAccessMask)
{
    ACL *lpOldDacl;                    // ��������� �� ������ DACL
    ACL *lpNewDacl;                    // ��������� �� ����� DACL
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
            lpSd = (SECURITY_DESCRIPTOR *) new char[dwSdLength]; // ������������ ������ ��� ������
        }
        else
        {
            printf("Get file security failed.\n");
            printf("Error code: %d\n", dwRetCode);

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
        printf("Error code: %d\n", dwRetCode);

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
            lpSid        = (SID *)  new char[dwSidLength];
            lpDomainName = (LPWSTR) new wchar_t[dwLengthOfDomainName];
        }
        else
        {
            // ������� �� ���������
            printf("Lookup account name failed.\n");
            printf("Error code: %d\n", dwRetCode);

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
        printf("Error code: %d\n", dwRetCode);

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
        printf("Error code: %d\n", dwRetCode);

        return dwRetCode;
    }

    // ���������� ����� ������ DACL
    dwDaclLength = lpOldDacl->AclSize + sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + dwSidLength;

    // ������������ ������ ��� ����� DACL
    lpNewDacl = (ACL *)new char[dwDaclLength];

    // �������������� ����� DACL
    if (!InitializeAcl(
        lpNewDacl,                   // ����� DACL
        dwDaclLength,                // ����� DACL
        ACL_REVISION))               // ������ DACL
    {
        dwRetCode = GetLastError();

        printf("Lookup account name failed.\n");
        printf("Error code: %d\n", dwRetCode);

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
        return false;
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
        printf("Error code: %d\n", dwRetCode);

        return dwRetCode;
    }

    // ������������ �������� �� ������� DACL � ����� DACL
    if (bDaclPresent)
    {
        if (!AddAce(
            lpNewDacl,                          // ����� ������ DACL
            ACL_REVISION,                       // ������ DACL
            MAXDWORD,                           // ��������� � ����� ������
            lpAce,                              // ����� ������� DACL
            lpOldDacl->AclSize - sizeof(ACL)))  // ����� ������� DACL
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
        printf("Error code: %d\n", dwRetCode);

        return dwRetCode;
    }

    // ����������� ������
    delete[] lpSd;
    delete[] lpSid;
    delete[] lpDomainName;
    delete[] lpNewDacl;

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

        if (dwRetCode == ERROR_INSUFFICIENT_BUFFER)
        {
            // ������������ ������ ��� ������
            lpSd = (SECURITY_DESCRIPTOR *) new WCHAR[dwLength];
        }
        else
        {
            // ������� �� ���������
            printf("Get file security failed.\n");
            printf("Error code: %d\n", dwRetCode);

            return dwRetCode;
        }
    }

    // ������������ ������ ��� ����������� ������������
    lpSd = (PSECURITY_DESCRIPTOR) new WCHAR[dwLength];

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
        printf("Error code: %d\n", dwRetCode);

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
        printf("Error code: %d\n", dwRetCode);

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
            printf("Error code: %d\n", dwRetCode);

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
                printf("Error code: %d\n", dwRetCode);

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
        printf("Error code: %d\n", dwRetCode);

        return dwRetCode;
    }

    // ����������� ������
    delete[] lpSd;

    return 0;
}

int FilesExplorer::SetFileOwner(WCHAR *wUsername, WCHAR *chDirName, WCHAR *wPassword)
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
        return -1;
    }

    return 0;
}
