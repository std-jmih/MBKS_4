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
