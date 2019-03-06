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

    PSECURITY_DESCRIPTOR lpSd = NULL; // указатель на SD

    PACL lpDacl = NULL;               // указатель на список управления доступом
    BOOL bDaclPresent;                // признак присутствия списка DACL
    BOOL bDaclDefaulted;              // признак списка DACL по умолчанию

    void *lpAce = NULL;               // указатель на элемент списка
    LPWSTR StringSid;                 // указатель на строку SID

    DWORD dwLength;                   // длина дескриптора безопасности
    DWORD dwRetCode;                  // код возврата

    // получаем длину дескриптора безопасности
    if (!GetFileSecurityW(
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
    if (!GetFileSecurityW(
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

    // освобождаем память
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
    ACL *lpOldDacl;                    // указатель на старый DACL
    ACL *lpNewDacl;                    // указатель на новый DACL
    LPVOID lpAce;                      // указатель на элемент ACE

    DWORD dwDaclLength         = 0;    // длина DACL
    DWORD dwSdLength           = 0;    // длина SD
    DWORD dwSidLength          = 0;    // длина SID
    DWORD dwLengthOfDomainName = 0;    // длина имени домена

    PSID lpSid          = NULL;        // указатель на разрешающий SID
    LPWSTR lpDomainName = NULL;        // указатель на имя домена

    SID_NAME_USE typeOfSid;            // тип учетной записи

    SECURITY_DESCRIPTOR *lpSd = NULL;  // адрес дескриптора безопасности
    SECURITY_DESCRIPTOR sdAbsoluteSd;  // абсолютный формат SD
    BOOL bDaclPresent;                 // признак присутствия списка DACL
    BOOL bDaclDefaulted;               // признак списка DACL по умолчанию

    DWORD dwRetCode;                   // код возврата
    
    // получаем длину дескриптора безопасности
    if (!GetFileSecurityW(
        wchDirName,                    // имя файла
        DACL_SECURITY_INFORMATION,     // получаем DACL
        lpSd,                          // адрес дескриптора безопасности
        0,                             // определяем длину буфера
        &dwSdLength))                  // адрес для требуемой длины
    {
        dwRetCode = GetLastError();

        if (dwRetCode == ERROR_INSUFFICIENT_BUFFER)
        {
            lpSd = (SECURITY_DESCRIPTOR *) new char[dwSdLength]; // распределяем память для буфера
        }
        else
        {
            printf("Get file security failed.\n");
            printf("Error code: %d\n", dwRetCode);

            return dwRetCode;
        }
    }

    // читаем дескриптор безопасности
    if (!GetFileSecurityW(
        wchDirName,                  // имя файла
        DACL_SECURITY_INFORMATION,   // получаем DACL
        lpSd,                        // адрес дескриптора безопасности
        dwSdLength,                  // длину буфера
        &dwSdLength))                // адрес для требуемой длины
    {
        dwRetCode = GetLastError();
        printf("Get file security failed.\n");
        printf("Error code: %d\n", dwRetCode);

        return dwRetCode;
    }

    // определяем длину SID пользователя
    if (!LookupAccountNameW(
        NULL,                        // ищем имя на локальном компьютере
        wchUserName,                 // имя пользователя
        NULL,                        // определяем длину SID
        &dwSidLength,                // длина SID
        NULL,                        // определяем имя домена
        &dwLengthOfDomainName,       // длина имени домена
        &typeOfSid))                 // тип учетной записи
    {
        dwRetCode = GetLastError();

        if (dwRetCode == ERROR_INSUFFICIENT_BUFFER)
        {
            // распределяем память для SID
            lpSid        = (SID *)  new char[dwSidLength];
            lpDomainName = (LPWSTR) new wchar_t[dwLengthOfDomainName];
        }
        else
        {
            // выходим из программы
            printf("Lookup account name failed.\n");
            printf("Error code: %d\n", dwRetCode);

            return dwRetCode;
        }
    }

    // определяем SID
    if (!LookupAccountNameW(
        NULL,                        // ищем имя на локальном компьютере
        wchUserName,                 // имя пользователя
        lpSid,                       // указатель на SID
        &dwSidLength,                // длина SID
        lpDomainName,                // указатель на имя домена
        &dwLengthOfDomainName,       // длина имени домена
        &typeOfSid))                 // тип учетной записи
    {
        dwRetCode = GetLastError();

        printf("Lookup account name failed.\n");
        printf("Error code: %d\n", dwRetCode);

        return dwRetCode;
    }

    // получаем список DACL из дескриптора безопасности
    if (!GetSecurityDescriptorDacl(
        lpSd,                        // адрес дескриптора безопасности
        &bDaclPresent,               // признак присутствия списка DACL
        &lpOldDacl,                  // адрес указателя на DACL
        &bDaclDefaulted))            // признак списка DACL по умолчанию
    {
        dwRetCode = GetLastError();
        printf("Get security descriptor DACL failed.\n");
        printf("Error code: %d\n", dwRetCode);

        return dwRetCode;
    }

    // определяем длину нового DACL
    dwDaclLength = lpOldDacl->AclSize + sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + dwSidLength;

    // распределяем память под новый DACL
    lpNewDacl = (ACL *)new char[dwDaclLength];

    // инициализируем новый DACL
    if (!InitializeAcl(
        lpNewDacl,                   // адрес DACL
        dwDaclLength,                // длина DACL
        ACL_REVISION))               // версия DACL
    {
        dwRetCode = GetLastError();

        printf("Lookup account name failed.\n");
        printf("Error code: %d\n", dwRetCode);

        return dwRetCode;
    }

    // добавляем новый элемент в новый DACL
    bool bStatus = false;
    switch (iAceType)
    {
    case ACCESS_ALLOWED_ACE_TYPE:
    {
        bStatus = AddAccessDeniedAce(
            lpNewDacl,                   // адрес DACL
            ACL_REVISION,                // версия DACL
            dAccessMask,                 // access mask
            lpSid);                      // адрес SID
        break;
    }
    case ACCESS_DENIED_ACE_TYPE:
    {
        bStatus = AddAccessDeniedAce(
            lpNewDacl,                   // адрес DACL
            ACL_REVISION,                // версия DACL
            dAccessMask,                 // access mask
            lpSid);                      // адрес SID
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


    // получаем адрес первого ACE в старом списке DACL
    if (!GetAce(
        lpOldDacl,                   // адрес старого DACL
        0,                           // ищем первый элемент
        &lpAce))                     // адрес первого элемента
    {
        dwRetCode = GetLastError();

        printf("Get ace failed.\n");
        printf("Error code: %d\n", dwRetCode);

        return dwRetCode;
    }

    // переписываем элементы из старого DACL в новый DACL
    if (bDaclPresent)
    {
        if (!AddAce(
            lpNewDacl,                          // адрес нового DACL
            ACL_REVISION,                       // версия DACL
            MAXDWORD,                           // добавляем в конец списка
            lpAce,                              // адрес старого DACL
            lpOldDacl->AclSize - sizeof(ACL)))  // длина старого DACL
        {
            dwRetCode = GetLastError();
            perror("Add access allowed ace failed.\n");
            printf("The last error code: %u\n", dwRetCode);

            return dwRetCode;
        }
    }

    // проверяем достоверность DACL
    if (!IsValidAcl(lpNewDacl))
    {
        dwRetCode = GetLastError();
        perror("The new ACL is invalid.\n");
        printf("The last error code: %u\n", dwRetCode);

        return dwRetCode;
    }

    // создаем новый дескриптор безопасности в абсолютной форме
    if (!InitializeSecurityDescriptor(
        &sdAbsoluteSd,       // адрес структуры SD
        SECURITY_DESCRIPTOR_REVISION))
    {
        dwRetCode = GetLastError();
        perror("Initialize security descriptor failed.\n");
        printf("The last error code: %u\n", dwRetCode);

        return dwRetCode;
    }

    // устанавливаем DACL  в новый дескриптор безопасности
    if (!SetSecurityDescriptorDacl(
        &sdAbsoluteSd,   // адрес дескриптора безопасности
        TRUE,            // DACL присутствует
        lpNewDacl,       // указатель на DACL
        FALSE))          // DACL не задан по умолчанию
    {
        dwRetCode = GetLastError();
        perror("Set security descriptor DACL failed.\n");
        printf("The last error code: %u\n", dwRetCode);

        return dwRetCode;
    }

    // проверяем структуру дескриптора безопасности
    if (!IsValidSecurityDescriptor(&sdAbsoluteSd))
    {
        dwRetCode = GetLastError();
        perror("Security descriptor is invalid.\n");
        printf("The last error code: %u\n", dwRetCode);

        return dwRetCode;
    }
    // устанавливаем новый дескриптор безопасности
    if (!SetFileSecurityW(
        wchDirName,                    // имя файла
        DACL_SECURITY_INFORMATION,     // устанавливаем DACL
        &sdAbsoluteSd))                // адрес дескриптора безопасности
    {
        dwRetCode = GetLastError();
        printf("Set file security failed.\n");
        printf("Error code: %d\n", dwRetCode);

        return dwRetCode;
    }

    // освобождаем память
    delete[] lpSd;
    delete[] lpSid;
    delete[] lpDomainName;
    delete[] lpNewDacl;

    return 0;
}

bool FilesExplorer::DelFileAcl(const WCHAR *wchDirName, const WCHAR *wchUserName, int iAceType)
{
    PSECURITY_DESCRIPTOR lpSd = NULL;  // указатель на SD

    PACL lpDacl = NULL;    // указатель на список управления доступом
    BOOL bDaclPresent;     // признак присутствия списка DACL
    BOOL bDaclDefaulted;   // признак списка DACL по умолчанию

    void *lpAce = NULL;    // указатель на элемент списка

    DWORD dwLength;        // длина дескриптора безопасности
    DWORD dwRetCode;       // код возврата

    // получаем длину дескриптора безопасности
    if (!GetFileSecurityW(
        wchDirName,                  // имя файла
        DACL_SECURITY_INFORMATION,   // получаем DACL
        lpSd,                        // адрес дескриптора безопасности
        0,                           // определяем длину буфера
        &dwLength))                  // адрес для требуемой длины
    {
        dwRetCode = GetLastError();

        if (dwRetCode == ERROR_INSUFFICIENT_BUFFER)
        {
            // распределяем память для буфера
            lpSd = (SECURITY_DESCRIPTOR *) new WCHAR[dwLength];
        }
        else
        {
            // выходим из программы
            printf("Get file security failed.\n");
            printf("Error code: %d\n", dwRetCode);

            return dwRetCode;
        }
    }

    // распределяем память для дескриптора безопасности
    lpSd = (PSECURITY_DESCRIPTOR) new WCHAR[dwLength];

    // читаем дескриптор безопасности
    if (!GetFileSecurityW(
        wchDirName,                  // имя файла
        DACL_SECURITY_INFORMATION,   // получаем DACL
        lpSd,                        // адрес дескриптора безопасности
        dwLength,                    // длину буфера
        &dwLength))                  // адрес для требуемой длины
    {
        dwRetCode = GetLastError();
        printf("Get file security failed.\n");
        printf("Error code: %d\n", dwRetCode);

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
        printf("Get security descriptor DACL failed.\n");
        printf("Error code: %d\n", dwRetCode);

        return dwRetCode;
    }

    // проверяем, есть ли DACL
    if (!bDaclPresent)
    {
        printf("Dacl is not present.");

        return 0;
    }

    // удаляем элементы списка DACL
    for (unsigned i = 0; i < lpDacl->AceCount; ++i)
    {
        // получить элемент списка DACL
        if (!GetAce(
            lpDacl,    // адрес DACL
            i,         // индекс элемента
            &lpAce))   // указатель на элемент списка
        {
            dwRetCode = GetLastError();
            printf("Get ace failed.\n");
            printf("Error code: %d\n", dwRetCode);

            return dwRetCode;
        }
        // проверяем тип элемента
        if (((ACE_HEADER *)lpAce)->AceType == iAceType)
        {
            // удаляем элемент из списка DACL
            if (!DeleteAce(lpDacl, i))
            {
                dwRetCode = GetLastError();
                printf("Delete ace failed.\n");
                printf("Error code: %d\n", dwRetCode);

                return dwRetCode;
            }
        }
    }
    // устанавливаем новый дескриптор безопасности
    if (!SetFileSecurityW(
        wchDirName,                   // имя файла
        DACL_SECURITY_INFORMATION,   // устанавливаем DACL
        lpSd))                       // адрес дескриптора безопасности
    {
        dwRetCode = GetLastError();
        printf("Set file security failed.\n");
        printf("Error code: %d\n", dwRetCode);

        return dwRetCode;
    }

    // освобождаем память
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

/*
int FilesExplorer::SetFileOwner(WCHAR *wUsername, WCHAR *chDirName)
{
    BOOL bRetval = FALSE;

    HANDLE hToken = NULL;
    PSID pSIDAdmin = NULL;
    PSID pSIDEveryone = NULL;
    PACL pACL = NULL;
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
    const int NUM_ACES = 2;
    EXPLICIT_ACCESS ea[NUM_ACES];
    DWORD dwRes;

    // Specify the DACL to use.
    // Create a SID for the Everyone group.
    if (!AllocateAndInitializeSid(&SIDAuthWorld, 1,
        SECURITY_WORLD_RID,
        0,
        0, 0, 0, 0, 0, 0,
        &pSIDEveryone))
    {
        printf("AllocateAndInitializeSid (Everyone) error %u\n", GetLastError());
        if (pSIDAdmin)
        {
            FreeSid(pSIDAdmin);
        }
        if (pSIDEveryone)
        {
            FreeSid(pSIDEveryone);
        }
        if (pACL)
        {
            LocalFree(pACL);
        }
        if (hToken)
        {
            CloseHandle(hToken);
        }
        return bRetval;
    }

    // Create a SID for the BUILTIN\Administrators group.
    if (!AllocateAndInitializeSid(&SIDAuthNT, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &pSIDAdmin))
    {
        printf("AllocateAndInitializeSid (Admin) error %u\n", GetLastError());
        if (pSIDAdmin)
        {
            FreeSid(pSIDAdmin);
        }
        if (pSIDEveryone)
        {
            FreeSid(pSIDEveryone);
        }
        if (pACL)
        {
            LocalFree(pACL);
        }
        if (hToken)
        {
            CloseHandle(hToken);
        }
        return bRetval;
    }

    ZeroMemory(&ea, NUM_ACES * sizeof(EXPLICIT_ACCESS));

    // Set read access for Everyone.
    ea[0].grfAccessPermissions = GENERIC_READ;
    ea[0].grfAccessMode = SET_ACCESS;
    ea[0].grfInheritance = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].Trustee.ptstrName = (LPTSTR)pSIDEveryone;

    // Set full control for Administrators.
    ea[1].grfAccessPermissions = GENERIC_ALL;
    ea[1].grfAccessMode = SET_ACCESS;
    ea[1].grfInheritance = NO_INHERITANCE;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea[1].Trustee.ptstrName = (LPTSTR)pSIDAdmin;

    if (ERROR_SUCCESS != SetEntriesInAcl(NUM_ACES,
        ea,
        NULL,
        &pACL))
    {
        printf("Failed SetEntriesInAcl\n");
        if (pSIDAdmin)
        {
            FreeSid(pSIDAdmin);
        }
        if (pSIDEveryone)
        {
            FreeSid(pSIDEveryone);
        }
        if (pACL)
        {
            LocalFree(pACL);
        }
        if (hToken)
        {
            CloseHandle(hToken);
        }
        return bRetval;
    }

    // Try to modify the object's DACL.
    dwRes = SetNamedSecurityInfoW(
        chDirName,                   // name of the object
        SE_FILE_OBJECT,              // type of object
        DACL_SECURITY_INFORMATION,   // change only the object's DACL
        NULL, NULL,                  // do not change owner or group
        pACL,                        // DACL specified
        NULL);                       // do not change SACL

    if (ERROR_SUCCESS == dwRes)
    {
        printf("Successfully changed DACL\n");
        bRetval = TRUE;
        // No more processing needed.
        if (pSIDAdmin)
        {
            FreeSid(pSIDAdmin);
        }
        if (pSIDEveryone)
        {
            FreeSid(pSIDEveryone);
        }
        if (pACL)
        {
            LocalFree(pACL);
        }
        if (hToken)
        {
            CloseHandle(hToken);
        }
        return bRetval;
    }
    if (dwRes != ERROR_ACCESS_DENIED)
    {
        printf("First SetNamedSecurityInfo call failed: %u\n", dwRes);
        if (pSIDAdmin)
        {
            FreeSid(pSIDAdmin);
        }
        if (pSIDEveryone)
        {
            FreeSid(pSIDEveryone);
        }
        if (pACL)
        {
            LocalFree(pACL);
        }
        if (hToken)
        {
            CloseHandle(hToken);
        }
        return bRetval;
    }

    // If the preceding call failed because access was denied, 
    // enable the SE_TAKE_OWNERSHIP_NAME privilege, create a SID for 
    // the Administrators group, take ownership of the object, and 
    // disable the privilege. Then try again to set the object's DACL.

    // Open a handle to the access token for the calling process.
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES,
        &hToken))
    {
        printf("OpenProcessToken failed: %u\n", GetLastError());
        if (pSIDAdmin)
        {
            FreeSid(pSIDAdmin);
        }
        if (pSIDEveryone)
        {
            FreeSid(pSIDEveryone);
        }
        if (pACL)
        {
            LocalFree(pACL);
        }
        if (hToken)
        {
            CloseHandle(hToken);
        }
        return bRetval;
    }

    // Enable the SE_TAKE_OWNERSHIP_NAME privilege.
    if (!Set_SE_TAKE_OWNERSHIP_NAME(hToken))
    {
        printf("You must be logged on as Administrator.\n");
        if (pSIDAdmin)
        {
            FreeSid(pSIDAdmin);
        }
        if (pSIDEveryone)
        {
            FreeSid(pSIDEveryone);
        }
        if (pACL)
        {
            LocalFree(pACL);
        }
        if (hToken)
        {
            CloseHandle(hToken);
        }
        return bRetval;
    }

    // Set the owner in the object's security descriptor.
    dwRes = SetNamedSecurityInfoW(
        chDirName,                   // name of the object
        SE_FILE_OBJECT,              // type of object
        OWNER_SECURITY_INFORMATION,  // change only the object's owner
        pSIDAdmin,                   // SID of Administrator group
        NULL,
        NULL,
        NULL);

    if (dwRes != ERROR_SUCCESS)
    {
        printf("Could not set owner. Error: %u\n", dwRes);
        if (pSIDAdmin)
        {
            FreeSid(pSIDAdmin);
        }
        if (pSIDEveryone)
        {
            FreeSid(pSIDEveryone);
        }
        if (pACL)
        {
            LocalFree(pACL);
        }
        if (hToken)
        {
            CloseHandle(hToken);
        }
        return bRetval;
    }

    // Disable the SE_TAKE_OWNERSHIP_NAME privilege.
    if (!Set_SE_TAKE_OWNERSHIP_NAME(hToken))
    {
        printf("Failed SetPrivilege call unexpectedly.\n");
        if (pSIDAdmin)
        {
            FreeSid(pSIDAdmin);
        }
        if (pSIDEveryone)
        {
            FreeSid(pSIDEveryone);
        }
        if (pACL)
        {
            LocalFree(pACL);
        }
        if (hToken)
        {
            CloseHandle(hToken);
        }
        return bRetval;
    }

    // Try again to modify the object's DACL,
    // now that we are the owner.
    dwRes = SetNamedSecurityInfoW(
        chDirName,                   // name of the object
        SE_FILE_OBJECT,              // type of object
        DACL_SECURITY_INFORMATION,   // change only the object's DACL
        NULL, NULL,                  // do not change owner or group
        pACL,                        // DACL specified
        NULL);                       // do not change SACL

    if (dwRes == ERROR_SUCCESS)
    {
        printf("Successfully changed DACL\n");
        bRetval = TRUE;
    }
    else
    {
        printf("Second SetNamedSecurityInfo call failed: %u\n", dwRes);
    }

    if (pSIDAdmin)
    {
        FreeSid(pSIDAdmin);
    }
    if (pSIDEveryone)
    {
        FreeSid(pSIDEveryone);
    }
    if (pACL)
    {
        LocalFree(pACL);
    }
    if (hToken)
    {
        CloseHandle(hToken);
    }
    return bRetval;
}
*/

