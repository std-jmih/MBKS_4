#pragma once
#include <string>
#include <vector>
#include <Windows.h>

#define MAX_COMPUTERNAME_LENGTH_MY 128

using namespace std;

struct stAceFlags
{
    BYTE ContainerInheritAce     : 1; // CONTAINER_INHERIT_ACE
    BYTE FailedAccessAce         : 1; // FAILED_ACCESS_ACE_FLAG
    BYTE InheritOnlyAce          : 1; // INHERIT_ONLY_ACE
    BYTE InheritedAce            : 1; // INHERITED_ACE
    BYTE NoPropagateInheritAce   : 1; // NO_PROPAGATE_INHERIT_ACE
    BYTE ObjectInheritAce        : 1; // OBJECT_INHERIT_ACE
    BYTE SuccessfulAccessAceFlag : 1; // SUCCESSFUL_ACCESS_ACE_FLAG
};

struct stACE
{
    // ACCESS_ALLOWED_ACE_TYPE                 | 0x0
    // ACCESS_MIN_MS_ACE_TYPE                  | 0x0
    // ACCESS_DENIED_ACE_TYPE                  | 0x1
    // SYSTEM_AUDIT_ACE_TYPE                   | 0x2
    // ACCESS_MAX_MS_V2_ACE_TYPE               | 0x3
    // SYSTEM_ALARM_ACE_TYPE                   | 0x3
    // ACCESS_MAX_MS_V3_ACE_TYPE               | 0x4
    // ACCESS_ALLOWED_COMPOUND_ACE_TYPE        | 0x4
    // ACCESS_ALLOWED_OBJECT_ACE_TYPE          | 0x5
    // ACCESS_MIN_MS_OBJECT_ACE_TYPE           | 0x5
    // ACCESS_DENIED_OBJECT_ACE_TYPE           | 0x6
    // SYSTEM_AUDIT_OBJECT_ACE_TYPE            | 0x7
    // ACCESS_MAX_MS_ACE_TYPE                  | 0x8
    // ACCESS_MAX_MS_V4_ACE_TYPE               | 0x8
    // ACCESS_MAX_MS_OBJECT_ACE_TYPE           | 0x8
    // SYSTEM_ALARM_OBJECT_ACE_TYPE            | 0x8
    // ACCESS_ALLOWED_CALLBACK_ACE_TYPE        | 0x9
    // ACCESS_DENIED_CALLBACK_ACE_TYPE         | 0xA
    // ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE | 0xB
    // ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE  | 0xC
    // SYSTEM_AUDIT_CALLBACK_ACE_TYPE          | 0xD
    // SYSTEM_ALARM_CALLBACK_ACE_TYPE          | 0xE
    // SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE   | 0xF
    // SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE   | 0x10
    // SYSTEM_MANDATORY_LABEL_ACE_TYPE         | 0x11
    int        iAceType;         // Specifies the ACE type. One value

    stAceFlags stFlags;          // Specifies a set of ACE type-specific control flags. Combination of values

    WCHAR      wSID[512];        // SID

    WCHAR      wUsername[512];   // Name
};

struct stUser
{
    WCHAR      wSID[512];        // SID

    WCHAR      wUsername[512];   // Name
};

class FilesExplorer
{
public:
    FilesExplorer();
    ~FilesExplorer();

    int  GetACL(vector<stACE> *vACEs, const WCHAR *chDirName);

    int  GetFileIntegrityLevel(LPCWSTR FileName);

    bool SetFileIntegrityLevel(int level, LPCWSTR FileName);

    int  AddFileAcl(const WCHAR *wchDirName, const WCHAR *wchUserName, int iAceType, DWORD dAccessMask); // wchUserName - user which will be added to acl

    bool DelFileAcl(const WCHAR *wchDirName, const WCHAR *wchUserName, int iAceType);

    int  SetFileOwner(WCHAR *wUsername, WCHAR *chDirName, WCHAR *wPassword);

    int  GetFileOwner(WCHAR *wUsername, WCHAR *wSID, const WCHAR *chDirName);

    vector<stUser> vUsers;

private:
    bool GetUsers(vector<stUser> *vectUsers);

    bool SetPrivileges(HANDLE hCurrentProcess);

    PSID GetSid(LPWSTR wUsername);
};

