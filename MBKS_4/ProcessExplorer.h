#pragma once
#include <string>
#include <vector>
#include <Windows.h>

using namespace std;

struct sThread
{
    WCHAR           wName[MAX_PATH];              // Process name
	DWORD           uiPID;                        // Process PID
    WCHAR           wPath[MAX_PATH];              // Path to executable file
    WCHAR           wParentName[MAX_PATH];        // Parent process name
    DWORD           uiParentPID;                  // Parent process PID
    WCHAR           wParentUserSID [512];         // Parent user's SID
    WCHAR           wParentUserName[512];         // Parent user's name
    bool            bType;                        // Type of process: true - 32, false - 64
    int             iDEP;                         // Is DEP enabled: -1 - error, 0 - no, 1 - yes
    vector<wstring> vwDLL;                        // DLLs used by process

    // ASLR flags: -1 - error, 0 - no, 1 - yes
    int             iEnableBottomUpRandomization; // Bottom-up ASLR
    int             iEnableForceRelocateImages;   // Forced ASLR
    int             iEnableHighEntropy;           // High enthropy
    int             iDisallowStrippedImages;      // Forced ASLR with Required Relocations
    
    // Integrity level:
    // 0x0000 Untrusted level        SECURITY_MANDATORY_UNTRUSTED_RID
    // 0x1000 Low integrity level    SECURITY_MANDATORY_LOW_RID
    // 0x2000 Medium integrity level SECURITY_MANDATORY_MEDIUM_RID
    // 0x3000 High integrity level   SECURITY_MANDATORY_HIGH_RID
    // 0x4000 System integrity level SECURITY_MANDATORY_SYSTEM_RID
    int             iIntegrityLevel;

    vector<wstring> vwPrivileges;                  // Process privileges
};

class ProcessExplorer
{
public:
    ProcessExplorer();
    ~ProcessExplorer();

    int GetThreads();

    vector<sThread> vsThThreads;

};

