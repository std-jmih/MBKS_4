#pragma once
#include <string>
#include <vector>
#include <Windows.h>

using namespace std;

struct sThread
{
    WCHAR           wName[MAX_PATH];        /// delo sdelano
	DWORD           uiPID;                  /// delo sdelano
    WCHAR           wPath[MAX_PATH];        /// delo sdelano
    WCHAR           wParentName[MAX_PATH];  /// delo sdelano
    DWORD           uiParentPID;            /// delo sdelano
    WCHAR           wParentUserSID[512];    /// delo sdelano
    WCHAR           wParentUserName[512];   /// delo sdelano
    bool            bType;                  /// delo sdelano // true - 32, false - 64
    int             iDEP;                   /// delo sdelano // -1 - error, 0 - no, 1 - yes

    // ASLR flags: -1 - error, 0 - no, 1 - yes
    int iEnableBottomUpRandomization;
    int iEnableForceRelocateImages;
    int iEnableHighEntropy;
    int iDisallowStrippedImages;

    //PROCESS_MITIGATION_ASLR_POLICY stASLR; // temporary!!
    vector<wstring> vwDLL;                  //  opyat' rabota?
    //void           *dBaseAddress;
};

class ProcessExplorer
{
public:
    ProcessExplorer();
    ~ProcessExplorer();

    int GetThreads();

    vector<sThread> vsThThreads;

};

