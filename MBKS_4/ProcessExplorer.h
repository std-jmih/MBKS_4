#pragma once
#include <string>
#include <vector>
#include <Windows.h>

using namespace std;

typedef struct sThread
{
    WCHAR           wName[MAX_PATH];        /// delo sdelano
	DWORD           uiPID;                  /// delo sdelano
    WCHAR           wPath[MAX_PATH];        /// delo sdelano
    WCHAR           wParentName[MAX_PATH];  /// delo sdelano
    DWORD           uiParentPID;            /// delo sdelano
    WCHAR           wParentSID[512];        //  opyat' rabota?
    bool            bType;                  /// delo sdelano // true - 32, false - 64
    bool            bDEP;                   //  opyat' rabota?
    bool            bASLR;                  //  opyat' rabota?
    vector<wstring> vwDLL;                  //  opyat' rabota?
};

class ProcessExplorer
{
public:
    ProcessExplorer();
    ~ProcessExplorer();

    int GetThreads();

    vector<sThread> vsThThreads;

};

