#include "ProcessExplorer.h"
#include <Windows.h>
#include <iostream>
#include <psapi.h>
#include <tlhelp32.h>

using namespace std;

void main()
{
    ProcessExplorer *Class = new ProcessExplorer;
    Class->GetThreads();
    int N = Class->vsThThreads.size();
    for (int i = 0; i < N; i++)
    {
        if (Class->vsThThreads[i].wName[0] != 52428)
        {
            wcout << 
                L"Name:\t\t\t"         <<   Class->vsThThreads[i].wName                      << endl <<
                L"Type:\t\t\t"         << ((Class->vsThThreads[i].bType) ? L"32" : L"64")    << endl <<
                L"PID:\t\t\t"          <<   Class->vsThThreads[i].uiPID                      << endl <<
                L"Path:\t\t\t"         <<   Class->vsThThreads[i].wPath                      << endl <<
                L"Parent user name:\t" <<   Class->vsThThreads[i].wParentUserName            << endl <<
                L"Parent user SID:\t"  <<   Class->vsThThreads[i].wParentUserSID             << endl <<
                L"Parent proc name:\t" <<   Class->vsThThreads[i].wParentName                << endl <<
                L"Parent proc PID:\t"  <<   Class->vsThThreads[i].uiParentPID                << endl <<
                L"DEP:\t\t\t"          <<   Class->vsThThreads[i].iDEP                       << endl <<
                L"ASLR: (-1 - error, 0 - disabled, 1 - enabled)"                                                          << endl <<
                    L"\tBottom-up ASLR -                        "   << Class->vsThThreads[i].iEnableBottomUpRandomization << endl <<
                    L"\tForced ASLR -                           "   << Class->vsThThreads[i].iEnableForceRelocateImages   << endl <<
                    L"\tHigh enthropy -                         "   << Class->vsThThreads[i].iEnableHighEntropy           << endl <<
                    L"\tForced ASLR with Required Relocations - "   << Class->vsThThreads[i].iDisallowStrippedImages      << endl <<
                endl;
        }
    }
    while (1) {}
}