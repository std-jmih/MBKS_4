#include "ProcessExplorer.h"
#include <Windows.h>
#include <iostream>
#include <psapi.h>
#include <tlhelp32.h>

using namespace std;

int main()
{
    ProcessExplorer *Class = new ProcessExplorer;
    Class->GetThreads();
    int N = (int)Class->vsThThreads.size();
    for (int i = 0; i < N; i++)
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
            L"Integrity level:\t"  <<   Class->vsThThreads[i].iIntegrityLevel            << endl <<
            L"DEP:\t\t\t"          <<   Class->vsThThreads[i].iDEP                       << endl <<
            L"ASLR: (-1 - error, 0 - disabled, 1 - enabled)"                                                          << endl <<
                L"\tBottom-up ASLR:                        "   << Class->vsThThreads[i].iEnableBottomUpRandomization << endl <<
                L"\tForced ASLR:                           "   << Class->vsThThreads[i].iEnableForceRelocateImages   << endl <<
                L"\tHigh enthropy:                         "   << Class->vsThThreads[i].iEnableHighEntropy           << endl <<
                L"\tForced ASLR with Required Relocations: "   << Class->vsThThreads[i].iDisallowStrippedImages      << endl;
        wcout << L"DLLs:" << endl;
        for (int k = 0; k < Class->vsThThreads[i].vwDLL.size(); k++)
        {
            wcout << L"\t" << Class->vsThThreads[i].vwDLL[k] << endl;
        }
        wcout << L"Privileges:" << endl;
        for (int k = 0; k < Class->vsThThreads[i].vwPrivileges.size(); k++)
        {
            if (Class->vsThThreads[i].vwPrivileges[k].bEnabled          ||
                Class->vsThThreads[i].vwPrivileges[k].bEnabledByDefault ||
                Class->vsThThreads[i].vwPrivileges[k].bUsedForAccess)
            {
                wcout << Class->vsThThreads[i].vwPrivileges[k].wName << endl << L"\t";
                if (Class->vsThThreads[i].vwPrivileges[k].bEnabled)
                {
                    wcout << L"Enabled  ";
                }
                if (Class->vsThThreads[i].vwPrivileges[k].bEnabledByDefault)
                {
                    wcout << L"EnabledByDefault  ";
                }
                if (Class->vsThThreads[i].vwPrivileges[k].bUsedForAccess)
                {
                    wcout << L"UsedForAccess  ";
                }
                wcout << endl;
            }
        }
        wcout << endl << endl;

        system("pause");
    }
    delete Class;
    system("pause");
    return 0;
}