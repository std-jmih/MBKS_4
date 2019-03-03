#include "ProcessExplorer.h"
#include "FilesExplorer.h"
#include <Windows.h>
#include <iostream>
#include <psapi.h>
#include <tlhelp32.h>

using namespace std;

int main()
{
    ProcessExplorer *ClassProc = new ProcessExplorer;
    FilesExplorer   *ClassFile = new FilesExplorer;

    WCHAR wRez[512];
    ClassFile->GetFileOwner(wRez, L"C:\\Users\\Public\\Projects\\test.txt");
    wcout << wRez;
    //vector<stACE> vACL;
    //Class->GetACL(&vACL, "C:\\Recovery.txt");
    //system("pause");
    //vACL.clear();

    vector<sThread> vThreads;
    ClassProc->GetThreads(&vThreads);
    int N = (int)vThreads.size();
    for (int i = 0; i < N; i++)
    {
        wcout << 
            L"Name:\t\t\t"         <<   vThreads[i].wName                      << endl <<
            L"Type:\t\t\t"         << ((vThreads[i].bType) ? L"32" : L"64")    << endl <<
            L"PID:\t\t\t"          <<   vThreads[i].uiPID                      << endl <<
            L"Path:\t\t\t"         <<   vThreads[i].wPath                      << endl <<
            L"Parent user name:\t" <<   vThreads[i].wParentUserName            << endl <<
            L"Parent user SID:\t"  <<   vThreads[i].wParentUserSID             << endl <<
            L"Parent proc name:\t" <<   vThreads[i].wParentName                << endl <<
            L"Parent proc PID:\t"  <<   vThreads[i].uiParentPID                << endl <<
            L"Integrity level:\t"  <<   vThreads[i].iIntegrityLevel            << endl <<
            L"DEP:\t\t\t"          <<   vThreads[i].iDEP                       << endl <<
            L"ASLR: (-1 - error, 0 - disabled, 1 - enabled)"                                                          << endl <<
                L"\tBottom-up ASLR:                        "   << vThreads[i].iEnableBottomUpRandomization << endl <<
                L"\tForced ASLR:                           "   << vThreads[i].iEnableForceRelocateImages   << endl <<
                L"\tHigh enthropy:                         "   << vThreads[i].iEnableHighEntropy           << endl <<
                L"\tForced ASLR with Required Relocations: "   << vThreads[i].iDisallowStrippedImages      << endl;
        wcout << L"DLLs:" << endl;
        for (int k = 0; k < vThreads[i].vwDLL.size(); k++)
        {
            wcout << L"\t" << vThreads[i].vwDLL[k] << endl;
        }
        wcout << L"Privileges:" << endl;
        for (int k = 0; k < vThreads[i].vwPrivileges.size(); k++)
        {
            if (vThreads[i].vwPrivileges[k].bEnabled          ||
                vThreads[i].vwPrivileges[k].bEnabledByDefault ||
                vThreads[i].vwPrivileges[k].bUsedForAccess)
            {
                wcout << vThreads[i].vwPrivileges[k].wName << endl << L"\t";
                if (vThreads[i].vwPrivileges[k].bEnabled)
                {
                    wcout << L"Enabled  ";
                }
                if (vThreads[i].vwPrivileges[k].bEnabledByDefault)
                {
                    wcout << L"EnabledByDefault  ";
                }
                if (vThreads[i].vwPrivileges[k].bUsedForAccess)
                {
                    wcout << L"UsedForAccess  ";
                }
                wcout << endl;
            }
        }
        wcout << endl << endl;

        system("pause");
    }
    delete ClassProc;
    system("pause");
    return 0;
}