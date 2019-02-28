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
                L"Name:\t\t\t"         << Class->vsThThreads[i].wName                     << endl <<
                L"Type:\t\t\t"         << ((Class->vsThThreads[i].bType) ? L"32" : L"64") << endl <<
                L"PID:\t\t\t"          << Class->vsThThreads[i].uiPID                     << endl <<
                L"Path:\t\t\t"         << Class->vsThThreads[i].wPath                     << endl <<
                L"Parent user name:\t" << Class->vsThThreads[i].wParentUserName           << endl <<
                L"Parent user SID:\t"  << Class->vsThThreads[i].wParentUserSID            << endl <<
                L"Parent proc name:\t" << Class->vsThThreads[i].wParentName               << endl <<
                L"Parent proc PID:\t"  << Class->vsThThreads[i].uiParentPID               << endl <<
                endl;
        }
    }
    while (1) {}
}