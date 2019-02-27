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
                L"Name:\t\t"         << Class->vsThThreads[i].wName                     << endl <<
                L"Type:\t\t"         << ((Class->vsThThreads[i].bType) ? L"32" : L"64") << endl <<
                L"PID:\t\t"          << Class->vsThThreads[i].uiPID                     << endl <<
                L"Path:\t\t"         << Class->vsThThreads[i].wPath                     << endl <<
                L"Parent\'s name:\t" << Class->vsThThreads[i].wParentName               << endl <<
                L"Parent\'s PID:\t"  << Class->vsThThreads[i].uiParentPID               << endl <<
                endl;
        }
    }
    while (1) {}
}