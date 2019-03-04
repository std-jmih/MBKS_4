#include "ProcessExplorer.h"
#include "FilesExplorer.h"
#include <Windows.h>
#include <iostream>
#include <psapi.h>
#include <tlhelp32.h>

#include <sddl.h>
using namespace std;

int main()
{
    ProcessExplorer *ClassProc = new ProcessExplorer;
    FilesExplorer   *ClassFile = new FilesExplorer;

    //WCHAR wName[512];
    //WCHAR wSID[512];
    //ClassFile->GetFileOwner(wName, wSID, L"C:\\Users\\Public\\Projects\\test.txt");
    //wcout << wName << endl << wSID;


    vector<stACE> vACL;
    ClassFile->GetACL(&vACL, L"C:\\Users\\Public\\Projects\\test1.txt");
    for (int k = 0; k < vACL.size(); k++)
    {
        wcout << vACL[k].iAceType << endl;
        if (vACL[k].stFlags.ContainerInheritAce)
            wcout << L"ContainerInheritAce" << endl;
        if (vACL[k].stFlags.FailedAccessAce)
            wcout << L"FailedAccessAce" << endl;
        if (vACL[k].stFlags.InheritedAce)
            wcout << L"InheritedAce" << endl;
        if (vACL[k].stFlags.InheritOnlyAce)
            wcout << L"InheritOnlyAce" << endl;
        if (vACL[k].stFlags.NoPropagateInheritAce)
            wcout << L"NoPropagateInheritAce" << endl;
        if (vACL[k].stFlags.ObjectInheritAce)
            wcout << L"ObjectInheritAce" << endl;
        if (vACL[k].stFlags.SuccessfulAccessAceFlag)
            wcout << L"SuccessfulAccessAceFlag" << endl;
        wcout << vACL[k].wSID << endl << endl;
    }
    vACL.clear();

    ClassFile->AddFileAcl(L"C:\\Users\\Public\\Projects\\test1.txt", L"Аркадий", ACCESS_ALLOWED_ACE_TYPE, FILE_WRITE_ACCESS);

    ClassFile->GetACL(&vACL, L"C:\\Users\\Public\\Projects\\test1.txt");
    for (int k = 0; k < vACL.size(); k++)
    {
        wcout << vACL[k].iAceType << endl;
        if (vACL[k].stFlags.ContainerInheritAce)
            wcout << L"ContainerInheritAce" << endl;
        if (vACL[k].stFlags.FailedAccessAce)
            wcout << L"FailedAccessAce" << endl;
        if (vACL[k].stFlags.InheritedAce)
            wcout << L"InheritedAce" << endl;
        if (vACL[k].stFlags.InheritOnlyAce)
            wcout << L"InheritOnlyAce" << endl;
        if (vACL[k].stFlags.NoPropagateInheritAce)
            wcout << L"NoPropagateInheritAce" << endl;
        if (vACL[k].stFlags.ObjectInheritAce)
            wcout << L"ObjectInheritAce" << endl;
        if (vACL[k].stFlags.SuccessfulAccessAceFlag)
            wcout << L"SuccessfulAccessAceFlag" << endl;
        wcout << vACL[k].wSID << endl << endl;
    }
    vACL.clear();

    system("pause");


    //int a;
    //while (1)
    //{
    //    cout << ClassFile->GetFileIntegrityLevel(L"C:\\Users\\Public\\Projects\\test1.txt") << endl;
    //    cin >> a;
    //    cout << ((ClassFile->SetFileIntegrityLevel(a, L"C:\\Users\\Public\\Projects\\test1.txt")) ? "y" : "n") << endl;
    //}

    vector<sThread> vThreads;
    ClassProc->GetThreads(&vThreads);

    int N = (int)vThreads.size();
    for (int i = 130; i < N; i++)
    {
        wcout << i << endl <<
            L"Name:\t\t\t"         <<   vThreads[i].wName                      << endl <<
            //L"Type:\t\t\t"         << ((vThreads[i].bType) ? L"32" : L"64")    << endl <<
            //L"PID:\t\t\t"          <<   vThreads[i].uiPID                      << endl <<
            //L"Path:\t\t\t"         <<   vThreads[i].wPath                      << endl <<
            //L"Parent user name:\t" <<   vThreads[i].wParentUserName            << endl <<
            //L"Parent user SID:\t"  <<   vThreads[i].wParentUserSID             << endl <<
            //L"Parent proc name:\t" <<   vThreads[i].wParentName                << endl <<
            //L"Parent proc PID:\t"  <<   vThreads[i].uiParentPID                << endl <<
            //L"Integrity level:\t"  <<   vThreads[i].iIntegrityLevel            << endl <<
            //L"DEP:\t\t\t"          <<   vThreads[i].iDEP                       << endl <<
            //L"ASLR: (-1 - error, 0 - disabled, 1 - enabled)"                                               << endl <<
            //    L"\tBottom-up ASLR:                        "   << vThreads[i].iEnableBottomUpRandomization << endl <<
            //    L"\tForced ASLR:                           "   << vThreads[i].iEnableForceRelocateImages   << endl <<
            //    L"\tHigh enthropy:                         "   << vThreads[i].iEnableHighEntropy           << endl <<
            //    L"\tForced ASLR with Required Relocations: "   << vThreads[i].iDisallowStrippedImages      << endl <<
            endl;
        //wcout << L"DLLs:" << endl;
        //for (int k = 0; k < vThreads[i].vwDLL.size(); k++)
        //{
        //    wcout << L"\t" << vThreads[i].vwDLL[k] << endl;
        //}
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

        //system("pause");
    }

    int k;
    cin >> k;
    
    WCHAR priv[32] = L"SeChangeNotifyPrivilege";
    
    ClassProc->SetProcessPrivilege(&vThreads[k], priv, false);
    
    ClassProc->GetThreads(&vThreads);
    
    N = (int)vThreads.size();
    for (int i = 150; i < N; i++)
    {
        wcout << i << endl <<
            L"Name:\t\t\t"        << vThreads[i].wName           << endl <<
            //L"Integrity level:\t" << vThreads[i].iIntegrityLevel << endl <<
            endl;
        wcout << L"Privileges:" << endl;
        for (int k = 0; k < vThreads[i].vwPrivileges.size(); k++)
        {
            if (vThreads[i].vwPrivileges[k].bEnabled ||
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
    }
    cout << GetLastError() << endl;
    delete ClassProc;
    system("pause");
    return 0;
}