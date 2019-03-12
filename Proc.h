#include <iostream>
#include <windows.h>
#include <psapi.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <locale.h>
#include <vector>
#include <string>
#include <algorithm>
#include <aclapi.h>


#pragma comment (lib, "Advapi32.lib")

struct Proc_info
{
	TCHAR Name[MAX_PATH];
	TCHAR Path[2048];
	DWORD PID;
	DWORD PPID;
	TCHAR Type[11];
	TCHAR Integrity_lvl[128];
	TCHAR stDEP[128];
	PROCESS_MITIGATION_ASLR_POLICY* stASLR;
	std::vector<std::string> DLLs;

	std::vector<std::vector<std::string>> Privs;
};

struct uOwner
{
	TCHAR Name[MAX_PATH];
	TCHAR Domain[MAX_PATH];
	TCHAR sSID[512];
};

class Processes
{
public:
	void GetProcList();
	void GetProcAllInfo(DWORD PID, Proc_info *Proc, uOwner *owner);
	int AddNewAce(LPTSTR dir);
	int SetIntergrityLvl(DWORD PID, DWORD lvl);
	int SetIntegrityLvlObj(LPTSTR filename, DWORD level);
	int GetIntegrityLvlObj(LPCSTR filename);
private:
	

	int SetOwner(LPTSTR filename, LPTSTR newuser);

	void Cleanup(PSECURITY_DESCRIPTOR pSD, PACL pNewDACL);

	int GetProcessPrivileges(DWORD processID, Proc_info *proc);

	void CutOffName(std::string &name);

	int GetAllDLLs(DWORD processID, Proc_info *proc);

	int GetDepAndAslrFlags(DWORD PID, Proc_info *proc);

	BOOL IsWow64(HANDLE process);
	bool IsX86Process(HANDLE process);
	int GetProcType(DWORD PID, Proc_info *proc);

	int GetPPID(DWORD PID, DWORD *PPID);
	int GetProcOwner(DWORD PID, uOwner *owner);

	int GetProcessName(DWORD PID, Proc_info *proc);
	int GetProcessPath(DWORD PID, Proc_info *proc);
	int GetAllProcPID(DWORD *procs_pid, DWORD size, DWORD *count);

	int GetIntergrityLvl(DWORD PID, Proc_info *proc);

	void error_msg(const char* msg);
};

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);