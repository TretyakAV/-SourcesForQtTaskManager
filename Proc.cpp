#define _CRT_SECURE_NO_WARNINGS

#include "Proc.h"


void Processes::error_msg(const char* msg)
{
	std::cout << "Error: " << msg << std::endl;
}



int Processes::GetIntegrityLvlObj(LPCSTR filename)
{
	std::wcout << filename << "|||||" << std::endl;
	DWORD integrityLevel = 0;
	PSECURITY_DESCRIPTOR pSD;
	PACL acl;
	DWORD err;
	if ((err = GetNamedSecurityInfoA(filename, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, 0, 0, 0, &acl, &pSD)) == ERROR_SUCCESS)
	{
		

		if (0 != &acl && 0 < acl->AceCount)
		{
			SYSTEM_MANDATORY_LABEL_ACE* ace = 0;
			if (GetAce(acl, 0, reinterpret_cast<void**>(&ace)))
			{
				SID* sid = reinterpret_cast<SID*>(&ace->SidStart);
				integrityLevel = sid->SubAuthority[0];
			}
			else
			{
				std::cout << "GetAce Error: " << GetLastError() << std::endl;
				return -1;
			}
		}
		else
		{
			
			return -1;
		}

		LPSTR stringSD;
		ULONG stringSDLen = 0;

		ConvertSecurityDescriptorToStringSecurityDescriptorA(pSD, SDDL_REVISION_1, LABEL_SECURITY_INFORMATION, &stringSD, &stringSDLen);

		if (pSD == 0)
		{
			LocalFree(pSD);
			std::cout << "ConvertSecurityDescriptorToStringSecurityDescriptorA Error: " << GetLastError() << std::endl;
			return -1;
		}
		LocalFree(pSD);
	}
	else 
	{
		std::cout << "GetNamedSecurityInfoA Error: " << err << std::endl;
		return -1;
	}

	std::cout << integrityLevel << "||||";

	if (integrityLevel == 0x0000)
		return 0;
	else if (integrityLevel == 0x1000)
		return 1;
	else if (integrityLevel == 0x2000)
		return 2;
	else if (integrityLevel == 0x3000)
		return 3;

	else
		return -1;
}

int Processes::SetIntegrityLvlObj(LPTSTR filename, DWORD level)
{
	std::string sidStr;
	sidStr = new char[13];

	std::cout << filename << "|||||" << std::endl;

	switch (level)
	{
	
	case 1:
		sidStr = "S:(ML;;NR;;;LW)";
		break;
	case 2:
		sidStr = "S:(ML;;NR;;;ME)";
		break;
	case 3:
		sidStr = "S:(ML;;NR;;;HI)";
		break;
	default:
		break;
	}

	DWORD dwErr = ERROR_SUCCESS;
	PSECURITY_DESCRIPTOR pSD = NULL;

	PACL pSacl = NULL;
	BOOL fSaclPresent = FALSE;
	BOOL fSaclDefaulted = FALSE;

	if (ConvertStringSecurityDescriptorToSecurityDescriptorA(
		sidStr.c_str(), SDDL_REVISION_1, &pSD, NULL))
	{
		if (GetSecurityDescriptorSacl(pSD, &fSaclPresent, &pSacl,
			&fSaclDefaulted))
		{
			dwErr = SetNamedSecurityInfoA(filename,
				SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION,
				NULL, NULL, NULL, pSacl);

			if (dwErr == ERROR_SUCCESS) {
				return 0;
			}
		}
		LocalFree(pSD);
		return -1;
	}
	{
		std::cout << "ConvertStringSecurityDescriptorToSecurityDescriptorA: error " << GetLastError() << std::endl;
		return -1;
	}
}

int Processes::SetOwner(LPTSTR filename, LPTSTR newuser)
{
	HANDLE token;
	DWORD len;
	PSECURITY_DESCRIPTOR security = NULL;
	PSID sidPtr = NULL;
	int retValue = -1;

	// Get the privileges you need
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) {
		SetPrivilege(token, "SeTakeOwnershipPrivilege", 1);
		SetPrivilege(token, "SeSecurityPrivilege", 1);
		SetPrivilege(token, "SeBackupPrivilege", 1);
		SetPrivilege(token, "SeRestorePrivilege", 1);
	}
	else retValue = -1;

	// Create the security descriptor
	if (retValue) {
		GetFileSecurity(filename, OWNER_SECURITY_INFORMATION, security, 0, &len);
		security = (PSECURITY_DESCRIPTOR)malloc(len);
		if (!InitializeSecurityDescriptor(security, SECURITY_DESCRIPTOR_REVISION))
			retValue = -1;
	}

	// Get the sid for the username
	if (retValue) {
		char domainbuf[4096];
		DWORD sidSize = 0;
		DWORD bufSize = 4096;
		SID_NAME_USE sidUse;
		LookupAccountName(NULL, newuser, sidPtr, &sidSize, domainbuf, &bufSize, &sidUse);
	}


	// Set the sid to be the new owner
	if (retValue && !SetSecurityDescriptorOwner(security, sidPtr, 0))
		retValue = -0;

	// Save the security descriptor
	if (retValue)
		retValue = SetFileSecurity(filename, OWNER_SECURITY_INFORMATION, security);
	if (security) free(security);
	return 0;
}

void Processes::Cleanup(PSECURITY_DESCRIPTOR pSD, PACL pNewDACL)
{
	if (pSD != NULL)
		LocalFree((HLOCAL)pSD);

	if (pNewDACL != NULL)
		LocalFree((HLOCAL)pNewDACL);

}

int Processes::AddNewAce(LPTSTR pszObjName)
{
	SE_OBJECT_TYPE ObjectType = SE_FILE_OBJECT; // ТИП ОБЪЕКТА
	DWORD dwAccessRights = STANDARD_RIGHTS_ALL; // Маска ACE
	ACCESS_MODE AccessMode = DENY_ACCESS; //Тип доступа ACE
	DWORD dwInheritance = NO_PROPAGATE_INHERIT_ACE; // Флаги наследования для новых ACE. Флаги OBJECT_INHERIT_ACE и CONTAINER_INHERIT_ACE не передаются в унаследованный ACE.
	TRUSTEE_FORM TrusteeForm = TRUSTEE_IS_NAME; 


	// Trustee for new ACE.  This just for fun...When you run once, only one
	// element will take effect.  By changing the first array element we
	// can change to other trustee and re run the program....
	// Other than Mike spoon, they are all well known trustees
	// Take note the localization issues

	CHAR pszTrustee[1][15] = { "Пользователи" }; //здесь должны быть имена групп

	DWORD dwRes = 0;

	// Existing and new DACL pointers...
	PACL pOldDACL = NULL, pNewDACL = NULL;

	// Security descriptor
	PSECURITY_DESCRIPTOR pSD = NULL;

	SecureZeroMemory(&pSD, sizeof(PSECURITY_DESCRIPTOR));

	//EXPLICIT_ACCESS структура.Для более чем одной записи объявите массив структуры EXPLICIT_ACCESS
	EXPLICIT_ACCESS ea;

	if (pszObjName == NULL)
	{
		std::cout << "Invalid dir name!" << std::endl;
		return -1;
	}
	else
	{
		std::cout << "Name:" << pszObjName << "|\n";
	}

	dwRes = GetNamedSecurityInfoA(pszObjName, ObjectType,
		DACL_SECURITY_INFORMATION,
		NULL,
		NULL,
		&pOldDACL,
		NULL,
		&pSD);

	if (dwRes != ERROR_SUCCESS)
	{
		std::cout << "GetNamedSecurityInfo() failed, error:" << dwRes << std::endl;
		Cleanup(pSD, pNewDACL);
		return -1;
	}


	SecureZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));

	ea.grfAccessPermissions = dwAccessRights;

	ea.grfAccessMode = AccessMode;

	ea.grfInheritance = dwInheritance;

	ea.Trustee.TrusteeForm = TrusteeForm;

	// Назначаем группу АДМИНИСТРАТОРЫ
	ea.Trustee.ptstrName = (LPTSTR)(pszTrustee[0]);

	// Создаем новый ACL, который объединяет новый ACE с существующим DACL.
	dwRes = SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL);

	if (dwRes != ERROR_SUCCESS)
	{
		std::cout << "SetEntriesInAcl() failed, error " << dwRes << std::endl;
		Cleanup(pSD, pNewDACL);
		return -1;
	}

	// Запихиваем новый ACL в DACL

	dwRes = SetNamedSecurityInfo((LPSTR)pszObjName, ObjectType,
		DACL_SECURITY_INFORMATION,
		NULL,
		NULL,
		pNewDACL,
		NULL);

	if (dwRes != ERROR_SUCCESS)
	{
		std::cout << "SetNamedSecurityInfo() failed, error " << dwRes << std::endl;
		Cleanup(pSD, pNewDACL);
		return -1;
	}

	return 0;
}

int Processes::GetProcessPrivileges(DWORD PID, Proc_info *proc)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,
		FALSE, PID);

	if (NULL == hProcess)
	{
		std::cout << GetLastError();
		error_msg(" Error: hProc zero.");
		return -1;
	}

	HANDLE hToken;
	OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);

	if (hToken == NULL)
	{
		error_msg(" Error: hToken zero.");
		return -1;
	}
	
	DWORD cb = 2048;
	CHAR * buf[2048];
	if (GetTokenInformation(hToken, TokenPrivileges,
		&buf, cb, &cb))
	{
		for (DWORD i = 0; i < ((_TOKEN_PRIVILEGES*)buf)->PrivilegeCount; i++)
		{
			DWORD dwSize = 0;
			LookupPrivilegeName(NULL, &((_TOKEN_PRIVILEGES*)buf)->Privileges[i].Luid, NULL, &dwSize);
			LPSTR szName = new CHAR[dwSize + 1];
			bool err = LookupPrivilegeName(NULL, &((_TOKEN_PRIVILEGES*)buf)->Privileges[i].Luid, szName, &dwSize);
			if (err == FALSE)
				return -1;
			std::string str = szName;
			proc->Privs.resize(i + 1);
			proc->Privs[i].push_back(str);

			// Display the privilege state.
			if (((_TOKEN_PRIVILEGES*)buf)->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)
			{
				proc->Privs[i].push_back("Enabled");
			}
			else if (((_TOKEN_PRIVILEGES*)buf)->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT)
				proc->Privs[i].push_back("Enabled by default");

			else if (((_TOKEN_PRIVILEGES*)buf)->Privileges[i].Attributes & SE_PRIVILEGE_REMOVED)
				proc->Privs[i].push_back("Removed.");

			else if (((_TOKEN_PRIVILEGES*)buf)->Privileges[i].Attributes & SE_PRIVILEGE_USED_FOR_ACCESS)
				proc->Privs[i].push_back("Used for access");

			else
				proc->Privs[i].push_back("Disabled");
			std::cout << std::endl;


			
		}

	}
	else
	{
		std::cout << GetLastError() << " Error: GetTokenInformation " << std::endl;
		return -1;
	}

	CloseHandle(hToken);
	CloseHandle(hProcess);
	return 0;
}

void Processes::CutOffName(std::string &name)
{
	size_t pos = name.find_last_of('\\');

	name.replace(0, pos + 1, "");
}

int Processes::GetAllDLLs(DWORD processID, Proc_info *proc)
{
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;

	// Print the process identifier.


	// Get a handle to the process.

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processID);
	if (NULL == hProcess)
		return -1;

	// Get a list of all the modules in this process.

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];

			// Get the full path to the module's file.

			if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
				sizeof(szModName) / sizeof(TCHAR)))
			{
				// Print the module name and handle value.

				std::string str = szModName;
				CutOffName(str);


				proc->DLLs.push_back(str);
			}
		}
	}

	// Release the handle to the process.
	std::sort(proc->DLLs.begin(), proc->DLLs.end());
	CloseHandle(hProcess);

	return 0;
}

int Processes::GetDepAndAslrFlags(DWORD PID, Proc_info *proc)
{
	int check = 0;
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION,
		FALSE, PID);

	if (NULL == hProcess)
	{
		std::cout << GetLastError();
		error_msg(" Error: hProc zero.");
		
		return -1;
	}

	DWORD Flags;
	BOOL Permanent;

	if (GetProcessDEPPolicy(
		hProcess,
		&Flags,
		&Permanent) == FALSE)
		check += 1;
	else
	{

		if (Flags == 0)
			std::strcpy(proc->stDEP, "Disable");
		else if (Flags == 0x00000001 || Flags == 3)
			std::strcpy(proc->stDEP, "Enable");
		else if (Flags == 0x00000002)
			std::strcpy(proc->stDEP, "DEP-ATL thunk emulation is disabled for the specified process.");
	}

	proc->stASLR = new PROCESS_MITIGATION_ASLR_POLICY;

	if (GetProcessMitigationPolicy(hProcess, ProcessASLRPolicy, proc->stASLR, sizeof(PROCESS_MITIGATION_ASLR_POLICY)) == FALSE)
	{
		std::cout << "Error aslr " << GetLastError() << std::endl;
		check += 3;
	}
	


	
	CloseHandle(hProcess);
	return check;
}

int Processes::GetIntergrityLvl(DWORD PID, Proc_info *proc)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,
		FALSE, PID);

	if (NULL == hProcess)
	{
		std::cout << GetLastError();
		error_msg(" Error: hProc zero.");
		return -1;
	}

	HANDLE hToken;
	OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken);

	if (hToken == NULL)
	{
		error_msg("Error: hToken zero.");
		return -1;
	}
	BYTE buf[512];
	DWORD cb = sizeof(buf);

	if (GetTokenInformation(hToken, TokenIntegrityLevel,
		buf, cb, &cb))
	{

		PDWORD err = GetSidSubAuthority(((TOKEN_MANDATORY_LABEL*)(buf))->Label.Sid,
			(DWORD)(UCHAR)(*GetSidSubAuthorityCount(((TOKEN_MANDATORY_LABEL*)(buf))->Label.Sid) - 1));
		
		if (err == NULL)
		{
			std::cout << GetLastError() << "Error: GetSidSubAuthority " << std::endl;
			return -1;
		}

		DWORD dwIntegrityLevel = *err;
		if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
		{
			// Low Integrity
			std::strcpy(proc->Integrity_lvl, "Low Process");
		}
		else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
			dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
		{
			// Medium Integrity
			std::strcpy(proc->Integrity_lvl, "Medium Process");
		}
		else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
		{
			// High Integrity
			std::strcpy(proc->Integrity_lvl, "High Integrity Process");
		}
		else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
		{
			// System Integrity
			std::strcpy(proc->Integrity_lvl, "System Integrity Process");
		}
		else 
		{
			return -1;
		}
	}
	else
	{
		std::cout << GetLastError() << "Error: GetTokenInformation " <<  std::endl;
		return -1;
	}

	CloseHandle(hToken);
	CloseHandle(hProcess);
	return 0;
}

int Processes::SetIntergrityLvl(DWORD PID, DWORD lvl)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,
		FALSE, PID);

	if (NULL == hProcess)
	{
		std::cout << GetLastError();
		error_msg(" Error: hProc zero.");
		return -1;
	}

	HANDLE hToken;
	OpenProcessToken(hProcess, MAXIMUM_ALLOWED, &hToken);

	if (hToken == NULL)
	{
		error_msg("Error: hToken zero.");
		return -1;
	}

	BYTE buf[512];
	DWORD cb = sizeof(buf);

	

	if (GetTokenInformation(hToken, TokenIntegrityLevel,
		buf, cb, &cb))
	{

		std::string sidStr;
		sidStr = new char[13];

		switch (lvl)
		{
		case 0:
			sidStr = "S-1-16-0";
			break;
		case 1:
			sidStr = "S-1-16-4096";
			break;
		case 2:
			sidStr = "S-1-16-8192";
			break;
		case 3:
			sidStr = "S-1-16-12288";
			break;
		case 4:
			sidStr = "S-1-16-16384";
			break;
		default:
			break;
		}

		PSID NewSid;

		bool err = ConvertStringSidToSidA(
			sidStr.c_str(),
			&NewSid
		);

		if (err == FALSE)
		{

			std::cout << "ConvertSidToStr error: " << GetLastError() << std::endl;
			return -1;
		}


		//PSECURITY_DESCRIPTOR * NewPSd = new PSECURITY_DESCRIPTOR;

		//ConvertStringSecurityDescriptorToSecurityDescriptorA(sidStr.c_str(), SDDL_REVISION_1, NewPSd, sizeof(PSECURITY_DESCRIPTOR));
		//SetNamedSecurityInfoA();

		TOKEN_MANDATORY_LABEL tml = { 0 };
		tml.Label.Attributes = SE_GROUP_INTEGRITY;
		tml.Label.Sid = NewSid;
		
		


		if (SetTokenInformation(hToken, TokenIntegrityLevel, &tml, sizeof(TOKEN_MANDATORY_LABEL) + ::GetSidLengthRequired(1)) == 0)
		{
			std::cout << "SetTokenInformation error: " << GetLastError() << std::endl;
			return -1;
		}

	}
	else
	{
		std::cout << GetLastError() << "Error: GetTokenInformation " << std::endl;
		return -1;
	}

	CloseHandle(hToken);
	CloseHandle(hProcess);
	return 0;
}

BOOL Processes::IsWow64(HANDLE process)
{
	BOOL bIsWow64 = FALSE;

	typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process;
	fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

	if (NULL != fnIsWow64Process)
	{
		if (!fnIsWow64Process(process, &bIsWow64))
		{
			//handle error
		}
	}
	return bIsWow64;
}

bool Processes::IsX86Process(HANDLE process)
{
	SYSTEM_INFO systemInfo = { 0 };
	GetNativeSystemInfo(&systemInfo);

	// x86 environment
	if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
		return true;

	// Check if the process is an x86 process that is running on x64 environment.
	// IsWow64 returns true if the process is an x86 process
	return IsWow64(process);
}

int Processes::GetProcType(DWORD PID, Proc_info *proc)
{
	proc->PID = PID;
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, proc->PID);
	bool isX86;

	if (NULL != hProcess)
	{
		isX86 = IsX86Process(hProcess);
		if (isX86 == true)
		{
			std::strcpy(proc->Type, "x86");
		}
		else std::strcpy(proc->Type, "x64");
	}
	else
	{
		return -1;
	}


	CloseHandle(hProcess);

	return 0;
}

int Processes::GetProcOwner(DWORD PID, uOwner *owner) //возвращать структуру owner
{

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,
		FALSE, PID);

	if (NULL == hProcess)
	{
		std::cout << GetLastError();
		error_msg(" Error: hProc zero.");
		
		return -1;
	}
	HANDLE hToken;
	OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken);

	if (hToken == NULL)
	{
		error_msg("Error: hToken zero.");
		return -1;
	}

	BYTE buf[512];
	DWORD cb = sizeof(buf);

	if (GetTokenInformation(hToken, TokenUser, buf, cb, &cb) == 0)
	{
		std::cout << GetLastError();
		error_msg(" Error: GetTokenInformation!");
		
		return -1;
	}

	TCHAR szName[MAX_PATH];
	DWORD dwName = MAX_PATH;
	TCHAR szDomain[MAX_PATH];
	DWORD dwDomain = MAX_PATH;
	SID_NAME_USE snu;
	if (LookupAccountSid(NULL, ((TOKEN_USER *)(buf))->User.Sid, szName, &dwName, szDomain, &dwDomain, &snu) == 0)
	{
		return -1;
	}

	
	PSID pSid = ((TOKEN_USER *)(buf))->User.Sid;

	std::strcpy(owner->Name, szName);
	std::strcpy(owner->Domain, szDomain);

	if (pSid != NULL)

	{
		
		LPTSTR sStringSid = NULL;
		if (ConvertSidToStringSid(pSid, &sStringSid))
		{
			
			std::strcpy(owner->sSID, sStringSid);
			LocalFree(sStringSid);
		}
		else
			wprintf(L"ConvertSidToSTringSid failed with error %d\n",
				GetLastError());

		CloseHandle(hToken);
		CloseHandle(hProcess);
		return 0;
	}
	else 
	{
		CloseHandle(hToken);
		CloseHandle(hProcess);
		error_msg("pSID is NULL!");
		return -1;
	}
}

int Processes::GetPPID(DWORD pid, DWORD* PPID)
{
	HANDLE hSnapshot;
	PROCESSENTRY32 pe32;
	DWORD ppid = -1;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	__try {
		if (hSnapshot == INVALID_HANDLE_VALUE) __leave;

		ZeroMemory(&pe32, sizeof(pe32));
		pe32.dwSize = sizeof(pe32);
		if (!Process32First(hSnapshot, &pe32)) __leave;

		do {
			if (pe32.th32ProcessID == pid) {
				ppid = pe32.th32ParentProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe32));
	}
	__finally {
		if (hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);
	}
	if (ppid == -1)
		return -1;
	*PPID = ppid;
	return 0;
}

int Processes::GetProcessPath(DWORD PID, Proc_info *proc)
{
	proc->PID = PID;

	// Get a handle to the process.

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,
		FALSE, proc->PID);

	// Get the process name.

	if (NULL != hProcess)
	{
		HMODULE hMod;
		DWORD cbNeeded;

		if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
			&cbNeeded))
		{
			if (GetModuleFileNameEx(hProcess, hMod, proc->Path,
				sizeof(proc->Path) / sizeof(TCHAR)) == 0)
			{
				std::cout << "ER:" << GetLastError();
			}
		}
		else
		{
			return -1;
		}
	}
	else
	{
		return -1;
	}

	// Release the handle to the process.

	CloseHandle(hProcess);

	return 0;
}

int Processes::GetProcessName(DWORD PID, Proc_info *proc)
{
	proc->PID = PID;

	// Get a handle to the process.

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, proc->PID);

	// Get the process name.

	if (NULL != hProcess)
	{
		HMODULE hMod;
		DWORD cbNeeded;

		if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
			&cbNeeded))
		{
			GetModuleBaseName(hProcess, hMod, proc->Name,
				sizeof(proc->Name) / sizeof(TCHAR));
		}
		else
		{
			return -1;
		}
	}
	else
	{
		return -1;
	}

	// Release the handle to the process.

	CloseHandle(hProcess);

	return 0;
} //EnumProcessModules Трабл 32 битки error 299

int Processes::GetAllProcPID(DWORD *procs_pid, DWORD size, DWORD *count)
{
	if (!EnumProcesses(procs_pid, size, count))
	{
		return -1;
	}
	*count /= sizeof(DWORD);
	return 0;
}

void Processes::GetProcList()
{
	DWORD ProcessesPID[2048];
	DWORD CountProc;

	if (GetAllProcPID(ProcessesPID, sizeof(ProcessesPID), &CountProc) != 0)
	{
		error_msg("Can't get processes' PIDs");
	}
	for (DWORD i = 0; i < CountProc; i++)
	{
		Proc_info Proc;
		if (GetProcessName(ProcessesPID[i] , &Proc) != 0)
		{
			std::strcpy(Proc.Name, "<unknown>");
		}
		_tprintf(TEXT("%s  (PID: %u)\n"), Proc.Name, Proc.PID);

	}
	return;

}

void Processes::GetProcAllInfo(DWORD PID, Proc_info *Proc, uOwner *owner)
{
	Proc->PID = PID;

	if (GetProcessName(Proc->PID, Proc) != 0)
	{
		std::strcpy(Proc->Name, "<unknown>");
	}

	if (GetProcessPath(Proc->PID, Proc) != 0)
	{
		std::strcpy(Proc->Path, "<unknown>");
	}


	if (GetPPID(Proc->PID, &(Proc->PPID)) != 0)
	{
		Proc->PPID = 0;
	}

	if (GetProcOwner(Proc->PID, owner) != 0)
	{
		std::strcpy(owner->Name, "<unknown>");
		std::strcpy(owner->sSID, "<unknown>");
	}

	if (GetProcType(Proc->PID, Proc) != 0)
	{
		std::strcpy(Proc->Path, "<unknown>");
	}

	if (GetIntergrityLvl(Proc->PID, Proc) != 0)
	{
		std::strcpy(Proc->Integrity_lvl, "<unknown>");
	}

	/*if (SetIntergrityLvl(Proc->PID, 2) != 0)
	{
		std::strcpy(Proc->Integrity_lvl, "<unknown>");
	}*/


	int check;
	if ((check = GetDepAndAslrFlags(Proc->PID, Proc)) != 0)
	{
		if (check == 4 || check == 1 || check == -1)
		{
			std::strcpy(Proc->stDEP, "<unknown>");
			check -= 1;
		}
		if (check == 3 || check == -2)
		{
			Proc->stASLR = NULL;
		}
		
	}

	GetAllDLLs(Proc->PID, Proc);

	GetProcessPrivileges(Proc->PID, Proc);

}

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	LUID luid;
	BOOL bRet = FALSE;

	if (LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
	{
		TOKEN_PRIVILEGES tp;

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;
		//
		//  Enable the privilege or disable all privileges.
		//
		if (AdjustTokenPrivileges(hToken, FALSE, &tp, NULL, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
		{
			//
			//  Check to see if you have proper access.
			//  You may get "ERROR_NOT_ALL_ASSIGNED".
			//
			bRet = (GetLastError() == ERROR_SUCCESS);
		}
	}
	return bRet;
}