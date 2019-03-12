#define UNICODE

#include "Proc.h"

int main()
{
	HANDLE hProcess = GetCurrentProcess();
	HANDLE hToken;

	if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);
		CloseHandle(hToken);
	}

	setlocale(LC_ALL, "Russian");
	Processes Processes;

	Processes.GetProcList();
	std::cout << std::endl;

	while (1)
	{
		DWORD PID;
		Proc_info Proc, PProc;
		uOwner Owner, pOwner;

		std::cin >> PID;
		Processes.GetProcAllInfo(PID, &Proc, &Owner);

		Processes.GetProcAllInfo(Proc.PPID, &PProc, &pOwner);


		std::cout << Proc.Name << ":" << "\n\tPID - " << Proc.PID << "\n\tPath - " << Proc.Path << "\n\tPPID - "
			<< PProc.PID << "\n\tPName - " << PProc.Name << "\n\tUser owner - "
			<< Owner.Name << "\n\tOwner SID - " << Owner.sSID
			<< "\n\tType - " << Proc.Type
			<< "\n\tIntegrity level - " << Proc.Integrity_lvl
			<< "\n\tDEP status - " << Proc.stDEP
			<< std::endl
			<< "\n\tPriveleges:";
		for (int i = 0; i < Proc.Privs.size(); i++)
		{
			std::cout << "\n\t" << Proc.Privs[i][0] << ": " << Proc.Privs[i][1];
		}
		std::cout << std::endl
			<< "\n\tDLLs:";
		for (int i = 1; i < Proc.DLLs.size(); i++)
		{
			std::cout << "\n\t" << Proc.DLLs[i];
		}

		/*char name_obj[MAX_PATH] = { "‪C:\\Users\\gvsp\\Documents\\7z.exe" };
		if (Processes.AddNewAce(&name_obj[1]) != 0)
		{

		}
		else {
			std::cout << "SUCCESSED ACE" << std::endl;
		}*/
		int err;
		CHAR name_obj[MAX_PATH] = { "C:\\‪fff" };
		/*if ((err = Processes.GetIntegrityLvlObj(name_obj)) == -1 )
		{
			std::cout << std::endl << ":(((" << std::endl;
		}
		else {
			std::cout << std::endl << "SUCCESSED: " << err << std::endl;
		}*/


		if ((err = Processes.SetIntegrityLvlObj(name_obj, 1)) == -1)
		{
			 std::cout << std::endl << ":(((" << std::endl;
		}
		else 
		{
				std::cout << std::endl << "SUCCESSED: " << err << std::endl;
		}


	}
	system("pause");
	return 0;
}