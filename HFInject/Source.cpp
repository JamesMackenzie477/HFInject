#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

// returns the nt headers of the specified module (32 bit processes only)
PIMAGE_NT_HEADERS32 ReadNtHeaders32(HANDLE hProcess, HMODULE hModule)
{
	// stores the image dos headers
	IMAGE_DOS_HEADER DosHeader;
	// reads the dos headers of the module
	if (ReadProcessMemory(hProcess, hModule, &DosHeader, sizeof(IMAGE_DOS_HEADER), NULL))
	{
		// stores the image nt headers
		PIMAGE_NT_HEADERS32 NtHeaders = new IMAGE_NT_HEADERS32();
		// reads the nt headers of the module
		if (ReadProcessMemory(hProcess, (PVOID)((DWORD64)hModule + DosHeader.e_lfanew), NtHeaders, sizeof(IMAGE_NT_HEADERS32), NULL))
		{
			// returns the nt headers
			return NtHeaders;
		}
	}
	// function failed
	return NULL;
}

// gets the address of a procedure within the given process module by remotely parsing the export table (32 bit processes only)
PVOID GetRemoteProcAddress32(HANDLE hProcess, HMODULE hModule, LPCSTR lpProcName)
{
	// reads the nt headers of the module
	if (PIMAGE_NT_HEADERS32 pNtHeaders = ReadNtHeaders32(hProcess, hModule))
	{
		// if the export directory exists
		if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
		{
			// stores the export directory
			IMAGE_EXPORT_DIRECTORY ExportDirectory;
			// reads the export directory of the module
			if (ReadProcessMemory(hProcess, (PVOID)((DWORD64)hModule + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress), &ExportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY), NULL))
			{
				// stores the functions array
				PDWORD pFunctions = new DWORD[ExportDirectory.NumberOfFunctions];
				// reads the functions array
				if (ReadProcessMemory(hProcess, (PVOID)((DWORD64)hModule + ExportDirectory.AddressOfFunctions), pFunctions, ExportDirectory.NumberOfFunctions * sizeof(DWORD), NULL))
				{
					// stores the names array
					PDWORD pNames = new DWORD[ExportDirectory.NumberOfNames];
					// reads the names array
					if (ReadProcessMemory(hProcess, (PVOID)((DWORD64)hModule + ExportDirectory.AddressOfNames), pNames, ExportDirectory.NumberOfNames * sizeof(DWORD), NULL))
					{
						// stores the ordinals array
						PWORD pOrdinals = new WORD[ExportDirectory.NumberOfFunctions];
						// reads the ordinals array
						if (ReadProcessMemory(hProcess, (PVOID)((DWORD64)hModule + ExportDirectory.AddressOfNameOrdinals), pOrdinals, ExportDirectory.NumberOfFunctions * sizeof(WORD), NULL))
						{
							// iterates through function names
							for (int i = 0; i < ExportDirectory.NumberOfNames; i++)
							{
								// gets the function name length
								// DWORD dwNameLength = Process::GetRemoteStringLength(hProcess, (PVOID)((DWORD64)hModule + pNames[i]));
								// stores the function name
								CHAR lpFunctionName[MAX_PATH];
								// reads the function name
								if (ReadProcessMemory(hProcess, (PVOID)((DWORD64)hModule + pNames[i]), &lpFunctionName, MAX_PATH, NULL))
								{
									// compares the function names
									if (_stricmp(lpProcName, lpFunctionName) == 0)
									{
										// gets the function address
										PVOID pFunction = (PVOID)((DWORD64)hModule + pFunctions[pOrdinals[i]]);
										// cleans up the heap to prevent memory leaks
										// deletes the ordinals array
										delete pOrdinals;
										// deletes the names array
										delete pNames;
										// deletes the functions array
										delete pFunctions;
										// returns the address
										return pFunction;
									}
								}
							}
						}
						// deletes the ordinals array
						delete pOrdinals;
					}
					// deletes the names array
					delete pNames;
				}
				// deletes the functions array
				delete pFunctions;
			}
		}
	}
	// function failed
	return NULL;
}

uint8_t sCode[]
{
	// LoadLibraryA(user32.dll)
	0x31,0xC9,                      // xor ecx, ecx
	0xB9, 0x77, 0x49, 0xC3, 0x76,   // mov ecx, 0x00    // address of loadlibraryA function 0x76fc5980
	0x31, 0xD2,                     // xor edx, edx
	0xBA, 0x00, 0x00, 0x00, 0x00,   // mov edx, 0x00    //address of user32.dll char array
	0x52,                           // push edx
	0xff, 0xD1,                     // call ecx         // call function

																	// GetProcAddress(return value of previous call(aka eax)HMODULE, MessageBoxA)

																	0x31,0xC9,                      // xor ecx, ecx
																	0xB9, 0xB0, 0x50, 0xFC, 0x76,   // mov ecx, 0x00    // address of GetProcAddress Function 0x76fc50b0
																	0x31, 0xDB,                     // xor ebx, ebx
																	0xBB, 0x00, 0x00, 0x00, 0x00,   // mov ebx, 0x00    // address of MessageBoxA char array
																	0x31, 0xD2,                     // xor edx, edx
																	0x89, 0xC2,                     // mov edx, eax     // move return value of previous call from eax to edx
																	0x53,                           // push ebx         // push ebx to stack
																	0x52,                           // push edx         // push edx to stack
																	0xff, 0xD1,                     // call ecx         // call function

																									// MessageBox(NULL, NULL, NULL, NULL) // eax should hold the address to the MessageBox Function
																									0x6A, 0x00,                     // push 0x00 // push NULL
																									0x6A, 0x00,                     // push 0x00
																									0x6A, 0x00,                     // push 0x00
																									0x6A, 0x00,                     // push 0x00
																									0x31, 0xD2,                     // xor edx, edx
																									0x89, 0xC2,                     // mov edx, eax
																									0xff, 0xD2,                     // call edx
																									0xC3                            // ret
};

DWORD GetTargetThreadIDFromProcName(const char * ProcName)
{
	PROCESSENTRY32 pe;
	HANDLE thSnapShot;
	BOOL retval, ProcFound = false;

	thSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (thSnapShot == INVALID_HANDLE_VALUE)
	{
		printf("Error: Unable to create toolhelp snapshot!");
		return false;
	}

	pe.dwSize = sizeof(PROCESSENTRY32);

	retval = Process32First(thSnapShot, &pe);
	while (retval)
	{
		if (!strcmp(pe.szExeFile, ProcName))
		{
			return pe.th32ProcessID;
		}
		retval = Process32Next(thSnapShot, &pe);
	}
	return 0;
}

int main()
{
	DWORD pID = NULL;

	SIZE_T bWrit = NULL;
	SIZE_T bWrit2 = NULL;

	const char target_dll[] = "User32.dll";
	const char target_function[] = "MessageBoxA";

	while (!pID)
	{
		pID = GetTargetThreadIDFromProcName("WinRAR.exe");

		Sleep(10);
	}

	if (pID)
	{
		HANDLE Proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);

		if (Proc == INVALID_HANDLE_VALUE)
		{
			std::cout << "OpenProcess error: 0x" << std::hex << GetLastError() << std::endl;
		}

		uintptr_t rString = (uintptr_t)VirtualAllocEx(Proc, NULL, sizeof(target_dll) + sizeof(target_function) + 2 + sizeof(sCode), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

		if (!rString)
		{
			std::cout << "VirtualAllocEx error: 0x" << std::hex << GetLastError() << std::endl;
		}

		if (!WriteProcessMemory(Proc, (LPVOID)rString, &target_dll, sizeof(target_dll) + 1, &bWrit))
		{
			std::cout << "WriteProcessMemory error: 0x" << std::hex << GetLastError() << std::endl;
		}

		if (bWrit > 0)
		{

			if (!WriteProcessMemory(Proc, (char*)rString + bWrit, &target_function, sizeof(target_function) + 1, &bWrit2))
			{
				std::cout << "WriteProcessMemory error: 0x" << std::hex << GetLastError() << std::endl;
			}

			if (bWrit2 > 0)
			{
				*(uintptr_t*)(sCode + 3) = (uintptr_t)GetRemoteProcAddress32(Proc, GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
				*(uintptr_t*)(sCode + 10) = rString;
				*(uintptr_t*)(sCode + 20) = (uintptr_t)GetRemoteProcAddress32(Proc, GetModuleHandleA("kernel32.dll"), "GetProcAddress");
				*(uintptr_t*)(sCode + 27) = (uintptr_t)(char*)rString + bWrit;

				int startAddyOffset = bWrit + bWrit2;

				uintptr_t startAddress = (uintptr_t)(char*)rString + startAddyOffset;

				if (!WriteProcessMemory(Proc, (LPVOID)startAddress, &sCode, sizeof(sCode), nullptr))
				{
					std::cout << "WriteProcessMemory error: 0x" << std::hex << GetLastError() << std::endl;
				}

				DWORD fpOldAccess = NULL;
				if (!VirtualProtectEx(Proc, (LPVOID)startAddress, sizeof(sCode), PAGE_EXECUTE_READWRITE, &fpOldAccess))
				{
					std::cout << "VirtualProtect error: 0x" << std::hex << GetLastError() << std::endl;
				}

				std::cout << "Shellcode allocated at: 0x" << std::hex << rString << std::endl;

				std::cin.get();

				LPVOID SA = (LPVOID)startAddress;
				if (!CreateRemoteThread(Proc, nullptr, NULL, (LPTHREAD_START_ROUTINE)SA, nullptr, 0, nullptr))
				{
					std::cout << "CreateRemoteThread error: 0x" << std::hex << GetLastError() << std::endl;
				}
				system("PAUSE");
			}
		}
	}
	system("PAUSE");
	return 0;
}