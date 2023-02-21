#include <windows.h>
#include <TlHelp32.h>
#include <vector>
#include <iostream>
#include <string>

#pragma comment(lib, "ntdll")

extern "C" NTSTATUS WINAPI NtQueryInformationProcess(HANDLE ProcessHandle, ULONG ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
extern "C" NTSTATUS WINAPI NtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG Attributes, ULONG Options);
extern "C" NTSTATUS WINAPI NtQueryObject(HANDLE ObjectHandle, ULONG ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);

#define ObjectNameInformation 1
#define ProcessHandleInformation 51

#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO {
	HANDLE HandleValue;
	ULONG_PTR HandleCount;
	ULONG_PTR PointerCount;
	ULONG GrantedAccess;
	ULONG ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, *PPROCESS_HANDLE_TABLE_ENTRY_INFO;

typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION {
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, *PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

class Process {
	HANDLE m_handle;
public:
	Process(LPCSTR name) {
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		DWORD pid = NULL;
		PROCESSENTRY32 pe;
		pe.dwSize = sizeof(pe);

		Process32First(snapshot, &pe);

		while (Process32Next(snapshot, &pe)) {
			if (!_strcmpi(pe.szExeFile, name)) {
				pid = pe.th32ProcessID;

				break;
			}
		}

		CloseHandle(snapshot);

		if (!(m_handle = OpenProcess(PROCESS_DUP_HANDLE, NULL, pid))) {
			return;
		}

		HANDLE dupHandle;
		if (!DuplicateHandle(m_handle, GetCurrentProcess(), GetCurrentProcess(), &dupHandle, NULL, FALSE, DUPLICATE_SAME_ACCESS)) {
			return;
		}

		CloseHandle(m_handle);
		m_handle = dupHandle;
	}

	~Process() {
		CloseHandle(m_handle);
	}

	const HANDLE GetHandle() {
		return m_handle;
	}
};

class Exception {
	std::string m_msg;
	bool m_error;
public:
	Exception(std::string msg, bool error = true) : m_msg(msg), m_error(error) {}

	std::string GetMsg() {
		return m_msg;
	}

	bool IsError() {
		return m_error;
	}
};

//-----------------------------------------------

int main() {
	try {
		Process process("GenshinImpact.exe");
		if (!process.GetHandle()) {
			throw Exception("Couldn't open Genshin Impact.");
		}

		HANDLE processHandle = process.GetHandle();

		std::vector<char> handleInfoBuffer;
		PPROCESS_HANDLE_SNAPSHOT_INFORMATION handleInfo = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)handleInfoBuffer.data();

		ULONG requiredSize;
		NTSTATUS status;
		while ((status = NtQueryInformationProcess(processHandle, ProcessHandleInformation, handleInfo, (ULONG)handleInfoBuffer.size(), &requiredSize)) == STATUS_INFO_LENGTH_MISMATCH) {
			handleInfoBuffer.resize(requiredSize);
			handleInfo = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)handleInfoBuffer.data();
		}

		if (!SUCCEEDED(status)) {
			throw Exception("NtQuerySystemInformation error.");
		}

		for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
			if (handleInfo->Handles[i].GrantedAccess == 1704073) {
				continue;
			}

			HANDLE handle = handleInfo->Handles[i].HandleValue;

			HANDLE dupHandle = NULL;
			if (!SUCCEEDED(NtDuplicateObject(processHandle, handle, GetCurrentProcess(), &dupHandle, NULL, FALSE, NULL))) {
				continue;
			}

			std::vector<char> objectNameBuffer;
			while ((status = NtQueryObject(dupHandle, ObjectNameInformation, objectNameBuffer.data(), (ULONG)objectNameBuffer.size(), &requiredSize)) == STATUS_INFO_LENGTH_MISMATCH) {
				objectNameBuffer.resize(requiredSize);
			}
			CloseHandle(dupHandle);

			if (!SUCCEEDED(status)) {
				continue;
			}

			UNICODE_STRING objectName = *(PUNICODE_STRING)objectNameBuffer.data();
			if (objectName.Length) {
				char name[MAX_PATH]{};
				wcstombs_s(NULL, name, objectName.Buffer, sizeof(name));

				if (strstr(name, "mhyprot")) {
					HANDLE thread = CreateRemoteThread(processHandle, NULL, NULL, (LPTHREAD_START_ROUTINE)CloseHandle, handle, NULL, NULL);
					WaitForSingleObject(thread, INFINITE);
					CloseHandle(thread);

					throw Exception("Anti-cheat bypass completed successfully!", false);
				}
			}
		}
	}
	catch (Exception error) {
		std::cout << error.GetMsg() << (error.IsError() ? " Error: " + std::to_string(GetLastError()) + "." : "") << std::endl;
	}

	system("pause");

	return FALSE;
}