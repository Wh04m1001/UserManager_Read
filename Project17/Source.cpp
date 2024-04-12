
#include <windows.h>
#include <stdio.h>

void Find();
#define STATUS_MORE_ENTRIES 0x00000105
#define STATUS_NO_MORE_ENTRIES 0x8000001A
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }
typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;

} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
	PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
typedef struct _OBJECT_DIRECTORY_INFORMATION {
	UNICODE_STRING Name;
	UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;
using _NtOpenDirectoryObject = NTSTATUS(NTAPI*)(OUT PHANDLE DirectoryHandle, IN ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
using _NtQueryDirectoryObject = NTSTATUS(NTAPI*)(_In_      HANDLE  DirectoryHandle, _Out_opt_ PVOID   Buffer, _In_ ULONG Length, _In_ BOOLEAN ReturnSingleEntry, _In_  BOOLEAN RestartScan, _Inout_   PULONG  Context, _Out_opt_ PULONG  ReturnLength);

void Find() {
	_NtQueryDirectoryObject NtQueryDirectoryObject = (_NtQueryDirectoryObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryDirectoryObject");
	_NtOpenDirectoryObject NtOpenDirectoryObect = (_NtOpenDirectoryObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenDirectoryObject");
	HANDLE dirobject;
	wchar_t* destination = new wchar_t[512];
	OBJECT_ATTRIBUTES obj;
	const wchar_t device[] = L"\\Device";
	UNICODE_STRING unicode_string = { 0 };
	unicode_string.Length = wcslen(device) * 2;
	unicode_string.MaximumLength = wcslen(device) * 2 + 2;
	unicode_string.Buffer = (PWSTR)device;
	InitializeObjectAttributes(&obj, &unicode_string, 0, 0, 00);

	NTSTATUS result = NtOpenDirectoryObect(&dirobject, 0x0001 | 0x0002, &obj);
	if (result == 0) {

		BYTE* buffer = new BYTE[100000];
		wchar_t* hive = new wchar_t[512];

		ULONG start = 0, index = 0, bytes;
		DWORD num_of_vss = 0;
		BOOLEAN restart = TRUE;
		for (;;)
		{
			result = NtQueryDirectoryObject(dirobject, PBYTE(buffer), 100000, FALSE, restart, &index, &bytes);
			if (result == 0)
			{
				POBJECT_DIRECTORY_INFORMATION const objectlist = reinterpret_cast<POBJECT_DIRECTORY_INFORMATION>(PBYTE(buffer));
				for (ULONG i = 0; i < index - start; i++)
				{
					if (0 == wcsncmp(objectlist[i].TypeName.Buffer, L"Device", objectlist[i].TypeName.Length / sizeof(WCHAR)))
					{
						if (wcsstr(objectlist[i].Name.Buffer, L"ShadowCopy")) {
							printf("Found VSS: \\\\?\\GLOBALROOT\\Device\\%ws\\\n", objectlist[i].Name.Buffer);
							
							num_of_vss += 1;



						}
					}
				}
			}
			if (STATUS_MORE_ENTRIES == result)
			{
				start = index;
				restart = FALSE;
				continue;
			}
			if (((STATUS_NO_MORE_ENTRIES == 0 || (result == 0))) && num_of_vss == 0)
			{
				printf("Can't find VSS!\n");
				CloseHandle(dirobject);
				delete[] buffer;
				delete[] destination;
				delete[] hive;
				exit(0);

			}
			else if (STATUS_NO_MORE_ENTRIES == 0 || (result == 0)) {
				CloseHandle(dirobject);

				delete[] buffer;
				delete[] destination;
				delete[] hive;
				exit(0);

			}
		}

	}
}
int wmain()
{
	Find();
}