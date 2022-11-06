#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

/*
On 32 bit Windows GS is reserved for future use.
The FS segment points to the Thread information block.

In x64 mode the FS and GS segment registers have been swapped around.

In x86 mode FS:[0] points to the start of the TIB, in X64 it's GS:[0].
The reason Win64 uses GS is that there the FS register is used in the 32 bit compatibility layer (confusingly called Wow64).
Because 32-bit apps use FS the bookkeeping for Win64 is simplified.
32 bit applications never cause GS to be altered and 64 bit applications never cause FS to be altered.

Note that the fact that GS is non-zero in Win64 and Wow64 can be used to detect if a 32-bit application is running in 64-bit Windows.
In a 'true' 32 bit Windows GS is always zero.
*/

struct _PEB * get_PEB() { // Get Base Address
	struct _PEB * PEB_ptr;
	__asm__ volatile (
#if __i386__
			"mov %%fs:0x18, %%eax;" // Copy from src -> dst
			"mov %%ds:0x30(%%eax), %%eax;"
#endif
#if __x86_64__
			"mov %%gs:0x30, %%rax;" // Copy from src -> dst
			"mov %%ds:0x60(%%rax), %%rax;"
#endif
			: "=a"(PEB_ptr)); // Store result in PEB_ptr
	return PEB_ptr;
}

int is_beingdebugged_peb() { // Check if process is being debugged
	struct _PEB * PEB;
	PEB = get_PEB();
	return PEB->BeingDebugged == 1 ? TRUE : FALSE;
}

PPEB get_peb_address(void) // Get base address of PEB
{
	struct _PEB * PEB;
	PEB = get_PEB();
	return PEB;
}

void spoofPPID(char* runCmd, int pid)
{
	STARTUPINFOEXA si;
	PROCESS_INFORMATION pi;
	SIZE_T attributeSize;
	ZeroMemory(&si, sizeof(STARTUPINFOEXA));
	
	HANDLE parentProcessHandle = OpenProcess(MAXIMUM_ALLOWED, FALSE, pid);

	InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
	si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
	InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);
	UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentProcessHandle, sizeof(HANDLE), NULL, NULL);
	si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	CreateProcessA(NULL, (LPSTR)runCmd, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi);
}

int main(int argc, char *argv[]) 
{
	if(is_beingdebugged_peb())
	{
		OutputDebugString("Hello!");
		return -1;
	}

	struct _PEB * PEB;
	UNICODE_STRING* commandLine; // Struct to hold commandLine_ptr
	wchar_t commandLineContents[] = { L"cmd.exe" }; // Our spoofing arguments
	int Count, CurCount = 0;
	PPEB_LDR_DATA pLdrData = NULL;
	PLIST_ENTRY pHeadEntry = NULL;
	PLDR_DATA_TABLE_ENTRY pLdrEntry = NULL;
	PMODULE_ENTRY CurModule = NULL;
	PLIST_ENTRY pEntry = NULL;
	PRTL_USER_PROCESS_PARAMETERS procParameters = NULL;
	PMODULE_INFORMATION_TABLE pModuleInformationTable = NULL;

	PEB = get_peb_address();

	printf("[+] PEB Address: 0x%02p\n", PEB);

	procParameters = PEB->ProcessParameters; // Process Parameters struct address
	commandLine = &procParameters->CommandLine; // Get pointer to commandline of our process
	commandLine->Length = (USHORT)wcslen(commandLineContents)*2; // Set commandline lenght to our spoofed command (I had to times by two for correct size)
	commandLine->Buffer = commandLineContents; // Replace the command line arguments with our spoofed ones

	pLdrData = PEB->Ldr; // Get ldr struct address
	pHeadEntry = &pLdrData->InMemoryOrderModuleList; // Get the double linked list

	pEntry = pHeadEntry->Flink; // Go through the linked list and count elements
    while (pEntry != pHeadEntry) {
        Count++;
        pEntry = pEntry->Flink;
    }

	// Allocate a MODULE_INFORMATION_TABLE
    if ((pModuleInformationTable = malloc (sizeof (MODULE_INFORMATION_TABLE))) == NULL) {
        printf ("Cannot allocate a MODULE_INFORMATION_TABLE.\n");
        return -1;
    }

	// Allocate the correct amount of memory depending of the modules count
    if ((pModuleInformationTable->Modules = malloc (Count * sizeof (MODULE_ENTRY))) == NULL) {
        printf ("Cannot allocate a MODULE_INFORMATION_TABLE.\n");
        return -1;
    }

	// Fill the basic information of MODULE_INFORMATION_TABLE
    pModuleInformationTable->ModuleCount = Count;

	// Fill all the modules information in the table
    pEntry = pHeadEntry->Flink;
    while (pEntry != pHeadEntry)
    {
        // Retrieve the current MODULE_ENTRY
        CurModule = &pModuleInformationTable->Modules[CurCount++];

        // Retrieve the current LDR_DATA_TABLE_ENTRY
        pLdrEntry = CONTAINING_RECORD (pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList);

        // Fill the MODULE_ENTRY with the LDR_DATA_TABLE_ENTRY information
        memcpy(&CurModule->BaseName,    &pLdrEntry->BaseDllName, sizeof (CurModule->BaseName));
        memcpy(&CurModule->FullName,    &pLdrEntry->FullDllName, sizeof (CurModule->FullName));
        memcpy(&CurModule->SizeOfImage, &pLdrEntry->SizeOfImage, sizeof (CurModule->SizeOfImage));
        memcpy(&CurModule->BaseAddress, &pLdrEntry->DllBase,     sizeof (CurModule->BaseAddress));
        memcpy(&CurModule->EntryPoint,  &pLdrEntry->EntryPoint,  sizeof (CurModule->EntryPoint));

        // Iterate to the next entry
        pEntry = pEntry->Flink;
    }

	MODULE_INFORMATION_TABLE * moduleTable = pModuleInformationTable;

	if (!moduleTable) {
        printf("Module table not found.\n");
        return -1;
    }

	HMODULE DllAddress = NULL;

	// Iterate through modules table and get base address of ntdll.dll
    size_t moduleIndex;
    for (moduleIndex = 1; moduleIndex < moduleTable->ModuleCount; moduleIndex++)
    {
        MODULE_ENTRY *moduleEntry = &moduleTable->Modules[moduleIndex];
        PVOID baseAddress  = moduleEntry->BaseAddress;
        DWORD sizeOfModule = (DWORD) moduleEntry->SizeOfImage;

		if(_wcsicmp(L"ntdll.dll", moduleEntry->BaseName.Buffer) == 0)
		{
			DllAddress = (HMODULE)baseAddress;
		}

        printf ("%-15S : 0x%02p -> 0x%02p (%S)\n", moduleEntry->BaseName.Buffer, baseAddress, baseAddress + sizeOfModule, moduleEntry->FullName.Buffer);
    }

	NtOpenProcess = (NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID))GetProcAddress(DllAddress,"NtOpenProcess"); //Using base address from PEB get the address of NtOpenProcess

	if (NtOpenProcess == NULL) return -1;

	printf("NtOpenProcess address = 0x%02p\n", NtOpenProcess);

	spoofPPID("notepad", 8644);

	MessageBoxA(NULL,"Executing!!!","Run", MB_OK);

	return 0;
}