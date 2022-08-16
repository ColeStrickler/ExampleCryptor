#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <iostream>




void main()
{
     std::cout << "Hello World!\n";
} // end main()-----------------------------------------------


// .code SECTION----------------------------------------------
/*
    Keep unreferenced data,linker options /OPT:NOREF
*/ 
#pragma section(".code",execute,read,write)
#pragma comment(linker,"/MERGE:.text=.code") // put all of our data into one section
#pragma comment(linker,"/MERGE:.data=.code") // makes life easier for the cryptor
#pragma comment(linker,"/SECTION:.code,ERW") // set .code to executable, readable, and writable

unsigned char var[] = { 0xBE, 0xBA, 0xFE, 0xCA }; // global variables would be in the .data section by default

// Everything from here until the next code_seg directive belongs to .code section
#pragma code_seg(".code")
// .code SECTION----------------------------------------------




// .stub SECTION----------------------------------------------
#pragma section(".stub",execute,read)
#pragma comment(linker,"/entry:\"StubEntry\"")



#define KEY 0x4
typedef struct _ADDRESS_INFO {
    uintptr_t modBase;
    uintptr_t moduleCodeOffset;
    uintptr_t fileCodeOffset;
    uintptr_t fileCodeSize;
} ADDRESS_INFO, * PADDRESS_INFO;




void getNameCurrentProc(wchar_t* out) {
    wchar_t fullPath[MAX_PATH + 1] = { 0 };
    GetProcessImageFileNameW(GetCurrentProcess(), fullPath, (DWORD)sizeof(fullPath));
    int lastSlash = 0;
    for (int i = 0; i < MAX_PATH; i++) {
        if ((wchar_t)fullPath[i] == (wchar_t)0x5c) { // NEEDS DEBUGGED RIGHT HERE
            lastSlash = i;
        }
    }
    lastSlash++;
    int i = 0;
    while (fullPath[lastSlash] != 0) {
        out[i] = fullPath[lastSlash];
        i++;
        lastSlash++;
    }
    return;
}

DWORD GetProcId(wchar_t* procName)
{
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry);

        if (Process32First(hSnap, &procEntry))
        {
            do
            {
                if (!_wcsicmp(procEntry.szExeFile, procName))
                {
                    procId = procEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &procEntry));
        }
    }
    CloseHandle(hSnap);
    return procId;
}

uintptr_t GetBaseAddress(DWORD procId, wchar_t* modName) {


    uintptr_t modBase = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
    if (hSnap && hSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(MODULEENTRY32);
        if (Module32First(hSnap, &modEntry)) {
            do {
                if (!_wcsicmp(modEntry.szModule, modName)) {
                    modBase = (uintptr_t)modEntry.modBaseAddr;
                    break;
                }
            } while (Module32Next(hSnap, &modEntry));
        }
        CloseHandle(hSnap);
        return modBase;
    }
    else {
        return NULL;
    }


}


void TraverseSectionHeaders(PIMAGE_SECTION_HEADER section, DWORD nSections, PADDRESS_INFO addr_info) {
    DWORD i;
    for (i = 0; i < nSections; i++) {
        if (!strcmp((const char*)section->Name, ".code")) {
            (*addr_info).fileCodeOffset = section->PointerToRawData;
            (*addr_info).fileCodeSize = section->SizeOfRawData;
        }
        section = section + 1;
    }
    return;
}




void find_Addrs(PADDRESS_INFO addr_info, wchar_t* name) {
    uintptr_t base = GetBaseAddress(GetProcId(name), name);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
#ifdef _WIN64
    IMAGE_OPTIONAL_HEADER64 opt = (IMAGE_OPTIONAL_HEADER64)(nt->OptionalHeader);
#else
    IMAGE_OPTIONAL_HEADER32 opt = (IMAGE_OPTIONAL_HEADER32)(nt->OptionalHeader);
#endif

    (*addr_info).modBase = opt.ImageBase;
    (*addr_info).moduleCodeOffset = opt.BaseOfCode;

    TraverseSectionHeaders(IMAGE_FIRST_SECTION(nt), nt->FileHeader.NumberOfSections, addr_info);
    return;
}

void decryptCodeSection(uintptr_t code_base, uintptr_t code_size, int key) {
    unsigned char* ptr;
    long int i;
    long int nbytes;
    ptr = (unsigned char*)code_base;
    nbytes = code_size;
    for (i = 0; i < nbytes; i++) {
        ptr[i] = ptr[i] ^ key;
    }
    return;
}


void StubEntry() {
    wchar_t* procName = (wchar_t*)L"encryptme.exe";
    DWORD procId = GetProcId(procName);
    uintptr_t base = GetBaseAddress(procId, procName);

    ADDRESS_INFO addrInfo;
    find_Addrs(&addrInfo, procName);

    printf("GOT ADDRINFO STRUCT\n");
    printf("addrInfo->fileCodeSize:  %d\n", addrInfo.fileCodeSize);
    printf("addrInfo->fileCodeOffset:  %p\n", addrInfo.fileCodeOffset);
    printf("addrInfo->modBase:  %p\n", addrInfo.modBase);
    printf("addrInfo->moduleCodeOffset: %d\n\n\n", addrInfo.moduleCodeOffset);

    uintptr_t code_base = (addrInfo.modBase + addrInfo.moduleCodeOffset);
    uintptr_t code_size = addrInfo.fileCodeSize;

    decryptCodeSection(code_base, code_size, KEY);
    printf("Decrypted code section ----> Attempting to enter main()\n");
    main();
    return;
}

#pragma code_seg(".stub")






// .stub SECTION----------------------------------------------


