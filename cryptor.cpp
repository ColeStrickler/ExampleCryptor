#include <Windows.h>
#include <iostream>


#define KEY 0x4
typedef struct _ADDRESS_INFO {
    uintptr_t modBase;
    uintptr_t moduleCodeOffset;
    uintptr_t fileCodeOffset;
    uintptr_t fileCodeSize;
} ADDRESS_INFO, * PADDRESS_INFO;


BYTE* getFileBase(char* filePath, DWORD* fileSize) {

    LPVOID fileData;
    HANDLE fileHandle = CreateFileA(filePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, NULL, NULL);
    *fileSize = GetFileSize(fileHandle, NULL);
    fileData = HeapAlloc(GetProcessHeap(), 0, *fileSize);
    ReadFile(fileHandle, fileData, *fileSize, NULL, NULL);
    CloseHandle(fileHandle);
    return (BYTE*)fileData;
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

void find_Addrs(LPVOID baseAddress, PADDRESS_INFO addr_info) {
    
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)baseAddress;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uintptr_t)baseAddress + (uintptr_t)dos->e_lfanew);
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






int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("[USAGE] ---> cryptor.exe <file to crypt>");
        exit(-1);
    }
    DWORD fileSize;
    ADDRESS_INFO addr_info;
    BYTE* base = getFileBase(argv[1], &fileSize);
    find_Addrs(base, &addr_info);

    printf("GOT ADDRINFO STRUCT\n");
    printf("addrInfo->fileCodeSize:  %d\n", addr_info.fileCodeSize);
    printf("addrInfo->fileCodeOffset:  %p\n", addr_info.fileCodeOffset);
    printf("addrInfo->modBase:  %p\n", addr_info.modBase);
    printf("addrInfo->moduleCodeOffset: %d\n\n\n", addr_info.moduleCodeOffset);



    BYTE* code_base = (BYTE*)(addr_info.fileCodeOffset + (uintptr_t)base);

    for (int i = 0; i < (int)addr_info.fileCodeSize; i++) {
        code_base[i] = code_base[i] ^ KEY;
    }
    HANDLE fHandle = CreateFileA(argv[1], GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, CREATE_ALWAYS, NULL, NULL);

    bool a = WriteFile(fHandle, base, fileSize, NULL, NULL);
    if (!a) {
        printf("FAILED: %d\n", GetLastError());
        exit(-1);
    }

    CloseHandle(fHandle);

}