#include <iostream>
#include <windows.h>
#include <string>

void ParsePEFile(const std::string& filePath) {
    HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] failed to open: " << filePath << std::endl;
        return;
    }

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        std::cerr << "[!] CreateFileMapping failed." << std::endl;
        CloseHandle(hFile);
        return;
    }

    LPVOID pBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pBase) {
        std::cerr << "[!] MapViewOfFile failed." << std::endl;
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return;
    }

    std::cout << "[+] mapped: " << filePath << std::endl;
    std::cout << "-------------------------------------------" << std::endl;

    PIMAGE_DOS_HEADER     pDos     = nullptr;
    PIMAGE_NT_HEADERS     pNt      = nullptr;
    PIMAGE_SECTION_HEADER pSection = nullptr;

    pDos = (PIMAGE_DOS_HEADER)pBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "[!] invalid DOS signature." << std::endl;
        goto cleanup;
    }

    pNt = (PIMAGE_NT_HEADERS)((DWORD_PTR)pBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "[!] invalid PE signature." << std::endl;
        goto cleanup;
    }

    std::cout << "[*] arch:       " << (pNt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ? "x64" : "x86") << std::endl;
    std::cout << "[*] entrypoint: 0x" << std::hex << pNt->OptionalHeader.AddressOfEntryPoint << std::endl;
    std::cout << "[*] imagebase:  0x" << std::hex << pNt->OptionalHeader.ImageBase << std::endl;
    std::cout << "-------------------------------------------" << std::endl;

    pSection = IMAGE_FIRST_SECTION(pNt);
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        char name[9] = { 0 };
        memcpy(name, pSection[i].Name, 8);
        std::cout << "  " << name
                  << "  va=0x"  << std::hex << pSection[i].VirtualAddress
                  << "  vs=0x"  << pSection[i].Misc.VirtualSize
                  << "  raw=0x" << pSection[i].SizeOfRawData
                  << std::endl;
    }

    // a loader would then resolve the iat, apply relocations, and jump to entrypoint

cleanup:
    if (pBase)    UnmapViewOfFile(pBase);
    if (hMapping) CloseHandle(hMapping);
    if (hFile && hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "usage: " << argv[0] << " <target.exe>" << std::endl;
        return 1;
    }
    ParsePEFile(argv[1]);
    return 0;
}
