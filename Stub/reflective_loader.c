#include <windows.h>
#include <stdio.h>

#ifndef IMAGE_REL_BASED_DIR64
#define IMAGE_REL_BASED_DIR64 10
#endif

BOOL ReflectiveLoader(LPVOID pPE) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("[*] ReflectiveLoader started\n");
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pPE;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Invalid DOS signature\n");
        return FALSE;
    }

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pPE + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Invalid NT signature\n");
        return FALSE;
    }
    printf("[*] Parsed headers\n");


    // try preferred base first fall back to anywhere
    LPVOID pBase = VirtualAlloc(
        (LPVOID)(ULONG_PTR)pNt->OptionalHeader.ImageBase,
        pNt->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    );
    if (!pBase) {
        pBase = VirtualAlloc(NULL, pNt->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    if (!pBase) {
        printf("[-] VirtualAlloc failed\n");
        return FALSE;
    }
    printf("[*] Allocated memory at %p\n", pBase);

    // copy headers

    memcpy(pBase, pPE, pNt->OptionalHeader.SizeOfHeaders);

    // map sections
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSec[i].SizeOfRawData == 0) continue;
        LPVOID dst = (BYTE*)pBase + pSec[i].VirtualAddress;
        LPVOID src = (BYTE*)pPE   + pSec[i].PointerToRawData;
        memcpy(dst, src, pSec[i].SizeOfRawData);
    }
    printf("[*] Copied sections\n");

    // base relocations

    DWORD_PTR delta = (DWORD_PTR)pBase - (DWORD_PTR)pNt->OptionalHeader.ImageBase;
    if (delta != 0) {
        DWORD rva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        if (rva) {
            PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pBase + rva);
            while (pReloc->VirtualAddress) {
                DWORD count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* pEntry = (WORD*)(pReloc + 1);
                for (DWORD i = 0; i < count; i++) {
                    if ((pEntry[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                        ULONG_PTR* ptr = (ULONG_PTR*)((BYTE*)pBase + pReloc->VirtualAddress + (pEntry[i] & 0xFFF));
                        *ptr += delta;
                    } else if ((pEntry[i] >> 12) == IMAGE_REL_BASED_HIGHLOW) {
                        DWORD* ptr = (DWORD*)((BYTE*)pBase + pReloc->VirtualAddress + (pEntry[i] & 0xFFF));
                        *ptr += (DWORD)delta;
                    }
                }
                pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pReloc + pReloc->SizeOfBlock);
            }
        }
    }
    printf("[*] Processed relocations\n");

    // resolve iat

    DWORD importRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importRVA) {
        PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pBase + importRVA);
        while (pImport->Name) {
            char* dllName = (char*)((BYTE*)pBase + pImport->Name);
            HMODULE hMod = LoadLibraryA(dllName);
            if (!hMod) { pImport++; continue; }

            PIMAGE_THUNK_DATA pOrig = (PIMAGE_THUNK_DATA)((BYTE*)pBase +
                (pImport->OriginalFirstThunk ? pImport->OriginalFirstThunk : pImport->FirstThunk));
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)pBase + pImport->FirstThunk);

            while (pOrig->u1.AddressOfData) {
                if (IMAGE_SNAP_BY_ORDINAL(pOrig->u1.Ordinal)) {
                    ULONG_PTR fn = (ULONG_PTR)GetProcAddress(hMod, (LPCSTR)IMAGE_ORDINAL(pOrig->u1.Ordinal));
                    pThunk->u1.Function = fn;
                    printf("    [+] Ordinal %d -> %p\n", IMAGE_ORDINAL(pOrig->u1.Ordinal), (void*)fn);
                } else {
                    PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pBase + pOrig->u1.AddressOfData);
                    ULONG_PTR fn = (ULONG_PTR)GetProcAddress(hMod, (LPCSTR)pName->Name);
                    pThunk->u1.Function = fn;
                    printf("    [+] %s -> %p\n", pName->Name, (void*)fn);
                }
                pOrig++;
                pThunk++;
            }
            pImport++;
        }
    }
    printf("[*] Resolved IAT\n");

    // call entry point
    typedef void (*EP_t)(void);
    EP_t ep = (EP_t)((BYTE*)pBase + pNt->OptionalHeader.AddressOfEntryPoint);
    printf("[*] Calling entry point at %p...\n", ep);
    ep();
    printf("[*] Returned from entry point\n");

    return TRUE;
}
