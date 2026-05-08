#include <windows.h>

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _PEB_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;


// for ascii export names
__forceinline DWORD Ror13Hash(const char* str) {
    DWORD hash = 0;
    while (*str) {
        hash = (hash >> 13) | (hash << 19);
        hash += (unsigned char)*str;
        str++;
    }
    return hash;
}

__forceinline DWORD Ror13HashW(const WCHAR* str) {
    DWORD hash = 0;
    while (*str) {
        hash = (hash >> 13) | (hash << 19);
        WCHAR c = *str;
        if (c >= L'a' && c <= L'z') c -= 32;
        hash += (DWORD)c;
        str++;
    }
    return hash;
}

// KERNEL32.DLL ROR13 = 0x6E2BCA17
#ifdef _WIN64
PVOID GetKernel32Base() {
    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(*(PULONG_PTR)((PUCHAR)__readgsqword(0x60) + 0x18));
    PLIST_ENTRY pEntry = pLdr->InLoadOrderModuleList.Flink;

    while (pEntry != &pLdr->InLoadOrderModuleList) {
        PLDR_DATA_TABLE_ENTRY pMod = (PLDR_DATA_TABLE_ENTRY)pEntry;
        if (pMod->BaseDllName.Buffer && Ror13HashW(pMod->BaseDllName.Buffer) == 0x6E2BCA17)
            return pMod->DllBase;
        pEntry = pEntry->Flink;
    }
    return NULL;
}
#endif

FARPROC GetExportAddress(PVOID pBase, DWORD funcHash) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)((PUCHAR)pBase + pDos->e_lfanew);

    DWORD expRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRVA) return NULL;

    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)pBase + expRVA);
    PDWORD names = (PDWORD)((PUCHAR)pBase + pExp->AddressOfNames);
    PDWORD funcs = (PDWORD)((PUCHAR)pBase + pExp->AddressOfFunctions);
    PWORD  ords  = (PWORD) ((PUCHAR)pBase + pExp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
        char* name = (char*)((PUCHAR)pBase + names[i]);
        if (Ror13Hash(name) == funcHash)
            return (FARPROC)((PUCHAR)pBase + funcs[ords[i]]);
    }
    return NULL;
}

/*
    example usage:

    PVOID k32 = GetKernel32Base();

    // LoadLibraryA ROR13 = 0xEC0E4E8E
    typedef HMODULE(WINAPI* fnLoadLibraryA)(LPCSTR);
    fnLoadLibraryA pLoadLibrary = (fnLoadLibraryA)GetExportAddress(k32, 0xEC0E4E8E);
    HMODULE hUser32 = pLoadLibrary("user32.dll");
*/
