#include <windows.h>

void __stdcall EntryPoint() {
    MessageBoxA(NULL, "PE2Shellcode executed successfully!\nDisk footprint: ZERO", "PE2Shellcode - Payload", MB_OK | MB_ICONINFORMATION);
    ExitProcess(0);
}
