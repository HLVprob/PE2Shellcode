# PE2Shellcode

[![LANG](https://img.shields.io/badge/LANGUAGE-555555?style=for-the-badge)![C](https://img.shields.io/badge/-%20-%2300599C?style=for-the-badge&logo=c&logoColor=white)](#)
[![LANG](https://img.shields.io/badge/LANGUAGE-555555?style=for-the-badge)![C++](https://img.shields.io/badge/-%20-%2300599C?style=for-the-badge&logo=cplusplus&logoColor=white)](#)
[![PLATFORM](https://img.shields.io/badge/PLATFORM-555555?style=for-the-badge)![Windows](https://img.shields.io/badge/-%20-%230078D4?style=for-the-badge&logo=microsoft&logoColor=white)](#)
[![BUILD](https://img.shields.io/badge/BUILD-555555?style=for-the-badge)![GCC](https://img.shields.io/badge/-%20-%23e34c26?style=for-the-badge&logo=gnu&logoColor=white)](#)
[![BUILD](https://img.shields.io/badge/BUILD-555555?style=for-the-badge)![NASM](https://img.shields.io/badge/-%20-%23141414?style=for-the-badge&logo=linux&logoColor=white)](#)


A reflective PE loader that converts a compiled Windows executable into position-independent shellcode that runs entirely in memory.

> [!WARNING]
> This project is intended for authorized red team operations and security research only. Running this against systems you do not own is illegal. The author is not responsible for any misuse.

## What it does

The builder prepends a PIC stub onto a target `.exe`. The resulting `.bin` can be mapped into any RWX memory region and executed — no OS loader involved.

The stub:
- walks the PEB to find `kernel32.dll` without calling `GetModuleHandle`
- resolves API addresses by comparing ROR13 hashes against the export table (no plaintext strings)
- maps the embedded PE sections into memory
- applies relocations and resolves the IAT
- jumps to the original entry point

## Layout

```
/Builder    - combines stub.bin + target.exe into payload.bin
/Stub       - PIC loader (pic_api_resolver.c) and x64 asm stub (loader.asm)
/Test       - simple messagebox target for verifying the chain
/Tester     - VirtualAlloc + CreateThread runner for payload.bin
```

## Build

Requires NASM (for the asm stub) and GCC/MSVC.

```
nasm -f bin Stub/loader.asm -o stub.bin
g++ Builder/main.cpp -o Builder.exe
Builder.exe stub.bin Test/messagebox.exe
Tester/shellcode_tester.exe payload.bin
```

## Techniques

| Technique | Purpose |
|---|---|
| PEB traversal | locate kernel32 without imports |
| ROR13 hashing | avoid plaintext API/DLL strings |
| Reflective loading | map PE sections manually |
| In-memory execution | zero disk footprint |
