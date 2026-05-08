#include <iostream>
#include <fstream>
#include <vector>
#include <windows.h>

// include the loader directly so linkage stays simple
#include "../Stub/reflective_loader.c"

static bool readFile(const std::string& path, std::vector<unsigned char>& buf) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return false;
    buf.resize((size_t)f.tellg());
    f.seekg(0);
    return (bool)f.read((char*)buf.data(), buf.size());
}

int main(int argc, char* argv[]) {
    std::string path = (argc >= 2) ? argv[1] : "payload.bin";

    std::vector<unsigned char> pe;
    if (!readFile(path, pe)) {
        std::cerr << "[!] could not read: " << path << std::endl;
        return 1;
    }

    std::cout << "[+] read " << pe.size() << " bytes" << std::endl;
    std::cout << "[+] calling reflective loader..." << std::endl;

    BOOL ok = ReflectiveLoader(pe.data());
    std::cout << (ok ? "[+] done" : "[!] loader returned FALSE") << std::endl;
    return ok ? 0 : 1;
}
