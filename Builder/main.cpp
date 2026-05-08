#include <iostream>
#include <fstream>
#include <vector>

static bool readFile(const std::string& path, std::vector<unsigned char>& buf) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return false;
    buf.resize((size_t)f.tellg());
    f.seekg(0);
    return (bool)f.read((char*)buf.data(), buf.size());
}

static bool writeFile(const std::string& path, const std::vector<unsigned char>& buf) {
    std::ofstream f(path, std::ios::binary);
    if (!f.is_open()) return false;
    f.write((const char*)buf.data(), buf.size());
    return f.good();
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " <stub.bin> <target.exe>" << std::endl;
        return 1;
    }

    std::vector<unsigned char> stub, exe;

    if (!readFile(argv[1], stub)) {
        std::cerr << "[!] could not read stub: " << argv[1] << std::endl;
        return 1;
    }

    if (!readFile(argv[2], exe)) {
        std::cerr << "[!] could not read target: " << argv[2] << std::endl;
        return 1;
    }

    /* stub first then exe.
       in a real impl the stub would need to know the exe offset,
       so you'd patch the exe size into a placeholder inside the stub */
    std::vector<unsigned char> payload;
    payload.insert(payload.end(), stub.begin(), stub.end());
    payload.insert(payload.end(), exe.begin(), exe.end());

    if (!writeFile("payload.bin", payload)) {
        std::cerr << "[!] failed to write payload.bin" << std::endl;
        return 1;
    }

    std::cout << "[+] payload.bin written (" << payload.size() << " bytes)" << std::endl;
    return 0;
}
