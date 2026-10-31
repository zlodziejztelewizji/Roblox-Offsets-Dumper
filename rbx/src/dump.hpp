
#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <string>
#include <unordered_map>
#include <fstream>
#include <cstdint>
#include <cstdio>

// Prosta klasa do zapisu offsetów + JSON
class OffsetDump {
public:
    std::unordered_map<std::string, uintptr_t> offsets;
    std::string roblox_version;
    std::string dump_time;

    void add(const std::string& name, uintptr_t value) {
        offsets[name] = value;
    }

    bool save(const std::string& path) const {
        FILE* f = nullptr;
        fopen_s(&f, path.c_str(), "w");
        if (!f) return false;

        fprintf(f, "{\n");
        fprintf(f, "  \"version\": \"%s\",\n", roblox_version.c_str());
        fprintf(f, "  \"dump_time\": \"%s\",\n", dump_time.c_str());
        fprintf(f, "  \"offsets\": {\n");

        size_t i = 0;
        for (auto& [name, val] : offsets) {
            if (val)
                fprintf(f, "    \"%s\": \"0x%llX\"%s\n", name.c_str(), val, (++i < offsets.size() ? "," : ""));
            else
                fprintf(f, "    \"%s\": null%s\n", name.c_str(), (++i < offsets.size() ? "," : ""));
        }

        fprintf(f, "  }\n}\n");
        fclose(f);
        return true;
    }

    void print() const {
        printf("\n--- OFFSET DUMP ---\n");
        printf("Wersja  : %s\n", roblox_version.c_str());
        printf("Czas    : %s\n\n", dump_time.c_str());

        for (auto& [name, val] : offsets) {
            if (val)
                printf("  [+] %-20s 0x%llX\n", name.c_str(), val);
            else
                printf("  [-] %-20s NIE ZNALEZIONY\n", name.c_str());
        }
        printf("-------------------\n");
    }
};

inline std::string get_roblox_version() {
    char appdata[MAX_PATH]{};
    size_t len = 0;
    getenv_s(&len, appdata, sizeof(appdata), "LOCALAPPDATA");
    if (len == 0) return "unknown";

    std::string search = std::string(appdata) + "\\Roblox\\Versions\\version-*";
    WIN32_FIND_DATAA fd{};
    HANDLE h = FindFirstFileA(search.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return "unknown";
    std::string ver = fd.cFileName;
    FindClose(h);
    return ver;
}

inline std::string current_time_str() {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    char buf[64]{};
    sprintf_s(buf, "%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);
    return buf;
}
