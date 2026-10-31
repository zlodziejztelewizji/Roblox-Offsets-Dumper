
#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>
#include <sstream>
#include <optional>
#include <cstdint>
#include <algorithm>

namespace mem {

    // Konwersja WCHAR* -> std::string (ANSI)
    inline std::string wchar_to_string(const WCHAR* wstr) {
        if (!wstr) return {};
        int len = WideCharToMultiByte(CP_ACP, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
        if (len <= 0) return {};
        std::string result(len - 1, '\0');
        WideCharToMultiByte(CP_ACP, 0, wstr, -1, &result[0], len, nullptr, nullptr);
        return result;
    }

    // Pobiera PID i handle do procesu po nazwie
    struct ProcessInfo {
        DWORD  pid;
        HANDLE handle;
    };

    inline std::optional<ProcessInfo> open_process(const std::string& proc_name) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return std::nullopt;

        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);

        if (Process32FirstW(snap, &pe)) {
            do {
                if (proc_name == wchar_to_string(pe.szExeFile)) {
                    CloseHandle(snap);
                    HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
                    if (!h) return std::nullopt;
                    return ProcessInfo{ pe.th32ProcessID, h };
                }
            } while (Process32NextW(snap, &pe));
        }

        CloseHandle(snap);
        return std::nullopt;
    }

    // Zwraca bazowy adres modułu w procesie
    inline uintptr_t get_module_base(DWORD pid, const std::string& mod_name) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap == INVALID_HANDLE_VALUE) return 0;

        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);

        if (Module32FirstW(snap, &me)) {
            do {
                if (mod_name == wchar_to_string(me.szModule)) {
                    CloseHandle(snap);
                    return reinterpret_cast<uintptr_t>(me.modBaseAddr);
                }
            } while (Module32NextW(snap, &me));
        }

        CloseHandle(snap);
        return 0;
    }

    // Odczytuje wartość z pamięci procesu
    template <typename T>
    inline std::optional<T> read(HANDLE proc, uintptr_t addr) {
        T val{};
        SIZE_T bytes_read = 0;
        if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(addr), &val, sizeof(T), &bytes_read))
            return std::nullopt;
        return val;
    }

    // Parsuje wzorzec IDA-style ("48 8B ? ? 48 89")
    inline std::vector<std::pair<uint8_t, bool>> parse_pattern(const std::string& pattern) {
        std::vector<std::pair<uint8_t, bool>> result;
        std::istringstream ss(pattern);
        std::string token;

        while (ss >> token) {
            if (token == "?" || token == "??") {
                result.emplace_back(0x00, false); // wildcard
            } else {
                result.emplace_back(static_cast<uint8_t>(std::stoul(token, nullptr, 16)), true);
            }
        }
        return result;
    }

    // Pattern scan w regionie pamięci
    inline uintptr_t pattern_scan(HANDLE proc, uintptr_t base, size_t region_size, const std::string& pattern) {
        auto sig = parse_pattern(pattern);
        if (sig.empty()) return 0;

        const size_t chunk = 0x1000;
        std::vector<uint8_t> buf(chunk + sig.size());

        for (size_t offset = 0; offset < region_size; offset += chunk) {
            size_t to_read = (std::min)(chunk + sig.size(), region_size - offset);
            SIZE_T bytes_read = 0;

            if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(base + offset), buf.data(), to_read, &bytes_read))
                continue;

            for (size_t i = 0; i + sig.size() <= bytes_read; ++i) {
                bool match = true;
                for (size_t j = 0; j < sig.size(); ++j) {
                    if (sig[j].second && buf[i + j] != sig[j].first) {
                        match = false;
                        break;
                    }
                }
                if (match) return base + offset + i;
            }
        }

        return 0;
    }

    // Rozwiązuje RIP-relative adres (x64)
    inline uintptr_t resolve_rip(HANDLE proc, uintptr_t addr, int offset_field = 3, int instr_size = 7) {
        auto rel = read<int32_t>(proc, addr + offset_field);
        if (!rel) return 0;
        return addr + instr_size + static_cast<int64_t>(*rel);
    }

} // namespace mem
