
#pragma once
#include <string>
#include <unordered_map>
#include <cstdint>

// Sygnatury do szukania (IDA-style patterns)
// Zaktualizuj je po każdym updacie Roblox

struct Signature {
    std::string name;
    std::string pattern;
    int         extra_offset; // dodatkowy offset po znalezieniu wzorca
    bool        resolve_rip;  // czy rozwiązać RIP-relative
    int         rip_offset;   // offset do pola rel32
    int         instr_size;   // rozmiar instrukcji dla RIP
};

// Znane sygnatury Roblox (x64, aktualne na ~2024)
// Pattern scanning bazuje na sekcji .text modułu
inline const std::vector<Signature> SIGNATURES = {

    // DataModel — główny kontener gry
    {
        "DataModel",
        "48 8B 05 ? ? ? ? 48 85 C0 74 ? 48 8B 88",
        0, true, 3, 7
    },

    // ScriptContext — silnik Lua
    {
        "ScriptContext",
        "48 8B 0D ? ? ? ? E8 ? ? ? ? 48 85 C0 74 ? 48 8B 50 ? 48 8B 02",
        0, true, 3, 7
    },

    // TaskScheduler — scheduler zadań
    {
        "TaskScheduler",
        "48 89 05 ? ? ? ? EB ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 90",
        0, true, 3, 7
    },

    // RenderView — renderowanie
    {
        "RenderView",
        "48 8B 1D ? ? ? ? 4C 8B F2 4C 8B E9",
        0, true, 3, 7
    },

    // Lua_State — aktywny stan Lua
    {
        "LuaState",
        "48 8B 15 ? ? ? ? 48 85 D2 74 ? 48 8B 0A",
        0, true, 3, 7
    },

    // Print (rbxprint) — funkcja drukowania w Lua
    {
        "rbxprint",
        "48 89 5C 24 ? 55 56 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05",
        0, false, 0, 0
    },

    // Lua_getfield
    {
        "lua_getfield",
        "40 55 53 56 57 41 54 41 56 41 57 48 8D AC 24",
        0, false, 0, 0
    },

    // Lua_setfield
    {
        "lua_setfield",
        "48 89 5C 24 ? 48 89 74 24 ? 55 57 41 56 48 8D 6C 24",
        0, false, 0, 0
    },

    // Lua_pushvalue
    {
        "lua_pushvalue",
        "48 83 EC 28 48 8B 51 ? 48 8B 41 ? 44 8B 42",
        0, false, 0, 0
    },

};
