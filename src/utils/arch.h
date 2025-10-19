#ifndef H_SRC_UTILS_ARCH_H
#define H_SRC_UTILS_ARCH_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <optional>
#include <string>

#include "alias.h"
#include "utils/defer.h"

namespace utils {
enum class Arch : u8 { X86, X64, ARM64, Unknown };

static std::wstring normalize_system32_path(std::wstring p) {
    BOOL wow = FALSE;
    if (IsWow64Process(GetCurrentProcess(), &wow) && wow) {
        const std::wstring needle = L"\\System32\\";
        if (auto pos = p.find(needle); pos != std::wstring::npos) {
            p.replace(pos, needle.size(), L"\\Sysnative\\");
        }
    }
    return p;
}

inline std::optional<Arch> DetectArch(std::wstring path) {
    path = normalize_system32_path(std::move(path));

    HANDLE h =
        CreateFileW(path.c_str(), GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return std::nullopt;

    HANDLE map = CreateFileMappingW(h, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!map) {
        CloseHandle(h);
        return std::nullopt;
    }

    auto base =
        static_cast<const BYTE *>(MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0));
    if (!base) {
        CloseHandle(map);
        CloseHandle(h);
        return std::nullopt;
    }

    defer {
        UnmapViewOfFile(base);
        CloseHandle(map);
        CloseHandle(h);
    };

    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return std::nullopt;
    }

    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return std::nullopt;
    }

    WORD mach = nt->FileHeader.Machine;
    WORD magic = nt->OptionalHeader.Magic;  // 0x10B = PE32, 0x20B = PE32+

    Arch a = Arch::Unknown;
    if (mach == IMAGE_FILE_MACHINE_AMD64 && magic == 0x20B)
        a = Arch::X64;
    else if (mach == IMAGE_FILE_MACHINE_I386 && magic == 0x10B)
        a = Arch::X86;
    else if (mach == IMAGE_FILE_MACHINE_ARM64 && magic == 0x20B)
        a = Arch::ARM64;

    return a;
}
}  // namespace utils

#endif  // H_SRC_UTILS_ARCH_H
