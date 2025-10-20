#include "dacl.h"
#include "utils/strconv.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "utils/log.h"

namespace dacl {
static std::wstring NormalizeToNtPath(const std::wstring &input) {
    std::vector<wchar_t> tmp(32768);
    DWORD n =
        ExpandEnvironmentStringsW(input.c_str(), tmp.data(), DWORD(tmp.size()));
    std::wstring expanded =
        (n && n < tmp.size()) ? std::wstring(tmp.data(), n - 1) : input;
    std::vector<wchar_t> full(32768);
    DWORD m = GetFullPathNameW(expanded.c_str(), DWORD(full.size()),
                               full.data(), nullptr);
    std::wstring abs =
        (m && m < full.size()) ? std::wstring(full.data(), m) : expanded;

    DWORD attrs = GetFileAttributesW(abs.c_str());
    bool isDir = (attrs != INVALID_FILE_ATTRIBUTES) &&
                 (attrs & FILE_ATTRIBUTE_DIRECTORY);

    HANDLE h = CreateFileW(
        abs.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, (isDir ? FILE_FLAG_BACKUP_SEMANTICS : 0), nullptr);

    if (h == INVALID_HANDLE_VALUE) {
        return {};
    }

    std::vector<wchar_t> buf(32768);
    DWORD got =
        GetFinalPathNameByHandleW(h, buf.data(), DWORD(buf.size()),
                                  FILE_NAME_NORMALIZED | VOLUME_NAME_NT);
    CloseHandle(h);

    if (!got || got >= buf.size()) return L"";
    std::wstring nt = std::wstring(buf.data(), got);

    if (nt.size() > 1 && nt.back() == L'\\') nt.pop_back();

    return nt;
}

bool PrepareRule(Rule &rule) {
    std::wstring normalized_path =
        NormalizeToNtPath({rule.path.begin(), rule.path.end()});
    if (normalized_path.empty()) {
        logger::Error("Invalid path");
        return false;
    }

    rule.path = utils::strconv::to_utf8(normalized_path.c_str());

    if (!dacl::user::Get(rule.user)) {
        logger::Error("User '{}' not found", rule.user);
        return false;
    }

    return true;
}
}  // namespace dacl
