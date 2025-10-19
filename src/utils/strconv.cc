#include "strconv.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

namespace utils::strconv {
std::string to_utf8(const wchar_t *wide) {
    if (!wide) return {};
    int size_needed =
        WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
    if (size_needed <= 1) return {};
    std::string result(usize(size_needed - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, result.data(), size_needed,
                        nullptr, nullptr);
    return result;
}
}  // namespace utils::strconv
