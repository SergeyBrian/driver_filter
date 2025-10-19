#ifndef H_SRC_UTILS_ENUM_H
#define H_SRC_UTILS_ENUM_H

#include <algorithm>
#include <cctype>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "utils/log.h"

namespace utils::enum_select {

struct Options {
    bool case_insensitive = true;
    bool allow_prefix = false;
};

inline char ascii_tolower(char c) {
    auto uc = static_cast<unsigned char>(c);
    if (uc >= 'A' && uc <= 'Z') uc = static_cast<unsigned char>(uc - 'A' + 'a');
    return static_cast<char>(uc);
}

inline bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (ascii_tolower(a[i]) != ascii_tolower(b[i])) return false;
    return true;
}

inline bool istarts_with(std::string_view s, std::string_view prefix) {
    if (prefix.size() > s.size()) return false;
    for (size_t i = 0; i < prefix.size(); ++i)
        if (ascii_tolower(s[i]) != ascii_tolower(prefix[i])) return false;
    return true;
}

template <class E, class Range>
std::optional<E> select(std::string_view input, const Range &mapping,
                        Options opt = {}) {
    for (const auto &kv : mapping) {
        const std::string_view key = kv.first;
        const E value = kv.second;

        const bool match =
            opt.case_insensitive
                ? (opt.allow_prefix ? istarts_with(key, input)
                                    : iequals(input, key))
                : (opt.allow_prefix ? key.starts_with(input) : input == key);

        if (match) return value;
    }

    logger::Error("Option '{}' not found.\nAvailable options:", input);
    for (const auto &kv : mapping) {
        logger::Error("\t- {}", kv.first);
    }
    return std::nullopt;
}
}  // namespace utils::enum_select

#endif  // H_SRC_UTILS_ENUM_H
