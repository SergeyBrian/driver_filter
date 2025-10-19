#ifndef H_SRC_UTILS_STRCONV_H
#define H_SRC_UTILS_STRCONV_H

#include <algorithm>
#include <string>
#include <stdexcept>
#include <algorithm>

#include "utils/alias.h"

namespace utils::strconv {
static const std::string alphabet =
    "0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz";

inline std::string to_base(u64 value, size_t base = 61) {
    if (base < 2) throw std::invalid_argument("Alphabet too small");
    if (base >= alphabet.size()) throw std::invalid_argument("Base too big");

    std::string result;
    do {
        result.push_back(alphabet[value % base]);
        value /= base;
    } while (value > 0);

    std::ranges::reverse(result);
    return result;
}

std::string to_utf8(const wchar_t *wide);
}  // namespace utils::strconv

#endif  // H_SRC_UTILS_STRCONV_H
