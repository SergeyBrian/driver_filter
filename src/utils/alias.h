#ifndef ALIAS_H
#define ALIAS_H

#include <cstddef>
#include <cstdint>

using byte = uint8_t;

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;

using usize = u64;

constexpr u8 u8_max = 0xFF;
constexpr u16 u16_max = 0xFFFF;
constexpr u32 u32_max = 0xFFFFFFFF;
constexpr u64 u64_max = 0xFFFFFFFFFFFFFFFF;

constexpr byte byte_max = u8_max;
constexpr usize usize_max = static_cast<usize>(-1);

using i8 = int8_t;
using i16 = int16_t;
using i32 = int32_t;
using i64 = int64_t;

using ptr_diff = std::ptrdiff_t;
using ptr_int = uintptr_t;

inline auto operator""_KB(u64 const x) {
    return static_cast<usize>(1024) * static_cast<usize>(x);
}

inline auto operator""_MB(u64 const x) {
    return static_cast<usize>(1024 * 1024) * static_cast<usize>(x);
}

inline auto operator""_GB(u64 const x) {
    return static_cast<usize>(1024 * 1024 * 1024) * static_cast<usize>(x);
}

#endif
