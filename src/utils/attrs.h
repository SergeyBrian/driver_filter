#pragma once

#if defined(__clang__)
#define PRINTF_LIKE(fmt, first) __attribute__((format(printf, fmt, first)))
#else
#define PRINTF_LIKE(fmt, first)
#endif
