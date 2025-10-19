#ifndef H_SRC_UTILS_HEX_H
#define H_SRC_UTILS_HEX_H

#include <vector>
#include <cstdint>
#include <string>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace hex_diff {

// ANSI colors (red for differences)
static constexpr const char *RED = "\x1b[31m";
static constexpr const char *DIM = "\x1b[2m";
static constexpr const char *RESET = "\x1b[0m";

static inline std::string to_hex(uint8_t b) {
    std::ostringstream oss;
    oss << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
        << int(b);
    return oss.str();
}

static inline char to_ascii(uint8_t b) {
    return (b >= 32 && b < 127) ? static_cast<char>(b) : '.';
}

/**
 * Print a visual hex diff of two byte buffers.
 *
 * @param a, b            buffers to compare
 * @param bytes_per_row   bytes per row (commonly 16)
 * @param color           highlight differences with ANSI color
 * @param skip_equal_rows collapse consecutive equal rows ("...") if true
 */
inline void PrintByteDiff(const std::vector<uint8_t> &a,
                          const std::vector<uint8_t> &b,
                          std::size_t bytes_per_row = 16, bool color = true,
                          bool skip_equal_rows = true) {
    const std::size_t max_len = std::max(a.size(), b.size());
    if (max_len == 0) {
        std::cout << "(both buffers are empty)\n";
        return;
    }

    std::size_t total_diffs = 0;
    std::size_t skipped_rows = 0;

    // Header
    std::cout << "Compare: A(" << a.size() << " bytes) vs B(" << b.size()
              << " bytes)\n";

    for (std::size_t base = 0; base < max_len; base += bytes_per_row) {
        const std::size_t row_end = std::min(base + bytes_per_row, max_len);

        // Is this whole row equal?
        bool row_equal = true;
        for (std::size_t i = base; i < row_end; ++i) {
            bool inA = i < a.size();
            bool inB = i < b.size();
            if (!inA || !inB || (inA && inB && a[i] != b[i])) {
                row_equal = false;
                break;
            }
        }

        if (row_equal && skip_equal_rows) {
            ++skipped_rows;
            continue;
        }
        if (skipped_rows > 0) {
            std::cout << "          ... (" << skipped_rows
                      << " equal rows hidden) ...\n";
            skipped_rows = 0;
        }

        // Build row strings
        std::ostringstream ahex, bhex, marks, aasc, basc;

        auto append_gap = [&](std::size_t j) {
            ahex << ' ';
            bhex << ' ';
            marks << ' ';
            if (bytes_per_row == 16 &&
                j == 7) {  // extra gap in the middle (8+8)
                ahex << ' ';
                bhex << ' ';
                marks << ' ';
            }
        };

        for (std::size_t j = 0; j < bytes_per_row; ++j) {
            std::size_t i = base + j;
            bool inA = i < a.size();
            bool inB = i < b.size();

            bool diff = false;
            std::string ah = "  ";  // placeholder if byte missing
            std::string bh = "  ";

            char aa = ' ';
            char ba = ' ';

            if (inA) {
                ah = to_hex(a[i]);
                aa = to_ascii(a[i]);
            }
            if (inB) {
                bh = to_hex(b[i]);
                ba = to_ascii(b[i]);
            }

            diff = (!inA || !inB) ? true : (a[i] != b[i]);
            if (diff) ++total_diffs;

            // A hex (with optional highlight)
            if (color && diff)
                ahex << RED << ah << RESET;
            else
                ahex << ah;

            // B hex
            if (color && diff)
                bhex << RED << bh << RESET;
            else
                bhex << bh;

            // ASCII
            aasc << aa;
            basc << ba;

            append_gap(j);
        }

        // Print row
        std::cout << std::setw(8) << std::setfill('0') << std::hex
                  << std::uppercase << base << std::dec << std::setfill(' ')
                  << "  "
                  << "A: " << ahex.str() << "  |  "
                  << "B: " << bhex.str() << "\n";
    }

    std::cout << "Total differing bytes: " << total_diffs << "\n";
}

}  // namespace hex_diff

#endif  // H_SRC_UTILS_HEX_H
