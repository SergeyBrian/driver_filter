#include <charconv>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <optional>
#include <iostream>

#include "log.h"

namespace utils::ini {
namespace fs = std::filesystem;
using KvMap = std::unordered_map<std::string, std::string>;

static inline std::string trim(std::string_view sv) {
    const auto isspace_ = [](char c) { return std::isspace(c); };
    size_t b = 0, e = sv.size();
    while (b < e && isspace_(sv[b])) ++b;
    while (e > b && isspace_(sv[e - 1])) --e;
    return std::string(sv.substr(b, e - b));
}

static inline std::string unescape(std::string_view sv) {
    std::string out;
    out.reserve(sv.size());
    for (size_t i = 0; i < sv.size(); ++i) {
        char c = sv[i];
        if (c == '\\' && i + 1 < sv.size()) {
            char n = sv[++i];
            switch (n) {
                case 'n':
                    out.push_back('\n');
                    break;
                case 't':
                    out.push_back('\t');
                    break;
                case '\\':
                    out.push_back('\\');
                    break;
                case '=':
                    out.push_back('=');
                    break;
                default:
                    out.push_back(n);
                    break;
            }
        } else
            out.push_back(c);
    }
    return out;
}

static inline std::string escape(std::string_view sv) {
    std::string out;
    out.reserve(sv.size());
    for (char c : sv) {
        switch (c) {
            case '\n':
                out += "\\n";
                break;
            case '\t':
                out += "\\t";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '=':
                out += "\\=";
                break;
            default:
                out.push_back(c);
                break;
        }
    }
    return out;
}

inline bool load_kv_file(const fs::path &path, KvMap &out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;

    std::string line, section;
    while (std::getline(in, line)) {
        auto sv = std::string_view(line);
        auto s = trim(sv);
        if (s.empty() || s[0] == '#' || s[0] == ';') continue;

        if (s.front() == '[' && s.back() == ']' && s.size() >= 2) {
            section = trim(std::string_view(s).substr(1, s.size() - 2));
            continue;
        }

        auto pos = s.find('=');
        if (pos == std::string::npos) {
            continue;
        }
        std::string key = trim(std::string_view(s).substr(0, pos));
        std::string val = trim(std::string_view(s).substr(pos + 1));
        if (!section.empty()) key = section + "." + key;

        out[key] = unescape(val);
    }
    return true;
}

inline bool save_kv_file(const fs::path &path, const KvMap &kv) {
    fs::create_directories(path.parent_path());

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        return false;
    }

    for (const auto &[k, v] : kv) {
        out << k << "=" << escape(v) << "\n";
    }
    out.flush();
    if (!out.good()) return false;
    out.close();

    return true;
}

inline bool get_bool(const KvMap &kv, std::string_view key, bool def = false) {
    if (auto it = kv.find(std::string(key)); it != kv.end()) {
        std::string v;
        v.reserve(it->second.size());
        for (char c : it->second)
            v.push_back(static_cast<char>(std::tolower(c)));
        if (v == "1" || v == "true" || v == "yes" || v == "on") return true;
        if (v == "0" || v == "false" || v == "no" || v == "off") return false;
    }
    return def;
}
template <class Int>
inline Int get_int(const KvMap &kv, std::string_view key, Int def = Int{}) {
    if (auto it = kv.find(std::string(key)); it != kv.end()) {
        Int x{};
        auto sv = std::string_view(it->second);
        auto *b = sv.data();
        auto *e = sv.data() + sv.size();
        if (std::from_chars(b, e, x).ec == std::errc{}) return x;
    }
    return def;
}
inline std::string get_str(const KvMap &kv, std::string_view key,
                           std::string def = {}) {
    if (auto it = kv.find(std::string(key)); it != kv.end()) return it->second;
    return def;
}
}  // namespace utils::ini
