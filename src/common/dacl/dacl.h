#ifndef H_SRC_COMMON_DACL_DACL_H
#define H_SRC_COMMON_DACL_DACL_H

#include <string>
#include <vector>

#include "utils/alias.h"
#include "rule.h"

namespace dacl {
using ::SummarizedRule;

struct Rule {
    int id{};
    enum class Type : u8 { Allow, Deny } type;
    enum class Permission : u8 {
        None = 0,
        Read = 1u << 0,
        Write = 1u << 1,
        Delete = 1u << 2,
        All = Read | Write | Delete,
    };
    u8 access_mask;
    std::string path;
    std::string user;
};

bool PrepareRule(Rule &rule);
SummarizedRule Summarize(const std::vector<Rule> &rules);
}  // namespace dacl
#endif  // H_SRC_COMMON_DACL_DACL_H
