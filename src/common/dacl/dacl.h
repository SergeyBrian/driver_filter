#ifndef H_SRC_COMMON_DACL_DACL_H
#define H_SRC_COMMON_DACL_DACL_H

#include "user.h"
#include "utils/alias.h"

namespace dacl {

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
}  // namespace dacl

#endif  // H_SRC_COMMON_DACL_DACL_H
