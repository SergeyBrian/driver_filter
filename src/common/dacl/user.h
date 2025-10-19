#ifndef H_SRC_COMMON_DACL_USER_H
#define H_SRC_COMMON_DACL_USER_H

#include <string>
#include <vector>

namespace dacl::user {

struct User {
    std::string name;
    std::string sid;
};

std::vector<User> List();

}  // namespace dacl::user

#endif  // H_SRC_COMMON_DACL_USER_H
