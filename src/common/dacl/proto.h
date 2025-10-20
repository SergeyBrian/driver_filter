#ifndef H_SRC_COMMON_DACL_PROTO_H
#define H_SRC_COMMON_DACL_PROTO_H

#include <optional>
#include "common/dacl/dacl.h"

namespace dacl::proto {
struct Status {
    bool service_running;
    bool driver_running;
};

std::optional<Status> GetStatus();
bool Set(dacl::Rule &rule);
bool Del(const dacl::Rule &rule);
std::vector<dacl::Rule> GetRules();
}  // namespace dacl::proto

#endif  // H_SRC_COMMON_DACL_PROTO_H
