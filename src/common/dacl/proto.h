#ifndef H_SRC_COMMON_DACL_PROTO_H
#define H_SRC_COMMON_DACL_PROTO_H

#include <optional>
#include "common/dacl/dacl.h"

namespace dacl::proto {
struct Status {
    bool service_running;
};

std::optional<Status> GetStatus();
bool Set(const dacl::Rule &rule);
}  // namespace dacl::proto

#endif  // H_SRC_COMMON_DACL_PROTO_H
