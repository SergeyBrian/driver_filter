#include "internal.h"

namespace dacl::proto::internal {
bool EncodeRule(const dacl::Rule &rule, void *buf, usize *result_len) {
    if (!buf) {
        return false;
    }

    auto ptr = reinterpret_cast<char *>(buf);

    *reinterpret_cast<int *>(ptr) = rule.id;
    ptr += sizeof(rule.id);

    *reinterpret_cast<Rule::Type *>(ptr) = rule.type;
    ptr += sizeof(rule.type);

    *reinterpret_cast<decltype(Rule::access_mask) *>(ptr) = rule.access_mask;
    ptr += sizeof(rule.access_mask);

    {
        usize path_str_size = rule.path.size() + 1;
        memcpy(ptr, rule.path.data(), path_str_size);
        ptr += path_str_size;
    }

    {
        usize user_str_size = rule.user.size() + 1;
        memcpy(ptr, rule.user.data(), user_str_size);
        ptr += user_str_size;
    }

    {
        usize sid_str_size = rule.sid.size() + 1;
        memcpy(ptr, rule.sid.data(), sid_str_size);
        ptr += sid_str_size;
    }

    if (result_len != nullptr) {
        *result_len = usize(reinterpret_cast<char *>(ptr) -
                            reinterpret_cast<char *>(buf));
    }

    /**msg_size = *result_len;*/

    return true;
}

dacl::Rule DecodeRule(const void *buf, usize *used_len) {
    if (!buf) return {};
    auto ptr = reinterpret_cast<const char *>(buf);

    dacl::Rule rule{};

    memcpy(&rule.id, ptr, sizeof(rule.id));
    ptr += sizeof(rule.id);

    memcpy(&rule.type, ptr, sizeof(rule.type));
    ptr += sizeof(rule.type);

    memcpy(&rule.access_mask, ptr, sizeof(rule.access_mask));
    ptr += sizeof(rule.access_mask);

    rule.path = ptr;
    ptr += rule.path.size() + 1;

    rule.user = ptr;
    ptr += rule.user.size() + 1;

    rule.sid = ptr;
    ptr += rule.sid.size() + 1;

    if (used_len != nullptr) {
        *used_len = usize(ptr - reinterpret_cast<const char *>(buf));
    }

    return rule;
}
}  // namespace dacl::proto::internal
