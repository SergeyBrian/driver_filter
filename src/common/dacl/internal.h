#ifndef H_SRC_COMMON_DACL_INTERNAL_H
#define H_SRC_COMMON_DACL_INTERNAL_H

#include "common/dacl/dacl.h"

namespace dacl::proto::internal {
constexpr const wchar_t *PipeName = L"\\\\.\\pipe\\DriverFilterConfigPipe";

constexpr const char *PingMessage = "ping";
constexpr const char *PongMessage = "pong";
constexpr const char *SetMessage = "set";

constexpr const char *RespUnknownRequest = "unknown_req";

bool EncodeRule(const dacl::Rule &rule, void *buf, usize *result_len);
dacl::Rule DecodeRule(void *buf);
}  // namespace dacl::proto::internal

#endif  // H_SRC_COMMON_DACL_INTERNAL_H
