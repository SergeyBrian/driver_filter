#ifndef H_SRC_COMMON_DACL_INTERNAL_H
#define H_SRC_COMMON_DACL_INTERNAL_H

#include "common/dacl/dacl.h"

namespace dacl::proto::internal {
constexpr const wchar_t *ServiceName = L"DriverFilterSvc";
constexpr const wchar_t *PipeName = L"\\\\.\\pipe\\DriverFilterConfigPipe";

constexpr const char *PingMessage = "ping";
constexpr const char *PongMessage = "pong";
constexpr const char *SetMessage = "set";
constexpr const char *DelMessage = "del";
constexpr const char *GetRulesMessage = "getrules";

constexpr const char *RespOk = "ok";
constexpr const char *RespError = "error";

constexpr const char *RespUnknownRequest = "unknown_req";

bool EncodeRule(const dacl::Rule &rule, void *buf, usize *result_len,
                bool with_set = true);
dacl::Rule DecodeRule(const void *buf, usize *used_len = nullptr);

bool EncodeDelRule(const std::string &path, void *buf, usize *result_len);
std::string DecodeDelRule(const void *buf);
}  // namespace dacl::proto::internal

#endif  // H_SRC_COMMON_DACL_INTERNAL_H
