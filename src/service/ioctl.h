#ifndef H_SRC_SERVICE_IOCTL_H
#define H_SRC_SERVICE_IOCTL_H

#include <string>

#include "common/dacl/dacl.h"
#include "common/dacl/user.h"

namespace ioctl {
std::string GetStatus();
bool UpdateRule(const dacl::SummarizedRule &rule);
bool DeleteRule(const std::string &path, const dacl::user::User &user);
bool ToggleNotifier(bool start);
}  // namespace ioctl

#endif  // H_SRC_SERVICE_IOCTL_H
