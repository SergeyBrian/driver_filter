#ifndef H_SRC_SERVICE_IOCTL_H
#define H_SRC_SERVICE_IOCTL_H

#include <string>

#include "common/dacl/dacl.h"

namespace ioctl {
std::string GetStatus();
bool UpdateRule(const dacl::SummarizedRule &rule);
}  // namespace ioctl

#endif  // H_SRC_SERVICE_IOCTL_H
