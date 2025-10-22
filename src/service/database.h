#ifndef H_SRC_SERVICE_DATABASE_H
#define H_SRC_SERVICE_DATABASE_H

#include <optional>

#include "common/dacl/dacl.h"

namespace database {
bool Connect();
void Disconnect();

bool InsertRule(const dacl::Rule &rule);
bool DeleteRule(const dacl::Rule &path);
std::vector<dacl::Rule> GetRules(const dacl::Rule &in);
std::optional<dacl::Rule> GetRule(int id);
}  // namespace database

#endif  // H_SRC_SERVICE_DATABASE_H
