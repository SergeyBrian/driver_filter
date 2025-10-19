#ifndef H_SRC_SERVICE_DATABASE_H
#define H_SRC_SERVICE_DATABASE_H

#include "common/dacl/dacl.h"
namespace database {
bool Connect();
void Disconnect();
bool InsertRule(const dacl::Rule &rule);
bool DeleteRule(const std::string &path);
std::vector<dacl::Rule> GetRules();
}  // namespace database

#endif  // H_SRC_SERVICE_DATABASE_H
