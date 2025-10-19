#ifndef H_SRC_USER_INTERPRETER_H
#define H_SRC_USER_INTERPRETER_H

#include <stack>
#include <string_view>

namespace interpreter {
bool Process(std::stack<std::string_view> args);
}

#endif  // H_SRC_USER_INTERPRETER_H
