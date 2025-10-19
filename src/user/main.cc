#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <string_view>
#include <stack>

#include "interpreter.h"
#include "utils/alias.h"

int main(int argc, char **argv) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    std::stack<std::string_view> args{};

    for (int i = argc - 1; i > 0; i--) {
        args.emplace(argv[i]);
    }

    if (!interpreter::Process(args)) {
        return 1;
    }

    return 0;
}
