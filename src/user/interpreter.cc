#include "interpreter.h"

#include <print>
#include <stack>
#include <utility>

#include "common/dacl/proto.h"
#include "common/dacl/user.h"
#include "common/dacl/dacl.h"

#include "utils/alias.h"
#include "utils/log.h"

namespace interpreter {
static void PrintHelp() {
    std::println("Usage: DriverFilter.exe <command> [params...]");
    std::println("\nAvailable commands:");

    std::println("\tset {{allow|deny}} <permissions> <path> <user>");
    std::println("\tlist {{users|rules}}");
    std::println("\tstatus");
    std::println("\tdelete <id>");

    std::println("\nAvailable permissions:");
    std::println("\tall");
    std::println("\t[r]ead");
    std::println("\t[w]rite");
    std::println("\t[d]elete");
}

enum class Command : u8 {
    Invalid,
    Set,
    List,
    Status,
    Delete,
};

static Command ParseCommand(std::string_view s) {
    if (s == "set") return Command::Set;
    if (s == "list") return Command::List;
    if (s == "status") return Command::Status;
    if (s == "delete") return Command::Delete;
    return Command::Invalid;
}

static bool HandleList(std::stack<std::string_view> &args) {
    if (args.empty()) {
        logger::Error("Not enough arguments");
        PrintHelp();
        return false;
    }

    const std::string_view &target = args.top();

    if (target == "users") {
        std::vector<dacl::user::User> users = dacl::user::List();
        for (const auto &user : users) {
            std::println("{}:\t{}", user.name, user.sid);
        }
    } else if (target == "rules") {
        std::vector<dacl::Rule> rules = dacl::proto::GetRules();
        if (rules.empty()) {
            std::println("No rules found");
            return false;
        }

        std::println("Active rules:");

        std::print("{:<4}  {:<50}  {:<20}  {:<6}  {:<8}\n", "Id", "Object",
                   "User", "Type", "Mask");

        for (const auto &r : rules) {
            std::print("{:<4}  {:<50}  {:<20}  {:<6}  0x{:08X}\n", r.id, r.path,
                       r.user, (r.type == dacl::Rule::Type::Allow) ? "A" : "D",
                       r.access_mask);
        }
    } else {
        logger::Error("Unknown list target `{}`", target);
        PrintHelp();
        return false;
    }

    return true;
}

static bool HandleStatus() {
    auto status = dacl::proto::GetStatus();
    if (!status) return false;
    std::println("Service running={}", status->service_running);
    std::println("Driver running={}", status->driver_running);

    return true;
}

static bool HandleSet(std::stack<std::string_view> &args) {
    auto check_args = [&args]() -> bool {
        if (args.empty()) {
            logger::Error("Not enough arguments");
            PrintHelp();
            return false;
        }
        return true;
    };
    if (!check_args()) return false;

    dacl::Rule rule{};

    if (args.top() == "allow") {
        rule.type = dacl::Rule::Type::Allow;
    } else if (args.top() == "deny") {
        rule.type = dacl::Rule::Type::Deny;
    } else {
        logger::Error("Invalid rule type `{}`", args.top());
        PrintHelp();
        return false;
    }
    {
        args.pop();
        if (!check_args()) return false;
    }

    if (args.top() == "all") {
        rule.access_mask = u8(dacl::Rule::Permission::All);
    } else {
        for (auto c : args.top()) {
            switch (c) {
                case 'r':
                    rule.access_mask |= u8(dacl::Rule::Permission::Read);
                    break;
                case 'w':
                    rule.access_mask |= u8(dacl::Rule::Permission::Write);
                    break;
                case 'd':
                    rule.access_mask |= u8(dacl::Rule::Permission::Delete);
                    break;
                default:
                    logger::Error("Unexpected permission code `{}`", c);
                    return false;
            }
        }
    }
    {
        args.pop();
        if (!check_args()) return false;
    }

    rule.path = args.top();

    {
        args.pop();
        if (!check_args()) return false;
    }

    rule.user = args.top();

    return dacl::proto::Set(rule);
}

static bool HandleDelete(std::stack<std::string_view> &args) {
    if (args.empty()) {
        logger::Error("Not enough arguments");
        PrintHelp();
        return false;
    }

    auto idStr = args.top();
    int id{};
    auto [_, ec] =
        std::from_chars(idStr.data(), idStr.data() + idStr.size(), id);
    if (ec != std::errc{}) {
        logger::Error("Can't parse `{}` as id", idStr);
        return false;
    }

    dacl::proto::Del({.id = id});

    return true;
}

bool Process(std::stack<std::string_view> args) {
    if (args.empty()) {
        PrintHelp();
        return false;
    }

    Command cmd = ParseCommand(args.top());

    if (cmd == Command::Invalid) {
        logger::Error("Invalid command `{}`", args.top());
        PrintHelp();
        return false;
    }

    args.pop();

    switch (cmd) {
        case Command::Set:
            return HandleSet(args);
        case Command::List:
            return HandleList(args);
        case Command::Status:
            return HandleStatus();
        case Command::Delete:
            return HandleDelete(args);
        default:
            std::unreachable();
    }
}
}  // namespace interpreter
