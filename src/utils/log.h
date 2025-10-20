#ifndef H_SRC_UTILS_LOG_H
#define H_SRC_UTILS_LOG_H

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

#include <format>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>

#include "strconv.h"

namespace logger {
static bool do_offset{};
static HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

enum class LogType : u8 {
    Print,
    Okay,
    Debug,
    Info,
    Warning,
    Error,
};

#define COLOR_RESET "\033[0m"
#define COLOR_BLUE "\033[36m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_RED "\033[31m"
#define COLOR_GRAY "\033[90m"

#define COLOR_OKAY COLOR_GREEN
#define COLOR_DEBUG COLOR_RESET
#define COLOR_INFO COLOR_RESET
#define COLOR_WARN COLOR_YELLOW
#define COLOR_ERROR COLOR_RED

static thread_local auto tid = utils::strconv::to_base(
    std::hash<std::thread::id>{}(std::this_thread::get_id()), 61);

template <typename... Args>
inline void Log(LogType log_type, std::format_string<Args...> format,
                Args &&...args) {
    /*#ifdef NDEBUG*/
    if (log_type < LogType::Info) {
        return;
    }
    /*#endif*/

    const char *color = COLOR_RESET;
    const char *prefix = "";
    const char *reset = COLOR_RESET;

    switch (log_type) {
        case LogType::Okay:
            color = COLOR_OKAY;
            prefix = "[+] ";
            break;
        case LogType::Debug:
        case LogType::Info:
            color = COLOR_INFO;
            prefix = "[-] ";
            break;
        case LogType::Warning:
            color = COLOR_WARN;
            prefix = "[*] ";
            break;
        case LogType::Error:
            color = COLOR_ERROR;
            prefix = "[!] ";
            break;
        case LogType::Print:
            color = "";
            reset = "";
            break;
    }

    std::string message = std::format(format, std::forward<Args>(args)...);

    std::string tid_prefix{};
#ifndef NDEBUG
    tid_prefix = std::format("[{}]", tid);
#endif

    std::cout << color << tid_prefix << prefix << message << reset << '\n';

    /*#if defined(_WIN32) && !defined(NDEBUG)*/
    static DWORD last_received_err{};
    if (log_type == LogType::Error) {
        DWORD err = GetLastError();
        if (err) {
            last_received_err = err;

            LPSTR message_raw{};
            size_t size = FormatMessageA(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                    FORMAT_MESSAGE_IGNORE_INSERTS,
                nullptr, err, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
                reinterpret_cast<LPSTR>(&message_raw), 0, nullptr);

            if (size && message_raw) {
                std::cout << color
                          << std::format("Windows error: ({}) {}",
                                         static_cast<unsigned long>(err),
                                         message_raw)
                          << reset << '\n';
                LocalFree(message_raw);
            }
        }
    }
    /*#endif*/
}

template <typename... Args>
inline void Okay(std::format_string<Args...> format, Args &&...args) {
    Log(LogType::Okay, format, std::forward<Args>(args)...);
}

template <typename... Args>
inline void Debug(std::format_string<Args...> format, Args &&...args) {
    /*#ifndef NDEBUG*/
    Log(LogType::Debug, format, std::forward<Args>(args)...);
    /*#endif*/
}

template <typename... Args>
inline void Info(std::format_string<Args...> format, Args &&...args) {
    Log(LogType::Info, format, std::forward<Args>(args)...);
}

template <typename... Args>
inline void Warn(std::format_string<Args...> format, Args &&...args) {
    Log(LogType::Warning, format, std::forward<Args>(args)...);
}

template <typename... Args>
inline void Error(std::format_string<Args...> format, Args &&...args) {
    Log(LogType::Error, format, std::forward<Args>(args)...);
}

template <typename... Args>
inline void Printf(std::format_string<Args...> format, Args &&...args) {
    Log(LogType::Print, format, std::forward<Args>(args)...);
}

class Logger {
public:
    template <typename T>
    Logger &operator<<(const T &value) {
        /*#ifndef NDEBUG*/
        buffer_ << value;
        /*#endif*/
        Flush();
        return *this;
    }

private:
    std::ostringstream buffer_;

    void Flush() {
        std::cout << buffer_.str();
        buffer_.str("");
        buffer_.clear();
    }
};

static Logger log;

}  // namespace logger

#endif  // H_SRC_UTILS_LOG_H
