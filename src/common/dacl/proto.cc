#include "proto.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>

#include "common/dacl/internal.h"
#include "utils/defer.h"
#include "utils/log.h"

namespace dacl::proto {

static HANDLE Connect() {
    HANDLE hPipe = CreateFileW(
        internal::PipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION, nullptr);
    if (hPipe == INVALID_HANDLE_VALUE) {
        logger::Error("Failed to connect");
        return nullptr;
    }
    logger::Okay("Connected");

    return hPipe;
}

std::optional<Status> GetStatus() {
    HANDLE pipe = Connect();
    if (!pipe) {
        return std::nullopt;
    }
    defer { CloseHandle(pipe); };

    DWORD written{};
    WriteFile(pipe, internal::PingMessage, DWORD(strlen(internal::PingMessage)),
              &written, nullptr);

    char buf[128]{};
    DWORD read{};
    if (!ReadFile(pipe, buf, sizeof(buf) - 1, &read, nullptr)) {
        logger::Error("ReadFile failed");
        return std::nullopt;
    }

    if (strncmp(buf, internal::PongMessage, sizeof(buf)) != 0) {
        logger::Error("Ping failed. Response: {}", buf);
        return Status{false};
    }

    return Status{true};
}

bool Set(const dacl::Rule &rule) {
    HANDLE pipe = Connect();
    if (!pipe) {
        return false;
    }
    defer { CloseHandle(pipe); };

    usize len{};
    char buf[512]{};
    if (!internal::EncodeRule(rule, buf, &len)) {
        logger::Error("Failed to encode rule");
        return false;
    }

    DWORD written{};
    WriteFile(pipe, buf, DWORD(len), &written, nullptr);
    std::memset(buf, 0, sizeof(buf));
    DWORD read{};
    if (!ReadFile(pipe, buf, sizeof(buf) - 1, &read, nullptr)) {
        logger::Error("ReadFile failed");
        return false;
    }
    logger::Okay("{}", buf);

    return true;
}

bool Del(const std::string &path) {
    HANDLE pipe = Connect();
    if (!pipe) {
        return false;
    }
    defer { CloseHandle(pipe); };

    usize len{};
    char buf[512]{};
    if (!internal::EncodeDelRule(path, buf, &len)) {
        logger::Error("Failed to encode delete rule");
        return false;
    }

    DWORD written{};
    WriteFile(pipe, buf, DWORD(len), &written, nullptr);
    std::memset(buf, 0, sizeof(buf));
    DWORD read{};
    if (!ReadFile(pipe, buf, sizeof(buf) - 1, &read, nullptr)) {
        logger::Error("ReadFile failed");
        return false;
    }
    logger::Okay("{}", buf);

    return true;
}

std::vector<dacl::Rule> GetRules() {
    HANDLE pipe = Connect();
    if (!pipe) {
        return {};
    }
    defer { CloseHandle(pipe); };

    auto req = internal::GetRulesMessage;
    char buf[512]{};

    DWORD written{};
    WriteFile(pipe, req, DWORD(strlen(internal::GetRulesMessage)), &written,
              nullptr);

    DWORD read{};

    std::vector<dacl::Rule> res{};

    if (!ReadFile(pipe, buf, sizeof(buf) - 1, &read, nullptr)) {
        logger::Error("ReadFile failed");
        return {};
    }

    DWORD total_read = read;

    auto expected_size = *reinterpret_cast<usize *>(buf);

    logger::Debug("Expecting size: {} (read: {})", expected_size, total_read);
    auto ptr = reinterpret_cast<const char *>(buf) + sizeof(usize);

    usize used_len{};
    usize parsed_len = sizeof(usize);
    while (ptr < buf + sizeof(buf) && parsed_len < expected_size) {
        logger::Debug("Decode");
        res.push_back(internal::DecodeRule(ptr, &used_len));
        ptr += used_len;
        parsed_len += used_len;
    }

    while (total_read < expected_size) {
        if (!ReadFile(pipe, buf, sizeof(buf) - 1, &read, nullptr)) {
            logger::Error("ReadFile failed");
            return {};
        }
        total_read += read;

        ptr = reinterpret_cast<const char *>(buf);
        while (ptr < buf + sizeof(buf) && parsed_len < expected_size) {
            res.push_back(internal::DecodeRule(ptr, &used_len));
            ptr += used_len;
            parsed_len += used_len;
        }
    }

    return res;
}
}  // namespace dacl::proto
