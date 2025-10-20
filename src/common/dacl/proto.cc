#include "proto.h"
#include <string.h>

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
    Status res{};

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

    if (strncmp(buf, internal::PongMessage, strlen(internal::PongMessage)) !=
        0) {
        logger::Error("Ping failed. Response: {}", buf);
        return res;
    }

    res.service_running = true;

    usize offset = strlen(internal::PongMessage) + 1;
    if (read == offset || strlen(buf + offset) == 0) {
        logger::Error("No driver response received");
        return res;
    }

    logger::Info("Driver version: {}", buf + offset);

    res.driver_running = true;

    return res;
}

bool Set(dacl::Rule &rule) {
    if (!dacl::PrepareRule(rule)) {
        return false;
    }

    HANDLE pipe = Connect();
    if (!pipe) {
        return false;
    }
    defer { CloseHandle(pipe); };

    usize len{};
    char buf[512]{};

    usize set_msg_size = strlen(internal::SetMessage) + 1;
    std::memcpy(buf, internal::SetMessage, set_msg_size);

    if (!internal::EncodeRule(rule, buf + set_msg_size, &len)) {
        logger::Error("Failed to encode rule");
        return false;
    }

    DWORD written{};
    WriteFile(pipe, buf, DWORD(len + sizeof(set_msg_size)), &written, nullptr);
    std::memset(buf, 0, sizeof(buf));
    DWORD read{};
    if (!ReadFile(pipe, buf, sizeof(buf) - 1, &read, nullptr)) {
        logger::Error("ReadFile failed");
        return false;
    }
    logger::Okay("{}", buf);

    return true;
}

bool Del(const dacl::Rule &rule) {
    HANDLE pipe = Connect();
    if (!pipe) {
        return false;
    }
    defer { CloseHandle(pipe); };

    usize len{};
    char buf[512]{};

    usize del_msg_size = strlen(internal::DelMessage) + 1;
    std::memcpy(buf, internal::DelMessage, del_msg_size);

    if (!internal::EncodeRule(rule, buf + del_msg_size, &len)) {
        logger::Error("Failed to encode delete rule");
        return false;
    }

    DWORD written{};
    WriteFile(pipe, buf, DWORD(len + del_msg_size), &written, nullptr);
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

    DWORD written{};
    WriteFile(pipe, req, DWORD(strlen(internal::GetRulesMessage)), &written,
              nullptr);

    DWORD read{};

    std::vector<dacl::Rule> res{};

    usize expected_size{};
    if (!ReadFile(pipe, &expected_size, sizeof(expected_size), &read,
                  nullptr)) {
        logger::Error("ReadFile failed");
        return {};
    }

    auto buf = new char[expected_size];
    defer { delete[] buf; };

    DWORD total_read = read;

    auto ptr = buf;
    do {
        if (!ReadFile(pipe, ptr, DWORD(expected_size), &read, nullptr)) {
            logger::Error("ReadFile failed");
            return {};
        }
        total_read += read;
        ptr += read;
    } while (total_read < expected_size);

    ptr = buf;
    usize parsed_len = sizeof(expected_size);
    while (ptr < buf + expected_size && parsed_len < expected_size) {
        usize used_len{};
        res.push_back(internal::DecodeRule(ptr, &used_len));
        ptr += used_len;
        parsed_len += used_len;
    }

    return res;
}
}  // namespace dacl::proto
