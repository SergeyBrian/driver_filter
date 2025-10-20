#include "pipe.h"
#include <cstring>
#include "common/dacl/rule.h"
#include "service/ioctl.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <sddl.h>

#include <iostream>
#include <format>
#include <algorithm>

#include "common/dacl/proto.h"
#include "common/dacl/dacl.h"
#include "common/dacl/internal.h"
#include "service/database.h"
#include "utils/alias.h"
#include "utils/defer.h"
#include "log.h"

namespace internal = dacl::proto::internal;

namespace pipe {
static void ProcessRequest(const HANDLE pipe) {
    char buf[512] = {};
    DWORD bytesRead = 0;
    if (!ReadFile(pipe, buf, sizeof(buf) - 1, &bytesRead, nullptr)) {
        logA("[svc] ReadFile failed: %lu", GetLastError());
        return;
    }
    buf[bytesRead] = 0;
    logA("[svc] got '%s' (%lu bytes)", buf, bytesRead);

    defer {
        if (!FlushFileBuffers(pipe)) {
            logA("[svc] FlushFileBuffers failed: %lu", GetLastError());
        }
    };

    auto send_resp = [&pipe](const char *resp) {
        DWORD bytesWritten = 0;
        if (!WriteFile(pipe, resp, DWORD(strlen(resp)), &bytesWritten,
                       nullptr)) {
            logA("[svc] WriteFile(resp='%s') failed: %lu", resp,
                 GetLastError());
        }
    };

    logA("[svc] Received: %s", buf);
    if (strcmp(buf, internal::PingMessage) == 0) {
        DWORD written{};

        std::string driverVersion = ioctl::GetStatus();
        logA("[svc] Driver response: %s", driverVersion.c_str());
        usize msg_size = strlen(internal::PongMessage) + 1;
        std::memcpy(buf, internal::PongMessage, msg_size);
        std::memcpy(buf + msg_size, driverVersion.c_str(),
                    driverVersion.size() + 1);

        if (!WriteFile(pipe, buf, DWORD(msg_size + driverVersion.size() + 1),
                       &written, nullptr)) {
            logA("[ERROR] WriteFile() failed: %lu", GetLastError());
        }

        return;
    }

    if (strncmp(buf, internal::SetMessage, strlen(internal::SetMessage)) == 0) {
        dacl::Rule rule =
            internal::DecodeRule(buf + strlen(internal::SetMessage) + 1);

        if (!database::InsertRule(rule)) {
            send_resp(internal::RespError);
        }

        auto rules = database::GetRules({.path = rule.path, .user = rule.user});
        if (rules.empty()) {
            logA("[ERROR] No rules after set");
            send_resp(internal::RespError);
            return;
        }

        SummarizedRule summarized = dacl::Summarize(rules);
        if (strlen(summarized.sid) == 0) {
            logA("[ERROR] Summarize failed");
            send_resp(internal::RespError);
            return;
        }

        if (!ioctl::UpdateRule(summarized)) {
            logA("[ERROR] ioctl UpdateRule failed");
            send_resp(internal::RespError);
            return;
        }

        send_resp(internal::RespOk);
        return;
    }

    if (strncmp(buf, internal::DelMessage, strlen(internal::DelMessage)) == 0) {
        dacl::Rule rule =
            internal::DecodeRule(buf + strlen(internal::DelMessage) + 1);

        if (!database::DeleteRule(rule)) {
            send_resp(internal::RespError);
        }
        send_resp(internal::RespOk);
        return;
    }

    if (strncmp(buf, internal::GetRulesMessage,
                strlen(internal::GetRulesMessage)) == 0) {
        auto rules = database::GetRules({});

        char *tmp_buf = new char[512 * (1 + rules.size())];
        defer { delete[] tmp_buf; };
        char *ptr = tmp_buf;

        usize used_len{};

        usize full_size{};
        ptr += sizeof(full_size);

        for (const auto &rule : rules) {
            dacl::proto::internal::EncodeRule(rule, ptr, &used_len);
            ptr += used_len;
            logA("[DEBUG] used_len = %d", used_len);
        }

        full_size = usize(ptr - tmp_buf);
        ptr = tmp_buf;

        logA("[DEBUG] full_size = %d", full_size);

        *reinterpret_cast<usize *>(ptr) = full_size;

        DWORD sent_size{};
        while (sent_size < full_size) {
            DWORD written{};

            if (!WriteFile(pipe, ptr,
                           DWORD(std::min(sizeof(buf), full_size - sent_size)),
                           &written, nullptr)) {
                logA("[ERROR] WriteFile() failed: %lu", GetLastError());
            }
            sent_size += written;
        }

        return;
    }

    logA("[ERROR] Unknown request '%s'", buf);
    send_resp(internal::RespUnknownRequest);
}

static DWORD WINAPI worker(LPVOID param) {
    HANDLE stop = param;
    auto make_pipe = []() -> HANDLE {
        LPCWSTR sddl = L"D:(A;;GA;;;BA)(A;;GA;;;SY)";
        PSECURITY_DESCRIPTOR sd = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, SDDL_REVISION_1, &sd, nullptr)) {
            logA("[svc] SDDL convert failed: %lu", GetLastError());
            return INVALID_HANDLE_VALUE;
        }

        SECURITY_ATTRIBUTES sa{sizeof(sa), sd, FALSE};
        HANDLE h = CreateNamedPipeW(
            dacl::proto::internal::PipeName, PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 4, 4096,
            4096, 0, &sa);

        LocalFree(sd);

        if (h == INVALID_HANDLE_VALUE) {
            logA("[svc] CreateNamedPipeW failed: %lu", GetLastError());
        }
        return h;
    };

    HANDLE pipe = make_pipe();
    if (pipe == INVALID_HANDLE_VALUE) {
        return 1;
    }
    defer {
        CloseHandle(pipe);
        logA("[svc] pipe handle closed");
    };

    while (WaitForSingleObject(stop, 100) == WAIT_TIMEOUT) {
        logA("[svc] waiting for client...");
        BOOL ok = ConnectNamedPipe(pipe, nullptr);
        DWORD gle = GetLastError();
        if (!ok && gle != ERROR_PIPE_CONNECTED) {
            logA("[svc] ConnectNamedPipe failed: %lu", gle);
            continue;
        }
        logA("[svc] client connected");

        defer {
            DisconnectNamedPipe(pipe);
            logA("[svc] client disconnected");
        };

        const char *unauth = "unauthorized";
        DWORD tmp{};

        if (!ImpersonateNamedPipeClient(pipe)) {
            DWORD e = GetLastError();
            logA("[svc] ImpersonateNamedPipeClient failed: %lu", e);
            if (!WriteFile(pipe, unauth, DWORD(strlen(unauth)), &tmp,
                           nullptr)) {
                logA("[svc] WriteFile(unauthorized) failed: %lu",
                     GetLastError());
            }
            continue;
        }

        HANDLE token{};
        if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
            DWORD e = GetLastError();
            logA("[svc] OpenThreadToken failed: %lu", e);
            RevertToSelf();
            if (!WriteFile(pipe, unauth, DWORD(strlen(unauth)), &tmp,
                           nullptr)) {
                logA("[svc] WriteFile(unauthorized) failed: %lu",
                     GetLastError());
            }
            continue;
        }

        SID_IDENTIFIER_AUTHORITY NT = SECURITY_NT_AUTHORITY;
        PSID adminSid{};
        BOOL isAdmin{};
        if (!AllocateAndInitializeSid(&NT, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                      DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                      &adminSid)) {
            DWORD e = GetLastError();
            logA("[svc] AllocateAndInitializeSid failed: %lu", e);
        } else {
            if (!CheckTokenMembership(token, adminSid, &isAdmin)) {
                logA("[svc] CheckTokenMembership failed: %lu", GetLastError());
                isAdmin = FALSE;
            } else {
                logA("[svc] CheckTokenMembership: isAdmin=%d", int(isAdmin));
            }
        }

        TOKEN_ELEVATION elev{};
        DWORD cb = 0;
        if (GetTokenInformation(token, TokenElevation, &elev, sizeof(elev),
                                &cb)) {
            logA("[svc] TokenElevation: %lu", elev.TokenIsElevated);
            if (!elev.TokenIsElevated) isAdmin = FALSE;
        } else {
            logA("[svc] GetTokenInformation(TokenElevation) failed: %lu",
                 GetLastError());
        }

        if (adminSid) FreeSid(adminSid);
        CloseHandle(token);
        RevertToSelf();

        if (!isAdmin) {
            logA("[svc] client not admin");
            if (!WriteFile(pipe, unauth, DWORD(strlen(unauth)), &tmp,
                           nullptr)) {
                logA("[svc] WriteFile(unauthorized) failed: %lu",
                     GetLastError());
            }
            continue;
        }
        logA("[svc] client authorized");

        ProcessRequest(pipe);
    }

    logA("[svc] stop signaled");
    return 0;
}

HANDLE StartWorker(HANDLE stop_event) {
    HANDLE worker_thread =
        CreateThread(nullptr, 0, worker, stop_event, 0, nullptr);
    return worker_thread;
}
}  // namespace pipe
