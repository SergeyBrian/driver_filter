#include "user.h"
#include <optional>

#pragma comment(lib, "netapi32.lib")

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <lm.h>
#include <sddl.h>

#include <cassert>

#include "utils/log.h"
#include "utils/defer.h"
#include "utils/strconv.h"

namespace dacl::user {
std::vector<User> List() {
    LPUSER_INFO_0 buf{};
    LPUSER_INFO_0 tmp_buf{};
    DWORD read{};
    DWORD total{};
    DWORD resume_handle{};
    std::vector<User> res{};

    NET_API_STATUS status{};

    do {
        defer {
            if (buf != nullptr) {
                NetApiBufferFree(buf);
            }
        };

        status = NetUserEnum(
            nullptr, 0, FILTER_NORMAL_ACCOUNT, reinterpret_cast<LPBYTE *>(&buf),
            MAX_PREFERRED_LENGTH, &read, &total, &resume_handle);
        if (status != NERR_Success && status != ERROR_MORE_DATA) {
            logger::Error("NetUserEnum failed (code: {})", status);
            return {};
        }
        if (buf == nullptr) {
            continue;
        }
        tmp_buf = buf;

        for (size_t i = 0; i < read; i++) {
            assert(tmp_buf != nullptr);
            if (tmp_buf == nullptr) {
                logger::Error("NetUserEnum returned null buffer");
                return {};
            }

            DWORD cbSid{};
            DWORD cchRef{};
            SID_NAME_USE use{};
            (void)LookupAccountNameW(L".", tmp_buf->usri0_name, nullptr, &cbSid,
                                     nullptr, &cchRef, &use);
            if (cbSid == 0 || cchRef == 0) {
                logger::Error("LookupAccountNameW(size) failed (code: {})",
                              GetLastError());
                return {};
            }

            std::vector<BYTE> sid(cbSid);
            std::wstring refDomain;
            refDomain.resize(cchRef);

            if (!LookupAccountNameW(L".", tmp_buf->usri0_name, sid.data(),
                                    &cbSid, refDomain.data(), &cchRef, &use)) {
                logger::Error("LookupAccountNameW failed (code: {})",
                              GetLastError());
                return {};
            }

            LPWSTR sid_str{};
            if (!ConvertSidToStringSidW(reinterpret_cast<PSID>(sid.data()),
                                        &sid_str)) {
                logger::Error("ConvertSidToStringSidW failed (code: {})",
                              GetLastError());
                return {};
            }

            res.emplace_back(utils::strconv::to_utf8(tmp_buf->usri0_name),
                             utils::strconv::to_utf8(sid_str));

            LocalFree(sid_str);
            tmp_buf++;
        }
    } while (status == ERROR_MORE_DATA);

    return res;
}

std::optional<User> Get(const std::string &name) {
    DWORD cbSid{};
    DWORD cchRef{};
    SID_NAME_USE use{};
    std::wstring wname{name.begin(), name.end()};
    (void)LookupAccountNameW(L".", wname.c_str(), nullptr, &cbSid, nullptr,
                             &cchRef, &use);
    if (cbSid == 0 || cchRef == 0) {
        logger::Error("LookupAccountNameW(size) failed (code: {})",
                      GetLastError());
        return std::nullopt;
    }

    std::vector<BYTE> sid(cbSid);
    std::wstring refDomain;
    refDomain.resize(cchRef);

    if (!LookupAccountNameW(L".", wname.c_str(), sid.data(), &cbSid,
                            refDomain.data(), &cchRef, &use)) {
        logger::Error("LookupAccountNameW failed (code: {})", GetLastError());
        return std::nullopt;
    }

    LPWSTR sid_str{};
    if (!ConvertSidToStringSidW(reinterpret_cast<PSID>(sid.data()), &sid_str)) {
        logger::Error("ConvertSidToStringSidW failed (code: {})",
                      GetLastError());
        return std::nullopt;
    }

    return User{
        .name = name,
        .sid = utils::strconv::to_utf8(sid_str),
    };
}
}  // namespace dacl::user
