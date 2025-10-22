#include "ioctl.h"
#include "common/dacl/rule.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <winioctl.h>

#include "common/dacl/dacl.h"
#include "driver/driver.h"
#include "log.h"

namespace ioctl {

static HANDLE Connect() {
    HANDLE hDevice =
        CreateFileW(L"\\\\.\\DriverFilterControl", GENERIC_READ | GENERIC_WRITE,
                    0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hDevice == INVALID_HANDLE_VALUE) {
        logA("[ERROR] Failed to open ioctl device");
        return {};
    }
    logA("[DEBUG] ioctl device open.");
    return hDevice;
}
std::string GetStatus() {
    HANDLE hDevice = Connect();
    if (hDevice == INVALID_HANDLE_VALUE) {
        return {};
    }

    const char input[] = "test";
    DWORD bytesReturned = 0;

    char version[512]{};
    BOOL ok =
        DeviceIoControl(hDevice, IOCTL_PING, LPVOID(input), sizeof(input),
                        version, sizeof(version), &bytesReturned, nullptr);

    if (!ok) {
        logA("[ERROR] DeviceIoControl failed");

        CloseHandle(hDevice);
        return {};
    }

    logA("[DEBUG] Sent ping to driver, received: {}", version);
    CloseHandle(hDevice);

    return version;
}

bool UpdateRule(const dacl::SummarizedRule &rule) {
    HANDLE hDevice = Connect();
    if (hDevice == INVALID_HANDLE_VALUE) {
        return false;
    }

    char buf[512]{};

    ULONG len{};
    if (!EncodeSummarizedRule(rule, buf, &len)) {
        logA("[ERROR] EncodeSummarizedRule failed");
        return false;
    }

    logA("[DEBUG] sending update ioctl (%s, %s)", rule.prefix, rule.sid);
    DWORD bytesReturned{};
    BOOL ok = DeviceIoControl(hDevice, IOCTL_UPDATE_RULE, LPVOID(buf),
                              sizeof(buf), nullptr, 0, &bytesReturned, nullptr);

    if (!ok) {
        logA("[ERROR] DeviceIoControl failed");

        CloseHandle(hDevice);
        return {};
    }

    logA("[DEBUG] Sent rule update to driver: status success");

    CloseHandle(hDevice);

    return true;
}

bool DeleteRule(const std::string &path, const dacl::user::User &user) {
    HANDLE hDevice = Connect();
    if (hDevice == INVALID_HANDLE_VALUE) {
        return false;
    }

    char buf[512]{};

    memcpy(buf, path.c_str(), path.size() + 1);
    memcpy(buf + path.size() + 1, user.sid.c_str(), user.sid.size() + 1);

    logA("[DEBUG] sending delete ioctl (%s, %s)", path.c_str(),
         user.sid.c_str());
    DWORD bytesReturned{};
    BOOL ok = DeviceIoControl(hDevice, IOCTL_DELETE_RULE, LPVOID(buf),
                              sizeof(buf), nullptr, 0, &bytesReturned, nullptr);

    if (!ok) {
        logA("[ERROR] DeviceIoControl failed");

        CloseHandle(hDevice);
        return {};
    }

    logA("[DEBUG] Sent rule delete to driver: status success");

    CloseHandle(hDevice);

    return true;
}

bool ToggleNotifier(bool start) {
    HANDLE hDevice = Connect();
    if (hDevice == INVALID_HANDLE_VALUE) {
        return false;
    }

    char buf[10]{};

    *buf = char(start);

    logA("[DEBUG] sending ToggleNotifier ioctl");

    BOOL ok = DeviceIoControl(hDevice, IOCTL_TOGGLE_NOTIFIER, LPVOID(buf),
                              sizeof(buf), nullptr, 0, nullptr, nullptr);

    if (!ok) {
        logA("[ERROR] DeviceIoControl failed");

        CloseHandle(hDevice);
        return {};
    }

    logA("[DEBUG] Sent toggle notifier to driver: status success");

    CloseHandle(hDevice);

    return true;
}
}  // namespace ioctl
