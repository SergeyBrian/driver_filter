#include "ioctl.h"
#include "utils/log.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <winioctl.h>

#include "driver/driver.h"

namespace ioctl {
std::string GetStatus() {
    HANDLE hDevice =
        CreateFileW(L"\\\\.\\DriverFilterControl", GENERIC_READ | GENERIC_WRITE,
                    0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hDevice == INVALID_HANDLE_VALUE) {
        logger::Error("Failed to open ioctl device");
        return {};
    }
    logger::Okay("ioctl device open.");

    const char input[] = "test";
    DWORD bytesReturned = 0;

    char version[512]{};
    BOOL ok =
        DeviceIoControl(hDevice, IOCTL_PING, LPVOID(input), sizeof(input),
                        version, sizeof(version), &bytesReturned, nullptr);

    if (!ok) {
        logger::Error("DeviceIoControl failed");

        CloseHandle(hDevice);
        return {};
    }

    logger::Okay("Sent ping to driver, received: {}", version);
    CloseHandle(hDevice);

    return version;
}
}  // namespace ioctl
