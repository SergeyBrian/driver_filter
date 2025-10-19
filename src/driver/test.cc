#include <windows.h>
#include <iostream>

#define IOCTL_DAC_TEST \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)

int main() {
    std::cout << "Before CreateFileW\n";
    HANDLE hDevice = CreateFileW(
        L"\\\\.\\DriverFilterControl",  // Имя устройства (должно совпадать с
                                        // симлинком из драйвера)
        GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cout << "[ERR] Failed to open device: " << GetLastError()
                  << std::endl;
        return 1;
    }
    std::cout << "Device opened.\n";

    const char input[] = "test";
    DWORD bytesReturned = 0;

    BOOL ok = DeviceIoControl(hDevice, IOCTL_DAC_TEST, (LPVOID)input,
                              sizeof(input),  // входной буфер
                              nullptr, 0,     // выходной буфер
                              &bytesReturned, nullptr);

    if (!ok) {
        std::cout << "[ERR] DeviceIoControl failed: " << GetLastError()
                  << std::endl;

        CloseHandle(hDevice);
        return 1;
    }

    std::cout << "[OK] Sent 'test' to driver, bytesReturned=" << bytesReturned
              << std::endl;
    CloseHandle(hDevice);
    return 0;
}
