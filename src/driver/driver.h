#ifndef H_SRC_DRIVER_DRIVER_H
#define H_SRC_DRIVER_DRIVER_H

#ifdef __cplusplus
extern "C" {
#endif

const wchar_t *DeviceName = L"\\Device\\DriverFilterControl";
const wchar_t *DeviceSymName = L"\\??\\DriverFilterControl";
const char *DriverVersion = "v0.0.1";

#define IOCTL_PING \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UPDATE_RULE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // H_SRC_DRIVER_DRIVER_H
