#ifndef H_SRC_SERVICE_LOG_H
#define H_SRC_SERVICE_LOG_H

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <sddl.h>

#include <iostream>

#include "common/dacl/internal.h"

inline void logA(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, _TRUNCATE, fmt, ap);
    va_end(ap);

    HANDLE hEvent =
        RegisterEventSourceW(nullptr, dacl::proto::internal::ServiceName);
    if (hEvent) {
        LPCSTR msgs[1] = {buf};
        WORD type = EVENTLOG_INFORMATION_TYPE;
        if (strncmp(buf, "[ERR", 4) == 0)
            type = EVENTLOG_ERROR_TYPE;
        else if (strncmp(buf, "[WARN", 5) == 0)
            type = EVENTLOG_WARNING_TYPE;

        ReportEventA(hEvent, type, 0, 0, nullptr, 1, 0, msgs, nullptr);

        DeregisterEventSource(hEvent);
    } else {
        OutputDebugStringA(buf);
        OutputDebugStringA("\r\n");
    }
}

#endif  // H_SRC_SERVICE_LOG_H
