#include "service/database.h"
#include "utils/defer.h"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "common/dacl/internal.h"
#include "service/pipe.h"

static SERVICE_STATUS g_ServiceStatus{};
static SERVICE_STATUS_HANDLE g_StatusHandle{};
static HANDLE g_StopEvent{};

static void WINAPI ServiceCtrlHandler(DWORD ctrlCode) {
    if (ctrlCode == SERVICE_CONTROL_STOP) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

        SetEvent(g_StopEvent);
    }
}

static void WINAPI ServiceMain(DWORD /* argc */, LPWSTR * /*argv */) {
    g_StatusHandle = RegisterServiceCtrlHandlerW(
        dacl::proto::internal::ServiceName, ServiceCtrlHandler);
    if (!g_StatusHandle) return;

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    if (!database::Connect()) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }
    defer { database::Disconnect(); };

    g_StopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);

    HANDLE service_worker = pipe::StartWorker(g_StopEvent);

    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    WaitForSingleObject(g_StopEvent, INFINITE);
    WaitForSingleObject(service_worker, 1000);

    CloseHandle(service_worker);
    CloseHandle(g_StopEvent);

    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

int wmain() {
    SERVICE_TABLE_ENTRYW ServiceTable[] = {
        {const_cast<LPWSTR>(dacl::proto::internal::ServiceName),
         reinterpret_cast<LPSERVICE_MAIN_FUNCTIONW>(ServiceMain)},
        {nullptr, nullptr},
    };

    StartServiceCtrlDispatcherW(ServiceTable);
    return 0;
}
