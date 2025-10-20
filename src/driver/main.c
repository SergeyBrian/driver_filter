#include <fltKernel.h>
#include <ntifs.h>
#include <dontuse.h>
#include <string.h>
#include <suppress.h>
#include <ntddk.h>
#include <wdmsec.h>

#include <stdio.h>

#include "driver.h"

#pragma prefast(disable : __WARNING_ENCODE_MEMBER_FUNCTION_POINTER, \
                "Not valid for kernel mode drivers")

#define SDDL_DACFLT L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"

static PFLT_FILTER gFilterHandle;
static NTSTATUS status;

static UNICODE_STRING gDevName =
    RTL_CONSTANT_STRING(L"\\Device\\DriverFilterControl");
static UNICODE_STRING gSymName =
    RTL_CONSTANT_STRING(L"\\??\\DriverFilterControl");
static PDEVICE_OBJECT gCtlDev;

DRIVER_DISPATCH CtlCreateClose, CtlDeviceControl;

static ULONG_PTR OperationStatusCtx = 1;

#define DBG_TRACE_ROUTINES 0x1
#define DBG_TRACE_STATUS 0x1 << 1
#define DBG_DEBUG 0x1 << 2
#define DBG_ERROR 0x1 << 3
#define DBG_WARN 0x1 << 4

#define DBG_TRACE_ALL 0xffffffff

static ULONG gTraceFlags = DBG_DEBUG | DBG_ERROR | DBG_WARN;

typedef struct _HANDLE_CTX {
    FILE_ID_128 FileId;
    ULONG VolumeSerial;
    PSID UserSid;
    ACCESS_MASK GrantedAccess;
} HANDLE_CTX, *PHANDLE_CTX;

typedef struct _PRE_CTX {
    PSID UserSid;
} PRE_CTX, *PPRE_CTX;

#define DBG_PRINT(_dbgLevel, _string) \
    (FlagOn(gTraceFlags, (_dbgLevel)) ? DbgPrint _string : ((int)0))

// === Forward declarations ===

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
            _In_ PUNICODE_STRING RegistryPath);

NTSTATUS
InstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects,
              _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
              _In_ DEVICE_TYPE VolumeDeviceType,
              _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);

VOID InstanceTeardownStart(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                           _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

VOID InstanceTeardownComplete(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                              _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

NTSTATUS
Unload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

NTSTATUS
InstanceQueryTeardown(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                      _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS
PreOperationCallback(_Inout_ PFLT_CALLBACK_DATA Data,
                     _In_ PCFLT_RELATED_OBJECTS FltObjects,
                     _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

VOID OperationStatusCallback(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                             _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
                             _In_ NTSTATUS OperationStatus,
                             _In_ PVOID RequesterContext);

FLT_POSTOP_CALLBACK_STATUS
PostOperationCallback(_Inout_ PFLT_CALLBACK_DATA Data,
                      _In_ PCFLT_RELATED_OBJECTS FltObjects,
                      _In_opt_ PVOID CompletionContext,
                      _In_ FLT_POST_OPERATION_FLAGS Flags);

FLT_POSTOP_CALLBACK_STATUS
NoPostOperationCallback(_Inout_ PFLT_CALLBACK_DATA Data,
                        _In_ PCFLT_RELATED_OBJECTS FltObjects,
                        _In_opt_ PVOID CompletionContext,
                        _In_ FLT_POST_OPERATION_FLAGS Flags);

BOOLEAN
DoFilterOperation(_In_ PFLT_CALLBACK_DATA Data);

// ==================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, Unload)
#pragma alloc_text(PAGE, InstanceQueryTeardown)
#pragma alloc_text(PAGE, InstanceSetup)
#pragma alloc_text(PAGE, InstanceTeardownStart)
#pragma alloc_text(PAGE, InstanceTeardownComplete)
#endif

static CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    {IRP_MJ_CREATE, 0, PreOperationCallback, PostOperationCallback, 0},

    {IRP_MJ_SET_INFORMATION, 0, PreOperationCallback, NoPostOperationCallback,
     0},

    {IRP_MJ_SET_SECURITY, 0, PreOperationCallback, NoPostOperationCallback, 0},

    {IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, 0, PreOperationCallback, NULL,
     0},

    {IRP_MJ_CLEANUP, 0, PreOperationCallback, NoPostOperationCallback, 0},

    {IRP_MJ_OPERATION_END, 0, 0, 0, 0},
};

NTSTATUS Unload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE()
    DBG_PRINT(DBG_TRACE_ROUTINES, ("DriverFilter!Unload: Entered\n"));

    IoDeleteSymbolicLink(&gSymName);
    if (gCtlDev) {
        IoDeleteDevice(gCtlDev);
    }

    FltUnregisterFilter(gFilterHandle);

    return STATUS_SUCCESS;
}

static CONST FLT_REGISTRATION FilterRegistration = {

    sizeof(FLT_REGISTRATION),  //  Size
    FLT_REGISTRATION_VERSION,  //  Version
    0,                         //  Flags

    NULL,       //  Context
    Callbacks,  //  Operation callbacks

    Unload,  //  MiniFilterUnload

    InstanceSetup,             //  InstanceSetup
    InstanceQueryTeardown,     //  InstanceQueryTeardown
    InstanceTeardownStart,     //  InstanceTeardownStart
    InstanceTeardownComplete,  //  InstanceTeardownComplete

    NULL,  //  GenerateFileName
    NULL,  //  GenerateDestinationFileName
    NULL   //  NormalizeNameComponent
};

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath) {
    UNICODE_STRING sddl;

    UNREFERENCED_PARAMETER(RegistryPath);

    DBG_PRINT(DBG_TRACE_ROUTINES, ("DriverFilter!DriverEntry Entered\n"));

    status =
        FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);

    FLT_ASSERT(NT_SUCCESS(status));

    status = FltStartFiltering(gFilterHandle);

    if (!NT_SUCCESS(status)) {
        DBG_PRINT(DBG_TRACE_ROUTINES,
                  ("DriverFilter!DriverEntry: FltStartFiltering failed\n"));
        FltUnregisterFilter(gFilterHandle);
    }

    // ==== IOCTL ====
    DriverObject->MajorFunction[IRP_MJ_CREATE] = CtlCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CtlCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = CtlDeviceControl;

    RtlInitUnicodeString(&sddl, SDDL_DACFLT);
    status = IoCreateDeviceSecure(DriverObject, 0, &gDevName,
                                  FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
                                  FALSE, &sddl, NULL, &gCtlDev);
    if (!NT_SUCCESS(status)) goto Fail;

    status = IoCreateSymbolicLink(&gSymName, &gDevName);
    if (!NT_SUCCESS(status)) goto Fail;

    gCtlDev->Flags |= DO_BUFFERED_IO;

    gCtlDev->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;

Fail:
    if (gCtlDev) {
        IoDeleteDevice(gCtlDev);
        gCtlDev = NULL;
    }
    IoDeleteSymbolicLink(&gSymName);
    if (gFilterHandle) FltUnregisterFilter(gFilterHandle);
    return status;
}

NTSTATUS
InstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects,
              _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
              _In_ DEVICE_TYPE VolumeDeviceType,
              _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    PAGED_CODE()
    DBG_PRINT(DBG_TRACE_ROUTINES, ("DriverFilter!InstanceSetup Entered\n"));
    return STATUS_SUCCESS;
}

NTSTATUS
InstanceQueryTeardown(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                      _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    DBG_PRINT(DBG_TRACE_ROUTINES,
              ("DriverFilter!InstanceQueryTeardown Entered\n"));
    return STATUS_SUCCESS;
}

VOID InstanceTeardownStart(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                           _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    DBG_PRINT(DBG_TRACE_ROUTINES,
              ("DriverFilter!InstanceTeardownStart Entered\n"));
}

VOID InstanceTeardownComplete(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                              _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    DBG_PRINT(DBG_TRACE_ROUTINES,
              ("DriverFilter!InstanceTeardownComplete Entered\n"));
}

static NTSTATUS GetRequestorUserToken(_In_ PFLT_CALLBACK_DATA Data,
                                      _Out_ PTOKEN_USER *userToken) {
    PACCESS_TOKEN token = NULL;
    PTOKEN_USER tokenUser = NULL;
    PEPROCESS reqProc = NULL;

    BOOLEAN copyOnOpen;
    BOOLEAN effectiveOnly;
    SECURITY_IMPERSONATION_LEVEL impersonationLevel;

    status = STATUS_SUCCESS;

    if (!userToken) {
        return STATUS_INVALID_PARAMETER_2;
    }

    *userToken = NULL;

    token = PsReferenceImpersonationToken(PsGetCurrentThread(), &copyOnOpen,
                                          &effectiveOnly, &impersonationLevel);
    if (!token) {
        reqProc = FltGetRequestorProcess(Data);
        if (!reqProc) {
            DBG_PRINT(DBG_WARN, ("DriverFilter!GetRequestorUserToken "
                                 "FltGetRequestorProcess failed"));
            reqProc = PsGetCurrentProcess();
        }

        token = PsReferencePrimaryToken(reqProc);
        if (!token) {
            return STATUS_NO_TOKEN;
        }
    }

    status = SeQueryInformationToken(token, TokenUser, (PVOID *)&tokenUser);

    if (reqProc) {
        PsDereferencePrimaryToken(token);
    } else {
        PsDereferenceImpersonationToken(token);
    }

    if (!NT_SUCCESS(status)) {
        if (tokenUser) {
            ExFreePool(tokenUser);
        }
        DBG_PRINT(DBG_ERROR, ("DriverFilter!GetRequestorUserToken: "
                              "SeQueryInformationToken Failed, status=%08x\n",
                              status));
        return status;
    }

    *userToken = tokenUser;

    return STATUS_SUCCESS;
}

// Callbacks

NTSTATUS CtlDeviceControl(PDEVICE_OBJECT DevObj, PIRP Irp) {
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = sp->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS st = STATUS_INVALID_DEVICE_REQUEST;
    PVOID buf = Irp->AssociatedIrp.SystemBuffer;
    ULONG inLen = sp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = sp->Parameters.DeviceIoControl.OutputBufferLength;

    UNREFERENCED_PARAMETER(DevObj);
    DBG_PRINT(DBG_DEBUG, ("DriverFilter!CtlDeviceControl: Entered\n"));

    switch (code) {
        case IOCTL_PING:
            DBG_PRINT(DBG_DEBUG,
                      ("DriverFilter!CtlDeviceControl Received IOCTL_PING '%s'",
                       (char *)buf));
            if (outLen < strlen(DriverVersion)) {
                Irp->IoStatus.Information = 0;
                st = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            RtlCopyMemory(buf, DriverVersion, strlen(DriverVersion) + 1);
            Irp->IoStatus.Information = (ULONG_PTR)strlen(DriverVersion) + 1;
            st = STATUS_SUCCESS;
            break;
        default:
            st = STATUS_INVALID_DEVICE_REQUEST;
            Irp->IoStatus.Information = 0;
            break;
    }

    Irp->IoStatus.Status = st;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return st;
}

NTSTATUS CtlCreateClose(PDEVICE_OBJECT DevObj, PIRP Irp) {
    UNREFERENCED_PARAMETER(DevObj);
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS
PreOperationCallback(_Inout_ PFLT_CALLBACK_DATA Data,
                     _In_ PCFLT_RELATED_OBJECTS FltObjects,
                     _Flt_CompletionContext_Outptr_ PVOID *CompletionContext) {
    PFLT_FILE_NAME_INFORMATION nameInfo;
    PTOKEN_USER tokenUser;
    PSID sid;
    PPRE_CTX ctx;
    ULONG sidLen;

    UNREFERENCED_PARAMETER(FltObjects);

    DBG_PRINT(DBG_TRACE_ROUTINES,
              ("DriverFilter!PreOperationCallback Entered\n"));
    if (!DoFilterOperation(Data)) {
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    status = GetRequestorUserToken(Data, &tokenUser);
    if (!NT_SUCCESS(status)) {
        DBG_PRINT(DBG_ERROR, ("DriverFilter!PreOperationCallback: "
                              "GetRequestorUserToken Failed, status=%08x\n",
                              status));
        // TODO handle user error
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    sid = tokenUser->User.Sid;

    if (RtlEqualSid(sid, SeExports->SeLocalServiceSid) ||
        RtlEqualSid(sid, SeExports->SeLocalSystemSid) ||
        RtlEqualSid(sid, SeExports->SeNetworkServiceSid)) {
        ExFreePool(tokenUser);
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    sidLen = RtlLengthSid(sid);

    ctx = (PPRE_CTX)ExAllocatePoolWithTag(NonPagedPoolNx,
                                          sizeof(PRE_CTX) + sidLen, 'DISP');
    if (ctx) {
        PSID sidCopy = ctx + 1;
        RtlCopySid(sidLen, sidCopy, sid);
        ctx->UserSid = sidCopy;
        *CompletionContext = ctx;
    }

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED |
            FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
        &nameInfo);

    if (!NT_SUCCESS(status)) {
        DBG_PRINT(DBG_ERROR, ("DriverFilter!PreOperationCallback: "
                              "FltGetFileNameInformation Failed, status=%08x\n",
                              status));
        status = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_OPENED |
                FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
            &nameInfo);
    }

    if (NT_SUCCESS(status)) {
        DBG_PRINT(DBG_DEBUG,
                  ("DriverFilter!PreOperationCallback: FileName %wZ\n",
                   &nameInfo->Name));
        // TODO filtering logic
    } else {
        DBG_PRINT(DBG_ERROR,
                  ("DriverFilter!PreOperationCallback: "
                   "Unable to read file name: FltGetFileNameInformation Failed "
                   "TWO TIMES, status=%08x\n",
                   status));
    }

    status = FltRequestOperationStatusCallback(Data, OperationStatusCallback,
                                               (PVOID)(++OperationStatusCtx));
    if (!NT_SUCCESS(status)) {
        DBG_PRINT(DBG_TRACE_STATUS,
                  ("DriverFilter!PreOperationCallback: "
                   "FltRequestOperationStatusCallback Failed, status=%08x\n",
                   status));
    }

    ExFreePool(tokenUser);
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

VOID OperationStatusCallback(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                             _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
                             _In_ NTSTATUS OperationStatus,
                             _In_ PVOID RequesterContext) {
    UNREFERENCED_PARAMETER(FltObjects);

    DBG_PRINT(DBG_TRACE_ROUTINES,
              ("DriverFilter!OperationStatusCallback: Entered\n"));

    DBG_PRINT(
        DBG_TRACE_STATUS,
        ("DriverFilter!OperationStatusCallback: Status=%08x ctx=%p "
         "IrpMj=%02x.%02x \"%s\"\n",
         OperationStatus, RequesterContext, ParameterSnapshot->MajorFunction,
         ParameterSnapshot->MinorFunction,
         FltGetIrpName(ParameterSnapshot->MajorFunction)));
}

FLT_POSTOP_CALLBACK_STATUS
NoPostOperationCallback(_Inout_ PFLT_CALLBACK_DATA Data,
                        _In_ PCFLT_RELATED_OBJECTS FltObjects,
                        _In_opt_ PVOID CompletionContext,
                        _In_ FLT_POST_OPERATION_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    if (CompletionContext) {
        ExFreePool(CompletionContext);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS
PostOperationCallback(_Inout_ PFLT_CALLBACK_DATA Data,
                      _In_ PCFLT_RELATED_OBJECTS FltObjects,
                      _In_opt_ PVOID CompletionContext,
                      _In_ FLT_POST_OPERATION_FLAGS Flags) {
    UNICODE_STRING sidStr;
    PPRE_CTX ctx = CompletionContext;

    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Data);

    DBG_PRINT(DBG_TRACE_ROUTINES,
              ("DriverFilter!PostOperationCallback: Entered\n"));
    if (ctx && ctx->UserSid) {
        status = RtlConvertSidToUnicodeString(&sidStr, ctx->UserSid, TRUE);
        if (NT_SUCCESS(status)) {
            DBG_PRINT(
                DBG_DEBUG,
                ("DriverFilter!PostOperationCallback: Requestor SID: %wZ\n",
                 &sidStr));
            RtlFreeUnicodeString(&sidStr);
        } else {
            DBG_PRINT(DBG_ERROR, ("DriverFilter!PostOperationCallback: "
                                  "RtlConvertSidToUnicodeString failed: 0x%X\n",
                                  status));
        }
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

BOOLEAN
DoFilterOperation(_In_ PFLT_CALLBACK_DATA Data) {
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    const UCHAR mj = iopb->MajorFunction;

    if (mj == IRP_MJ_CREATE) return TRUE;

    if (mj == IRP_MJ_WRITE) return TRUE;
    if (mj == IRP_MJ_READ) return TRUE;

    if (mj == IRP_MJ_SET_INFORMATION) {
        FILE_INFORMATION_CLASS fic =
            iopb->Parameters.SetFileInformation.FileInformationClass;

        switch (fic) {
            case FileDispositionInformation:
            case FileDispositionInformationEx:
            case FileRenameInformation:
            case FileRenameInformationEx:
            case FileLinkInformation:
            case FileLinkInformationEx:
            case FileEndOfFileInformation:
            case FileAllocationInformation:
            case FileBasicInformation:
                return TRUE;
            default:
                return FALSE;
        }
    }

    if (mj == IRP_MJ_SET_SECURITY || mj == IRP_MJ_QUERY_SECURITY) return TRUE;

    if (mj == IRP_MJ_LOCK_CONTROL) return TRUE;

    return FALSE;
}
